//go:build integration

package kubeadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
	corev1 "k8s.io/api/core/v1"
)

// Native truth separation on one API object. The test oracle is deliberately
// not a new portable verifier profile. PostgreSQL evidenceverify is not invoked
// on Kubernetes facts. Privileged A=0 writes are outside the fenced executor.
func TestKindACPConditionalCollapse(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		name := fmt.Sprintf("%03b", mask)
		t.Run(name, func(t *testing.T) {
			a, claim := setupKubernetesNativeFence(t)
			ctx := context.Background()
			actual := claim
			if mask&2 == 0 {
				actual.AttemptID, actual.Executor.ID = "attempt:other", "executor:other"
			}
			prep, err := r.ReserveFenced(ctx, actual, a)
			if err != nil {
				t.Fatal(err)
			}
			crossing := prep.Custody
			crossing.Phase = r.CustodyCrossing
			if err := a.TransitionFencedCustodyCAS(ctx, prep.Custody, crossing); err != nil {
				t.Fatal(err)
			}
			if mask&4 != 0 {
				if _, err := a.ExecuteFenced(ctx, actual.Transition, crossing); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := a.mutateCurrent(ctx, func(cm *corev1.ConfigMap) {
					cm.Data[kubeFenceAuthorityActive] = "false"
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := a.ExecuteFenced(ctx, actual.Transition, crossing); err != errKubeNativeAuthority {
					t.Fatalf("governed executor accepted revoked authority: %v", err)
				}
				// Explicit outside-boundary writer. The API credential still works,
				// while the relevant governed authority has already been revoked.
				if err := a.mutateCurrent(ctx, func(cm *corev1.ConfigMap) {
					cm.Data[kubeFenceStateRevision] = actual.Transition.To.Revision
					cm.Data[kubeFenceStateDigest] = actual.Transition.To.Digest
					cm.Data[kubeFenceEffectMarker] = crossing.EffectID
					cm.Data[kubeFenceEffectCount] = "1"
				}); err != nil {
					t.Fatal(err)
				}
			}
			// Capture the actual native commit version before subsequent writes.
			committed, err := a.configMap(ctx)
			if err != nil {
				t.Fatal(err)
			}
			custody, err := parseKubeCustody(committed)
			if err != nil || !custody.Equal(crossing) || committed.Data[kubeFenceEffectMarker] != crossing.EffectID || string(committed.UID) != a.uid {
				t.Fatal("native commit snapshot lost actual cause or enforcing-object identity")
			}
			if err := a.mutateCurrent(ctx, func(cm *corev1.ConfigMap) {
				cm.Data[kubeFenceAuthorityActive] = "true"
				if mask&1 == 0 {
					cm.Data[kubeFenceStateDigest] = "later-kubernetes-state"
				}
			}); err != nil {
				t.Fatal(err)
			}
			current, err := a.CurrentState(ctx, a.target)
			if err != nil {
				t.Fatal(err)
			}
			coords := [3]bool{
				committed.Data[kubeFenceAuthorityActive] == "true" && committed.Annotations[kubeFenceAdmissionBinding] == claim.Admission.BindingDigest,
				custody.AttemptID == claim.AttemptID && custody.Owner.Equal(claim.Executor),
				current.Equal(claim.Transition.To),
			}
			if coords != ([3]bool{mask&4 != 0, mask&2 != 0, mask&1 != 0}) || kubeNativeEffectCount(t, a) != 1 {
				t.Fatalf("native Kubernetes coordinates differ: %v", coords)
			}
			result := struct {
				Coordinates       [3]bool           `json:"coordinates_A_C_P"`
				ActualCommit      *corev1.ConfigMap `json:"actual_native_commit_version"`
				Current           r.State           `json:"current_state"`
				ExactEffectOracle bool              `json:"exact_effect_truth_oracle"`
				PortableProfile   string            `json:"portable_verifier_profile"`
				Retry             string            `json:"retry"`
			}{coords, committed, current, coords[0] && coords[1] && coords[2], "UNSUPPORTED: do not manufacture a PostgreSQL certificate", "no replay; effect already exists"}
			raw, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(raw))
			if root := os.Getenv("ACP_KUBE_ARTIFACT_DIR"); root != "" {
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, name+".json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
