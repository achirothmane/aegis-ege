//go:build integration

package kubeadapter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

const (
	kubeFenceStateRevision   = "state_revision"
	kubeFenceStateDigest     = "state_digest"
	kubeFenceAuthorityActive = "authority_active"
	kubeFenceEffectMarker    = "effect_marker"
	kubeFenceEffectCount     = "effect_count"

	kubeFenceEffectID         = "aegis.openai.com/effect-id"
	kubeFenceAttemptID        = "aegis.openai.com/attempt-id"
	kubeFenceOwnerID          = "aegis.openai.com/owner-id"
	kubeFenceOwnerKind        = "aegis.openai.com/owner-kind"
	kubeFenceGeneration       = "aegis.openai.com/fence-generation"
	kubeFencePhase            = "aegis.openai.com/custody-phase"
	kubeFenceAdmissionBinding = "aegis.openai.com/admission-binding"
)

var (
	errKubeNativeFence       = errors.New("kubernetes native destination fence rejected stale owner or generation")
	errKubeNativeState       = errors.New("kubernetes native destination fence rejected stale semantic state")
	errKubeNativeAuthority   = errors.New("kubernetes native destination fence rejected inactive authority")
	errKubeNativeTransition  = errors.New("kubernetes native destination fence rejected transition substitution")
	errKubeNativeObservation = errors.New("kubernetes native destination observation missing exact effect")
	errKubeNativeUntrusted   = errors.New("kubernetes native destination attestation issuer is not trusted")
	errKubeNativeCAS         = errors.New("kubernetes native custody compare-and-swap failed")
	errKubeNativeConflict    = errors.New("kubernetes api-server resourceVersion rejected stale native mutation")
	errKubeNativeReplay      = errors.New("kubernetes native destination rejected exact effect replay")
	errKubeNativeTarget      = errors.New("kubernetes native destination target identity changed")
)

var (
	kubeNativePolicyIssuer   = gaRuntime.Identity{ID: "policy:native-kubernetes", Kind: "policy"}
	kubeNativeTakeoverIssuer = gaRuntime.Identity{ID: "controller:native-kubernetes", Kind: "controller"}
	kubeNativeObserverIssuer = gaRuntime.Identity{ID: "observer:native-kubernetes", Kind: "observer"}
)

type kubernetesNativeFenceAdapter struct {
	client    kubernetes.Interface
	namespace string
	name      string
	uid       string
	target    string
	req       gaRuntime.Request

	mu                 sync.Mutex
	beforeNativeUpdate func()
}

func (a *kubernetesNativeFenceAdapter) configMap(ctx context.Context) (*corev1.ConfigMap, error) {
	return a.client.CoreV1().ConfigMaps(a.namespace).Get(ctx, a.name, metav1.GetOptions{})
}

func (a *kubernetesNativeFenceAdapter) canonicalTarget(cm *corev1.ConfigMap) string {
	return fmt.Sprintf("k8s-configmap:%s/%s@%s", cm.Namespace, cm.Name, cm.UID)
}

func (a *kubernetesNativeFenceAdapter) CurrentState(ctx context.Context, target string) (gaRuntime.State, error) {
	cm, err := a.configMap(ctx)
	if err != nil {
		return gaRuntime.State{}, err
	}
	if string(cm.UID) != a.uid || a.canonicalTarget(cm) != target || target != a.target {
		return gaRuntime.State{}, errKubeNativeTarget
	}
	return gaRuntime.State{
		Target:   a.target,
		Revision: cm.Data[kubeFenceStateRevision],
		Digest:   cm.Data[kubeFenceStateDigest],
	}, nil
}

func (a *kubernetesNativeFenceAdapter) VerifyAttestation(ctx context.Context, att gaRuntime.Attestation, expected string) error {
	if att.BindingDigest != expected {
		return gaRuntime.ErrAdmissionBinding
	}
	switch {
	case att.Issuer.Equal(kubeNativePolicyIssuer):
		cm, err := a.configMap(ctx)
		if err != nil {
			return err
		}
		if string(cm.UID) != a.uid {
			return errKubeNativeTarget
		}
		if cm.Data[kubeFenceAuthorityActive] != "true" {
			return errKubeNativeAuthority
		}
		return nil
	case att.Issuer.Equal(kubeNativeTakeoverIssuer), att.Issuer.Equal(kubeNativeObserverIssuer):
		return nil
	default:
		return errKubeNativeUntrusted
	}
}

func (a *kubernetesNativeFenceAdapter) ReserveFencedCustody(ctx context.Context, custody gaRuntime.FencedCustody) error {
	cm, err := a.configMap(ctx)
	if err != nil {
		return err
	}
	if _, ok := cm.Annotations[kubeFenceEffectID]; ok {
		return errKubeNativeCAS
	}
	setKubeCustody(cm, custody)
	cm.Annotations[kubeFenceAdmissionBinding] = a.req.Admission.BindingDigest
	_, err = a.client.CoreV1().ConfigMaps(a.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return errKubeNativeCAS
	}
	return err
}

func (a *kubernetesNativeFenceAdapter) LoadFencedCustody(ctx context.Context, effectID, attemptID string) (gaRuntime.FencedCustody, error) {
	cm, err := a.configMap(ctx)
	if err != nil {
		return gaRuntime.FencedCustody{}, err
	}
	custody, err := parseKubeCustody(cm)
	if err != nil {
		return gaRuntime.FencedCustody{}, err
	}
	if custody.EffectID != effectID || custody.AttemptID != attemptID {
		return gaRuntime.FencedCustody{}, errKubeNativeFence
	}
	return custody, nil
}

func (a *kubernetesNativeFenceAdapter) TransitionFencedCustodyCAS(
	ctx context.Context,
	expected gaRuntime.FencedCustody,
	next gaRuntime.FencedCustody,
) error {
	cm, err := a.configMap(ctx)
	if err != nil {
		return err
	}
	current, err := parseKubeCustody(cm)
	if err != nil {
		return err
	}
	if !current.Equal(expected) {
		return errKubeNativeCAS
	}
	setKubeCustody(cm, next)
	_, err = a.client.CoreV1().ConfigMaps(a.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return errKubeNativeCAS
	}
	return err
}

// ExecuteFenced uses one Kubernetes object as the complete native destination
// record: target semantic state, authority state, fencing owner/generation,
// custody phase, and effect marker are co-located in the same ConfigMap.
//
// The API server's resourceVersion precondition on Update is therefore the
// linearization point. If takeover, state drift, or authority revocation occurs
// after this method reads and checks the object, that competing write changes
// resourceVersion and the stale effect write is rejected by Kubernetes itself.
func (a *kubernetesNativeFenceAdapter) ExecuteFenced(
	ctx context.Context,
	transition gaRuntime.Transition,
	custody gaRuntime.FencedCustody,
) (gaRuntime.Acceptance, error) {
	if transition.Operation != a.req.Transition.Operation ||
		!transition.From.Equal(a.req.Transition.From) ||
		!transition.To.Equal(a.req.Transition.To) {
		return gaRuntime.Acceptance{}, errKubeNativeTransition
	}

	cm, err := a.configMap(ctx)
	if err != nil {
		return gaRuntime.Acceptance{}, err
	}
	if string(cm.UID) != a.uid || a.canonicalTarget(cm) != a.target {
		return gaRuntime.Acceptance{}, errKubeNativeTarget
	}
	currentCustody, err := parseKubeCustody(cm)
	if err != nil {
		return gaRuntime.Acceptance{}, err
	}
	if !currentCustody.Equal(custody) || currentCustody.Phase != gaRuntime.CustodyCrossing {
		return gaRuntime.Acceptance{}, errKubeNativeFence
	}
	if cm.Annotations[kubeFenceAdmissionBinding] != a.req.Admission.BindingDigest {
		return gaRuntime.Acceptance{}, errKubeNativeFence
	}
	if cm.Data[kubeFenceAuthorityActive] != "true" {
		return gaRuntime.Acceptance{}, errKubeNativeAuthority
	}
	if cm.Data[kubeFenceEffectMarker] != "" {
		return gaRuntime.Acceptance{}, errKubeNativeReplay
	}
	if cm.Data[kubeFenceStateRevision] != transition.From.Revision ||
		cm.Data[kubeFenceStateDigest] != transition.From.Digest {
		return gaRuntime.Acceptance{}, errKubeNativeState
	}

	a.mu.Lock()
	hook := a.beforeNativeUpdate
	a.beforeNativeUpdate = nil
	a.mu.Unlock()
	if hook != nil {
		hook()
	}

	cm.Data[kubeFenceStateRevision] = transition.To.Revision
	cm.Data[kubeFenceStateDigest] = transition.To.Digest
	cm.Data[kubeFenceEffectMarker] = custody.EffectID
	count, _ := strconv.Atoi(cm.Data[kubeFenceEffectCount])
	cm.Data[kubeFenceEffectCount] = strconv.Itoa(count + 1)

	updated, err := a.client.CoreV1().ConfigMaps(a.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return gaRuntime.Acceptance{}, errKubeNativeConflict
	}
	if err != nil {
		return gaRuntime.Acceptance{}, err
	}
	if string(updated.UID) != a.uid {
		return gaRuntime.Acceptance{}, errKubeNativeTarget
	}
	return gaRuntime.Acceptance{Reference: "kubernetes-native:" + custody.EffectID}, nil
}

func (a *kubernetesNativeFenceAdapter) ObserveFenced(
	ctx context.Context,
	transition gaRuntime.Transition,
	custody gaRuntime.FencedCustody,
) (gaRuntime.Observation, error) {
	cm, err := a.configMap(ctx)
	if err != nil {
		return gaRuntime.Observation{}, err
	}
	if string(cm.UID) != a.uid ||
		cm.Data[kubeFenceEffectMarker] != custody.EffectID ||
		cm.Data[kubeFenceEffectCount] != "1" {
		return gaRuntime.Observation{}, errKubeNativeObservation
	}
	state := gaRuntime.State{
		Target:   a.target,
		Revision: cm.Data[kubeFenceStateRevision],
		Digest:   cm.Data[kubeFenceStateDigest],
	}
	binding := gaRuntime.ObservationBindingDigest(custody.EffectID, state)
	return gaRuntime.Observation{
		State: state,
		Attestation: gaRuntime.Attestation{
			ID:            "observation:native-kubernetes",
			Issuer:        kubeNativeObserverIssuer,
			BindingDigest: binding,
		},
	}, nil
}

func setKubeCustody(cm *corev1.ConfigMap, custody gaRuntime.FencedCustody) {
	if cm.Annotations == nil {
		cm.Annotations = map[string]string{}
	}
	cm.Annotations[kubeFenceEffectID] = custody.EffectID
	cm.Annotations[kubeFenceAttemptID] = custody.AttemptID
	cm.Annotations[kubeFenceOwnerID] = custody.Owner.ID
	cm.Annotations[kubeFenceOwnerKind] = custody.Owner.Kind
	cm.Annotations[kubeFenceGeneration] = strconv.FormatUint(custody.Generation, 10)
	cm.Annotations[kubeFencePhase] = string(custody.Phase)
}

func parseKubeCustody(cm *corev1.ConfigMap) (gaRuntime.FencedCustody, error) {
	if cm.Annotations == nil {
		return gaRuntime.FencedCustody{}, errKubeNativeFence
	}
	generation, err := strconv.ParseUint(cm.Annotations[kubeFenceGeneration], 10, 64)
	if err != nil || generation == 0 {
		return gaRuntime.FencedCustody{}, errKubeNativeFence
	}
	custody := gaRuntime.FencedCustody{
		EffectID:  cm.Annotations[kubeFenceEffectID],
		AttemptID: cm.Annotations[kubeFenceAttemptID],
		Target:    fmt.Sprintf("k8s-configmap:%s/%s@%s", cm.Namespace, cm.Name, cm.UID),
		Owner: gaRuntime.Identity{
			ID:   cm.Annotations[kubeFenceOwnerID],
			Kind: cm.Annotations[kubeFenceOwnerKind],
		},
		Generation: generation,
		Phase:      gaRuntime.CustodyPhase(cm.Annotations[kubeFencePhase]),
	}
	if !custody.Complete() {
		return gaRuntime.FencedCustody{}, errKubeNativeFence
	}
	return custody, nil
}

func kubeNativeRequest(t *testing.T, target string) gaRuntime.Request {
	t.Helper()
	from := gaRuntime.State{
		Target:   target,
		Revision: "rev:1",
		Digest:   "sha256:kube-native-state-1",
	}
	to := gaRuntime.State{
		Target:   target,
		Revision: "rev:2",
		Digest:   "sha256:kube-native-state-2",
	}
	req := gaRuntime.Request{
		Subject:    gaRuntime.Identity{ID: "subject:kube-native-001", Kind: "service"},
		Executor:   gaRuntime.Identity{ID: "executor:A", Kind: "worker"},
		Current:    from,
		Transition: gaRuntime.Transition{Operation: "kubernetes-configmap-effect", From: from, To: to},
		AttemptID:  "attempt:kube-native-001",
		Admission: gaRuntime.Attestation{
			ID:     "admission:kube-native-001",
			Issuer: kubeNativePolicyIssuer,
		},
	}
	binding, err := gaRuntime.AdmissionBindingDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Admission.BindingDigest = binding
	return req
}

func setupKubernetesNativeFence(t *testing.T) (*kubernetesNativeFenceAdapter, gaRuntime.Request) {
	t.Helper()
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Fatal("KUBECONFIG is required for Kubernetes native destination fencing proof")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(t.Name()))
	namespace := fmt.Sprintf("aegis-kube-fence-%x", sum[:5])
	ctx := context.Background()
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	})

	created, err := client.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "governed-target", Namespace: namespace},
		Data: map[string]string{
			kubeFenceStateRevision:   "rev:1",
			kubeFenceStateDigest:     "sha256:kube-native-state-1",
			kubeFenceAuthorityActive: "true",
			kubeFenceEffectMarker:    "",
			kubeFenceEffectCount:     "0",
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	adapter := &kubernetesNativeFenceAdapter{
		client:    client,
		namespace: namespace,
		name:      created.Name,
		uid:       string(created.UID),
	}
	adapter.target = adapter.canonicalTarget(created)
	req := kubeNativeRequest(t, adapter.target)
	adapter.req = req
	return adapter, req
}

func (a *kubernetesNativeFenceAdapter) mutateCurrent(
	ctx context.Context,
	mutate func(*corev1.ConfigMap),
) error {
	cm, err := a.configMap(ctx)
	if err != nil {
		return err
	}
	mutate(cm)
	_, err = a.client.CoreV1().ConfigMaps(a.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func kubeNativeEffectCount(t *testing.T, adapter *kubernetesNativeFenceAdapter) int {
	t.Helper()
	cm, err := adapter.configMap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count, err := strconv.Atoi(cm.Data[kubeFenceEffectCount])
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func kubeNativeTakeoverRequest(
	t *testing.T,
	original gaRuntime.Request,
	current gaRuntime.FencedCustody,
	newOwner gaRuntime.Identity,
) gaRuntime.TakeoverRequest {
	t.Helper()
	return gaRuntime.TakeoverRequest{
		Original: original,
		NewOwner: newOwner,
		Authorization: gaRuntime.Attestation{
			ID:            "takeover:native-kubernetes",
			Issuer:        kubeNativeTakeoverIssuer,
			BindingDigest: gaRuntime.TakeoverBindingDigest(current, newOwner),
		},
	}
}

func TestKindNativeDestinationFenceRejectsStaleOwnerAfterTakeover(t *testing.T) {
	adapter, req := setupKubernetesNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	ownerB := gaRuntime.Identity{ID: "executor:B", Kind: "worker"}
	taken, err := gaRuntime.TakeoverReserved(ctx, kubeNativeTakeoverRequest(t, req, prep.Custody, ownerB), adapter)
	if err != nil {
		t.Fatal(err)
	}
	if taken.Current.Generation != 2 || !taken.Current.Owner.Equal(ownerB) {
		t.Fatalf("unexpected takeover: %+v", taken)
	}

	staleA := prep.Custody
	staleA.Phase = gaRuntime.CustodyCrossing
	if _, err := adapter.ExecuteFenced(ctx, req.Transition, staleA); !errors.Is(err, errKubeNativeFence) {
		t.Fatalf("stale A reached Kubernetes destination: %v", err)
	}
	if got := kubeNativeEffectCount(t, adapter); got != 0 {
		t.Fatalf("stale A produced %d native effects", got)
	}

	reqB := req
	reqB.Executor = ownerB
	result := gaRuntime.ExecuteReservedFenced(ctx, reqB, taken.Current, adapter)
	if result.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("current owner did not close exact effect: %+v", result)
	}
	if got := kubeNativeEffectCount(t, adapter); got != 1 {
		t.Fatalf("expected one native effect, got %d", got)
	}
	if result.Custody.Generation != 2 || result.Custody.Phase != gaRuntime.CustodyClosed {
		t.Fatalf("unexpected closed custody: %+v", result.Custody)
	}
}

func TestKindNativeDestinationFenceRejectsStateRaceAtAPIServerCAS(t *testing.T) {
	adapter, req := setupKubernetesNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	adapter.beforeNativeUpdate = func() {
		if err := adapter.mutateCurrent(ctx, func(cm *corev1.ConfigMap) {
			cm.Data[kubeFenceStateRevision] = "rev:drift"
			cm.Data[kubeFenceStateDigest] = "sha256:drift"
		}); err != nil {
			t.Fatalf("inject semantic state race: %v", err)
		}
	}

	result := gaRuntime.ExecuteReservedFenced(ctx, req, prep.Custody, adapter)
	if !result.BoundaryEntered || result.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("native state race was not represented conservatively: %+v", result)
	}
	if !errors.Is(result.EffectError, errKubeNativeConflict) {
		t.Fatalf("api server did not reject stale resourceVersion after state race: %+v", result)
	}
	if got := kubeNativeEffectCount(t, adapter); got != 0 {
		t.Fatalf("state race produced %d native effects", got)
	}
	if result.Custody.Phase != gaRuntime.CustodyUnknown {
		t.Fatalf("rejected callback reopened custody: %+v", result.Custody)
	}
}

func TestKindNativeDestinationFenceRejectsAuthorityRaceAtAPIServerCAS(t *testing.T) {
	adapter, req := setupKubernetesNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	adapter.beforeNativeUpdate = func() {
		if err := adapter.mutateCurrent(ctx, func(cm *corev1.ConfigMap) {
			cm.Data[kubeFenceAuthorityActive] = "false"
		}); err != nil {
			t.Fatalf("inject authority race: %v", err)
		}
	}

	result := gaRuntime.ExecuteReservedFenced(ctx, req, prep.Custody, adapter)
	if !result.BoundaryEntered || result.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("native authority race was not represented conservatively: %+v", result)
	}
	if !errors.Is(result.EffectError, errKubeNativeConflict) {
		t.Fatalf("api server did not reject stale resourceVersion after authority race: %+v", result)
	}
	if got := kubeNativeEffectCount(t, adapter); got != 0 {
		t.Fatalf("authority race produced %d native effects", got)
	}
	if result.Custody.Phase != gaRuntime.CustodyUnknown {
		t.Fatalf("rejected callback reopened custody: %+v", result.Custody)
	}
}

func TestKindNativeDestinationFenceRejectsExactTokenReplay(t *testing.T) {
	adapter, req := setupKubernetesNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}
	crossing := prep.Custody
	crossing.Phase = gaRuntime.CustodyCrossing
	if err := adapter.TransitionFencedCustodyCAS(ctx, prep.Custody, crossing); err != nil {
		t.Fatal(err)
	}

	if _, err := adapter.ExecuteFenced(ctx, req.Transition, crossing); err != nil {
		t.Fatalf("first exact native effect failed: %v", err)
	}
	if _, err := adapter.ExecuteFenced(ctx, req.Transition, crossing); !errors.Is(err, errKubeNativeReplay) {
		t.Fatalf("exact token replay was not rejected by native destination: %v", err)
	}
	if got := kubeNativeEffectCount(t, adapter); got != 1 {
		t.Fatalf("exact token replay changed cardinality: %d", got)
	}
}

func TestKindSeparateLeaseCannotNativelyFenceTargetMutation(t *testing.T) {
	adapter, _ := setupKubernetesNativeFence(t)
	ctx := context.Background()

	holderA := "executor:A"
	transitions1 := int32(1)
	lease, err := adapter.client.CoordinationV1().Leases(adapter.namespace).Create(ctx, &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: "separate-fence", Namespace: adapter.namespace},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:    &holderA,
			LeaseTransitions: &transitions1,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	staleTarget, err := adapter.configMap(ctx)
	if err != nil {
		t.Fatal(err)
	}

	holderB := "executor:B"
	transitions2 := int32(2)
	lease.Spec.HolderIdentity = &holderB
	lease.Spec.LeaseTransitions = &transitions2
	if _, err := adapter.client.CoordinationV1().Leases(adapter.namespace).Update(
		ctx,
		lease,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatalf("take over separate Lease: %v", err)
	}

	// Counterexample: the target object did not participate in the Lease update,
	// so its resourceVersion is still current. A stale A mutation can therefore
	// be accepted by the API server even though B owns the separate fence.
	staleTarget.Data[kubeFenceEffectMarker] = "stale-A-effect"
	staleTarget.Data[kubeFenceEffectCount] = "1"
	if _, err := adapter.client.CoreV1().ConfigMaps(adapter.namespace).Update(
		ctx,
		staleTarget,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatalf("expected split-object stale mutation to remain admissible, got %v", err)
	}

	current, err := adapter.configMap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Data[kubeFenceEffectMarker] != "stale-A-effect" {
		t.Fatalf("split-object counterexample did not reach destination: %+v", current.Data)
	}
	if current.ResourceVersion == "" || strings.TrimSpace(current.ResourceVersion) == "" {
		t.Fatal("expected Kubernetes resourceVersion evidence")
	}
}
