//go:build integration

package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestKindM10ExternalHeadDetectsFullLocalRollback(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("KUBECONFIG is required")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	namespace := "state-latch-m10-head"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	})

	headStore, err := NewKubernetesHeadStore(client, namespace)
	if err != nil {
		t.Fatal(err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("kind-key-v1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyring := NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	anchorPath := filepath.Join(dir, "journal.anchor.json")
	j, err := CreateAnchoredFileJournal(ctx, path, anchorPath, "kind-m10-history", signer, keyring, headStore)
	if err != nil {
		t.Fatalf("CreateAnchoredFileJournal: %v", err)
	}

	if _, err := j.Append(ctx, testEvent("kind-one", "ALLOW")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(ctx, testEvent("kind-two", "ALLOW")); err != nil {
		t.Fatal(err)
	}

	oldJournal, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldAnchor, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := j.Append(ctx, testEvent("kind-three", "ALLOW")); err != nil {
		t.Fatal(err)
	}
	current, err := headStore.Load(ctx, mustReadAnchor(t, anchorPath).JournalID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Sequence != 3 {
		t.Fatalf("expected external sequence 3, got %+v", current)
	}

	if err := os.WriteFile(path, oldJournal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorPath, oldAnchor, 0o600); err != nil {
		t.Fatal(err)
	}

	// Local cryptography still accepts the restored historical pair.
	local, err := NewFileJournalWithSecurity(path, anchorPath, signer, keyring, nil)
	if err != nil {
		t.Fatalf("restored local pair should be internally valid: %v", err)
	}
	if got := local.Verify(ctx); !got.Valid || got.EntryCount != 2 {
		t.Fatalf("restored local pair should verify locally, got %+v", got)
	}

	// The independently retained Kubernetes head is newer and makes rollback
	// visible.
	got := j.Verify(ctx)
	if got.Valid || !strings.Contains(got.Error, "external journal head mismatch") {
		t.Fatalf("expected external anti-rollback mismatch, got %+v", got)
	}

	// Losing the entire local pair must not manufacture another witness
	// namespace. The native ConfigMap retains the same history identity/head.
	for _, p := range []string{path, anchorPath} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := OpenAnchoredFileJournal(ctx, path, anchorPath, "kind-m10-history", signer, keyring, headStore); !errors.Is(err, ErrJournalHistoryUnavailable) {
		t.Fatalf("native witness allowed absent local history to reopen: %v", err)
	}
	if _, err := CreateAnchoredFileJournal(ctx, path, anchorPath, "kind-m10-history", signer, keyring, headStore); !errors.Is(err, ErrJournalAlreadyExists) {
		t.Fatalf("native witness allowed history rebootstrap: %v", err)
	}
	retained, err := headStore.Load(ctx, current.JournalID)
	if err != nil || retained.Sequence != current.Sequence || retained.HeadHash != current.HeadHash || retained.KeyID != current.KeyID {
		t.Fatalf("native history reset attempt changed independent truth: head=%+v err=%v", retained, err)
	}
}

func mustReadAnchor(t *testing.T, path string) Anchor {
	t.Helper()
	anchor, err := readAnchor(path)
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}
