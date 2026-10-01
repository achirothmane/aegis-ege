package kubeadapter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

type boundaryHookStore struct {
	DrainCheckpointStore
	writes int
	hook   func(int, DrainExecutionCheckpoint) error
}

func (s *boundaryHookStore) Save(ctx context.Context, checkpoint DrainExecutionCheckpoint) error {
	_, err := s.SaveVersioned(ctx, checkpoint)
	return err
}

func (s *boundaryHookStore) SaveVersioned(ctx context.Context, checkpoint DrainExecutionCheckpoint) (DrainExecutionCheckpoint, error) {
	s.writes++
	saved := checkpoint
	var err error
	if versioned, ok := s.DrainCheckpointStore.(VersionedDrainCheckpointStore); ok {
		saved, err = versioned.SaveVersioned(ctx, checkpoint)
	} else {
		err = s.DrainCheckpointStore.Save(ctx, checkpoint)
	}
	if err != nil {
		return DrainExecutionCheckpoint{}, err
	}
	if s.hook != nil {
		if err := s.hook(s.writes, saved); err != nil {
			return DrainExecutionCheckpoint{}, err
		}
	}
	return saved, nil
}

func TestCheckpointedSharedBoundaryRechecksAfterCustody(t *testing.T) {
	for _, phase := range []string{"cordon", "eviction"} {
		for _, fault := range []string{"expiry", "state-change", "lease-loss", "custody-ack-loss"} {
			t.Run(phase+"/"+fault, func(t *testing.T) {
				ctx := context.Background()
				now := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
				reader := executionReaderFixture()
				reader.node.UID = types.UID("shared-node-uid")
				executor := &stubDryRunExecutor{}
				executor.cordonApply = func(_, _ string) error {
					reader.node.Spec.Unschedulable = true
					reader.node.ResourceVersion = "928442"
					return nil
				}
				executor.evictApply = func(target PodStateRef) error {
					var remaining []corev1.Pod
					for _, pod := range reader.pods {
						if string(pod.UID) != target.UID {
							remaining = append(remaining, pod)
						}
					}
					reader.pods = remaining
					return nil
				}
				adapter := NewWithClockAndExperimentalMutations(&reader, executor, func() time.Time { return now })
				policy := defaultExecutionPolicy()
				prepared, err := adapter.PrepareNodeDrainExecution(ctx, "shared-fault", "node-7", policy)
				if err != nil || prepared.Authorization == nil {
					t.Fatalf("prepare: %+v, %v", prepared, err)
				}
				dir := filepath.Join(t.TempDir(), "custody")
				durable, err := NewFileDrainCheckpointStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				boundaryWrite := 2
				if phase == "eviction" {
					boundaryWrite = 4
				}
				store := &boundaryHookStore{DrainCheckpointStore: durable}
				store.hook = func(n int, _ DrainExecutionCheckpoint) error {
					if n != boundaryWrite {
						return nil
					}
					switch fault {
					case "expiry":
						now = prepared.Authorization.ValidUntil
					case "state-change":
						if phase == "cordon" {
							reader.node.ResourceVersion = "changed-after-custody"
						} else {
							reader.pods[0].UID = types.UID("replacement-pod-uid")
						}
					case "lease-loss":
						executor.lockRenewErr = ErrExecutionLockLost
					case "custody-ack-loss":
						return errors.New("custody persisted but acknowledgement lost")
					}
					return nil
				}
				report, err := adapter.ExecuteAuthorizedNodeDrainWithCheckpointStore(ctx, *prepared.Authorization, "node-7", policy, store)
				if err != nil || report.Decision == decision.Allow {
					t.Fatalf("boundary did not fail closed: %+v, %v", report, err)
				}
				wantCordons := 0
				if phase == "eviction" {
					wantCordons = 1
				}
				if executor.realCordons != wantCordons || len(executor.realEvictedPods) != 0 {
					t.Fatalf("unauthorized boundary entered: cordons=%d evictions=%v", executor.realCordons, executor.realEvictedPods)
				}
				// Reopen disk storage with no in-memory store state. The exact
				// original action/node/UID scope survives every injected fault.
				reopened, err := NewFileDrainCheckpointStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				custody, err := reopened.Load(ctx, "shared-fault")
				if err != nil || custody.NodeUID != "shared-node-uid" || len(custody.AuthorizedPods) != 2 || len(custody.CompletedPodUIDs) != 0 {
					t.Fatalf("original custody lost or fabricated completion: %+v, %v", custody, err)
				}
				if custody.Cordoned != (phase == "eviction") {
					t.Fatalf("custody fabricated cordon receipt: %+v", custody)
				}
			})
		}
	}
}
