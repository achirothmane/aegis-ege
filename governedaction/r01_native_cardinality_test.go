package governedaction_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/governedaction"
)

// nativeShipmentBoundary models the adapter-owned durable destination fence:
// EffectIdentity is unique at the destination. The mutex stands for the
// destination transaction/CAS critical section, not process-local admission.
// The mutation count is the externally durable shipment effect.
type nativeShipmentBoundary struct {
	mu      sync.Mutex
	effects map[string]struct{}
	count   atomic.Int64
}

func (b *nativeShipmentBoundary) create(effectID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.effects[effectID]; exists {
		return false
	}
	b.effects[effectID] = struct{}{}
	b.count.Add(1)
	return true
}

func TestR01DuplicateCallbacksInsideValidAuthorityProduceOneNativeEffect(t *testing.T) {
	const effectID = "effect:r01:e3"
	boundary := &nativeShipmentBoundary{effects: map[string]struct{}{}}
	validUntil := time.Now().Add(time.Minute)

	check := func(context.Context) error {
		return governedaction.CheckValidity(validUntil, time.Now())
	}
	retain := func(context.Context) error { return nil }

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := governedaction.Dispatch(context.Background(), check, retain, func(context.Context) (bool, error) {
				return boundary.create(effectID), nil
			})
			if err != nil {
				t.Errorf("dispatch failed while authority was current: %v", err)
				return
			}
			results <- r.Value
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for created := range results {
		if created {
			winners++
		}
	}
	if winners != 1 || boundary.count.Load() != 1 {
		t.Fatalf("R01-04 cardinality failure: winners=%d durable_effects=%d; want exactly one", winners, boundary.count.Load())
	}
}
