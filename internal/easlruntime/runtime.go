package easlruntime

import (
	"errors"
	"fmt"
	"sync"

	"github.com/achirothmane/easl"
)

var (
	ErrRuntimeUnavailable = errors.New("aegis-ege: Genesis-gated EASL runtime is unavailable")
	ErrRuntimeMismatch    = errors.New("aegis-ege: a different Genesis-gated EASL runtime is already bound")
)

var registry struct {
	sync.RWMutex
	runtime  *easl.Runtime
	metadata easl.RuntimeMetadata
}

// Bind installs the process-wide EASL runtime after Level -1 Genesis bootstrap.
// Binding is idempotent for the exact same Genesis identity and fail-closed for
// nil, unready, or conflicting runtimes.
func Bind(runtime *easl.Runtime) error {
	if runtime == nil {
		return ErrRuntimeUnavailable
	}
	metadata, err := runtime.Metadata()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeUnavailable, err)
	}

	registry.Lock()
	defer registry.Unlock()

	if registry.runtime == nil {
		registry.runtime = runtime
		registry.metadata = metadata
		return nil
	}
	if registry.metadata != metadata {
		return ErrRuntimeMismatch
	}
	return nil
}

func Evaluate(snapshot easl.Snapshot) (easl.Evaluation, error) {
	registry.RLock()
	runtime := registry.runtime
	registry.RUnlock()
	if runtime == nil {
		return easl.Evaluation{
			State:          easl.StateInvalid,
			EvidenceStatus: easl.EvidenceInsufficient,
		}, ErrRuntimeUnavailable
	}
	return runtime.Evaluate(snapshot)
}

func Metadata() (easl.RuntimeMetadata, error) {
	registry.RLock()
	defer registry.RUnlock()
	if registry.runtime == nil {
		return easl.RuntimeMetadata{}, ErrRuntimeUnavailable
	}
	return registry.metadata, nil
}
