package kernelfabric

import "context"

// DurableHeadAnchorState is a domain-agnostic monotonic exact-head commitment.
// Sequence is strictly monotonic; HeadDigest commits to the exact accepted
// durable object at that sequence.
type DurableHeadAnchorState struct {
	Sequence   uint64
	HeadDigest string
}

// DurableHeadAnchor must live outside the rollback domain of the writable state
// it protects.
type DurableHeadAnchor interface {
	Current(context.Context) (DurableHeadAnchorState, error)
	CompareAndAdvance(
		context.Context,
		DurableHeadAnchorState,
		DurableHeadAnchorState,
	) (DurableHeadAnchorState, error)
}
