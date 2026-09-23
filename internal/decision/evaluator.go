package decision

// Evaluate is intentionally incomplete.
//
// v0.1 starts contract-first. The first implementation step will enforce
// evidence freshness before any higher-level scoring or authorization logic.
func Evaluate(req Request) Result {
	return Result{Decision: Allow}
}
