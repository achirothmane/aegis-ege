package governedactionnormative

import (
	"context"
	"errors"
	"testing"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

// This is a supplemental bridge for the extracted relations, not a replacement
// oracle. All 28 original vectors still run through unchanged evaluateK07.
// Native CRM and PostgreSQL tests separately establish actual adapter behavior.
func TestD04ExtractedRelationsAgreeWithFrozenRevisionAndCustodyVectors(t *testing.T) {
	selected := map[string]error{
		"CE2-R1-revision-substitution": ga.ErrBindingChanged,
		"CE2-A1-exact-scope-reuse": nil,
		"CE4-R1-effect-before-custody": ga.ErrMissingCustody,
		"CE4-A1-custody-before-dispatch": nil,
	}
	seen := 0
	for _, tc := range loadK07ExecutionSet(t).Cases {
		want, ok := selected[tc.CaseID]
		if !ok { continue }
		seen++
		t.Run(tc.CaseID, func(t *testing.T) {
			admitted := ga.Binding{ActionRevision: tc.ActionRef, Target: "native-scope:" + tc.EffectID, Profile: "frozen-domain-profile/v1"}
			current := admitted
			if !tc.Input.RevisionExact { current.ActionRevision += ":substituted" }
			var retain func(context.Context) error
			custody := false
			if tc.Input.CustodyBeforeDispatch { retain = func(context.Context) error { custody = true; return nil } }
			effects := 0
			result, err := ga.Dispatch(context.Background(),
				func(context.Context) error { return ga.CheckBinding(admitted, current) },
				retain,
				func(context.Context) (int, error) {
					if !custody { t.Fatal("effect escaped before custody") }
					effects++
					return effects, nil
				},
			)
			oracle := evaluateK07(tc)
			if !errors.Is(err, want) || effects != oracle.AuthorizedEffects || result.BoundaryEntered != oracle.ValidTrace {
				t.Fatalf("library=%+v error=%v effects=%d; frozen=%+v", result, err, effects, oracle)
			}
		})
	}
	if seen != len(selected) { t.Fatalf("selected frozen vectors missing: %d/%d", seen, len(selected)) }
}
