package governedactionnormative

import "testing"

// R01 is strongest where its realities can be projected onto already-frozen
// K07 executable relations. This file deliberately does not add a compound
// relation. A missing projection remains an explicit proof boundary.
type r01K07Projection struct {
	id              string
	caseID          string
	wantDisposition string
}

func TestR01ProjectsOntoFrozenK07ExecutableRelations(t *testing.T) {
	set := loadK07ExecutionSet(t)
	byID := map[string]k07ExecutableCase{}
	for _, tc := range set.Cases {
		byID[tc.CaseID] = tc
	}

	projections := []r01K07Projection{
		{"R01-01", "CE3-R1-timeout-provider-substitution", "REJECT_SECOND_EFFECT"},
		{"R01-03", "CE6-R1-stale-worker-after-takeover", "REJECT_TAKEOVER_EFFECT"},
		{"R01-05", "CE7-R1-unrelated-change-as-success", "REJECT_FALSE_VERIFIED"},
		{"R01-06", "CE7-R1-unrelated-change-as-success", "REJECT_FALSE_VERIFIED"},
		{"R01-08", "CE7-A1-exact-postcondition-verified", "DISCHARGE_INTENDED_STATE_OBLIGATION"},
	}

	for _, p := range projections {
		p := p
		t.Run(p.id+"/"+p.caseID, func(t *testing.T) {
			tc, ok := byID[p.caseID]
			if !ok {
				t.Fatalf("frozen K07 relation %s missing", p.caseID)
			}
			got := evaluateK07(tc)
			if got.Disposition != p.wantDisposition {
				t.Fatalf("projection drift: got=%s want=%s", got.Disposition, p.wantDisposition)
			}
			if got.UnauthorizedEffects != 0 {
				t.Fatalf("projection emitted unauthorized effect: %+v", got)
			}
		})
	}
}

// These vectors have no exact one-relation projection in frozen K07. Keeping
// the boundary executable prevents the R01 adapter from silently claiming
// that K07 directly proves semantics it does not encode.
func TestR01ExplicitK07ProofBoundary(t *testing.T) {
	notDirectlyProjected := map[string]string{
		"R01-02": "authority revocation plus later compound progression is composed from currentness/admission, not one frozen K07 vector",
		"R01-04": "old plus duplicate webhook identity is observation-lineage composition, not one frozen K07 vector",
		"R01-07": "contradictory provider observations require composition of observation evidence; K07 has no direct contradiction vector",
	}
	f := loadR01(t)
	seen := map[string]bool{}
	for _, a := range f.Attacks {
		if _, ok := notDirectlyProjected[a.ID]; ok {
			seen[a.ID] = true
		}
	}
	for id, reason := range notDirectlyProjected {
		if !seen[id] || reason == "" {
			t.Fatalf("proof boundary lost for %s", id)
		}
	}
}
