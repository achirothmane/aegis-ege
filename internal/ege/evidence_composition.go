package ege

import (
	"sort"
	"strings"
)

// EvidenceIndependenceRequirement is the domain-agnostic predicate used to
// assess whether evidence sources are independent enough for a caller's
// consequence class. It deliberately knows nothing about permits, GPUs,
// Kubernetes, billing, or settlement.
type EvidenceIndependenceRequirement struct {
	RequiredIndependence    EvidenceIndependenceStatus
	MinIndependentSources   int
	RequiredDependencyKinds []string
}

// AssessEvidenceIndependence evaluates declared producer, observation-path,
// dependency, and assurance relationships. Source names and trust-domain labels
// are descriptive only; they cannot manufacture independent failure domains.
func AssessEvidenceIndependence(
	sources []EvidenceSource,
	requirement EvidenceIndependenceRequirement,
) EvidenceCompositionAssessment {
	required := requirement.RequiredIndependence
	if required == "" {
		required = EvidenceIndependenceUnknown
	}
	assessment := EvidenceCompositionAssessment{
		ProfileVersion:       EvidenceCompositionProfileVersion,
		RequiredIndependence: required,
		OverallIndependence: overallEvidenceIndependence(
			sources,
			requirement.RequiredDependencyKinds,
		),
	}

	for i := 0; i < len(sources); i++ {
		for j := i + 1; j < len(sources); j++ {
			assessment.PairAssessments = append(
				assessment.PairAssessments,
				assessEvidencePair(
					sources[i],
					sources[j],
					requirement.RequiredDependencyKinds,
				),
			)
		}
	}

	if requirement.MinIndependentSources > 0 {
		assessment.IndependentSourceCount = maxQualifyingIndependentSourceCount(
			sources,
			assessment.PairAssessments,
			requirement.RequiredIndependence,
		)
	}
	return assessment
}

// EvidenceIndependenceSatisfied answers only the configured independence
// threshold. Other composition constraints such as required source names and
// trust-domain diversity remain caller-owned.
func EvidenceIndependenceSatisfied(
	assessment EvidenceCompositionAssessment,
	requirement EvidenceIndependenceRequirement,
) bool {
	if requirement.MinIndependentSources <= 0 {
		return true
	}
	switch requirement.RequiredIndependence {
	case EvidenceIndependenceAsserted, EvidenceIndependenceCorroborated:
	default:
		return false
	}
	return assessment.IndependentSourceCount >= requirement.MinIndependentSources
}

func assessEvidencePair(
	left EvidenceSource,
	right EvidenceSource,
	requiredDependencyKinds []string,
) EvidencePairAssessment {
	assessment := EvidencePairAssessment{
		LeftSource:  left.Name,
		RightSource: right.Name,
	}
	if left.Declaration == nil || right.Declaration == nil {
		assessment.Status = EvidenceIndependenceUnknown
		assessment.ReasonCodes = []string{"MISSING_DECLARATION"}
		return assessment
	}
	if left.Declaration.Subject != right.Declaration.Subject {
		assessment.Status = EvidenceIndependenceUnknown
		assessment.ReasonCodes = []string{"SUBJECT_MISMATCH"}
		return assessment
	}
	if !declarationCovers(left.Declaration, requiredDependencyKinds) ||
		!declarationCovers(right.Declaration, requiredDependencyKinds) {
		assessment.Status = EvidenceIndependenceUnknown
		assessment.ReasonCodes = []string{"DEPENDENCY_COVERAGE_UNKNOWN"}
		return assessment
	}
	if left.Declaration.ProducerID == right.Declaration.ProducerID {
		assessment.Status = EvidenceIndependenceDependent
		assessment.ReasonCodes = []string{"SHARED_PRODUCER"}
		return assessment
	}
	if left.Declaration.ObservationPath == right.Declaration.ObservationPath {
		assessment.Status = EvidenceIndependenceDependent
		assessment.ReasonCodes = []string{"SHARED_OBSERVATION_PATH"}
		return assessment
	}

	shared := sharedMaterialDependencies(
		left.Declaration.Dependencies,
		right.Declaration.Dependencies,
	)
	if len(shared) > 0 {
		assessment.Status = EvidenceIndependenceDependent
		assessment.SharedDependencies = shared
		assessment.ReasonCodes = []string{"SHARED_MATERIAL_DEPENDENCY"}
		return assessment
	}

	if left.Declaration.Assurance == EvidenceDeclarationUnknown ||
		right.Declaration.Assurance == EvidenceDeclarationUnknown {
		assessment.Status = EvidenceIndependenceUnknown
		assessment.ReasonCodes = []string{"DECLARATION_ASSURANCE_UNKNOWN"}
		return assessment
	}
	if left.Declaration.Assurance == EvidenceDeclarationCorroborated &&
		right.Declaration.Assurance == EvidenceDeclarationCorroborated {
		assessment.Status = EvidenceIndependenceCorroborated
		return assessment
	}
	assessment.Status = EvidenceIndependenceAsserted
	return assessment
}

func overallEvidenceIndependence(
	sources []EvidenceSource,
	requiredDependencyKinds []string,
) EvidenceIndependenceStatus {
	if len(sources) < 2 {
		return EvidenceIndependenceUnknown
	}
	status := EvidenceIndependenceCorroborated
	for i := 0; i < len(sources); i++ {
		for j := i + 1; j < len(sources); j++ {
			pair := assessEvidencePair(
				sources[i],
				sources[j],
				requiredDependencyKinds,
			)
			switch pair.Status {
			case EvidenceIndependenceDependent:
				return EvidenceIndependenceDependent
			case EvidenceIndependenceUnknown:
				status = EvidenceIndependenceUnknown
			case EvidenceIndependenceAsserted:
				if status == EvidenceIndependenceCorroborated {
					status = EvidenceIndependenceAsserted
				}
			}
		}
	}
	return status
}

func maxQualifyingIndependentSourceCount(
	sources []EvidenceSource,
	pairs []EvidencePairAssessment,
	required EvidenceIndependenceStatus,
) int {
	if len(sources) == 0 {
		return 0
	}
	if len(sources) == 1 {
		return 1
	}

	pairStatus := make(map[string]EvidenceIndependenceStatus, len(pairs))
	for _, pair := range pairs {
		pairStatus[pairKey(pair.LeftSource, pair.RightSource)] = pair.Status
	}

	best := 0
	var search func(int, []int)
	search = func(next int, selected []int) {
		if len(selected)+(len(sources)-next) <= best {
			return
		}
		if next == len(sources) {
			if len(selected) > best {
				best = len(selected)
			}
			return
		}

		qualifies := true
		for _, existing := range selected {
			status := pairStatus[pairKey(sources[existing].Name, sources[next].Name)]
			if !independenceMeets(status, required) {
				qualifies = false
				break
			}
		}
		if qualifies {
			search(next+1, append(selected, next))
		}
		search(next+1, selected)
	}
	search(0, nil)
	return best
}

func independenceMeets(
	actual EvidenceIndependenceStatus,
	required EvidenceIndependenceStatus,
) bool {
	switch required {
	case EvidenceIndependenceAsserted:
		return actual == EvidenceIndependenceAsserted ||
			actual == EvidenceIndependenceCorroborated
	case EvidenceIndependenceCorroborated:
		return actual == EvidenceIndependenceCorroborated
	default:
		return false
	}
}

func pairKey(left, right string) string {
	if left > right {
		left, right = right, left
	}
	return left + "\x00" + right
}

func declarationCovers(
	declaration *EvidenceSourceDeclaration,
	requiredDependencyKinds []string,
) bool {
	if declaration == nil ||
		strings.TrimSpace(declaration.ProducerID) == "" ||
		strings.TrimSpace(declaration.Subject) == "" ||
		strings.TrimSpace(declaration.ObservationPath) == "" {
		return false
	}
	coverage := make(map[string]struct{}, len(declaration.DependencyCoverage))
	for _, kind := range declaration.DependencyCoverage {
		coverage[kind] = struct{}{}
	}
	for _, required := range requiredDependencyKinds {
		if _, ok := coverage[required]; !ok {
			return false
		}
	}
	return true
}

func sharedMaterialDependencies(
	left []EvidenceDependency,
	right []EvidenceDependency,
) []EvidenceDependency {
	rightSet := make(map[string]EvidenceDependency)
	for _, dependency := range right {
		if !dependency.Material {
			continue
		}
		rightSet[dependency.Kind+"\x00"+dependency.ID] = dependency
	}
	shared := make([]EvidenceDependency, 0)
	seen := make(map[string]struct{})
	for _, dependency := range left {
		if !dependency.Material {
			continue
		}
		key := dependency.Kind + "\x00" + dependency.ID
		if _, ok := rightSet[key]; !ok {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		shared = append(shared, dependency)
	}
	sort.Slice(shared, func(i, j int) bool {
		if shared[i].Kind != shared[j].Kind {
			return shared[i].Kind < shared[j].Kind
		}
		return shared[i].ID < shared[j].ID
	})
	return shared
}
