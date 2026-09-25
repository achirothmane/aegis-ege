package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/falsification"
)

const timingIterations = 2000

func main() {
	corpus := falsification.CorpusV1()
	comparison := falsification.EvaluateCorpus(corpus)

	fmt.Println("StateLatch Moat Falsification Benchmark v1")
	fmt.Printf("Corpus: %d labeled synthetic scenarios\n\n", len(corpus))

	printMetrics("Baseline", comparison.Baseline)
	printMetrics("StateLatch", comparison.StateLatch)

	fmt.Println("\nDecision differences by category:")
	categoryDiffs := make(map[string]int)
	for _, result := range comparison.Cases {
		if result.Baseline.Decision != result.StateLatch.Decision {
			categoryDiffs[result.Category]++
		}
	}
	categories := make([]string, 0, len(categoryDiffs))
	for category := range categoryDiffs {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for _, category := range categories {
		fmt.Printf("  %-34s %d\n", category, categoryDiffs[category])
	}

	baselineDuration, baselineSink := timeSystem(corpus, false)
	stateDuration, stateSink := timeSystem(corpus, true)
	decisions := int64(timingIterations * len(corpus))

	fmt.Println("\nCPU-only decision-path timing (GitHub runner; not production latency):")
	fmt.Printf(
		"  baseline:   %s total, ~%d ns/scenario\n",
		baselineDuration,
		baselineDuration.Nanoseconds()/decisions,
	)
	fmt.Printf(
		"  StateLatch: %s total, ~%d ns/scenario\n",
		stateDuration,
		stateDuration.Nanoseconds()/decisions,
	)

	// Keep decision results observable so timing loops cannot be trivially
	// optimized away.
	if baselineSink+stateSink == -1 {
		panic("unreachable timing sink")
	}
}

func printMetrics(name string, m falsification.SystemMetrics) {
	fmt.Printf("%s:\n", name)
	fmt.Printf("  unsafe allows:                %d\n", m.UnsafeAllows)
	fmt.Printf("  unresolved/unknown allows:    %d\n", m.UnknownAllows)
	fmt.Printf("  safe blocks:                  %d\n", m.SafeBlocks)
	fmt.Printf("  safe escalations:             %d\n", m.SafeEscalations)
	fmt.Printf("  unsafe cases prevented:       %d\n", m.UnsafePrevented)
	fmt.Printf("  unknown cases prevented:      %d\n", m.UnknownPrevented)
	fmt.Printf(
		"  postflight divergence detect: %d/%d\n",
		m.OutcomeDivergencesDetected,
		m.OutcomeDivergences,
	)
	fmt.Printf("  active probe attempts:        %d\n", m.ProbeAttempts)
	fmt.Printf(
		"  decisions A/B/E:             %d/%d/%d\n",
		m.Allows,
		m.Blocks,
		m.Escalates,
	)
}

func timeSystem(corpus []falsification.Scenario, stateLatch bool) (time.Duration, int) {
	sink := 0
	start := time.Now()
	for i := 0; i < timingIterations; i++ {
		for _, scenario := range corpus {
			var eval falsification.Evaluation
			if stateLatch {
				eval = falsification.EvaluateStateLatch(scenario)
			} else {
				eval = falsification.EvaluateBaseline(scenario)
			}
			switch eval.Decision {
			case decision.Allow:
				sink += 1
			case decision.Block:
				sink += 2
			case decision.Escalate:
				sink += 3
			}
		}
	}
	return time.Since(start), sink
}
