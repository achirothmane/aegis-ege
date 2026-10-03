// aegis-evidence-inspect reads two local inputs. It has no network client,
// runtime adapter, signing key, database credential or mutation operation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/evidenceverify"
)

func readInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, evidenceverify.MaxInputBytes+1))
	if err == nil && len(data) > evidenceverify.MaxInputBytes {
		return nil, fmt.Errorf("input exceeds 8 MiB")
	}
	return data, err
}

func run() int {
	started := time.Now()
	bundle := flag.String("bundle", "", "existing exported evidence file")
	policy := flag.String("policy", "", "policy and roots supplied through your independent trusted channel")
	format := flag.String("format", "text", "text or json")
	flag.Parse()
	if *bundle == "" || *policy == "" || flag.NArg() != 0 || (*format != "text" && *format != "json") {
		flag.Usage()
		return 2
	}
	b, err := readInput(*bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	p, err := readInput(*policy)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	r := evidenceverify.Verify(b, p)
	if *format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		fmt.Printf("Result: %s\nHistory: %s\nClaim: %s (%s evidence)\nRequired claim: %s\nIntent: %s\nAttempt: %s\nEffect: %s\nAdmitted: %t\nAuthority at commitment: %s\nEffect evidence: %s\nCausality: %s\n", r.Closure, r.HistoricalTrust, r.ClaimType, r.Grade, r.RequiredClaimType, r.IntentID, r.AttemptID, r.EffectID, r.Admitted, r.AuthorityAtCommit, r.EffectEvidence, r.Causality)
		if r.AuthorityCurrentlyActive != nil {
			fmt.Printf("Authority active when observed: %t\n", *r.AuthorityCurrentlyActive)
		}
		if r.ExternallyCommittedEffects != nil {
			fmt.Printf("Committed effects in this case: %d\n", *r.ExternallyCommittedEffects)
		}
		if r.SuccessionValidity != "NOT_PROVIDED" {
			fmt.Printf("Authority and history handoff: %s\nRight to continue this history: %s\n", r.SuccessionValidity, r.CustodianAuthority)
			if r.CurrentCustodian != nil {
				fmt.Printf("Current history holder: %s (%s)\n", r.CurrentCustodian.ID, r.CurrentCustodian.Kind)
			}
			if r.EvidenceGrades != nil {
				fmt.Printf("Evidence: effect=%s; handoff=%s; bootstrap=%s\n", r.EvidenceGrades.Effect, r.EvidenceGrades.Succession, r.EvidenceGrades.Genesis)
			}
		}
		fmt.Printf("Structure: %s; signatures: %s; expected roots: %s\nClaims supported: %t\n", r.Structure, r.Signatures, r.TrustRoots, r.ClaimsSupported)
		if len(r.Uncertainty) > 0 {
			fmt.Printf("Uncertainty:\n- %s\n", strings.Join(r.Uncertainty, "\n- "))
		}
		if len(r.Errors) > 0 {
			fmt.Printf("Unsupported claims:\n- %s\n", strings.Join(r.Errors, "\n- "))
		}
	}
	fmt.Fprintf(os.Stderr, "Report completed in %s; two local files; read permission only\n", time.Since(started).Round(time.Millisecond))
	if !r.ClaimsSupported {
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
