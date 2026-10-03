package simulation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

// Signed but semantically false traces stay in the native verifier corpus.
// Valid signatures are deliberately retained in relation falsifications.
func falsifySuccessionBundle(t *testing.T, dir string, b v.Bundle, p v.Policy, keys map[string]ed25519.PrivateKey) {
	t.Helper()
	folder := filepath.Join(dir, "falsification")
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	type vector struct {
		name            string
		change          func(*v.Bundle, *v.Policy)
		validSignatures bool
	}
	resignWitness := func(bundle *v.Bundle, policy *v.Policy, change func(*v.SuccessionObservation)) {
		var o v.SuccessionObservation
		if err := json.Unmarshal(bundle.Succession.Witness.Payload, &o); err != nil {
			t.Fatal(err)
		}
		change(&o)
		env, err := v.Seal("succession_witness", policy.RoleKeys["succession_witness"], keys["succession_witness"], o)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Succession.Witness = env
	}
	vectors := []vector{
		{"early-new-policy", func(b *v.Bundle, p *v.Policy) {
			resignWitness(b, p, func(o *v.SuccessionObservation) { o.Transitions[0].After = o.Transitions[len(o.Transitions)-1].After })
		}, true},
		{"foreign-predecessor", func(b *v.Bundle, p *v.Policy) {
			resignWitness(b, p, func(o *v.SuccessionObservation) {
				o.HistoryBefore.HeadHash = v.ContentDigest([]byte("another history"))
			})
		}, true},
		{"missing-native-transition", func(b *v.Bundle, p *v.Policy) {
			resignWitness(b, p, func(o *v.SuccessionObservation) { o.Transitions = o.Transitions[1:] })
		}, true},
		{"wrong-current-custodian-key", func(b *v.Bundle, p *v.Policy) {
			resignWitness(b, p, func(o *v.SuccessionObservation) {
				for id, s := range o.Current {
					s.HistoryHead.KeyID = p.RoleKeys["old_history"]
					o.Current[id] = s
				}
			})
		}, true},
		{"different-authority-completion", func(b *v.Bundle, p *v.Policy) {
			resignWitness(b, p, func(o *v.SuccessionObservation) { o.AuthorityAfter.KeyID = "other-authority/rotation/other" })
		}, true},
		{"missing-independent-predecessor", func(b *v.Bundle, p *v.Policy) { p.Succession.OldCheckpoint = v.Head{} }, true},
		{"bundle-root-substitution", func(b *v.Bundle, p *v.Policy) { delete(p.PublicKeys, p.RoleKeys["new_genesis"]) }, false},
		{"mixed-Genesis-envelope", func(b *v.Bundle, p *v.Policy) {
			b.Succession.NewGenesis.CapabilityEnvelope = b.Succession.OldGenesis.CapabilityEnvelope
		}, true},
		{"unauthorized-custodian-identity", func(b *v.Bundle, p *v.Policy) { p.Succession.NewCustodian.ID = "unapproved replacement" }, true},
		{"composite-grade-inflation", func(b *v.Bundle, p *v.Policy) {
			var e v.Execution
			if err := json.Unmarshal(b.Execution.Payload, &e); err != nil {
				t.Fatal(err)
			}
			e.Grade = "native"
			env, err := v.Seal("execution", p.RoleKeys["execution"], keys["execution"], e)
			if err != nil {
				t.Fatal(err)
			}
			b.Execution = env
		}, true},
		{"recomputed-history-reset", func(b *v.Bundle, p *v.Policy) { b.History.Entries = b.History.Entries[1:] }, true},
		{"new-key-rewrites-predecessor", func(b *v.Bundle, p *v.Policy) {
			// A new, correctly authorized signer rehashes a replacement prefix
			// and signs its final anchor. Even a fresh trusted final checkpoint
			// cannot erase the independently retained predecessor commitment.
			prev := ""
			for i, raw := range b.History.Entries {
				var entry journal.Entry
				if err := json.Unmarshal(raw, &entry); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					entry.Event.PayloadDigest = v.ContentDigest([]byte("rewritten admission"))
				}
				entry.PrevHash = prev
				entry.EntryHash = ""
				payload, _ := json.Marshal(entry)
				entry.EntryHash = v.ContentDigest(payload)
				prev = entry.EntryHash
				b.History.Entries[i], _ = json.Marshal(entry)
			}
			var anchor journal.Anchor
			if err := json.Unmarshal(b.History.Anchor, &anchor); err != nil {
				t.Fatal(err)
			}
			anchor.HeadHash = prev
			anchor.Signature = ""
			payload, _ := json.Marshal(anchor)
			anchor.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(keys["history"], payload))
			b.History.Anchor, _ = json.Marshal(anchor)
			p.Checkpoint.HeadHash = prev
			witness, err := v.Seal("witness", p.RoleKeys["witness"], keys["witness"], v.Witness{BuildSHA: p.BuildSHA, CaseID: p.CaseID, Head: *p.Checkpoint})
			if err != nil {
				t.Fatal(err)
			}
			b.History.Witness = witness
			resignWitness(b, p, func(o *v.SuccessionObservation) {
				for id, s := range o.Current {
					if s.Policy.GenesisEpoch == 8 {
						s.HistoryHead = *p.Checkpoint
						o.Current[id] = s
					}
				}
			})
		}, true},
	}
	if p.CaseID == "UNKNOWN" {
		vectors = append(vectors, vector{"trusted-history-promoted-to-closed", func(b *v.Bundle, p *v.Policy) {
			var e v.Execution
			if err := json.Unmarshal(b.Execution.Payload, &e); err != nil {
				t.Fatal(err)
			}
			e.ClaimedClosure = "CLOSED"
			env, err := v.Seal("execution", p.RoleKeys["execution"], keys["execution"], e)
			if err != nil {
				t.Fatal(err)
			}
			b.Execution = env
		}, true})
	}
	baseBundle, _ := json.Marshal(b)
	basePolicy, _ := json.Marshal(p)
	for _, test := range vectors {
		t.Run("verifier/"+test.name, func(t *testing.T) {
			var b v.Bundle
			var p v.Policy
			if err := json.Unmarshal(baseBundle, &b); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(basePolicy, &p); err != nil {
				t.Fatal(err)
			}
			test.change(&b, &p)
			bundle, _ := json.Marshal(b)
			policy, _ := json.Marshal(p)
			r := v.Verify(bundle, policy)
			if r.ClaimsSupported || (test.validSignatures && r.Signatures != "VALID") {
				t.Fatalf("false signed composition accepted or signature oracle changed: %+v", r)
			}
			writeCompositeJSON(t, filepath.Join(folder, test.name+".bundle.json"), b)
			writeCompositeJSON(t, filepath.Join(folder, test.name+".policy.json"), p)
			writeCompositeJSON(t, filepath.Join(folder, test.name+".report.json"), r)
		})
	}
}
