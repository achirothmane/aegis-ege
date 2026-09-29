package ege

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalJSONExactCrossLanguageVectors(t *testing.T) {
	tests := []struct {
		name     string
		raw      json.RawMessage
		expected string
		digest   string
	}{
		{
			name:     "key order",
			raw:      json.RawMessage(`{"b":2,"a":1}`),
			expected: `{"a":1,"b":2}`,
			digest:   "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
		},
		{
			name:     "unicode html and separators",
			raw:      json.RawMessage(`{"unicode":"café 😀","html":"<&>","separator":"x\u2028y\u2029z"}`),
			expected: `{"html":"\u003c\u0026\u003e","separator":"x\u2028y\u2029z","unicode":"café 😀"}`,
			digest:   "7f2e599c014e92f6a70aad42b64deb3077b5489db77352a0d9898a283862761f",
		},
		{
			name:     "safe integers",
			raw:      json.RawMessage(`{"zero":0,"min":-9007199254740991,"max":9007199254740991}`),
			expected: `{"max":9007199254740991,"min":-9007199254740991,"zero":0}`,
			digest:   "b7b2401ddca2165824e98c61890c0aaec470258d3119dd265d02be9438bf47e6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := CanonicalJSON(tt.raw)
			if err != nil {
				t.Fatalf("CanonicalJSON() error = %v", err)
			}
			if string(body) != tt.expected {
				t.Fatalf("canonical bytes = %q, want %q", body, tt.expected)
			}
			if tt.digest != "" {
				sum := sha256.Sum256(body)
				if got := hex.EncodeToString(sum[:]); got != tt.digest {
					t.Fatalf("digest = %s, want %s", got, tt.digest)
				}
			}
		})
	}
}

func TestCanonicalJSONRejectsAmbiguousRepresentation(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		code string
	}{
		{"duplicate key", `{"a":1,"a":2}`, "CANONICAL_DUPLICATE_KEY"},
		{"fraction", `{"n":1.0}`, "CANONICAL_NON_INTEGER_NUMBER"},
		{"exponent", `{"n":1e0}`, "CANONICAL_NON_INTEGER_NUMBER"},
		{"negative zero", `{"n":-0}`, "CANONICAL_NEGATIVE_ZERO"},
		{"unsafe integer", `{"n":9007199254740992}`, "CANONICAL_INTEGER_OUT_OF_RANGE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CanonicalJSON(json.RawMessage(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.code) {
				t.Fatalf("error = %v, want %s", err, tt.code)
			}
		})
	}
}

func TestEBAArtifactRefIgnoresObjectKeyOrderOnly(t *testing.T) {
	left, err := EBAArtifactRef(json.RawMessage(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := EBAArtifactRef(json.RawMessage(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("refs differ: %s != %s", left, right)
	}
}
