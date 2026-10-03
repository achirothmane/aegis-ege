package genesisbootstrap

import (
	"errors"

	"github.com/achirothmane/aegis-ege/internal/journal"
)

// VerifiedGenesisPin is an opaque capability emitted only after the production
// Genesis verifier reaches BOOTSTRAP_READY for the exact manifest loaded by
// that verification. Callers cannot populate its trust-bearing fields.
type VerifiedGenesisPin struct {
	ready                  bool
	genesisEpoch           uint64
	capabilityEnvelopeHash string
	manifestPayloadHash    string
}

func (p VerifiedGenesisPin) GenesisEpoch() uint64 {
	if !p.ready {
		return 0
	}
	return p.genesisEpoch
}

func (p VerifiedGenesisPin) CapabilityEnvelopeHash() string {
	if !p.ready {
		return ""
	}
	return p.capabilityEnvelopeHash
}

func (p VerifiedGenesisPin) ManifestPayloadHash() string {
	if !p.ready {
		return ""
	}
	return p.manifestPayloadHash
}

// ParseQuorumBinding is the production-safe bridge from a successfully
// verified Level -1 Genesis state to the journal quorum constructor. The
// capability envelope must be byte-for-byte the artifact pinned by Genesis.
func (p VerifiedGenesisPin) ParseQuorumBinding(
	capabilityEnvelope []byte,
) (journal.GenesisQuorumBinding, error) {
	if !p.ready ||
		p.genesisEpoch == 0 ||
		p.capabilityEnvelopeHash == "" ||
		p.manifestPayloadHash == "" {
		return journal.GenesisQuorumBinding{}, errors.New(
			"verified Genesis pin is unavailable",
		)
	}
	return journal.ParseGenesisQuorumBinding(
		capabilityEnvelope,
		p.capabilityEnvelopeHash,
	)
}


func (p VerifiedGenesisPin) ParseEnrollmentSuccessorGovernanceBinding(
	capabilityEnvelope []byte,
) (journal.GenesisEnrollmentSuccessorGovernanceBinding, error) {
	if !p.ready ||
		p.genesisEpoch == 0 ||
		p.capabilityEnvelopeHash == "" ||
		p.manifestPayloadHash == "" {
		return journal.GenesisEnrollmentSuccessorGovernanceBinding{}, errors.New(
			"verified Genesis pin is unavailable",
		)
	}
	return journal.ParseGenesisEnrollmentSuccessorGovernanceBinding(
		capabilityEnvelope,
		p.capabilityEnvelopeHash,
		p.genesisEpoch,
	)
}

func verifiedGenesisPin(
	genesisEpoch uint64,
	capabilityEnvelopeHash string,
	manifestPayloadHash string,
) (VerifiedGenesisPin, error) {
	if genesisEpoch == 0 ||
		capabilityEnvelopeHash == "" ||
		manifestPayloadHash == "" {
		return VerifiedGenesisPin{}, errors.New(
			"verified Genesis pin requires epoch and cryptographic bindings",
		)
	}
	return VerifiedGenesisPin{
		ready:                  true,
		genesisEpoch:           genesisEpoch,
		capabilityEnvelopeHash: capabilityEnvelopeHash,
		manifestPayloadHash:    manifestPayloadHash,
	}, nil
}
