package journal

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// HistoricalTrust concerns the custody of the recorded claims, not their
// operational outcome. A CLOSED claim is not rewritten to UNKNOWN when its
// history becomes untrusted. These assessments are point-in-time, never leases.
type HistoricalTrust string

const (
	HistoryTrusted    HistoricalTrust = "TRUSTED_HISTORY"
	HistoryUntrusted  HistoricalTrust = "UNTRUSTED_HISTORY"
	HistoryUnverified HistoricalTrust = "UNVERIFIED_HISTORY"
)

var (
	ErrJournalIdentityRequired   = errors.New("anchored journal requires a trusted identity pin and explicit create or open")
	ErrJournalAlreadyExists      = errors.New("anchored journal history already exists")
	ErrJournalHistoryUnavailable = errors.New("anchored journal history is unavailable or untrusted")
)

// CreateAnchoredFileJournal performs first creation only. journalID must come
// from the trusted relying context (for example, governed configuration), not
// from the local anchor being checked. It must remain stable across restart,
// relocation and signer rotation. The witness must have no head for that ID.
//
// Creation is a provisioning action. Runtime restart uses OpenAnchoredFileJournal.
// A failed creation can leave durable partial state; it is not erased or
// automatically re-enrolled. If the external commit succeeded but its reply was
// lost, Open can verify the exact retained pair and continue without creating a
// replacement history.
func CreateAnchoredFileJournal(
	ctx context.Context,
	path, anchorPath, journalID string,
	signer AnchorSigner,
	verifier AnchorVerifier,
	externalHead ExternalHeadStore,
) (*FileJournal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j, err := newAnchoredFileJournal(path, anchorPath, journalID, signer, verifier, externalHead)
	if err != nil {
		return nil, err
	}
	for _, localPath := range []string{path, anchorPath} {
		exists, err := pathExists(localPath)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrJournalAlreadyExists
		}
	}
	if _, err := externalHead.Load(ctx, journalID); err == nil {
		return nil, ErrJournalAlreadyExists
	} else if !errors.Is(err, ErrExternalHeadNotFound) {
		return nil, fmt.Errorf("check journal creation witness: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := j.initialize(ctx); err != nil {
		return nil, err
	}
	if verification := j.verifyUnlocked(ctx); !verification.Valid {
		return nil, fmt.Errorf("%w: %s", ErrJournalHistoryUnavailable, verification.Error)
	}
	return j, nil
}

// OpenAnchoredFileJournal verifies an existing exact history without creating
// files, anchors or witness heads. Missing local or external custody fails
// closed. Possessing the signing key is not permission to reset lineage.
func OpenAnchoredFileJournal(
	ctx context.Context,
	path, anchorPath, expectedJournalID string,
	signer AnchorSigner,
	verifier AnchorVerifier,
	externalHead ExternalHeadStore,
) (*FileJournal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j, err := newAnchoredFileJournal(path, anchorPath, expectedJournalID, signer, verifier, externalHead)
	if err != nil {
		return nil, err
	}
	if verification := j.verifyUnlocked(ctx); !verification.Valid {
		return nil, fmt.Errorf("%w: %s", ErrJournalHistoryUnavailable, verification.Error)
	}
	return j, nil
}

func newAnchoredFileJournal(
	path, anchorPath, journalID string,
	signer AnchorSigner,
	verifier AnchorVerifier,
	externalHead ExternalHeadStore,
) (*FileJournal, error) {
	if strings.TrimSpace(journalID) == "" || journalID != strings.TrimSpace(journalID) {
		return nil, ErrJournalIdentityRequired
	}
	if externalHead == nil {
		return nil, errors.New("anchored journal requires an external continuity witness")
	}
	j, err := newFileJournal(path, anchorPath, signer, verifier)
	if err != nil {
		return nil, err
	}
	j.expectedJournalID = journalID
	j.externalHead = externalHead
	return j, nil
}
