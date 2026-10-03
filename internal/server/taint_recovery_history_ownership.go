//go:build linux && cgo

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const taintRecoveryHistoryOwnershipGenesisKeyID = "aegis-ege/taint-recovery-history-ownership/genesis/v1"

var (
	ErrTaintRecoveryHistoryOwnershipMismatch = errors.New("taint recovery history ownership mismatch")
	ErrTaintRecoveryHistoryOwnershipReplay   = errors.New("taint recovery history ownership transfer replay detected")
)

type TaintRecoveryHistoryOwnershipState struct {
	Epoch                  uint64
	ActiveDeviceIdentity   string
	AuthorizationDigest    string
}

type TaintRecoveryHistoryOwnershipWitness struct {
	store     journal.ExternalHeadStore
	witnessID string
}

func NewTaintRecoveryHistoryOwnershipWitness(
	store journal.ExternalHeadStore,
	witnessID string,
) (*TaintRecoveryHistoryOwnershipWitness, error) {
	if store == nil {
		return nil, errors.New("recovery history ownership witness store is required")
	}
	witnessID = strings.TrimSpace(witnessID)
	if witnessID == "" {
		return nil, errors.New("recovery history ownership witness id is required")
	}
	return &TaintRecoveryHistoryOwnershipWitness{
		store:     store,
		witnessID: witnessID,
	}, nil
}

func (w *TaintRecoveryHistoryOwnershipWitness) Initialize(
	ctx context.Context,
	activeDeviceIdentity string,
) (TaintRecoveryHistoryOwnershipState, error) {
	if w == nil || w.store == nil {
		return TaintRecoveryHistoryOwnershipState{}, errors.New("recovery history ownership witness is unavailable")
	}
	if !validSHA256Ref(activeDeviceIdentity) {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: active device identity is invalid",
			ErrTaintRecoveryHistoryOwnershipMismatch,
		)
	}
	if head, err := w.store.Load(ctx, w.witnessID); err == nil {
		return w.decode(head)
	} else if !errors.Is(err, journal.ErrExternalHeadNotFound) {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf("load recovery history ownership witness: %w", err)
	}

	next := journal.ExternalHead{
		JournalID: w.witnessID,
		Sequence:  0,
		HeadHash:  activeDeviceIdentity,
		KeyID:     taintRecoveryHistoryOwnershipGenesisKeyID,
	}
	advanced, err := w.store.CompareAndAdvance(ctx, journal.ExternalHead{}, next)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf("initialize recovery history ownership witness: %w", err)
	}
	return w.decode(advanced)
}

func (w *TaintRecoveryHistoryOwnershipWitness) Current(
	ctx context.Context,
) (TaintRecoveryHistoryOwnershipState, error) {
	if w == nil || w.store == nil {
		return TaintRecoveryHistoryOwnershipState{}, errors.New("recovery history ownership witness is unavailable")
	}
	head, err := w.store.Load(ctx, w.witnessID)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf("load recovery history ownership witness: %w", err)
	}
	return w.decode(head)
}

func (w *TaintRecoveryHistoryOwnershipWitness) BeginTransfer(
	ctx context.Context,
	expected TaintRecoveryHistoryOwnershipState,
	authorizationDigest string,
) (TaintRecoveryHistoryOwnershipState, error) {
	if !validSHA256Ref(authorizationDigest) {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: transfer authorization digest is invalid",
			ErrTaintRecoveryHistoryOwnershipMismatch,
		)
	}
	quiesced := TaintRecoveryHistoryOwnershipState{
		Epoch:                expected.Epoch + 1,
		ActiveDeviceIdentity: quiescedRecoveryHistoryOwnershipIdentity(authorizationDigest),
		AuthorizationDigest:  authorizationDigest,
	}
	current, err := w.Current(ctx)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	if current == quiesced {
		return current, nil
	}
	if current != expected {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: cannot quiesce current=%+v expected=%+v",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			current,
			expected,
		)
	}
	currentHead, err := w.store.Load(ctx, w.witnessID)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	advanced, err := w.store.CompareAndAdvance(ctx, currentHead, journal.ExternalHead{
		JournalID: w.witnessID,
		Sequence:  quiesced.Epoch,
		HeadHash:  quiesced.ActiveDeviceIdentity,
		KeyID:     quiesced.AuthorizationDigest,
	})
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf("quiesce recovery history ownership witness: %w", err)
	}
	got, err := w.decode(advanced)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	if got != quiesced {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: quiesce returned %+v expected %+v",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			got,
			quiesced,
		)
	}
	return got, nil
}

func (w *TaintRecoveryHistoryOwnershipWitness) CompleteTransfer(
	ctx context.Context,
	quiesced TaintRecoveryHistoryOwnershipState,
	destinationDeviceIdentity string,
	authorizationDigest string,
) (TaintRecoveryHistoryOwnershipState, error) {
	if !validSHA256Ref(destinationDeviceIdentity) ||
		!validSHA256Ref(authorizationDigest) ||
		quiesced.ActiveDeviceIdentity != quiescedRecoveryHistoryOwnershipIdentity(authorizationDigest) ||
		quiesced.AuthorizationDigest != authorizationDigest {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: invalid quiesced ownership transfer state",
			ErrTaintRecoveryHistoryOwnershipMismatch,
		)
	}
	final := TaintRecoveryHistoryOwnershipState{
		Epoch:                quiesced.Epoch + 1,
		ActiveDeviceIdentity: destinationDeviceIdentity,
		AuthorizationDigest:  authorizationDigest,
	}
	current, err := w.Current(ctx)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	if current == final {
		return TaintRecoveryHistoryOwnershipState{}, ErrTaintRecoveryHistoryOwnershipReplay
	}
	if current != quiesced {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: cannot complete current=%+v quiesced=%+v",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			current,
			quiesced,
		)
	}
	currentHead, err := w.store.Load(ctx, w.witnessID)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	advanced, err := w.store.CompareAndAdvance(ctx, currentHead, journal.ExternalHead{
		JournalID: w.witnessID,
		Sequence:  final.Epoch,
		HeadHash:  final.ActiveDeviceIdentity,
		KeyID:     final.AuthorizationDigest,
	})
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf("complete recovery history ownership transfer: %w", err)
	}
	got, err := w.decode(advanced)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	if got != final {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: completed transfer returned %+v expected %+v",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			got,
			final,
		)
	}
	return got, nil
}

func quiescedRecoveryHistoryOwnershipIdentity(authorizationDigest string) string {
	sum := sha256.Sum256([]byte("aegis-ege/recovery-history-ownership-quiesced/v1\x00" + authorizationDigest))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (w *TaintRecoveryHistoryOwnershipWitness) Transfer(
	ctx context.Context,
	expected TaintRecoveryHistoryOwnershipState,
	destinationDeviceIdentity string,
	authorizationDigest string,
) (TaintRecoveryHistoryOwnershipState, error) {
	if w == nil || w.store == nil {
		return TaintRecoveryHistoryOwnershipState{}, errors.New("recovery history ownership witness is unavailable")
	}
	if err := validateTaintRecoveryHistoryOwnershipState(expected); err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	if !validSHA256Ref(destinationDeviceIdentity) || destinationDeviceIdentity == expected.ActiveDeviceIdentity {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: destination device identity is invalid",
			ErrTaintRecoveryHistoryOwnershipMismatch,
		)
	}
	if !validSHA256Ref(authorizationDigest) {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: transfer authorization digest is invalid",
			ErrTaintRecoveryHistoryOwnershipMismatch,
		)
	}

	currentHead, err := w.store.Load(ctx, w.witnessID)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf("load recovery history ownership witness: %w", err)
	}
	current, err := w.decode(currentHead)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	next := TaintRecoveryHistoryOwnershipState{
		Epoch:                expected.Epoch + 1,
		ActiveDeviceIdentity: destinationDeviceIdentity,
		AuthorizationDigest:  authorizationDigest,
	}
	if current == next {
		return TaintRecoveryHistoryOwnershipState{}, ErrTaintRecoveryHistoryOwnershipReplay
	}
	if current != expected {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: current=(epoch=%d device=%s auth=%s) expected=(epoch=%d device=%s auth=%s)",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			current.Epoch,
			current.ActiveDeviceIdentity,
			current.AuthorizationDigest,
			expected.Epoch,
			expected.ActiveDeviceIdentity,
			expected.AuthorizationDigest,
		)
	}

	advanced, err := w.store.CompareAndAdvance(
		ctx,
		currentHead,
		journal.ExternalHead{
			JournalID: w.witnessID,
			Sequence:  next.Epoch,
			HeadHash:  next.ActiveDeviceIdentity,
			KeyID:     next.AuthorizationDigest,
		},
	)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf("advance recovery history ownership witness: %w", err)
	}
	got, err := w.decode(advanced)
	if err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	if got != next {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: witness advanced to %+v expected %+v",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			got,
			next,
		)
	}
	return got, nil
}

func (w *TaintRecoveryHistoryOwnershipWitness) decode(
	head journal.ExternalHead,
) (TaintRecoveryHistoryOwnershipState, error) {
	if strings.TrimSpace(head.JournalID) != w.witnessID {
		return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
			"%w: witness id mismatch: got=%q want=%q",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			head.JournalID,
			w.witnessID,
		)
	}
	state := TaintRecoveryHistoryOwnershipState{
		Epoch:                head.Sequence,
		ActiveDeviceIdentity: head.HeadHash,
	}
	if head.Sequence == 0 {
		if head.KeyID != taintRecoveryHistoryOwnershipGenesisKeyID {
			return TaintRecoveryHistoryOwnershipState{}, fmt.Errorf(
				"%w: genesis authorization marker mismatch",
				ErrTaintRecoveryHistoryOwnershipMismatch,
			)
		}
	} else {
		state.AuthorizationDigest = head.KeyID
	}
	if err := validateTaintRecoveryHistoryOwnershipState(state); err != nil {
		return TaintRecoveryHistoryOwnershipState{}, err
	}
	return state, nil
}

func validateTaintRecoveryHistoryOwnershipState(
	state TaintRecoveryHistoryOwnershipState,
) error {
	if !validSHA256Ref(state.ActiveDeviceIdentity) {
		return fmt.Errorf(
			"%w: active device identity is invalid",
			ErrTaintRecoveryHistoryOwnershipMismatch,
		)
	}
	if state.Epoch == 0 {
		if state.AuthorizationDigest != "" {
			return fmt.Errorf(
				"%w: genesis ownership cannot carry transfer authorization",
				ErrTaintRecoveryHistoryOwnershipMismatch,
			)
		}
		return nil
	}
	if !validSHA256Ref(state.AuthorizationDigest) {
		return fmt.Errorf(
			"%w: non-genesis ownership requires authorization digest",
			ErrTaintRecoveryHistoryOwnershipMismatch,
		)
	}
	return nil
}

type DeviceBoundTaintRecoveryHistoryAnchor interface {
	kernelfabric.TaintRecoveryHistoryAnchor
	DeviceIdentity(context.Context) (string, error)
}

// OwnedConjunctiveTaintRecoveryHistoryAnchor requires three independent facts
// before history can be used:
//   1. the local TPM exact-head state,
//   2. the external recovery-history witness quorum,
//   3. the external active-device ownership witness.
//
// After ownership transfers to a replacement TPM, the predecessor TPM can no
// longer satisfy Current() even when it still carries the same history head.
type OwnedConjunctiveTaintRecoveryHistoryAnchor struct {
	Local     DeviceBoundTaintRecoveryHistoryAnchor
	Witness   kernelfabric.TaintRecoveryHistoryAnchor
	Ownership *TaintRecoveryHistoryOwnershipWitness
}

func NewOwnedConjunctiveTaintRecoveryHistoryAnchor(
	local DeviceBoundTaintRecoveryHistoryAnchor,
	witness kernelfabric.TaintRecoveryHistoryAnchor,
	ownership *TaintRecoveryHistoryOwnershipWitness,
) (*OwnedConjunctiveTaintRecoveryHistoryAnchor, error) {
	if local == nil || witness == nil || ownership == nil {
		return nil, errors.New("local TPM, history witness, and ownership witness are required")
	}
	return &OwnedConjunctiveTaintRecoveryHistoryAnchor{
		Local:     local,
		Witness:   witness,
		Ownership: ownership,
	}, nil
}

func (a *OwnedConjunctiveTaintRecoveryHistoryAnchor) Current(
	ctx context.Context,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if err := a.requireActiveDevice(ctx); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	local, err := a.Local.Current(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	witness, err := a.Witness.Current(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if local != witness {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: local=(%d,%q) witness=(%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			local.Sequence,
			local.HeadDigest,
			witness.Sequence,
			witness.HeadDigest,
		)
	}
	return local, nil
}

func (a *OwnedConjunctiveTaintRecoveryHistoryAnchor) CompareAndAdvance(
	ctx context.Context,
	expected,
	next kernelfabric.TaintRecoveryHistoryAnchorState,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if err := a.requireActiveDevice(ctx); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	conjunctive, err := NewConjunctiveTaintRecoveryHistoryAnchor(a.Local, a.Witness)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	advanced, err := conjunctive.CompareAndAdvance(ctx, expected, next)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if err := a.requireActiveDevice(ctx); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	return advanced, nil
}

func (a *OwnedConjunctiveTaintRecoveryHistoryAnchor) requireActiveDevice(
	ctx context.Context,
) error {
	if a == nil || a.Local == nil || a.Ownership == nil {
		return errors.New("owned recovery history anchor is unavailable")
	}
	identity, err := a.Local.DeviceIdentity(ctx)
	if err != nil {
		return err
	}
	ownership, err := a.Ownership.Current(ctx)
	if err != nil {
		return err
	}
	if ownership.ActiveDeviceIdentity != identity {
		return fmt.Errorf(
			"%w: local=%s active=%s epoch=%d",
			ErrTaintRecoveryHistoryOwnershipMismatch,
			identity,
			ownership.ActiveDeviceIdentity,
			ownership.Epoch,
		)
	}
	return nil
}
