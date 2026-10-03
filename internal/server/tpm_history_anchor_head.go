//go:build linux && cgo

package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const tpmNVHistoryProtectedHeadSize = 48

type tpmNVHistoryProtectedHead struct {
	Generation uint64
	Sequence   uint64
	HeadDigest string
}

func validateTPMNVHistoryAnchorConfig(
	device transport.TPM,
	cfg TPMNVHistoryAnchorConfig,
) error {
	if err := validateTPMNVRootConfig(device, historyAnchorRootConfig(cfg)); err != nil {
		return err
	}
	if cfg.HeadNVIndex == 0 {
		return fmt.Errorf("%w: exact-head NV index is required", ErrTPMHistoryAnchorInvalid)
	}
	if cfg.HeadNVIndex == cfg.NVIndex {
		return fmt.Errorf("%w: counter and exact-head NV indexes must differ", ErrTPMHistoryAnchorInvalid)
	}
	return nil
}

func defineTPMNVHistoryProtectedHead(
	device transport.TPM,
	cfg TPMNVHistoryAnchorConfig,
) error {
	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(cfg.OwnerAuth),
		},
		Auth: tpm2.TPM2BAuth{Buffer: append([]byte(nil), cfg.HeadIndexAuth...)},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: cfg.HeadNVIndex,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				AuthWrite:  true,
				AuthRead:   true,
				NT:         tpm2.TPMNTOrdinary,
				NoDA:       true,
			},
			DataSize: tpmNVHistoryProtectedHeadSize,
		}),
	}
	if _, err := def.Execute(device); err != nil {
		return fmt.Errorf("define TPM history exact-head NV 0x%x: %w", uint32(cfg.HeadNVIndex), err)
	}
	return nil
}

func undefineTPMNVHistorySpaceBestEffort(
	device transport.TPM,
	handle tpm2.TPMHandle,
	ownerAuth []byte,
) {
	response, err := (tpm2.NVReadPublic{NVIndex: handle}).Execute(device)
	if err != nil {
		return
	}
	_, _ = (tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: handle,
			Name:   response.NVName,
		},
	}).Execute(device)
}

func (a *TPMNVHistoryAnchor) readProtectedHead(
	ctx context.Context,
) (tpmNVHistoryProtectedHead, error) {
	if err := ctx.Err(); err != nil {
		return tpmNVHistoryProtectedHead{}, err
	}
	pub, err := a.readProtectedHeadPublic()
	if err != nil {
		return tpmNVHistoryProtectedHead{}, err
	}
	authHandle := tpm2.AuthHandle{
		Handle: a.cfg.HeadNVIndex,
		Name:   pub.NVName,
		Auth:   tpm2.PasswordAuth(a.cfg.HeadIndexAuth),
	}
	response, err := (tpm2.NVRead{
		AuthHandle: authHandle,
		NVIndex: tpm2.NamedHandle{
			Handle: a.cfg.HeadNVIndex,
			Name:   pub.NVName,
		},
		Size: tpmNVHistoryProtectedHeadSize,
	}).Execute(a.helper.tpm)
	if err != nil {
		return tpmNVHistoryProtectedHead{}, fmt.Errorf("read TPM history exact head: %w", err)
	}
	return decodeTPMNVHistoryProtectedHead(response.Data.Buffer)
}

func (a *TPMNVHistoryAnchor) writeProtectedHead(
	ctx context.Context,
	head tpmNVHistoryProtectedHead,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := encodeTPMNVHistoryProtectedHead(head)
	if err != nil {
		return err
	}
	pub, err := a.readProtectedHeadPublic()
	if err != nil {
		return err
	}
	authHandle := tpm2.AuthHandle{
		Handle: a.cfg.HeadNVIndex,
		Name:   pub.NVName,
		Auth:   tpm2.PasswordAuth(a.cfg.HeadIndexAuth),
	}
	if _, err := (tpm2.NVWrite{
		AuthHandle: authHandle,
		NVIndex: tpm2.NamedHandle{
			Handle: a.cfg.HeadNVIndex,
			Name:   pub.NVName,
		},
		Data:   tpm2.TPM2BMaxNVBuffer{Buffer: encoded},
		Offset: 0,
	}).Execute(a.helper.tpm); err != nil {
		return fmt.Errorf("write TPM history exact head: %w", err)
	}
	return nil
}

func (a *TPMNVHistoryAnchor) readProtectedHeadPublic() (*tpm2.NVReadPublicResponse, error) {
	response, err := (tpm2.NVReadPublic{NVIndex: a.cfg.HeadNVIndex}).Execute(a.helper.tpm)
	if err != nil {
		return nil, err
	}
	public, err := response.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	if public.NVIndex != a.cfg.HeadNVIndex ||
		public.Attributes.NT != tpm2.TPMNTOrdinary ||
		public.DataSize != tpmNVHistoryProtectedHeadSize {
		return nil, fmt.Errorf(
			"%w: NV index 0x%x is not expected exact-head area",
			ErrTPMHistoryAnchorInvalid,
			uint32(a.cfg.HeadNVIndex),
		)
	}
	return response, nil
}

func encodeTPMNVHistoryProtectedHead(
	head tpmNVHistoryProtectedHead,
) ([]byte, error) {
	if head.Generation == 0 {
		return nil, fmt.Errorf("%w: exact-head generation is zero", ErrTPMHistoryAnchorInvalid)
	}
	var digest [32]byte
	if head.Sequence == 0 {
		if head.HeadDigest != "" {
			return nil, fmt.Errorf("%w: sequence zero cannot carry exact head", ErrTPMHistoryAnchorInvalid)
		}
	} else {
		parsed, err := kernelfabric.ParseSHA256Digest(head.HeadDigest)
		if err != nil {
			return nil, fmt.Errorf("%w: exact head digest: %v", ErrTPMHistoryAnchorInvalid, err)
		}
		digest = parsed
	}
	out := make([]byte, tpmNVHistoryProtectedHeadSize)
	binary.BigEndian.PutUint64(out[0:8], head.Generation)
	binary.BigEndian.PutUint64(out[8:16], head.Sequence)
	copy(out[16:], digest[:])
	return out, nil
}

func decodeTPMNVHistoryProtectedHead(
	data []byte,
) (tpmNVHistoryProtectedHead, error) {
	if len(data) != tpmNVHistoryProtectedHeadSize {
		return tpmNVHistoryProtectedHead{}, fmt.Errorf(
			"%w: exact-head size=%d want=%d",
			ErrTPMHistoryAnchorInvalid,
			len(data),
			tpmNVHistoryProtectedHeadSize,
		)
	}
	head := tpmNVHistoryProtectedHead{
		Generation: binary.BigEndian.Uint64(data[0:8]),
		Sequence:   binary.BigEndian.Uint64(data[8:16]),
	}
	if head.Generation == 0 {
		return tpmNVHistoryProtectedHead{}, fmt.Errorf("%w: exact-head generation is zero", ErrTPMHistoryAnchorInvalid)
	}
	var zero [32]byte
	digest := data[16:48]
	if head.Sequence == 0 {
		if string(digest) != string(zero[:]) {
			return tpmNVHistoryProtectedHead{}, fmt.Errorf(
				"%w: sequence zero exact-head digest is nonzero",
				ErrTPMHistoryAnchorInvalid,
			)
		}
		return head, nil
	}
	head.HeadDigest = "sha256:" + hex.EncodeToString(digest)
	return head, nil
}

func protectedTPMHistoryHeadMatches(
	protected tpmNVHistoryProtectedHead,
	state tpmNVHistoryAnchorState,
) bool {
	return protected.Generation == state.Generation &&
		protected.Sequence == state.Sequence &&
		protected.HeadDigest == state.HeadDigest
}
