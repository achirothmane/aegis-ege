package kernelfabric

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const DefaultIMAPCRIndex = 10

func ReplayIMASHA256PCR10(measurements []byte) ([]byte, error) {
	if len(measurements) == 0 {
		return nil, errors.New("IMA SHA-256 measurement log is empty")
	}
	pcr := make([]byte, sha256.Size)
	scanner := bufio.NewScanner(bytes.NewReader(measurements))
	// IMA template data can be long (e.g. ima-buf), so raise the scanner limit.
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	records := 0
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("IMA line %d has fewer than 3 fields", lineNo)
		}
		pcrIndex, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("IMA line %d invalid PCR index: %w", lineNo, err)
		}
		if pcrIndex != DefaultIMAPCRIndex {
			continue
		}
		digestHex := fields[1]
		if len(digestHex) != sha256.Size*2 {
			return nil, fmt.Errorf(
				"IMA line %d template digest length=%d; expected SHA-256 log",
				lineNo,
				len(digestHex),
			)
		}
		digest, err := hex.DecodeString(digestHex)
		if err != nil {
			return nil, fmt.Errorf("IMA line %d invalid template digest: %w", lineNo, err)
		}
		h := sha256.New()
		h.Write(pcr)
		h.Write(digest)
		pcr = h.Sum(nil)
		records++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan IMA measurements: %w", err)
	}
	if records == 0 {
		return nil, errors.New("IMA SHA-256 log contains no PCR 10 records")
	}
	return pcr, nil
}


func IMAMeasurementContainsDigest(measurements []byte, wantDigest string) bool {
	wantDigest = strings.TrimSpace(strings.ToLower(wantDigest))
	if !strings.HasPrefix(wantDigest, "sha256:") {
		return false
	}
	wantHex := strings.TrimPrefix(wantDigest, "sha256:")
	if len(wantHex) != sha256.Size*2 {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(measurements))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		for _, field := range fields[3:] {
			field = strings.TrimSpace(strings.ToLower(field))
			if field == wantDigest || field == wantHex {
				return true
			}
			if strings.HasPrefix(field, "sha256:") &&
				strings.TrimPrefix(field, "sha256:") == wantHex {
				return true
			}
		}
	}
	return false
}
