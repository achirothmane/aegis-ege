package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/server"
)

func loadEvidenceIndependenceProfile(path string) (*server.EvidenceIndependenceProfileConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence independence profile: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var profile server.EvidenceIndependenceProfileConfig
	if err := decoder.Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode evidence independence profile: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("evidence independence profile contains trailing JSON")
		}
		return nil, fmt.Errorf("decode evidence independence profile trailing data: %w", err)
	}
	return &profile, nil
}
