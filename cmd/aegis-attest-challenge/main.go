package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/achirothmane/aegis-ege/internal/cliio"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	deviceID := flag.String("device", "", "enrolled device id")
	out := flag.String("out", "remote-attestation-challenge.json", "challenge output")
	ttl := flag.Duration("ttl", 2*time.Minute, "challenge TTL")
	flag.Parse()
	if *deviceID == "" {
		fatalf("-device is required")
	}
	challenge, err := kernelfabric.NewRemoteAttestationChallenge(
		*deviceID, *ttl, time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, challenge, 0o644); err != nil {
		fatalf("write challenge: %v", err)
	}
	fmt.Printf("remote attestation challenge: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-attest-challenge: "+format+"\n", args...)
	os.Exit(1)
}
