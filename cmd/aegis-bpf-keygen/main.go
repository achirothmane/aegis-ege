package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	var (
		privatePath = flag.String("private-out", "", "private key output path")
		publicPath  = flag.String("public-out", "", "public key output path")
	)
	flag.Parse()
	if *privatePath == "" || *publicPath == "" {
		fatalf("-private-out and -public-out are required")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("generate Ed25519 key: %v", err)
	}
	keyID, err := kernelfabric.BootstrapKeyID(publicKey)
	if err != nil {
		fatalf("derive key id: %v", err)
	}

	if err := writeExclusive(
		*privatePath,
		[]byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"),
		0o600,
	); err != nil {
		fatalf("write private key: %v", err)
	}
	if err := writeExclusive(
		*publicPath,
		[]byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"),
		0o644,
	); err != nil {
		_ = os.Remove(*privatePath)
		fatalf("write public key: %v", err)
	}

	fmt.Printf("key id: %s\n", keyID)
	fmt.Printf("private key: %s\n", *privatePath)
	fmt.Printf("public key: %s\n", *publicPath)
}

func writeExclusive(path string, payload []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-bpf-keygen: "+format+"\n", args...)
	os.Exit(1)
}
