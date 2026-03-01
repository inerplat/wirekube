// Package wireguard provides WireGuard interface management for WireKube agents.
package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

const (
	KeyDir      = "/var/lib/wirekube"
	PrivKeyFile = "privatekey"
	PubKeyFile  = "publickey"
)

// KeyPair holds a WireGuard key pair.
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// PrivateKeyBase64 returns the private key as a base64-encoded string.
func (kp *KeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.Private[:])
}

// PublicKeyBase64 returns the public key as a base64-encoded string.
func (kp *KeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.Public[:])
}

// LoadOrGenerate loads an existing key pair from disk, or generates a new one.
// Keys are stored in KeyDir.
func LoadOrGenerate() (*KeyPair, error) {
	return loadOrGenerateFromDir(KeyDir)
}

// loadOrGenerateFromDir is the testable implementation of LoadOrGenerate.
func loadOrGenerateFromDir(dir string) (*KeyPair, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}

	privPath := filepath.Join(dir, PrivKeyFile)
	data, err := os.ReadFile(privPath)
	if err == nil && len(data) == 44 {
		// Existing key found (base64 encoded 32 bytes = 44 chars)
		privBytes, decErr := base64.StdEncoding.DecodeString(string(data))
		if decErr == nil && len(privBytes) == 32 {
			kp := &KeyPair{}
			copy(kp.Private[:], privBytes)
			curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
			return kp, nil
		}
	}

	// Generate new key pair
	kp, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	// Persist private key (chmod 600)
	if err := os.WriteFile(privPath, []byte(kp.PrivateKeyBase64()), 0600); err != nil {
		return nil, fmt.Errorf("writing private key: %w", err)
	}
	// Persist public key (readable)
	pubPath := filepath.Join(dir, PubKeyFile)
	if err := os.WriteFile(pubPath, []byte(kp.PublicKeyBase64()), 0644); err != nil {
		return nil, fmt.Errorf("writing public key: %w", err)
	}

	return kp, nil
}

func generateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}
	// Clamp the private key per RFC 7748
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64
	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return kp, nil
}
