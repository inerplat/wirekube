package wireguard

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair() error: %v", err)
	}

	// Must produce 32-byte keys
	if len(kp.Private) != 32 {
		t.Errorf("private key len = %d, want 32", len(kp.Private))
	}
	if len(kp.Public) != 32 {
		t.Errorf("public key len = %d, want 32", len(kp.Public))
	}

	// Must not be all zeros
	var zero [32]byte
	if kp.Private == zero {
		t.Error("private key is all zeros")
	}
	if kp.Public == zero {
		t.Error("public key is all zeros")
	}

	// Verify RFC 7748 clamping
	if kp.Private[0]&7 != 0 {
		t.Error("private key[0] low 3 bits should be zero (clamp)")
	}
	if kp.Private[31]&128 != 0 {
		t.Error("private key[31] high bit should be zero (clamp)")
	}
	if kp.Private[31]&64 == 0 {
		t.Error("private key[31] bit 6 should be set (clamp)")
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	kp1, _ := generateKeyPair()
	kp2, _ := generateKeyPair()

	if kp1.Private == kp2.Private {
		t.Error("two generated key pairs have the same private key")
	}
	if kp1.Public == kp2.Public {
		t.Error("two generated key pairs have the same public key")
	}
}

func TestKeyPair_Base64Encoding(t *testing.T) {
	kp, _ := generateKeyPair()

	privB64 := kp.PrivateKeyBase64()
	pubB64 := kp.PublicKeyBase64()

	// Decoded base64 must be 32 bytes
	privBytes, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatalf("PrivateKeyBase64() is not valid base64: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("decoded private key len = %d, want 32", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("PublicKeyBase64() is not valid base64: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("decoded public key len = %d, want 32", len(pubBytes))
	}
}

func TestLoadOrGenerate_CreatesNew(t *testing.T) {
	dir := t.TempDir()

	// Test with a temp directory instead of the package-level KeyDir.
	// KeyDir is a package const, so we call loadOrGenerateFromDir directly.
	origDir := KeyDir
	_ = origDir

	// Generate new keys
	kp, err := loadOrGenerateFromDir(dir)
	if err != nil {
		t.Fatalf("loadOrGenerateFromDir() error: %v", err)
	}

	// Key files must be created
	if _, err := os.Stat(filepath.Join(dir, PrivKeyFile)); err != nil {
		t.Errorf("privatekey file not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, PubKeyFile)); err != nil {
		t.Errorf("publickey file not created: %v", err)
	}

	// Reloading must return the same keys
	kp2, err := loadOrGenerateFromDir(dir)
	if err != nil {
		t.Fatalf("second loadOrGenerateFromDir() error: %v", err)
	}
	if kp.Private != kp2.Private {
		t.Error("loaded private key differs from generated key")
	}
	if kp.Public != kp2.Public {
		t.Error("loaded public key differs from generated key")
	}
}

func TestLoadOrGenerate_PrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()

	_, err := loadOrGenerateFromDir(dir)
	if err != nil {
		t.Fatalf("loadOrGenerateFromDir() error: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, PrivKeyFile))
	if err != nil {
		t.Fatalf("stat privatekey: %v", err)
	}
	// Must have 0600 permissions
	if info.Mode().Perm() != 0600 {
		t.Errorf("privatekey mode = %o, want 0600", info.Mode().Perm())
	}
}
