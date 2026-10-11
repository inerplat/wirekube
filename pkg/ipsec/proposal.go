package ipsec

import (
	"fmt"
	"strings"
)

// ProposalParts is a strongSwan proposal spelled out the way VPN gateway
// consoles ask for it.
type ProposalParts struct {
	Encryption string
	Integrity  string
	DHGroup    string
}

var (
	encryptionNames = map[string]string{
		"aes128": "AES-128-CBC", "aes192": "AES-192-CBC", "aes256": "AES-256-CBC",
		"aes128gcm16": "AES-128-GCM", "aes192gcm16": "AES-192-GCM", "aes256gcm16": "AES-256-GCM",
		"aes128gcm128": "AES-128-GCM", "aes256gcm128": "AES-256-GCM",
		"3des": "3DES", "chacha20poly1305": "ChaCha20-Poly1305",
	}
	integrityNames = map[string]string{
		"sha1": "SHA-1", "sha256": "SHA2-256", "sha384": "SHA2-384", "sha512": "SHA2-512", "md5": "MD5",
		"prfsha1": "PRF SHA-1", "prfsha256": "PRF SHA2-256", "prfsha384": "PRF SHA2-384", "prfsha512": "PRF SHA2-512",
	}
	dhNames = map[string]string{
		"modp768": "group 1 (MODP 768)", "modp1024": "group 2 (MODP 1024)", "modp1536": "group 5 (MODP 1536)",
		"modp2048": "group 14 (MODP 2048)", "modp3072": "group 15 (MODP 3072)", "modp4096": "group 16 (MODP 4096)",
		"modp6144": "group 17 (MODP 6144)", "modp8192": "group 18 (MODP 8192)",
		"ecp256": "group 19 (ECP 256)", "ecp384": "group 20 (ECP 384)", "ecp521": "group 21 (ECP 521)",
		"curve25519": "group 31 (Curve25519)", "x25519": "group 31 (Curve25519)", "curve448": "group 32 (Curve448)",
	}
)

// DescribeProposal splits a proposal such as "aes256-sha256-modp2048" into
// the terms a remote gateway's configuration uses. Unknown algorithms are
// returned as written. With AEAD encryption the integrity part is empty.
func DescribeProposal(p string) ProposalParts {
	var out ProposalParts
	var unknown []string
	for _, alg := range strings.Split(strings.ToLower(strings.TrimSpace(p)), "-") {
		switch {
		case encryptionNames[alg] != "" && out.Encryption == "":
			out.Encryption = encryptionNames[alg]
		case integrityNames[alg] != "" && out.Integrity == "":
			out.Integrity = integrityNames[alg]
		case dhNames[alg] != "" && out.DHGroup == "":
			out.DHGroup = dhNames[alg]
		case alg != "":
			unknown = append(unknown, alg)
		}
	}
	if len(unknown) > 0 {
		extra := strings.Join(unknown, "-")
		if out.Encryption == "" {
			out.Encryption = extra
		} else {
			out.Integrity = strings.TrimSpace(fmt.Sprintf("%s %s", out.Integrity, extra))
		}
	}
	return out
}
