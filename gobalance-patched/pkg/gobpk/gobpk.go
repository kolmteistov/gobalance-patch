package gobpk

import (
	"crypto/ed25519"
	"fmt"
	"gobalance/pkg/onionbalance/hs_v3/ext"
)

// gobpk == gobalance private key

// PrivateKey wrapper around ed25519 private key to handle both tor format or normal
type PrivateKey struct {
	isPrivKeyInTorFormat bool
	privateKey           ed25519.PrivateKey
}

// Public returns the public key bytes
func (k PrivateKey) Public() ed25519.PublicKey {
	if k.isPrivKeyInTorFormat {
		return ext.PublickeyFromESK(k.privateKey)
	}
	return k.privateKey.Public().(ed25519.PublicKey)
}

// PrivKey returns the FULL underlying private key bytes.
//
// For tor-format keys this is the 64-byte EXTENDED key (a || h):
//   - a (32 bytes): the secret scalar,
//   - h (32 bytes): the PRF key used to derive the blinded signature nonce
//     prefix (rend-spec-v3 "Derive temporary signing key hash input").
//
// SECURITY: the 'h' half must NEVER be discarded. Signing routines that
// truncate the key down to 'a' degenerate into a public, constant nonce
// prefix, which lets anyone recover the master identity key (mod L) from a
// single published descriptor. See pkg/stem/util/ed25519.go
// (BlindedSignWithTorKey) for the hard length check.
func (k PrivateKey) PrivKey() ed25519.PrivateKey {
	return k.privateKey
}

// Seed returns the first 32 bytes of the underlying ed25519 private key.
//
// For seed-format keys this is the real ed25519 seed. For tor-format keys it
// is the secret scalar 'a' — which is NOT a seed and must not be fed back
// into seed-based key expansion. Blind signing of tor-format keys must use
// PrivKey() instead.
func (k PrivateKey) Seed() []byte {
	return k.privateKey.Seed()
}

// IsPrivKeyInTorFormat returns either or not the private key is in tor format
func (k PrivateKey) IsPrivKeyInTorFormat() bool {
	return k.isPrivKeyInTorFormat
}

// New created a new PrivateKey
func New(privateKey ed25519.PrivateKey, isPrivKeyInTorFormat bool) PrivateKey {
	if isPrivKeyInTorFormat && len(privateKey) != ed25519.PrivateKeySize {
		// A tor-format key must be the complete extended key (a||h).
		// Anything shorter means the PRF half was already lost upstream;
		// refuse it here instead of silently producing signatures whose
		// nonce prefix is a public constant (master key recovery flaw).
		panic(fmt.Sprintf("gobpk: tor-format private key must be the full %d-byte extended key (a||h); got %d bytes",
			ed25519.PrivateKeySize, len(privateKey)))
	}
	return PrivateKey{
		privateKey:           privateKey,
		isPrivKeyInTorFormat: isPrivKeyInTorFormat,
	}
}
