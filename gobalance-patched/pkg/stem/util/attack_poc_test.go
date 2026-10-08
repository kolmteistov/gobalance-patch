package util

// attack_poc_test.go — SECURITY REGRESSION / DEFENSE PROOF (patched code)
//
// The original flaw (pre-patch): the dispatcher passed identityKey.Seed()
// (the 32-byte scalar 'a') into BlindedSignWithTorKey, whose blindedSignP2
// derived the signature nonce prefix as
//
//      kPrime = SHA512("Derive temporary signing key hash input" + <empty>)
//
// — a PUBLIC CONSTANT. From one published descriptor anyone could recompute
// the nonce r, solve s' = (S-r)·H(R||PK||M)^-1 mod L, unblind with the
// public multiplier, and recover the master identity scalar (mod L).
//
// These tests prove that the PATCHED code:
//   - refuses truncated keys (the vulnerable configuration is unreachable);
//   - still produces protocol-correct signatures (standard ed25519 verifies
//     under the blinded public key);
//   - makes the same attack math yield garbage (no master key recovery);
//   - leaves the seed-format path unchanged and safe.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"gobalance/pkg/gobpk"
	"math/big"
	"testing"
)

// ---- victim / helper setup -------------------------------------------------

// torKeyFixture builds a realistic tor-format extended key (a||h) from a
// fresh seed, exactly like tored25519.LoadTorKeyFromDisk would load it.
type torKeyFixture struct {
	seed        []byte
	h           [64]byte
	aClamped    []byte // 32-byte clamped scalar (esk[0:32])
	prfHalf     []byte // 32-byte PRF key (esk[32:64])
	esk         []byte // a||h
	identityPub []byte // A = [a]B, embedded in the onion address
}

func newTorKeyFixture() *torKeyFixture {
	_, seed, _ := ed25519.GenerateKey(nil)
	digest := sha512.Sum512(seed)
	a := make([]byte, 32)
	copy(a, digest[:32])
	// clamping per Tor spec
	a[0] &= 248
	a[31] &= 63
	a[31] |= 64
	fx := &torKeyFixture{
		seed:     seed,
		h:        digest,
		aClamped: a,
		prfHalf:  digest[32:64],
		esk:      append(append([]byte{}, a...), digest[32:64]...),
	}
	fx.identityPub = pubFromTor(fx.aClamped)
	return fx
}

func clampScalar(b32 []byte) []byte {
	out := append([]byte{}, b32...)
	out[0] &= 248
	out[31] &= 63
	out[31] |= 64
	return out
}

// ---- 1. compatibility: patched tor path emits valid ed25519 signatures ----

func TestPatchedTorPath_ProducesValidEd25519Signatures(t *testing.T) {
	fx := newTorKeyFixture()
	for _, nonce := range [][]byte{bytes.Repeat([]byte{0xAB}, 32), bytes.Repeat([]byte{0xCD}, 32)} {
		blindedPub := BlindedPubkey(fx.identityPub, nonce)
		msg := []byte("descriptor cert bytes")
		sig := BlindedSignWithTorKey(msg, ed25519.PrivateKey(fx.esk), blindedPub, nonce)
		if !ed25519.Verify(blindedPub, msg, sig) {
			t.Fatalf("patched tor-path signature does not verify as standard ed25519 (nonce %x)", nonce[:2])
		}
		// tamper detection must still work
		bad := append([]byte{}, msg...)
		bad[0] ^= 1
		if ed25519.Verify(blindedPub, bad, sig) {
			t.Fatal("signature verified under a tampered message")
		}
	}
	t.Log("OK: patched signatures are protocol-correct (standard ed25519 under the blinded pubkey)")
}

// ---- 2. the attack now fails ----------------------------------------------

func TestAttackFailsOnPatchedTorPath(t *testing.T) {
	fx := newTorKeyFixture()

	// Victim publishes descriptors for two consecutive time periods.
	nonce1 := bytes.Repeat([]byte{0xAB}, 32)
	nonce2 := bytes.Repeat([]byte{0xCD}, 32)
	blindedPub1 := BlindedPubkey(fx.identityPub, nonce1)
	blindedPub2 := BlindedPubkey(fx.identityPub, nonce2)
	msg1 := []byte("period 1 descriptor cert")
	msg2 := []byte("period 2 descriptor cert")
	sig1 := BlindedSignWithTorKey(msg1, ed25519.PrivateKey(fx.esk), blindedPub1, nonce1)
	sig2 := BlindedSignWithTorKey(msg2, ed25519.PrivateKey(fx.esk), blindedPub2, nonce2)

	// Attacker runs the EXACT same math that broke the old code:
	// assume kPrime is the constant, recompute r1, solve for s'.
	kPrime := sha512.Sum512([]byte("Derive temporary signing key hash input"))
	r1 := hint(append(append([]byte{}, kPrime[:32]...), msg1...))
	hval := hint(bytes.Join([][]byte{sig1[:32], blindedPub1, msg1}, nil))
	sWrong := new(big.Int).Sub(decodeInt(sig1[32:]), r1)
	sWrong.Mul(sWrong, new(big.Int).ModInverse(hval, l))
	sWrong.Mod(sWrong, l)

	// ground truth (test-internal knowledge only)
	trueSPrime1 := new(big.Int).Mod(new(big.Int).Mul(decodeInt(fx.aClamped), blindingMult(nonce1)), l)
	if sWrong.Cmp(trueSPrime1) == 0 {
		t.Fatal("attack recovered the true blinded scalar — patch ineffective?!")
	}

	// unblinding the garbage yields garbage, not the master scalar
	aWrong := new(big.Int).Mod(new(big.Int).Mul(sWrong, new(big.Int).ModInverse(blindingMult(nonce1), l)), l)
	trueA := decodeInt(fx.aClamped)
	if aWrong.Cmp(trueA) == 0 {
		t.Fatal("attack recovered the master scalar — patch ineffective?!")
	}

	// forging with the garbage scalar for period 2 must not match the victim
	forged := forgeWithRecoveredScalar(msg2, aWrong, blindedPub2, nonce2)
	if bytes.Equal(forged, sig2) {
		t.Fatal("forged period-2 signature matches the victim's real signature")
	}
	if ed25519.Verify(blindedPub2, msg2, forged) {
		t.Fatal("forged period-2 signature verifies under the real blinded pubkey")
	}
	if !ed25519.Verify(blindedPub2, msg2, sig2) {
		t.Fatal("sanity: victim's real period-2 signature should verify")
	}

	t.Logf("attacker-recovered master scalar (garbage): %x", aWrong.Bytes())
	t.Logf("true master scalar                      : %x", trueA.Bytes())
	t.Log("VULNERABILITY CLOSED: same attack math yields garbage; forgery fails verification.")
}

// forgeWithRecoveredScalar replicates blindedSignP2 with an attacker-chosen
// scalar and the constant kPrime the old code used.
func forgeWithRecoveredScalar(msg []byte, aRecovered *big.Int, blindedKey, blindingNonce []byte) []byte {
	mult := blindingMult(blindingNonce)
	sPrime := new(big.Int).Mod(new(big.Int).Mul(aRecovered, mult), l)
	kPrime := sha512.Sum512([]byte("Derive temporary signing key hash input"))
	blindedEsk := append(encodeint(sPrime), kPrime[:32]...)

	a := decodeInt(blindedEsk[:32])
	toHint := append(append([]byte{}, blindedEsk[32:64]...), msg...)
	r := hint(toHint)
	R := Scalarmult1(bB1, r)
	S := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(hint(bytes.Join([][]byte{Encodepoint(R), blindedKey, msg}, nil)), a)), l)
	return append(Encodepoint(R), encodeint(S)...)
}

// ---- 3. insecure configurations are now unreachable ------------------------

func assertPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected a panic for insecure key material", name)
		}
	}()
	fn()
}

func TestBlindedSignWithTorKey_RejectsTruncatedKey(t *testing.T) {
	fx := newTorKeyFixture()
	nonce := bytes.Repeat([]byte{0xAB}, 32)
	blindedPub := BlindedPubkey(fx.identityPub, nonce)
	msg := []byte("m")
	// the exact pre-patch misuse: 32-byte scalar instead of a||h
	assertPanic(t, "32-byte scalar", func() {
		BlindedSignWithTorKey(msg, ed25519.PrivateKey(fx.aClamped), blindedPub, nonce)
	})
	assertPanic(t, "31-byte key", func() {
		BlindedSignWithTorKey(msg, ed25519.PrivateKey(fx.esk[:31]), blindedPub, nonce)
	})
	assertPanic(t, "empty key", func() {
		BlindedSignWithTorKey(msg, ed25519.PrivateKey{}, blindedPub, nonce)
	})
	t.Log("OK: truncated keys (the vulnerable configuration) are rejected")
}

func TestBlindedSign_RejectsNonSeed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	nonce := bytes.Repeat([]byte{0x01}, 32)
	blindedPub := BlindedPubkey(pub, nonce)
	assertPanic(t, "64-byte standard key", func() {
		BlindedSign([]byte("m"), priv, blindedPub, nonce)
	})
	assertPanic(t, "tor extended key", func() {
		fx := newTorKeyFixture()
		BlindedSign([]byte("m"), ed25519.PrivateKey(fx.esk), blindedPub, nonce)
	})
}

// ---- 4. seed-format control path (unchanged behaviour) ----------------------

func TestControl_SeedFormatPathIsSafe(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	seed := priv.Seed() // the real 32-byte seed
	nonce := bytes.Repeat([]byte{0xAB}, 32)
	blindedPub := BlindedPubkey(pub, nonce)
	msg := []byte("simulated cert bytes")

	sig := BlindedSign(msg, seed, blindedPub, nonce) // seed-format path (correct key expansion)
	R := sig[:32]
	S := decodeInt(sig[32:])

	kPrime := sha512.Sum512([]byte("Derive temporary signing key hash input"))
	r := hint(append(append([]byte{}, kPrime[:32]...), msg...))
	hval := hint(bytes.Join([][]byte{R, blindedPub, msg}, nil))

	sPrime := new(big.Int).Sub(S, r)
	sPrime.Mul(sPrime, new(big.Int).ModInverse(hval, l))
	sPrime.Mod(sPrime, l)

	trueSPrime := new(big.Int).Mod(new(big.Int).Mul(decodeInt(seed), blindingMult(nonce)), l)
	if sPrime.Cmp(trueSPrime) == 0 {
		t.Fatal("unexpected: seed-format path is also vulnerable")
	}
	t.Log("CONTROL PASSED: seed-format (PEM) path does not leak the scalar — flaw was isolated to the tor-format path")
}

// ---- 5. gobpk invariant -----------------------------------------------------

func TestGobpkNew_RejectsTruncatedTorKey(t *testing.T) {
	fx := newTorKeyFixture()
	assertPanic(t, "gobpk.New truncated tor key", func() {
		gobpk.New(ed25519.PrivateKey(fx.aClamped), true)
	})
	// the full key is accepted and PrivKey() round-trips
	k := gobpk.New(ed25519.PrivateKey(fx.esk), true)
	if !bytes.Equal(k.PrivKey(), fx.esk) {
		t.Fatal("gobpk PrivKey() did not return the full extended key")
	}
	if !bytes.Equal(k.PrivKey()[:32], fx.aClamped) {
		t.Fatal("gobpk PrivKey() scalar half mismatch")
	}
	if !bytes.Equal(k.PrivKey()[32:], fx.prfHalf) {
		t.Fatal("gobpk PrivKey() PRF half mismatch")
	}
	t.Log("OK: gobpk refuses tor keys without the PRF half and preserves the full a||h material")
}

// ---- helpers ---------------------------------------------------------------

func blindingMult(nonce []byte) *big.Int {
	sum := bi(0)
	for i := int64(3); i < int64(b)-2; i++ {
		sum = biAdd(sum, biMul(biExp(bi(2), bi(i)), bi(int64(Bit(nonce, i)))))
	}
	return biAdd(biExp(bi(2), bi(int64(b-2))), sum)
}

// pubFromTor computes the ed25519 public key from the tor scalar (A = aB)
func pubFromTor(aBytes []byte) []byte {
	A := Scalarmult1(bB1, decodeInt(aBytes))
	return Encodepoint(A)
}
