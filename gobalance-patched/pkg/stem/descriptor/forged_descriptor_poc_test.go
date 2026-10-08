package descriptor

// forged_descriptor_poc_test.go — SECURITY PROOF OF CONCEPT
//
// Demonstrates the second takeover path that the patch closes:
//
// An attacker can mint a FULLY SELF-CONSISTENT v3 descriptor for somebody
// else's onion address using keys of their own choosing. The subcredential
// binds the encrypted layers to (identity pubkey, blinded pubkey) — and the
// blinded pubkey is carried INSIDE the descriptor itself, so the attacker
// simply derives the subcredential from the victim's (public) identity key
// and their own blinded key. Signature checks 1 and 2 therefore pass for
// such a descriptor; only check 3 (binding the blinded key to the
// consensus-derived expectation) rejects it.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"gobalance/pkg/gobpk"
	"gobalance/pkg/stem/util"
)

func TestForgedSelfConsistentDescriptorIsDetected(t *testing.T) {
	// ---- victim (simulated) ----
	victimPub, _, _ := ed25519.GenerateKey(nil)
	victimAddress := AddressFromIdentityKey(victimPub)

	// ---- attacker keys ----
	attBlindPub, attBlindPriv, _ := ed25519.GenerateKey(nil)
	_, attDescSign, _ := ed25519.GenerateKey(nil)

	cert := NewEd25519CertificateV1(HsV3DescSigning, nil, 1,
		attDescSign.Public().(ed25519.PublicKey),
		[]Ed25519Extension{NewEd25519Extension(HasSigningKey, 0, attBlindPub)},
		nil, nil)
	cert.SetSignature(ed25519.Sign(attBlindPriv, cert.pack()))

	inner := InnerLayerCreate(nil)
	revCounter := int64(42)

	subcred := subcredential(victimPub, attBlindPub)
	outer := outerLayerCreate(inner, &revCounter, subcred, attBlindPub)
	super := outer.encrypt(revCounter, subcred, attBlindPub)

	body := "hs-descriptor 3\n" +
		"descriptor-lifetime 180\n" +
		"descriptor-signing-key-cert\n" +
		cert.ToBase64() + "\n" +
		"revision-counter 42\n" +
		"superencrypted\n" +
		super + "\n"
	sig := ed25519.Sign(attDescSign, []byte(SigPrefixHsV3+body))
	forged := body + "signature " + base64.StdEncoding.EncodeToString(sig)


	if err := VerifyHiddenServiceDescriptorV3(forged); err != nil {
		t.Fatalf("expected the forged descriptor to pass internal chain checks (that is exactly the pre-patch trust model), got: %v", err)
	}
	t.Log("[DEMONSTRATED] self-consistent forged descriptor passes parse + cert-sig + descriptor-sig checks")
	t.Log("               => pre-patch RegisterDescriptor would accept it and republish attacker intro points")


	honestNonce := bytes.Repeat([]byte{0x77}, 32)
	expectedBlinded := util.BlindedPubkey(victimPub, honestNonce)
	if err := VerifyHiddenServiceDescriptorV3(forged, expectedBlinded); err == nil {
		t.Fatal("binding check FAILED to reject the forged descriptor")
	}
	t.Logf("[DEFENSE] binding check rejected the forged descriptor for %s", victimAddress)


	_, victimSeed, _ := ed25519.GenerateKey(nil)
	victimIdentity := gobpk.New(victimSeed, false)
	_, victimDescSigning, _ := ed25519.GenerateKey(nil)
	honestDesc := HiddenServiceDescriptorV3Create(honestNonce, victimIdentity, victimDescSigning, nil, 7)
	honestText := honestDesc.String()

	if err := VerifyHiddenServiceDescriptorV3(honestText); err != nil {
		t.Fatalf("honest descriptor failed verification: %v", err)
	}
	expectedHonest := util.BlindedPubkey(victimIdentity.Public(), honestNonce)
	if err := VerifyHiddenServiceDescriptorV3(honestText, expectedHonest); err != nil {
		t.Fatalf("honest descriptor failed the binding check: %v", err)
	}


	badSig := strings.Replace(honestText, "signature ", "signature A", 1)
	if err := VerifyHiddenServiceDescriptorV3(badSig, expectedHonest); err == nil {
		t.Fatal("tampered descriptor signature was accepted")
	}

	otherNonce := bytes.Repeat([]byte{0x99}, 32)
	wrongExpectation := util.BlindedPubkey(victimIdentity.Public(), otherNonce)
	if err := VerifyHiddenServiceDescriptorV3(honestText, wrongExpectation); err == nil {
		t.Fatal("descriptor bound to another period was accepted")
	}

	t.Log("[DEFENSE] honest descriptors pass; tampered/misbound descriptors are rejected")
}
