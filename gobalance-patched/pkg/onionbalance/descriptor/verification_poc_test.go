package descriptor

// verification_poc_test.go — SECURITY PROOF OF CONCEPT (defensive)
//
// Exercises the REAL intake path (NewReceivedDescriptor) that the frontend
// uses when an instance descriptor arrives from the network:
//
//   - an honest descriptor is accepted (with and without the consensus
//     binding argument) — no false positives;
//   - the same descriptor with a tampered signature is rejected;
//   - a descriptor whose blinded key does not match the expected
//     (consensus-derived) value is rejected — identity binding.
//
// The fully self-consistent forged descriptor (attacker keys + victim
// subcredential) is demonstrated in pkg/stem/descriptor/
// forged_descriptor_poc_test.go, which runs against the very verifier that
// NewReceivedDescriptor invokes first.
//
// All keys are generated locally; the victim is simulated.

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"gobalance/pkg/gobpk"
	sdescriptor "gobalance/pkg/stem/descriptor"
	"gobalance/pkg/stem/util"
)

func buildHonestDescriptor(t *testing.T) (descText, onionAddress string, expectedBlinded ed25519.PublicKey) {
	t.Helper()
	_, seed, _ := ed25519.GenerateKey(nil)
	identity := gobpk.New(seed, false)
	identityPub := identity.Public()
	_, descSigning, _ := ed25519.GenerateKey(nil)
	nonce := bytes.Repeat([]byte{0x5A}, 32)

	desc := sdescriptor.HiddenServiceDescriptorV3Create(nonce, identity, descSigning, nil, 7)
	return desc.String(), sdescriptor.AddressFromIdentityKey(identityPub),
		util.BlindedPubkey(identityPub, nonce)
}

func TestNewReceivedDescriptor_AcceptsHonestDescriptor(t *testing.T) {
	descText, onionAddress, expectedBlinded := buildHonestDescriptor(t)

	// with the consensus binding
	d, err := NewReceivedDescriptor(descText, onionAddress, expectedBlinded)
	if err != nil || d == nil {
		t.Fatalf("honest descriptor rejected with binding: err=%v", err)
	}
	// chain-only (no binding arguments) also works
	if _, err := NewReceivedDescriptor(descText, onionAddress); err != nil {
		t.Fatalf("honest descriptor rejected chain-only: %v", err)
	}
	t.Log("OK: honest descriptor accepted (no false positives)")
}

func TestNewReceivedDescriptor_RejectsTamperedSignature(t *testing.T) {
	descText, onionAddress, expectedBlinded := buildHonestDescriptor(t)

	// corrupt the first character of the descriptor signature
	idx := bytes.LastIndex([]byte(descText), []byte("\nsignature "))
	if idx < 0 {
		t.Fatal("test descriptor has no signature line")
	}
	sigStart := idx + len("\nsignature ")
	tampered := []byte(descText)
	if tampered[sigStart] == 'A' {
		tampered[sigStart] = 'B'
	} else {
		tampered[sigStart] = 'A'
	}
	if _, err := NewReceivedDescriptor(string(tampered), onionAddress, expectedBlinded); err != ErrBadDescriptor {
		t.Fatalf("tampered descriptor not rejected as BadDescriptor: %v", err)
	}
	t.Log("OK: tampered descriptor rejected")
}

func TestNewReceivedDescriptor_RejectsWrongIdentityBinding(t *testing.T) {
	descText, onionAddress, _ := buildHonestDescriptor(t)

	// expectation derived for a DIFFERENT period/identity
	otherExpected := bytes.Repeat([]byte{0x13}, 32)
	if _, err := NewReceivedDescriptor(descText, onionAddress, otherExpected); err != ErrBadDescriptor {
		t.Fatalf("descriptor not bound to the expected blinded key was accepted: %v", err)
	}
	t.Log("OK: descriptor carrying a blinded key that does not match the consensus expectation is rejected")
}
