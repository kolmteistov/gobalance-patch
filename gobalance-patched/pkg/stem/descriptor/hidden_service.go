package descriptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/brand"
	"gobalance/pkg/btime"
	"gobalance/pkg/gobpk"
	"gobalance/pkg/onionbalance/utils"
	"gobalance/pkg/stem/util"
	"golang.org/x/crypto/sha3"
	"maze.io/x/crypto/x25519"
	"strconv"
	"strings"
)

// Descriptor common parent for all types of descriptors.
// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/rend-spec-v3.txt#L1057
type Descriptor struct {
	hsDescriptorVersion      int64
	descriptorLifetime       int64
	descriptorSigningKeyCert string
	revisionCounter          int64
	superencrypted           string
	signature                string
}

func (d *Descriptor) FromStr(content string) error {
	desc, err := descFromStr(content)
	if err != nil {
		return err
	}
	*d = *desc
	return nil
}

func descFromStr(content string) (*Descriptor, error) {
	d := &Descriptor{}
	lines := strings.Split(content, "\n")
	startCert := false
	startSuperencrypted := false
	var err error
	for idx, line := range lines {
		if idx == 0 {
			d.hsDescriptorVersion, err = strconv.ParseInt(strings.TrimPrefix(line, "hs-descriptor "), 10, 64)
			if err != nil {
				return nil, err
			}
			continue
		} else if idx == 1 {
			d.descriptorLifetime, err = strconv.ParseInt(strings.TrimPrefix(line, "descriptor-lifetime "), 10, 64)
			if err != nil {
				return nil, err
			}
			continue
		} else if line == "descriptor-signing-key-cert" {
			startCert = true
			continue
		} else if line == "superencrypted" {
			startSuperencrypted = true
			continue
		} else if strings.HasPrefix(line, "revision-counter ") {
			d.revisionCounter, err = strconv.ParseInt(strings.TrimPrefix(line, "revision-counter "), 10, 64)
			if err != nil {
				return nil, err
			}
			continue
		} else if strings.HasPrefix(line, "signature ") {
			d.signature = strings.TrimPrefix(line, "signature ")
			continue
		}
		if startCert {
			d.descriptorSigningKeyCert += line + "\n"
			if line == "-----END ED25519 CERT-----" {
				startCert = false
				d.descriptorSigningKeyCert = strings.TrimSpace(d.descriptorSigningKeyCert)
			}
		} else if startSuperencrypted {
			d.superencrypted += line + "\n"
			if line == "-----END MESSAGE-----" {
				startSuperencrypted = false
				d.superencrypted = strings.TrimSpace(d.superencrypted)
			}
		}
	}
	return d, nil
}

// BaseHiddenServiceDescriptor hidden service descriptor.
type BaseHiddenServiceDescriptor struct {
	Descriptor
}

const (
	// ExtensionType

	HasSigningKey = 4
)

// HiddenServiceDescriptorV3 version 3 hidden service descriptor.
type HiddenServiceDescriptorV3 struct {
	BaseHiddenServiceDescriptor
	SigningCert Ed25519CertificateV1
	InnerLayer  *InnerLayer
	rawContents string
}

func (d *HiddenServiceDescriptorV3) String() string {
	var sb strings.Builder
	sb.WriteString("hs-descriptor 3\n")
	sb.WriteString("descriptor-lifetime ")
	sb.WriteString(strconv.FormatInt(d.descriptorLifetime, 10))
	sb.WriteByte('\n')
	sb.WriteString("descriptor-signing-key-cert\n")
	sb.WriteString(d.descriptorSigningKeyCert)
	sb.WriteByte('\n')
	sb.WriteString("revision-counter ")
	sb.WriteString(strconv.FormatInt(d.revisionCounter, 10))
	sb.WriteByte('\n')
	sb.WriteString("superencrypted\n")
	sb.WriteString(d.superencrypted)
	sb.WriteByte('\n')
	sb.WriteString("signature ")
	sb.WriteString(d.signature)
	return sb.String()
}

func (d *HiddenServiceDescriptorV3) Decrypt(onionAddress string) (*InnerLayer, error) {
	if d.InnerLayer == nil {

		descriptorSigningKeyCert := d.descriptorSigningKeyCert
		cert, err := Ed25519CertificateFromBase64(descriptorSigningKeyCert)
		if err != nil {
			return d.InnerLayer, fmt.Errorf("failed to get certificate: %s : %w", descriptorSigningKeyCert, err)
		}
		blindedKey := cert.SigningKey()
		if blindedKey == nil {
			return d.InnerLayer, errors.New("no signing key is present")
		}
		identityPublicKey := identityKeyFromAddress(onionAddress)
		subcredential := subcredential(identityPublicKey, blindedKey)
		outerLayer := outerLayerDecrypt(d.superencrypted, d.revisionCounter, subcredential, blindedKey)
		d.InnerLayer = innerLayerDecrypt(outerLayer, d.revisionCounter, subcredential, blindedKey)
	}
	return d.InnerLayer, nil
}

func blindedPubkey(identityKey gobpk.PrivateKey, blindingNonce []byte) ed25519.PublicKey {
	return util.BlindedPubkey(identityKey.Public(), blindingNonce)
}

func blindedSign(msg []byte, identityKey gobpk.PrivateKey, blindedKey, blindingNonce []byte) []byte {
	if identityKey.IsPrivKeyInTorFormat() {
		// Tor-format keys are already EXTENDED (a||h, 64 bytes).
		// SECURITY (fixed): the previous code passed identityKey.Seed() here,
		// which is only the 32-byte scalar 'a'. Discarding the PRF half 'h'
		// made the blinded signature nonce prefix a public constant
		// (kPrime = SHA512("Derive temporary signing key hash input")) so
		// anyone could recover the master identity key from one public
		// descriptor. Pass the complete key instead.
		return util.BlindedSignWithTorKey(msg, identityKey.PrivKey(), blindedKey, blindingNonce)
	}
	return util.BlindedSign(msg, identityKey.Seed(), blindedKey, blindingNonce)
}

func hiddenServiceDescriptorV3Content(blindingNonce []byte, identityKey gobpk.PrivateKey,
	descSigningKey ed25519.PrivateKey, innerLayer *InnerLayer, revCounter *int64) string {
	if innerLayer == nil {
		innerLayer = InnerLayerCreate(nil)
	}
	if descSigningKey == nil {
		_, descSigningKey, _ = ed25519.GenerateKey(brand.Reader())
	}
	if revCounter == nil {
		tmp := btime.Clock.Now().Unix()
		revCounter = &tmp
	}
	blindedKey := blindedPubkey(identityKey, blindingNonce)
	//if blinding_nonce != nil {
	//      blindedKey = onionbalance.BlindedPubkey(identityKey, blinding_nonce)
	//}
	pub := identityKey.Public()
	subCredential := subcredential(pub, blindedKey)

	//if outerLayer == nil {
	outerLayer := outerLayerCreate(innerLayer, revCounter, subCredential, blindedKey)
	//}

	// if {
	signingCert := getSigningCert(blindedKey, descSigningKey, identityKey, blindingNonce)
	// }

	descContent := "hs-descriptor 3\n"
	descContent += fmt.Sprintf("descriptor-lifetime %d\n", 180)
	descContent += "descriptor-signing-key-cert\n"
	descContent += signingCert.ToBase64() + "\n"
	descContent += fmt.Sprintf("revision-counter %d\n", *revCounter)
	descContent += "superencrypted\n"
	descContent += outerLayer.encrypt(*revCounter, subCredential, blindedKey) + "\n"

	sigContent := SigPrefixHsV3 + descContent
	sig := ed25519.Sign(descSigningKey, []byte(sigContent))
	descContent += fmt.Sprintf("signature %s", strings.TrimRight(base64.StdEncoding.EncodeToString(sig), "="))

	return descContent
}

func getSigningCert(blindedKey ed25519.PublicKey, descSigningKey ed25519.PrivateKey, identityKey gobpk.PrivateKey, blindingNonce []byte) Ed25519CertificateV1 {
	extensions := []Ed25519Extension{NewEd25519Extension(HasSigningKey, 0, blindedKey)}
	signingCert := NewEd25519CertificateV1(HsV3DescSigning, nil, 1, descSigningKey.Public().(ed25519.PublicKey), extensions, nil, nil)
	signingCert.SetSignature(blindedSign(signingCert.pack(), identityKey, blindedKey, blindingNonce))
	return signingCert
}

const SigPrefixHsV3 = "Tor onion service descriptor sig v3"

func HiddenServiceDescriptorV3Create(blindingNonce []byte, identityPrivKey gobpk.PrivateKey, descSigningKey ed25519.PrivateKey, v3DescInnerLayer *InnerLayer, revCounter int64) *HiddenServiceDescriptorV3 {
	return newHiddenServiceDescriptorV3(hiddenServiceDescriptorV3Content(blindingNonce, identityPrivKey, descSigningKey, v3DescInnerLayer, &revCounter))
}

func newHiddenServiceDescriptorV3(rawContents string) *HiddenServiceDescriptorV3 {
	d := &HiddenServiceDescriptorV3{}
	d.rawContents = rawContents
	if err := d.Descriptor.FromStr(rawContents); err != nil {
		logrus.Panicf("failed to parse descriptor from string (%v)", err)
	}
	var err error
	d.SigningCert, err = Ed25519CertificateFromBase64(d.descriptorSigningKeyCert)
	if err != nil {
		logrus.Panicf("failed to get certificate: %s : %v", rawContents, err)
	}
	return d
}

type InnerLayer struct {
	outer                      OuterLayer
	IntroductionPoints         []IntroductionPointV3
	unparsedIntroductionPoints string
	rawContents                string
}

func (l *InnerLayer) encrypt(revisionCounter int64, subcredential, blindedKey []byte) string {
	// encrypt back into an outer layer's 'encrypted' field
	return encryptLayer(l.getBytes(), []byte("hsdir-encrypted-data"), revisionCounter, subcredential, blindedKey)
}

func (l *InnerLayer) getBytes() []byte {
	return []byte(l.rawContents)
}

func innerLayerContent(introductionPoints []IntroductionPointV3) string {
	var sb strings.Builder
	sb.WriteString("create2-formats 2")
	for _, ip := range introductionPoints {
		sb.WriteByte('\n')
		sb.WriteString(ip.encode())
	}
	return sb.String()
}

func InnerLayerCreate(introductionPoints []IntroductionPointV3) *InnerLayer {
	return newInnerLayer(innerLayerContent(introductionPoints), OuterLayer{})
}

func newInnerLayer(content string, outerLayer OuterLayer) *InnerLayer {
	l := &InnerLayer{}
	l.rawContents = content
	l.outer = outerLayer
	div := strings.Index(content, "\nintroduction-point ")
	if div != -1 {
		l.unparsedIntroductionPoints = content[div+1:]
		//content = content[:div]
	} else {
		l.unparsedIntroductionPoints = ""
	}
	//entries := descriptor_components(content, validate)
	l.parseV3IntroductionPoints()
	return l
}

type IntroductionPointV3 struct {
	LinkSpecifiers []LinkSpecifier
	OnionKey       string
	EncKey         string
	AuthKeyCertRaw string
	EncKeyCertRaw  string
	AuthKeyCert    Ed25519CertificateV1
	EncKeyCert     Ed25519CertificateV1
	LegacyKeyRaw   any
}

func (i IntroductionPointV3) Equals(other IntroductionPointV3) bool {
	return i.encode() == other.encode()
}

// Descriptor representation of this introduction point.
func (i IntroductionPointV3) encode() string {
	var sb strings.Builder
	linkCount := uint8(len(i.LinkSpecifiers))
	linkSpecifiers := []byte{linkCount}
	for _, ls := range i.LinkSpecifiers {
		linkSpecifiers = append(linkSpecifiers, ls.pack()...)
	}
	sb.WriteString("introduction-point ")
	sb.WriteString(base64.StdEncoding.EncodeToString(linkSpecifiers))
	sb.WriteString("\n")

	sb.WriteString("onion-key ntor ")
	sb.WriteString(i.OnionKey)
	sb.WriteString("\n")

	sb.WriteString("auth-key\n")
	sb.WriteString(i.AuthKeyCertRaw)
	sb.WriteString("\n")

	if i.EncKey != "" {
		sb.WriteString("enc-key ntor ")
		sb.WriteString(i.EncKey)
		sb.WriteString("\n")
	}
	sb.WriteString("enc-key-cert\n")
	sb.WriteString(i.EncKeyCertRaw)
	return sb.String()
}

func parseLinkSpecifier(content string) []LinkSpecifier {
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		logrus.Panicf("Unable to base64 decode introduction point (%v): %s", err, content)
	}
	count, decoded := decoded[0], decoded[1:]
	linkSpecifiers := make([]LinkSpecifier, count)
	for i := 0; i < int(count); i++ {
		var linkSpecifier LinkSpecifier
		linkSpecifier, decoded = linkSpecifierPop(decoded)
		linkSpecifiers[i] = linkSpecifier
	}
	if len(decoded) > 0 {
		logrus.Panicf("Introduction point had excessive data (%s)", decoded)
	}
	return linkSpecifiers
}

type LinkSpecifier struct {
	typ   uint8
	value []byte
}

func (l LinkSpecifier) String() string {
	return fmt.Sprintf("T:%d,V:%x", l.typ, l.value)
}

func (l LinkSpecifier) pack() []byte {
	var buf bytes.Buffer
	buf.WriteByte(l.typ)
	buf.WriteByte(byte(len(l.value)))
	buf.Write(l.value)
	return buf.Bytes()
}

func linkSpecifierPop(packed []byte) (LinkSpecifier, []byte) {
	linkType, packed := packed[0], packed[1:]
	valueSize, packed := packed[0], packed[1:]
	if int(valueSize) > len(packed) {
		logrus.Panicf("Link specifier should have %d bytes, but only had %d remaining", valueSize, len(packed))
	}
	value, packed := packed[:valueSize], packed[valueSize:]
	if linkType == 0 {
		return linkByIPv4Unpack(value).LinkSpecifier, packed
	} else if linkType == 1 {
		return linkByIPv6Unpack(value).LinkSpecifier, packed
	} else if linkType == 2 {
		return newLinkByFingerprint(value).LinkSpecifier, packed
	} else if linkType == 3 {
		return newLinkByEd25519(value).LinkSpecifier, packed
	}
	return LinkSpecifier{typ: linkType, value: value}, packed // unrecognized type
}

type LinkByIPv4 struct {
	LinkSpecifier
	address string
	port    uint16
}

func newLinkByIPv4(address string, port uint16) LinkByIPv4 {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	l := LinkByIPv4{}
	l.typ = 0
	l.value = append(packIPV4Address(address), portBytes...)
	l.address = address
	l.port = port
	return l
}

func linkByIPv4Unpack(value []byte) LinkByIPv4 {
	if len(value) != 6 {
		logrus.Panicf("IPv4 link specifiers should be six bytes, but was %d instead: %x", len(value), value)
	}
	addr, portRaw := value[:4], value[4:]
	port := binary.BigEndian.Uint16(portRaw)
	return newLinkByIPv4(unpackIPV4Address(addr), port)
}

func newLinkByIPv6(address string, port uint16) LinkByIPv6 {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	l := LinkByIPv6{}
	l.typ = 1
	l.value = append(packIPV6Address(address), portBytes...)
	l.address = address
	l.port = port
	return l
}

func linkByIPv6Unpack(value []byte) LinkByIPv6 {
	if len(value) != 18 {
		logrus.Panicf("IPv6 link specifiers should be eighteen bytes, but was %d instead: %x", len(value), value)
	}
	addr, portRaw := value[:16], value[16:]
	port := binary.BigEndian.Uint16(portRaw)
	return newLinkByIPv6(unpackIPV6Address(addr), port)
}

func packIPV4Address(address string) (out []byte) {
	parts := strings.Split(address, ".")
	for _, part := range parts {
		tmp, _ := strconv.ParseUint(part, 10, 8)
		out = append(out, uint8(tmp))
	}
	return
}

func unpackIPV4Address(value []byte) string {
	strs := make([]string, 0)
	for i := 0; i < 4; i++ {
		strs = append(strs, fmt.Sprintf("%d", value[i]))
	}
	return strings.Join(strs, ".")
}

func packIPV6Address(address string) (out []byte) {
	parts := strings.Split(address, ":")
	for _, part := range parts {
		tmp, _ := hex.DecodeString(part)
		out = append(out, tmp...)
	}
	return
}

func unpackIPV6Address(value []byte) string {
	strs := make([]string, 0)
	for i := 0; i < 8; i++ {
		strs = append(strs, fmt.Sprintf("%04x", value[i*2:(i+1)*2]))
	}
	return strings.Join(strs, ":")
}

type LinkByIPv6 struct {
	LinkSpecifier
	address string
	port    uint16
}

type LinkByFingerprint struct {
	LinkSpecifier
	fingerprint []byte
}

type LinkByEd25519 struct {
	LinkSpecifier
	fingerprint []byte
}

func newLinkByFingerprint(value []byte) LinkByFingerprint {
	if len(value) != 20 {
		logrus.Panicf("Fingerprint link specifiers should be twenty bytes, but was %d instead: %x", len(value), value)
	}
	l := LinkByFingerprint{}
	l.typ = 2
	l.value = value
	l.fingerprint = value
	return l
}

func newLinkByEd25519(value []byte) LinkByEd25519 {
	if len(value) != 32 {
		logrus.Panicf("Fingerprint link specifiers should be thirty two bytes, but was %d instead: %x", len(value), value)
	}
	l := LinkByEd25519{}
	l.typ = 3
	l.value = value
	l.fingerprint = value
	return l
}

func introductionPointV3Parse(content string) (IntroductionPointV3, error) {
	ip := IntroductionPointV3{}
	authKeyCertContent := ""
	encKeyCertContent := ""
	lines := strings.Split(content, "\n")
	startAuthKey := false
	startEncKeyCert := false
	for _, line := range lines {
		if line == "auth-key" {
			startAuthKey = true
			continue
		} else if strings.HasPrefix(line, "introduction-point ") {
			ip.LinkSpecifiers = parseLinkSpecifier(strings.TrimPrefix(line, "introduction-point "))
			continue
		} else if strings.HasPrefix(line, "onion-key ntor ") {
			ip.OnionKey = strings.TrimPrefix(line, "onion-key ntor ")
			continue
		} else if strings.HasPrefix(line, "enc-key ntor ") {
			ip.EncKey = strings.TrimPrefix(line, "enc-key ntor ")
			continue
		} else if line == "enc-key-cert" {
			startEncKeyCert = true
			continue
		}
		if startAuthKey {
			authKeyCertContent += line + "\n"
			if line == "-----END ED25519 CERT-----" {
				startAuthKey = false
				authKeyCertContent = strings.TrimSpace(authKeyCertContent)
			}
		}
		if startEncKeyCert {
			encKeyCertContent += line + "\n"
			if line == "-----END ED25519 CERT-----" {
				startEncKeyCert = false
				encKeyCertContent = strings.TrimSpace(encKeyCertContent)
			}
		}
	}
	ip.AuthKeyCertRaw = authKeyCertContent
	ip.EncKeyCertRaw = encKeyCertContent
	var err error
	ip.AuthKeyCert, err = Ed25519CertificateFromBase64(authKeyCertContent)
	if err != nil {
		return ip, err
	}
	ip.EncKeyCert, err = Ed25519CertificateFromBase64(encKeyCertContent)
	if err != nil {
		return ip, err
	}
	return ip, nil
}

func (l *InnerLayer) parseV3IntroductionPoints() {
	introductionPoints := make([]IntroductionPointV3, 0)
	remaining := l.unparsedIntroductionPoints
	for remaining != "" {
		div := strings.Index(remaining, "\nintroduction-point ")
		var content string
		if div != -1 {
			content = remaining[:div]
			remaining = remaining[div+1:]
		} else {
			content = remaining
			remaining = ""
		}
		ip, err := introductionPointV3Parse(content)
		if err != nil {
			logrus.Errorf("introductionPointV3Parse %v", err)
			continue
		}
		introductionPoints = append(introductionPoints, ip)
	}
	l.IntroductionPoints = introductionPoints
}

func innerLayerDecrypt(outerLayer OuterLayer, revisionCounter int64, subcredential, blindedKey ed25519.PublicKey) *InnerLayer {
	plaintext := decryptLayer(outerLayer.encrypted, []byte("hsdir-encrypted-data"), revisionCounter, subcredential, blindedKey)
	return newInnerLayer(plaintext, outerLayer)
}

type OuterLayer struct {
	encrypted  string
	rawContent string
}

func (l OuterLayer) encrypt(revisionCounter int64, subcredential, blindedKey []byte) string {
	// Spec mandated padding: "Before encryption the plaintext is padded with
	// NUL bytes to the nearest multiple of 10k bytes."
	content := append(l.getBytes(), bytes.Repeat([]byte("\x00"), len(l.getBytes())%10000)...)
	// encrypt back into a hidden service descriptor's 'superencrypted' field
	return encryptLayer(content, []byte("hsdir-superencrypted-data"), revisionCounter, subcredential, blindedKey)
}

func encryptLayer(plaintext, constant []byte, revisionCounter int64, subcredential, blindedKey []byte) string {
	salt := make([]byte, 16)
	_, _ = brand.Read(salt)
	return encryptLayerDet(plaintext, constant, revisionCounter, subcredential, blindedKey, salt)
}

// Deterministic code for tests
func encryptLayerDet(plaintext, constant []byte, revisionCounter int64, subcredential, blindedKey, salt []byte) string {
	ciphr, macFor := layerCipher(constant, revisionCounter, subcredential, blindedKey, salt)
	ciphertext := make([]byte, len(plaintext))
	ciphr.XORKeyStream(ciphertext, plaintext)
	encoded := base64.StdEncoding.EncodeToString(utils.BConcat(salt, ciphertext, macFor(ciphertext)))
	splits := splitByLength(encoded, 64)
	joined := strings.Join(splits, "\n")
	return fmt.Sprintf("-----BEGIN MESSAGE-----\n%s\n-----END MESSAGE-----", joined)
}

func (l OuterLayer) getBytes() []byte {
	return []byte(l.rawContent)
}

func outerLayerCreate(innerLayer *InnerLayer, revisionCounter *int64, subcredential, blindedKey []byte) OuterLayer {
	return newOuterLayer(outerLayerContent(innerLayer, revisionCounter, subcredential, blindedKey))
}

// AuthorizedClient Client authorized to use a v3 hidden service.
// id: base64 encoded client id
// iv: base64 encoded randomized initialization vector
// cookie: base64 encoded authentication cookie
type AuthorizedClient struct {
	id     string
	iv     string
	cookie string
}

func newAuthorizedClient() AuthorizedClient {
	a := AuthorizedClient{}
	idBytes := make([]byte, 8)
	_, _ = brand.Read(idBytes)
	a.id = strings.TrimRight(base64.StdEncoding.EncodeToString(idBytes), "=")
	ivBytes := make([]byte, 16)
	_, _ = brand.Read(ivBytes)
	a.iv = strings.TrimRight(base64.StdEncoding.EncodeToString(ivBytes), "=")
	cookieBytes := make([]byte, 16)
	_, _ = brand.Read(cookieBytes)
	a.cookie = strings.TrimRight(base64.StdEncoding.EncodeToString(cookieBytes), "=")
	return a
}

func outerLayerContent(innerLayer *InnerLayer, revisionCounter *int64, subcredential, blindedKey []byte) string {
	if innerLayer == nil {
		innerLayer = InnerLayerCreate(nil)
	}

	authorizedClients := make([]AuthorizedClient, 0)
	for i := 0; i < 16; i++ {
		authorizedClients = append(authorizedClients, newAuthorizedClient())
	}

	pk, err := x25519.GenerateKey(brand.Reader())
	if err != nil {
		panic(err)
	}

	out := "desc-auth-type x25519\n"
	out += "desc-auth-ephemeral-key " + base64.StdEncoding.EncodeToString(pk.PublicKey.Bytes()) + "\n"
	for _, c := range authorizedClients {
		out += fmt.Sprintf("auth-client %s %s %s\n", c.id, c.iv, c.cookie)
	}
	out += "encrypted\n"
	out += innerLayer.encrypt(*revisionCounter, subcredential, blindedKey)
	return out
}

func newOuterLayer(content string) OuterLayer {
	l := OuterLayer{}
	l.rawContent = content
	encrypted := parseOuterLayer(content)
	l.encrypted = encrypted
	return l
}

func parseOuterLayer(content string) string {
	out := ""
	lines := strings.Split(content, "\n")
	startEncrypted := false
	for _, line := range lines {
		if line == "encrypted" {
			startEncrypted = true
			continue
		}
		if startEncrypted {
			out += line + "\n"
			if line == "-----END MESSAGE-----" {
				startEncrypted = false
				out = strings.TrimSpace(out)
			}
		}
	}
	out = strings.ReplaceAll(out, "\r", "")
	out = strings.ReplaceAll(out, "\x00", "")
	return strings.TrimSpace(out)
}

func outerLayerDecrypt(encrypted string, revisionCounter int64, subcredential, blindedKey ed25519.PublicKey) OuterLayer {
	plaintext := decryptLayer(encrypted, []byte("hsdir-superencrypted-data"), revisionCounter, subcredential, blindedKey)
	return newOuterLayer(plaintext)
}

func decryptLayer(encryptedBlock string, constant []byte, revisionCounter int64, subcredential, blindedKey ed25519.PublicKey) string {
	if strings.HasPrefix(encryptedBlock, "-----BEGIN MESSAGE-----\n") &&
		strings.HasSuffix(encryptedBlock, "\n-----END MESSAGE-----") {
		encryptedBlock = strings.TrimPrefix(encryptedBlock, "-----BEGIN MESSAGE-----\n")
		encryptedBlock = strings.TrimSuffix(encryptedBlock, "\n-----END MESSAGE-----")
	}
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBlock)
	if err != nil {
		panic("Unable to decode encrypted block as base64")
	}
	if len(encrypted) < SaltLen+MacLen {
		logrus.Panicf("Encrypted block malformed (only %d bytes)", len(encrypted))
	}
	salt := encrypted[:SaltLen]
	ciphertext := encrypted[SaltLen : len(encrypted)-MacLen]
	expectedMac := encrypted[len(encrypted)-MacLen:]
	ciphr, macFor := layerCipher(constant, revisionCounter, subcredential, blindedKey, salt)

	if !bytes.Equal(expectedMac, macFor(ciphertext)) {
		logrus.Panicf("Malformed mac (expected %x, but was %x)", expectedMac, macFor(ciphertext))
	}

	plaintext := make([]byte, len(ciphertext))
	ciphr.XORKeyStream(plaintext, ciphertext)
	return string(plaintext)
}

func layerCipher(constant []byte, revisionCounter int64, subcredential []byte, blindedKey ed25519.PublicKey, salt []byte) (cipher.Stream, func([]byte) []byte) {
	keys := make([]byte, SKeyLen+SIvLen+MacLen)
	data1 := make([]byte, 8)
	binary.BigEndian.PutUint64(data1, uint64(revisionCounter))
	data := utils.BConcat(blindedKey, subcredential, data1, salt, constant)
	sha3.ShakeSum256(keys, data)

	secretKey := keys[:SKeyLen]
	secretIv := keys[SKeyLen : SKeyLen+SIvLen]
	macKey := keys[SKeyLen+SIvLen:]

	block, _ := aes.NewCipher(secretKey)
	ciphr := cipher.NewCTR(block, secretIv)
	data2 := make([]byte, 8)
	binary.BigEndian.PutUint64(data2, uint64(len(macKey)))
	data3 := make([]byte, 8)
	binary.BigEndian.PutUint64(data3, uint64(len(salt)))
	macPrefix := utils.BConcat(data2, macKey, data3, salt)
	fn := func(ciphertext []byte) []byte {
		tmp := sha3.Sum256(utils.BConcat(macPrefix, ciphertext))
		return tmp[:]
	}
	return ciphr, fn
}

const (
	SKeyLen = 32
	SIvLen  = 16
	SaltLen = 16
	MacLen  = 32
)

// Converts a hidden service address into its public identity key.
func identityKeyFromAddress(onionAddress string) ed25519.PublicKey {
	onionAddress = strings.TrimSuffix(onionAddress, ".onion")
	decodedAddress, _ := base32.StdEncoding.DecodeString(strings.ToUpper(onionAddress))
	pubKey := decodedAddress[:32]
	expectedChecksum := decodedAddress[32:34]
	version := decodedAddress[34:35]
	checksumTmp := sha3.Sum256(utils.BConcat([]byte(".onion checksum"), pubKey, version))
	checksum := checksumTmp[:2]
	if !bytes.Equal(expectedChecksum, checksum) {
		logrus.Panicf("Bad checksum (expected %x but was %x)", expectedChecksum, checksum)
	}
	return pubKey
}

// IdentityKeyFromAddress decode an onion address back into its ed25519
// identity public key. Exported so that peer packages (e.g. onionbalance's
// descriptor intake) can bind a received descriptor to the identity it
// claims to belong to before trusting it.
func IdentityKeyFromAddress(onionAddress string) ed25519.PublicKey {
	return identityKeyFromAddress(onionAddress)
}

// VerifyHiddenServiceDescriptorV3 cryptographically verifies a v3 hidden
// service descriptor:
//
//  1. the descriptor-signing-key certificate must be signed by the blinded
//     key it carries (standard ed25519 verification against the cert bytes);
//  2. the descriptor 'signature' line must be a valid ed25519 signature over
//     the descriptor body made by the certified descriptor signing key;
//  3. if any expected blinded keys are supplied, the blinded key carried in
//     the certificate must match one of them — binding the descriptor to the
//     identity and time period(s) derived independently from the consensus.
//
// SECURITY (fixed): descriptors received from the network used to be accepted
// after parsing/decrypting only. Because the subcredential is derived from
// the identity pubkey AND the blinded key carried inside the descriptor
// itself, an attacker can mint a fully self-consistent descriptor for
// somebody else's onion address using keys of their own choosing. Without
// check (3) such a forged descriptor is accepted, and the frontend then
// republishes the attacker's introduction points under the victim's real
// identity — a complete traffic hijack that needs no key recovery at all.
func VerifyHiddenServiceDescriptorV3(descText string, expectedBlindedKeys ...ed25519.PublicKey) error {
	// The 'signature' line is always the last line of the descriptor.
	sigMarker := "\nsignature "
	sigIdx := strings.LastIndex(descText, sigMarker)
	if sigIdx < 0 {
		return fmt.Errorf("descriptor has no signature line")
	}
	// The newline BEFORE the signature line is part of the signed body (it
	// terminates the last body line); the signature line starts after it.
	body := descText[:sigIdx+1]
	sigB64 := strings.TrimSpace(descText[sigIdx+len(sigMarker):])
	// Tor writes the descriptor signature as UNPADDED base64 (it strips the
	// trailing '='). Normalise back to a padded form before decoding.
	sigB64 = strings.TrimRight(sigB64, "=")
	if pad := len(sigB64) % 4; pad != 0 {
		sigB64 += strings.Repeat("=", 4-pad)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("descriptor signature is not valid base64: %w", err)
	}

	// Parse the descriptor header fields (cert, superencrypted block, ...).
	d, err := descFromStr(descText)
	if err != nil {
		return fmt.Errorf("cannot parse descriptor: %w", err)
	}
	if d.descriptorSigningKeyCert == "" {
		return fmt.Errorf("descriptor carries no signing key certificate")
	}
	certRaw, err := certPemToBytes(d.descriptorSigningKeyCert)
	if err != nil {
		return fmt.Errorf("cannot decode signing cert: %w", err)
	}
	cert, err := Ed25519CertificateV1Unpack(certRaw)
	if err != nil {
		return fmt.Errorf("cannot unpack signing cert: %w", err)
	}
	blindedKey := cert.SigningKey()
	if blindedKey == nil {
		return fmt.Errorf("signing cert carries no blinded key extension")
	}
	descSigningKey := cert.Key()
	if descSigningKey == nil || len(descSigningKey) != ed25519.PublicKeySize {
		return fmt.Errorf("signing cert carries no certified descriptor signing key")
	}

	// (1) Certificate signature: the packed cert minus its trailing 64-byte
	// signature, verified under the blinded key it certifies.
	if len(certRaw) < ed25519.SignatureSize {
		return fmt.Errorf("signing cert is too short to carry a signature")
	}
	unsignedCert := certRaw[:len(certRaw)-ed25519.SignatureSize]
	certSig := certRaw[len(certRaw)-ed25519.SignatureSize:]
	if !ed25519.Verify(blindedKey, unsignedCert, certSig) {
		return fmt.Errorf("signing-cert signature does not verify under the blinded key")
	}

	// (2) Descriptor signature under the certified descriptor signing key.
	sigContent := SigPrefixHsV3 + body
	if !ed25519.Verify(descSigningKey, []byte(sigContent), sig) {
		return fmt.Errorf("descriptor signature does not verify under the certified descriptor signing key")
	}

	// (3) Bind the blinded key to the identity/time-period expected by the
	// caller (derived independently from the consensus, NOT from the
	// descriptor itself).
	if len(expectedBlindedKeys) > 0 {
		bound := false
		for _, expected := range expectedBlindedKeys {
			if bytes.Equal(expected, blindedKey) {
				bound = true
				break
			}
		}
		if !bound {
			return fmt.Errorf("blinded key in descriptor is not bound to this identity/time-period — possible forged descriptor")
		}
	}
	return nil
}

// certPemToBytes decodes the PEM-wrapped base64 certificate body embedded in
// a descriptor into its raw packed bytes.
func certPemToBytes(pem string) ([]byte, error) {
	pem = strings.TrimSpace(pem)
	pem = strings.TrimPrefix(pem, "-----BEGIN ED25519 CERT-----\n")
	pem = strings.TrimSuffix(pem, "\n-----END ED25519 CERT-----")
	pem = strings.ReplaceAll(pem, "\n", "")
	return base64.StdEncoding.DecodeString(pem)
}

func AddressFromIdentityKey(pub ed25519.PublicKey) string {
	var checksumBytes bytes.Buffer
	checksumBytes.WriteString(".onion checksum")
	checksumBytes.Write(pub)
	checksumBytes.WriteByte(0x03)
	checksum := sha3.Sum256(checksumBytes.Bytes())
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write(pub)
	onionAddressBytes.Write(checksum[:2])
	onionAddressBytes.WriteByte(0x03)
	addr := strings.ToLower(base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes()))
	return addr + ".onion"
}

func subcredential(identityKey, blindedKey ed25519.PublicKey) []byte {
	// credential = H('credential' | public-identity-key)
	// subcredential = H('subcredential' | credential | blinded-public-key)
	credential := sha3.Sum256(utils.BConcat([]byte("credential"), identityKey))
	sub := sha3.Sum256(utils.BConcat([]byte("subcredential"), credential[:], blindedKey))
	return sub[:]
}
