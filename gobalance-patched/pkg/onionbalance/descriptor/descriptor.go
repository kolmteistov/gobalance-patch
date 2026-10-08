package descriptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/brand"
	"gobalance/pkg/btime"
	"gobalance/pkg/gobpk"
	"gobalance/pkg/onionbalance/consensus"
	"gobalance/pkg/onionbalance/param"
	"gobalance/pkg/onionbalance/utils"
	"gobalance/pkg/stem/descriptor"
	"golang.org/x/crypto/sha3"
	"sort"
	"time"
)

var ErrBadDescriptor = errors.New("BadDescriptor")

type IntroductionPointSet struct {
}

type IntroductionPointSetV3 struct {
	IntroductionPointSet
	introPoints [][]descriptor.IntroductionPointV3
}

func (i *IntroductionPointSetV3) IntroPoints() [][]descriptor.IntroductionPointV3 {
	return i.introPoints
}

func NewIntroductionPointSetV3(introductionPoints [][]descriptor.IntroductionPointV3) *IntroductionPointSetV3 {
	for _, instanceIps := range introductionPoints {
		for i := len(instanceIps) - 1; i >= 0; i-- {
			if instanceIps[i].LegacyKeyRaw != nil {
				logrus.Info("Ignoring introduction point with legacy key.")
				instanceIps = append(instanceIps[:i], instanceIps[i+1:]...)
			}
		}
	}

	i := &IntroductionPointSetV3{}

	for idx, instanceIntroPoints := range introductionPoints {
		cryptoShuffle(len(instanceIntroPoints), func(i, j int) {
			introductionPoints[idx][i], introductionPoints[idx][j] = introductionPoints[idx][j], introductionPoints[idx][i]
		})
	}
	cryptoShuffle(len(introductionPoints), func(i, j int) {
		introductionPoints[i], introductionPoints[j] = introductionPoints[j], introductionPoints[i]
	})
	i.introPoints = introductionPoints
	// self._intro_point_generator = self._get_intro_point()
	return i
}

// cryptoShuffle randomizes the order of elements using cryptographically
// secure randomness (brand.Read, i.e. crypto/rand) instead of math/rand.
// SECURITY (hardening): the previous math/rand-based shuffling produced a
// predictable introduction-point ordering when the global source was not
// randomly seeded, which makes client routing choices linkable/predictable.
func cryptoShuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		j := cryptoRandInt(i + 1)
		swap(i, j)
	}
}

// cryptoRandInt returns a uniform random int in [0, n) using rejection
// sampling over 4 random bytes.
func cryptoRandInt(n int) int {
	if n <= 1 {
		return 0
	}
	// Largest multiple of n that fits in 32 bits; values below it are uniform.
	limit := (int64(1) << 32) / int64(n) * int64(n)
	var buf [4]byte
	for {
		if _, err := brand.Read(buf[:]); err != nil {
			// crypto/rand failure is unrecoverable — never fall back to a
			// predictable source.
			panic(fmt.Sprintf("crypto/rand failed: %v", err))
		}
		v := int64(binary.BigEndian.Uint32(buf[:]))
		if v < limit {
			return int(v % int64(n))
		}
	}
}

func (i *IntroductionPointSetV3) Equals(other IntroductionPointSetV3) bool {
	aIntroPoints := i.GetIntroPointsFlat()
	bIntroPoints := other.GetIntroPointsFlat()
	if len(aIntroPoints) != len(bIntroPoints) {
		return false
	}
	sort.Slice(aIntroPoints, func(i, j int) bool { return aIntroPoints[i].OnionKey < aIntroPoints[j].OnionKey })
	sort.Slice(bIntroPoints, func(i, j int) bool { return bIntroPoints[i].OnionKey < bIntroPoints[j].OnionKey })
	for idx := 0; idx < len(aIntroPoints); idx++ {
		if !aIntroPoints[idx].Equals(bIntroPoints[idx]) {
			return false
		}
	}
	return true
}

func (i *IntroductionPointSetV3) Len() (count int) {
	for _, ip := range i.introPoints {
		count += len(ip)
	}
	return
}

// GetIntroPointsFlat Flatten the .intro_points list of list into a single list and return it
func (i *IntroductionPointSetV3) GetIntroPointsFlat() []descriptor.IntroductionPointV3 {
	flatten := make([]descriptor.IntroductionPointV3, 0)
	for _, ip := range i.introPoints {
		flatten = append(flatten, ip...)
	}
	return flatten
}

// Choose Retrieve N introduction points from the set of IPs
// Where more than `count` IPs are available, introduction points are
// selected to try and achieve the greatest distribution of introduction
// points across all of the available backend instances.
// Return a list of IntroductionPoints.
func (i *IntroductionPointSetV3) Choose(count int) []descriptor.IntroductionPointV3 {
	shuffle := utils.Noop(true)
	choosenIps := i.GetIntroPointsFlat()
	if shuffle {
		cryptoShuffle(len(choosenIps), func(i, j int) { choosenIps[i], choosenIps[j] = choosenIps[j], choosenIps[i] })
	}
	if len(choosenIps) > count {
		choosenIps = choosenIps[:count]
	}
	return choosenIps
}

// V3Descriptor a generic v3 descriptor.
// Serves as the base class for OBDescriptor and ReceivedDescriptor which
// implement more specific functionalities.
type V3Descriptor struct {
	onionAddress string
	v3Desc       *descriptor.HiddenServiceDescriptorV3
	introSet     *IntroductionPointSetV3
}

func (d *V3Descriptor) OnionAddress() string {
	return d.onionAddress
}

func (d *V3Descriptor) V3Desc() *descriptor.HiddenServiceDescriptorV3 {
	return d.v3Desc
}

func (d *V3Descriptor) IntroSet() *IntroductionPointSetV3 {
	return d.introSet
}

// GetIntroPoints get the raw intro points for this descriptor.
func (d *V3Descriptor) GetIntroPoints() []descriptor.IntroductionPointV3 {
	return d.introSet.GetIntroPointsFlat()
}

// GetBlindedKey Extract and return the blinded key from the descriptor
func (d *V3Descriptor) GetBlindedKey() ed25519.PublicKey {
	// The descriptor signing cert, signs the descriptor signing key using
	// the blinded key. So the signing key should be the one we want here.
	return d.v3Desc.SigningCert.SigningKey()
}

// ReceivedDescriptor an instance v3 descriptor received from the network.
// This class supports parsing descriptors.
type ReceivedDescriptor struct {
	V3Descriptor
	receivedTs *time.Time
}

// NewReceivedDescriptor parse a descriptor in 'desc_text' and return an ReceivedDescriptor object.
// Raises BadDescriptor if the descriptor cannot be used.
//
// SECURITY (fixed): if any expectedBlindedKeys are supplied, the descriptor
// is first cryptographically verified (cert signature under the blinded key,
// descriptor signature under the certified signing key) AND bound to the
// supplied blinded keys — which the caller derives from the consensus and
// the instance identity, independently of the descriptor contents. A fully
// self-consistent descriptor minted by an attacker with their own keys for
// somebody else's onion address is now rejected.
func NewReceivedDescriptor(descText, onionAddress string, expectedBlindedKeys ...ed25519.PublicKey) (*ReceivedDescriptor, error) {
	d := &ReceivedDescriptor{}
	// SECURITY: verify BEFORE parsing into usable structures. A descriptor
	// that fails its signature chain or the identity binding must never
	// reach the introduction-point aggregation path.
	if err := descriptor.VerifyHiddenServiceDescriptorV3(descText, expectedBlindedKeys...); err != nil {
		logrus.Warningf("Rejecting descriptor for %s: %v", onionAddress, err)
		return nil, ErrBadDescriptor
	}
	v3Desc := &descriptor.HiddenServiceDescriptorV3{}
	if err := v3Desc.FromStr(descText); err != nil {
		logrus.Warningf("Descriptor is corrupted (%v).", err)
		return nil, ErrBadDescriptor
	}
	if _, err := v3Desc.Decrypt(onionAddress); err != nil {
		logrus.Errorf("failed to decrypt v3Desc : %s : %s : %v", onionAddress, descText, err)
		return nil, ErrBadDescriptor
	}
	//logger.warning("Descriptor is corrupted (%s).", err)
	//raise BadDescriptor
	d.setReceivedTimestamp(btime.Clock.Now().UTC())
	logrus.Debugf("Successfuly decrypted descriptor for %s!", onionAddress)

	d.onionAddress = onionAddress
	d.v3Desc = v3Desc
	// An IntroductionPointSetV3 object with the intros of this descriptor
	d.introSet = NewIntroductionPointSetV3([][]descriptor.IntroductionPointV3{d.v3Desc.InnerLayer.IntroductionPoints})
	return d, nil
}

func (d *ReceivedDescriptor) setReceivedTimestamp(receivedTs time.Time) {
	d.receivedTs = &receivedTs
}

// IsOld return True if this received descriptor is old and we should consider the
// instance as offline.
func (d *ReceivedDescriptor) IsOld() bool {
	receivedAge := int64(btime.Clock.Now().UTC().Sub(*d.receivedTs).Seconds())
	tooOldThreshold := param.InstanceDescriptorTooOld
	return receivedAge > int64(tooOldThreshold)
}

type OBDescriptor struct {
	V3Descriptor
	lastPublishAttemptTs *time.Time
	lastUploadTs         *time.Time
	responsibleHsdirs    []string
	consensus            *consensus.ConsensusDoc
}

func (d *OBDescriptor) ResponsibleHsdirs() []string {
	return d.responsibleHsdirs
}

func (d *OBDescriptor) LastUploadTs() *time.Time {
	return d.lastUploadTs
}

// NewOBDescriptor A v3 descriptor created by Onionbalance and meant to be published to the
// network.
// This class supports generating descriptors.
// Can raise BadDescriptor if we can't or should not generate a valid descriptor
func NewOBDescriptor(onionAddress string, identityPrivKey gobpk.PrivateKey, blindingParam []byte, introPoints []descriptor.IntroductionPointV3, isFirstDesc bool, consensus *consensus.ConsensusDoc) (*OBDescriptor, error) {
	d := &OBDescriptor{}
	d.consensus = consensus
	// Timestamp of the last attempt to assemble this descriptor
	// d.lastPublishAttemptTs = nil
	// Timestamp we last uploaded this descriptor
	// d.lastUploadTs = nil
	// Set of responsible HSDirs for last time we uploaded this descriptor
	// d.responsibleHsdirs = nil

	// Start generating descriptor
	_, descSigningKey, _ := ed25519.GenerateKey(brand.Reader())

	// Get the intro points for this descriptor and recertify them!
	recertifiedIntroPoints := make([]descriptor.IntroductionPointV3, 0)

	for _, ip := range introPoints {
		rec := d.recertifyIntroPoint(ip, descSigningKey)
		recertifiedIntroPoints = append(recertifiedIntroPoints, rec)
	}

	revCounter := d.getRevisionCounter(identityPrivKey, isFirstDesc)

	v3DescInnerLayer := descriptor.InnerLayerCreate(recertifiedIntroPoints)
	v3Desc := descriptor.HiddenServiceDescriptorV3Create(blindingParam, identityPrivKey, descSigningKey, v3DescInnerLayer, revCounter)

	// TODO stem should probably initialize it itself so that it has balance
	// between descriptor creation (where this is not inted) and descriptor
	// parsing (where this is inited)
	v3Desc.InnerLayer = v3DescInnerLayer

	// Check max size is within range
	if len(v3Desc.String()) > param.MaxDescriptorSize {
		logrus.Errorf("Created descriptor is too big (%%d intros). Consider relaxing number of instances or intro points per instance (see N_INTROS_PER_INSTANCE)")
		return nil, ErrBadDescriptor
	}

	d.onionAddress = onionAddress
	d.v3Desc = v3Desc
	d.introSet = NewIntroductionPointSetV3([][]descriptor.IntroductionPointV3{d.v3Desc.InnerLayer.IntroductionPoints})

	return d, nil
}

func (d *OBDescriptor) SetLastPublishAttemptTs(lastPublishAttemptTs time.Time) {
	d.lastPublishAttemptTs = &lastPublishAttemptTs
}

func (d *OBDescriptor) SetLastUploadTs(lastUploadTs time.Time) {
	d.lastUploadTs = &lastUploadTs
}

func (d *OBDescriptor) SetResponsibleHsdirs(responsibleHsdirs []string) {
	d.responsibleHsdirs = responsibleHsdirs
}

// Get the revision counter using the order-preserving-encryption scheme from
// rend-spec-v3.txt section F.2.
func (d *OBDescriptor) getRevisionCounter(identityPrivKey gobpk.PrivateKey, isFirstDesc bool) int64 {
	now := btime.Clock.Now().Unix()

	// TODO: Mention that this is done with the private key instead of the blinded priv key
	// this means that this won't cooperate with normal tor
	privKeyBytes := identityPrivKey.Seed()

	var srvStart int64
	if isFirstDesc {
		srvStart = d.consensus.GetStartTimeOfPreviousSrvRun()
	} else {
		srvStart = d.consensus.GetStartTimeOfCurrentSrvRun()
	}

	opeResult, secondsSinceSrvStart := getRevisionCounterDet(privKeyBytes, now, srvStart)
	logrus.Debugf("Rev counter for %s descriptor (SRV secs %d, OPE %d)", utils.Ternary(isFirstDesc, "first", "second"), secondsSinceSrvStart, opeResult)
	return opeResult
}

func getRevisionCounterDet(privKeyBytes []byte, now, srvStart int64) (opeResult int64, secondsSinceSrvStart int64) {
	cipherKeyTmp := sha3.Sum256([]byte("rev-counter-generation" + string(privKeyBytes))) // good
	cipherKey := cipherKeyTmp[:]

	secondsSinceSrvStart = now - srvStart
	// This must be strictly positive
	secondsSinceSrvStart += 1

	iv := make([]byte, 16)
	block, _ := aes.NewCipher(cipherKey)
	stream := cipher.NewCTR(block, iv)
	getOpeSchemeWords := func() int64 {
		v := make([]byte, 2)
		stream.XORKeyStream(v, []byte("\x00\x00"))
		return int64(v[0]) + 256*int64(v[1]) + 1
	}

	for i := int64(0); i < secondsSinceSrvStart; i++ {
		opeResult += getOpeSchemeWords()
	}

	return opeResult, secondsSinceSrvStart
}

func (d *OBDescriptor) recertifyIntroPoint(introPoint descriptor.IntroductionPointV3, descriptorSigningKey ed25519.PrivateKey) descriptor.IntroductionPointV3 {
	originalAuthKeyCert := introPoint.AuthKeyCert
	originalEncKeyCert := introPoint.EncKeyCert

	// We have already removed all the intros with legacy keys. Make sure that
	// no legacy intros sneaks up on us, becausey they would result in
	// unparseable descriptors if we don't recertify them (and we won't).
	// assert(not intro_point.legacy_key_cert)

	// Get all the certs we need to recertify
	// [we need to use the _replace method of namedtuples because there is no
	// setter for those attributes due to the way stem sets those fields. If we
	// attempt to normally replace the attributes we get the following
	// exception: AttributeError: can't set attribute]
	introPoint.AuthKeyCert = d.recertifyEdCertificate(originalAuthKeyCert, descriptorSigningKey)
	introPoint.EncKeyCert = d.recertifyEdCertificate(originalEncKeyCert, descriptorSigningKey)
	introPoint.AuthKeyCertRaw = introPoint.AuthKeyCert.ToBase64()
	introPoint.EncKeyCertRaw = introPoint.EncKeyCert.ToBase64()
	recertifiedIntroPoint := introPoint

	return recertifiedIntroPoint
}

// Recertify an HSv3 intro point certificate using the new descriptor signing
// key so that it can be accepted as part of a new descriptor.
// "Recertifying" means taking the certified key and signing it with a new
// key.
// Return the new certificate.
func (d *OBDescriptor) recertifyEdCertificate(edCert descriptor.Ed25519CertificateV1, descriptorSigningKey ed25519.PrivateKey) descriptor.Ed25519CertificateV1 {
	return recertifyEdCertificate(edCert, descriptorSigningKey)
}

func recertifyEdCertificate(edCert descriptor.Ed25519CertificateV1, descriptorSigningKey ed25519.PrivateKey) descriptor.Ed25519CertificateV1 {
	extensions := []descriptor.Ed25519Extension{descriptor.NewEd25519Extension(descriptor.HasSigningKey, 0, descriptorSigningKey.Public().(ed25519.PublicKey))}
	expiration := edCert.Expiration()
	newCert := descriptor.NewEd25519CertificateV1(edCert.Typ(), &expiration, edCert.KeyType(), edCert.Key(), extensions, descriptorSigningKey, nil)
	return newCert
}
