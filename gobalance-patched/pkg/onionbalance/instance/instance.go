package instance

import (
	"crypto/ed25519"
	"errors"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/onionbalance/controller"
	"gobalance/pkg/onionbalance/descriptor"
	sdescriptor "gobalance/pkg/stem/descriptor"
	"strings"
	"sync"
	"time"
)

type Instance struct {
	controller                    *controller.Controller
	onionAddress                  string
	introSetChangedSincePublished bool
	descriptor                    *descriptor.ReceivedDescriptor
	descriptorMtx                 sync.RWMutex
	introSetModifiedTimestamp     *time.Time
	introSetModifiedTimestampMtx  sync.RWMutex
}

func (i *Instance) OnionAddress() string {
	return i.onionAddress
}

func (i *Instance) IntroSetModifiedTimestamp() *time.Time {
	i.introSetModifiedTimestampMtx.RLock()
	defer i.introSetModifiedTimestampMtx.RUnlock()
	return i.introSetModifiedTimestamp
}

func (i *Instance) setIntroSetModifiedTimestamp(introSetModifiedTimestamp time.Time) {
	i.introSetModifiedTimestampMtx.Lock()
	defer i.introSetModifiedTimestampMtx.Unlock()
	i.introSetModifiedTimestamp = &introSetModifiedTimestamp
}

func (i *Instance) getDescriptor() *descriptor.ReceivedDescriptor {
	i.descriptorMtx.RLock()
	defer i.descriptorMtx.RUnlock()
	return i.descriptor
}

func (i *Instance) setDescriptor(descriptor *descriptor.ReceivedDescriptor) {
	i.descriptorMtx.Lock()
	defer i.descriptorMtx.Unlock()
	i.descriptor = descriptor
}

func NewInstance(controller *controller.Controller, onionAddress string) *Instance {
	i := &Instance{}
	i.controller = controller

	if onionAddress != "" {
		onionAddress = strings.Replace(onionAddress, ".onion", "", 1)
	}
	i.onionAddress = onionAddress

	// Onion address does not contain the '.onion'.
	logrus.Warnf("Loaded instance %s", onionAddress)

	i.introSetChangedSincePublished = false

	// i.setDescriptor(nil)

	// When was the intro set of this instance last modified?
	// i.setIntroSetModifiedTimestamp(nil)
	return i
}

// HasOnionAddress Return True if this instance has this onion address
func (i *Instance) HasOnionAddress(onionAddress string) bool {
	// Strip the ".onion" part of the address if it exists since some
	// subsystems don't use it (e.g. Tor sometimes omits it from control
	// port responses)
	myOnionAddress := strings.TrimSuffix(i.onionAddress, ".onion")
	theirOnionAddress := strings.TrimSuffix(onionAddress, ".onion")

	return myOnionAddress == theirOnionAddress
}

// FetchDescriptor try fetch a fresh descriptor for this service instance from the HSDirs
func (i *Instance) FetchDescriptor() error {
	logrus.Debugf("Trying to fetch a descriptor for instance %s.onion.", i.onionAddress)
	return i.controller.GetHiddenServiceDescriptor(i.onionAddress, false)
}

var ErrInstanceHasNoDescriptor = errors.New("InstanceHasNoDescriptor")
var ErrInstanceIsOffline = errors.New("InstanceIsOffline")

// GetIntrosForPublish get a list of stem.descriptor.IntroductionPointV3 objects for this descriptor
// Raise :InstanceHasNoDescriptor: if there is no descriptor for this instance
// Raise :InstanceIsOffline: if the instance is offline.
func (i *Instance) GetIntrosForPublish() ([]sdescriptor.IntroductionPointV3, error) {
	desc := i.getDescriptor()
	if desc == nil {
		return nil, ErrInstanceHasNoDescriptor
	}
	if desc.IsOld() {
		return nil, ErrInstanceIsOffline
	}
	return desc.GetIntroPoints(), nil
}

// RegisterDescriptor We received a descriptor (with 'descriptor_text') for 'onion_address'.
// Register it to this instance.
//
// SECURITY (fixed): expectedBlindedKeys are the blinded pubkeys the instance
// descriptor must carry — derived by the caller from the consensus and the
// instance identity. The descriptor is cryptographically verified and bound
// to them before it can replace the current descriptor. Callers that fail to
// supply any expected key only get the internal signature-chain check (still
// far stronger than the previous parse-and-trust behaviour).
func (i *Instance) RegisterDescriptor(descriptorText, onionAddress string, expectedBlindedKeys ...ed25519.PublicKey) {
	logrus.Infof("Found instance %s for this new descriptor!", i.onionAddress)

	if onionAddress != i.onionAddress {
		panic("onion_address != i.OnionAddress")
	}

	// Parse and verify descriptor. If it parsed correctly, we know that this
	// descriptor is truly for this instance (since the onion address
	// matches) — and, since the security fix, that its signature chain is
	// valid and its blinded key is bound to the expected identity/period.
	newDescriptor, err := descriptor.NewReceivedDescriptor(descriptorText, onionAddress, expectedBlindedKeys...)
	if err != nil {
		if err == descriptor.ErrBadDescriptor {
			logrus.Warningf("Received bad descriptor for %s. Ignoring.", i.onionAddress)
			return
		}
		panic(err)
	}

	// Before replacing the current descriptor with this one, check if the
	// introduction point set changed:

	// If this is the first descriptor for this instance, the intro point set changed
	instDescriptor := i.getDescriptor()
	if instDescriptor == nil {
		logrus.Infof("This is the first time we see a descriptor for instance %s!", i.onionAddress)
		i.setIntroSetModifiedTimestamp(btime.Clock.Now().UTC())
		i.setDescriptor(newDescriptor)
		return
	}

	if newDescriptor.IntroSet().Len() == 0 {
		panic("new_descriptor.introSet.Len() == 0")
	}

	// We already have a descriptor but this is a new one. Check the intro points!
	if !newDescriptor.IntroSet().Equals(*instDescriptor.IntroSet()) {
		logrus.Infof("We got a new descriptor for instance %s and the intro set changed!", i.onionAddress)
		i.setIntroSetModifiedTimestamp(btime.Clock.Now().UTC())
	} else {
		logrus.Infof("We got a new descriptor for instance %s but the intro set did not change.", i.onionAddress)
	}
	i.setDescriptor(newDescriptor)
}
