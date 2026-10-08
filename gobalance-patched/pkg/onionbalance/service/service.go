package service

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/gobpk"
	"gobalance/pkg/onionbalance/config"
	"gobalance/pkg/onionbalance/consensus"
	"gobalance/pkg/onionbalance/controller"
	"gobalance/pkg/onionbalance/descriptor"
	"gobalance/pkg/onionbalance/hashring"
	"gobalance/pkg/onionbalance/hs_v3/ext"
	"gobalance/pkg/onionbalance/instance"
	"gobalance/pkg/onionbalance/param"
	"gobalance/pkg/onionbalance/tored25519"
	"gobalance/pkg/onionbalance/utils"
	sdescriptor "gobalance/pkg/stem/descriptor"
	"gobalance/pkg/stem/util"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Service struct {
	controller          *controller.Controller
	identityPrivKey     gobpk.PrivateKey
	onionAddress        string
	instances           []*instance.Instance
	firstDescriptor     *descriptor.OBDescriptor
	firstDescriptorMtx  sync.RWMutex
	secondDescriptor    *descriptor.OBDescriptor
	secondDescriptorMtx sync.RWMutex
	consensus           *consensus.Consensus
}

func (s *Service) Instances() []*instance.Instance {
	return s.instances
}

func (s *Service) getFirstDescriptor() *descriptor.OBDescriptor {
	s.firstDescriptorMtx.RLock()
	defer s.firstDescriptorMtx.RUnlock()
	return s.firstDescriptor
}

func (s *Service) setFirstDescriptor(firstDescriptor *descriptor.OBDescriptor) {
	s.firstDescriptorMtx.Lock()
	defer s.firstDescriptorMtx.Unlock()
	s.firstDescriptor = firstDescriptor
}

func (s *Service) getSecondDescriptor() *descriptor.OBDescriptor {
	s.secondDescriptorMtx.RLock()
	defer s.secondDescriptorMtx.RUnlock()
	return s.secondDescriptor
}

func (s *Service) setSecondDescriptor(secondDescriptor *descriptor.OBDescriptor) {
	s.secondDescriptorMtx.Lock()
	defer s.secondDescriptorMtx.Unlock()
	s.secondDescriptor = secondDescriptor
}

// NewService new with 'config_data' straight out of the config file, create the service and its instances.
// 'config_path' is the full path to the config file.
// Raise ValueError if the config file is not well formatted
func NewService(consensus *consensus.Consensus, controller *controller.Controller, serviceConfigData config.ServiceConfig, configPath string) *Service {
	s := &Service{}
	s.controller = controller
	s.consensus = consensus

	// Load private key and onion address from config
	// (the onion_address also includes the ".onion")
	s.identityPrivKey, s.onionAddress = s.loadServiceKeys(serviceConfigData, configPath)

	// Now load up the instances
	s.instances = s.loadInstances(serviceConfigData)

	// First descriptor for this service (the one we uploaded last)
	// s.setFirstDescriptor(nil)
	// Second descriptor for this service (the one we uploaded last)
	// s.setSecondDescriptor(nil)

	return s
}

func (s *Service) loadServiceKeys(serviceConfigData config.ServiceConfig, configPath string) (gobpk.PrivateKey, string) {
	// First of all let's load up the private key
	keyFname := serviceConfigData.Key
	configDirectory := filepath.Dir(configPath)
	if !filepath.IsAbs(keyFname) {
		keyFname = filepath.Join(configDirectory, keyFname)
	}
	pemKeyBytes, err := os.ReadFile(keyFname)
	if err != nil {
		logrus.Fatalf("Unable to read service private key file ('%v')", err)
	}

	// Get the service private key
	// First try with the OBv3 PEM format
	var identityPrivKey ed25519.PrivateKey
	blocks, rest := pem.Decode(pemKeyBytes)
	if len(rest) == 0 {
		identityPrivKey = ed25519.NewKeyFromSeed(blocks.Bytes[16 : 16+32])
	}

	// If the key was not in OBv3 PEM format, try the Tor binary format
	isPrivKeyInTorFormat := false
	var privKey gobpk.PrivateKey
	if identityPrivKey == nil {
		identityPrivKey = tored25519.LoadTorKeyFromDisk(pemKeyBytes)
		isPrivKeyInTorFormat = true
	}
	privKey = gobpk.New(identityPrivKey, isPrivKeyInTorFormat)

	// Get onion address
	identityPubKey := identityPrivKey.Public().(ed25519.PublicKey)

	if isPrivKeyInTorFormat {
		identityPubKey = ext.PublickeyFromESK(identityPrivKey)
	}
	onionAddress := sdescriptor.AddressFromIdentityKey(identityPubKey)

	logrus.Warnf("Loaded onion %s from %s", onionAddress, keyFname)

	return privKey, onionAddress
}

func (s *Service) loadInstances(serviceConfigData config.ServiceConfig) []*instance.Instance {
	instances := make([]*instance.Instance, 0)
	for _, configInstance := range serviceConfigData.Instances {
		newInstance := instance.NewInstance(s.controller, configInstance.Address)
		instances = append(instances, newInstance)
	}

	// Some basic validation
	for _, inst := range instances {
		if s.HasOnionAddress(inst.OnionAddress()) {
			logrus.Errorf("Config file error. Did you configure your frontend (%s) as an instance?", s.onionAddress)
			panic("BadServiceInit")
		}
	}
	return instances
}

// HasOnionAddress Return True if this service has this onion address
func (s *Service) HasOnionAddress(onionAddress string) bool {
	// Strip the ".onion" part of the address if it exists since some
	// subsystems don't use it (e.g. Tor sometimes omits it from control
	// port responses)
	myOnionAddress := strings.Replace(s.onionAddress, ".onion", "", 1)
	theirOnionAddress := strings.Replace(onionAddress, ".onion", "", 1)
	return myOnionAddress == theirOnionAddress
}

func (s *Service) PublishDescriptors() {
	s.publishDescriptor(true)
	s.publishDescriptor(false)
}

// Attempt to publish descriptor if needed.
// If 'is_first_desc' is set then attempt to upload the first descriptor
// of the service, otherwise the second.
func (s *Service) publishDescriptor(isFirstDesc bool) {

	if !s.shouldPublishDescriptorNow(isFirstDesc) {
		logrus.Infof("No reason to publish %s descriptor for %s", utils.Ternary(isFirstDesc, "first", "second"), s.onionAddress)
		return
	}

	introPoints, err := s.getIntrosForDesc()
	if err != nil {
		if err == ErrNotEnoughIntros {
			return
		}
		panic(err)
	}

	// Derive blinding parameter
	_, timePeriodNumber := hashring.GetSrvAndTimePeriod(isFirstDesc, *s.consensus.Consensus())
	blindingParam := s.consensus.Consensus().GetBlindingParam(s.getIdentityPubkeyBytes(), timePeriodNumber)

	desc, err := descriptor.NewOBDescriptor(s.onionAddress, s.identityPrivKey, blindingParam, introPoints, isFirstDesc, s.consensus.Consensus())
	if err != nil {
		if err == descriptor.ErrBadDescriptor {
			return
		}
		panic(err)
	}

	logrus.Infof("Service %s created %s descriptor (%d intro points) (blinding param: %x) (size: %d bytes). About to publish:",
		s.onionAddress, utils.Ternary(isFirstDesc, "first", "second"), desc.IntroSet().Len(), blindingParam, len(desc.V3Desc().String()))

	// When we do a v3 HSPOST on the control port, Tor decodes the
	// descriptor and extracts the blinded pubkey to be used when uploading
	// the descriptor. So let's do the same to compute the responsible
	// HSDirs:
	blindedKey := desc.GetBlindedKey()

	// Calculate responsible HSDirs for our service
	responsibleHsdirs, err := hashring.GetResponsibleHsdirs(blindedKey, isFirstDesc, s.consensus)
	if err != nil {
		if err == hashring.ErrEmptyHashRing {
			logrus.Warning("Can't publish desc with no hash ring. Delaying...")
			return
		}
		panic(err)
	}

	desc.SetLastPublishAttemptTs(btime.Clock.Now().UTC())

	logrus.Infof("Uploading %s descriptor for %s to %s", utils.Ternary(isFirstDesc, "first", "second"), s.onionAddress, responsibleHsdirs)

	// Upload descriptor
	s.uploadDescriptor(s.controller, desc, responsibleHsdirs)

	// It would be better to set last_upload_ts when an upload succeeds and
	// not when an upload is just attempted. Unfortunately the HS_DESC #
	// UPLOADED event does not provide information about the service and
	// so it can't be used to determine when descriptor upload succeeds
	desc.SetLastUploadTs(btime.Clock.Now().UTC())
	desc.SetResponsibleHsdirs(responsibleHsdirs)

	// Set the descriptor
	if isFirstDesc {
		s.setFirstDescriptor(desc)
	} else {
		s.setSecondDescriptor(desc)
	}
}

// Convenience method to upload a descriptor
// Handle some error checking and logging inside the Service class
func (s *Service) uploadDescriptor(ctrl *controller.Controller, obDesc *descriptor.OBDescriptor, hsdirs []string) {
	for {
		err := commonUploadDescriptor(ctrl, obDesc.V3Desc(), hsdirs, obDesc.OnionAddress())
		if err != nil {
			if err == controller.ErrSocketClosed {
				logrus.Errorf("Error uploading descriptor for service %s.onion. Control port socket is closed.", obDesc.OnionAddress())
				ctrl.ReAuthenticate()
				continue
			} else {
				logrus.Errorf("Error uploading descriptor for service %s.onion.: %v", obDesc.OnionAddress(), err)
				break
			}
		}
		break
	}
}

func commonUploadDescriptor(controller *controller.Controller, signedDescriptor *sdescriptor.HiddenServiceDescriptorV3, hsdirs []string, v3OnionAddress string) error {
	logrus.Debug("Beginning service descriptor upload.")
	serverArgs := ""
	// Provide server fingerprints to control command if HSDirs are specified.
	if hsdirs != nil {
		strs := make([]string, len(hsdirs))
		for i, hsDir := range hsdirs {
			strs[i] = "SERVER=" + hsDir
		}
		serverArgs += strings.Join(strs, " ")
	}
	if v3OnionAddress != "" {
		serverArgs += " HSADDRESS=" + strings.Replace(v3OnionAddress, ".onion", "", 1)
	}
	msg := fmt.Sprintf("+HSPOST %s\n%s\r\n.\r\n", serverArgs, signedDescriptor)
	res, err := controller.Msg(msg)
	if err != nil {
		return err
	}
	if !res.IsOk() {
		return fmt.Errorf("HSPOST returned unexpected response code: %s", res)
	}
	return nil
}

var ErrNotEnoughIntros = errors.New("NotEnoughIntros")

// Get the intros that should be included in a descriptor for this service.
func (s *Service) getIntrosForDesc() ([]sdescriptor.IntroductionPointV3, error) {
	allIntros := s.getAllIntrosForPublish()

	// Get number of instances that contributed to final intro point list
	nInstances := len(allIntros.IntroPoints())
	nIntrosWanted := nInstances * param.NIntrosPerInstance

	finalIntros := allIntros.Choose(nIntrosWanted)
	if len(finalIntros) == 0 {
		logrus.Info("Got no usable intro points from our instances. Delaying descriptor push...")
		return nil, ErrNotEnoughIntros
	}

	logrus.Infof("We got %d intros from %d instances. We want %d intros ourselves (got: %d)", len(allIntros.GetIntroPointsFlat()), nInstances, nIntrosWanted, len(finalIntros))

	return finalIntros, nil
}

// Return an IntroductionPointSetV3 with all the intros of all the instances
// of this service.
func (s *Service) getAllIntrosForPublish() *descriptor.IntroductionPointSetV3 {
	allIntros := make([][]sdescriptor.IntroductionPointV3, 0)
	for _, inst := range s.instances {
		instanceIntros, err := inst.GetIntrosForPublish()
		if err != nil {
			if err == instance.ErrInstanceHasNoDescriptor {
				logrus.Infof("Entirely missing a descriptor for instance %s. Continuing anyway if possible", inst.OnionAddress())
				continue
			} else if err == instance.ErrInstanceIsOffline {
				logrus.Infof("Instance %s is offline. Ignoring its intro points...", inst.OnionAddress())
				continue
			}
		}
		allIntros = append(allIntros, instanceIntros)
	}
	return descriptor.NewIntroductionPointSetV3(allIntros)
}

// Return True if we should publish a descriptor right now
func (s *Service) shouldPublishDescriptorNow(isFirstDesc bool) bool {
	forcePublish := utils.Noop(false)

	// If descriptor not yet uploaded, do it now!
	if isFirstDesc && s.getFirstDescriptor() == nil {
		return true
	}
	if !isFirstDesc && s.getSecondDescriptor() == nil {
		return true
	}

	// OK this is not the first time we publish a descriptor. Check various
	// parameters to see if we should try to publish again:
	return s.introSetModified(isFirstDesc) ||
		s.descriptorHasExpired(isFirstDesc) ||
		s.hsdirSetChanged(isFirstDesc) ||
		forcePublish
}

// Check if the introduction point set has changed since last publish.
func (s *Service) introSetModified(isFirstDesc bool) bool {
	var lastUploadTs *time.Time
	if isFirstDesc {
		lastUploadTs = s.getFirstDescriptor().LastUploadTs()
	} else {
		lastUploadTs = s.getSecondDescriptor().LastUploadTs()
	}
	if lastUploadTs == nil {
		logrus.Info("\t Descriptor never published before. Do it now!")
		return true
	}
	for _, inst := range s.instances {
		instIntroSetModifiedTimestamp := inst.IntroSetModifiedTimestamp()
		if instIntroSetModifiedTimestamp == nil {
			logrus.Info("\t Still dont have a descriptor for this instance")
			continue
		}
		if (*instIntroSetModifiedTimestamp).After(*lastUploadTs) {
			logrus.Info("\t Intro set modified")
			return true
		}
	}
	logrus.Info("\t Intro set not modified")
	return false
}

// Check if the descriptor has expired (hasn't been uploaded recently).
// If 'is_first_desc' is set then check the first descriptor of the
// service, otherwise the second.
func (s *Service) descriptorHasExpired(isFirstDesc bool) bool {
	var lastUploadTs *time.Time
	if isFirstDesc {
		lastUploadTs = s.getFirstDescriptor().LastUploadTs()
	} else {
		lastUploadTs = s.getSecondDescriptor().LastUploadTs()
	}
	descriptorAge := int64(btime.Clock.Now().UTC().Sub(*lastUploadTs).Seconds())
	if descriptorAge > s.getDescriptorLifetime() {
		logrus.Infof("\t Our %s descriptor has expired (%d seconds old). Uploading new one.", utils.Ternary(isFirstDesc, "first", "second"), descriptorAge)
		return true
	}
	logrus.Infof("\t Our %s descriptor is still fresh (%d seconds old).", utils.Ternary(isFirstDesc, "first", "second"), descriptorAge)
	return false
}

// Return True if the HSDir has changed between the last upload of this
// descriptor and the current state of things
func (s *Service) hsdirSetChanged(isFirstDesc bool) bool {
	// Derive blinding parameter
	_, timePeriodNumber := hashring.GetSrvAndTimePeriod(isFirstDesc, *s.consensus.Consensus())
	blindedParam := s.consensus.Consensus().GetBlindingParam(s.getIdentityPubkeyBytes(), timePeriodNumber)

	// Get blinded key
	blindedKey := util.BlindedPubkey(s.getIdentityPubkeyBytes(), blindedParam)

	responsibleHsdirs, err := hashring.GetResponsibleHsdirs(blindedKey, isFirstDesc, s.consensus)
	if err != nil {
		if err == hashring.ErrEmptyHashRing {
			return false
		}
		panic(err)
	}

	var previousResponsibleHsdirs []string
	if isFirstDesc {
		previousResponsibleHsdirs = s.getFirstDescriptor().ResponsibleHsdirs()
	} else {
		previousResponsibleHsdirs = s.getSecondDescriptor().ResponsibleHsdirs()
	}

	sort.Strings(responsibleHsdirs)
	sort.Strings(previousResponsibleHsdirs)
	if len(responsibleHsdirs) != len(previousResponsibleHsdirs) {
		logrus.Infof("\t HSDir set changed (%s vs %s)", responsibleHsdirs, previousResponsibleHsdirs)
		return true
	}
	changed := false
	for i, el := range responsibleHsdirs {
		if previousResponsibleHsdirs[i] != el {
			changed = true
		}
	}
	if changed {
		logrus.Infof("\t HSDir set changed (%s vs %s)", responsibleHsdirs, previousResponsibleHsdirs)
		return true
	}

	logrus.Info("\t HSDir set remained the same")
	return false
}

func (s *Service) getIdentityPubkeyBytes() ed25519.PublicKey {
	return s.identityPrivKey.Public()
}

func (s *Service) getDescriptorLifetime() int64 {
	//if onionbalance.Onionbalance().IsTestnet {
	//	return param.FrontendDescriptorLifetimeTestnet
	//}
	return param.FrontendDescriptorLifetime
}
