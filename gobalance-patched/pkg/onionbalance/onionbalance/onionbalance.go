package onionbalance

import (
	"crypto/ed25519"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/clockwork"
	"gobalance/pkg/onionbalance/config"
	"gobalance/pkg/onionbalance/consensus"
	"gobalance/pkg/onionbalance/controller"
	"gobalance/pkg/onionbalance/hashring"
	"gobalance/pkg/onionbalance/instance"
	"gobalance/pkg/onionbalance/service"
	"gobalance/pkg/stem/descriptor"
	"gobalance/pkg/stem/util"
	"gopkg.in/yaml.v3"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Onionbalance struct {
	isTestnet  bool
	configPath string
	configData config.ConfigData
	controller *controller.Controller
	consensus  *consensus.Consensus
	services   []*service.Service
}

func (b *Onionbalance) IsTestnet() bool {
	return b.isTestnet
}

func NewOnionbalance() *Onionbalance {
	return &Onionbalance{isTestnet: false}
}

func (b *Onionbalance) Consensus() *consensus.Consensus {
	return b.consensus
}

func (b *Onionbalance) Controller() *controller.Controller {
	return b.controller
}

type InitSubsystemsParams struct {
	ConfigPath  string
	IP          string
	Port        int
	Socket      string
	TorPassword string
}

func (b *Onionbalance) InitSubsystems(args InitSubsystemsParams) error {
	btime.Clock = clockwork.NewRealClock()
	rand.Seed(time.Now().UnixNano())
	//btime.Clock = clockwork.NewFakeClockAt(time.Now().Round(time.Hour))
	//rand.Seed(1)

	var err error
	b.configPath, err = filepath.Abs(args.ConfigPath)
	if err != nil {
		return err
	}
	b.configData = b.LoadConfigFile()
	b.isTestnet = false
	if b.isTestnet {
		logrus.Warn("Onionbalance configured on a testnet!")
	}
	b.controller = controller.NewController(
		args.IP, args.Port, args.TorPassword,
		b.descEventClb,
		b.descContentEventClb,
		b.statusEventClb)
	b.consensus = consensus.NewConsensus(b.controller, true)

	// Initialize our service
	b.services = b.initializeServicesFromConfigData()

	// Catch interesting events (like receiving descriptors etc.)
	if err := b.controller.SetEvents(); err != nil {
		return err
	}

	logrus.Warnf("Onionbalance initialized (tor version: %s)!", b.controller.GetVersion())
	logrus.Warn(strings.Repeat("=", 80))
	return nil
}

func (b *Onionbalance) initializeServicesFromConfigData() []*service.Service {
	services := make([]*service.Service, len(b.configData.Services))
	for i, svc := range b.configData.Services {
		services[i] = service.NewService(b.consensus, b.controller, svc, b.configPath)
	}
	return services
}

func (b *Onionbalance) LoadConfigFile() (out config.ConfigData) {
	logrus.Infof("Loaded the config file '%s'.", b.configPath)
	by, err := os.ReadFile(b.configPath)
	if err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(by, &out); err != nil {
		panic(err)
	}
	logrus.Debugf("Onionbalance config data: %v", out)
	return
}

// PublishAllDescriptors for each service attempt to publish all descriptors
func (b *Onionbalance) PublishAllDescriptors() {
	logrus.Info("[*] PublishAllDescriptors() called [*]")

	if !b.consensus.IsLive() {
		logrus.Info("No live consensus. Waiting before publishing descriptors...")
		return
	}

	for _, svc := range b.services {
		svc.PublishDescriptors()
	}
}

func (b *Onionbalance) FetchInstanceDescriptors() {
	logrus.Info("[*] FetchInstanceDescriptors() called [*]")

	// TODO: Don't do this here. Instead do it on a specialized function
	b.controller.MarkTorAsActive()

	if !b.consensus.IsLive() {
		logrus.Warn("No live consensus. Waiting before fetching descriptors...")
		return
	}

	allInstances := b.getAllInstances()

	helperFetchAllInstanceDescriptors(b.controller, allInstances)
}

// Get all instances for all services
func (b *Onionbalance) getAllInstances() []*instance.Instance {
	instances := make([]*instance.Instance, 0)
	for _, srv := range b.services {
		instances = append(instances, srv.Instances()...)
	}
	return instances
}

// Try fetch fresh descriptors for all HS instances
func helperFetchAllInstanceDescriptors(ctrl *controller.Controller, instances []*instance.Instance) {
	logrus.Info("Initiating fetch of descriptors for all service instances.")

	for {
		// Clear Tor descriptor cache before making fetches by sending
		// the NEWNYM singal
		if _, err := ctrl.Signal("NEWNYM"); err != nil {
			if err == controller.ErrSocketClosed {
				logrus.Error("Failed to send NEWNYM signal, socket is closed.")
				ctrl.ReAuthenticate()
				continue
			} else {
				break
			}
		}
		time.Sleep(5 * time.Second) // Sleep to allow Tor time to build new circuits
		break
	}

	uniqueInstances := make(map[string]*instance.Instance)
	for _, inst := range instances {
		uniqueInstances[inst.OnionAddress()] = inst
	}

	for _, inst := range uniqueInstances {
		for {
			if err := inst.FetchDescriptor(); err != nil {
				if err == controller.ErrSocketClosed {
					logrus.Error("Failed to fetch descriptor, socket is closed")
					ctrl.ReAuthenticate()
					continue
				}
			}
			break
		}
	}
}

// Return True if 'onion_address' is one of our instances.
func (b *Onionbalance) addressIsInstance(onionAddress string) bool {
	for _, svc := range b.services {
		for _, inst := range svc.Instances() {
			if inst.HasOnionAddress(onionAddress) {
				return true
			}
		}
	}
	return false
}

func (b *Onionbalance) AddressIsFrontend(onionAddress string) bool {
	for _, svc := range b.services {
		if svc.HasOnionAddress(onionAddress) {
			return true
		}
	}
	return false
}

// A wrapper for this control port event (see above)
// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/control-spec.txt#L3594
func (b *Onionbalance) descEventClb(statusEvent string) {
	// HS_DESC Action HSAddress AuthType HsDir
	// HS_DESC RECEIVED o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad NO_AUTH $3D1BBDB539FAACA19EC27334DC6D08FD68D82775~alan 35D0MMu7YxXqhlV/u4uQ26qdT/jZXH1Ua2eYDXnavFs
	// HS_DESC UPLOADED o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad UNKNOWN $6A51575EFF4DC40CE8D97169E0F0AC9DE97E8B69~a9RelayMIA
	// HS_DESC REQUESTED dkforestseeaaq2dqz2uflmlsybvnq2irzn4ygyvu53oazyorednviid NO_AUTH $B7327B559CA1531D182386E21B4868FCB7F0F456~Maine obnMXJfQ9YhQ2ekm6uLiAu4TICHx1EeM5+DYVvvo480 HSDIR_INDEX=04F61F2A8367AED55A6E7FC1906AAFA8FC2610D9A8E96A02E9792FC53857D10D
	// HS_DESC FAILED xa5mofmlp2iwsapc6cskc4uflvcon2f4j2fbklycjk55e4bkqmxblyyd NO_AUTH $12CB4C0E78A71C846069605361B1E1FF528E1AF0~bammbamm OnxmaOKfU5mbR02QgVXrLh16/33MsrZmt7URcL0sffI REASON=UPLOAD_REJECTED
	words := strings.Split(statusEvent, " ")
	action := words[1]
	hsAddress := words[2]
	// authType := words[3]
	hsDir := words[4]
	if action == "RECEIVED" {
		return // We already log in HS_DESC_CONTENT so no need to do it here too
	} else if action == "UPLOADED" {
		logrus.Debugf("Successfully uploaded descriptor for %s to %s", hsAddress, hsDir)
	} else if action == "FAILED" {
		reason := "REASON NULL"
		if len(words) >= 6 {
			reason = words[6]
		}
		if b.addressIsInstance(hsAddress) {
			logrus.Infof("Descriptor fetch failed for instance %s from %s (%s)", hsAddress, hsDir, reason)
		} else if b.AddressIsFrontend(hsAddress) {
			logrus.Warningf("Descriptor upload failed for frontend %s to %s (%s)", hsAddress, hsDir, reason)
		} else {
			logrus.Warningf("Descriptor action failed for unknown service %s to %s (%s)", hsAddress, hsDir, reason)
		}
	} else if action == "REQUESTED" {
		logrus.Debugf("Requested descriptor for %s from %s...", hsAddress, hsDir)
	}
}

// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/control-spec.txt#L3664
func (b *Onionbalance) descContentEventClb(statusEvent string) {
	/*
	   o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad 35D0MMu7YxXqhlV/u4uQ26qdT/jZXH1Ua2eYDXnavFs $14A1D6B6F417DEC38BB05A3FFAD566F6E003E0D9~quartzyrelay
	   hs-descriptor 3
	   descriptor-lifetime 180
	   descriptor-signing-key-cert
	   -----BEGIN ED25519 CERT-----
	   AQgABvm2AU9N5AzUVIwCITJ2J4Cj/EbgUPKA74jCUsSG3a6Dg+BuAQAgBADfkPQw
	   y7tjFeqGVX+7i5Dbqp1P+NlcfVRrZ5gNedq8W/V3lx6ZWy4kSjsHUPz5mJjEnay/
	   yxBpz2MPh7Key9TtMX3kkOV+YSdVVEj3RYZDFO3L2d41pfsOyofmSVscEg0=
	   -----END ED25519 CERT-----
	   revision-counter 3767530536
	   superencrypted
	   -----BEGIN MESSAGE-----
	   4irIE1RXoopvgBEHohhUfv4s1p0wKRK0CJ86fB9CoxkAO6MkJl/QQMvM4XvLbTe+
	   IsvKSujhPsrMxeJywS02wUrKNyEPYsb229l7mYLsHCTcp/Yr4EjFVlgt9QC7x7p0
	   4h3EsUT1izNY8p72LV5k7A==
	   -----END MESSAGE-----
	   signature ivnFALhtO63SlCUj6sZDzllUGGZzuh9MnqOGyr3tU6O2MXVsQpQL7QJLavU1/4c5ITUsX90Bov20mCHSwKNODw
	*/
	lines := strings.SplitN(statusEvent, "\n", 2)
	descriptorText := lines[1]
	words := strings.Split(lines[0], " ")
	hsAddress := words[1]
	//DescId := words[2]
	//HsDir := words[3]
	//Descriptor := words[4:]
	for _, inst := range b.getAllInstances() {
		if inst.OnionAddress() == hsAddress {
			// SECURITY (fixed): bind the received descriptor to this
			// instance's identity and the CURRENT time periods before it is
			// allowed to replace the stored descriptor. Without this binding
			// an attacker can feed the frontend a self-consistent descriptor
			// built with the attacker's own keys (the subcredential only
			// needs the victim's public identity key, which is public), and
			// the frontend would then happily republish the attacker's
			// introduction points under the victim's onion address.
			expectedBlinded := b.expectedBlindedKeysFor(hsAddress)
			if len(expectedBlinded) == 0 {
				logrus.Errorf("Refusing to register descriptor for %s: cannot derive expected blinded keys (no live consensus?)", hsAddress)
				return
			}
			inst.RegisterDescriptor(descriptorText, hsAddress, expectedBlinded...)
		}
	}
}

// expectedBlindedKeysFor derives the blinded public keys that a descriptor
// for 'onionAddress' must carry for the current first/second descriptor time
// periods, computed exclusively from the consensus (rend-spec-v3 §5.5 / A.2)
// and the identity key encoded in the onion address — never from data found
// inside the descriptor itself.
func (b *Onionbalance) expectedBlindedKeysFor(onionAddress string) []ed25519.PublicKey {
	if b.consensus == nil || b.consensus.Consensus() == nil {
		return nil
	}
	doc := b.consensus.Consensus()
	instPub := descriptor.IdentityKeyFromAddress(onionAddress)
	expected := make([]ed25519.PublicKey, 0, 2)
	for _, isFirst := range []bool{true, false} {
		_, timePeriodNumber := hashring.GetSrvAndTimePeriod(isFirst, *doc)
		blindingParam := doc.GetBlindingParam(instPub, timePeriodNumber)
		expected = append(expected, util.BlindedPubkey(instPub, blindingParam))
	}
	return expected
}

// Parse Tor status events such as "STATUS_GENERAL"
// STATUS_CLIENT NOTICE CONSENSUS_ARRIVED
func (b *Onionbalance) statusEventClb(statusEvent string) {
	words := strings.Split(statusEvent, " ")
	action := words[2]
	if action == "CONSENSUS_ARRIVED" {
		logrus.Info("Received new consensus!")
		b.consensus.Refresh()
		// Call all callbacks in case we just got a live consensus
		b.PublishAllDescriptors()
		b.FetchInstanceDescriptors()
	}
}
