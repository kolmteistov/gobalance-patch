package hashring

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/onionbalance/consensus"
	"gobalance/pkg/onionbalance/param"
	"gobalance/pkg/onionbalance/tornode"
	"gobalance/pkg/onionbalance/utils"
	"golang.org/x/crypto/sha3"
	"sort"
)

var ErrEmptyHashRing = errors.New("EmptyHashRing")

// GetSrvAndTimePeriod return SRV and time period based on current consensus time
func GetSrvAndTimePeriod(isFirstDescriptor bool, consensus consensus.ConsensusDoc) ([]byte, int64) {
	validAfter := consensus.ValidAfter().Unix()
	currentTp := consensus.GetTimePeriodNum(validAfter)
	previousTp := currentTp - 1
	nextTp := currentTp + 1
	// assert(previous_tp > 0)

	// Get the right TP/SRV
	var srv []byte
	var tp int64
	var casee int
	if isFirstDescriptor {
		if timeBetweenTpAndSrv(validAfter, consensus) {
			srv = consensus.GetPreviousSrv(previousTp)
			tp = previousTp
			casee = 1 // just for debugging
		} else {
			srv = consensus.GetPreviousSrv(currentTp)
			tp = currentTp
			casee = 2 // just for debugging
		}
	} else {
		if timeBetweenTpAndSrv(validAfter, consensus) {
			srv = consensus.GetCurrentSrv(currentTp)
			tp = currentTp
			casee = 3 // just for debugging
		} else {
			srv = consensus.GetCurrentSrv(nextTp)
			tp = nextTp
			casee = 4 // just for debugging
		}
	}
	srvB64 := base64.StdEncoding.EncodeToString(srv)
	logrus.Debugf("For valid_after %d we got SRV %s and TP %d (case: #%d)\n", validAfter, srvB64, tp, casee)
	return srv, tp
}

func timeBetweenTpAndSrv(validAfter int64, consensus consensus.ConsensusDoc) bool {
	srvStartTime := consensus.GetStartTimeOfCurrentSrvRun()
	tpStartTime := consensus.GetStartTimeOfNextTimePeriod(srvStartTime)
	if validAfter >= srvStartTime && validAfter < tpStartTime {
		logrus.Debug("We are between SRV and TP")
		return false
	}
	logrus.Debugf("We are between TP and SRV (valid_after: %d, srv_start_time: %d -> tp_start_time: %d)\n", validAfter, srvStartTime, tpStartTime)
	return true
}

func GetResponsibleHsdirs(blindedPubkey ed25519.PublicKey, isFirstDescriptor bool, consensus *consensus.Consensus) ([]string, error) {
	responsibleHsdirs := make([]string, 0)

	// dictionary { <node hsdir index> : Node , .... }
	nodeHashRing := getHashRingForDescriptor(isFirstDescriptor, consensus)
	if len(nodeHashRing) == 0 {
		return nil, ErrEmptyHashRing
	}

	sortedHashRingList := make([]string, 0)
	for k := range nodeHashRing {
		sortedHashRingList = append(sortedHashRingList, k)
	}
	sort.Slice(sortedHashRingList, func(i, j int) bool {
		return sortedHashRingList[i] < sortedHashRingList[j]
	})

	logrus.Infof("Initialized hash ring of size %d (blinded key: %s)", len(nodeHashRing), base64.StdEncoding.EncodeToString(blindedPubkey))

	for replicaNum := 1; replicaNum < param.HsdirNReplicas+1; replicaNum++ {
		// The HSDirs that we are gonna store this replica in
		replicaStoreHsdirs := make([]string, 0)

		hiddenServiceIndex := getHiddenServiceIndex(blindedPubkey, replicaNum, isFirstDescriptor, consensus)
		// Find position of descriptor ID in the HSDir list
		index := sort.SearchStrings(sortedHashRingList, hex.EncodeToString(hiddenServiceIndex))

		logrus.Infof("\t Tried with HS index %s got position %d", hex.EncodeToString(hiddenServiceIndex), index)

		for len(replicaStoreHsdirs) < param.HsdirSpreadStore {
			var hsdirKey string
			if index < len(sortedHashRingList) {
				hsdirKey = sortedHashRingList[index]
				index += 1
			} else {
				// Wrap around when we reach the end of the HSDir list
				index = 0
				hsdirKey = sortedHashRingList[index]
			}
			hsdirNode := nodeHashRing[hsdirKey]

			// Check if we have already added this node to this
			// replica. This should never happen on the real network but
			// might happen in small testnets like chutney!
			if utils.InArr(string(hsdirNode.GetHexFingerprint()), replicaStoreHsdirs) {
				logrus.Debug("Ignoring already added HSDir to this replica!")
				break
			}

			// Check if we have already added this node to the responsible
			// HSDirs. This can happen in the second replica and we should
			// skip the node
			if utils.InArr(string(hsdirNode.GetHexFingerprint()), responsibleHsdirs) {
				logrus.Debug("Ignoring already added HSDir!")
				continue
			}

			logrus.Debugf("%d: %s: %s", index, hsdirNode.GetHexFingerprint(), hsdirKey)

			replicaStoreHsdirs = append(replicaStoreHsdirs, string(hsdirNode.GetHexFingerprint()))
		}

		responsibleHsdirs = append(responsibleHsdirs, replicaStoreHsdirs...)
	}

	// Do a sanity check
	//if my_onionbalance.is_testnet {
	//	// If we are on chutney it's normal to not have enough nodes to populate the hashring
	//	assert(len(responsible_hsdirs) <= params.HSDIR_N_REPLICAS*params.HSDIR_SPREAD_STORE)
	//} else {
	if len(responsibleHsdirs) != param.HsdirNReplicas*param.HsdirSpreadStore {
		logrus.Panicf("Got the wrong number of responsible HSDirs: %d. Aborting", len(responsibleHsdirs))
	}
	//}

	return responsibleHsdirs, nil
}

func getHiddenServiceIndex(blindedPubkey ed25519.PublicKey, replicaNum int, isFirstDescriptor bool, consensus *consensus.Consensus) []byte {
	periodLength := consensus.Consensus().GetTimePeriodLength()
	replicaNumInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(replicaNumInt8, uint64(replicaNum))
	periodLengthInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodLengthInt8, uint64(periodLength))
	_, timePeriodNum := GetSrvAndTimePeriod(isFirstDescriptor, *consensus.Consensus())
	logrus.Infof("Getting HS index with TP#%d for %s descriptor (%d replica) ", timePeriodNum, utils.Ternary(isFirstDescriptor, "first", "second"), replicaNum)
	periodNumInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodNumInt8, uint64(timePeriodNum))

	var hashBody bytes.Buffer
	hashBody.WriteString("store-at-idx")
	hashBody.Write(blindedPubkey)
	hashBody.Write(replicaNumInt8)
	hashBody.Write(periodLengthInt8)
	hashBody.Write(periodNumInt8)
	hsIndex := sha3.Sum256(hashBody.Bytes())

	return hsIndex[:]
}

func getHashRingForDescriptor(isFirstDescriptor bool, consensus *consensus.Consensus) map[string]*tornode.TorNode {
	nodeHashRing := make(map[string]*tornode.TorNode)
	srv, timePeriodNum := GetSrvAndTimePeriod(isFirstDescriptor, *consensus.Consensus())
	logrus.Infof("Using srv %x and TP#%d (%s descriptor)", srv, timePeriodNum, utils.Ternary(isFirstDescriptor, "first", "second"))
	for _, node := range consensus.Nodes() {
		hsdirIndex, err := node.GetHsdirIndex(srv, timePeriodNum, consensus.Consensus().GetTimePeriodLength())
		if err != nil {
			if err == tornode.ErrNoHSDir || err == tornode.ErrNoEd25519Identity {
				logrus.Debugf("Could not find ed25519 for node %s (%s)", node.Routerstatus().Fingerprint, err.Error())
				continue
			}
			logrus.Error(err)
			continue
		}
		logrus.Debugf("%s: Node: %s,  index: %x", utils.Ternary(isFirstDescriptor, "first", "second"), node.GetHexFingerprint(), hsdirIndex)
		nodeHashRing[hex.EncodeToString(hsdirIndex)] = node
	}
	return nodeHashRing
}
