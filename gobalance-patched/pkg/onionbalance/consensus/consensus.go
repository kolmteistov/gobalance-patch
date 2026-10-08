package consensus

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/onionbalance/controller"
	"gobalance/pkg/onionbalance/stem"
	"gobalance/pkg/onionbalance/tornode"
	"gobalance/pkg/onionbalance/utils"
	"golang.org/x/crypto/sha3"
	"io"
	"strings"
	"time"
)

type Consensus struct {
	nodes      []*tornode.TorNode
	consensus  *ConsensusDoc
	controller *controller.Controller
}

func (c *Consensus) Nodes() []*tornode.TorNode {
	return c.nodes
}

func NewConsensus(controller *controller.Controller, doRefreshConsensus bool) *Consensus {
	c := &Consensus{}
	c.controller = controller
	// A list of tor_node:Node objects contained in the current consensus
	// c.nodes = nil
	// A stem NetworkStatusDocumentV3 object representing the current consensus
	// c.consensus = nil
	if !doRefreshConsensus {
		return c
	}
	c.Refresh()
	return c
}

func (c *Consensus) Consensus() *ConsensusDoc {
	return c.consensus
}

// Refresh attempt to refresh the consensus with the latest one available.
func (c *Consensus) Refresh() {
	mdConsensusStr := c.controller.GetMdConsensus()
	var err error
	c.consensus, err = NetworkStatusDocumentV3(mdConsensusStr)
	if err != nil {
		logrus.Warn("No valid consensus received. Waiting for one...")
		return
	}
	if !c.IsLive() {
		logrus.Info("Loaded consensus is not live. Waiting for a live one.")
		return
	}
	c.nodes = c.initializeNodes()
}

// IsLive return True if the consensus is live.
// This function replicates the behavior of the little-t-tor
// networkstatus_get_reasonably_live_consensus() function.
func (c *Consensus) IsLive() bool {
	if c.consensus == nil {
		return false
	}
	reasonablyLiveTime := 24 * 60 * 60 * time.Second
	now := btime.Clock.Now().UTC()
	isLive := now.After(c.consensus.validAfter.Add(-reasonablyLiveTime)) &&
		now.Before(c.consensus.validUntil.Add(reasonablyLiveTime))
	return isLive
}

func (c *Consensus) initializeNodes() []*tornode.TorNode {
	nodes := make([]*tornode.TorNode, 0)
	microdescriptorsList, err := c.controller.GetMicrodescriptors()
	if err != nil {
		logrus.Warn("Can't get microdescriptors from Tor. Delaying...")
		return nodes
	}
	// Turn the mds into a dictionary indexed by the digest as an
	// optimization while matching them with routerstatuses.
	microdescriptorsDict := make(map[string]controller.MicroDescriptor)
	for _, md := range microdescriptorsList {
		microdescriptorsDict[md.Digest()] = md
	}

	// Go through the routerstatuses and match them up with
	// microdescriptors, and create a Node object for each match. If there
	// is no match we don't register it as a node.
	for _, relayRouterStatus := range c.getRouterStatuses() {
		logrus.Debugf("Checking routerstatus with md digest %s", relayRouterStatus.Digest)
		nodeMicrodescriptor, found := microdescriptorsDict[relayRouterStatus.Digest]
		if !found {
			logrus.Debugf("Could not find microdesc for rs with fpr %s", relayRouterStatus.Fingerprint)
			continue
		}
		node := tornode.NewNode(nodeMicrodescriptor, relayRouterStatus)
		nodes = append(nodes, node)
	}
	return nodes
}

// Give access to the routerstatus entries in this Consensus
func (c *Consensus) getRouterStatuses() map[stem.Fingerprint]*stem.RouterStatus {
	// We should never be asked for routerstatuses with a non-live consensus
	// so make sure this is the case.
	if !c.IsLive() {
		panic("getRouterStatuses and not live")
	}
	return c.consensus.routers
}

type queueUnit struct {
	blurb string
	err   error
}

// NetworkStatusDocumentV3 parse a v3 network status document
// https://github.com/NullHypothesis/zoossh/blob/017a7be2e7138b78438186e76cd7655553c38224/consensus.go#L601
func NetworkStatusDocumentV3(mdConsensusStr string) (*ConsensusDoc, error) {
	var consensus = NewConsensusDoc()

	lines1 := strings.Split(mdConsensusStr, "\n")
	br := bufio.NewReader(strings.NewReader(strings.Join(lines1[2:], "\n")))
	err := extractMetaInfo(br, consensus)
	if err != nil {
		return nil, fmt.Errorf("metadata info extraction failed: %w", err)
	}
	queue := make(chan queueUnit)
	go dissectFile(br, extractStatusEntry, queue)

	// Parse incoming router statuses until the channel is closed by the remote
	// end.
	for unit := range queue {
		if unit.err != nil {
			return nil, unit.err
		}

		status, err := stem.ParseRawStatus(unit.blurb)
		if err != nil {
			return nil, err
		}

		consensus.routers[status.Fingerprint] = status
	}

	return consensus, nil
}

// NewConsensusDoc serves as a constructor and returns a pointer to a freshly
// allocated and empty Consensus.
func NewConsensusDoc() *ConsensusDoc {
	return &ConsensusDoc{routers: make(map[stem.Fingerprint]*stem.RouterStatus)}
}

type ConsensusDoc struct {
	// Generic map of consensus metadata
	metaInfo map[string][]byte

	// Document validity period
	validAfter time.Time
	freshUntil time.Time
	validUntil time.Time

	// Shared randomness
	sharedRandomnessPreviousValue []byte
	sharedRandomnessCurrentValue  []byte

	// A map from relay fingerprint to a function which returns the relay
	// status.
	routers map[stem.Fingerprint]*stem.RouterStatus
}

func (c ConsensusDoc) ValidAfter() time.Time {
	return c.validAfter
}

// Return the start time of the upcoming time period
func (c ConsensusDoc) GetStartTimeOfNextTimePeriod(validAfter int64) int64 {
	// Get start time of next time period
	timePeriodLength := c.GetTimePeriodLength()
	nextTimePeriodNum := c.getNextTimePeriodNum(validAfter)
	startOfNextTpInMins := nextTimePeriodNum * timePeriodLength
	// Apply rotation offset as specified by prop224 section [TIME-PERIODS]
	timePeriodRotationOffset := getSrvPhaseDuration()
	return (startOfNextTpInMins + timePeriodRotationOffset) * 60
}

func (c ConsensusDoc) GetPreviousSrv(timePeriodNum int64) []byte {
	if c.sharedRandomnessPreviousValue != nil {
		return c.sharedRandomnessPreviousValue
	} else if timePeriodNum != 0 {
		logrus.Info("SRV not found so falling back to disaster mode")
		return c.getDisasterSrv(timePeriodNum)
	}
	return nil
}

func (c ConsensusDoc) GetCurrentSrv(timePeriodNum int64) []byte {
	if c.sharedRandomnessCurrentValue != nil {
		return c.sharedRandomnessCurrentValue
	} else if timePeriodNum != 0 {
		logrus.Info("SRV not found so falling back to disaster mode")
		return c.getDisasterSrv(timePeriodNum)
	}
	return nil
}

func (c ConsensusDoc) GetStartTimeOfCurrentSrvRun() int64 {
	beginningOfCurrentRound := c.validAfter.Unix()
	votingIntervalSecs := int64(60 * 60)
	currRoundSlot := (beginningOfCurrentRound / votingIntervalSecs) % 24
	timeElapsedSinceStartOfRun := currRoundSlot * votingIntervalSecs
	logrus.Debugf("Current SRV proto run: Start of current round: %d. Time elapsed: %d (%d)\n", beginningOfCurrentRound,
		timeElapsedSinceStartOfRun, votingIntervalSecs)
	return beginningOfCurrentRound - timeElapsedSinceStartOfRun
}

func (c ConsensusDoc) GetStartTimeOfPreviousSrvRun() int64 {
	startTimeOfCurrentRun := c.GetStartTimeOfCurrentSrvRun()
	return startTimeOfCurrentRun - 24*3600
}

func (c ConsensusDoc) GetBlindingParam(identityPubkey ed25519.PublicKey, timePeriodNumber int64) []byte {
	// Calculate the HSv3 blinding parameter as specified in rend-spec-v3.txt section A.2:
	//
	// h = H(BLIND_STRING | A | s | B | N)
	// BLIND_STRING = "Derive temporary signing key" | INT_1(0)
	// N = "key-blind" | INT_8(period-number) | INT_8(period_length)
	// B = "(1511[...]2202, 4631[...]5960)"
	//
	// Use the time period number in 'time_period_number'.
	Ed25519Basepoint := []byte("(15112221349535400772501151409588531511" +
		"454012693041857206046113283949847762202, " +
		"463168356949264781694283940034751631413" +
		"07993866256225615783033603165251855960)")
	BlindString := []byte("Derive temporary signing key\x00")
	periodLength := c.GetTimePeriodLength()
	data1 := make([]byte, 8)
	binary.BigEndian.PutUint64(data1, uint64(timePeriodNumber))
	data2 := make([]byte, 8)
	binary.BigEndian.PutUint64(data2, uint64(periodLength))
	N := utils.BConcat([]byte("key-blind"), data1, data2)
	toEnc := utils.BConcat(BlindString, identityPubkey, Ed25519Basepoint, N)
	tmp := sha3.Sum256(toEnc)
	return tmp[:]
}

// Return disaster SRV for 'timePeriodNum'.
func (c ConsensusDoc) getDisasterSrv(timePeriodNum int64) []byte {
	timePeriodLength := c.GetTimePeriodLength()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(timePeriodLength))
	data1 := make([]byte, 8)
	binary.BigEndian.PutUint64(data1, uint64(timePeriodNum))
	disasterBody := utils.BConcat([]byte("shared-random-disaster"), data, data1)
	s := sha3.Sum256(disasterBody)
	return s[:]
}

func (c ConsensusDoc) getNextTimePeriodNum(validAfter int64) int64 {
	return c.GetTimePeriodNum(validAfter) + 1
}

// GetTimePeriodLength get the HSv3 time period length in minutes
func (c ConsensusDoc) GetTimePeriodLength() int64 {
	return 24 * 60
}

func getSrvPhaseDuration() int64 {
	return 12 * 60
}

// GetTimePeriodNum get time period number for this 'valid_after'.
//
// valid_after is a datetime (if not set, we get it ourselves)
// time_period_length set to default value of 1440 minutes == 1 day
func (c ConsensusDoc) GetTimePeriodNum(validAfter int64) int64 {
	timePeriodLength := c.GetTimePeriodLength()
	secondsSinceEpoch := validAfter
	minutesSinceEpoch := secondsSinceEpoch / 60
	// Calculate offset as specified in rend-spec-v3.txt [TIME-PERIODS]
	timePeriodRotationOffset := getSrvPhaseDuration()
	// assert(minutes_since_epoch > time_period_rotation_offset)
	minutesSinceEpoch -= timePeriodRotationOffset
	timePeriodNum := minutesSinceEpoch / timePeriodLength
	return timePeriodNum
}

// extractMetainfo extracts meta information of the open consensus document
// (such as its validity times) and writes it to the provided consensus struct.
// It assumes that the type annotation has already been read.
func extractMetaInfo(br *bufio.Reader, c *ConsensusDoc) error {

	c.metaInfo = make(map[string][]byte)

	// Read the initial metadata. We'll later extract information of particular
	// interest by name. The weird Reader loop is because scanner reads too much.
	for line, err := br.ReadSlice('\n'); ; line, err = br.ReadSlice('\n') {
		if err != nil {
			return err
		}

		// splits to (key, value)
		split := bytes.SplitN(line, []byte(" "), 2)
		if len(split) != 2 {
			return errors.New("malformed metainfo line")
		}

		key := string(split[0])
		c.metaInfo[key] = bytes.TrimSpace(split[1])

		// Look ahead to check if we've reached the end of the unique keys.
		nextKey, err := br.Peek(11)
		if err != nil {
			return err
		}
		if bytes.HasPrefix(nextKey, []byte("dir-source")) || bytes.HasPrefix(nextKey, []byte("fingerprint")) {
			break
		}
	}

	var err error
	// Define a parser for validity timestamps
	parseTime := func(line []byte) (time.Time, error) {
		return time.Parse("2006-01-02 15:04:05", string(line))
	}

	// Extract the validity period of this consensus
	c.validAfter, err = parseTime(c.metaInfo["valid-after"])
	if err != nil {
		return err
	}
	c.freshUntil, err = parseTime(c.metaInfo["fresh-until"])
	if err != nil {
		return err
	}
	c.validUntil, err = parseTime(c.metaInfo["valid-until"])
	if err != nil {
		return err
	}

	// Reads a shared-rand line from the consensus and returns decoded bytes.
	parseRand := func(line []byte) ([]byte, error) {
		split := bytes.SplitN(line, []byte(" "), 2)
		if len(split) != 2 {
			return nil, errors.New("malformed shared random line")
		}
		// should split to (vote count, b64 bytes)
		_, rand := split[0], split[1]
		return base64.StdEncoding.DecodeString(string(rand))
	}

	// Only the newer consensus documents have these values.
	if line, ok := c.metaInfo["shared-rand-previous-value"]; ok {
		val, err := parseRand(line)
		if err != nil {
			return err
		}
		c.sharedRandomnessPreviousValue = val
	}
	if line, ok := c.metaInfo["shared-rand-current-value"]; ok {
		val, err := parseRand(line)
		if err != nil {
			return err
		}
		c.sharedRandomnessCurrentValue = val
	}

	return nil
}

// Dissects the given file into string chunks by using the given string
// extraction function.  The resulting string chunks are then written to the
// given queue where the receiving end parses them.
func dissectFile(r io.Reader, extractor bufio.SplitFunc, queue chan queueUnit) {

	defer close(queue)

	scanner := bufio.NewScanner(r)
	scanner.Split(extractor)

	for scanner.Scan() {
		unit := scanner.Text()
		queue <- queueUnit{blurb: unit, err: nil}
	}

	if err := scanner.Err(); err != nil {
		queue <- queueUnit{blurb: "", err: err}
	}
}

// extractStatusEntry is a bufio.SplitFunc that extracts individual network
// status entries.
func extractStatusEntry(data []byte, atEOF bool) (advance int, token []byte, err error) {

	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	start := 0
	if !bytes.HasPrefix(data, []byte("r ")) {
		start = bytes.Index(data, []byte("\nr "))
		if start < 0 {
			if atEOF {
				return 0, nil, fmt.Errorf("cannot find beginning of status entry: \"\\nr \"")
			}
			// Request more data.
			return 0, nil, nil
		}
		start++
	}

	end := bytes.Index(data[start:], []byte("\nr "))
	if end >= 0 {
		return start + end + 1, data[start : start+end+1], nil
	}
	end = bytes.Index(data[start:], []byte("directory-signature"))
	if end >= 0 {
		// "directory-signature" means this is the last status; stop
		// scanning.
		return start + end, data[start : start+end], bufio.ErrFinalToken
	}
	if atEOF {
		return len(data), data[start:], errors.New("no status entry")
	}
	// Request more data.
	return 0, nil, nil
}
