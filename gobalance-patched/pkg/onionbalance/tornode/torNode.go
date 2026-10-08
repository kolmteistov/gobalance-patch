package tornode

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/onionbalance/controller"
	"gobalance/pkg/onionbalance/stem"
	"gobalance/pkg/onionbalance/utils"
	"golang.org/x/crypto/sha3"
)

type TorNode struct {
	microdescriptor controller.MicroDescriptor
	routerstatus    *stem.RouterStatus
}

func (n *TorNode) Routerstatus() *stem.RouterStatus {
	return n.routerstatus
}

func NewNode(microdescriptor controller.MicroDescriptor, routerstatus *stem.RouterStatus) *TorNode {
	logrus.Debugf("Initializing node with fpr %s", routerstatus.Fingerprint)

	n := &TorNode{}
	n.microdescriptor = microdescriptor
	n.routerstatus = routerstatus
	return n
}

func (n *TorNode) GetHexFingerprint() stem.Fingerprint {
	return n.routerstatus.Fingerprint
}

var ErrNoHSDir = errors.New("NoHSDir")
var ErrNoEd25519Identity = errors.New("NoEd25519Identity")

// GetHsdirIndex get the HSDir index for this node:
//
//	hsdir_index(node) = H("node-idx" | node_identity |
//	                      shared_random_value |
//	                      INT_8(period_num) |
//	                      INT_8(period_length) )
//
// Raises NoHSDir or NoEd25519Identity in case of errors.
func (n *TorNode) GetHsdirIndex(srv []byte, period_num, periodLength int64) ([]byte, error) {
	// See if this node can be an HSDir (it needs to be supported both in
	// protover and in flags)
	//arr, found := n.routerstatus.Protocols["HSDir"]
	//if !found {
	//	panic("NoHSDir")
	//}
	//found = false
	//for _, el := range arr {
	//	if 2 == el {
	//		found = true
	//		break
	//	}
	//}
	//if !found {
	//	panic("NoHSDir")
	//}
	if !n.routerstatus.Flags.HSDir {
		return nil, ErrNoHSDir
	}

	// See if ed25519 identity is supported for this node
	ed25519NodeIdentityB64, found := n.microdescriptor.Identifiers()["ed25519"]
	if !found {
		return nil, ErrNoEd25519Identity
	}

	// In stem the ed25519 identity is a base64 string and we need to add
	// the missing padding so that the python base64 module can successfully
	// decode it.
	// TODO: Abstract this into its own function...
	for len(ed25519NodeIdentityB64)%4 != 0 {
		ed25519NodeIdentityB64 += "="
	}
	ed25519NodeIdentity, err := base64.StdEncoding.DecodeString(ed25519NodeIdentityB64)
	if err != nil {
		return nil, err
	}

	periodNumInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodNumInt8, uint64(period_num))
	periodLengthInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodLengthInt8, uint64(periodLength))

	hashBody := utils.BConcat([]byte("node-idx"), ed25519NodeIdentity, srv, periodNumInt8, periodLengthInt8)
	hsdirIndex := sha3.Sum256(hashBody)

	return hsdirIndex[:], nil
}
