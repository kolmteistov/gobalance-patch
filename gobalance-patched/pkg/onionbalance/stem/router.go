package stem

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Fingerprint represents a relay's fingerprint as 40 hex digits.
type Fingerprint string

type RouterStatus struct {

	// The single fields of an "r" line.
	Nickname    string
	Fingerprint Fingerprint
	Digest      string
	Publication time.Time

	// The IPv4 and IPv6 fields of "a" line
	Address RouterAddress

	// The single fields of an "s" line.
	Flags RouterFlags

	// The single fields of a "v" line.
	TorVersion string

	// The single fields of a "w" line.
	Bandwidth  uint64
	Measured   uint64
	Unmeasured bool

	// The single fields of a "p" line.
	Accept   bool
	PortList string
}

type RouterFlags struct {
	Authority bool
	BadExit   bool
	Exit      bool
	Fast      bool
	Guard     bool
	HSDir     bool
	Named     bool
	Stable    bool
	Running   bool
	Unnamed   bool
	Valid     bool
	V2Dir     bool
}

type RouterAddress struct {
	IPv4Address net.IP
	IPv4ORPort  uint16
	IPv4DirPort uint16

	IPv6Address net.IP
	IPv6ORPort  uint16
}

// ParseRawStatus parses a raw router status (in string format) and returns the
// router's fingerprint, a function which returns a RouterStatus, and an error
// if there were any during parsing.
func ParseRawStatus(rawStatus string) (*RouterStatus, error) {

	var status = new(RouterStatus)

	lines := strings.Split(rawStatus, "\n")

	// Go over raw statuses line by line and extract the fields we are
	// interested in.
	for _, line := range lines {

		words := strings.Split(line, " ")

		switch words[0] {

		case "r":
			status.Nickname = words[1]
			fingerprint, err := base64ToString(words[2])
			if err != nil {
				return nil, err
			}
			status.Fingerprint = sanitiseFingerprint(fingerprint)

			parsedTime, _ := time.Parse(publishedTimeLayout, strings.Join(words[3:5], " "))
			status.Publication = parsedTime
			status.Address.IPv4Address = net.ParseIP(words[5])
			status.Address.IPv4ORPort = stringToPort(words[6])
			status.Address.IPv4DirPort = stringToPort(words[7])

		case "a":
			status.Address.IPv6Address, status.Address.IPv6ORPort = parseIPv6AddressAndPort(words[1])

		case "m":
			status.Digest = words[1]

		case "s":
			status.Flags = *parseRouterFlags(words[1:])

		case "v":
			status.TorVersion = words[2]

		case "w":
			bwExpr := words[1]
			values := strings.Split(bwExpr, "=")
			status.Bandwidth, _ = strconv.ParseUint(values[1], 10, 64)

		case "p":
			if words[1] == "accept" {
				status.Accept = true
			} else {
				status.Accept = false
			}
			status.PortList = strings.Join(words[2:], " ")
		}
	}

	return status, nil
}

const (
	// The layout of the "published" field.
	publishedTimeLayout = "2006-01-02 15:04:05"
)

// Returns a sanitised version of the given fingerprint by
// making it upper case and removing leading and trailing white spaces.
func sanitiseFingerprint(fingerprint string) Fingerprint {
	sanitised := strings.ToUpper(strings.TrimSpace(fingerprint))
	return Fingerprint(sanitised)
}

func parseIPv6AddressAndPort(addressAndPort string) (address net.IP, port uint16) {
	var ipV6regex = regexp.MustCompile(`\[(.*?)]`)
	var ipV6portRegex = regexp.MustCompile(`]:(.*)`)
	address = net.ParseIP(ipV6regex.FindStringSubmatch(addressAndPort)[1])
	port = stringToPort(ipV6portRegex.FindStringSubmatch(addressAndPort)[1])

	return address, port
}

// stringToPort Convert the given port string to an unsigned 16-bit integer.  If the
// conversion fails or the number cannot be represented in 16 bits, 0 is
// returned.
func stringToPort(portStr string) uint16 {

	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return uint16(0)
	}

	return uint16(portNum)
}

func parseRouterFlags(flags []string) *RouterFlags {

	var routerFlags = new(RouterFlags)

	for _, flag := range flags {
		switch flag {
		case "Authority":
			routerFlags.Authority = true
		case "BadExit":
			routerFlags.BadExit = true
		case "Exit":
			routerFlags.Exit = true
		case "Fast":
			routerFlags.Fast = true
		case "Guard":
			routerFlags.Guard = true
		case "HSDir":
			routerFlags.HSDir = true
		case "Named":
			routerFlags.Named = true
		case "Stable":
			routerFlags.Stable = true
		case "Running":
			routerFlags.Running = true
		case "Unnamed":
			routerFlags.Unnamed = true
		case "Valid":
			routerFlags.Valid = true
		case "V2Dir":
			routerFlags.V2Dir = true
		}
	}

	return routerFlags
}

// Decodes the given Base64-encoded string and returns the resulting string.
// If there are errors during decoding, an error string is returned.
func base64ToString(encoded string) (string, error) {

	// dir-spec.txt says that Base64 padding is removed so we have to account
	// for that here.
	if rem := len(encoded) % 4; rem != 0 {
		encoded += strings.Repeat("=", 4-rem)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(decoded), nil
}
