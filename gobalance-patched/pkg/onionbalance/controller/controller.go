package controller

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/brand"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrSocketClosed = errors.New("socket closed")

type Controller struct {
	host     string
	port     int
	password string
	conn     net.Conn
	connMtx  sync.Mutex
	events   chan string
	msgs     chan TorReply
}

func NewController(host string, port int, torPassword string,
	descEventClb,
	descContentEventClb,
	statusEventClb func(string)) *Controller {
	c := new(Controller)
	c.host = host
	c.port = port
	c.password = torPassword
	c.MustDial()
	c.launchThreads(
		descEventClb,
		descContentEventClb,
		statusEventClb)
	if err := c.protocolAuth(); err != nil {
		panic(err)
	}
	//_ = c.SetEvents()
	return c
}

var reauthMtx sync.Mutex

func (c *Controller) ReAuthenticate() {
	if !reauthMtx.TryLock() {
		logrus.Error("re-authenticate already in progress")
		time.Sleep(10 * time.Second)
		return
	}
	defer reauthMtx.Unlock()
	for {
		time.Sleep(10 * time.Second)
		var err error
		if err = c.Dial(); err != nil {
			logrus.Error("Failed to re-authenticate controller.")
			continue
		}
		go c.connScannerThread()
		if err := c.protocolAuth(); err != nil {
			logrus.Error("Failed to re-authenticate controller.")
			c.connClose()
			continue
		}
		if err := c.SetEvents(); err != nil {
			logrus.Error("Failed to re-authenticate controller.")
			c.connClose()
			continue
		}
		break
	}
}

func (c *Controller) connClose() {
	c.connMtx.Lock()
	defer c.connMtx.Unlock()
	if err := c.conn.Close(); err != nil {
		logrus.Error(err)
	}
}

func (c *Controller) connWrite(msg string) error {
	c.connMtx.Lock()
	defer c.connMtx.Unlock()
	if _, err := c.conn.Write([]byte(msg)); err != nil {
		return ErrSocketClosed
	}
	return nil
}

func (c *Controller) protocolAuth() error {
	protocolInfo, err := c.ProtocolInfo()
	if err != nil {
		return err
	}
	if protocolInfo.isHashedPassword {
		if err := c.Auth(c.password); err != nil {
			return err
		}
	} else if protocolInfo.CookieContent != nil {
		if err := c.AuthWithCookie(protocolInfo.CookieContent); err != nil {
			return err
		}
	} else {
		if err := c.Auth(c.password); err != nil {
			return err
		}
	}
	logrus.Debug("Successfully authenticated on the Tor control connection.")
	return nil
}

// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/dir-spec.txt#L1642
func (c *Controller) launchThreads(
	descEventClb,
	descContentEventClb,
	statusEventClb func(string)) {
	c.events = make(chan string, 1000)
	c.msgs = make(chan TorReply, 1000)
	go c.eventsHandlerThread(
		descEventClb,
		descContentEventClb,
		statusEventClb)
	go c.connScannerThread()
}

func (c *Controller) eventsHandlerThread(
	descEventClb,
	descContentEventClb,
	statusEventClb func(string)) {
	for msg := range c.events {
		words := strings.Split(msg, " ")
		event := words[0]
		switch event {
		case "HS_DESC":
			descEventClb(msg)
		case "HS_DESC_CONTENT":
			descContentEventClb(msg)
		case "STATUS_CLIENT":
			statusEventClb(msg)
		}
	}
}

func (c *Controller) connScannerThread() {
	clb := func(msg TorReply) {
		if strings.HasPrefix(msg.code, "650") {
			c.events <- msg.inner
		} else {
			c.msgs <- msg
		}
	}
	connScannerThread(c.conn, clb)
	logrus.Error("Tor control connection lost")
	c.connClose()
}

type TorReply struct {
	code  string
	inner string
}

func (r TorReply) IsOk() bool {
	return r.code == "250"
}

// https://github.com/torproject/torspec/blob/f16803f6f93680f41f72bae29cf9dbef3962f94d/control-spec.txt#L248
func connScannerThread(r io.Reader, clb func(TorReply)) {
	scanner := bufio.NewScanner(r)
	firstLine := true
	firstLineCode := ""
	var sb strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			sb.WriteString(line)
			sb.WriteString("\n")
			firstLineCode = line[0:3]
			if line[3] != ' ' { // "650 " "650+" "250 " "250-"
				firstLine = false
				continue
			}
		} else if line != firstLineCode+" OK" {
			sb.WriteString(line)
			sb.WriteString("\n")
			continue
		}

		res := strings.TrimSpace(sb.String())[4:]
		res1 := TorReply{code: firstLineCode, inner: res}
		clb(res1)
		firstLine = true
		sb.Reset()
	}
}

func (c *Controller) MustDial() {
	if err := c.Dial(); err != nil {
		logrus.Fatalf("Unable to connect to Tor control port: %s:%d; %v", c.host, c.port, err)
	}
}

func (c *Controller) Dial() error {
	conn, err := dial(c.host, c.port)
	if err != nil {
		return err
	}

	c.connMtx.Lock()
	c.conn = conn
	c.connMtx.Unlock()
	return nil
}

func dial(host string, port int) (net.Conn, error) {
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	logrus.Debug("Successfully connected to the Tor control port.")
	return conn, nil
}

func (c *Controller) Auth(password string) error {
	msg, err := c.Msg(fmt.Sprintf("AUTHENTICATE \"%s\"\n", password))
	if err != nil {
		return err
	}
	if !msg.IsOk() {
		return fmt.Errorf("failed to AUTHENTICATE: %s", msg)
	}
	return nil
}

func (c *Controller) AuthWithCookie(cookieContent []byte) error {
	clientNonceBytes := make([]byte, 32)
	_, _ = brand.Read(clientNonceBytes)
	clientNonce := strings.ToUpper(hex.EncodeToString(clientNonceBytes))
	msg, err := c.Msg(fmt.Sprintf("AUTHCHALLENGE SAFECOOKIE %s\n", clientNonce))
	if err != nil {
		return err
	}
	rgx := regexp.MustCompile(`SERVERNONCE=(\S+)`)
	m := rgx.FindStringSubmatch(msg.inner)
	if len(m) != 2 {
		panic("failed to get server nonce")
	}
	serverNonce := m[1]
	cookieString := strings.ToUpper(hex.EncodeToString(cookieContent))
	toHash := fmt.Sprintf("%s%s%s\n", cookieString, clientNonce, serverNonce)
	toHashBytes, _ := hex.DecodeString(toHash)
	h := hmac.New(sha256.New, []byte("Tor safe cookie authentication controller-to-server hash"))
	h.Write(toHashBytes)
	sha := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	msg, err = c.Msg(fmt.Sprintf("AUTHENTICATE %s\n", sha))
	if err != nil {
		return err
	}
	if !msg.IsOk() {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (c *Controller) SetEvents() error {
	_, err := c.Msg("SETEVENTS SIGNAL CONF_CHANGED STATUS_SERVER STATUS_CLIENT HS_DESC HS_DESC_CONTENT\n")
	return err
}

func (c *Controller) GetInfo(s string) (TorReply, error) {
	return c.Msg(fmt.Sprintf("GETINFO %s\n", s))
}

func (c *Controller) Ip2Country(ip string) (string, error) {
	line, err := c.Msg(fmt.Sprintf("GETINFO ip-to-country/%s\n", ip))
	if err != nil {
		return "", err
	}
	rgx := regexp.MustCompile(`^250-ip-to-country/[^=]+=(\w+)$`)
	m := rgx.FindStringSubmatch(line.inner)
	if len(m) != 2 {
		return "", errors.New("failed to get country: " + string(line.inner))
	}
	return m[1], nil
}

func (c *Controller) HSFetch(addr string) error {
	line, err := c.Msg(fmt.Sprintf("HSFETCH %s\n", addr))
	if err != nil {
		return err
	}
	if !line.IsOk() {
		return errors.New(line.inner)
	}
	return nil
}

func (c *Controller) HSPost(addr string) error {
	_, err := c.Msg(fmt.Sprintf("+HSPOST HSADDRESS=%s\r\n%s\r\n.\r\n", strings.TrimSuffix(addr, ".onion"), "descriptor"))
	return err
}

func (c *Controller) Msg(msg string) (out TorReply, err error) {
	if err := c.connWrite(msg); err != nil {
		return out, ErrSocketClosed
	}

	select {
	case out = <-c.msgs:
	case <-time.After(5 * time.Second):
		logrus.Error("timed out trying to receive message from Tor control")
		return out, ErrSocketClosed
	}
	return out, nil
}

func (c *Controller) GetMdConsensus() string {
	res, _ := c.GetInfo("dir/status-vote/current/consensus-microdesc")
	return res.inner
}

type MicroDescriptor struct {
	identifiers map[string]string // string -> base64
	raw         string
}

func newMicroDescriptor(raw string) MicroDescriptor {
	return MicroDescriptor{raw: raw, identifiers: make(map[string]string)}
}

func (m MicroDescriptor) Identifiers() map[string]string {
	return m.identifiers
}

func (m MicroDescriptor) Digest() string {
	src := sha256.Sum256([]byte(m.raw))
	return strings.TrimRight(base64.StdEncoding.EncodeToString(src[:]), "=")
}

func (c *Controller) GetMicrodescriptors() ([]MicroDescriptor, error) {
	out := make([]MicroDescriptor, 0)

	mdAll, err := c.GetInfo("md/all")
	if err != nil {
		return out, err
	}
	lines := strings.Split(mdAll.inner, "\n")
	lines = lines[1 : len(lines)-1]

	desc := ""
	for _, line := range lines {
		if line == "onion-key" {
			if desc != "" {
				out = append(out, newMicroDescriptor(desc))
			}
			desc = line + "\n"
		} else {
			desc += line + "\n"
		}
	}
	out = append(out, newMicroDescriptor(desc))

	for idx := range out {
		lines := strings.Split(out[idx].raw, "\n")
		for _, line := range lines {
			// id ed25519 ufqCAi2Oqasmu67Dm0Ugru+Nk4xxCADXFj6RwdQk4WY
			if strings.HasPrefix(line, "id ed25519 ") {
				out[idx].identifiers["ed25519"] = strings.TrimPrefix(line, "id ed25519 ")
			}
		}
	}

	return out, nil
}

type ProtocolInfoStruct struct {
	isHashedPassword bool
	CookieContent    []byte
}

func (c *Controller) ProtocolInfo() (out ProtocolInfoStruct, err error) {
	msg, err := c.Msg("PROTOCOLINFO\n")
	if err != nil {
		return out, err
	}
	lines := strings.Split(msg.inner, "\n")
	if len(lines) != 3 {
		panic(msg)
	}
	if strings.Contains(lines[1], "NULL") {
	} else if strings.Contains(lines[1], "HASHEDPASSWORD") {
		out.isHashedPassword = true
	} else if strings.Contains(lines[1], "COOKIE") {
		rgx := regexp.MustCompile(`250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="([^"]+)"`)
		m := rgx.FindStringSubmatch(lines[1])
		if len(m) != 2 {
			panic("failed to get cookie path")
		}
		cookiePath := m[1]
		cookieBytes, err := os.ReadFile(cookiePath)
		if err != nil {
			panic(err)
		}
		out.CookieContent = cookieBytes
	}
	return
}

func (c *Controller) GetVersion() string {
	reply, _ := c.GetInfo("version")
	versionStr := strings.TrimPrefix(reply.inner, "version=")
	return versionStr
}

func (c *Controller) Signal(signal string) (string, error) {
	reply, err := c.Msg(fmt.Sprintf("SIGNAL %s\n", signal))
	return reply.inner, err
}

func (c *Controller) MarkTorAsActive() {
	if _, err := c.Signal("ACTIVE"); err != nil {
		logrus.Warn("Can't connect to the control port to send ACTIVE signal. Moving on...")
	}
}

// GetHiddenServiceDescriptor We need a way to await these results.
func (c *Controller) GetHiddenServiceDescriptor(address string, awaitResult bool) error {
	return c.HSFetch(address)
}
