package reality

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

var GlobalPostHandshakeRecordsLens sync.Map
var GlobalMaxCSSMsgCount sync.Map

// Probe cadence: re-probe a working dest occasionally so a long-running server
// tracks dest-side changes (cert / session-ticket sizes) instead of forever
// serving a snapshot frozen at startup; retry a failed probe much sooner so a
// transient blip while the server is starting doesn't leave the mimicry
// degraded until the next restart.
const (
	postHandshakeReprobeInterval = 30 * time.Minute
	postHandshakeRetryInterval   = time.Minute
)

func DetectPostHandshakeRecordsLens(config *Config) {
	for sni := range config.ServerNames {
		for alpn := range 3 { // 0, 1, 2
			key := config.Dest + " " + sni + " " + strconv.Itoa(alpn)
			if _, loaded := GlobalPostHandshakeRecordsLens.LoadOrStore(key, false); !loaded {
				// One supervisor per key. sni/alpn travel as arguments rather
				// than being captured, which also sidesteps the loop-variable
				// caveat the inline goroutines used to carry.
				go probePostHandshakeLoop(config, sni, alpn, key)
			}
		}
	}
}

// probePostHandshakeLoop keeps the cached record / CCS lengths for one
// (dest, sni, alpn) fresh. It probes, then sleeps for the re-probe interval on
// success or the shorter retry interval on failure, and loops forever. On a
// failure before any success it seeds an empty slice so a client polling this
// key in the handshake path doesn't block while the dest is unreachable; a
// later successful probe replaces it with the real lengths.
func probePostHandshakeLoop(config *Config, sni string, alpn int, key string) {
	everSucceeded := false
	for {
		ok := probePostHandshakeRecordLens(config, sni, alpn, key)
		// CCS tolerance is a stable property of the dest's stack and the probe
		// emits junk records, so only probe it until it's been captured once.
		if _, has := GlobalMaxCSSMsgCount.Load(key); !has {
			probeMaxCSSMsgCount(config, sni, alpn, key)
		}
		if ok {
			everSucceeded = true
			time.Sleep(postHandshakeReprobeInterval)
		} else {
			if !everSucceeded {
				if val, _ := GlobalPostHandshakeRecordsLens.Load(key); val != nil {
					if _, isBool := val.(bool); isBool { // still the initial placeholder
						GlobalPostHandshakeRecordsLens.Store(key, []int{})
					}
				}
			}
			time.Sleep(postHandshakeRetryInterval)
		}
	}
}

// probeProtos picks the uTLS fingerprint and ALPN list for the given alpn index
// (shared by both probes).
func probeProtos(alpn int) (utls.ClientHelloID, []string) {
	fingerprint := utls.HelloChrome_Auto
	nextProtos := []string{"h2", "http/1.1"}
	if alpn != 2 {
		fingerprint = utls.HelloGolang
	}
	if alpn == 1 {
		nextProtos = []string{"http/1.1"}
	}
	if alpn == 0 {
		nextProtos = nil
	}
	return fingerprint, nextProtos
}

// probePostHandshakeRecordLens runs one record-length probe against the dest.
// It returns true iff the TLS handshake to the dest completed — in which case
// PostHandshakeRecordDetectConn has stored the observed lengths for key. A
// failed dial/handshake returns false so the supervisor retries.
func probePostHandshakeRecordLens(config *Config, sni string, alpn int, key string) bool {
	target, err := net.Dial(config.Type, config.Dest)
	if err != nil {
		return false
	}
	defer target.Close()
	if config.Xver == 1 || config.Xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
			return false
		}
	}
	detectConn := &PostHandshakeRecordDetectConn{
		Conn: target,
		Key:  key,
	}
	fingerprint, nextProtos := probeProtos(alpn)
	uConn := utls.UClient(detectConn, &utls.Config{
		ServerName: sni,
		NextProtos: nextProtos,
	}, fingerprint)
	if err = uConn.Handshake(); err != nil {
		return false
	}
	io.Copy(io.Discard, uConn)
	return true
}

// probeMaxCSSMsgCount runs one ChangeCipherSpec-tolerance probe against the
// dest; CCSDetectConn stores the result for key during the handshake.
func probeMaxCSSMsgCount(config *Config, sni string, alpn int, key string) {
	target, err := net.Dial(config.Type, config.Dest)
	if err != nil {
		return
	}
	defer target.Close()
	if config.Xver == 1 || config.Xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
			return
		}
	}
	conn := &CCSDetectConn{
		Conn: target,
		Key:  key,
	}
	fingerprint, nextProtos := probeProtos(alpn)
	uConn := utls.UClient(conn, &utls.Config{
		ServerName: sni,
		NextProtos: nextProtos,
	}, fingerprint)
	uConn.Handshake()
}

type PostHandshakeRecordDetectConn struct {
	net.Conn
	Key     string
	CcsSent bool
}

func (c *PostHandshakeRecordDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.CcsSent = true
	}
	return c.Conn.Write(b)
}

func (c *PostHandshakeRecordDetectConn) Read(b []byte) (n int, err error) {
	if !c.CcsSent {
		return c.Conn.Read(b)
	}
	// Collect the dest's post-handshake records, but stop as soon as it goes
	// quiet — its NewSessionTickets arrive within milliseconds. The original
	// fixed 5s read deadline made every probe take a full 5s, which stalls the
	// first real client until the probe finishes (its handshake loop in tls.go
	// blocks until these lengths are stored). Adaptive read: a short per-read
	// timeout ends collection on ~200ms of silence, hard-capped at 2s.
	var data []byte
	buf := make([]byte, 4096)
	hardCap := time.Now().Add(2 * time.Second)
	for time.Now().Before(hardCap) {
		c.Conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		nn, rerr := c.Conn.Read(buf)
		if nn > 0 {
			data = append(data, buf[:nn]...)
		}
		if rerr != nil { // timeout (dest quiet) or EOF → done collecting
			break
		}
	}
	var postHandshakeRecordsLens []int
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			if len(data) < length { // a record claiming more bytes than collected would slice out of range → panic
				break
			}
			postHandshakeRecordsLens = append(postHandshakeRecordsLens, length)
			data = data[length:]
		} else {
			break
		}
	}
	if len(postHandshakeRecordsLens) > 0 {
		GlobalPostHandshakeRecordsLens.Store(c.Key, postHandshakeRecordsLens)
	} else {
		// An empty result (dest happened to be quiet this round) may only
		// overwrite the initial placeholder, never a previously captured
		// non-empty snapshot — otherwise a re-probe could degrade good mimicry.
		if val, ok := GlobalPostHandshakeRecordsLens.Load(c.Key); !ok {
			GlobalPostHandshakeRecordsLens.Store(c.Key, postHandshakeRecordsLens)
		} else if _, isBool := val.(bool); isBool {
			GlobalPostHandshakeRecordsLens.Store(c.Key, postHandshakeRecordsLens)
		}
	}
	return 0, io.EOF
}

var CCSMsg = []byte{0x14, 0x3, 0x3, 0x0, 0x1, 0x1}

type CCSDetectConn struct {
	net.Conn
	Key string
}

func (c *CCSDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		var hasAlert atomic.Bool
		go func() {
			defer hasAlert.Store(true)
			buf := make([]byte, 512)
			for {
				_, err = c.Conn.Read(buf)
				if err != nil {
					return
				}
				if buf[0] == 0x15 {
					return
				}
			}
		}()
		sendProbePayload := func(count int) bool {
			msg := bytes.Repeat(CCSMsg, count)
			c.Conn.Write(msg)
			time.Sleep(1 * time.Second)
			if hasAlert.Load() {
				return true
			}
			return false
		}
		if sendProbePayload(2) {
			GlobalMaxCSSMsgCount.Store(c.Key, 1)
			return c.Conn.Write(b)
		}
		if sendProbePayload(15) {
			GlobalMaxCSSMsgCount.Store(c.Key, 16)
			return c.Conn.Write(b)
		}
		if sendProbePayload(16) {
			GlobalMaxCSSMsgCount.Store(c.Key, 32)
			return c.Conn.Write(b)
		}
		GlobalMaxCSSMsgCount.Store(c.Key, math.MaxInt)
		return c.Conn.Write(b)
	}
	return c.Conn.Write(b)
}
