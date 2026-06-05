package reality

import (
	"bytes"
	"context"
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

const (
	// Probe cadence: re-probe a working dest occasionally so a long-running
	// server tracks dest-side changes (cert / session-ticket sizes) instead of
	// forever serving a snapshot frozen at startup; retry a failed probe much
	// sooner so a transient blip at startup doesn't leave the mimicry degraded
	// until the next restart.
	postHandshakeReprobeInterval = 30 * time.Minute
	postHandshakeRetryInterval   = time.Minute

	// Adaptive probe-read tuning (see PostHandshakeRecordDetectConn.Read).
	probeReadChunk    = 4096                   // per-read buffer size
	probeQuietTimeout = 200 * time.Millisecond // dest silence that ends collection
	probeHardCap      = 2 * time.Second        // absolute cap on one collection

	// Handshake-path tuning (see Server in tls.go).
	destHandshakeReadDeadline = 15 * time.Second      // bound on mirroring the dest's ServerHello flight
	postHandshakePollBudget   = 5 * time.Second       // max wait for the probe before serving without mimicry
	postHandshakePollInterval = 50 * time.Millisecond // poll granularity while waiting
)

// DetectPostHandshakeRecordsLens probes the dest for the whole process lifetime.
// Prefer DetectPostHandshakeRecordsLensContext when a cancellation scope is
// available (e.g. a listener's context) so the probe goroutines stop with it.
func DetectPostHandshakeRecordsLens(config *Config) {
	DetectPostHandshakeRecordsLensContext(context.Background(), config)
}

// DetectPostHandshakeRecordsLensContext starts one supervisor goroutine per
// (dest, sni, alpn) key, each keeping that key's cached lengths fresh until ctx
// is cancelled.
func DetectPostHandshakeRecordsLensContext(ctx context.Context, config *Config) {
	for sni := range config.ServerNames {
		for alpn := range 3 { // 0, 1, 2
			key := config.Dest + " " + sni + " " + strconv.Itoa(alpn)
			if _, loaded := GlobalPostHandshakeRecordsLens.LoadOrStore(key, false); !loaded {
				// sni/alpn travel as arguments rather than being captured, which
				// also sidesteps the loop-variable caveat the inline goroutines
				// used to carry.
				go probePostHandshakeLoop(ctx, config, sni, alpn, key)
			}
		}
	}
}

// probePostHandshakeLoop keeps the cached record / CCS lengths for one
// (dest, sni, alpn) fresh: it probes, then waits the re-probe interval on
// success or the shorter retry interval on failure, and loops until ctx is
// cancelled. On a failure before any success it seeds an empty slice so a
// client polling this key in the handshake path doesn't block while the dest is
// unreachable; a later successful probe replaces it with the real lengths.
func probePostHandshakeLoop(ctx context.Context, config *Config, sni string, alpn int, key string) {
	everSucceeded := false
	for {
		ok := probePostHandshakeRecordLens(config, sni, alpn, key)
		// CCS tolerance is a stable property of the dest's stack and the probe
		// emits junk records, so only probe it until it's been captured once.
		if _, has := GlobalMaxCSSMsgCount.Load(key); !has {
			probeMaxCSSMsgCount(config, sni, alpn, key)
		}
		interval := postHandshakeRetryInterval
		if ok {
			everSucceeded = true
			interval = postHandshakeReprobeInterval
		} else if !everSucceeded {
			storeEmptyIfPlaceholder(key)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// storeEmptyIfPlaceholder records an empty length list for key, but only while
// the entry is still the initial bool placeholder — it never overwrites real
// lengths captured by an earlier successful probe. This is the "dest momentarily
// unreachable or quiet" fallback that keeps a polling client from blocking.
func storeEmptyIfPlaceholder(key string) {
	if v, ok := GlobalPostHandshakeRecordsLens.Load(key); !ok {
		GlobalPostHandshakeRecordsLens.Store(key, []int{})
	} else if _, isPlaceholder := v.(bool); isPlaceholder {
		GlobalPostHandshakeRecordsLens.Store(key, []int{})
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
	buf := make([]byte, probeReadChunk)
	hardCap := time.Now().Add(probeHardCap)
	for time.Now().Before(hardCap) {
		c.Conn.SetReadDeadline(time.Now().Add(probeQuietTimeout))
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
		// An empty result (dest was quiet this round) may only replace the
		// placeholder, never a previously captured non-empty snapshot.
		storeEmptyIfPlaceholder(c.Key)
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
