// Package btfcore is the iOS network-extension core of Bridge to Freedom.
//
// It terminates the IP packets of an iOS packet tunnel in a userspace TCP/IP
// stack (gVisor), and carries every TCP connection through the existing
// Bridge-to-Freedom stream protocol (helper side). The adapter on the server
// side always dials a fixed target (a SOCKS5 server), so each stream starts
// with a SOCKS5 CONNECT that names the real destination.
package btfcore

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"btfcore/internal/config"
	"btfcore/internal/protocol"
	"btfcore/internal/streams"
	"btfcore/internal/upstream"
	"btfcore/internal/wsapi"
)

// PacketWriter receives IP packets that must be written back to the tunnel
// interface (implemented in Swift).
type PacketWriter interface {
	WritePacket(b []byte)
}

// Logger receives log lines (implemented in Swift). May be nil.
type Logger interface {
	Log(line string)
}

// Core is one running tunnel instance.
type Core struct {
	cfg    *config.Config
	writer PacketWriter
	logger Logger

	ctx    context.Context
	cancel context.CancelFunc

	wsClient wsapi.Client
	ups      *upstream.Upstream
	sm       *streams.Manager
	dns      *fakeDNS
	ns       *netStack

	pendingMu sync.Mutex
	pending   map[uint32]chan protocol.Frame

	started  atomic.Bool
	stopped  atomic.Bool
	openOK   atomic.Int64
	openFail atomic.Int64

	logMu   sync.Mutex
	logRing []string
}

// NewCore creates a core. mtu is the tunnel MTU.
func NewCore(bridgeURL, authToken string, relay bool, coalesceMs int, mtu int, w PacketWriter, l Logger) *Core {
	cfg := &config.Config{}
	cfg.Bridge.URL = strings.TrimSpace(bridgeURL)
	cfg.Bridge.AuthToken = strings.TrimSpace(authToken)
	cfg.Bridge.Reconnect.InitialDelayMs = 1000
	cfg.Bridge.Reconnect.MaxDelayMs = 30000
	cfg.Bridge.Reconnect.BackoffMultiplier = 2
	cfg.Bridge.PingIntervalMs = 30000
	cfg.WsAPI.Mode = "grpc"
	cfg.WsAPI.Relay = relay
	if coalesceMs > 0 {
		cfg.WriteCoalescing.Enabled = true
		cfg.WriteCoalescing.DelayMs = coalesceMs
	}
	if mtu <= 0 {
		mtu = 1400
	}
	c := &Core{
		cfg:     cfg,
		writer:  w,
		logger:  l,
		pending: make(map[uint32]chan protocol.Frame),
		dns:     newFakeDNS(),
	}
	c.ns = newNetStack(c, mtu)
	return c
}

// Start brings the netstack and the upstream connection up. It returns quickly;
// the upstream keeps (re)connecting in the background.
func (c *Core) Start() error {
	if !c.started.CompareAndSwap(false, true) {
		return fmt.Errorf("already started")
	}
	// Network extensions on iOS are limited to ~50 MB: keep the Go heap tight.
	debug.SetGCPercent(40)
	debug.SetMemoryLimit(34 << 20)

	log.SetFlags(log.LstdFlags)
	log.SetOutput(logSink{c})

	if c.cfg.Bridge.URL == "" || c.cfg.Bridge.AuthToken == "" {
		return fmt.Errorf("bridge URL and token are required")
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.wsClient = wsapi.NewClient()

	c.sm = streams.NewManager(c.send)
	c.sm.CoalesceDelay = c.cfg.CoalesceDelay()
	c.sm.Reorder = true

	c.ups = upstream.New(c.cfg, c.onFrame)

	if err := c.ns.start(c.ctx); err != nil {
		return err
	}
	go func() {
		c.ups.Run(c.ctx)
	}()
	go c.memoryTrim()
	log.Printf("[INFO] core started bridge=%s relay=%v coalesce=%v", c.cfg.Bridge.URL, c.cfg.WsAPI.Relay, c.cfg.CoalesceDelay())
	return nil
}

// Stop tears everything down. Safe to call more than once.
func (c *Core) Stop() {
	if !c.started.Load() || !c.stopped.CompareAndSwap(false, true) {
		return
	}
	log.Printf("[INFO] core stopping")
	if c.sm != nil {
		c.sm.CloseAll()
	}
	c.cancelPending("stopping")
	if c.cancel != nil {
		c.cancel()
	}
	c.ns.stop()
}

// InjectPacket hands one raw IP packet read from the tunnel interface to the stack.
func (c *Core) InjectPacket(b []byte) {
	if c.stopped.Load() {
		return
	}
	c.ns.inject(b)
}

// Status is a short human-readable state line.
func (c *Core) Status() string {
	if c.stopped.Load() || !c.started.Load() {
		return "stopped"
	}
	state := "connecting"
	if c.ready() {
		state = "ready"
	}
	return fmt.Sprintf("%s streams=%d openOK=%d openFail=%d", state, c.sm.Count(), c.openOK.Load(), c.openFail.Load())
}

// Logs returns the recent log lines joined by newlines.
func (c *Core) Logs() string {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	return strings.Join(c.logRing, "\n")
}

func (c *Core) ready() bool {
	if c.cfg.WsAPI.Relay {
		return c.ups.OwnConnID() != ""
	}
	return c.ups.PeerConnID() != "" && c.ups.IAMToken() != ""
}

// --- logging ---

type logSink struct{ c *Core }

func (l logSink) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\r\n")
	// Skip very chatty debug lines.
	if strings.Contains(line, "[DEBUG]") {
		return len(p), nil
	}
	l.c.logMu.Lock()
	l.c.logRing = append(l.c.logRing, line)
	if len(l.c.logRing) > 150 {
		l.c.logRing = l.c.logRing[len(l.c.logRing)-150:]
	}
	l.c.logMu.Unlock()
	if l.c.logger != nil {
		l.c.logger.Log(line)
	}
	return len(p), nil
}

// memoryTrim returns freed memory to the OS periodically.
func (c *Core) memoryTrim() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			debug.FreeOSMemory()
		}
	}
}

// --- send path (same logic as the Go helper) ---

func (c *Core) send(data []byte) error {
	if c.cfg.WsAPI.Relay {
		return c.ups.Send(data)
	}
	peerID := c.ups.PeerConnID()
	token := c.ups.IAMToken()
	if peerID == "" || token == "" {
		return fmt.Errorf("no peer connected")
	}
	err := c.wsClient.Send(peerID, data, "BINARY", token)
	if err != nil {
		if wsapi.IsConnectionNotFound(err) {
			c.ups.MarkPeerStale(peerID)
		} else {
			log.Printf("[WARN] transient wsSend error (keeping peer): %v", err)
		}
	}
	return err
}

// --- frame dispatch (same logic as the Go helper) ---

func (c *Core) onFrame(f protocol.Frame) {
	switch f.Type {
	case protocol.MsgPeerConn:
		peerID, iamToken, _, err := protocol.DecodePeerConn(f.Payload)
		if err != nil {
			log.Printf("[WARN] bad PEER_CONN: %v", err)
			return
		}
		if c.ups.IsStaleConnID(peerID) {
			log.Printf("[WARN] PEER_CONN with stale ID %s, ignoring", peerID)
			return
		}
		c.ups.ClearStaleConnID()
		c.cancelPending("new peer connected")
		log.Printf("[INFO] PEER_CONN received: peerID=%s tokenLen=%d", peerID, len(iamToken))
		c.ups.SetPeerConnID(peerID)
		if iamToken != "" {
			c.ups.SetIAMToken(iamToken)
		}
	case protocol.MsgPeerGone:
		if c.cfg.WsAPI.Relay {
			log.Printf("[INFO] PEER_GONE (relay mode) - ignoring")
			return
		}
		log.Printf("[INFO] PEER_GONE received, closing %d streams", c.sm.Count())
		c.ups.SetPeerConnID("")
		c.cancelPending("peer gone")
		c.sm.CloseAll()
	case protocol.MsgPong:
		iamToken, err := protocol.DecodePong(f.Payload)
		if err != nil {
			log.Printf("[WARN] bad PONG: %v", err)
			return
		}
		c.ups.SetIAMToken(iamToken)
	case protocol.MsgPing:
		// Only the cloud function answers PINGs; ignore strays.
	case protocol.MsgOpenOK, protocol.MsgOpenFail, protocol.MsgData, protocol.MsgFin, protocol.MsgRst:
		c.sm.HandleStreamFrame(f, func(of protocol.Frame) {
			switch of.Type {
			case protocol.MsgOpenOK, protocol.MsgOpenFail:
				c.deliverOpen(of)
			case protocol.MsgData:
				c.sm.HandleData(of.StreamID, of.Payload)
			case protocol.MsgFin:
				c.sm.HandleFin(of.StreamID)
			case protocol.MsgRst:
				c.sm.HandleRst(of.StreamID)
			}
		})
	default:
		log.Printf("[WARN] unknown frame type=0x%02x stream=%d", f.Type, f.StreamID)
	}
}

func (c *Core) deliverOpen(f protocol.Frame) {
	c.pendingMu.Lock()
	ch, ok := c.pending[f.StreamID]
	c.pendingMu.Unlock()
	if ok {
		select {
		case ch <- f:
		default:
		}
		return
	}
	log.Printf("[WARN] OPEN response for unknown stream=%d type=0x%02x", f.StreamID, f.Type)
}

func (c *Core) cancelPending(reason string) {
	c.pendingMu.Lock()
	n := len(c.pending)
	for sid, ch := range c.pending {
		close(ch)
		delete(c.pending, sid)
	}
	c.pendingMu.Unlock()
	if n > 0 {
		log.Printf("[INFO] cancelled %d pending opens: %s", n, reason)
	}
}
