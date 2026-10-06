package btfcore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"btfcore/internal/protocol"
	"btfcore/internal/streams"
)

// target is where a tunnelled connection should end up: either a domain name
// (fake-IP hit; the exit node resolves it) or a literal IPv4 address.
type target struct {
	host string
	ip   netip.Addr
	port uint16
}

func (t target) String() string {
	if t.host != "" {
		return fmt.Sprintf("%s:%d", t.host, t.port)
	}
	return fmt.Sprintf("%s:%d", t.ip, t.port)
}

// socksRequest builds the pipelined SOCKS5 greeting + CONNECT request. Both
// are sent in the very first DATA frame so the handshake costs no extra
// tunnel round trips; the server's two replies are stripped on the way back.
func socksRequest(t target) []byte {
	b := []byte{0x05, 0x01, 0x00} // greeting: 1 method, no-auth
	b = append(b, 0x05, 0x01, 0x00)
	if t.host != "" {
		b = append(b, 0x03, byte(len(t.host)))
		b = append(b, t.host...)
	} else {
		a := t.ip.As4()
		b = append(b, 0x01)
		b = append(b, a[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, t.port)
	return b
}

// socksConn wraps the local (app-facing) connection of a stream:
//   - the first Read returns the SOCKS5 handshake bytes, so they are the first
//     thing forwarded to the exit node (and get coalesced with the first
//     application bytes);
//   - Write (peer -> local) swallows the SOCKS5 replies before passing real
//     data through.
type socksConn struct {
	net.Conn
	hs []byte

	replyDone bool
	rbuf      []byte
}

var errSocks = errors.New("socks5 handshake failed")

func (s *socksConn) Read(p []byte) (int, error) {
	if len(s.hs) > 0 {
		n := copy(p, s.hs)
		s.hs = s.hs[n:]
		return n, nil
	}
	return s.Conn.Read(p)
}

// Write receives data coming back from the exit node.
func (s *socksConn) Write(p []byte) (int, error) {
	if s.replyDone {
		return s.Conn.Write(p)
	}
	s.rbuf = append(s.rbuf, p...)
	// method reply: [05 00]
	if len(s.rbuf) < 2 {
		return len(p), nil
	}
	if s.rbuf[0] != 0x05 || s.rbuf[1] != 0x00 {
		return 0, fmt.Errorf("%w: method reply % x", errSocks, s.rbuf[:2])
	}
	// connect reply: [05 REP 00 ATYP BND.ADDR BND.PORT]
	if len(s.rbuf) < 6 {
		return len(p), nil
	}
	if s.rbuf[2] != 0x05 {
		return 0, fmt.Errorf("%w: bad reply version", errSocks)
	}
	rep := s.rbuf[3]
	var alen int
	switch s.rbuf[5] {
	case 0x01:
		alen = 4
	case 0x04:
		alen = 16
	case 0x03:
		if len(s.rbuf) < 7 {
			return len(p), nil
		}
		alen = 1 + int(s.rbuf[6])
	default:
		return 0, fmt.Errorf("%w: bad ATYP %d", errSocks, s.rbuf[5])
	}
	total := 2 + 4 + alen + 2
	// NOTE: ATYP lives at index 2+3=5 after the 2-byte method reply.
	if len(s.rbuf) < total {
		return len(p), nil
	}
	if rep != 0x00 {
		return 0, fmt.Errorf("%w: CONNECT refused (rep=%d)", errSocks, rep)
	}
	s.replyDone = true
	rest := s.rbuf[total:]
	s.rbuf = nil
	if len(rest) > 0 {
		if _, err := s.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (s *socksConn) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (s *socksConn) CloseRead() error {
	if cr, ok := s.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// handleConn tunnels one local connection to t. It blocks until the stream is
// finished and always closes conn.
func (c *Core) handleConn(conn net.Conn, t target) {
	if !c.waitForPeer(10 * time.Second) {
		log.Printf("[WARN] no peer available, dropping connection to %s", t)
		conn.Close()
		return
	}

	shortID := c.ups.HelperShortID()
	localID := c.sm.NextID() & protocol.StreamLocalIDMask
	sid := (uint32(shortID) << protocol.StreamHelperShortIDShift) | localID

	s := &streams.Stream{ID: sid, Conn: &socksConn{Conn: conn, hs: socksRequest(t)}}

	// Pre-register so frames arriving right after OPEN_OK are not dropped.
	c.sm.Register(s)

	ch := make(chan protocol.Frame, 1)
	c.pendingMu.Lock()
	c.pending[sid] = ch
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, sid)
		c.pendingMu.Unlock()
	}()

	if err := c.sm.SendFrame(protocol.Frame{Type: protocol.MsgOpen, StreamID: sid}); err != nil {
		log.Printf("[WARN] send OPEN failed stream=%d err=%v", sid, err)
		c.openFail.Add(1)
		c.sm.CloseStream(s)
		return
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			c.sm.CloseStream(s)
			return
		}
		if resp.Type == protocol.MsgOpenFail {
			log.Printf("[INFO] stream rejected stream=%d target=%s reason=%s", sid, t, string(resp.Payload))
			c.openFail.Add(1)
			c.sm.CloseStream(s)
			return
		}
		c.openOK.Add(1)
	case <-time.After(30 * time.Second):
		log.Printf("[WARN] OPEN timeout stream=%d target=%s", sid, t)
		c.openFail.Add(1)
		c.sm.CloseStream(s)
		return
	case <-c.ctx.Done():
		c.sm.CloseStream(s)
		return
	}

	c.sm.ReadLoop(s)
}

// waitForPeer blocks until the tunnel can carry a stream: HELLO_OK received
// (so we own a helper short ID) and, in direct mode, the adapter is known.
func (c *Core) waitForPeer(timeout time.Duration) bool {
	ready := func() bool {
		if c.cfg.WsAPI.Relay {
			return c.ups.OwnConnID() != ""
		}
		return c.ups.PeerConnID() != "" && c.ups.IAMToken() != ""
	}
	if ready() {
		return true
	}
	if !c.cfg.WsAPI.Relay {
		c.ups.SendSync()
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	poll := time.NewTicker(150 * time.Millisecond)
	defer poll.Stop()
	syncT := time.NewTicker(2 * time.Second)
	defer syncT.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-syncT.C:
			if !c.cfg.WsAPI.Relay && c.ups.PeerConnID() == "" {
				c.ups.SendSync()
			}
		case <-poll.C:
			if ready() {
				return true
			}
		}
	}
}
