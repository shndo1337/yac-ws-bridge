package streams

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"btfcore/internal/protocol"
)

// SendFunc sends a protocol frame to the peer. Implementations differ between
// adapter (always wsSend) and helper (wsSend or relay via upstream WS).
type SendFunc func(data []byte) error

// Stream represents one multiplexed TCP connection.
type Stream struct {
	ID   uint32
	Conn net.Conn

	mu     sync.Mutex
	closed bool
	// Half-close bookkeeping. A stream stays alive until BOTH directions have
	// finished (or either side sends RST):
	//   localReadEnded   — our Conn hit EOF; we sent FIN to the peer.
	//   remoteWriteEnded — the peer sent FIN; we half-closed our Conn's write side.
	localReadEnded   bool
	remoteWriteEnded bool

	// Async write queue (peer -> local). The upstream read loop must never
	// block on a slow local consumer, so frames are queued here and drained
	// by a per-stream goroutine started in Register.
	wq        chan writeItem
	closeCh   chan struct{}
	closeOnce sync.Once
}

// writeItem is one queued peer->local operation: a data write or a FIN.
type writeItem struct {
	data []byte
	fin  bool
}

// maxWriteQueue bounds queued frames per stream. A stream that falls this far
// behind is reset instead of buffering without limit (memory is tight inside
// an iOS network extension).
const maxWriteQueue = 96

type closeWriter interface{ CloseWrite() error }
type closeReader interface{ CloseRead() error }

// Manager tracks active streams and dispatches incoming frames.
type Manager struct {
	mu            sync.Mutex
	streams       map[uint32]*Stream
	nextID        atomic.Uint32 // helper-only: allocates stream IDs
	send          SendFunc
	CoalesceDelay time.Duration // 0 = disabled

	// Per-stream send sequence counters (auto-incremented in SendFrame).
	seqCounters sync.Map // streamID → *atomic.Uint32

	// Reorder incoming stream frames by SeqID (adapter-only).
	Reorder     bool
	reorderMu   sync.Mutex
	reorderBufs map[uint32]*reorderBuf
}

// reorderBuf holds out-of-order frames for a single stream.
type reorderBuf struct {
	mu       sync.Mutex
	expected uint32
	pending  map[uint32]protocol.Frame
	broken   bool // overflowed or timed out; stream is being reset, drop further frames
	// gapTimer fires if a sequence gap is not filled within reorderGapTimeout,
	// bounding how long a stream may stall behind a single lost frame.
	gapTimer *time.Timer
}

func NewManager(send SendFunc) *Manager {
	m := &Manager{
		streams:     make(map[uint32]*Stream),
		send:        send,
		reorderBufs: make(map[uint32]*reorderBuf),
	}
	m.nextID.Store(1)
	return m
}

// NextID allocates a new stream ID (used by helper).
func (m *Manager) NextID() uint32 {
	return m.nextID.Add(1) - 1
}

// Register adds a stream to the manager.
func (m *Manager) Register(s *Stream) {
	s.wq = make(chan writeItem, maxWriteQueue)
	s.closeCh = make(chan struct{})
	m.mu.Lock()
	m.streams[s.ID] = s
	m.mu.Unlock()
	go m.writeLoop(s)
}

// writeLoop drains the stream's peer->local queue in order.
func (m *Manager) writeLoop(s *Stream) {
	for {
		select {
		case <-s.closeCh:
			return
		case it := <-s.wq:
			if it.fin {
				s.mu.Lock()
				if s.closed {
					s.mu.Unlock()
					return
				}
				s.remoteWriteEnded = true
				if cw, ok := s.Conn.(closeWriter); ok {
					cw.CloseWrite()
				}
				bothDone := s.localReadEnded
				s.mu.Unlock()
				if bothDone {
					m.CloseStream(s)
				}
				continue
			}
			if _, err := s.Conn.Write(it.data); err != nil {
				log.Printf("[WARN] write to TCP failed stream=%d err=%v", s.ID, err)
				m.SendFrame(protocol.Frame{Type: protocol.MsgRst, StreamID: s.ID})
				m.CloseStream(s)
				return
			}
		}
	}
}

// enqueue queues a peer->local item without blocking the caller. If the queue
// is full the stream is reset.
func (m *Manager) enqueue(s *Stream, it writeItem) {
	select {
	case s.wq <- it:
	default:
		log.Printf("[WARN] write queue overflow stream=%d, resetting", s.ID)
		go func() {
			m.SendFrame(protocol.Frame{Type: protocol.MsgRst, StreamID: s.ID})
			m.CloseStream(s)
		}()
	}
}

// Get returns a stream by ID, or nil.
func (m *Manager) Get(id uint32) *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[id]
}

// Remove unregisters a stream and cleans up associated state.
func (m *Manager) Remove(id uint32) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
	m.seqCounters.Delete(id)
	m.dropReorderBuf(id)
}

// SendFrame encodes and sends a frame to the peer.
// For stream frames (StreamID > 0), SeqID is auto-assigned.
func (m *Manager) SendFrame(f protocol.Frame) error {
	if f.StreamID > 0 {
		v, _ := m.seqCounters.LoadOrStore(f.StreamID, &atomic.Uint32{})
		f.SeqID = v.(*atomic.Uint32).Add(1)
	}
	return m.send(protocol.Encode(f))
}

// HandleData queues payload for the stream's TCP connection (non-blocking).
func (m *Manager) HandleData(streamID uint32, payload []byte) {
	s := m.Get(streamID)
	if s == nil {
		return
	}
	s.mu.Lock()
	skip := s.closed || s.remoteWriteEnded
	s.mu.Unlock()
	if skip {
		return
	}
	m.enqueue(s, writeItem{data: payload})
}

// HandleFin processes a graceful close from the peer: the peer has finished
// sending, so we half-close our local write side (the local app reads EOF) but
// keep the read side open so local->peer data still flows until our own read
// ends. The stream is fully closed only once BOTH directions are done.
func (m *Manager) HandleFin(streamID uint32) {
	s := m.Get(streamID)
	if s == nil {
		log.Printf("[DEBUG] FIN for unknown stream=%d", streamID)
		return
	}
	log.Printf("[DEBUG] FIN handling stream=%d", streamID)
	m.enqueue(s, writeItem{fin: true})
}

// HandleRst aborts a stream immediately.
func (m *Manager) HandleRst(streamID uint32) {
	s := m.Get(streamID)
	if s == nil {
		log.Printf("[DEBUG] RST for unknown stream=%d", streamID)
		return
	}
	log.Printf("[DEBUG] RST handling stream=%d", streamID)
	m.CloseStream(s)
}

// CloseStream closes the TCP connection and removes the stream.
func (m *Manager) CloseStream(s *Stream) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	if s.closeCh != nil {
		s.closeOnce.Do(func() { close(s.closeCh) })
	}
	log.Printf("[DEBUG] closing stream=%d", s.ID)
	s.Conn.Close()
	m.Remove(s.ID)
}

// CloseAll RSTs all active streams and closes their TCP connections.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	all := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		all = append(all, s)
	}
	m.mu.Unlock()

	if len(all) > 0 {
		log.Printf("[INFO] closing all %d streams", len(all))
	}
	for _, s := range all {
		m.CloseStream(s)
	}

	// Clear seq counters
	m.seqCounters.Range(func(key, _ any) bool {
		m.seqCounters.Delete(key)
		return true
	})
	// Clear reorder buffers
	if m.Reorder {
		m.reorderMu.Lock()
		for _, rb := range m.reorderBufs {
			rb.mu.Lock()
			m.stopGapTimer(rb)
			rb.broken = true
			rb.mu.Unlock()
		}
		m.reorderBufs = make(map[uint32]*reorderBuf)
		m.reorderMu.Unlock()
	}
}

// CloseHelper closes every stream whose top byte of stream ID matches the
// given helper short ID. Used on the adapter side when a single helper goes
// away (PEER_GONE for that helper, or wsSend persistently fails) without
// disturbing streams belonging to other helpers. Returns the number of
// streams closed.
func (m *Manager) CloseHelper(shortID byte) int {
	if shortID == 0 {
		return 0
	}
	m.mu.Lock()
	victims := make([]*Stream, 0)
	for id, s := range m.streams {
		if byte(id>>24) == shortID {
			victims = append(victims, s)
		}
	}
	m.mu.Unlock()

	for _, s := range victims {
		m.CloseStream(s)
	}

	// Clear reorder buffers for this helper.
	if m.Reorder {
		m.reorderMu.Lock()
		for id, rb := range m.reorderBufs {
			if byte(id>>24) == shortID {
				rb.mu.Lock()
				m.stopGapTimer(rb)
				rb.broken = true
				rb.mu.Unlock()
				delete(m.reorderBufs, id)
			}
		}
		m.reorderMu.Unlock()
	}
	// Seq counters get cleaned up by Remove() inside CloseStream.
	return len(victims)
}

// maxReorderPending bounds how many out-of-order frames are buffered per stream
// while waiting for a missing SeqID. wsSend parallelism normally reorders only
// a handful of frames; reaching this many pending almost certainly means a
// frame was genuinely lost and the gap will never close. Rather than buffer
// forever (unbounded memory + a permanently stalled stream), we give up: RST
// the peer and tear the stream down so the application layer can recover.
const maxReorderPending = 1024

// reorderGapTimeout bounds how long a stream may wait for a single missing
// frame before we give up. maxReorderPending only fires when >1024 later frames
// pile up; if just a handful follow the gap, the buffer would otherwise wait
// forever. This per-stream timer guarantees a stalled stream is reset within a
// bounded interval so the application layer can recover.
const reorderGapTimeout = 30 * time.Second

// HandleStreamFrame processes an incoming stream frame with optional reordering.
// When Reorder is true, frames are buffered and delivered in SeqID order.
// The handler callback is invoked for each frame in sequence order and may be
// called multiple times if buffered frames become deliverable.
//
// The handler is always invoked WITHOUT rb.mu held. A handler may tear the
// stream down (FIN/RST -> CloseStream -> Remove -> dropReorderBuf, which locks
// rb.mu); calling it under rb.mu would self-deadlock the single read loop. Since
// HandleStreamFrame is only ever driven by that one read loop per manager,
// collecting the deliverable frames under the lock and dispatching them after
// unlocking still preserves strict in-order delivery.
func (m *Manager) HandleStreamFrame(f protocol.Frame, handler func(protocol.Frame)) {
	if !m.Reorder || f.SeqID == 0 {
		handler(f)
		return
	}

	m.reorderMu.Lock()
	rb, ok := m.reorderBufs[f.StreamID]
	if !ok {
		rb = &reorderBuf{expected: 1, pending: make(map[uint32]protocol.Frame)}
		m.reorderBufs[f.StreamID] = rb
	}
	m.reorderMu.Unlock()

	overflow := false
	var overflowExpected uint32
	var deliver []protocol.Frame // dispatched in order after rb.mu is released
	rb.mu.Lock()
	if rb.broken {
		// Stream already flagged for reset; drop further frames so the buffer
		// can't regrow and we don't spawn duplicate resets.
		rb.mu.Unlock()
		return
	}
	if f.SeqID == rb.expected {
		deliver = append(deliver, f)
		rb.expected++
		// Drain consecutive buffered frames.
		for {
			next, exists := rb.pending[rb.expected]
			if !exists {
				break
			}
			delete(rb.pending, rb.expected)
			deliver = append(deliver, next)
			rb.expected++
		}
		// The gap (if any) advanced: stop the timer when fully caught up, else
		// restart it so the next still-missing frame gets its own deadline.
		if len(rb.pending) == 0 {
			m.stopGapTimer(rb)
		} else {
			m.armGapTimer(f.StreamID, rb)
		}
	} else if f.SeqID > rb.expected {
		if _, dup := rb.pending[f.SeqID]; !dup {
			rb.pending[f.SeqID] = f
		}
		if len(rb.pending) > maxReorderPending {
			overflow = true
			overflowExpected = rb.expected
			rb.broken = true
			m.stopGapTimer(rb)
		} else {
			// First out-of-order frame for the current gap: start the timer so a
			// single lost frame can't stall the stream forever.
			if rb.gapTimer == nil {
				m.armGapTimer(f.StreamID, rb)
			}
			if len(rb.pending)%100 == 0 {
				log.Printf("[WARN] reorder buffer growing stream=%d pending=%d expected=%d got=%d",
					f.StreamID, len(rb.pending), rb.expected, f.SeqID)
			}
		}
	} else {
		log.Printf("[WARN] duplicate/old frame stream=%d seq=%d expected=%d", f.StreamID, f.SeqID, rb.expected)
	}
	rb.mu.Unlock()

	// Dispatch in order without holding rb.mu (see the doc comment above).
	for _, df := range deliver {
		handler(df)
	}

	if overflow {
		log.Printf("[ERROR] reorder overflow stream=%d pending>%d expected=%d (lost frame?), resetting stream",
			f.StreamID, maxReorderPending, overflowExpected)
		m.resetStream(f.StreamID)
	}
}

// armGapTimer (re)starts the reorder gap timer for rb. Caller must hold rb.mu.
// A superseded timer that has already fired is ignored by comparing identity in
// the callback, so restarting can never trigger a spurious reset.
func (m *Manager) armGapTimer(streamID uint32, rb *reorderBuf) {
	if rb.gapTimer != nil {
		rb.gapTimer.Stop()
	}
	var t *time.Timer
	t = time.AfterFunc(reorderGapTimeout, func() {
		rb.mu.Lock()
		if rb.gapTimer != t || rb.broken || len(rb.pending) == 0 {
			rb.mu.Unlock()
			return
		}
		rb.broken = true
		rb.gapTimer = nil
		expected := rb.expected
		rb.mu.Unlock()
		log.Printf("[ERROR] reorder gap timeout stream=%d expected=%d (lost frame?), resetting stream", streamID, expected)
		m.resetStream(streamID)
	})
	rb.gapTimer = t
}

// stopGapTimer cancels rb's gap timer if running. Caller must hold rb.mu.
func (m *Manager) stopGapTimer(rb *reorderBuf) {
	if rb.gapTimer != nil {
		rb.gapTimer.Stop()
		rb.gapTimer = nil
	}
}

// resetStream RSTs the peer and tears the stream down. Runs off the read-loop
// goroutine because SendFrame (wsSend) may block; stalling there would delay
// delivery for every other stream.
func (m *Manager) resetStream(streamID uint32) {
	go func() {
		_ = m.SendFrame(protocol.Frame{Type: protocol.MsgRst, StreamID: streamID})
		if s := m.Get(streamID); s != nil {
			m.CloseStream(s) // Remove() clears the reorder buffer + seq counter.
		} else {
			m.dropReorderBuf(streamID)
		}
	}()
}

// dropReorderBuf stops any gap timer and removes the stream's reorder buffer.
func (m *Manager) dropReorderBuf(streamID uint32) {
	if !m.Reorder {
		return
	}
	m.reorderMu.Lock()
	if rb, ok := m.reorderBufs[streamID]; ok {
		rb.mu.Lock()
		m.stopGapTimer(rb)
		rb.broken = true
		rb.mu.Unlock()
		delete(m.reorderBufs, streamID)
	}
	m.reorderMu.Unlock()
}

// ReadLoop reads from TCP and sends DATA frames to the peer.
// On EOF it sends FIN; on error it sends RST. Returns when done.
// When CoalesceDelay > 0, small reads are buffered and flushed as one
// DATA frame after the delay expires (Nagle-like write coalescing).
func (m *Manager) ReadLoop(s *Stream) {
	buf := make([]byte, 32*1024)
	var coalesceBuf []byte
	coalesce := m.CoalesceDelay > 0

	flush := func() error {
		if len(coalesceBuf) == 0 {
			return nil
		}
		payload := coalesceBuf
		coalesceBuf = nil
		if sendErr := m.SendFrame(protocol.Frame{
			Type:     protocol.MsgData,
			StreamID: s.ID,
			Payload:  payload,
		}); sendErr != nil {
			log.Printf("[WARN] send DATA failed stream=%d err=%v", s.ID, sendErr)
			return sendErr
		}
		return nil
	}

	// sendFailed records whether the loop is unwinding because forwarding to
	// the peer broke (RST) rather than a clean local EOF (FIN).
	sendFailed := false

	defer func() {
		if coalesce {
			if err := flush(); err != nil {
				sendFailed = true
			}
		}
		m.finishLocalRead(s, sendFailed)
	}()

	for {
		// If coalescing and we have buffered data, set a short read deadline
		// so we flush after CoalesceDelay if no more data arrives.
		if coalesce && len(coalesceBuf) > 0 {
			s.Conn.SetReadDeadline(time.Now().Add(m.CoalesceDelay))
		} else if coalesce {
			s.Conn.SetReadDeadline(time.Time{}) // block indefinitely
		}

		n, err := s.Conn.Read(buf)
		if n > 0 {
			if coalesce {
				coalesceBuf = append(coalesceBuf, buf[:n]...)
				// Flush immediately if buffer is large enough
				if len(coalesceBuf) >= 32*1024 {
					if flushErr := flush(); flushErr != nil {
						sendFailed = true
						return
					}
				}
			} else {
				payload := make([]byte, n)
				copy(payload, buf[:n])
				if sendErr := m.SendFrame(protocol.Frame{
					Type:     protocol.MsgData,
					StreamID: s.ID,
					Payload:  payload,
				}); sendErr != nil {
					log.Printf("[WARN] send DATA failed stream=%d err=%v", s.ID, sendErr)
					sendFailed = true
					return
				}
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Read deadline expired — flush buffered data and continue
				if flushErr := flush(); flushErr != nil {
					sendFailed = true
					return
				}
				continue
			}
			return
		}
	}
}

// finishLocalRead is called once the local read side (Conn -> peer) ends. On a
// clean local EOF it sends FIN and half-closes our read side, leaving the write
// side open so peer -> local data keeps flowing until the peer FINs. If the
// loop ended because forwarding to the peer failed, it RSTs instead. The stream
// is fully closed only when both directions are done (or on RST).
func (m *Manager) finishLocalRead(s *Stream, forwardingFailed bool) {
	s.mu.Lock()
	if s.closed || s.localReadEnded {
		s.mu.Unlock()
		return
	}
	s.localReadEnded = true
	remoteDone := s.remoteWriteEnded
	s.mu.Unlock()

	if forwardingFailed {
		log.Printf("[DEBUG] forwarding failed stream=%d, sending RST", s.ID)
		m.SendFrame(protocol.Frame{Type: protocol.MsgRst, StreamID: s.ID})
		m.CloseStream(s)
		return
	}

	log.Printf("[DEBUG] TCP read ended stream=%d, sending FIN", s.ID)
	m.SendFrame(protocol.Frame{Type: protocol.MsgFin, StreamID: s.ID})
	if cr, ok := s.Conn.(closeReader); ok {
		cr.CloseRead()
	}
	if remoteDone {
		// Peer already FIN'd — both directions done, close fully.
		m.CloseStream(s)
	}
}

// Count returns the number of active streams.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.streams)
}
