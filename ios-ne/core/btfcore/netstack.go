package btfcore

import (
	"context"
	"log"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID tcpip.NICID = 1

// maxInflightConns bounds concurrently handled TCP connections (memory).
const maxInflightConns = 400

// netStack is the userspace TCP/IP stack behind the packet tunnel.
type netStack struct {
	core *Core
	mtu  int

	stack *stack.Stack
	ep    *channel.Endpoint
	conns chan struct{}
}

func newNetStack(c *Core, mtu int) *netStack {
	return &netStack{core: c, mtu: mtu, conns: make(chan struct{}, maxInflightConns)}
}

func (n *netStack) start(ctx context.Context) error {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// Small buffers: the tunnel leg is the bottleneck, and extension memory is tight.
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 64 << 10, Max: 256 << 10}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 64 << 10, Max: 256 << 10}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	ep := channel.New(512, uint32(n.mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return wrapTcpipErr("create NIC", err)
	}
	// Accept packets for ANY destination address and answer as that address.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return wrapTcpipErr("promiscuous", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return wrapTcpipErr("spoofing", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	tcpFwd := tcp.NewForwarder(s, 0, 1024, n.onTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, n.onUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	n.stack = s
	n.ep = ep

	go n.outLoop(ctx)
	return nil
}

func (n *netStack) stop() {
	if n.stack != nil {
		n.stack.Close()
	}
}

// inject feeds one IP packet from the tunnel interface into the stack.
func (n *netStack) inject(b []byte) {
	if n.ep == nil || len(b) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch b[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	n.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

// outLoop forwards packets the stack wants to send to the tunnel interface.
func (n *netStack) outLoop(ctx context.Context) {
	for {
		pkt := n.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		b := view.AsSlice()
		out := make([]byte, len(b))
		copy(out, b)
		view.Release()
		pkt.DecRef()
		if n.core.writer != nil {
			n.core.writer.WritePacket(out)
		}
	}
}

// onTCP is called for every new TCP connection arriving from the tunnel.
func (n *netStack) onTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstAddr, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok || !dstAddr.Is4() {
		// IPv6 (or anything odd): reset so apps fall back to IPv4 immediately.
		r.Complete(true)
		return
	}
	dstAddr = dstAddr.Unmap()
	port := id.LocalPort

	select {
	case n.conns <- struct{}{}:
	default:
		log.Printf("[WARN] too many connections, resetting %s:%d", dstAddr, port)
		r.Complete(true)
		return
	}

	t := target{ip: dstAddr, port: port}
	if name, ok := n.core.dns.Lookup(dstAddr); ok {
		t = target{host: name, port: port}
	} else if n.core.dns.IsFake(dstAddr) {
		// Fake address whose mapping was evicted: nothing sensible to connect to.
		<-n.conns
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		<-n.conns
		r.Complete(true)
		return
	}
	r.Complete(false)
	conn := gonet.NewTCPConn(&wq, ep)

	go func() {
		defer func() { <-n.conns }()
		n.core.handleConn(conn, t)
	}()
}

// onUDP handles datagrams from the tunnel. Only DNS (port 53) is served;
// everything else is refused (ICMP port unreachable) so QUIC and friends fall
// back to TCP immediately.
func (n *netStack) onUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	if id.LocalPort != 53 {
		return false
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return true
	}
	conn := gonet.NewUDPConn(&wq, ep)
	go n.serveDNS(conn)
	return true
}

func (n *netStack) serveDNS(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		k, err := conn.Read(buf)
		if err != nil {
			return
		}
		if resp, ok := n.core.dns.Answer(buf[:k]); ok {
			conn.Write(resp)
		}
	}
}

func wrapTcpipErr(what string, err tcpip.Error) error {
	return &tcpipError{what: what, err: err}
}

type tcpipError struct {
	what string
	err  tcpip.Error
}

func (e *tcpipError) Error() string { return e.what + ": " + e.err.String() }
