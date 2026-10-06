package btfcore

import (
	"context"
	"runtime"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// A second gVisor stack plays the role of the iPhone: it sends real IP
// packets into the core and reads the replies, so the full path
// app -> packets -> netstack -> BTF stream -> exit node -> internet is exercised.
//
//	BTF_URL=wss://.../helper-path BTF_TOKEN=... go test ./btfcore -run E2E -v
type loopWriter struct{ ep *channel.Endpoint }

func (l loopWriter) WritePacket(b []byte) {
	var proto tcpip.NetworkProtocolNumber = ipv4.ProtocolNumber
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	l.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

func TestE2E(t *testing.T) {
	url, token := os.Getenv("BTF_URL"), os.Getenv("BTF_TOKEN")
	if url == "" || token == "" {
		t.Skip("BTF_URL/BTF_TOKEN not set")
	}

	// "phone" side stack
	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	cep := channel.New(512, 1400, "")
	if err := cs.CreateNIC(1, cep); err != nil {
		t.Fatal(err)
	}
	addr := tcpip.AddrFrom4([4]byte{198, 18, 0, 1})
	if err := cs.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	cs.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	core := NewCore(url, token, false, 50, 1400, loopWriter{cep}, nil)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	defer core.Stop()

	// phone -> core
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			pkt := cep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			b := append([]byte(nil), v.AsSlice()...)
			v.Release()
			pkt.DecRef()
			core.InjectPacket(b)
		}
	}()

	// wait for the tunnel
	deadline := time.Now().Add(60 * time.Second)
	for !core.ready() {
		if time.Now().After(deadline) {
			t.Fatalf("tunnel never became ready; logs:\n%s", core.Logs())
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Logf("tunnel ready: %s", core.Status())

	resolve := func(name string) string {
		dns := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), Port: 53}
		uc, err := gonet.DialUDP(cs, nil, &dns, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("dial dns: %v", err)
		}
		defer uc.Close()
		n, _ := dnsmessage.NewName(name + ".")
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
		b.StartQuestions()
		b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		uc.Write(q)
		uc.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1500)
		k, err := uc.Read(buf)
		if err != nil {
			t.Fatalf("dns read: %v", err)
		}
		var p dnsmessage.Parser
		if _, err := p.Start(buf[:k]); err != nil {
			t.Fatal(err)
		}
		p.SkipAllQuestions()
		ans, err := p.Answer()
		if err != nil {
			t.Fatalf("no answer: %v", err)
		}
		a := ans.Body.(*dnsmessage.AResource).A
		return net.IP(a[:]).String()
	}

	fetch := func(host string) string {
		ip := resolve(host)
		t.Logf("dns %s -> %s", host, ip)
		if !strings.HasPrefix(ip, "198.18.") {
			t.Fatalf("expected fake ip, got %s", ip)
		}
		parsed := net.ParseIP(ip).To4()
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte(parsed)), Port: 80}, ipv4.ProtocolNumber)
		}}
		cl := &http.Client{Transport: tr, Timeout: 40 * time.Second}
		start := time.Now()
		resp, err := cl.Get("http://" + host + "/")
		if err != nil {
			t.Fatalf("get %s: %v\nlogs:\n%s", host, err, core.Logs())
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		t.Logf("GET %s -> %d in %v, %d bytes", host, resp.StatusCode, time.Since(start), len(body))
		return string(body)
	}

	out := fetch("api.ipify.org")
	t.Logf("exit ip: %s", strings.TrimSpace(out))
	if net.ParseIP(strings.TrimSpace(out)) == nil {
		t.Fatalf("unexpected body: %q", out)
	}
	// literal-IP path (no DNS): connect straight to 1.1.1.1:80
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 80}, ipv4.ProtocolNumber)
	}}
	cl := &http.Client{Transport: tr, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Get("http://1.1.1.1/")
	if err != nil {
		t.Fatalf("literal ip get: %v\nlogs:\n%s", err, core.Logs())
	}
	resp.Body.Close()
	t.Logf("GET http://1.1.1.1/ -> %d", resp.StatusCode)
	if big := os.Getenv("BTF_BIG"); big != "" {
		host := strings.TrimPrefix(strings.TrimPrefix(big, "http://"), "https://")
		host = strings.SplitN(host, "/", 2)[0]
		ip := resolve(host)
		parsed := net.ParseIP(ip).To4()
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte(parsed)), Port: 80}, ipv4.ProtocolNumber)
		}}
		cl := &http.Client{Transport: tr, Timeout: 120 * time.Second}
		start := time.Now()
		resp, err := cl.Get(big)
		if err != nil {
			t.Fatalf("big get: %v", err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d := time.Since(start)
		t.Logf("BIG %s: %d bytes in %v = %.2f Mbit/s", big, n, d, float64(n)*8/d.Seconds()/1e6)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("mem: HeapAlloc=%.1fMB HeapSys=%.1fMB Sys=%.1fMB", float64(ms.HeapAlloc)/1e6, float64(ms.HeapSys)/1e6, float64(ms.Sys)/1e6)
	t.Logf("final status: %s", core.Status())
}
