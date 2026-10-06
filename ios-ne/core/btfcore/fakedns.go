package btfcore

import (
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers every A query instantly with an address from a private pool
// and remembers which name it belongs to. When an app later connects to that
// address the tunnel asks the exit node to connect to the NAME, so name
// resolution happens remotely (no DNS round trip through the slow tunnel, no
// DNS leak). Everything that is not an A query gets an empty NOERROR answer,
// which makes apps stay on IPv4.
type fakeDNS struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	base    uint32
	size    uint32
	next    uint32
	byName  map[string]uint32
	byIndex []string
}

// fakePoolPrefix is the pool of fake addresses (16384 entries).
var fakePoolPrefix = netip.MustParsePrefix("198.18.64.0/18")

func newFakeDNS() *fakeDNS {
	a := fakePoolPrefix.Addr().As4()
	base := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	size := uint32(1) << (32 - fakePoolPrefix.Bits())
	return &fakeDNS{
		prefix:  fakePoolPrefix,
		base:    base,
		size:    size,
		next:    2, // skip .0 / .1
		byName:  make(map[string]uint32),
		byIndex: make([]string, size),
	}
}

func (f *fakeDNS) addrFor(idx uint32) netip.Addr {
	v := f.base + idx
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// alloc returns the fake address for name, creating it if needed. When the
// pool wraps, the oldest mapping is evicted.
func (f *fakeDNS) alloc(name string) netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if idx, ok := f.byName[name]; ok {
		return f.addrFor(idx)
	}
	idx := f.next
	f.next++
	if f.next >= f.size {
		f.next = 2
	}
	if old := f.byIndex[idx]; old != "" {
		delete(f.byName, old)
	}
	f.byIndex[idx] = name
	f.byName[name] = idx
	return f.addrFor(idx)
}

// Lookup maps a fake address back to its name.
func (f *fakeDNS) Lookup(a netip.Addr) (string, bool) {
	if !a.Is4() || !f.prefix.Contains(a) {
		return "", false
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	idx := v - f.base
	f.mu.Lock()
	defer f.mu.Unlock()
	if idx < f.size && f.byIndex[idx] != "" {
		return f.byIndex[idx], true
	}
	return "", false
}

// IsFake reports whether a lies inside the fake pool.
func (f *fakeDNS) IsFake(a netip.Addr) bool { return a.Is4() && f.prefix.Contains(a) }

// Answer builds the DNS response for a raw query. ok=false means the query
// could not be parsed and should be dropped.
func (f *fakeDNS) Answer(query []byte) (resp []byte, ok bool) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	rh := dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		OpCode:             h.OpCode,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 128), rh)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, false
	}
	if err := b.Question(q); err != nil {
		return nil, false
	}
	if q.Type == dnsmessage.TypeA && q.Class == dnsmessage.ClassINET {
		name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
		if name != "" {
			if err := b.StartAnswers(); err != nil {
				return nil, false
			}
			ip := f.alloc(name).As4()
			err := b.AResource(dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   5,
			}, dnsmessage.AResource{A: ip})
			if err != nil {
				return nil, false
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, false
	}
	return out, true
}
