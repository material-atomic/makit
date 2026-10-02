// Package shield is `makit shield`: an IP gate in front of web apps. Reverse proxies (Caddy forward_auth, nginx
// auth_request) ask it about every request; directly-connected IPs are also dropped in the kernel (nftables set).
package shield

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Set is makit's own IP set — the ipset hash:ip / hash:net design in memory: one hash table per prefix length, so a
// lookup is at most 33 (IPv4) or 129 (IPv6) map probes whatever the size, most specific first. Each element stores
// only its expiry and an index into a table of distinct (reason, source) pairs, so millions of entries stay compact.
type Set struct {
	mu    sync.RWMutex
	v4    map[uint8]map[[4]byte]meta
	v6    map[uint8]map[[16]byte]meta
	bits4 []uint8 // prefix lengths present, longest first
	bits6 []uint8
	infos []info
	index map[info]uint32
	n     int
}

type meta struct {
	until int64 // unix seconds; 0 = permanent
	added int64
	info  uint32
}

type info struct{ reason, source string }

type Entry struct {
	Prefix netip.Prefix `json:"prefix"`
	Until  time.Time    `json:"until,omitempty"` // zero = permanent
	Reason string       `json:"reason,omitempty"`
	Source string       `json:"source,omitempty"` // manual, rule:<id>, list:<name>
	Added  time.Time    `json:"added"`
}

func NewSet() *Set {
	return &Set{v4: map[uint8]map[[4]byte]meta{}, v6: map[uint8]map[[16]byte]meta{}, index: map[info]uint32{}}
}

// ParsePrefix accepts an IP or CIDR (IPv4/IPv6) and normalises it.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (s *Set) infoID(reason, source string) uint32 {
	k := info{reason, source}
	if id, ok := s.index[k]; ok {
		return id
	}
	id := uint32(len(s.infos))
	s.infos = append(s.infos, k)
	s.index[k] = id
	return id
}

func insertBits(bs []uint8, b uint8) []uint8 {
	for _, x := range bs {
		if x == b {
			return bs
		}
	}
	bs = append(bs, b)
	sort.Slice(bs, func(i, j int) bool { return bs[i] > bs[j] })
	return bs
}

func (s *Set) Add(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.add(e.Prefix, meta{until: unix(e.Until), added: unix(e.Added), info: s.infoID(e.Reason, e.Source)})
}

func (s *Set) add(p netip.Prefix, m meta) {
	b := uint8(p.Bits())
	if p.Addr().Is4() {
		t := s.v4[b]
		if t == nil {
			t = map[[4]byte]meta{}
			s.v4[b], s.bits4 = t, insertBits(s.bits4, b)
		}
		if _, ok := t[p.Addr().As4()]; !ok {
			s.n++
		}
		t[p.Addr().As4()] = m
		return
	}
	t := s.v6[b]
	if t == nil {
		t = map[[16]byte]meta{}
		s.v6[b], s.bits6 = t, insertBits(s.bits6, b)
	}
	if _, ok := t[p.Addr().As16()]; !ok {
		s.n++
	}
	t[p.Addr().As16()] = m
}

// AddMany inserts entries sharing one reason/source/expiry (bulk lists) with a single lock.
func (s *Set) AddMany(ps []netip.Prefix, until time.Time, reason, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := meta{until: unix(until), added: time.Now().Unix(), info: s.infoID(reason, source)}
	for _, p := range ps {
		s.add(p, m)
	}
}

func (s *Set) Remove(p netip.Prefix) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := uint8(p.Bits())
	if p.Addr().Is4() {
		if t := s.v4[b]; t != nil {
			if _, ok := t[p.Addr().As4()]; ok {
				delete(t, p.Addr().As4())
				s.n--
				return true
			}
		}
		return false
	}
	if t := s.v6[b]; t != nil {
		if _, ok := t[p.Addr().As16()]; ok {
			delete(t, p.Addr().As16())
			s.n--
			return true
		}
	}
	return false
}

// Len is the number of elements (expired ones included until pruned).
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.n
}

func (s *Set) entry(p netip.Prefix, m meta) Entry {
	e := Entry{Prefix: p, Reason: s.infos[m.info].reason, Source: s.infos[m.info].source}
	if m.until != 0 {
		e.Until = time.Unix(m.until, 0)
	}
	if m.added != 0 {
		e.Added = time.Unix(m.added, 0)
	}
	return e
}

// Match returns the live entry containing addr, most specific prefix first.
func (s *Set) Match(addr netip.Addr, now time.Time) (Entry, bool) {
	addr = addr.Unmap()
	ts := now.Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if addr.Is4() {
		a := addr.As4()
		for _, b := range s.bits4 {
			k := mask4(a, b)
			if m, ok := s.v4[b][k]; ok && (m.until == 0 || ts < m.until) {
				return s.entry(netip.PrefixFrom(netip.AddrFrom4(k), int(b)), m), true
			}
		}
		return Entry{}, false
	}
	a := addr.As16()
	for _, b := range s.bits6 {
		k := mask16(a, b)
		if m, ok := s.v6[b][k]; ok && (m.until == 0 || ts < m.until) {
			return s.entry(netip.PrefixFrom(netip.AddrFrom16(k), int(b)), m), true
		}
	}
	return Entry{}, false
}

func mask4(a [4]byte, bits uint8) [4]byte {
	for i := 0; i < 4; i++ {
		switch {
		case bits >= 8:
			bits -= 8
		case bits == 0:
			a[i] = 0
		default:
			a[i] &= ^byte(0xff >> bits)
			bits = 0
		}
	}
	return a
}

func mask16(a [16]byte, bits uint8) [16]byte {
	for i := 0; i < 16; i++ {
		switch {
		case bits >= 8:
			bits -= 8
		case bits == 0:
			a[i] = 0
		default:
			a[i] &= ^byte(0xff >> bits)
			bits = 0
		}
	}
	return a
}

// Live returns non-expired entries, sorted (for small sets: listings and the kernel sync of manual bans).
func (s *Set) Live(now time.Time) []Entry {
	ts := now.Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, s.n)
	for b, t := range s.v4 {
		for k, m := range t {
			if m.until == 0 || ts < m.until {
				out = append(out, s.entry(netip.PrefixFrom(netip.AddrFrom4(k), int(b)), m))
			}
		}
	}
	for b, t := range s.v6 {
		for k, m := range t {
			if m.until == 0 || ts < m.until {
				out = append(out, s.entry(netip.PrefixFrom(netip.AddrFrom16(k), int(b)), m))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix.String() < out[j].Prefix.String() })
	return out
}

// Prune drops expired entries and reports how many were removed.
func (s *Set) Prune(now time.Time) int {
	ts := now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.v4 {
		for k, m := range t {
			if m.until != 0 && ts >= m.until {
				delete(t, k)
				n++
			}
		}
	}
	for _, t := range s.v6 {
		for k, m := range t {
			if m.until != 0 && ts >= m.until {
				delete(t, k)
				n++
			}
		}
	}
	s.n -= n
	return n
}

// Cloudflare's published edge ranges (https://www.cloudflare.com/ips/), used until a fresher copy is downloaded.
var CloudflareFallback = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// ReadPrefixes reads one IP/CIDR per line (# comments allowed).
func ReadPrefixes(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		if l == "" {
			continue
		}
		p, err := ParsePrefix(l)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", path, l, err)
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// never lists addresses that must not be blocked in the kernel (lock-out protection).
var never = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"}

// KernelSafe reports whether p may go into the nftables set (not private/loopback, not wider than /8 or /32 for v6).
func KernelSafe(p netip.Prefix) bool {
	for _, n := range never {
		np := netip.MustParsePrefix(n)
		if np.Overlaps(p) {
			return false
		}
	}
	return (p.Addr().Is4() && p.Bits() >= 8) || (p.Addr().Is6() && p.Bits() >= 32)
}
