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

// Set is a set of addresses and prefixes, with optional expiry — what ipset does, in memory.
type Set struct {
	mu      sync.RWMutex
	entries map[netip.Prefix]Entry
}

type Entry struct {
	Prefix netip.Prefix `json:"prefix"`
	Until  time.Time    `json:"until,omitempty"` // zero = permanent
	Reason string       `json:"reason,omitempty"`
	Source string       `json:"source,omitempty"` // manual, rule:<id>, feed:<name>
	Added  time.Time    `json:"added"`
}

func NewSet() *Set { return &Set{entries: map[netip.Prefix]Entry{}} }

// ParsePrefix accepts an IP or CIDR (IPv4/IPv6) and normalises it.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
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

func (s *Set) Add(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Added.IsZero() {
		e.Added = time.Now()
	}
	s.entries[e.Prefix] = e
}

func (s *Set) Remove(p netip.Prefix) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[p]
	delete(s.entries, p)
	return ok
}

// Match returns the live entry containing addr (most specific first).
func (s *Set) Match(addr netip.Addr, now time.Time) (Entry, bool) {
	addr = addr.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	best, found := Entry{}, false
	for p, e := range s.entries {
		if !e.Until.IsZero() && now.After(e.Until) {
			continue
		}
		if p.Contains(addr) && (!found || p.Bits() > best.Prefix.Bits()) {
			best, found = e, true
		}
	}
	return best, found
}

// Live returns non-expired entries, sorted.
func (s *Set) Live(now time.Time) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.Until.IsZero() || now.Before(e.Until) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix.String() < out[j].Prefix.String() })
	return out
}

// Prune drops expired entries and reports how many were removed.
func (s *Set) Prune(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for p, e := range s.entries {
		if !e.Until.IsZero() && now.After(e.Until) {
			delete(s.entries, p)
			n++
		}
	}
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
