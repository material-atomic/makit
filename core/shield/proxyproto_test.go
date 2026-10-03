package shield

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func v2Header(cmd byte, src, dst netip.AddrPort, tlv []byte) []byte {
	b := append([]byte{}, proxyV2Sig...)
	fam, addrs := byte(0x11), []byte{}
	if src.Addr().Is6() {
		fam = 0x21
		s, d := src.Addr().As16(), dst.Addr().As16()
		addrs = append(append(addrs, s[:]...), d[:]...)
	} else {
		s, d := src.Addr().As4(), dst.Addr().As4()
		addrs = append(append(addrs, s[:]...), d[:]...)
	}
	addrs = binary.BigEndian.AppendUint16(addrs, src.Port())
	addrs = binary.BigEndian.AppendUint16(addrs, dst.Port())
	addrs = append(addrs, tlv...)
	b = append(b, 0x20|cmd, fam)
	b = binary.BigEndian.AppendUint16(b, uint16(len(addrs)))
	return append(b, addrs...)
}

// proxyServer listens on 127.0.0.1 behind a proxy listener; trustLoopback decides whether 127.0.0.1 is a trusted proxy.
func proxyServer(t *testing.T, trustLoopback bool) (*proxyListener, string) {
	t.Helper()
	g := gate(t)
	if trustLoopback {
		p := g.policy.Load()
		p.Trusted = append(p.Trusted, netip.MustParsePrefix("127.0.0.0/8"))
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newProxyListener(raw, g, "test")
	t.Cleanup(func() { l.Close() })
	return l, raw.Addr().String()
}

// send dials addr, writes data and returns what the accepting side sees: the remote address and the first line.
func send(t *testing.T, l *proxyListener, addr string, data []byte) (string, string, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	type res struct {
		remote, line string
		err          error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := l.Accept()
		if err != nil {
			ch <- res{err: err}
			return
		}
		defer s.Close()
		line, err := bufio.NewReader(s).ReadString('\n')
		ch <- res{s.RemoteAddr().String(), line, err}
	}()
	select {
	case r := <-ch:
		return r.remote, r.line, r.err
	case <-time.After(2 * time.Second):
		return "", "", context.DeadlineExceeded
	}
}

func TestProxyProtocolFromTrustedProxy(t *testing.T) {
	l, addr := proxyServer(t, true)
	src, dst := netip.MustParseAddrPort("198.51.100.9:51234"), netip.MustParseAddrPort("10.0.0.5:443")
	cases := []struct {
		name   string
		data   []byte
		remote string
	}{
		{"v1 TCP4", []byte("PROXY TCP4 198.51.100.9 10.0.0.5 51234 443\r\nhello\n"), "198.51.100.9:51234"},
		{"v1 TCP6", []byte("PROXY TCP6 2001:db8::9 2001:db8::5 51234 443\r\nhello\n"), "[2001:db8::9]:51234"},
		{"v2 TCP4", append(v2Header(1, src, dst, nil), "hello\n"...), "198.51.100.9:51234"},
		{"v2 TCP4 with an AWS VPC endpoint TLV", append(v2Header(1, src, dst, []byte{0xEA, 0, 5, 1, 'v', 'p', 'c', 'e'}), "hello\n"...),
			"198.51.100.9:51234"},
		{"v2 TCP6", append(v2Header(1, netip.MustParseAddrPort("[2001:db8::9]:40000"), netip.MustParseAddrPort("[2001:db8::5]:443"), nil),
			"hello\n"...), "[2001:db8::9]:40000"},
	}
	for _, c := range cases {
		remote, line, err := send(t, l, addr, c.data)
		if err != nil || remote != c.remote || line != "hello\n" {
			t.Errorf("%s: remote %q line %q err %v, want %q", c.name, remote, line, err, c.remote)
		}
	}
	// LOCAL (health check) and a peer sending no header keep the connection's own address.
	for name, data := range map[string][]byte{"v2 LOCAL": append(v2Header(0, src, dst, nil), "hello\n"...), "no header": []byte("hello\n")} {
		remote, line, err := send(t, l, addr, data)
		if err != nil || !strings.HasPrefix(remote, "127.0.0.1:") || line != "hello\n" {
			t.Errorf("%s: remote %q line %q err %v", name, remote, line, err)
		}
	}
}

// From a peer that is not a trusted proxy, a PROXY line is just bytes: it never becomes an address.
func TestProxyProtocolFromVisitorIsNotBelieved(t *testing.T) {
	l, addr := proxyServer(t, false)
	remote, line, err := send(t, l, addr, []byte("PROXY TCP4 192.0.2.10 10.0.0.5 1 443\r\n"))
	if err != nil || !strings.HasPrefix(remote, "127.0.0.1:") || !strings.HasPrefix(line, "PROXY TCP4 192.0.2.10") {
		t.Errorf("remote %q line %q err %v", remote, line, err)
	}
}

func TestProxyProtocolMalformedIsDropped(t *testing.T) {
	l, addr := proxyServer(t, true)
	cases := map[string][]byte{
		"v1 garbage":      []byte("PROXY TCP4 nope\r\nhello\n"),
		"v1 family mixup": []byte("PROXY TCP4 2001:db8::1 10.0.0.5 1 2\r\nhello\n"),
		"v1 no CRLF":      []byte(strings.Repeat("P", 200) + "\n"),
		"v2 UDP": append(func() []byte {
			h := v2Header(1, netip.MustParseAddrPort("1.2.3.4:1"), netip.MustParseAddrPort("5.6.7.8:2"), nil)
			h[13] = 0x12
			return h
		}(), "x\n"...),
	}
	for _, data := range cases {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(data)
		// The listener closes the connection: the read ends without any data echoed or accepted.
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, _ := c.Read(make([]byte, 1)); n != 0 {
			t.Errorf("malformed header got data back")
		}
		c.Close()
	}
	if n := l.g.Stats()["proxy-protocol-error"]; n != int64(len(cases)) {
		t.Errorf("malformed headers dropped: %d, want %d", n, len(cases))
	}
	// Then a good header is accepted as usual.
	if remote, line, err := send(t, l, addr, []byte("PROXY TCP4 198.51.100.7 10.0.0.5 1 443\r\nhello\n")); err != nil ||
		remote != "198.51.100.7:1" || line != "hello\n" {
		t.Errorf("after malformed headers: %q %q %v", remote, line, err)
	}
}

// A trusted peer that starts a header and stalls is cut off after the timeout, without blocking other clients.
func TestProxyProtocolStallDoesNotBlock(t *testing.T) {
	old := proxyHeaderTimeout
	proxyHeaderTimeout = 200 * time.Millisecond
	l, addr := proxyServer(t, true)
	proxyHeaderTimeout = old
	stall, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer stall.Close()
	_, _ = stall.Write([]byte("PROXY TCP4 "))
	if remote, line, err := send(t, l, addr, []byte("PROXY TCP4 198.51.100.7 10.0.0.5 1 443\r\nhello\n")); err != nil ||
		remote != "198.51.100.7:1" || line != "hello\n" {
		t.Errorf("a stalled header must not block the next client: %q %q %v", remote, line, err)
	}
	_ = stall.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := stall.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Errorf("stalled connection must be closed after the timeout: %d %v", n, err)
	}
}

// End to end: an NLB (trusted) sends PROXY v2 to an edge listener; the visitor's ban applies at accept, and an allowed
// visitor reaches the upstream as itself.
func TestEdgeBehindNLB(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Forwarded-For"))
	}))
	defer up.Close()
	g := gate(t)
	p := g.policy.Load()
	p.Trusted = append(p.Trusted, netip.MustParsePrefix("127.0.0.0/8"))
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := probe.Addr().String()
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = g.Serve(ctx, []Listener{{Name: "nlb", Listen: addr, Upstream: up.URL, AcceptProxyProtocol: true}})
	}()
	request := func(client string) (string, error) {
		var c net.Conn
		var err error
		for i := 0; i < 50; i++ {
			if c, err = net.Dial("tcp", addr); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(v2Header(1, netip.MustParseAddrPort(client), netip.MustParseAddrPort("10.0.0.5:80"), nil))
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n")
		b, err := io.ReadAll(c)
		return string(b), err
	}
	if b, _ := request("198.51.100.10:40000"); !strings.HasSuffix(b, "198.51.100.10") {
		t.Errorf("allowed visitor must reach the upstream as itself: %q", b)
	}
	if b, _ := request("198.51.100.9:40000"); b != "" {
		t.Errorf("banned visitor must be dropped at accept: %q", b)
	}
}
