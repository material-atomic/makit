package shield

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PROXY protocol in (v1 text and v2 binary): a TCP load balancer such as an AWS NLB, or HAProxy, puts the visitor's
// address in front of the connection, so makit sees the visitor without TLS ending at the load balancer. The header is
// read only from trusted proxies (trusted_proxies): from anyone else the bytes are passed on untouched, so a visitor
// who sends its own "PROXY TCP4 <any address>" gets a broken request, never a new address. A trusted peer that sends
// no header (a plain TCP health check) is passed on as it is.

// proxyHeaderTimeout bounds how long a trusted peer may take to send its header; reading happens off the accept loop.
var proxyHeaderTimeout = 5 * time.Second

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

type proxyListener struct {
	net.Listener
	g       *Gate
	name    string
	timeout time.Duration
	conns   chan net.Conn
	errc    chan error
	done    chan struct{}
	closer  sync.Once
}

func newProxyListener(ln net.Listener, g *Gate, name string) *proxyListener {
	l := &proxyListener{Listener: ln, g: g, name: name, timeout: proxyHeaderTimeout, conns: make(chan net.Conn),
		errc: make(chan error, 1), done: make(chan struct{})}
	go l.loop()
	return l
}

func (l *proxyListener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.errc <- err:
			case <-l.done:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		go l.handshake(c)
	}
}

func (l *proxyListener) handshake(c net.Conn) {
	pc, err := l.readHeader(c)
	if err != nil {
		l.g.count("proxy-protocol-error")
		log.Printf("shield: %s: PROXY header from %s: %v", l.name, c.RemoteAddr(), err)
		c.Close()
		return
	}
	select {
	case l.conns <- pc:
	case <-l.done:
		c.Close()
	}
}

// readHeader returns the connection with the visitor as its RemoteAddr when a trusted peer sent a header.
func (l *proxyListener) readHeader(c net.Conn) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return c, nil
	}
	if p := l.g.policy.Load(); p == nil || !p.trusted(ap.Addr().Unmap()) {
		return c, nil
	}
	_ = c.SetReadDeadline(time.Now().Add(l.timeout))
	defer c.SetReadDeadline(time.Time{})
	br := bufio.NewReaderSize(c, 512)
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	pc := &proxyConn{Conn: c, br: br}
	switch first[0] {
	case 'P':
		err = pc.readV1()
	case '\r':
		err = pc.readV2()
	default:
		return pc, nil // no header: a health check or a client of a proxy that does not send one
	}
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// proxyConn reads what is left in the header buffer first, then straight from the connection.
type proxyConn struct {
	net.Conn
	br     *bufio.Reader
	remote net.Addr
	local  net.Addr
}

func (c *proxyConn) Read(b []byte) (int, error) {
	if c.br != nil {
		if c.br.Buffered() > 0 {
			return c.br.Read(b)
		}
		c.br = nil
	}
	return c.Conn.Read(b)
}

func (c *proxyConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

func (c *proxyConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}

// readV1: "PROXY TCP4 198.51.100.9 10.0.0.5 51234 443\r\n" (at most 107 bytes) or "PROXY UNKNOWN…\r\n".
func (c *proxyConn) readV1() error {
	var line []byte
	for len(line) < 108 {
		b, err := c.br.ReadByte()
		if err != nil {
			return err
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
	}
	s, ok := strings.CutSuffix(string(line), "\r\n")
	if !ok || !strings.HasPrefix(s, "PROXY ") {
		return fmt.Errorf("not a PROXY v1 line")
	}
	f := strings.Fields(s)
	if len(f) >= 2 && f[1] == "UNKNOWN" {
		return nil // the proxy does not know the source: keep the connection's own addresses
	}
	if len(f) != 6 || (f[1] != "TCP4" && f[1] != "TCP6") {
		return fmt.Errorf("malformed PROXY v1 line %q", s)
	}
	src, err1 := netip.ParseAddr(f[2])
	dst, err2 := netip.ParseAddr(f[3])
	sp, err3 := strconv.ParseUint(f[4], 10, 16)
	dp, err4 := strconv.ParseUint(f[5], 10, 16)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return fmt.Errorf("malformed PROXY v1 line %q: %w", s, err)
	}
	if (f[1] == "TCP4") != src.Is4() {
		return fmt.Errorf("PROXY v1 %s with address %s", f[1], src)
	}
	c.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, uint16(sp)))
	c.local = net.TCPAddrFromAddrPort(netip.AddrPortFrom(dst, uint16(dp)))
	return nil
}

// readV2: 12-byte signature, version/command, family/protocol, 2-byte length, addresses, then TLVs (skipped, e.g.
// the AWS VPC endpoint id).
func (c *proxyConn) readV2() error {
	hdr, err := c.br.Peek(16)
	if err != nil {
		return err
	}
	if !bytes.Equal(hdr[:12], proxyV2Sig) {
		return fmt.Errorf("not a PROXY v2 signature")
	}
	if hdr[12]>>4 != 2 {
		return fmt.Errorf("PROXY v2 version %d", hdr[12]>>4)
	}
	cmd, fam := hdr[12]&0x0f, hdr[13]
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n > 4096 {
		return fmt.Errorf("PROXY v2 header of %d bytes", n)
	}
	body := make([]byte, 16+n)
	if _, err := ioReadFull(c.br, body); err != nil {
		return err
	}
	body = body[16:]
	if cmd == 0 { // LOCAL: the proxy's own connection (health checks)
		return nil
	}
	if cmd != 1 {
		return fmt.Errorf("PROXY v2 command %d", cmd)
	}
	switch fam {
	case 0x11: // TCP over IPv4
		if len(body) < 12 {
			return fmt.Errorf("short PROXY v2 IPv4 block")
		}
		src, dst := netip.AddrFrom4([4]byte(body[0:4])), netip.AddrFrom4([4]byte(body[4:8]))
		c.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[8:10])))
		c.local = net.TCPAddrFromAddrPort(netip.AddrPortFrom(dst, binary.BigEndian.Uint16(body[10:12])))
	case 0x21: // TCP over IPv6
		if len(body) < 36 {
			return fmt.Errorf("short PROXY v2 IPv6 block")
		}
		src, dst := netip.AddrFrom16([16]byte(body[0:16])).Unmap(), netip.AddrFrom16([16]byte(body[16:32])).Unmap()
		c.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[32:34])))
		c.local = net.TCPAddrFromAddrPort(netip.AddrPortFrom(dst, binary.BigEndian.Uint16(body[34:36])))
	case 0x00: // UNSPEC: keep the connection's own addresses
	default:
		return fmt.Errorf("PROXY v2 family/protocol 0x%02x is not TCP", fam)
	}
	return nil
}

func ioReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (l *proxyListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errc:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *proxyListener) Close() error {
	l.closer.Do(func() { close(l.done) })
	return l.Listener.Close()
}
