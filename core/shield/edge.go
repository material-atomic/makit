package shield

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Gate holds the live policy; reloads swap it atomically.
type Gate struct {
	policy atomic.Pointer[Policy]
	ask    atomic.Bool // /check enforces; off = always allow
	rec    *Recorder
	header string
	notify func(text string) // set when notifications are configured

	mu    sync.Mutex
	stats map[string]int64 // verdict → count since start
}

func (g *Gate) count(v string) {
	g.mu.Lock()
	g.stats[v]++
	g.mu.Unlock()
}

func (g *Gate) Stats() map[string]int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int64, len(g.stats))
	for k, v := range g.stats {
		out[k] = v
	}
	return out
}

// guardListener closes connections from blocked direct peers right after accept (before TLS or HTTP).
type guardListener struct {
	net.Listener
	g    *Gate
	name string
}

func (l *guardListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		p := l.g.policy.Load()
		ap, perr := netip.ParseAddrPort(c.RemoteAddr().String())
		if perr != nil || p.Pass || p.Observe || p.trusted(ap.Addr().Unmap()) {
			return c, nil // trusted proxies (Cloudflare) are judged per request, on the real client IP
		}
		addr := ap.Addr().Unmap()
		if _, ok := p.Allow.Match(addr, time.Now()); ok {
			return c, nil
		}
		e, ok := p.Block.Match(addr, time.Now())
		if !ok && p.Lists != nil {
			e, ok = p.Lists.Match(addr, time.Now())
		}
		if ok {
			l.g.count("dropped")
			l.g.rec.Write(Snapshot{Time: time.Now(), Listener: l.name, Decision: Decision{Client: addr.String(), Peer: addr.String(),
				Verdict: "dropped", Rule: e.Source, Reason: "connection closed: " + e.Prefix.String() + " " + e.Reason}})
			c.Close()
			continue
		}
		return c, nil
	}
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

const blockedPage = "<!doctype html><title>403 Forbidden</title><p>Forbidden.</p>\n"

// httpHandler decides on every request, then forwards it to the upstream with the real client IP.
func (g *Gate) httpHandler(l Listener) (http.Handler, error) {
	u, err := url.Parse(l.Upstream)
	if err != nil {
		return nil, err
	}
	// Rewrite (not Director): the outgoing request starts without X-Forwarded-* headers, so nothing a client sent
	// survives; makit sets them from its own decision.
	rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(u)
		pr.Out.Host = pr.In.Host // upstream virtual hosts keep working
		in := pr.In.Header
		pr.Out.Header.Set("X-Forwarded-For", in.Get("X-Makit-Client"))
		pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		pr.Out.Header.Set("X-Forwarded-Proto", in.Get("X-Makit-Proto"))
		pr.Out.Header.Del("X-Makit-Proto")
	}}
	if l.InsecureUpstreamTLS {
		rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("shield: %s upstream %s: %v", l.Name, l.Upstream, err)
		w.WriteHeader(http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		hdr := map[string]string{}
		for k, v := range r.Header {
			if lk := strings.ToLower(k); lk != "cookie" && lk != "authorization" && lk != "proxy-authorization" {
				hdr[lk] = strings.Join(v, ", ")
			}
		}
		q := Request{Peer: r.RemoteAddr, Client: r.Header.Get(g.header), Method: r.Method, Host: r.Host, URI: r.RequestURI,
			UA: r.UserAgent(), Referer: r.Referer(), Country: r.Header.Get("CF-IPCountry"), Ray: r.Header.Get("CF-Ray"),
			Headers: hdr, Received: start}
		d := g.policy.Load().Decide(q)
		g.count(d.Verdict)
		snap := Snapshot{Time: start, Listener: l.Name, Decision: d, Method: q.Method, Host: q.Host, URI: q.URI, UA: q.UA,
			Referer: q.Referer, Country: q.Country, Ray: q.Ray}
		if !d.Allow {
			snap.Status = http.StatusForbidden
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, blockedPage)
			g.rec.Write(snap)
			return
		}
		// What the service behind sees: the resolved client IP, never a header a direct client tried to spoof.
		r.Header.Set("X-Real-IP", d.Client)
		r.Header.Set("X-Makit-Client", d.Client)
		proto := "http"
		if r.TLS != nil || (d.Via != "" && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
			proto = "https" // TLS here, or Cloudflare saying the visitor used HTTPS
		}
		r.Header.Set("X-Makit-Proto", proto)
		sw := &statusWriter{ResponseWriter: w, code: 200}
		rp.ServeHTTP(sw, r)
		snap.Status, snap.Ms = sw.code, time.Since(start).Milliseconds()
		g.rec.Write(snap)
	}), nil
}

// tcpProxy forwards raw TCP (after the accept-time IP check), optionally with a PROXY v1 header.
func (g *Gate) tcpProxy(ln net.Listener, l Listener) {
	target := strings.TrimPrefix(l.Upstream, "tcp://")
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			up, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			if l.ProxyProtocol {
				src, _ := netip.ParseAddrPort(c.RemoteAddr().String())
				dst, _ := netip.ParseAddrPort(c.LocalAddr().String())
				fam := "TCP4"
				if src.Addr().Unmap().Is6() {
					fam = "TCP6"
				}
				fmt.Fprintf(up, "PROXY %s %s %s %d %d\r\n", fam, src.Addr().Unmap(), dst.Addr().Unmap(), src.Port(), dst.Port())
			}
			g.count("tcp")
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
			go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
			<-done
		}(c)
	}
}

// Serve starts every listener and blocks until ctx is cancelled.
func (g *Gate) Serve(ctx context.Context, ls []Listener) error {
	var servers []*http.Server
	errc := make(chan error, len(ls))
	for _, l := range ls {
		raw, err := net.Listen("tcp", l.Listen)
		if err != nil {
			return fmt.Errorf("%s: %w", l.Name, err)
		}
		ln := net.Listener(&guardListener{Listener: raw, g: g, name: l.Name})
		if strings.HasPrefix(l.Upstream, "tcp://") {
			go g.tcpProxy(ln, l)
			go func() { <-ctx.Done(); ln.Close() }()
			continue
		}
		h, err := g.httpHandler(l)
		if err != nil {
			return err
		}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second,
			ErrorLog: log.New(io.Discard, "", 0)}
		if l.TLS != nil {
			cfg, err := tlsConfig(l)
			if err != nil {
				return fmt.Errorf("%s: %w", l.Name, err)
			}
			srv.TLSConfig = cfg
			ln = tls.NewListener(ln, cfg)
		}
		servers = append(servers, srv)
		go func(srv *http.Server, ln net.Listener) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(srv, ln)
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sh)
	}
	return nil
}

func tlsConfig(l Listener) (*tls.Config, error) {
	t := l.TLS
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	switch {
	case t.Cert != "" && t.Key != "":
		pair, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	case len(t.ACME) > 0:
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(t.ACME...),
			Cache: autocert.DirCache(StateDir + "/acme"), Email: t.Email}
		cfg.GetCertificate = m.GetCertificate
		cfg.NextProtos = append(cfg.NextProtos, "acme-tls/1") // TLS-ALPN-01: no port 80 needed
	default:
		return nil, errors.New("tls needs cert+key or acme domains")
	}
	return cfg, nil
}
