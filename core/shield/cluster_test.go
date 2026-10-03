package shield

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef-test"

// Behind N replicas, limit 60/1m must stay 60 a minute: each replica adds the others' counts to its window.
func TestLimitAcrossReplicas(t *testing.T) {
	a, b := NewLimiter(), NewLimiter()
	a.Share()
	b.Share()
	act := Act{Kind: "limit", N: 60, Dur: time.Minute}
	now := time.Date(2026, 10, 3, 9, 0, 10, 0, time.UTC)
	for i := 0; i < 40; i++ {
		if !a.Allow("ip", act, now) {
			t.Fatal("40 of 60 must pass on replica a")
		}
	}
	b.Merge(a.TakeDeltas(), now)
	allowed := 0
	for i := 0; i < 40; i++ {
		if b.Allow("ip", act, now) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Errorf("replica b let %d through after a's 40; want 20", allowed)
	}
	// a hears b's 40 too: the next one is over.
	a.Merge(b.TakeDeltas(), now)
	if a.Allow("ip", act, now) {
		t.Error("a must count b's requests")
	}
	// A new window starts clean everywhere; counts for a window that is over are dropped.
	later := now.Add(time.Minute)
	b.Merge([]LimitDelta{{Key: "ip", Idx: now.UnixNano() / int64(time.Minute), Dur: time.Minute, N: 1000}}, later)
	if !b.Allow("ip", act, later) {
		t.Error("an old window's counts must not block the new one")
	}
	if d := a.TakeDeltas(); len(d) != 1 || d[0].N != 1 {
		t.Errorf("deltas are taken once: %+v", d)
	}
	if d := a.TakeDeltas(); len(d) != 0 {
		t.Errorf("and then empty: %+v", d)
	}
}

// A scan spread across replicas escalates as if it hit one.
func TestScoreAcrossReplicas(t *testing.T) {
	sc, err := LoadScoring([]string{repoCatalog}, "", ScoringOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if sc.Escalation.Every == 0 {
		t.Skip("the scoring set has no escalation")
	}
	a, b := NewTracker(sc, 100), NewTracker(sc, 100)
	a.Share()
	b.Share()
	ip := netip.MustParseAddr("203.0.113.9")
	at := time.Now()
	sus := max(sc.Escalation.MinScore, 1)
	// Half the suspicious requests on each replica: alone, neither reaches an escalation step it would reach together.
	n := sc.Escalation.Every
	for i := 0; i < n; i++ {
		a.Observe(ip, sus, nil, 404, at)
		b.Observe(ip, sus, nil, 404, at)
	}
	alone, _ := b.Observe(ip, 0, nil, 200, at)
	b.Merge(a.TakeDeltas("http"))
	together, _ := b.Observe(ip, 0, nil, 200, at)
	if together <= alone {
		t.Errorf("score with a's requests %d must exceed b's alone %d", together, alone)
	}
	// Merging does not echo: b's deltas hold only b's own requests.
	for _, d := range b.TakeDeltas("http") {
		if d.Count != n+2 {
			t.Errorf("b's own requests: %d, want %d", d.Count, n+2)
		}
	}
}

type replica struct {
	g    *Gate
	addr string
	stop context.CancelFunc
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func startReplicas(t *testing.T, addrs []string, which ...int) []*replica {
	t.Helper()
	t.Setenv("MAKIT_CLUSTER_SECRET", testSecret)
	var out []*replica
	for _, i := range which {
		g := gate(t)
		p := g.policy.Load()
		p.Limiter = NewLimiter()
		p.Ban = g.autoBan
		c, err := NewCluster(g, ClusterConfig{Listen: addrs[i], Peers: addrs, Sync: "100ms"})
		if err != nil {
			t.Fatal(err)
		}
		g.cluster = c
		p.Limiter.Share()
		c.StateLoaded(&State{})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = c.Run(ctx) }()
		t.Cleanup(cancel)
		out = append(out, &replica{g: g, addr: addrs[i], stop: cancel})
	}
	return out
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 60; i++ {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("not within 3 s: %s", what)
}

func TestClusterBansReachEveryReplica(t *testing.T) {
	StateDir = t.TempDir()
	addrs := []string{freeAddr(t), freeAddr(t), freeAddr(t)}
	rs := startReplicas(t, addrs, 0, 1)
	ip := netip.MustParseAddr("203.0.113.77")
	// An automatic ban on replica 0 (a probe) is enforced by replica 1.
	if d := rs[0].g.policy.Load().Decide(Request{Peer: ip.String(), URI: "/.env", Method: "GET", Headers: map[string]string{}}); d.Allow {
		t.Fatalf("probe: %+v", d)
	}
	eventually(t, "the ban reaches replica 1", func() bool {
		_, ok := rs[1].g.policy.Load().Block.Match(ip, time.Now())
		return ok
	})
	if d := rs[1].g.policy.Load().Decide(Request{Peer: ip.String(), URI: "/", Headers: map[string]string{}}); d.Allow {
		t.Errorf("replica 1 must block the IP banned on replica 0: %+v", d)
	}
	// A manual unban on replica 1 (the CLI changes state.json, the gate reloads it) reaches replica 0.
	rs[1].g.cluster.StateLoaded(&State{Block: nil})
	rs[1].g.policy.Load().Block.Remove(netip.PrefixFrom(ip, 32))
	eventually(t, "the unban reaches replica 0", func() bool {
		_, ok := rs[0].g.policy.Load().Block.Match(ip, time.Now())
		return !ok
	})
	// A manual allow entry on replica 0 reaches replica 1.
	office := Entry{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Source: "manual", Added: time.Now()}
	rs[0].g.cluster.StateLoaded(&State{Allow: []Entry{office}})
	eventually(t, "the allow entry reaches replica 1", func() bool {
		_, ok := rs[1].g.policy.Load().Allow.Match(netip.MustParseAddr("198.51.100.4"), time.Now())
		return ok
	})
	// A replica that starts later copies the bans of a running one.
	rs[0].g.autoBan(netip.MustParseAddr("203.0.113.88"), time.Hour, "rule:MK-HTTP-PROBE", "probe", "", false)
	late := startReplicas(t, addrs, 2)[0]
	eventually(t, "the new replica has the existing bans", func() bool {
		_, ok := late.g.policy.Load().Block.Match(netip.MustParseAddr("203.0.113.88"), time.Now())
		return ok
	})
	// Every replica finds itself among the peers and stops sending to itself.
	for _, r := range append(rs, late) {
		eventually(t, r.addr+" drops itself from its peers", func() bool {
			for _, p := range r.g.cluster.Peers() {
				if p.Addr == r.addr {
					return false
				}
			}
			return len(r.g.cluster.Peers()) == 2
		})
	}
}

func TestClusterRefusesForgedAndReplayed(t *testing.T) {
	StateDir = t.TempDir()
	addrs := []string{freeAddr(t)}
	r := startReplicas(t, addrs, 0)[0]
	ip := netip.MustParseAddr("192.0.2.200")
	batch := clusterBatch{Node: "attacker", Seq: 1, Ops: []ClusterOp{{Op: "ban", Entry: Entry{Prefix: netip.PrefixFrom(ip, 32)}}}}
	post := func(secret string, b clusterBatch, skew time.Duration) int {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_ = json.NewEncoder(zw).Encode(b)
		_ = zw.Close()
		c := &Cluster{secret: []byte(secret)}
		ts := strconv.FormatInt(time.Now().Add(skew).UnixNano(), 10)
		var res *http.Response
		var err error
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest("POST", "http://"+addrs[0]+"/cluster/push", bytes.NewReader(buf.Bytes()))
			req.Header.Set("X-Makit-Time", ts)
			req.Header.Set("X-Makit-Signature", c.sign(ts, buf.Bytes()))
			if res, err = http.DefaultClient.Do(req); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	banned := func() bool { _, ok := r.g.policy.Load().Block.Match(ip, time.Now()); return ok }
	if code := post("the-wrong-secret-0123456789abcdefghij", batch, 0); code != 401 || banned() {
		t.Errorf("a forged message must be refused: %d", code)
	}
	if code := post(testSecret, batch, -time.Minute); code != 401 || banned() {
		t.Errorf("an old message must be refused: %d", code)
	}
	if code := post(testSecret, batch, 0); code != 200 || !banned() {
		t.Errorf("a signed message is applied: %d", code)
	}
	r.g.policy.Load().Block.Remove(netip.PrefixFrom(ip, 32))
	if code := post(testSecret, batch, 0); code != 409 || banned() {
		t.Errorf("a replayed message must be refused: %d", code)
	}
}

func TestClusterNeedsASecret(t *testing.T) {
	t.Setenv("MAKIT_CLUSTER_SECRET", "short")
	if _, err := NewCluster(&Gate{}, ClusterConfig{Listen: ":0", Peers: []string{"x:1"}}); err == nil {
		t.Error("a short secret must be refused")
	}
}

func BenchmarkLimiterShared(b *testing.B) {
	for _, share := range []bool{false, true} {
		b.Run(map[bool]string{false: "single", true: "cluster"}[share], func(b *testing.B) {
			l := NewLimiter()
			if share {
				l.Share()
			}
			act := Act{Kind: "limit", N: 1 << 30, Dur: time.Minute}
			now := time.Now()
			keys := make([]string, 1024)
			for i := range keys {
				keys[i] = "|203.0.113." + strconv.Itoa(i)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				l.Allow(keys[i&1023], act, now)
			}
		})
	}
}

// The cost of a cluster on the request path: the same decisions with the limiter and trackers keeping deltas.
func BenchmarkDecideCluster(b *testing.B) {
	for _, shared := range []bool{false, true} {
		p := benchPolicy(b)
		if shared {
			p.Limiter.Share()
			p.Tracker.Share()
			p.BotTracker.Share()
		}
		b.Run(map[bool]string{false: "single", true: "cluster"}[shared], func(b *testing.B) {
			reqs := make([]Request, 4096)
			for i := range reqs {
				reqs[i] = browserReq(clientIP(i * 7919))
				if i%4 == 0 {
					reqs[i].URI = "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.Decide(reqs[i&4095])
				if shared && i&1023 == 0 { // the sync loop (every second, off the request path): not timed
					b.StopTimer()
					p.Limiter.TakeDeltas()
					p.Tracker.TakeDeltas("http")
					p.BotTracker.TakeDeltas("bots")
					b.StartTimer()
				}
			}
		})
	}
}

// How long a ban made on one replica takes to be enforced by the two others (localhost): reported as ms/ban and the
// worst; the run waits for every replica each time. Bans do not wait for the 250 ms sync: they are sent at once.
func BenchmarkClusterBanPropagation(b *testing.B) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	StateDir = b.TempDir()
	b.Setenv("MAKIT_CLUSTER_SECRET", testSecret)
	addrs := []string{freeAddrB(b), freeAddrB(b), freeAddrB(b)}
	var gs []*Gate
	for i := range addrs {
		g := &Gate{stats: map[string]int64{}}
		g.policy.Store(&Policy{Allow: NewSet(), Block: NewSet(), Limiter: NewLimiter()})
		c, err := NewCluster(g, ClusterConfig{Listen: addrs[i], Peers: addrs, Sync: "250ms"})
		if err != nil {
			b.Fatal(err)
		}
		g.cluster = c
		c.StateLoaded(&State{})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = c.Run(ctx) }()
		b.Cleanup(cancel)
		gs = append(gs, g)
	}
	time.Sleep(time.Second) // the replicas find each other
	var worst time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer() // a ban on its own: past the 20 ms batching gap of the one before
		time.Sleep(25 * time.Millisecond)
		b.StartTimer()
		ip := netip.AddrFrom4([4]byte{203, 0, byte(113 + i/250), byte(i % 250)})
		start := time.Now()
		gs[0].autoBan(ip, time.Hour, "rule:MK-HTTP-PROBE", "probe", "", false)
		for _, g := range gs[1:] {
			for {
				if _, ok := g.policy.Load().Block.Match(ip, time.Now()); ok {
					break
				}
				time.Sleep(time.Millisecond)
			}
		}
		worst = max(worst, time.Since(start))
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Milliseconds())/float64(b.N), "ms/ban")
	b.ReportMetric(float64(worst.Milliseconds()), "ms-worst")
}

func freeAddrB(b *testing.B) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}
