package shield

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// One shield across replicas. Every replica decides on its own memory, so a decision never waits on the network; in
// the background, once per sync interval, each replica sends the others what changed here: bans, unbans and allow
// entries, and the requests counted against each rate limit and scoring window. The others add them in, so behind N
// replicas a limit of 60 a minute stays 60 (not 60 × N), a scan spread across pods escalates as if it hit one, and an
// IP banned by one pod is banned by all within a fraction of a second. A new replica first copies the bans of a running one.
//
// Every message is signed with a shared secret (HMAC-SHA256) over its time and body, and carries the sender's
// sequence number: a forged or replayed message — which could inflate a count and get a visitor banned — is refused.

// ClusterConfig: cluster: in shield.yaml.
type ClusterConfig struct {
	Listen     string   `yaml:"listen"`      // where replicas reach this one, e.g. ":9181" (keep it inside the cluster)
	Peers      []string `yaml:"peers"`       // host:port, or dns:NAME:PORT for every address of a name (a headless Service)
	SecretFile string   `yaml:"secret_file"` // the shared key; or MAKIT_CLUSTER_SECRET in the environment
	Sync       string   `yaml:"sync"`        // how often changes are sent (default 250ms)
}

func (c ClusterConfig) Enabled() bool { return c.Listen != "" && len(c.Peers) > 0 }

func (c ClusterConfig) secret() ([]byte, error) {
	s := os.Getenv("MAKIT_CLUSTER_SECRET")
	if s == "" && c.SecretFile != "" {
		b, err := os.ReadFile(c.SecretFile)
		if err != nil {
			return nil, err
		}
		s = string(b)
	}
	s = strings.TrimSpace(s)
	if len(s) < 32 {
		return nil, errors.New("cluster: a shared secret of at least 32 characters is required (MAKIT_CLUSTER_SECRET or cluster.secret_file; e.g. openssl rand -hex 32)")
	}
	return []byte(s), nil
}

func (c ClusterConfig) interval() time.Duration {
	if d, err := time.ParseDuration(c.Sync); err == nil && d >= 100*time.Millisecond {
		return d
	}
	// Between two syncs a replica does not see the others' requests: a limit can be exceeded by about
	// rate × interval. 250 ms keeps that small; the messages carry only what changed.
	return 250 * time.Millisecond
}

// ClusterOp is a change of the block or allow list.
type ClusterOp struct {
	Op    string `json:"op"` // ban, unban, allow, unallow
	Entry Entry  `json:"e"`
}

type clusterBatch struct {
	Node   string       `json:"node"`
	Seq    uint64       `json:"seq"`
	Ops    []ClusterOp  `json:"ops,omitempty"`
	Limits []LimitDelta `json:"limits,omitempty"`
	Scores []ScoreDelta `json:"scores,omitempty"`
}

type peerState struct {
	ops    []ClusterOp // not delivered yet: kept until the peer takes them (counts are not: they are only worth it now)
	lastOK time.Time
	err    string
}

type Cluster struct {
	g      *Gate
	cfg    ClusterConfig
	secret []byte
	node   string
	seq    atomic.Uint64
	client *http.Client

	mu       sync.Mutex
	ops      []ClusterOp
	peers    map[string]*peerState
	self     map[string]bool      // addresses that turned out to be this replica
	lastSeq  map[string]uint64    // per sending node: replays are refused
	seen     map[string]time.Time // when each node last reached this one
	known    map[string]Entry     // block/allow entries at the last state load, to see what the CLI changed
	remote   map[string]time.Time
	baseline bool
	pulled   bool // the bans of a running replica are copied (or there was none to copy from)
	recvd    atomic.Uint64
	refused  atomic.Uint64
}

const maxPeerOps = 200000

func NewCluster(g *Gate, cfg ClusterConfig) (*Cluster, error) {
	secret, err := cfg.secret()
	if err != nil {
		return nil, err
	}
	id := make([]byte, 6)
	_, _ = rand.Read(id)
	host, _ := os.Hostname()
	c := &Cluster{g: g, cfg: cfg, secret: secret, node: host + "-" + hex.EncodeToString(id),
		client: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 4}},
		peers:  map[string]*peerState{}, self: map[string]bool{}, lastSeq: map[string]uint64{}, seen: map[string]time.Time{}, known: map[string]Entry{},
		remote: map[string]time.Time{}}
	// Sequence numbers survive a restart without being stored: they start from the clock.
	c.seq.Store(uint64(time.Now().UnixNano()))
	return c, nil
}

func opKey(list string, e Entry) string { return list + "|" + e.Prefix.String() + "|" + e.Site }

// sign returns the signature of a message: HMAC-SHA256 over its time and body.
func (c *Cluster) sign(ts string, body []byte) string {
	m := hmac.New(sha256.New, c.secret)
	m.Write([]byte(ts))
	m.Write([]byte{'\n'})
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// verify checks a message's time (within 30 s) and signature.
func (c *Cluster) verify(ts, sig string, body []byte) error {
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("no time")
	}
	if d := time.Since(time.Unix(0, n)); d > 30*time.Second || d < -30*time.Second {
		return fmt.Errorf("time off by %s (are the clocks in sync?)", d.Round(time.Second))
	}
	want := c.sign(ts, body)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return errors.New("bad signature (is the shared secret the same everywhere?)")
	}
	return nil
}

// Ban, Unban, Allow, Unallow queue a local change for the other replicas.
func (c *Cluster) publish(op string, e Entry) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.ops = append(c.ops, ClusterOp{Op: op, Entry: e})
	list := "b"
	if op == "allow" || op == "unallow" {
		list = "a"
	}
	if op == "ban" || op == "allow" {
		c.known[opKey(list, e)] = e
	} else {
		delete(c.known, opKey(list, e))
	}
	c.mu.Unlock()
}

// StateLoaded compares the state the gate just loaded with the last one and publishes what the CLI changed on this
// replica (makit shield ban/unban/allow/unallow). The first load is the baseline.
func (c *Cluster) StateLoaded(st *State) {
	if c == nil || st == nil {
		return
	}
	now := time.Now()
	cur := map[string]Entry{}
	for _, e := range live(append([]Entry(nil), st.Block...), now) {
		cur[opKey("b", e)] = e
	}
	for _, e := range live(append([]Entry(nil), st.Allow...), now) {
		cur[opKey("a", e)] = e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, t := range c.remote {
		if now.Sub(t) > 10*time.Minute {
			delete(c.remote, k)
		}
	}
	if c.baseline {
		for k, e := range cur {
			// Additions: manual bans and allow entries (automatic bans were published when they happened); nothing
			// that came from another replica.
			if _, had := c.known[k]; had || c.remote[k] != (time.Time{}) || (k[0] == 'b' && e.Source != "manual") {
				continue
			}
			c.ops = append(c.ops, ClusterOp{Op: map[byte]string{'b': "ban", 'a': "allow"}[k[0]], Entry: e})
		}
		// Removals: anything this replica knew that is gone (a remote unban already took it out of known).
		for k, e := range c.known {
			if _, has := cur[k]; has || (!e.Until.IsZero() && e.Until.Before(now.Add(time.Second))) {
				continue
			}
			c.ops = append(c.ops, ClusterOp{Op: map[byte]string{'b': "unban", 'a': "unallow"}[k[0]], Entry: e})
		}
	}
	c.known, c.baseline = cur, true
}

// Run sends changes every sync interval and serves the other replicas until ctx ends.
func (c *Cluster) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.cfg.Listen)
	if err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/push", c.handlePush)
	mux.HandleFunc("/cluster/state", c.handleState)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	// Replicas start together: the others may not be in DNS yet. Look every 2 s until there are peers, then every
	// 15 s; copy a running replica's bans as soon as one answers.
	sync := time.NewTicker(c.cfg.interval())
	defer sync.Stop()
	resolveEvery, started := 2*time.Second, time.Now()
	next := time.Now()
	for {
		if !time.Now().Before(next) {
			c.resolve()
			if !c.pulled {
				c.pullState()
			}
			if len(c.Peers()) > 0 || time.Since(started) > 2*time.Minute {
				resolveEvery = 15 * time.Second
			}
			next = time.Now().Add(resolveEvery)
		}
		select {
		case <-ctx.Done():
			c.push() // the last changes, so a replica that stops does not take its bans with it
			return nil
		case <-sync.C:
			c.push()
		}
	}
}

// resolve finds the peers: static addresses, and every address a dns: name has now (pods come and go).
func (c *Cluster) resolve() {
	addrs := map[string]bool{}
	for _, p := range c.cfg.Peers {
		name, ok := strings.CutPrefix(p, "dns:")
		if !ok {
			addrs[p] = true
			continue
		}
		host, port, err := net.SplitHostPort(name)
		if err != nil {
			log.Printf("shield: cluster peer %q: want dns:NAME:PORT", p)
			continue
		}
		ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
		if err != nil {
			log.Printf("shield: cluster peers %s: %v", host, err)
			continue
		}
		for _, ip := range ips {
			addrs[net.JoinHostPort(ip, port)] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for a := range addrs {
		if !c.self[a] && c.peers[a] == nil {
			c.peers[a] = &peerState{}
		}
	}
	for a := range c.peers {
		if !addrs[a] {
			delete(c.peers, a) // a pod that is gone
		}
	}
}

func (c *Cluster) push() {
	p := c.g.policy.Load()
	b := clusterBatch{Node: c.node}
	if p != nil {
		if p.Limiter != nil {
			b.Limits = p.Limiter.TakeDeltas()
		}
		if p.Tracker != nil {
			b.Scores = append(b.Scores, p.Tracker.TakeDeltas("http")...)
		}
		if p.BotTracker != nil {
			b.Scores = append(b.Scores, p.BotTracker.TakeDeltas("bots")...)
		}
	}
	c.mu.Lock()
	ops := c.ops
	c.ops = nil
	targets := map[string][]ClusterOp{}
	for addr, ps := range c.peers {
		ps.ops = append(ps.ops, ops...)
		if len(ps.ops) > maxPeerOps {
			ps.ops = ps.ops[len(ps.ops)-maxPeerOps:]
		}
		// Every interval while there is something to say; otherwise a heartbeat every 10 s for the lag metric.
		if len(ps.ops) > 0 || len(b.Limits) > 0 || len(b.Scores) > 0 || time.Since(ps.lastOK) > 10*time.Second {
			targets[addr] = ps.ops
		}
	}
	c.mu.Unlock()
	var wg sync.WaitGroup
	for addr, pops := range targets {
		wg.Add(1)
		go func(addr string, pops []ClusterOp) {
			defer wg.Done()
			bb := b
			bb.Ops = pops
			bb.Seq = c.seq.Add(1)
			err := c.send(addr, bb)
			c.mu.Lock()
			defer c.mu.Unlock()
			ps := c.peers[addr]
			switch {
			case errors.Is(err, errSelf):
				c.self[addr] = true
				delete(c.peers, addr)
			case ps == nil:
			case err != nil:
				ps.err = err.Error()
			default:
				ps.lastOK, ps.err = time.Now(), ""
				ps.ops = ps.ops[min(len(pops), len(ps.ops)):]
			}
		}(addr, pops)
	}
	wg.Wait()
}

var errSelf = errors.New("this replica")

func (c *Cluster) send(addr string, b clusterBatch) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().UnixNano(), 10)
	req, err := http.NewRequest("POST", "http://"+addr+"/cluster/push", bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("X-Makit-Time", ts)
	req.Header.Set("X-Makit-Signature", c.sign(ts, buf.Bytes()))
	req.Header.Set("X-Makit-Node", c.node)
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	switch {
	case res.StatusCode == http.StatusConflict && strings.TrimSpace(string(msg)) == "self":
		return errSelf
	case res.StatusCode != http.StatusOK:
		return fmt.Errorf("%s: %s", res.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (c *Cluster) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Makit-Node") == c.node {
		http.Error(w, "self", http.StatusConflict)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	if err := c.verify(r.Header.Get("X-Makit-Time"), r.Header.Get("X-Makit-Signature"), body); err != nil {
		c.refused.Add(1)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		http.Error(w, "gzip", http.StatusBadRequest)
		return
	}
	var b clusterBatch
	if err := json.NewDecoder(io.LimitReader(zr, 512<<20)).Decode(&b); err != nil || b.Node == "" {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	if b.Seq <= c.lastSeq[b.Node] {
		c.mu.Unlock()
		c.refused.Add(1)
		http.Error(w, "replayed", http.StatusConflict)
		return
	}
	c.lastSeq[b.Node] = b.Seq
	c.seen[b.Node] = time.Now()
	c.mu.Unlock()
	c.apply(b)
	c.recvd.Add(1)
	w.WriteHeader(http.StatusOK)
}

// apply adds another replica's changes to this one: in memory at once, on disk with the next ban batch.
func (c *Cluster) apply(b clusterBatch) {
	p := c.g.policy.Load()
	if p == nil {
		return
	}
	now := time.Now()
	if p.Limiter != nil && len(b.Limits) > 0 {
		p.Limiter.Merge(b.Limits, now)
	}
	var httpD, botD []ScoreDelta
	for _, d := range b.Scores {
		if d.Set == "bots" {
			botD = append(botD, d)
		} else {
			httpD = append(httpD, d)
		}
	}
	if p.Tracker != nil && len(httpD) > 0 {
		p.Tracker.Merge(httpD)
	}
	if p.BotTracker != nil && len(botD) > 0 {
		p.BotTracker.Merge(botD)
	}
	if len(b.Ops) == 0 {
		return
	}
	c.mu.Lock()
	for _, op := range b.Ops {
		list := "b"
		if op.Op == "allow" || op.Op == "unallow" {
			list = "a"
		}
		k := opKey(list, op.Entry)
		c.remote[k] = now
		if op.Op == "ban" || op.Op == "allow" {
			c.known[k] = op.Entry
		} else {
			delete(c.known, k)
		}
	}
	c.mu.Unlock()
	c.g.applyRemote(b.Ops)
}

// handleState gives a new replica the live block and allow entries (signed, so it cannot be fed a forged list).
func (c *Cluster) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Makit-Node") == c.node {
		http.Error(w, "self", http.StatusConflict)
		return
	}
	if err := c.verify(r.Header.Get("X-Makit-Time"), r.Header.Get("X-Makit-Signature"), []byte("state")); err != nil {
		c.refused.Add(1)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	p := c.g.policy.Load()
	if p == nil {
		http.Error(w, "not loaded", http.StatusServiceUnavailable)
		return
	}
	now := time.Now()
	st := State{Block: p.Block.Live(now)}
	for _, s := range p.sites {
		if bs := p.SiteBlockSet(s.Site); bs != nil {
			for _, e := range bs.Live(now) {
				e.Site = s.Site
				st.Block = append(st.Block, e)
			}
		}
	}
	c.mu.Lock()
	for k, e := range c.known {
		if k[0] == 'a' {
			st.Allow = append(st.Allow, e)
		}
	}
	c.mu.Unlock()
	body, _ := json.Marshal(st)
	ts := strconv.FormatInt(time.Now().UnixNano(), 10)
	w.Header().Set("X-Makit-Time", ts)
	w.Header().Set("X-Makit-Signature", c.sign(ts, body))
	_, _ = w.Write(body)
}

// pullState copies the bans and allow entries of the first replica that answers.
func (c *Cluster) pullState() {
	c.mu.Lock()
	addrs := make([]string, 0, len(c.peers))
	for a := range c.peers {
		addrs = append(addrs, a)
	}
	c.mu.Unlock()
	sort.Strings(addrs)
	for _, addr := range addrs {
		ts := strconv.FormatInt(time.Now().UnixNano(), 10)
		req, _ := http.NewRequest("GET", "http://"+addr+"/cluster/state", nil)
		req.Header.Set("X-Makit-Time", ts)
		req.Header.Set("X-Makit-Signature", c.sign(ts, []byte("state")))
		req.Header.Set("X-Makit-Node", c.node)
		res, err := c.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 256<<20))
		res.Body.Close()
		if res.StatusCode != http.StatusOK || c.verify(res.Header.Get("X-Makit-Time"), res.Header.Get("X-Makit-Signature"), body) != nil {
			continue
		}
		var st State
		if json.Unmarshal(body, &st) != nil {
			continue
		}
		ops := make([]ClusterOp, 0, len(st.Block)+len(st.Allow))
		for _, e := range st.Block {
			ops = append(ops, ClusterOp{Op: "ban", Entry: e})
		}
		for _, e := range st.Allow {
			ops = append(ops, ClusterOp{Op: "allow", Entry: e})
		}
		c.apply(clusterBatch{Ops: ops})
		c.pulled = true
		log.Printf("shield: cluster: copied %d bans and %d allow entries from %s", len(st.Block), len(st.Allow), addr)
		return
	}
}

// Leader tells whether this replica does what only one should (push bans to AWS WAF): the one whose node name sorts
// first among itself and the replicas heard from in the last 30 s (every replica sends a heartbeat every 10 s).
func (c *Cluster) Leader() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, t := range c.seen {
		if time.Since(t) < 30*time.Second && n < c.node {
			return false
		}
	}
	return true
}

// PeerStatus is one peer for /metrics and makit shield status.
type PeerStatus struct {
	Addr    string
	LastOK  time.Time
	Err     string
	Pending int
}

func (c *Cluster) Peers() []PeerStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]PeerStatus, 0, len(c.peers))
	for a, ps := range c.peers {
		out = append(out, PeerStatus{Addr: a, LastOK: ps.lastOK, Err: ps.err, Pending: len(ps.ops)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// applyRemote applies list changes from another replica: in memory now, persisted with the next batch (no reload,
// no notification — the replica where it happened reports it).
func (g *Gate) applyRemote(ops []ClusterOp) {
	p := g.policy.Load()
	if p == nil {
		return
	}
	for _, op := range ops {
		e := op.Entry
		set := p.Block
		if op.Op == "allow" || op.Op == "unallow" {
			set = p.Allow
		}
		if e.Site != "" {
			if op.Op == "allow" || op.Op == "unallow" {
				set = nil // site allowlists come from the config, the same on every replica
				if sp := p.siteAllowSet(e.Site); sp != nil {
					set = sp
				}
			} else {
				set = p.SiteBlockSet(e.Site)
			}
		}
		if set == nil {
			continue
		}
		switch op.Op {
		case "ban", "allow":
			set.Add(e)
		case "unban", "unallow":
			set.Remove(e.Prefix)
		}
	}
	g.banMu.Lock()
	if len(g.remoteOps) < maxPeerOps {
		g.remoteOps = append(g.remoteOps, ops...)
	}
	g.banMu.Unlock()
}

// flushRemote persists list changes that came from other replicas, in one state write.
func (g *Gate) flushRemote() {
	g.banMu.Lock()
	ops := g.remoteOps
	g.remoteOps = nil
	g.banMu.Unlock()
	if len(ops) == 0 {
		return
	}
	_, err := withState(func(st *State) error {
		for _, op := range ops {
			switch op.Op {
			case "ban":
				st.Block = upsert(st.Block, op.Entry)
			case "unban":
				st.Block, _ = remove(st.Block, op.Entry.Prefix, op.Entry.Site)
			case "allow":
				st.Allow = upsert(st.Allow, op.Entry)
			case "unallow":
				st.Allow, _ = remove(st.Allow, op.Entry.Prefix, op.Entry.Site)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("shield: saving %d changes from other replicas: %v (they stay active until restart)", len(ops), err)
		return
	}
	if info, err := os.Stat(statePath()); err == nil {
		g.selfWrite.Store(info.ModTime().UnixNano())
	}
}
