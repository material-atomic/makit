package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPlanWAF(t *testing.T) {
	now := time.Now()
	e := func(p string, added time.Duration, site string, until time.Duration) Entry {
		x := Entry{Prefix: netip.MustParsePrefix(p), Added: now.Add(-added), Site: site}
		if until != 0 {
			x.Until = now.Add(until)
		}
		return x
	}
	bans := []Entry{
		e("203.0.113.9/32", time.Minute, "", time.Hour),
		e("203.0.113.9/32", time.Minute, "", time.Hour), // twice: once in the plan
		e("198.51.100.0/24", time.Hour, "", 0),
		e("2001:db8::7/128", time.Minute, "", 0),
		e("192.0.2.10/32", time.Minute, "", 0),            // allowlisted
		e("10.0.1.5/32", time.Minute, "", 0),              // the load balancer (trusted)
		e("203.0.113.50/32", time.Minute, "shop", 0),      // one site only
		e("128.0.0.0/4", time.Minute, "", 0),              // too wide
		e("203.0.113.66/32", time.Hour, "", -time.Minute), // expired
	}
	allow := []Entry{{Prefix: netip.MustParsePrefix("192.0.2.0/28")}}
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	pl := planWAF(bans, allow, trusted, now, 10000)
	if strings.Join(pl.V4, " ") != "198.51.100.0/24 203.0.113.9/32" || strings.Join(pl.V6, " ") != "2001:db8::7/128" {
		t.Errorf("plan: %+v", pl)
	}
	if pl.Allowed != 1 || pl.Trusted != 1 || pl.Site != 1 || pl.TooWide != 1 {
		t.Errorf("left out: %+v", pl)
	}
	// Over the limit, the newest bans win.
	pl = planWAF(bans[:3], nil, nil, now, 1)
	if strings.Join(pl.V4, " ") != "203.0.113.9/32" || pl.OverMax != 1 {
		t.Errorf("over the limit: %+v", pl)
	}
}

// fakeWAF answers GetIPSet and UpdateIPSet the way the AWS WAFv2 API does (JSON 1.1), with lock tokens.
type fakeWAF struct {
	mu        sync.Mutex
	addrs     map[string][]string
	token     int
	updates   int
	lockFails int // UpdateIPSet answers WAFOptimisticLockException this many times first
	srv       *httptest.Server
}

func newFakeWAF(t *testing.T) *fakeWAF {
	f := &fakeWAF{addrs: map[string][]string{"v4id": {"192.0.2.99/32"}, "v6id": {}}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in struct {
			Id, LockToken, Scope string
			Addresses            []string
		}
		_ = json.Unmarshal(body, &in)
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if in.Scope != "REGIONAL" {
			http.Error(w, "scope", 400)
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AWSWAF_20190729.GetIPSet":
			_ = json.NewEncoder(w).Encode(map[string]any{"LockToken": fmt.Sprint(f.token),
				"IPSet": map[string]any{"Id": in.Id, "Name": in.Id, "ARN": "arn:x", "IPAddressVersion": "IPV4", "Addresses": f.addrs[in.Id]}})
		case "AWSWAF_20190729.UpdateIPSet":
			if f.lockFails > 0 || in.LockToken != fmt.Sprint(f.token) {
				f.lockFails--
				f.token++ // someone else wrote in between
				w.Header().Set("X-Amzn-ErrorType", "WAFOptimisticLockException")
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"__type":"WAFOptimisticLockException","Message":"changed"}`)
				return
			}
			f.addrs[in.Id] = in.Addresses
			f.token++
			f.updates++
			_ = json.NewEncoder(w).Encode(map[string]any{"NextLockToken": fmt.Sprint(f.token)})
		default:
			http.Error(w, "unknown "+r.Header.Get("X-Amz-Target"), 400)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func wafTestSync(t *testing.T, f *fakeWAF) *WAFSync {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	w, err := NewWAFSync(context.Background(), AWSWAFConfig{Region: "us-east-2", IPv4: AWSWAFIPSet{Name: "v4id", ID: "v4id"},
		IPv6: AWSWAFIPSet{Name: "v6id", ID: "v6id"}, Endpoint: f.srv.URL, timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWAFSync(t *testing.T) {
	f := newFakeWAF(t)
	w := wafTestSync(t, f)
	ctx := context.Background()
	pl := WAFPlan{V4: []string{"198.51.100.0/24", "203.0.113.9/32"}, V6: []string{"2001:db8::7/128"}}
	// --dry-run: says the sets differ, writes nothing.
	if st, err := w.Sync(ctx, pl, true); err != nil || !st.Changed || f.updates != 0 {
		t.Fatalf("dry run: %+v %v updates=%d", st, err, f.updates)
	}
	// A real sync replaces what is there (192.0.2.99 is no longer banned) and survives a concurrent writer.
	f.lockFails = 1
	if st, err := w.Sync(ctx, pl, false); err != nil || !st.Changed {
		t.Fatalf("sync: %+v %v", st, err)
	}
	got := append([]string(nil), f.addrs["v4id"]...)
	sort.Strings(got)
	if strings.Join(got, " ") != "198.51.100.0/24 203.0.113.9/32" || strings.Join(f.addrs["v6id"], " ") != "2001:db8::7/128" {
		t.Errorf("IP sets: %v %v", f.addrs["v4id"], f.addrs["v6id"])
	}
	// Nothing changed: nothing is written.
	before := f.updates
	if st, err := w.Sync(ctx, pl, false); err != nil || st.Changed || f.updates != before {
		t.Errorf("unchanged sync wrote: %+v %v %d→%d", st, err, before, f.updates)
	}
	if w.Status() == nil || w.Status().V4 != 2 {
		t.Errorf("status: %+v", w.Status())
	}
}

func TestConfigCheckAWSWAF(t *testing.T) {
	got := issuesText(CheckConfig([]byte("aws_waf:\n  scope: global\n  region: eu-west-1\n  ipv4: { name: bans }\n  every: 1s\n  max: 20000\n"), CheckOptions{}))
	for _, want := range []string{"scope must be REGIONAL", "ipv4 needs both name and id", `every "1s"`, "max: 1 to 10000"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if got := issuesText(CheckConfig([]byte("aws_waf:\n  scope: CLOUDFRONT\n  region: eu-west-1\n  ipv4: { name: b, id: x }\n"), CheckOptions{})); !strings.Contains(got, "us-east-1") {
		t.Errorf("CloudFront IP sets are in us-east-1:\n%s", got)
	}
}
