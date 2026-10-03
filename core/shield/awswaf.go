package shield

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// Bans pushed to AWS WAF: makit keeps one IP set per address family equal to its live bans, so a web ACL rule on the
// load balancer (or CloudFront) drops that traffic before it reaches the cluster. makit only writes the IP sets you
// name; the web ACL rule that uses them is yours. Never pushed: anything that overlaps an allow entry or a trusted
// proxy (a ban there would block every visitor at the edge), site-only bans (a web ACL covers every site), and ranges
// wider than /8 (IPv4) or /32 (IPv6).
//
// Credentials come from the usual AWS chain: environment, EKS Pod Identity or IRSA, the instance role, a profile.
// The IAM policy needs wafv2:GetIPSet and wafv2:UpdateIPSet on the two IP sets, nothing else.

// AWSWAFConfig: aws_waf: in shield.yaml.
type AWSWAFConfig struct {
	Region   string        `yaml:"region"`   // the region of the web ACL (CLOUDFRONT: us-east-1)
	Scope    string        `yaml:"scope"`    // REGIONAL (ALB, API Gateway, AppSync) or CLOUDFRONT
	IPv4     AWSWAFIPSet   `yaml:"ipv4"`     // an IPV4 IP set
	IPv6     AWSWAFIPSet   `yaml:"ipv6"`     // an IPV6 IP set (optional)
	Every    string        `yaml:"every"`    // how often the IP sets are brought up to date (default 30s)
	Max      int           `yaml:"max"`      // addresses per IP set (default and AWS limit: 10000)
	Endpoint string        `yaml:"endpoint"` // a VPC endpoint or a test server
	timeout  time.Duration // per call (tests)
}

type AWSWAFIPSet struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
}

func (c AWSWAFConfig) Enabled() bool { return c.IPv4.ID != "" || c.IPv6.ID != "" }

func (c AWSWAFConfig) interval() time.Duration {
	if d, err := time.ParseDuration(c.Every); err == nil && d >= 10*time.Second {
		return d
	}
	return 30 * time.Second
}

func (c AWSWAFConfig) max() int {
	if c.Max > 0 && c.Max <= 10000 {
		return c.Max
	}
	return 10000
}

func (c AWSWAFConfig) scope() waftypes.Scope {
	if strings.EqualFold(c.Scope, "CLOUDFRONT") {
		return waftypes.ScopeCloudfront
	}
	return waftypes.ScopeRegional
}

// WAFPlan is what the IP sets should hold, and what was left out and why.
type WAFPlan struct {
	V4, V6                          []string
	Allowed, Trusted, Site, TooWide int // bans left out
	OverMax                         int // the oldest bans beyond the IP set limit
}

// planWAF picks the addresses to push from the live bans.
func planWAF(bans []Entry, allow []Entry, trusted []netip.Prefix, now time.Time, max int) WAFPlan {
	var pl WAFPlan
	overlaps := func(p netip.Prefix) (allowed, isTrusted bool) {
		for _, a := range allow {
			if a.Prefix.Overlaps(p) && (a.Until.IsZero() || now.Before(a.Until)) {
				return true, false
			}
		}
		for _, t := range trusted {
			if t.Overlaps(p) {
				return false, true
			}
		}
		return false, false
	}
	var v4, v6 []Entry
	for _, e := range bans {
		switch al, tr := overlaps(e.Prefix); {
		case !e.Until.IsZero() && !now.Before(e.Until):
		case e.Site != "":
			pl.Site++
		case al:
			pl.Allowed++
		case tr:
			pl.Trusted++
		case e.Prefix.Addr().Is4() && e.Prefix.Bits() < 8, e.Prefix.Addr().Is6() && e.Prefix.Bits() < 32:
			pl.TooWide++
		case e.Prefix.Addr().Is4():
			v4 = append(v4, e)
		default:
			v6 = append(v6, e)
		}
	}
	take := func(es []Entry) []string {
		// Over the limit: the newest bans win — the attacks going on now. The same range twice counts once.
		sort.SliceStable(es, func(i, j int) bool { return es[i].Added.After(es[j].Added) })
		seen := make(map[netip.Prefix]bool, len(es))
		out := make([]string, 0, min(len(es), max))
		for _, e := range es {
			p := e.Prefix.Masked()
			if seen[p] {
				continue
			}
			seen[p] = true
			if len(out) == max {
				pl.OverMax++
				continue
			}
			out = append(out, p.String())
		}
		sort.Strings(out)
		return out
	}
	pl.V4, pl.V6 = take(v4), take(v6)
	return pl
}

// WAFSync keeps the IP sets equal to a plan.
type WAFSync struct {
	cfg    AWSWAFConfig
	client *wafv2.Client
	last   atomic.Pointer[WAFStatus]
	errors atomic.Uint64
}

// WAFStatus is the outcome of the last sync, for status and metrics.
type WAFStatus struct {
	At      time.Time
	V4, V6  int
	Changed bool
	Plan    WAFPlan
	Err     string
}

func NewWAFSync(ctx context.Context, cfg AWSWAFConfig) (*WAFSync, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	ac, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws_waf: %w", err)
	}
	if ac.Region == "" {
		return nil, errors.New("aws_waf: no region (aws_waf.region, or AWS_REGION)")
	}
	client := wafv2.NewFromConfig(ac, func(o *wafv2.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	if cfg.timeout == 0 {
		cfg.timeout = 15 * time.Second
	}
	return &WAFSync{cfg: cfg, client: client}, nil
}

// Sync brings both IP sets up to date; with dryRun it only reports what it would change.
func (w *WAFSync) Sync(ctx context.Context, pl WAFPlan, dryRun bool) (WAFStatus, error) {
	st := WAFStatus{At: time.Now(), Plan: pl, V4: len(pl.V4), V6: len(pl.V6)}
	var errs []error
	for _, set := range []struct {
		s    AWSWAFIPSet
		want []string
	}{{w.cfg.IPv4, pl.V4}, {w.cfg.IPv6, pl.V6}} {
		if set.s.ID == "" {
			continue
		}
		changed, err := w.syncSet(ctx, set.s, set.want, dryRun)
		st.Changed = st.Changed || changed
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", set.s.Name, err))
		}
	}
	err := errors.Join(errs...)
	if err != nil {
		st.Err = err.Error()
		w.errors.Add(1)
	}
	if !dryRun {
		w.last.Store(&st)
	}
	return st, err
}

func (w *WAFSync) syncSet(ctx context.Context, s AWSWAFIPSet, want []string, dryRun bool) (bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, w.cfg.timeout)
		got, err := w.client.GetIPSet(cctx, &wafv2.GetIPSetInput{Id: aws.String(s.ID), Name: aws.String(s.Name), Scope: w.cfg.scope()})
		cancel()
		if err != nil {
			return false, err
		}
		have := append([]string(nil), got.IPSet.Addresses...)
		sort.Strings(have)
		if slices.Equal(have, want) {
			return false, nil
		}
		if dryRun {
			return true, nil
		}
		cctx, cancel = context.WithTimeout(ctx, w.cfg.timeout)
		_, err = w.client.UpdateIPSet(cctx, &wafv2.UpdateIPSetInput{Id: aws.String(s.ID), Name: aws.String(s.Name), Scope: w.cfg.scope(),
			Addresses: want, LockToken: got.LockToken, Description: got.IPSet.Description})
		cancel()
		var lock *waftypes.WAFOptimisticLockException
		if errors.As(err, &lock) {
			continue // changed in between (another writer): read it again
		}
		return err == nil, err
	}
	return false, errors.New("the IP set kept changing under makit (another writer?)")
}

// Status returns the last sync (nil before the first).
func (w *WAFSync) Status() *WAFStatus { return w.last.Load() }

// wafLoop pushes the gate's bans to AWS WAF. With a cluster, one replica writes: the one whose node name sorts first
// among those it has heard from recently.
func (g *Gate) wafLoop(ctx context.Context, w *WAFSync) {
	t := time.NewTicker(w.cfg.interval())
	defer t.Stop()
	var lastErr string
	for {
		if p := g.policy.Load(); p != nil && (g.cluster == nil || g.cluster.Leader()) {
			now := time.Now()
			pl := planWAF(p.Block.Live(now), p.Allow.Live(now), p.Trusted, now, w.cfg.max())
			if st, err := w.Sync(ctx, pl, false); err != nil {
				if err.Error() != lastErr {
					log.Printf("shield: aws_waf: %v (kept trying every %s)", err, w.cfg.interval())
				}
				lastErr = err.Error()
			} else {
				if st.Changed || lastErr != "" {
					log.Printf("shield: aws_waf: %d IPv4 and %d IPv6 bans in the IP sets", st.V4, st.V6)
				}
				lastErr = ""
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
