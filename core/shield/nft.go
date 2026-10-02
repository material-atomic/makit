package shield

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// The kernel layer: nftables sets — the in-kernel successor of ipset, same hash structures, millions of elements —
// checked in prerouting at raw priority (before conntrack and Docker's NAT). No ipset package needed.
//
//	block4/block6     manual and automatic bans (interval sets, per-element timeouts)
//	list4ip/list6ip   bulk lists, single addresses (hash sets)
//	list4net/list6net bulk lists, CIDR ranges (interval sets)
const nftTable = "makit_shield"

var nftSets = []struct{ name, typ, flags string }{
	{"block4", "ipv4_addr", "interval, timeout"}, {"block6", "ipv6_addr", "interval, timeout"},
	{"list4ip", "ipv4_addr", "timeout"}, {"list6ip", "ipv6_addr", "timeout"},
	{"list4net", "ipv4_addr", "interval, timeout"}, {"list6net", "ipv6_addr", "interval, timeout"},
}

// nftEnsure creates the table, sets and chain when missing (idempotent: "add" keeps existing elements).
func nftEnsure() string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", nftTable)
	for _, s := range nftSets {
		fmt.Fprintf(&b, "add set inet %s %s { type %s; flags %s; size 16000000; }\n", nftTable, s.name, s.typ, s.flags)
	}
	fmt.Fprintf(&b, "add chain inet %s prerouting { type filter hook prerouting priority raw; policy accept; }\n", nftTable)
	fmt.Fprintf(&b, "flush chain inet %s prerouting\n", nftTable)
	for _, s := range nftSets {
		fam := "ip"
		if strings.HasSuffix(strings.TrimSuffix(strings.TrimSuffix(s.name, "ip"), "net"), "6") {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "add rule inet %s prerouting %s saddr @%s counter drop\n", nftTable, fam, s.name)
	}
	return b.String()
}

func element(p netip.Prefix, until time.Time, now time.Time) string {
	el := p.String()
	if p.IsSingleIP() {
		el = p.Addr().String()
	}
	if !until.IsZero() {
		el += fmt.Sprintf(" timeout %ds", int(until.Sub(now).Seconds())+1)
	}
	return el
}

// NftScript renders the ensure step plus a full replacement of the small block sets.
func NftScript(block []Entry, now time.Time) string {
	var v4, v6 []string
	for _, e := range block {
		if !KernelSafe(e.Prefix) || (!e.Until.IsZero() && !now.Before(e.Until)) {
			continue
		}
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, element(e.Prefix, e.Until, now))
		} else {
			v6 = append(v6, element(e.Prefix, e.Until, now))
		}
	}
	var b strings.Builder
	b.WriteString(nftEnsure())
	for _, x := range []struct {
		set string
		els []string
	}{{"block4", v4}, {"block6", v6}} {
		fmt.Fprintf(&b, "flush set inet %s %s\n", nftTable, x.set)
		if len(x.els) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", nftTable, x.set, strings.Join(x.els, ", "))
		}
	}
	return b.String()
}

// NftListBatches renders the bulk lists as several scripts of at most batch elements each (the first flushes).
func NftListBatches(lists *Set, now time.Time, batch int) []string {
	if batch <= 0 {
		batch = 20000
	}
	bySet := map[string][]string{}
	for _, e := range lists.Live(now) {
		if !KernelSafe(e.Prefix) {
			continue
		}
		name := "list4"
		if e.Prefix.Addr().Is6() {
			name = "list6"
		}
		if e.Prefix.IsSingleIP() {
			name += "ip"
		} else {
			name += "net"
		}
		bySet[name] = append(bySet[name], element(e.Prefix, e.Until, now))
	}
	var flush strings.Builder
	for _, s := range []string{"list4ip", "list6ip", "list4net", "list6net"} {
		fmt.Fprintf(&flush, "flush set inet %s %s\n", nftTable, s)
	}
	out := []string{nftEnsure() + flush.String()}
	for _, s := range []string{"list4ip", "list6ip", "list4net", "list6net"} {
		els := bySet[s]
		for i := 0; i < len(els); i += batch {
			j := min(i+batch, len(els))
			out = append(out, fmt.Sprintf("add element inet %s %s { %s }\n", nftTable, s, strings.Join(els[i:j], ", ")))
		}
	}
	return out
}

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ApplyKernel replaces the block sets with the current bans (lists untouched).
func ApplyKernel(block []Entry) error { return nft(NftScript(block, time.Now())) }

// ApplyKernelLists replaces the list sets, in batches.
func ApplyKernelLists(lists *Set) error {
	for _, s := range NftListBatches(lists, time.Now(), 20000) {
		if err := nft(s); err != nil {
			return err
		}
	}
	return nil
}

// RemoveKernel deletes the makit table (shield off or kernel_block off).
func RemoveKernel() error {
	return nft(fmt.Sprintf("table inet %[1]s {}\ndelete table inet %[1]s\n", nftTable))
}

// kernelAdd adds one ban immediately (automatic bans between syncs).
func kernelAdd(p netip.Prefix, until time.Time) error {
	if !KernelSafe(p) {
		return nil
	}
	set := "block4"
	if p.Addr().Is6() {
		set = "block6"
	}
	return nft(fmt.Sprintf("add element inet %s %s { %s }\n", nftTable, set, element(p, until, time.Now())))
}
