package shield

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// The kernel layer: an nftables table with two interval sets (IPv4/IPv6, per-entry timeouts) checked in prerouting
// at raw priority — before conntrack, before Docker's NAT, for host services and published container ports alike.
// No ipset needed: sets are native to nftables (the backend of iptables on current Debian/Ubuntu).
const nftTable = "makit_shield"

// NftScript renders the whole table from the live block entries that are safe to drop in the kernel.
func NftScript(block []Entry, now time.Time) string {
	var v4, v6 []string
	for _, e := range block {
		if !KernelSafe(e.Prefix) || (!e.Until.IsZero() && !now.Before(e.Until)) {
			continue
		}
		el := e.Prefix.String()
		if e.Prefix.IsSingleIP() {
			el = e.Prefix.Addr().String()
		}
		if !e.Until.IsZero() {
			el += fmt.Sprintf(" timeout %ds", int(e.Until.Sub(now).Seconds())+1)
		}
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}
	elems := func(es []string) string {
		if len(es) == 0 {
			return ""
		}
		return "\n    elements = { " + strings.Join(es, ", ") + " }"
	}
	return fmt.Sprintf(`table inet %[1]s {}
delete table inet %[1]s
table inet %[1]s {
  set block4 {
    type ipv4_addr
    flags interval, timeout%[2]s
  }
  set block6 {
    type ipv6_addr
    flags interval, timeout%[3]s
  }
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    ip saddr @block4 counter drop
    ip6 saddr @block6 counter drop
  }
}
`, nftTable, elems(v4), elems(v6))
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

// ApplyKernel replaces the makit table atomically with the current block list.
func ApplyKernel(block []Entry) error { return nft(NftScript(block, time.Now())) }

// RemoveKernel deletes the makit table (shield off).
func RemoveKernel() error {
	return nft(fmt.Sprintf("table inet %[1]s {}\ndelete table inet %[1]s\n", nftTable))
}

// kernelAdd adds one entry immediately (used by auto-bans between full syncs).
func kernelAdd(p netip.Prefix, until time.Time) error {
	if !KernelSafe(p) {
		return nil
	}
	set := "block4"
	if p.Addr().Is6() {
		set = "block6"
	}
	el := p.String()
	if p.IsSingleIP() {
		el = p.Addr().String()
	}
	if !until.IsZero() {
		el += fmt.Sprintf(" timeout %ds", int(time.Until(until).Seconds())+1)
	}
	return nft(fmt.Sprintf("add element inet %s %s { %s }\n", nftTable, set, el))
}
