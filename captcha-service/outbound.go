// SPDX-License-Identifier: MIT
//
// outbound.go — unified egress pool for every VK-bound dialer
// (creds.go's sharedAuthClient, vk_captcha.go's newCaptchaClient, and
// the DoH client in dns_resolver.go). Each pool entry is either:
//
//   - a direct IPv4 the host owns (LocalAddr-bound — VK sees that IP
//     as the source), or
//   - a WireGuard / WARP interface (SO_BINDTODEVICE-bound — VK sees
//     the interface's egress IP, e.g. a Cloudflare edge for wgcf).
//
// Pool composition at startup:
//
//   1. Direct IPs:
//        a. OUTBOUND_BIND_IPS env (comma-separated explicit list)
//        b. OUTBOUND_BIND_IP env (legacy single-IP knob)
//        c. Auto-discovery — every globally-routable IPv4 the host has
//           configured (skips loopback / link-local / multicast /
//           RFC1918 / CGNAT). Default when neither env var is set.
//   2. WARP iface — appended when WARP_INTERFACE env names a live
//      WireGuard interface (e.g. wgcf). Doesn't replace the direct
//      IPs, it joins them so VK sees a mix of source IPs across
//      successive requests.
//
// pickEgress() rotates through the pool round-robin via an atomic
// counter; every fresh net.Dialer gets one entry baked in (LocalAddr
// + Control). The user-visible effect: a single cluster node with
// three v4 addresses and WARP up gives VK four distinct egress
// identities to rate-limit, instead of one.

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// egressEntry is one slot in the egress pool. IP set = LocalAddr
// binding. Iface set = SO_BINDTODEVICE binding. Both set is legal
// but typical entries set one or the other.
type egressEntry struct {
	IP    net.IP
	Iface string
	Label string // for logs + /stats
}

func (e egressEntry) String() string {
	if e.Label != "" {
		return e.Label
	}
	switch {
	case e.IP != nil && e.Iface != "":
		return fmt.Sprintf("ip:%s+iface:%s", e.IP, e.Iface)
	case e.IP != nil:
		return "ip:" + e.IP.String()
	case e.Iface != "":
		return "iface:" + e.Iface
	default:
		return "default"
	}
}

// applyEgress mutates d to bind to this entry's egress on every Dial.
// LocalAddr is the source-IP knob; Control is wrapped so any
// pre-existing Control hook (e.g. from upstream test fixtures) still
// runs before SO_BINDTODEVICE.
func (e egressEntry) applyEgress(d *net.Dialer) {
	if e.IP != nil {
		d.LocalAddr = &net.TCPAddr{IP: e.IP}
	}
	if e.Iface != "" {
		iface := e.Iface
		prev := d.Control
		d.Control = func(network, address string, c syscall.RawConn) error {
			if prev != nil {
				if err := prev(network, address, c); err != nil {
					return err
				}
			}
			var serr error
			if cerr := c.Control(func(fd uintptr) {
				serr = unix.BindToDevice(int(fd), iface)
			}); cerr != nil {
				return cerr
			}
			return serr
		}
	}
}

var (
	// egressPool is built once at startup by initEgressPool. Read-only
	// after init; safe for concurrent reads.
	egressPool []egressEntry

	// egressRR is the global round-robin counter shared by every
	// pickEgress call. atomic.AddUint64 - 1 mod len gives a stable
	// "next slot" without locks. Wraps cleanly at uint64 overflow.
	egressRR atomic.Uint64
)

// initEgressPool populates egressPool from env / auto-discovery /
// WARP. Must be called once before any HTTP client is constructed.
func initEgressPool() {
	// 1. Direct IPs.
	var ips []net.IP
	var ipSource string
	switch {
	case strings.TrimSpace(os.Getenv("OUTBOUND_BIND_IPS")) != "":
		ipSource = "OUTBOUND_BIND_IPS env"
		for _, s := range strings.Split(os.Getenv("OUTBOUND_BIND_IPS"), ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			ip := net.ParseIP(s)
			if ip == nil {
				log.Fatalf("OUTBOUND_BIND_IPS: %q is not a valid IP literal", s)
			}
			ips = append(ips, ip)
		}
	case strings.TrimSpace(os.Getenv("OUTBOUND_BIND_IP")) != "":
		ipSource = "OUTBOUND_BIND_IP env"
		v := strings.TrimSpace(os.Getenv("OUTBOUND_BIND_IP"))
		ip := net.ParseIP(v)
		if ip == nil {
			log.Fatalf("OUTBOUND_BIND_IP=%q is not a valid IP literal", v)
		}
		ips = []net.IP{ip}
	default:
		ipSource = "auto-discovery"
		ips = discoverGlobalV4()
	}
	for _, ip := range ips {
		egressPool = append(egressPool, egressEntry{
			IP:    ip,
			Label: "ip:" + ip.String(),
		})
	}

	// 2. WARP iface (joins direct IPs, doesn't replace them).
	if iface := strings.TrimSpace(os.Getenv("WARP_INTERFACE")); iface != "" {
		egressPool = append(egressPool, egressEntry{
			Iface: iface,
			Label: "iface:" + iface,
		})
	}

	// 3. Fallback: if both auto-discovery and env returned nothing AND
	// no WARP iface, leave the pool empty — pickEgress returns a
	// zero-value entry that means "kernel chooses". applyEgress on an
	// empty entry is a no-op so the dialer behaves like vanilla net.
	if len(egressPool) == 0 {
		log.Printf("egress: pool empty (no IPs auto-discovered, no env, no WARP) — kernel default egress only")
		return
	}

	log.Printf("egress: rotating %d source(s) for VK traffic (direct-IP source: %s):", len(egressPool), ipSource)
	for _, e := range egressPool {
		log.Printf("  - %s", e)
	}
}

// pickEgress returns the next pool entry via round-robin. Returns a
// zero-value entry (which applyEgress treats as no-op) when the pool
// is empty, so callers don't need to nil-check.
func pickEgress() egressEntry {
	n := uint64(len(egressPool))
	if n == 0 {
		return egressEntry{}
	}
	idx := (egressRR.Add(1) - 1) % n
	return egressPool[idx]
}

// newEgressDialer is the rotation-aware net.Dialer for code paths
// that build a fresh dialer per dial (creds.go's doRequest via
// customDial, the DoH client). Picks one entry per call.
func newEgressDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	pickEgress().applyEgress(d)
	return d
}

// newEgressNetDialer returns a net.Dialer value (not pointer) for
// tls-client's WithDialer, which takes net.Dialer by value. tls-client
// uses this dialer for the lifetime of one HTTP client, so the
// rotation happens at newCaptchaClient() call time (vk_captcha.go
// makes one fresh client per /cred attempt).
func newEgressNetDialer() net.Dialer {
	d := net.Dialer{}
	pickEgress().applyEgress(&d)
	return d
}

// egressPoolSnapshot returns the configured pool for /stats. Safe to
// call concurrently; pool is immutable after init.
func egressPoolSnapshot() []string {
	if len(egressPool) == 0 {
		return nil
	}
	out := make([]string, 0, len(egressPool))
	for _, e := range egressPool {
		out = append(out, e.String())
	}
	return out
}

// discoverGlobalV4 returns every IPv4 address bound to a system
// interface that's plausibly a public egress address: skips loopback,
// link-local, multicast, and RFC1918 / CGNAT ranges. Caller may still
// override via OUTBOUND_BIND_IP* env if the heuristic guesses wrong.
func discoverGlobalV4() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("egress: net.InterfaceAddrs failed: %v", err)
		return nil
	}
	var out []net.IP
	seen := make(map[string]bool)
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipn.IP.To4()
		if ip4 == nil {
			continue
		}
		if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsMulticast() || ip4.IsUnspecified() {
			continue
		}
		if isPrivateOrCGNAT(ip4) {
			continue
		}
		key := ip4.String()
		if seen[key] {
			// netplan can advertise the same IP under multiple masks
			// (/24 + /26 on the same interface); de-dupe.
			continue
		}
		seen[key] = true
		out = append(out, ip4)
	}
	return out
}

// isPrivateOrCGNAT excludes addresses we definitely don't want to use
// as VK egress: RFC1918 (10/8, 172.16/12, 192.168/16) and CGNAT
// (100.64/10). These don't have public reachability so VK couldn't
// route replies back even if we bound to them.
func isPrivateOrCGNAT(ip net.IP) bool {
	switch {
	case ip[0] == 10:
		return true
	case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
		return true
	case ip[0] == 192 && ip[1] == 168:
		return true
	case ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127:
		return true
	}
	return false
}
