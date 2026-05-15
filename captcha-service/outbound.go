// SPDX-License-Identifier: MIT
//
// outbound.go — pool of source IPv4 addresses used as the LocalAddr for
// every VK-bound dialer (creds.go's sharedAuthClient, vk_captcha.go's
// newCaptchaClient, and the DoH client in dns_resolver.go).
//
// Why a pool: VK enforces captcha rate-limits per source IP. A single
// VPS with multiple v4 addresses can spread captcha attempts across
// those addresses, multiplying the per-IP budget without spinning up
// extra hosts. captcha-service rotates through the pool round-robin so
// successive solves leave different source IPs.
//
// Pool sources (in priority order, evaluated once at startup):
//
//   1. OUTBOUND_BIND_IPS env — explicit comma-separated list.
//      e.g. OUTBOUND_BIND_IPS=67.217.246.160,198.71.56.216
//
//   2. OUTBOUND_BIND_IP env — legacy single-IP knob. Treated as a
//      one-element pool. Behaves exactly as before this change.
//
//   3. Auto-discovery — enumerate every globally-routable IPv4 address
//      bound to a system interface (skipping loopback, link-local,
//      multicast and private RFC1918 / CGNAT space where possible).
//      Default when neither env var is set.
//
//   4. Empty pool — fall back to the kernel's normal source-IP
//      selection (LocalAddr=nil). The dialer logs once if it lands here
//      so operators know auto-discovery returned nothing.
//
// Within outboundDialer(), connections rotate through the pool with an
// atomic counter. The rotation is per-connection, not per-captcha-attempt:
// because the captcha-service code path opens a fresh http.Client for
// each /cred request and that client makes several short-lived connections
// to VK over the attempt's ~5s lifetime, the practical effect is "one
// captcha attempt per IP" for small pools.

package main

import (
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// outboundBindPool is built once at startup by initOutboundBindIP.
	// Read-only after init; safe for concurrent reads.
	outboundBindPool []net.IP

	// outboundRR is the global round-robin counter shared by every
	// pickOutboundIP call. atomic.AddUint64 - 1 mod len gives a stable
	// "next slot" without locks. Wraps cleanly at uint64 overflow.
	outboundRR atomic.Uint64
)

// initOutboundBindIP populates outboundBindPool from env / auto-discovery.
// Must be called once before any HTTP client is constructed.
func initOutboundBindIP() {
	// 1. Explicit list takes precedence.
	if v := strings.TrimSpace(os.Getenv("OUTBOUND_BIND_IPS")); v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			ip := net.ParseIP(s)
			if ip == nil {
				log.Fatalf("OUTBOUND_BIND_IPS: %q is not a valid IP literal", s)
			}
			outboundBindPool = append(outboundBindPool, ip)
		}
		logPool("OUTBOUND_BIND_IPS")
		return
	}

	// 2. Legacy single-IP knob.
	if v := strings.TrimSpace(os.Getenv("OUTBOUND_BIND_IP")); v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			log.Fatalf("OUTBOUND_BIND_IP=%q is not a valid IP literal", v)
		}
		outboundBindPool = []net.IP{ip}
		logPool("OUTBOUND_BIND_IP")
		return
	}

	// 3. Auto-discovery.
	outboundBindPool = discoverGlobalV4()
	if len(outboundBindPool) == 0 {
		log.Printf("outbound: no global v4 found on interfaces; kernel will pick the source IP for VK traffic")
		return
	}
	logPool("auto-discovery")
}

func logPool(source string) {
	if len(outboundBindPool) == 0 {
		return
	}
	log.Printf("outbound: rotating %d source IP(s) for VK + DoH (source: %s):", len(outboundBindPool), source)
	for _, ip := range outboundBindPool {
		log.Printf("  - %s", ip)
	}
}

// discoverGlobalV4 returns every IPv4 address bound to a system
// interface that's plausibly a public egress address: skips loopback,
// link-local, multicast, and RFC1918 / CGNAT ranges. Caller may still
// override via env if the heuristic guesses wrong.
func discoverGlobalV4() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("outbound: net.InterfaceAddrs failed: %v", err)
		return nil
	}
	var out []net.IP
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

// pickOutboundIP returns the next source IP from the pool via
// round-robin. Returns nil when the pool is empty (signals "let kernel
// choose"), which callers translate to LocalAddr=nil.
func pickOutboundIP() net.IP {
	n := uint64(len(outboundBindPool))
	if n == 0 {
		return nil
	}
	idx := (outboundRR.Add(1) - 1) % n
	return outboundBindPool[idx]
}

// outboundDialer returns a net.Dialer with the configured timeout and,
// when the pool is non-empty, LocalAddr pinned to the next source IP.
// Called fresh per connection so each connection lands on a different
// pool entry under sustained traffic.
func outboundDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if ip := pickOutboundIP(); ip != nil {
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return d
}

// outboundPoolSnapshot returns the configured pool for /stats. Safe to
// call concurrently; pool is immutable after init.
func outboundPoolSnapshot() []string {
	if len(outboundBindPool) == 0 {
		return nil
	}
	out := make([]string, 0, len(outboundBindPool))
	for _, ip := range outboundBindPool {
		out = append(out, ip.String())
	}
	return out
}
