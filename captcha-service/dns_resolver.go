// SPDX-License-Identifier: MIT
//
// Resilient DNS for VK captcha/identity HTTP. The system resolver on
// mobile carriers in censorship-heavy regions sometimes returns
// NXDOMAIN, hijacked IPs, or hangs on api.vk.com / id.vk.com lookups,
// even when the underlying network is otherwise fine. The captcha
// solver then errors out with "no such host" or a timeout before any
// of our retry logic can engage.
//
// customDial is a drop-in replacement for net.Dialer.DialContext that
// layers:
//   1. literal IP addresses     — dial immediately, no resolution.
//   2. system resolver          — 4 s budget. Works on WiFi where the
//                                 carrier isn't censoring.
//   3. DNS-over-HTTPS (DoH)     — Cloudflare's 1.1.1.1 JSON endpoint
//                                 by IP, so the lookup itself needs
//                                 no DNS. Cached for 10 minutes per
//                                 hostname to avoid hammering DoH.
//   4. fallback IP map          — last-resort hardcoded A records for
//                                 VK domains, in case DoH is also
//                                 blocked. Stale risk but better than
//                                 a hard failure.
//
// The TLS handshake uses the original hostname (Go's http.Transport
// passes the request URL host as SNI/ServerName regardless of what
// DialContext returned), so dialing to a raw IP doesn't break cert
// verification.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	dohURL           = "https://1.1.1.1/dns-query"
	dohCacheTTL      = 10 * time.Minute
	systemDialBudget = 4 * time.Second
	dohDialBudget    = 6 * time.Second
)

// dohClient is used ONLY for the DoH lookup itself. Plain net.Dialer
// (no recursion into customDial). The egress pool's Control hook is
// installed per Dial via dohDialContext so DoH queries to 1.1.1.1
// rotate alongside VK traffic and pick up SO_BINDTODEVICE when WARP
// is in the pool. Cloudflare's 1.1.1.1 is reachable from inside WARP
// just fine.
func dohDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := newEgressDialer(4 * time.Second)
	return d.DialContext(ctx, network, address)
}

var dohClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DialContext:     dohDialContext,
		TLSClientConfig: &tls.Config{},
	},
}

type dohEntry struct {
	ips     []string
	expires time.Time
}

var dohCache sync.Map // host -> dohEntry

// Last-resort hardcoded A records. Used only if BOTH system resolver
// and DoH fail. VK's API endpoints have lived on these IPs for a long
// time; refresh manually if VK migrates infrastructure.
var fallbackIPs = map[string][]string{
	"login.vk.com": {"87.240.132.78", "87.240.137.158"},
	"api.vk.com":   {"87.240.132.78", "87.240.137.158"},
	"id.vk.com":    {"87.240.132.78", "87.240.137.158"},
	"vk.com":       {"87.240.132.78", "87.240.137.158"},
	"m.vk.com":     {"87.240.132.78"},
	// keep .ru hosts too in case some upstream code path still
	// hits them (and they're reachable on the user's network).
	"login.vk.ru": {"87.240.137.158", "87.240.190.78"},
	"api.vk.ru":   {"87.240.137.158", "87.240.190.78"},
	"id.vk.ru":    {"87.240.137.158", "87.240.190.78"},
	"vk.ru":       {"87.240.137.158"},
}

// customDial is the net.Dialer.DialContext-shaped function plug into
// http.Transport on any HTTP client that needs censorship-tolerant DNS.
func customDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// Pick one egress entry up-front and stick with it across all
	// resolution layers — system, DoH, hardcoded fallback — so VK
	// sees a stable source IP per logical lookup attempt instead of
	// the source flapping between layers' connect()s.
	egress := pickEgress()
	mkDialer := func(timeout time.Duration) *net.Dialer {
		d := &net.Dialer{Timeout: timeout}
		egress.applyEgress(d)
		return d
	}

	// Fast path: literal IP needs no resolution.
	if net.ParseIP(host) != nil {
		return mkDialer(8*time.Second).DialContext(ctx, network, address)
	}

	// Layer 1: system resolver.
	d := mkDialer(dohDialBudget)
	sysCtx, cancel := context.WithTimeout(ctx, systemDialBudget)
	conn, sysErr := d.DialContext(sysCtx, network, address)
	cancel()
	if sysErr == nil {
		return conn, nil
	}
	log.Printf("dns: system resolve+dial failed for %s: %v — falling back to DoH", host, sysErr)

	// Layer 2: DoH.
	if ips, err := resolveViaDoH(ctx, host); err == nil && len(ips) > 0 {
		log.Printf("dns: DoH %s → %v", host, ips)
		for _, ip := range ips {
			c, derr := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if derr == nil {
				return c, nil
			}
			log.Printf("dns: dial %s (DoH) failed: %v", ip, derr)
		}
	} else if err != nil {
		log.Printf("dns: DoH lookup failed for %s: %v", host, err)
	}

	// Layer 3: hardcoded fallback.
	if ips, ok := fallbackIPs[strings.ToLower(host)]; ok {
		log.Printf("dns: trying hardcoded fallback IPs for %s: %v", host, ips)
		for _, ip := range ips {
			c, derr := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if derr == nil {
				return c, nil
			}
			log.Printf("dns: dial %s (fallback) failed: %v", ip, derr)
		}
	}

	return nil, fmt.Errorf("all DNS layers exhausted for %s (sys=%v)", host, sysErr)
}

func resolveViaDoH(ctx context.Context, host string) ([]string, error) {
	host = strings.ToLower(host)
	if v, ok := dohCache.Load(host); ok {
		if entry, ok := v.(dohEntry); ok && time.Now().Before(entry.expires) {
			return entry.ips, nil
		}
	}

	url := dohURL + "?name=" + host + "&type=A"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")

	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var doh struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &doh); err != nil {
		return nil, err
	}

	var ips []string
	for _, a := range doh.Answer {
		if a.Type == 1 && net.ParseIP(a.Data) != nil { // A record
			ips = append(ips, strings.TrimSpace(a.Data))
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DoH returned no A records for %s", host)
	}
	dohCache.Store(host, dohEntry{
		ips:     ips,
		expires: time.Now().Add(dohCacheTTL),
	})
	return ips, nil
}
