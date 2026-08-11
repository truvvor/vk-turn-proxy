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

// Last-resort hardcoded A records. Used only if BOTH the system resolver
// and DoH fail — layer 3 of 3, so on a healthy VPS it should stay cold.
//
// Provenance: re-derived 2026-08-11 from two independent vantage points
// (this repo's build sandbox and an operator machine) that returned
// byte-identical answers, which is why these are trusted despite VK
// running geo-DNS. Re-derive with `getent ahostsv4 <host>` if VK migrates.
//
// The previous table was stale in a way that mattered: login.vk.com and
// api.vk.com were both mapped to 87.240.132.78 / 87.240.137.158, and
// neither address appears in either host's live answer today. 87.240.132.78
// is in fact a vk.com WEB address, so the auth and API lookups were
// pointed at the wrong cluster entirely — this layer would have failed
// every time it fired.
//
// VK serves these names from three distinct address clusters, and the
// split is operationally significant, not trivia:
//
//	auth/ID  93.186.237.1, 95.213.56.1
//	         login.vk.com, login.vk.ru, id.vk.com, id.vk.ru
//	web      87.240.129.133, 87.240.132.67/.72/.78, 87.240.137.164, 93.186.225.194
//	         vk.com, vk.ru, m.vk.com
//	API      87.240.129.140, 87.240.137.130/.206/.207/.208,
//	         87.240.139.193, 87.240.190.70/.75, 93.186.225.205
//	         api.vk.com, api.vk.ru, api.vk.me
//
// Restrictive networks in the field have been observed passing the web and
// API clusters while blocking the auth/ID cluster — which is what makes the
// VK Calls path (creds_vkcalls.go) valuable beyond dodging the captcha
// gate: it draws its anon token from auth.getAnonymToken on api.vk.me, in
// the API cluster, instead of login.vk.com in the blocked auth cluster.
var fallbackIPs = map[string][]string{
	// auth / VK-ID cluster.
	"login.vk.com": {"93.186.237.1", "95.213.56.1"},
	"login.vk.ru":  {"93.186.237.1", "95.213.56.1"},
	"id.vk.com":    {"93.186.237.1", "95.213.56.1"},
	"id.vk.ru":     {"93.186.237.1", "95.213.56.1"},

	// web cluster.
	"vk.com":   {"87.240.132.67", "87.240.132.72", "87.240.132.78", "93.186.225.194"},
	"vk.ru":    {"87.240.132.67", "87.240.132.72", "87.240.132.78", "93.186.225.194"},
	"m.vk.com": {"87.240.132.67", "87.240.132.72", "87.240.137.164"},

	// API cluster. api.vk.me shares this pool with api.vk.com — same
	// backend, different FQDN, which is precisely how VK can captcha-gate
	// one and not the other: the gate keys on the (FQDN, method,
	// client_id) tuple, not on the machine answering.
	"api.vk.com": {"87.240.129.140", "87.240.137.130", "87.240.190.70", "93.186.225.205"},
	"api.vk.ru":  {"87.240.129.140", "87.240.137.130", "87.240.190.70", "93.186.225.205"},
	"api.vk.me":  {"87.240.129.140", "87.240.137.130", "87.240.190.70", "93.186.225.205"},

	// OK relay — steps 4-5 (auth.anonymLogin, vchat.joinConversationByLink).
	// Used by BOTH the bypass and legacy paths and previously absent from
	// this map entirely, so a DoH outage took out credential fetch on every
	// path rather than just one.
	"calls.okcdn.ru": {"155.212.204.12", "155.212.204.136", "155.212.204.195"},
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
