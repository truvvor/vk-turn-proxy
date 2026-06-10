// cluster.go — peer-to-peer fan-out for the captcha-service.
//
// Each binary is symmetric: it can act as the master (the entry
// point the client talks to) AND as a slave (a worker another peer
// forwards to). The peer the client hits acts as master FOR THAT
// REQUEST — there's no global leader. Picking a peer for a /cred
// call is just round-robin over the configured peer list, including
// self.
//
// Why this exists: VK enforces captcha rate-limits per source IP,
// so a single server's per-IP budget caps the unique-identity
// throughput. Running N captcha-services on N distinct VPS IPs
// multiplies the budget. The client only ever talks to one URL;
// the master transparently distributes work behind it.
//
// Saturation tracking: each peer knows its OWN cooldown state
// (directSaturated() — trips on VK ERROR_LIMIT, auto-clears after
// captchaCooldown). When a master forwards to a peer and the peer
// returns 429 or sets X-Captcha-Self-Saturated: 1, the master
// records "peer X cool down until now + 60 s" locally and skips X
// in subsequent rounds. No proactive gossip — saturation is learned
// passively from response.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type peer struct {
	URL  string // empty when Self is true and we never need to dial out
	Key  string
	Self bool

	mu             sync.Mutex
	saturatedUntil time.Time
	// healthy tracks whether the peer's /healthz is currently
	// responsive. Defaults to true so we don't lock everyone out
	// before the first healthcheck cycle runs; the background
	// healthcheck loop (see runHealthcheckLoop) flips it to false
	// the moment a probe fails and back to true on the next
	// successful probe.
	healthy           bool
	lastHealthcheckAt time.Time
}

const (
	// healthcheckInterval is how often the background loop pings
	// each non-self peer's /healthz. 15 s gives a dead peer at most
	// one stale /cred routing decision before it's pulled out of
	// rotation, without overwhelming small clusters.
	healthcheckInterval = 15 * time.Second
	// healthcheckTimeout caps a single /healthz probe. Healthy
	// peers respond in <10 ms; anything that takes longer than a
	// second is effectively hung from the client's point of view.
	healthcheckTimeout = 2 * time.Second
)

var (
	peers    []*peer
	rrCursor atomic.Uint64
)

// peerHTTPClient is dedicated to inter-peer /internal/cred calls. A
// separate transport from sharedAuthClient (which talks to VK) so a
// hung peer can't starve the captcha pipeline of HTTP connections,
// and vice versa.
var peerHTTPClient = &http.Client{
	Timeout: 90 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     120 * time.Second,
	},
}

// initPeers parses PEERS + SELF_URL env vars. PEERS is comma-
// separated URL|KEY pairs; SELF_URL must exactly match one of the
// URLs (so the binary can recognise itself and avoid HTTP-looping
// back to its own listen socket).
//
// PEERS absent → single-node mode; the binary serves /cred locally
// with no forwarding. This is the same behaviour as V1.
func initPeers() {
	peersEnv := strings.TrimSpace(os.Getenv("PEERS"))
	selfURL := strings.TrimSpace(os.Getenv("SELF_URL"))

	if peersEnv == "" {
		peers = []*peer{{Self: true, healthy: true}}
		log.Printf("cluster: single-node mode (no PEERS configured)")
		return
	}

	sawSelf := false
	for _, entry := range strings.Split(peersEnv, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "|", 2)
		if len(parts) != 2 {
			log.Fatalf("cluster: malformed PEERS entry %q (expected URL|API_KEY)", entry)
		}
		url := strings.TrimRight(strings.TrimSpace(parts[0]), "/")
		key := strings.TrimSpace(parts[1])
		isSelf := url == selfURL
		if isSelf {
			sawSelf = true
		}
		peers = append(peers, &peer{URL: url, Key: key, Self: isSelf, healthy: true})
	}

	if !sawSelf {
		log.Fatalf("cluster: SELF_URL=%q does not match any PEERS entry; refusing to start (would loop)", selfURL)
	}

	log.Printf("cluster: %d peer(s) configured, self=%s", len(peers), selfURL)
	for _, p := range peers {
		role := "remote"
		if p.Self {
			role = "self"
		}
		log.Printf("cluster:   - %s (%s)", p.URL, role)
	}
}

func (p *peer) isAvailable() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Self is always considered healthy — we're in the same process,
	// the active healthcheck loop skips us. The healthy flag only
	// gates remote peers, which the background loop tracks via
	// /healthz probes.
	if !p.Self && !p.healthy {
		return false
	}
	return time.Now().After(p.saturatedUntil)
}

// markHealthy records a successful healthcheck and logs the
// recovery transition. Idempotent — repeated calls only log on
// the false→true transition.
func (p *peer) markHealthy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.healthy {
		log.Printf("cluster: peer %s back online (healthcheck OK)", p.statusLabel())
	}
	p.healthy = true
	p.lastHealthcheckAt = time.Now()
}

// markUnhealthy flags the peer as not eligible for /cred routing
// until the next successful healthcheck. Logged on the true→false
// transition so the operator can see the moment a peer dropped.
func (p *peer) markUnhealthy(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.healthy {
		log.Printf("cluster: peer %s marked unhealthy (%s)", p.statusLabel(), reason)
	}
	p.healthy = false
	p.lastHealthcheckAt = time.Now()
}

// healthcheckPeer issues a short-timeout GET /healthz against the
// peer. Returns (true, nil) on a 2xx response, (false, err) otherwise.
// Self peers always return true without dialing — we're in the same
// process and /healthz wouldn't surface in-process hangs anyway.
func healthcheckPeer(ctx context.Context, p *peer) (bool, error) {
	if p.Self {
		return true, nil
	}
	cctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "GET", p.URL+"/healthz", nil)
	if err != nil {
		return false, err
	}
	resp, err := peerHTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("healthz returned HTTP %d", resp.StatusCode)
	}
	return true, nil
}

// runHealthcheckLoop probes every non-self peer's /healthz on a
// ticker and updates the peer.healthy flag. Started once from main
// after initPeers; runs for the lifetime of the process.
//
// Why active probing: without it the cluster only learns a peer is
// dead when a /cred request lands on it and waits out the per-call
// HTTP timeout — that's seconds of latency per dead peer, paid by
// every client request. With this loop a dead peer is dropped from
// rotation within healthcheckInterval and only the healthcheck
// goroutine pays the wait, not the request path.
func runHealthcheckLoop(ctx context.Context) {
	probe := func() {
		for _, p := range peers {
			if p.Self {
				continue
			}
			ok, err := healthcheckPeer(ctx, p)
			if ok {
				p.markHealthy()
			} else {
				p.markUnhealthy(fmt.Sprintf("healthcheck: %v", err))
			}
		}
	}
	probe() // initial pass at startup so a dead peer is parked
	// from the first /cred call onwards rather than waiting up to
	// healthcheckInterval for the first tick.
	tick := time.NewTicker(healthcheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			probe()
		}
	}
}

func (p *peer) markSaturated() {
	p.mu.Lock()
	defer p.mu.Unlock()
	until := time.Now().Add(captchaCooldown)
	if until.After(p.saturatedUntil) {
		p.saturatedUntil = until
	}
}

func (p *peer) statusLabel() string {
	if p.Self {
		return "self"
	}
	return p.URL
}

// pickPeer advances the round-robin cursor by one and returns the
// next available (non-saturated) peer. Caller is expected to use
// it inside a loop bounded by len(peers): if every peer is
// saturated, this returns nil after a full sweep.
func pickPeer(triedMask []bool) *peer {
	for i := 0; i < len(peers); i++ {
		idx := int(rrCursor.Add(1)-1) % len(peers)
		if triedMask[idx] {
			continue
		}
		if !peers[idx].isAvailable() {
			continue
		}
		triedMask[idx] = true
		return peers[idx]
	}
	return nil
}

// forwardToPeer POSTs to peer.URL + /internal/cred with the link.
// On 429 / X-Captcha-Self-Saturated=1 it returns the saturated flag
// so the master can mark the peer for cooldown. On other errors the
// returned saturated=false leaves the peer in rotation (transient
// failures shouldn't ban the peer for 60 s).
func forwardToPeer(ctx context.Context, p *peer, link string, identity ClientIdentity) (*credResponse, bool, error) {
	body, _ := json.Marshal(credRequest{
		Link:      link,
		UserAgent: identity.UserAgent,
		Cookies:   identity.Cookies,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", p.URL+"/internal/cred", bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Key)

	resp, err := peerHTTPClient.Do(req)
	if err != nil {
		// Any transport-level failure (connection refused, context
		// canceled mid-request, EOF before headers) is signal that
		// the peer is dead or hung. Mark it unhealthy so subsequent
		// /cred calls skip it without paying the timeout again — the
		// next healthcheck tick will flip it back on recovery.
		p.markUnhealthy(fmt.Sprintf("transport: %v", err))
		return nil, false, fmt.Errorf("call peer %s: %w", p.URL, err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	saturated := resp.Header.Get("X-Captcha-Self-Saturated") == "1" || resp.StatusCode == http.StatusTooManyRequests

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, true, fmt.Errorf("peer %s saturated", p.URL)
	}
	if resp.StatusCode != http.StatusOK {
		var errBody errorResponse
		_ = json.Unmarshal(rawBody, &errBody)
		msg := errBody.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, saturated, fmt.Errorf("peer %s: %s", p.URL, msg)
	}

	var cr credResponse
	if err := json.Unmarshal(rawBody, &cr); err != nil {
		return nil, saturated, fmt.Errorf("peer %s decode: %w", p.URL, err)
	}
	return &cr, saturated, nil
}
