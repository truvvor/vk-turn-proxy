// creds.go — captcha-and-identity pipeline against VK Calls.
//
// Lifted verbatim from wireguard-apple/Sources/WireGuardKitGo/turn_proxy.go.
// Keep changes in sync when the iOS side gets fixes — eventually the
// shared logic should move into a third Go package both consume, but
// for V1 we copy.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type getCredsFunc func(context.Context, string, ClientIdentity) (string, string, []string, time.Duration, error)

// vkCallsBypassEnabled gates the captcha-free VK Calls path (see
// creds_vkcalls.go). On by default — it's the only path that currently gets
// past VK's captcha gate on calls.getAnonymousToken. Set VKCALLS_BYPASS=0 to
// force the legacy captcha-solving flow, e.g. to test the solvers.
var vkCallsBypassEnabled = true

// Path counters for /stats, so the operator can see at a glance whether the
// captcha-free path is still holding or VK has gated it and we're back to
// burning solver budget.
var (
	credsViaBypass atomic.Int64
	credsViaLegacy atomic.Int64
)

// getCreds obtains TURN credentials for a VK call link.
//
// Two paths, tried in order:
//
//  1. VK Calls (api.vk.me + VK Connect client_id) — captcha-free. VK gates
//     anon flows per (FQDN, method, client_id) and this tuple is currently
//     ungated, so it succeeds without touching the captcha machinery at all.
//     See creds_vkcalls.go for the full reverse-engineering notes.
//  2. Legacy (login.vk.com + api.vk.com calls.getAnonymousToken) — the
//     original flow, captcha-gated by VK since 2026-05-15. Kept as the
//     fallback so the v2 solver + headless escalation still cover us when VK
//     eventually gates path 1 too.
//
// Returns every TURN address VK handed back (the caller picks / rotates) plus
// the credential lifetime VK reported, so the caller doesn't have to guess an
// expiry.
func getCreds(ctx context.Context, link string, identity ClientIdentity) (string, string, []string, time.Duration, error) {
	if vkCallsBypassEnabled {
		user, pass, addrs, lifetime, err := getCredsViaVKCalls(ctx, link, identity)
		if err == nil {
			credsViaBypass.Add(1)
			return user, pass, addrs, lifetime, nil
		}
		log.Printf("[Creds] VK Calls bypass path failed, falling back to legacy captcha flow: %v", err)
	}
	user, pass, addrs, lifetime, err := getCredsLegacy(ctx, link, identity)
	if err == nil {
		credsViaLegacy.Add(1)
	}
	return user, pass, addrs, lifetime, err
}

// sharedAuthClient — package-level so the connection pool spans the
// whole server lifetime. See F4 in the iOS-side commit history.
// customDial already carries the WARP control hook (see dns_resolver.go),
// so VK token-acquisition POSTs egress via WARP when WARP_INTERFACE is
// configured.
var sharedAuthClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext:         customDial,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

// getCredsLegacy is the original login.vk.com + calls.getAnonymousToken flow.
// VK captcha-gated calls.getAnonymousToken, so this path routes through
// solveVkCaptcha (fast Go solver → headless Chromium escalation). Retained as
// the fallback behind the VK Calls bypass; see getCreds.
func getCredsLegacy(ctx context.Context, link string, identity ClientIdentity) (resUser string, resPass string, resAddrs []string, resLifetime time.Duration, resErr error) {
	profile := getRandomProfile()
	name := generateName()
	escapedName := neturl.QueryEscape(name)

	effectiveUA := profile.UserAgent
	if identity.UserAgent != "" {
		effectiveUA = identity.UserAgent
	}
	cookieHeader := identity.CookieHeader()

	log.Printf("Connecting - Name: %s | UA: %s | client-identity=%v",
		name, effectiveUA, !identity.Empty())

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", effectiveUA)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if cookieHeader != "" {
			req.Header.Set("Cookie", cookieHeader)
		}

		httpResp, err := sharedAuthClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			// When VK / a WAF in front of it serves an HTML block
			// page (typical first symptom of source-IP rate-limit
			// or anti-bot tripping) the body starts with '<' and
			// json.Unmarshal returns the unhelpful "invalid
			// character '<' looking for beginning of value". Log
			// the first ~400 bytes so the operator can tell at a
			// glance whether it was a block page, a 5xx HTML, etc.
			// rather than just "body wasn't JSON".
			snip := string(body)
			if len(snip) > 400 {
				snip = snip[:400] + "...(truncated)"
			}
			log.Printf("[Auth] %s returned non-JSON body (HTTP %d, %d bytes): %s",
				url, httpResp.StatusCode, len(body), snip)
			return nil, fmt.Errorf("non-JSON response from %s (HTTP %d): %w",
				url, httpResp.StatusCode, err)
		}

		return resp, nil
	}

	var resp map[string]interface{}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("get TURN creds error (bad JSON?): %v\n\n", resp)
			resErr = fmt.Errorf("panic in getCreds: %v", r)
		}
	}()

	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.com/?act=get_anonym_token"

	resp, err := doRequest(data, url)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("request error:%s", err)
	}

	token1 := resp["data"].(map[string]interface{})["access_token"].(string)

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	reqURL := "https://api.vk.com/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

	var token2 string
	const maxCaptchaAttempts = 3
	for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
		resp, err = doRequest(data, reqURL)
		if err != nil {
			return "", "", nil, 0, fmt.Errorf("request error:%s", err)
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			errCode, _ := errObj["error_code"].(float64)
			if errCode == 14 {
				if attempt == maxCaptchaAttempts {
					return "", "", nil, 0, fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts)
				}

				captchaErr := ParseVkCaptchaError(errObj)
				if captchaErr.IsCaptchaError() {
					log.Printf("[Captcha] Attempt %d/%d: solving...", attempt+1, maxCaptchaAttempts)

					successToken, solveErr := solveVkCaptcha(ctx, captchaErr, identity)
					if solveErr != nil {
						return "", "", nil, 0, fmt.Errorf("captcha solve error: %v", solveErr)
					}

					if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
						captchaErr.CaptchaAttempt = "1"
					}

					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s"+
						"&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s"+
						"&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
						link, escapedName, captchaErr.CaptchaSid, successToken,
						captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
					continue
				}
			}
			return "", "", nil, 0, fmt.Errorf("VK API error: %v", errObj)
		}

		token2 = resp["response"].(map[string]interface{})["token"].(string)
		break
	}

	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("request error:%s", err)
	}

	token3 := resp["session_key"].(string)

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("request error:%s", err)
	}

	turnServer := resp["turn_server"].(map[string]interface{})
	user := turnServer["username"].(string)
	pass := turnServer["credential"].(string)

	// Return every address VK offered, not just urls[0]. The client can then
	// rotate to the next one when a dial fails instead of writing off the
	// whole credential (this is the "TURN address rotation" idea from the
	// WINGS-N fork). vkcallsParseTURNAddresses is shared with the bypass path.
	addresses := vkcallsParseTURNAddresses(turnServer)
	if len(addresses) == 0 {
		return "", "", nil, 0, fmt.Errorf("legacy: no valid TURN addresses parsed")
	}

	var lifetime time.Duration
	if rawLifetime, ok := turnServer["lifetime"].(float64); ok && rawLifetime > 0 {
		lifetime = time.Duration(rawLifetime) * time.Second
	} else if rawTTL, ok := turnServer["ttl"].(float64); ok && rawTTL > 0 {
		lifetime = time.Duration(rawTTL) * time.Second
	}

	return user, pass, addresses, lifetime, nil
}
