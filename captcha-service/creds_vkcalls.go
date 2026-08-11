// SPDX-License-Identifier: MIT
//
// creds_vkcalls.go — VK Calls captcha-free anon-join flow.
//
// Ported from WINGS-N/vk-turn-proxy's client/creds_vkcalls.go, which in turn
// credits anton48/vk-turn-proxy-ios commit 05583b6 (reverse-engineered from
// the VK Calls iOS app). Adapted to captcha-service: server-side egress pool,
// ClientIdentity forwarding, our tls-client factory.
//
// WHY THIS EXISTS — the whole reason the cluster was failing:
//
// VK gates anonymous flows per (FQDN, method, client_id) tuple. Our legacy
// bootstrap uses:
//
//	host:       api.vk.com / login.vk.com
//	client_id:  6287487
//	auth ep:    login.vk.com/?act=get_anonym_token
//	call ep:    /method/calls.getAnonymousToken
//
// VK captcha-gated calls.getAnonymousToken on that client_id. No amount of
// captcha solving, IP rotation or WARP egress fixes that — the gate is on the
// method, and every solve attempt just burns rate-limit budget until the
// source IP is cooked (which is exactly the ERROR_LIMIT / status:ERROR
// spiral in the cluster journals).
//
// The VK Calls app uses a completely different surface:
//
//	host:       api.vk.me                            (different FQDN)
//	client_id:  8093730  (VK Connect public app_id)  (different app)
//	auth ep:    /method/auth.getAnonymToken
//	param:      anonymous_token=                     (not access_token=)
//	api ver:    v=5.276
//	call ep:    /method/messages.getAnonymCallToken   (not calls.getAnonymousToken)
//
// That tuple is captcha-free. Steps 4-5 (OK auth.anonymLogin +
// vchat.joinConversationByLink) are shared with the legacy flow.
//
// getCreds tries this path first and falls through to the legacy
// captcha-solving flow on any error, so the v2 solver + headless escalation
// remain the safety net for when VK eventually gates this path too.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	neturl "net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
)

const (
	// vkConnectClientID is VK Connect's public app_id (the vk8093730:// scheme
	// in VK Calls). No client_secret required; the anon token it mints carries
	// an app_id:8093730 claim that passes messages.getAnonymCallToken without
	// a captcha gate.
	vkConnectClientID = "8093730"
	// vkCallsAPIHost is the FQDN VK Calls uses. Same backend as api.vk.com but
	// VK gates per FQDN, so the captcha rules differ.
	vkCallsAPIHost = "api.vk.me"
	// vkCallsAPIVersion matches what the VK Calls iOS app sends.
	vkCallsAPIVersion = "5.276"
)

// getCredsViaVKCalls fetches TURN credentials over the captcha-free VK Calls
// surface. Returns (user, pass, addresses, lifetime, error). Any error —
// including an unexpected captcha gate — tells the caller to fall back to the
// legacy captcha-solving flow.
func getCredsViaVKCalls(ctx context.Context, link string, identity ClientIdentity) (string, string, []string, time.Duration, error) {
	// Pick a profile from the family the client's UA claims so the uTLS
	// ClientHello still matches the User-Agent we put on the wire; see
	// identity.go::profileForClientUA.
	profile := getRandomProfile()
	if identity.UserAgent != "" {
		profile = profileForClientUA(identity.UserAgent)
	}
	cookieHeader := identity.CookieHeader()

	name := generateName()
	deviceID := uuid.New().String()
	linkURL := neturl.QueryEscape("https://vk.com/call/join/" + link)
	nameEnc := neturl.QueryEscape(name)

	client := newCaptchaClient(profile)

	log.Printf("vkcalls: identity - name: %s, device_id: %s, client-identity=%v",
		name, deviceID, !identity.Empty())

	// doRequest issues a POST with no body; VK/OK read every parameter from the
	// URL. Headers are the minimal set the NATIVE VK Calls app sends — notably
	// no Origin/Referer, which would imitate a WebView. VK Calls is a native
	// client and the mismatch is a fingerprint tell.
	doRequest := func(url string) (map[string]interface{}, error) {
		req, reqErr := fhttp.NewRequest("POST", url, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		req = withCaptchaCtx(ctx, req)
		req.Header.Set("User-Agent", profile.UserAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
		if cookieHeader != "" {
			req.Header.Set("Cookie", cookieHeader)
		}

		httpResp, doErr := client.Do(req)
		if doErr != nil {
			return nil, doErr
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("vkcalls: close body: %s", closeErr)
			}
		}()
		body, readErr := io.ReadAll(httpResp.Body)
		if readErr != nil {
			return nil, readErr
		}
		var resp map[string]interface{}
		if jsonErr := json.Unmarshal(body, &resp); jsonErr != nil {
			return nil, fmt.Errorf("unmarshal (HTTP %d): %w, body: %s",
				httpResp.StatusCode, jsonErr, vkcallsTruncate(string(body), 200))
		}
		return resp, nil
	}

	// Step 1: auth.getAnonymToken -> anonymous_token JWT.
	step1URL := fmt.Sprintf(
		"https://%s/method/auth.getAnonymToken?v=%s&client_id=%s&link=%s&device_id=%s&anonymName=%s&lang=en",
		vkCallsAPIHost, vkCallsAPIVersion, vkConnectClientID, linkURL, deviceID, nameEnc,
	)
	resp1, err := doRequest(step1URL)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step1 (auth.getAnonymToken): %w", err)
	}
	anonymToken, err := vkcallsExtractStr(resp1, "response", "token")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step1 parse: %w (resp: %s)", err, vkcallsTruncResp(resp1))
	}
	anonymTokenEnc := neturl.QueryEscape(anonymToken)
	log.Printf("vkcalls: step1 OK, anonymous_token (%d chars)", len(anonymToken))

	// Step 2: messages.getCallPreview -> user_id + secret.
	step2URL := fmt.Sprintf(
		"https://%s/method/messages.getCallPreview?v=%s&anonymous_token=%s&device_id=%s&extended=1&fields=first_name,last_name,photo_200&lang=en&link=%s",
		vkCallsAPIHost, vkCallsAPIVersion, anonymTokenEnc, deviceID, linkURL,
	)
	resp2, err := doRequest(step2URL)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step2 (messages.getCallPreview): %w", err)
	}
	if sid := vkcallsCaptchaSID(resp2); sid != "" {
		return "", "", nil, 0, fmt.Errorf("vkcalls step2: captcha gate appeared (sid=%s), VK closed messages.getCallPreview", sid)
	}
	userIDFloat, err := vkcallsExtractFloat(resp2, "response", "user_id")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step2 parse user_id: %w (resp: %s)", err, vkcallsTruncResp(resp2))
	}
	userIDStr := fmt.Sprintf("%.0f", userIDFloat)
	secret, err := vkcallsExtractStr(resp2, "response", "secret")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step2 parse secret: %w", err)
	}
	log.Printf("vkcalls: step2 OK, user_id=%s, secret (%d chars)", userIDStr, len(secret))

	// Step 3: messages.getAnonymCallToken -> OK anonymToken. This is the method
	// VK captcha-gated on the legacy path; VK Connect passes it captcha-free.
	step3URL := fmt.Sprintf(
		"https://%s/method/messages.getAnonymCallToken?v=%s&anonymous_token=%s&device_id=%s&link=%s&name=%s&user_id=%s&secret=%s&lang=en",
		vkCallsAPIHost, vkCallsAPIVersion, anonymTokenEnc, deviceID, linkURL,
		nameEnc, userIDStr, neturl.QueryEscape(secret),
	)
	resp3, err := doRequest(step3URL)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step3 (messages.getAnonymCallToken): %w", err)
	}
	if sid := vkcallsCaptchaSID(resp3); sid != "" {
		return "", "", nil, 0, fmt.Errorf("vkcalls step3: captcha gate appeared (sid=%s), VK closed messages.getAnonymCallToken", sid)
	}
	okAnonymToken, err := vkcallsExtractStr(resp3, "response", "token")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step3 parse: %w (resp: %s)", err, vkcallsTruncResp(resp3))
	}
	log.Printf("vkcalls: step3 OK, OK anonymToken (%d chars)", len(okAnonymToken))

	// Step 4: OK auth.anonymLogin -> session_key. Same OK endpoint and shape as
	// the legacy flow.
	okDeviceID := uuid.New().String()
	step4URL := "https://calls.okcdn.ru/fb.do?session_data=" +
		neturl.QueryEscape(fmt.Sprintf(
			`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, okDeviceID,
		)) +
		"&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA"
	resp4, err := doRequest(step4URL)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step4 (auth.anonymLogin): %w", err)
	}
	sessionKey, err := vkcallsExtractStr(resp4, "session_key")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step4 parse: %w (resp: %s)", err, vkcallsTruncResp(resp4))
	}
	log.Printf("vkcalls: step4 OK, OK session_key (%d chars)", len(sessionKey))

	// Step 5: vchat.joinConversationByLink -> TURN credentials.
	step5URL := fmt.Sprintf(
		"https://calls.okcdn.ru/fb.do?joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s",
		link, okAnonymToken, sessionKey,
	)
	resp5, err := doRequest(step5URL)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("vkcalls step5 (vchat.joinConversationByLink): %w", err)
	}
	turnServer, ok := resp5["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", nil, 0, fmt.Errorf("vkcalls step5: missing turn_server (resp: %s)", vkcallsTruncResp(resp5))
	}
	user, _ := turnServer["username"].(string)
	pass, _ := turnServer["credential"].(string)
	if user == "" || pass == "" {
		return "", "", nil, 0, fmt.Errorf("vkcalls step5: incomplete turn_server credentials")
	}
	addresses := vkcallsParseTURNAddresses(turnServer)
	if len(addresses) == 0 {
		return "", "", nil, 0, fmt.Errorf("vkcalls step5: no valid TURN addresses parsed")
	}
	// VK tells us how long the credential is good for; prefer that over our
	// hardcoded guess. Falls back to 0 (caller applies the default) when
	// absent.
	var lifetime time.Duration
	if rawLifetime, ok := turnServer["lifetime"].(float64); ok && rawLifetime > 0 {
		lifetime = time.Duration(rawLifetime) * time.Second
	} else if rawTTL, ok := turnServer["ttl"].(float64); ok && rawTTL > 0 {
		lifetime = time.Duration(rawTTL) * time.Second
	}

	log.Printf("vkcalls: SUCCESS - username=%s, addresses (%d) %v, lifetime=%v",
		user, len(addresses), addresses, lifetime)
	return user, pass, addresses, lifetime, nil
}

// vkcallsCaptchaSID returns the captcha_sid from a VK error object if the
// response carries a captcha gate (error_code 14), else "".
func vkcallsCaptchaSID(resp map[string]interface{}) string {
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		return ""
	}
	if code, _ := errObj["error_code"].(float64); code != 14 {
		return ""
	}
	sid, _ := errObj["captcha_sid"].(string)
	if sid == "" {
		sid = "unknown"
	}
	return sid
}

// vkcallsExtractStr walks resp[keys[0]][keys[1]]... and returns the leaf as a
// string.
func vkcallsExtractStr(resp map[string]interface{}, keys ...string) (string, error) {
	var cur interface{} = resp
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("expected map at key %q, got %T", k, cur)
		}
		cur = m[k]
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("expected string at end of path, got %T", cur)
	}
	return s, nil
}

// vkcallsExtractFloat is vkcallsExtractStr for numeric leaves. VK returns
// user_id as a JSON number, unmarshalled to float64.
func vkcallsExtractFloat(resp map[string]interface{}, keys ...string) (float64, error) {
	var cur interface{} = resp
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return 0, fmt.Errorf("expected map at key %q, got %T", k, cur)
		}
		cur = m[k]
	}
	f, ok := cur.(float64)
	if !ok {
		return 0, fmt.Errorf("expected float64 at end of path, got %T", cur)
	}
	return f, nil
}

// vkcallsParseTURNAddresses extracts host:port strings from turn_server.urls,
// stripping the turn:/turns: prefix and any ?query suffix.
func vkcallsParseTURNAddresses(turnServer map[string]interface{}) []string {
	urls, ok := turnServer["urls"].([]interface{})
	if !ok {
		return nil
	}
	var addrs []string
	for _, u := range urls {
		s, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(s, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// vkcallsTruncate trims s to at most n characters for compact error messages.
func vkcallsTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// vkcallsTruncResp renders a response map as a short string for error messages.
func vkcallsTruncResp(resp map[string]interface{}) string {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Sprintf("(unmarshallable: %v)", err)
	}
	return vkcallsTruncate(string(b), 300)
}
