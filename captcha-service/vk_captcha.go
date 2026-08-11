package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectUri             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func randomHex(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		for i := range bytes {
			bytes[i] = byte(mathrand.Intn(256))
		}
	}
	return hex.EncodeToString(bytes)
}

// newCaptchaClient returns a TLS-fingerprinted client whose uTLS ClientHello
// is paired with the profile's User-Agent (see identity.go), dialing through
// the egress pool so the socket lands on a rotating source IP / the WARP
// interface. See captcha_client.go and outbound.go.
func newCaptchaClient(profile Profile) tlsclient.HttpClient {
	c, err := newTLSCaptchaClient(profile)
	if err != nil {
		panic(fmt.Sprintf("newTLSCaptchaClient: %v", err))
	}
	return c
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	code := int(codeFloat)

	redirectUri, _ := errData["redirect_uri"].(string)
	captchaSid, _ := errData["captcha_sid"].(string)
	captchaImg, _ := errData["captcha_img"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	var sessionToken string
	if redirectUri != "" {
		if parsed, err := url.Parse(redirectUri); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	isSound, _ := errData["is_sound_captcha_available"].(bool)

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectUri:             redirectUri,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectUri != "" && e.SessionToken != ""
}

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, identity ClientIdentity) (string, error) {
	if manualCaptchaForcedMode() {
		log.Printf("[Captcha] Manual mode enabled — handing the challenge to the UI")
		return requestManualCaptcha(captchaErr.RedirectUri, 180*time.Second)
	}

	// Egress decision. The default is whatever captchaTunnelEgress
	// dictates (direct pre-handshake, tunnel post-handshake). When
	// tunnel is saturated AND direct still has budget, we override
	// and pin a physical interface (cellular / WiFi) for this attempt
	// so the request bypasses utun — that's the only way to retry
	// the direct egress after WG comes up. cellularDial falls back
	// to the system route if no usable physical interface is found.
	forceDirect := captchaTunnelEgress.Load() && tunnelSaturated() && !directSaturated()
	if forceDirect {
		log.Printf("[Captcha] tunnel egress saturated — forcing physical-interface egress")
	}

	// Bump the in-flight gauge for this egress so the UI sees an
	// increase the moment a solve starts. Released on every return
	// path via defer.
	isTunnel := markCaptchaAttemptStart(forceDirect)
	defer markCaptchaAttemptDone(isTunnel)

	// Anti-bot pacing used to live here as a 1.5-2.5 s pre-solve
	// sleep, but it was held INSIDE poolCreds' solveSlot semaphore
	// which throttles 5 in-flight solves. The slot now covers only
	// the real PoW + HTTP work; pacing has been moved to poolCreds'
	// pre-slot wait so the same wall-clock delay overlaps the slot
	// queue instead of serialising inside it.

	log.Printf("[Captcha] Solving Not Robot Captcha...")

	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Honour the iOS client's UA across the Go-solver HTTP path so
	// fetchPowInput / componentDone / check all advertise the same browser
	// the success_token will later be redeemed on — but pick a profile from
	// the family that UA claims, so the ClientHello still matches it.
	profile := getRandomProfile()
	if identity.UserAgent != "" {
		profile = profileForClientUA(identity.UserAgent)
	}
	client := newCaptchaClient(profile)

	powInput, difficulty, htmlSettings, err := fetchPowInput(ctx, client, profile, captchaErr.RedirectUri, identity)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}

	log.Printf("[Captcha] PoW input: %s, difficulty: %d, htmlSettings=%v", powInput, difficulty, htmlSettings != nil)

	hash := solvePoW(powInput, difficulty)
	log.Printf("[Captcha] PoW solved: hash=%s", hash)

	successToken, err := callCaptchaNotRobot(ctx, client, profile, sessionToken, hash, htmlSettings, isTunnel, identity)
	if err == nil {
		log.Printf("[Captcha] Success! Got success_token")
		return successToken, nil
	}

	// Fast Go solver failed (almost always VK returned `checkbox status:
	// BOT` then the slider couldn't recover either). If the operator has
	// chrome-headless-shell installed and HEADLESS_CAPTCHA=1, escalate
	// to the real-browser MITM solver — it runs VK's anti-bot JS for
	// real and beats `BOT` verdicts that the plain-HTTP solver can't.
	//
	// EXCEPT when the Go-side already reported a session-terminal VK
	// status (ERROR_LIMIT / status: ERROR). On the SAME session token,
	// VK won't accept a do-over from the headless browser either — it'll
	// burn ~2 s on chromedp startup just to get the same status back.
	// Skip straight to the cluster rotate path so a fresh peer (or a
	// fresh session after captchaCooldown) handles the actual solve.
	if headlessCaptchaEnabled {
		errStr := err.Error()
		if strings.Contains(errStr, "ERROR_LIMIT") || strings.Contains(errStr, "status: ERROR") {
			log.Printf("[Captcha] go-solver hit terminal VK status (%v) — skipping headless (same session would also fail), marking saturated", err)
			markCaptchaSaturated(isTunnel)
			return "", fmt.Errorf("captchaNotRobot API failed (session terminal): %w", err)
		}
		log.Printf("[Captcha] go-solver failed (%v) — escalating to headless MITM solver", err)
		token, hErr := solveCaptchaViaProxy(captchaErr.RedirectUri, captchaProxyDialer(), identity)
		if hErr == nil {
			log.Printf("[Captcha] Success! Got success_token via headless")
			return token, nil
		}
		// When the headless MITM bailed out fast on a VK terminal
		// status, mark this egress saturated so the cluster master
		// rotates to the next peer immediately rather than burning
		// the rest of the retry chain on the same dead IP. The
		// solveCaptchaViaProxy err message carries the upstream
		// status verbatim ("headless captcha terminal: ERROR_LIMIT"
		// / "headless captcha terminal: ERROR").
		if strings.Contains(hErr.Error(), "ERROR_LIMIT") || strings.Contains(hErr.Error(), "terminal:") {
			markCaptchaSaturated(isTunnel)
		}
		return "", fmt.Errorf("captchaNotRobot API failed: %w; headless fallback: %w", err, hErr)
	}

	return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
}

func fetchPowInput(ctx context.Context, client tlsclient.HttpClient, profile Profile, redirectUri string, identity ClientIdentity) (string, int, map[string]interface{}, error) {
	req, err := fhttp.NewRequest("GET", redirectUri, nil)
	if err != nil {
		return "", 0, nil, err
	}
	req = withCaptchaCtx(ctx, req)

	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", acceptLanguageOf(profile))
	// Client Hints are Chromium-only; applyClientHints is a no-op under
	// Safari / Firefox profiles, which never send sec-ch-ua*.
	applyClientHints(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	if h := identity.CookieHeader(); h != "" {
		req.Header.Set("Cookie", h)
	}
	applyHeaderOrder(req, profile)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, nil, err
	}

	html := string(body)

	// Parse PoW input
	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return "", 0, nil, fmt.Errorf("powInput not found in captcha HTML")
	}
	powInput := powInputMatch[1]

	// Parse difficulty
	diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
	diffMatch := diffRe.FindStringSubmatch(html)
	difficulty := 2
	if len(diffMatch) >= 2 {
		if d, err := strconv.Atoi(diffMatch[1]); err == nil {
			difficulty = d
		}
	}

	// Parse window.init for slider captcha settings
	var htmlSettings map[string]interface{}
	initRe := regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?\})\s*;\s*window\.lang`)
	if initMatch := initRe.FindStringSubmatch(html); len(initMatch) >= 2 {
		var initPayload map[string]interface{}
		if err := json.Unmarshal([]byte(initMatch[1]), &initPayload); err == nil {
			if data, ok := initPayload["data"].(map[string]interface{}); ok {
				htmlSettings = map[string]interface{}{"response": data}
				log.Printf("[Captcha] Parsed window.init htmlSettings")
			}
		}
	}

	// Stash not_robot_captcha.js URL so the caller can fetch debug_info
	// dynamically. See captcha_debug_info.go.
	scriptURL := extractScriptURL(html)
	if scriptURL != "" {
		if htmlSettings == nil {
			htmlSettings = map[string]interface{}{}
		}
		htmlSettings["_scriptURL"] = scriptURL
	}

	return powInput, difficulty, htmlSettings, nil
}

func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)

	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])

		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

func callCaptchaNotRobot(ctx context.Context, client tlsclient.HttpClient, profile Profile, sessionToken, hash string, htmlSettings map[string]interface{}, isTunnel bool, identity ClientIdentity) (string, error) {
	cookieHeader := identity.CookieHeader()
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		requestURL := "https://api.vk.com/method/" + method + "?v=5.131"

		req, err := fhttp.NewRequest("POST", requestURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req = withCaptchaCtx(ctx, req)

		req.Header.Set("User-Agent", profile.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", acceptLanguageOf(profile))
		applyClientHints(req, profile)
		req.Header.Set("Origin", "https://id.vk.com")
		req.Header.Set("Referer", "https://id.vk.com/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")
		if cookieHeader != "" {
			req.Header.Set("Cookie", cookieHeader)
		}
		applyHeaderOrder(req, profile)

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		return resp, nil
	}

	domain := "vk.com"
	baseParams := fmt.Sprintf("session_token=%s&domain=%s&adFp=&access_token=",
		url.QueryEscape(sessionToken), url.QueryEscape(domain))

	// Step 1: settings
	log.Printf("[Captcha] Step 1/4: settings")
	settingsResp, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	time.Sleep(time.Duration(100+mathrand.Intn(100)) * time.Millisecond)

	// Step 2: componentDone
	log.Printf("[Captcha] Step 2/4: componentDone")

	// crypto/rand-backed 32-hex-char browser fingerprint (v2).
	browserFp := randomHex(16)

	// v2 device shape: fixed desktop Chrome 8-core/1080p. See iOS-side
	// captcha-vk for full rationale.
	const (
		screenW = 1920
		screenH = 1080
	)
	deviceMap := map[string]interface{}{
		"screenWidth":             screenW,
		"screenHeight":            screenH,
		"screenAvailWidth":        screenW,
		"screenAvailHeight":       screenH,
		"innerWidth":              screenW,
		"innerHeight":             951,
		"devicePixelRatio":        1,
		"language":                "en-US",
		"languages":               []string{"en-US", "en"},
		"webdriver":               false,
		"hardwareConcurrency":     8,
		"notificationsPermission": "denied",
	}
	deviceBytes, _ := json.Marshal(deviceMap)

	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s",
		browserFp, url.QueryEscape(string(deviceBytes)))

	_, err = vkReq("captchaNotRobot.componentDone", componentDoneData)
	if err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	time.Sleep(time.Duration(1500+mathrand.Intn(1000)) * time.Millisecond)

	// Step 3: checkbox check
	log.Printf("[Captcha] Step 3/4: check (checkbox)")

	type Point struct {
		X int   `json:"x"`
		Y int   `json:"y"`
		T int64 `json:"t"`
	}
	var cursor []Point
	startX, startY := screenW/2+mathrand.Intn(200)-100, screenH/2+mathrand.Intn(200)-100
	startTime := time.Now().Add(-300 * time.Millisecond).UnixMilli()

	pointsCount := 4 + mathrand.Intn(5)
	for i := 0; i < pointsCount; i++ {
		cursor = append(cursor, Point{
			X: startX,
			Y: startY,
			T: startTime + int64(i*20+mathrand.Intn(10)),
		})
		startX += mathrand.Intn(30) - 15
		startY += mathrand.Intn(30) - 15
	}
	cursorBytes, _ := json.Marshal(cursor)

	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	// Dynamic debug_info from not_robot_captcha.js. See iOS-side
	// captcha_debug_info.go for the rationale; fallback to legacy
	// constant when fetch fails.
	scriptURL, _ := htmlSettings["_scriptURL"].(string)
	debugInfo, debugErr := fetchDebugInfo(ctx, client, profile, scriptURL)
	if debugErr != nil {
		log.Printf("[Captcha] fetchDebugInfo: %v — using legacy constant", debugErr)
		debugInfo = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}

	// v2 wire shape: all motion arrays empty including connectionDownlink.
	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
			"&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		url.QueryEscape("[]"),
		url.QueryEscape("[]"),
		url.QueryEscape("[]"),
		url.QueryEscape(string(cursorBytes)),
		url.QueryEscape("[]"),
		url.QueryEscape("[]"),
		url.QueryEscape("[]"),
		browserFp,
		hash,
		answer,
		debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}

	status, _ := respObj["status"].(string)
	showType, _ := respObj["show_captcha_type"].(string)
	log.Printf("[Captcha] checkbox status: %s show_type=%q", status, showType)

	if status == "OK" {
		successToken, ok := respObj["success_token"].(string)
		if ok && successToken != "" {
			log.Printf("[Captcha] Step 4/4: endSession")
			_, _ = vkReq("captchaNotRobot.endSession", baseParams)
			markCaptchaSuccess(isTunnel)
			return successToken, nil
		}
	}

	if status == "ERROR_LIMIT" {
		markCaptchaSaturated(isTunnel)
		return "", fmt.Errorf("captchaNotRobot.check ERROR_LIMIT (no slider fallback under rate-limit)")
	}

	// v2 routing: only try slider on explicit BOT status with slider show_type.
	sliderEligible := status == "BOT" && (showType == "" || showType == "slider")
	if !sliderEligible {
		return "", fmt.Errorf("captchaNotRobot.check non-OK status=%q show_type=%q", status, showType)
	}

	log.Printf("[Captcha] Checkbox status=BOT show_type=%q, switching to slider", showType)

	// Use htmlSettings from the HTML page if available, otherwise use API settings
	mergedSettings := settingsResp
	if htmlSettings != nil {
		mergedSettings = htmlSettings
	}

	sliderToken, sliderErr := solveSliderCaptcha(vkReq, baseParams, browserFp, hash, debugInfo, mergedSettings, isTunnel)
	if sliderErr != nil {
		// saturation accounting now happens inside solveSliderCaptcha
		// at the exact branch (ERROR_LIMIT or unparseable_response),
		// so this caller just propagates the error.
		return "", fmt.Errorf("slider captcha also failed: %w", sliderErr)
	}

	log.Printf("[Captcha] Slider solved! endSession...")
	_, _ = vkReq("captchaNotRobot.endSession", baseParams)
	markCaptchaSuccess(isTunnel)
	return sliderToken, nil
}
