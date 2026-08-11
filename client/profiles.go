package main

import (
	"math/rand"

	tlsprofiles "github.com/bogdanfinn/tls-client/profiles"
)

type Profile struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	// TLS is the uTLS ClientHello paired with UserAgent. Empty means the
	// caller picks; the entries that matter for VK set it explicitly, so a
	// Safari UA never rides a Chrome ClientHello.
	TLS tlsprofiles.ClientProfile
}

// iosSafariProfiles are what VK's anti-bot pipeline does NOT challenge: a
// real user opening a call link in Safari on an iPhone. Everything else in
// this file is a desktop browser, which VK does challenge.
//
// This matters most for the VK Calls path (creds_vkcalls.go), which talks to
// api.vk.me — the private API of VK's iOS Calls app. Presenting a desktop
// Chrome identity there is an obvious mismatch, and in the field it produced
// exactly that: steps 1-3 passed captcha-free, then the final join demanded
// not_robot.
//
// UA and ClientHello are paired per entry. Mirrors captcha-service/identity.go.
var iosSafariProfiles = []Profile{
	{
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1",
		TLS:       tlsprofiles.Safari_IOS_18_0,
	},
	{
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
		TLS:       tlsprofiles.Safari_IOS_18_5,
	},
	{
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
		TLS:       tlsprofiles.Safari_IOS_26_0,
	},
	{
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		TLS:       tlsprofiles.Safari_IOS_17_0,
	},
}

// getIOSSafariProfile returns a random iPhone Safari identity with its
// matching ClientHello.
func getIOSSafariProfile() Profile {
	return iosSafariProfiles[rand.Intn(len(iosSafariProfiles))]
}

// profiles contain paired User-Agent and Client Hints strings to harden bot detection.
var profile = []Profile{
	// Windows Chrome
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// Windows Edge
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Microsoft Edge";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Microsoft Edge";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// macOS Chrome
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},

	// Linux Chrome
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
}

// getRandomProfile returns a paired User-Agent and Client Hints profile.
func getRandomProfile() Profile {
	return profile[rand.Intn(len(profile))]
}
