package main

// vk_zone.go — pin every VK-facing hostname to a single DNS zone.
//
// Why: some mobile operators run a captive whitelist that admits vk.com and
// its API subdomains but drops the .ru / .me spellings of the same backends.
// The hosts are interchangeable — api.vk.com, api.vk.ru and api.vk.me all
// resolve to one address pool (87.240.129.140, 87.240.137.130, .206, .207,
// .208, 87.240.139.193, 87.240.190.70, .75, 93.186.225.205) and answer the
// same methods — so which spelling we send is purely an SNI/Host choice, and
// on a whitelisted network it is the difference between working and not.
//
// VK gates anonymous flows per (FQDN, method, client_id), so the FQDN is NOT
// cosmetic to VK's anti-bot: a method that is captcha-free on one spelling can
// be gated on another. As of 2026-08-11 auth.getAnonymToken and
// messages.getCallPreview behave identically on api.vk.me and api.vk.com for
// client_id 8093730 (verified: same anon token shape, same error_code 954 on a
// bad link, no error_code 14). If VK ever splits them, -vk-zone native puts
// every host back to the spelling upstream uses.
//
// calls.okcdn.ru is deliberately absent from the rewrite table. VK Calls' TURN
// signalling is Odnoklassniki infrastructure and has no .com equivalent:
// okcdn.com and calls.okcdn.com resolve to unrelated AWS Global Accelerator
// addresses (13.248.169.48, 76.223.54.146) and fail TLS with
// "unrecognized name", i.e. they are somebody else's parked domain. There is
// nothing to point at, so steps 4-5 of the VK Calls chain stay on .ru whatever
// zone is selected.

import "fmt"

const (
	// vkZoneCom rewrites every VK host to its .com spelling.
	vkZoneCom = "com"
	// vkZoneNative leaves hosts exactly as upstream spells them.
	vkZoneNative = "native"
)

// vkZone is the process-wide zone selection, set once from -vk-zone before any
// VK request is issued. Defaults to .com: it is the spelling most likely to
// survive an operator whitelist, and is equivalent to the others on VK's side.
var vkZone = vkZoneCom

// vkComZone maps each VK hostname we send to its .com spelling. Hosts already
// in .com are listed as identities so vkHost can distinguish "known host, no
// rewrite needed" from "unknown host" — an unknown host is a caller bug and
// panicking in tests is better than silently shipping the wrong SNI.
var vkComZone = map[string]string{
	"api.vk.com":   "api.vk.com",
	"api.vk.ru":    "api.vk.com",
	"api.vk.me":    "api.vk.com",
	"id.vk.com":    "id.vk.com",
	"id.vk.ru":     "id.vk.com",
	"login.vk.com": "login.vk.com",
	"login.vk.ru":  "login.vk.com",
	"m.vk.com":     "m.vk.com",
	"m.vk.ru":      "m.vk.com",
	"vk.com":       "vk.com",
	"vk.ru":        "vk.com",
	"st.vk.com":    "st.vk.com",

	// Odnoklassniki — no .com equivalent exists, see the file comment.
	"calls.okcdn.ru": "calls.okcdn.ru",
}

// setVKZone validates and applies the -vk-zone selection. An unrecognised
// value returns an error so parseClientOptions can reject it rather than
// silently falling back.
func setVKZone(zone string) error {
	switch zone {
	case "", vkZoneCom:
		vkZone = vkZoneCom
	case vkZoneNative:
		vkZone = vkZoneNative
	default:
		return fmt.Errorf("invalid -vk-zone %q (want %s or %s)", zone, vkZoneCom, vkZoneNative)
	}
	return nil
}

// vkHost maps a VK hostname to the configured zone. Call sites pass the host
// upstream uses; in native mode they get it straight back.
func vkHost(host string) string {
	if vkZone == vkZoneNative {
		return host
	}
	if mapped, ok := vkComZone[host]; ok {
		return mapped
	}
	// Not a host we know how to move. Returning it unchanged keeps the request
	// working; the zone table is the thing to fix.
	return host
}

// vkAPIHost is the API FQDN for the current zone. The VK Calls chain uses
// api.vk.me upstream because VK's captcha gating is per-FQDN; see the file
// comment for why .com is equivalent today.
func vkAPIHost() string { return vkHost("api.vk.me") }

// okCallsHost is the Odnoklassniki TURN-signalling FQDN. It is not zone
// -dependent — there is no .com spelling of it — and exists as a function so
// the call sites read consistently with the rest and so the "this one cannot
// move" fact lives in exactly one place.
func okCallsHost() string { return "calls.okcdn.ru" }
