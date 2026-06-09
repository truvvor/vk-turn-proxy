// SPDX-License-Identifier: MIT
//
// manual_captcha_server_stubs.go — server-side replacements for the
// helpers manual_captcha.go expects from the iOS client tree. On the
// captcha-service we don't run inside iSH, don't persist a browser
// profile to disk, and don't expose a debug toggle, so the helpers
// degenerate to no-ops / pass-through.

package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
)

// isDebug gates the noisy [Captcha Proxy] traces in manual_captcha.go.
// We expose it as an atomic so toggling it (e.g. from a future env or
// runtime endpoint) is safe; the gated logs read it on every fire.
var isDebug atomic.Bool

// wrapISHListener is a no-op on the server: there's no Apple iSH
// short-lived listener semantics to compensate for.
func wrapISHListener(l net.Listener) (net.Listener, error) {
	return l, nil
}

// SavedProfile mirrors the client-side struct but server-side has no
// disk-persistence target; we keep the type so manual_captcha.go's
// MITM-proxy fingerprint-capture path compiles. SaveProfileToDisk is
// a no-op — the server generates fresh profiles per solve and doesn't
// reuse them across runs.
type SavedProfile struct {
	Profile    Profile
	DeviceJSON string
	BrowserFp  string
}

func SaveProfileToDisk(_ SavedProfile) error { return nil }

// captchaProxyDialer returns the dnsdialer the MITM reverse-proxy uses
// to reach id.vk.ru. We hand it the same VK-friendly resolvers
// (Yandex DNS first because it routes faster from RU-adjacent VPSes,
// then Google + Cloudflare) the Moroka8 client uses, with the same
// strategy + cache shape. One per process — cheap to share, the
// dialer is goroutine-safe.
var captchaProxyDialerOnce sync.Once
var captchaProxyDialerInst *dnsdialer.Dialer

func captchaProxyDialer() *dnsdialer.Dialer {
	captchaProxyDialerOnce.Do(func() {
		captchaProxyDialerInst = dnsdialer.New(
			dnsdialer.WithResolvers(
				"77.88.8.8:53", "77.88.8.1:53",
				"8.8.8.8:53", "8.8.4.4:53",
				"1.1.1.1:53", "1.0.0.1:53",
			),
			dnsdialer.WithStrategy(dnsdialer.Fallback{}),
			dnsdialer.WithCache(100, 10*time.Hour, 10*time.Hour),
		)
	})
	return captchaProxyDialerInst
}
