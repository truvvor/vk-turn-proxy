// captcha_client.go — server-side equivalent of the iOS-side
// captcha_client.go. Builds a Safari iOS 18.0 TLS+HTTP/2 impersonator
// for VK API calls. See the iOS file for the full rationale of why
// we use bogdanfinn/tls-client + fhttp instead of net/http.
//
// Server-side specific: the underlying net.Dialer is constructed via
// newEgressNetDialer(), which picks one entry from the egress pool
// (direct IPs auto-discovered from interfaces + WARP iface when set)
// and bakes its LocalAddr + Control into the dialer. vk_captcha.go
// makes a fresh captcha client per /cred attempt, so successive
// attempts land on different source IPs / WARP. See outbound.go.

package main

import (
	"context"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tlsclient "github.com/bogdanfinn/tls-client"
	tlsprofiles "github.com/bogdanfinn/tls-client/profiles"
)

// Header / pseudo-header order Safari iOS 18 emits. Order is a
// classifier signal even though HTTP/2 is order-insensitive in the
// spec. Mirror of the iOS-side list — keep in sync.
var safariHeaderOrder = []string{
	"host",
	"accept",
	"sec-fetch-site",
	"accept-encoding",
	"sec-fetch-mode",
	"user-agent",
	"accept-language",
	"sec-fetch-dest",
	"referer",
	"priority",
	"cookie",
	"content-type",
	"content-length",
	"origin",
}

var safariPHeaderOrder = []string{
	":method",
	":scheme",
	":path",
	":authority",
}

// chromiumHeaderOrder / chromiumPHeaderOrder mirror what Chromium engines
// (Chrome, Edge) put on the wire. Sending Safari's ordering under a Chrome UA
// and Chrome ClientHello would reintroduce exactly the contradiction the
// paired profiles exist to avoid, so the order follows the engine.
var chromiumHeaderOrder = []string{
	"host",
	"connection",
	"content-length",
	"sec-ch-ua-platform",
	"user-agent",
	"sec-ch-ua",
	"content-type",
	"sec-ch-ua-mobile",
	"accept",
	"origin",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"accept-language",
	"cookie",
	"priority",
}

var chromiumPHeaderOrder = []string{
	":method",
	":authority",
	":scheme",
	":path",
}

// newTLSCaptchaClient builds a client whose uTLS ClientHello matches the
// profile's advertised browser. This used to pin Safari_IOS_18_0 for every
// request regardless of the UA in play, which made the entire fleet a single
// TLS fingerprint; profile.TLS now carries the pairing. See identity.go.
func newTLSCaptchaClient(profile Profile) (tlsclient.HttpClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(tlsClientProfileFor(profile)),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDisableHttp3(),
		// Egress-pool dialer: picks one entry (direct IP via LocalAddr
		// or WARP iface via SO_BINDTODEVICE) per call. tls-client
		// keeps this dialer for the lifetime of the client, so the
		// rotation happens at newCaptchaClient time — fresh choice
		// every /cred attempt. See outbound.go.
		tlsclient.WithDialer(newEgressNetDialer()),
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
}

// tlsClientProfileFor falls back to the historical Safari iOS ClientHello only
// if a Profile was somehow built without a TLS pairing.
func tlsClientProfileFor(profile Profile) tlsprofiles.ClientProfile {
	if profile.TLS.GetClientHelloId().Client != "" {
		return profile.TLS
	}
	return tlsprofiles.Safari_IOS_18_0
}

// applyHeaderOrder sets the header ordering matching the profile's engine.
func applyHeaderOrder(req *fhttp.Request, profile Profile) {
	if profile.isChromium() {
		req.Header[fhttp.HeaderOrderKey] = chromiumHeaderOrder
		req.Header[fhttp.PHeaderOrderKey] = chromiumPHeaderOrder
		return
	}
	req.Header[fhttp.HeaderOrderKey] = safariHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = safariPHeaderOrder
}

// applyClientHints sets sec-ch-ua* only for Chromium profiles. Safari and
// Firefox never send Client Hints, so emitting them under those UAs is a tell.
func applyClientHints(req *fhttp.Request, profile Profile) {
	if !profile.isChromium() {
		return
	}
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
}

// acceptLanguageOf returns the profile's Accept-Language, defaulting to the
// value Chromium and Safari both send.
func acceptLanguageOf(profile Profile) string {
	if profile.AcceptLanguage != "" {
		return profile.AcceptLanguage
	}
	return "en-US,en;q=0.9"
}

func withCaptchaCtx(ctx context.Context, req *fhttp.Request) *fhttp.Request {
	return req.WithContext(ctx)
}
