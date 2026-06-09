// SPDX-License-Identifier: MIT
//
// client_identity.go — optional browser identity (UA + cookies) that
// the iOS client can forward to /cred so the captcha solve and the
// subsequent TURN-credential request share one browser fingerprint
// from VK's perspective. Empty identity = use the server's random
// profile (V2 behaviour, preserved for callers that don't forward).
//
// Why this exists: the success_token returned by captchaNotRobot.check
// is consumed by calls.getAnonymousToken, which VK validates against
// the same client signals (Cookie / User-Agent / IP) that performed
// the solve. If the captcha is solved by browser X and the token is
// then redeemed by browser Y on the iOS client, VK can refuse. The
// safe arrangement is to make the server-side solver mimic the same
// identity the iOS client will use post-redemption.

package main

import (
	"fmt"
	"net/http"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
)

type ClientIdentity struct {
	UserAgent string         `json:"user_agent,omitempty"`
	Cookies   []ClientCookie `json:"cookies,omitempty"`
}

type ClientCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}

func (id ClientIdentity) Empty() bool {
	return id.UserAgent == "" && len(id.Cookies) == 0
}

// CookieHeader serialises identity cookies to a single "name=value; ..."
// string for use as the Cookie request header. Empty when no cookies.
func (id ClientIdentity) CookieHeader() string {
	if len(id.Cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(id.Cookies))
	for _, c := range id.Cookies {
		if c.Name == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	return strings.Join(parts, "; ")
}

// applyToRequest sets User-Agent + Cookie on a stdlib http.Request.
// No-op when the corresponding identity field is empty so callers can
// blanket-apply without first checking.
func (id ClientIdentity) applyToRequest(req *http.Request) {
	if id.UserAgent != "" {
		req.Header.Set("User-Agent", id.UserAgent)
	}
	if h := id.CookieHeader(); h != "" {
		req.Header.Set("Cookie", h)
	}
}

// applyToFHTTPRequest is the fhttp variant for the tls-fingerprinted
// captcha client used in vk_captcha.go.
func (id ClientIdentity) applyToFHTTPRequest(req *fhttp.Request) {
	if id.UserAgent != "" {
		req.Header.Set("User-Agent", id.UserAgent)
	}
	if h := id.CookieHeader(); h != "" {
		req.Header.Set("Cookie", h)
	}
}
