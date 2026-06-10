// warp_dialer.go — Cloudflare WARP egress setup notes + the
// /stats-side status snapshot. The actual SO_BINDTODEVICE binding
// moved into outbound.go's unified egress pool — a WARP interface
// is now just one entry in that pool alongside every direct IPv4
// the host owns, so successive VK requests can round-robin between
// WARP and the box's own public IPs instead of all going one or
// the other way.
//
// Operational model (unchanged from when this file was the binding
// path):
//   1. Operator runs wgcf (https://github.com/ViRb3/wgcf) to obtain
//      free WARP credentials, gets a WireGuard config file. The
//      cluster workflow does this automatically — see
//      scripts/install-warp.sh.
//   2. The interface comes up via wg-quick with `Table = off` in the
//      [Interface] block so it doesn't install default routes — we
//      don't want WARP eating all outbound traffic from this host,
//      only specific sockets captcha-service rotates onto it.
//   3. captcha-service runs with WARP_INTERFACE=wgcf in its env.
//      initEgressPool sees that env, appends an egressEntry with
//      Iface=wgcf to the pool, and every Nth outbound Dial gets
//      SO_BINDTODEVICE'd to it.
//
// SO_BINDTODEVICE requires CAP_NET_RAW. The systemd unit at
// deploy/captcha-service.service grants it unconditionally —
// DynamicUser=yes runs the process as an ephemeral non-root user
// which has no privileges by default.

package main

import "os"

// warpInterface is the configured WARP iface name, retained at
// package level so warpStatus() can report it without re-reading env.
// The actual binding logic lives in outbound.go::egressEntry; this
// var exists purely for the /stats endpoint and startup-banner log.
var warpInterface = os.Getenv("WARP_INTERFACE")

// warpStatus is for the /stats endpoint and startup log.
func warpStatus() string {
	if warpInterface == "" {
		return "off"
	}
	return "on:" + warpInterface
}
