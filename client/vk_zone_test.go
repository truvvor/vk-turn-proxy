package main

import "testing"

// restoreZone resets the process-wide zone after a test mutates it.
func restoreZone(t *testing.T) {
	t.Helper()
	prev := vkZone
	t.Cleanup(func() { vkZone = prev })
}

func TestSetVKZone(t *testing.T) {
	restoreZone(t)
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "com", want: vkZoneCom},
		{in: "", want: vkZoneCom}, // empty means "unset", not "invalid"
		{in: "native", want: vkZoneNative},
		{in: "ru", wantErr: true},
		{in: "COM", wantErr: true}, // options.go lowercases before calling
	} {
		err := setVKZone(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("setVKZone(%q) = nil, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("setVKZone(%q) = %v, want nil", tc.in, err)
			continue
		}
		if vkZone != tc.want {
			t.Errorf("setVKZone(%q): vkZone = %q, want %q", tc.in, vkZone, tc.want)
		}
	}
}

func TestVKHostComZone(t *testing.T) {
	restoreZone(t)
	vkZone = vkZoneCom
	for in, want := range map[string]string{
		"api.vk.me":    "api.vk.com",
		"api.vk.ru":    "api.vk.com",
		"api.vk.com":   "api.vk.com",
		"id.vk.ru":     "id.vk.com",
		"login.vk.ru":  "login.vk.com",
		"m.vk.ru":      "m.vk.com",
		"vk.ru":        "vk.com",
		"unknown.host": "unknown.host", // pass through, never rewrite blindly
	} {
		if got := vkHost(in); got != want {
			t.Errorf("vkHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVKHostNativeZoneIsIdentity(t *testing.T) {
	restoreZone(t)
	vkZone = vkZoneNative
	for in := range vkComZone {
		if got := vkHost(in); got != in {
			t.Errorf("native vkHost(%q) = %q, want unchanged", in, got)
		}
	}
}

// calls.okcdn.ru is Odnoklassniki infrastructure with no .com spelling
// (okcdn.com is an unrelated parked domain). It must stay put in every zone,
// otherwise the VK Calls chain would break at step 4 with a TLS error instead
// of merely being unreachable on a whitelisted network.
func TestOKCallsHostIsZoneIndependent(t *testing.T) {
	restoreZone(t)
	for _, z := range []string{vkZoneCom, vkZoneNative} {
		vkZone = z
		if got := okCallsHost(); got != "calls.okcdn.ru" {
			t.Errorf("zone %s: okCallsHost() = %q, want calls.okcdn.ru", z, got)
		}
		if got := vkHost("calls.okcdn.ru"); got != "calls.okcdn.ru" {
			t.Errorf("zone %s: vkHost(calls.okcdn.ru) = %q, want unchanged", z, got)
		}
	}
}

func TestVKAPIHostFollowsZone(t *testing.T) {
	restoreZone(t)
	vkZone = vkZoneCom
	if got := vkAPIHost(); got != "api.vk.com" {
		t.Errorf("com zone: vkAPIHost() = %q, want api.vk.com", got)
	}
	vkZone = vkZoneNative
	if got := vkAPIHost(); got != "api.vk.me" {
		t.Errorf("native zone: vkAPIHost() = %q, want api.vk.me", got)
	}
}
