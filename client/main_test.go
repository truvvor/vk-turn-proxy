package main

import "testing"

func TestCaptchaSolveModeForAttempt(t *testing.T) {
	t.Parallel()

	t.Run("default flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, false, true)
		if !ok || mode != captchaSolveModeAuto {
			t.Fatalf("expected first attempt to use auto captcha, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(1, false, true)
		if !ok || mode != captchaSolveModeSliderPOC {
			t.Fatalf("expected second attempt to use slider POC, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(2, false, true)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected third attempt to use manual captcha, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(3, false, true); ok {
			t.Fatal("expected no fourth captcha attempt in default flow")
		}
	})

	t.Run("manual only flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, true, true)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected manual mode on first attempt, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(1, true, true); ok {
			t.Fatal("expected only one manual captcha attempt when manual mode is forced")
		}
	})

	t.Run("flow without slider poc", func(t *testing.T) {
		t.Parallel()

		mode, ok := captchaSolveModeForAttempt(0, false, false)
		if !ok || mode != captchaSolveModeAuto {
			t.Fatalf("expected auto captcha first, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = captchaSolveModeForAttempt(1, false, false)
		if !ok || mode != captchaSolveModeManual {
			t.Fatalf("expected manual captcha second when slider POC is disabled, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = captchaSolveModeForAttempt(2, false, false); ok {
			t.Fatal("expected only two attempts when slider POC is disabled")
		}
	})
}

// TestParseVkCaptchaErrorNotRobot pins the not_robot web-challenge shape.
//
// VK serves error_code 14 in two shapes and only the older one carries
// captcha_sid / captcha_img. The parser used to bail out with
// "missing captcha_sid" on the newer not_robot shape, so every such
// challenge looked like "not a captcha error" and credential acquisition
// failed with a redirect_uri sitting unused in the response.
func TestParseVkCaptchaErrorNotRobot(t *testing.T) {
	t.Parallel()

	const sessionToken = "eyJhbGciOiJIUzI1NiJ9.test"
	notRobot := map[string]interface{}{
		"error_code":         float64(14),
		"error_msg":          "Captcha need",
		"is_enabled_captcha": true,
		"redirect_uri": "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=" +
			sessionToken + "&variant=popup&blank=1",
		// deliberately no captcha_sid, no captcha_img
	}

	got := ParseVkCaptchaError(notRobot)
	if got == nil {
		t.Fatal("ParseVkCaptchaError returned nil for a not_robot challenge; " +
			"captcha_sid and captcha_img are absent in this shape and must be optional")
	}
	if !got.IsCaptchaError() {
		t.Errorf("IsCaptchaError() = false, want true (code=%d redirect=%q session=%q)",
			got.ErrorCode, got.RedirectURI, got.SessionToken)
	}
	if got.SessionToken != sessionToken {
		t.Errorf("SessionToken = %q, want %q", got.SessionToken, sessionToken)
	}
	if got.CaptchaSid != "" {
		t.Errorf("CaptchaSid = %q, want empty for the not_robot shape", got.CaptchaSid)
	}
}

// TestParseVkCaptchaErrorLegacyImage keeps the older image-captcha shape
// working, including VK's habit of sending captcha_sid as a JSON number.
func TestParseVkCaptchaErrorLegacyImage(t *testing.T) {
	t.Parallel()

	legacy := map[string]interface{}{
		"error_code":  float64(14),
		"error_msg":   "Captcha needed",
		"captcha_sid": float64(721234567890),
		"captcha_img": "https://api.vk.com/captcha.php?sid=721234567890",
		"redirect_uri": "https://id.vk.ru/not_robot_captcha?session_token=" +
			"legacy-token",
	}

	got := ParseVkCaptchaError(legacy)
	if got == nil {
		t.Fatal("ParseVkCaptchaError returned nil for the legacy image shape")
	}
	if got.CaptchaSid != "721234567890" {
		t.Errorf("CaptchaSid = %q, want %q (numeric sid must be stringified)",
			got.CaptchaSid, "721234567890")
	}
	if got.CaptchaImg == "" {
		t.Error("CaptchaImg is empty, want the image URL preserved")
	}
	if !got.IsCaptchaError() {
		t.Error("IsCaptchaError() = false, want true for the legacy shape")
	}
}

// TestParseVkCaptchaErrorNonCaptcha guards the other direction: a plain VK
// API error must not be mistaken for a solvable captcha now that the
// optional fields no longer gate parsing.
func TestParseVkCaptchaErrorNonCaptcha(t *testing.T) {
	t.Parallel()

	plain := map[string]interface{}{
		"error_code": float64(5),
		"error_msg":  "User authorization failed",
	}

	got := ParseVkCaptchaError(plain)
	if got != nil && got.IsCaptchaError() {
		t.Error("IsCaptchaError() = true for a non-captcha error; " +
			"RedirectURI/SessionToken must gate this")
	}
}
