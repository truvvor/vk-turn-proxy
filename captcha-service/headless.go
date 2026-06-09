// SPDX-License-Identifier: MIT
// headless.go — drive headless Chromium via CDP (chromedp) to render the
// local MITM captcha page so VK's anti-bot JS executes fully. The page is
// kept alive (chromedp context) until the token is captured; the injected
// JS in manual_captcha.go posts success_token to /local-captcha-result.
package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

var (
	headlessCaptchaEnabled bool
	chromiumPathOverride   string
)

func findChromium() string {
	if chromiumPathOverride != "" {
		return chromiumPathOverride
	}
	for _, c := range []string{
		"chrome-headless-shell", "chromium", "chromium-browser",
		"google-chrome", "google-chrome-stable", "chrome",
		"/usr/local/bin/chrome-headless-shell", "/snap/bin/chromium",
	} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// launchHeadlessCaptcha renders url in headless Chromium via chromedp and
// keeps the page alive until the returned cleanup func is called.
func launchHeadlessCaptcha(url string) func() {
	bin := findChromium()
	if bin == "" {
		log.Printf("[Captcha] headless: no chromium found; falling back to system browser")
		openBrowser(url)
		return func() {}
	}
	tmp, err := os.MkdirTemp("", "tbchrome-")
	if err != nil {
		tmp = ""
	}

	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts,
		chromedp.ExecPath(bin),
		chromedp.NoSandbox,
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("mute-audio", true),
	)
	// chrome-headless-shell is already headless; the default --headless
	// flag is harmless but the shell prefers no duplicate. Leave defaults.
	_ = filepath.Base
	_ = strings.Contains
	if tmp != "" {
		opts = append(opts, chromedp.UserDataDir(tmp))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	taskCtx, cancelTask := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))

	go func() {
		// Navigate + click VK's "I'm not a robot" checkbox, then keep the
		// page alive so the async captchaNotRobot.check completes and the
		// injected JS / server proxy can capture success_token.
		err := chromedp.Run(taskCtx,
			chromedp.Navigate(url),
			chromedp.WaitVisible(`#not-robot-captcha-checkbox`, chromedp.ByID),
			chromedp.Sleep(800*time.Millisecond),
			chromedp.Click(`#not-robot-captcha-checkbox`, chromedp.ByID),
		)
		if err != nil {
			log.Printf("[Captcha] headless: interact error: %v (keeping page alive)", err)
		} else {
			log.Printf("[Captcha] headless: clicked not-robot checkbox; page running, waiting for solve...")
		}
		<-taskCtx.Done() // keep page + JS alive until cleanup
	}()
	log.Printf("[Captcha] headless: chromedp launched %s", bin)

	var once sync.Once
	return func() {
		once.Do(func() {
			cancelTask()
			cancelAlloc()
			if tmp != "" {
				_ = os.RemoveAll(tmp)
			}
		})
	}
}
