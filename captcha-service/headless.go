// SPDX-License-Identifier: MIT
// headless.go — drive headless Chromium via CDP (chromedp) to render the
// local MITM captcha page so VK's anti-bot JS executes fully. The page is
// kept alive (chromedp context) until the token is captured; the injected
// JS in manual_captcha.go posts success_token to /local-captcha-result.
//
// Two challenge types supported:
//   - Checkbox "I'm not a robot": chromedp clicks
//     #not-robot-captcha-checkbox; a real browser engine clears VK's
//     anti-bot check that the plain-HTTP solver fails.
//   - Slider (escalation after BOT): chromedp swipes the
//     .vkc__SwipeButton-module__thumb across .vkc__SwipeButton-module__track
//     via low-level mouse events to FIRE captchaNotRobot.check; the
//     correct tile permutation is supplied not by the swipe geometry but
//     by the MITM proxy, which intercepts captchaNotRobot.getContent,
//     ranks candidates via parseSliderContent + rankSliderCandidates,
//     and injects the winning answer into the check request body.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/input"
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
//
// identity (optional) lets the iOS client pin the navigator.userAgent
// the embedded VK JS sees. Cookies are NOT injected into the browser
// here — they are forwarded server-side by the MITM ReverseProxy on
// every outbound VK request (see manual_captcha.go). That keeps cookie
// scoping correct (the browser is on localhost:8765, not vk.com) and
// avoids `document.cookie` exposing the iOS client's secrets to any
// VK-side script that touches it.
func launchHeadlessCaptcha(url string, identity ClientIdentity) func() {
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
		// --no-zygote keeps Chromium from spawning a zygote helper
		// process; combined with --no-sandbox above it removes the
		// CLONE_NEWUSER dance entirely and lets the headless solver
		// start cleanly under systemd's sandbox.
		chromedp.Flag("no-zygote", true),
	)
	if identity.UserAgent != "" {
		// Browser-process flag so the request that loads the very first
		// HTML page (before any CDP runtime override can attach)
		// already carries the iOS UA. emulation.SetUserAgentOverride is
		// also installed below for subsequent navigations / XHRs.
		opts = append(opts, chromedp.UserAgent(identity.UserAgent))
	}
	_ = filepath.Base
	_ = strings.Contains
	if tmp != "" {
		opts = append(opts, chromedp.UserDataDir(tmp))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	taskCtx, cancelTask := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))

	go func() {
		actions := []chromedp.Action{}
		if identity.UserAgent != "" {
			actions = append(actions, emulation.SetUserAgentOverride(identity.UserAgent))
		}
		// 1) Click the "I'm not a robot" checkbox. A real browser engine
		//    clears VK's bot check the plain-HTTP solver fails.
		actions = append(actions,
			chromedp.Navigate(url),
			chromedp.WaitVisible(`#not-robot-captcha-checkbox`, chromedp.ByID),
			chromedp.Sleep(700*time.Millisecond),
			chromedp.Click(`#not-robot-captcha-checkbox`, chromedp.ByID),
		)
		if err := chromedp.Run(taskCtx, actions...); err != nil {
			log.Printf("[Captcha] headless: checkbox interact error: %v", err)
		} else {
			log.Printf("[Captcha] headless: clicked checkbox; watching for slider escalation...")
		}
		// 2) If VK escalates to the slider, swipe the confirm button to
		//    fire captchaNotRobot.check. The MITM proxy injects the
		//    ranker-computed answer into that request, so the arrangement
		//    geometry on screen doesn't need to be exact.
		for attempt := 0; attempt < 4; attempt++ {
			sel := `.vkc__SwipeButton-module__track`
			wctx, wcancel := context.WithTimeout(taskCtx, 12*time.Second)
			err := chromedp.Run(wctx, chromedp.WaitVisible(sel, chromedp.ByQuery))
			wcancel()
			if err != nil {
				return // no slider escalation — checkbox already passed
			}
			log.Printf("[Captcha] headless: slider present, swiping (attempt %d)...", attempt+1)
			if err := swipeConfirm(taskCtx); err != nil {
				log.Printf("[Captcha] headless: swipe error: %v", err)
			}
			// give VK time to respond / re-issue
			sctx, scancel := context.WithTimeout(taskCtx, 4*time.Second)
			_ = chromedp.Run(sctx, chromedp.Sleep(3500*time.Millisecond))
			scancel()
		}
		<-taskCtx.Done()
	}()
	log.Printf("[Captcha] headless: chromedp launched %s (UA-override=%v)", bin, identity.UserAgent != "")

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

// swipeConfirm drags VK's "swipe to confirm" thumb fully right via
// low-level mouse events so the captcha JS submits captchaNotRobot.check.
// The MITM proxy intercepts that request and injects the ranker-computed
// answer — geometry only triggers the submit, it doesn't carry the
// solution.
func swipeConfirm(ctx context.Context) error {
	var c []float64
	js := `(()=>{const th=document.querySelector('.vkc__SwipeButton-module__thumb');const tr=document.querySelector('.vkc__SwipeButton-module__track');if(!th||!tr)return null;const a=th.getBoundingClientRect(),b=tr.getBoundingClientRect();return [a.x+a.width/2,a.y+a.height/2,b.x+b.width-a.width/2];})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &c)); err != nil {
		return err
	}
	if len(c) < 3 {
		return fmt.Errorf("swipe button geometry not found")
	}
	sx, sy, ex := c[0], c[1], c[2]
	return chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		if err := input.DispatchMouseEvent(input.MousePressed, sx, sy).WithButton(input.Left).WithClickCount(1).Do(ctx); err != nil {
			return err
		}
		const steps = 24
		for i := 1; i <= steps; i++ {
			x := sx + (ex-sx)*float64(i)/float64(steps)
			if err := input.DispatchMouseEvent(input.MouseMoved, x, sy).WithButton(input.Left).Do(ctx); err != nil {
				return err
			}
			time.Sleep(18 * time.Millisecond)
		}
		return input.DispatchMouseEvent(input.MouseReleased, ex, sy).WithButton(input.Left).WithClickCount(1).Do(ctx)
	}))
}
