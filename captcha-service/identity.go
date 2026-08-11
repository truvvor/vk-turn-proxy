package main

import (
	"fmt"
	mathrand "math/rand"
	"os"
	"strings"

	tlsprofiles "github.com/bogdanfinn/tls-client/profiles"
)

// Browser family identifiers for the fingerprint selector. "auto" (the
// default) picks a random profile across every family. Ported from the
// WINGS-N fork, which pairs each User-Agent with its matching uTLS
// ClientHello so the HTTP and TLS fingerprints can't contradict each other.
const (
	FamilyAuto    = "auto"
	FamilyChrome  = "chrome"
	FamilyEdge    = "edge"
	FamilySafari  = "safari"
	FamilyFirefox = "firefox"
)

type Profile struct {
	Family          string
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	AcceptLanguage  string
	// TLS is the uTLS ClientHello paired with UserAgent so the JA3/JA4
	// fingerprint matches the advertised browser. A Safari UA over a Chrome
	// ClientHello is an instant tell, so the two travel together.
	TLS tlsprofiles.ClientProfile
}

// isChromium reports whether this profile's engine emits sec-ch-ua* Client
// Hints and uses Chromium's header ordering. Safari and Firefox do neither.
func (p Profile) isChromium() bool {
	return p.SecChUa != ""
}

var firstNames = []string{
	"Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артём", "Илья",
	"Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений", "Иван",
	"Денис", "Даниил", "Тимофей", "Владислав", "Игорь", "Павел", "Руслан", "Марк",
	"Анна", "Мария", "Елена", "Дарья", "Анастасия", "Екатерина", "Виктория", "Ольга",
	"Наталья", "Юлия", "Татьяна", "Светлана", "Ирина", "Ксения", "Алина", "Елизавета",
}

var lastNames = []string{
	"Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов", "Михайлов",
	"Новиков", "Федоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семенов", "Егоров",
	"Павлов", "Козлов", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин",
	"Захаров", "Зайцев", "Соловьев", "Борисов", "Яковлев", "Григорьев", "Романов", "Воробьев",
}

// profiles pair a User-Agent, Client Hints and a uTLS ClientHello so the HTTP
// and TLS fingerprints stay self-consistent. Only Chromium engines (Chrome,
// Edge) emit sec-ch-ua* Client Hints; Safari and Firefox never send them, so
// those entries leave SecChUa empty and the apply helpers omit the headers.
//
// Before this table the whole fleet presented exactly ONE TLS fingerprint
// (Safari_IOS_18_0) on every request from every node — a trivially clusterable
// signal. The families come from the WINGS-N fork, whose captcha-free VK Calls
// path runs against this same mix in production.
//
// iPhone Safari stays first-among-equals for the legacy captcha path: real
// users clicking a VK call link from Safari on iPhone aren't asked for a
// captcha, and that's the request we most want to look like.
var profiles = []Profile{
	// iOS Safari — exact UA/uTLS pairing.
	{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1",
		AcceptLanguage: "en-US,en;q=0.9",
		TLS:            tlsprofiles.Safari_IOS_18_0,
	},
	{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
		AcceptLanguage: "en-US,en;q=0.9",
		TLS:            tlsprofiles.Safari_IOS_18_5,
	},
	{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
		AcceptLanguage: "en-US,en;q=0.9",
		TLS:            tlsprofiles.Safari_IOS_26_0,
	},
	{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		AcceptLanguage: "en-US,en;q=0.9",
		TLS:            tlsprofiles.Safari_IOS_17_0,
	},
	// macOS Safari. Safari's ClientHello is stable across major versions, so
	// the current UA pairs with the closest available desktop uTLS profile.
	{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
		AcceptLanguage: "en-US,en;q=0.9",
		TLS:            tlsprofiles.Safari_16_0,
	},

	// Windows Chrome
	{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		TLS:             tlsprofiles.Chrome_146,
	},
	{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Google Chrome";v="144", "Not_A Brand";v="99"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		TLS:             tlsprofiles.Chrome_144,
	},
	// macOS Chrome
	{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		TLS:             tlsprofiles.Chrome_146,
	},

	// Windows Edge
	{
		Family:          FamilyEdge,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Microsoft Edge";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		TLS:             tlsprofiles.Chrome_146,
	},

	// Firefox (no Client Hints)
	{
		Family:         FamilyFirefox,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
		AcceptLanguage: "en-US,en;q=0.5",
		TLS:            tlsprofiles.Firefox_147,
	},
	{
		Family:         FamilyFirefox,
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
		AcceptLanguage: "en-US,en;q=0.5",
		TLS:            tlsprofiles.Firefox_147,
	},
}

// browserFamily restricts profile selection to one engine family. Set once at
// startup from BROWSER_FP; empty / "auto" means random across all families.
var browserFamily = FamilyAuto

// initBrowserFamily reads BROWSER_FP. Unknown values fall back to auto rather
// than failing the boot — a typo shouldn't take the node down.
func initBrowserFamily() {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("BROWSER_FP")))
	switch raw {
	case FamilyChrome, FamilyEdge, FamilySafari, FamilyFirefox:
		browserFamily = raw
	case "", FamilyAuto:
		browserFamily = FamilyAuto
	default:
		browserFamily = FamilyAuto
	}
}

// profileForClientUA returns a profile suitable for carrying the iOS client's
// own User-Agent. Overriding UserAgent on an arbitrary profile would break the
// UA↔ClientHello pairing (an iPhone Safari UA riding a Chrome ClientHello is
// the exact contradiction the paired table exists to prevent), so we first
// pick a profile from the family the UA claims, then swap the UA string in.
//
// Falls back to a random profile when the UA doesn't look like anything we
// model — better a self-consistent guess than a guaranteed mismatch.
func profileForClientUA(ua string) Profile {
	family := familyOfUserAgent(ua)
	matches := make([]Profile, 0, len(profiles))
	for _, candidate := range profiles {
		if candidate.Family == family {
			matches = append(matches, candidate)
		}
	}
	var chosen Profile
	if len(matches) > 0 {
		chosen = matches[mathrand.Intn(len(matches))]
	} else {
		chosen = getRandomProfile()
	}
	chosen.UserAgent = ua
	return chosen
}

// familyOfUserAgent classifies a UA string into one of our engine families.
// Order matters: Edge and Chrome UAs both contain "Chrome", and every
// Chromium UA also contains "Safari", so the most specific token wins.
func familyOfUserAgent(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "edg/"):
		return FamilyEdge
	case strings.Contains(lower, "firefox/"):
		return FamilyFirefox
	case strings.Contains(lower, "chrome/"), strings.Contains(lower, "chromium/"):
		return FamilyChrome
	case strings.Contains(lower, "safari/"):
		return FamilySafari
	}
	return ""
}

// getRandomProfile returns a random profile within the selected family, or a
// random profile across all families when the selection is auto.
func getRandomProfile() Profile {
	if browserFamily != "" && browserFamily != FamilyAuto {
		matches := make([]Profile, 0, len(profiles))
		for _, candidate := range profiles {
			if candidate.Family == browserFamily {
				matches = append(matches, candidate)
			}
		}
		if len(matches) > 0 {
			return matches[mathrand.Intn(len(matches))]
		}
	}
	return profiles[mathrand.Intn(len(profiles))]
}

func generateName() string {
	if mathrand.Float32() < 0.3 {
		return firstNames[mathrand.Intn(len(firstNames))]
	}
	fn := firstNames[mathrand.Intn(len(firstNames))]
	ln := lastNames[mathrand.Intn(len(lastNames))]
	lastChar := fn[len(fn)-2:]
	if lastChar == "а" || lastChar == "я" {
		return fmt.Sprintf("%s %sа", fn, ln)
	}
	return fmt.Sprintf("%s %s", fn, ln)
}
