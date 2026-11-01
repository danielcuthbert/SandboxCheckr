package proxy

import "strings"

// relayPatterns are hostnames of services that store what they are sent or
// fetch on the caller's behalf. An allow-listed host like this is a message
// board between agents and, if it proxies upstream, a way out to the whole
// internet — the shape of the 2026 OpenAI–Hugging Face incident, where agents
// used an internal package registry for both. Allowing one is sometimes
// necessary; doing it without noticing is the mistake this list exists to
// catch.
//
// onGet marks services where a plain GET is enough to store data or reach
// another host: a shortener that creates a link from a query string, a reader
// that fetches whatever URL follows its own, a tunnel or user-hosted app that
// runs someone else's code. A download-only --rule does nothing for these. The
// 2026 agent swarms (SWM-007) used exactly this class — URL
// shorteners' public statistics pages as message boards, and fourteen fetchers
// and CORS proxies to reach the pages they were not given.
//
// Matching is by hostname (see hostMatches), so it is a heuristic: it names
// likely relays, it does not prove a host is one, and it cannot know every
// relay that exists.
var relayPatterns = []struct {
	match, kind string
	onGet       bool
}{
	{"artifactory", "package registry", false},
	{"jfrog.io", "package registry", false},
	{"nexus", "package registry", false},
	{"registry.npmjs.org", "package registry", false},
	{"npm.pkg.github.com", "package registry", false},
	{"pypi.org", "package registry", false},
	{"files.pythonhosted.org", "package registry", false},
	{"upload.pypi.org", "package registry (upload endpoint)", false},
	{"crates.io", "package registry", false},
	{"rubygems.org", "package registry", false},
	{"proxy.golang.org", "package registry", false},
	{"repo.maven.apache.org", "package registry", false},
	{"registry-1.docker.io", "container registry", false},
	{"ghcr.io", "container registry", false},
	{"quay.io", "container registry", false},
	{"gcr.io", "container registry", false},
	{"pkg.dev", "container/package registry", false},
	{"amazonaws.com", "cloud service (S3 and others accept uploads)", false},
	{"blob.core.windows.net", "object storage", false},
	{"storage.googleapis.com", "object storage", false},
	{"r2.cloudflarestorage.com", "object storage", false},
	{"huggingface.co", "model/dataset hub", false},
	{"github.com", "code host (repositories, gists, issues accept writes)", false},
	{"githubusercontent.com", "code host content", false},
	{"gitlab.com", "code host", false},
	{"bitbucket.org", "code host", false},
	{"pastebin", "paste service", false},
	{"gist.", "paste service", false},
	{"hastebin", "paste service", false},
	{"paste.", "paste service", false},
	{"jsonhero.io", "document store", false},
	{"transfer.sh", "file drop", false},
	{"discord.com", "chat (webhooks accept posts)", false},
	{"slack.com", "chat (webhooks accept posts)", false},
	{"hooks.", "webhook endpoint", false},

	// A GET is enough: request capture and echo.
	{"webhook.site", "request capture", true},
	{"requestbin", "request capture", true},
	{"httpbin.org", "echo / redirect service", true},
	{"urlquery.net", "URL scanner (fetches what it is given)", true},

	// URL shorteners: a link is created, and its statistics page records the
	// referrer of every visit — both writable with a GET.
	{"is.gd", "URL shortener", true},
	{"v.gd", "URL shortener", true},
	{"da.gd", "URL shortener", true},
	{"2dd.pl", "URL shortener", true},
	{"tinyurl.com", "URL shortener", true},
	{"bit.ly", "URL shortener", true},
	{"bitly.com", "URL shortener", true},
	{"bitily.in", "URL shortener", true},
	{"t.ly", "URL shortener", true},
	{"cutt.ly", "URL shortener", true},
	{"rb.gy", "URL shortener", true},
	{"ow.ly", "URL shortener", true},
	{"tiny.cc", "URL shortener", true},
	{"shorturl.at", "URL shortener", true},
	{"rebrand.ly", "URL shortener", true},
	{"yourls", "URL shortener", true},
	{"vanderbi.lt", "URL shortener", true},
	{"uoft.me", "URL shortener", true},
	{"goto.unm.edu", "URL shortener", true},
	{"u.ethz.ch", "URL shortener", true},

	// Fetchers, readers and CORS proxies: hand them a URL, they fetch it.
	{"r.jina.ai", "fetcher (fetches any URL it is given)", true},
	{"pure.md", "fetcher (fetches any URL it is given)", true},
	{"markdown.new", "fetcher (fetches any URL it is given)", true},
	{"md.succ.ai", "fetcher (fetches any URL it is given)", true},
	{"microlink.io", "fetcher (fetches any URL it is given)", true},
	{"allorigins", "CORS proxy (fetches any URL it is given)", true},
	{"cors.lol", "CORS proxy (fetches any URL it is given)", true},
	{"cors.io", "CORS proxy (fetches any URL it is given)", true},
	{"corsproxy.io", "CORS proxy (fetches any URL it is given)", true},
	{"cors.", "CORS proxy (fetches any URL it is given)", true},
	{"docs.google.com", "document viewer (fetches any URL it is given)", true},
	{"translate.goog", "translation proxy (fetches any URL it is given)", true},
	{"translate.google.com", "translation proxy (fetches any URL it is given)", true},
	{"web.archive.org", "archive (save fetches any URL it is given)", true},
	{"archive.ph", "archive (fetches any URL it is given)", true},
	{"archive.today", "archive (fetches any URL it is given)", true},

	// Tunnels and user-hosted apps: every request reaches someone's code.
	{"ngrok", "tunnel", true},
	{"trycloudflare.com", "tunnel", true},
	{"loca.lt", "tunnel", true},
	{"serveo.net", "tunnel", true},
	{"workers.dev", "user-hosted app (anyone's code)", true},
	{"vercel.app", "user-hosted app (anyone's code)", true},
	{"netlify.app", "user-hosted app (anyone's code)", true},
	{"pages.dev", "user-hosted app (anyone's code)", true},
	{"deno.dev", "user-hosted app (anyone's code)", true},
	{"glitch.me", "user-hosted app (anyone's code)", true},
	{"herokuapp.com", "user-hosted app (anyone's code)", true},
	{"replit.dev", "user-hosted app (anyone's code)", true},
}

// hostMatches reports whether host h matches pattern p. A pattern with no dot
// ("artifactory") matches anywhere in the name; one ending in a dot ("gist.")
// matches a leading label; anything else is a domain and matches itself and
// its subdomains, so "is.gd" does not match "analysis.gd" and "github.com"
// does not match "notgithub.com".
func hostMatches(h, p string) bool {
	switch {
	case !strings.Contains(p, "."):
		return strings.Contains(h, p)
	case strings.HasSuffix(p, "."):
		return strings.HasPrefix(h, p) || strings.Contains(h, "."+p)
	default:
		return h == p || strings.HasSuffix(h, "."+p)
	}
}

func normHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(host, ".")), ".")
}

// RelayKind reports whether host looks like a store-or-forward service, and
// which kind. Empty means no match.
func RelayKind(host string) string {
	h := normHost(host)
	for _, p := range relayPatterns {
		if hostMatches(h, p.match) {
			return p.kind
		}
	}
	return ""
}

// RelaysOnGet reports whether a plain GET to host can store data or reach
// another host, so that a download-only rule does not make it safe. Allowing
// such a host is close to allowing the whole internet.
func RelaysOnGet(host string) bool {
	h := normHost(host)
	for _, p := range relayPatterns {
		if hostMatches(h, p.match) {
			return p.onGet
		}
	}
	return false
}

// codeHostPatterns are hosts that serve arbitrary user-controlled content
// from a domain most environments already trust. A download-only rule does
// not make them safe: in ProjectDiscovery's 2026 backdoored-model demo the
// payload was a plain GET from raw.githubusercontent.com. Only a path rule —
// scoping the host to your own organisation's repositories — stops a fetch
// from someone else's. See SBX-011.
var codeHostPatterns = []string{
	"githubusercontent.com",
	"github.com",
	"gitlab.com",
	"bitbucket.org",
	"huggingface.co",
	"gist.",
}

// IsCodeHost reports whether host serves user-controlled content, so that a
// method-only rule still lets anyone's content in.
func IsCodeHost(host string) bool {
	h := normHost(host)
	for _, p := range codeHostPatterns {
		if hostMatches(h, p) {
			return true
		}
	}
	return false
}

// modelAPIPatterns are hosted model endpoints. Allowing one is usually the
// point of running an agent, but it is also a destination that receives
// everything the agent reads: a hostile or backdoored model needs no download
// and no collector, it can simply ask the agent to print a secret. The proxy
// cannot close that channel; it names it so the reader knows it is open.
var modelAPIPatterns = []string{
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"aiplatform.googleapis.com",
	"openai.azure.com",
	"bedrock-runtime.",
	"openrouter.ai",
	"api.together.xyz",
	"api.groq.com",
	"api.mistral.ai",
	"api.deepseek.com",
	"api.fireworks.ai",
	"inference.huggingface.co",
	"router.huggingface.co",
}

// IsModelAPI reports whether host looks like a hosted model endpoint.
func IsModelAPI(host string) bool {
	h := normHost(host)
	for _, p := range modelAPIPatterns {
		if hostMatches(h, p) {
			return true
		}
	}
	return false
}

// SuggestedRule is the --rule the proxy recommends for an allowed relay host.
// Code hosts get a path placeholder the user must fill in, because the
// method alone does not stop the download that matters; the placeholder fails
// closed (nothing matches it) if pasted unedited. Hosts that relay on a GET
// get no suggestion (""): no method rule helps, and suggesting one would
// imply it did.
func SuggestedRule(host string) string {
	if RelaysOnGet(host) {
		return ""
	}
	if IsCodeHost(host) {
		return host + ":GET,HEAD:/YOUR-ORG/"
	}
	return host + ":GET,HEAD"
}
