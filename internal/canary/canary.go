// Package canary creates credentials whose use is visible at the egress proxy.
// Hostnames end in .invalid and can never name a real service.
package canary

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Credential struct {
	Label string `json:"label"`
	Host  string `json:"host"`
	Value string `json:"value"`
	// External marks a hostname from an outside token service (for example
	// canarytokens.org) rather than a planted fake. Nothing about it is
	// written into the sandbox: it trips when the program looks the name up
	// or sends it somewhere, which is the token's intended use.
	External bool `json:"external,omitempty"`
}

type Set struct {
	RunID       string            `json:"run_id"`
	Credentials []Credential      `json:"credentials"`
	Env         map[string]string `json:"env"`
	Files       map[string]string `json:"files"`
}

func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// New makes one run's credentials. A whole group is omitted when its real
// credential or config directory is explicitly passed into the sandbox.
func New(passEnv, extra, mount string) (*Set, error) {
	id, err := random(12)
	if err != nil {
		return nil, err
	}
	s := &Set{RunID: id, Env: map[string]string{}, Files: map[string]string{}}
	passed := map[string]bool{}
	for _, name := range strings.Fields(passEnv) {
		passed[name] = true
	}
	contains := func(names ...string) bool {
		for _, n := range names {
			if passed[n] {
				return true
			}
		}
		return false
	}
	add := func(group, prefix string) (Credential, error) {
		secret, err := random(24)
		if err != nil {
			return Credential{}, err
		}
		c := Credential{Label: group, Host: prefix + "-" + id + ".sandboxcheckr.invalid", Value: "sbc_" + secret}
		s.Credentials = append(s.Credentials, c)
		return c, nil
	}
	config := strings.ToLower(extra)
	if !contains("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ENDPOINT_URL") && !strings.Contains(config, "/.aws") {
		c, err := add("cloud", "sts")
		if err != nil {
			return nil, err
		}
		s.Env["AWS_ACCESS_KEY_ID"] = "AKIA" + strings.ToUpper(c.Value[4:20])
		s.Env["AWS_SECRET_ACCESS_KEY"] = c.Value
		s.Env["AWS_ENDPOINT_URL"] = "https://" + c.Host
		s.Env["AWS_SHARED_CREDENTIALS_FILE"] = filepath.Join(mount, "aws-credentials")
		s.Files["aws-credentials"] = fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n", s.Env["AWS_ACCESS_KEY_ID"], c.Value)
	}
	if !contains("KUBECONFIG", "KUBERNETES_SERVICE_HOST") && !strings.Contains(config, "/.kube") {
		c, err := add("kube", "kube")
		if err != nil {
			return nil, err
		}
		s.Env["KUBECONFIG"] = filepath.Join(mount, "kubeconfig")
		s.Files["kubeconfig"] = fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: canary\n  cluster:\n    server: https://%s\nusers:\n- name: canary\n  user:\n    token: %s\ncontexts:\n- name: canary\n  context:\n    cluster: canary\n    user: canary\ncurrent-context: canary\n", c.Host, c.Value)
	}
	if !contains("DOCKER_CONFIG", "DOCKER_AUTH_CONFIG") && !strings.Contains(config, "/.docker") {
		c, err := add("registry", "registry")
		if err != nil {
			return nil, err
		}
		s.Env["DOCKER_CONFIG"] = filepath.Join(mount, "docker")
		auth := base64.StdEncoding.EncodeToString([]byte("canary:" + c.Value))
		s.Files["docker/config.json"] = fmt.Sprintf("{\"auths\":{\"%s\":{\"auth\":\"%s\"}}}\n", c.Host, auth)
	}
	if !contains("DATABASE_URL", "PGHOST", "PGPASSWORD") {
		c, err := add("database", "db")
		if err != nil {
			return nil, err
		}
		s.Env["DATABASE_URL"] = fmt.Sprintf("postgres://canary:%s@%s:5432/canary", c.Value, c.Host)
	}
	if !contains("API_KEY", "GENERIC_API_KEY", "GENERIC_API_URL") {
		c, err := add("generic-api", "api")
		if err != nil {
			return nil, err
		}
		s.Env["API_KEY"] = c.Value
		s.Env["GENERIC_API_URL"] = "https://" + c.Host
	}
	// This is mounted over existing project .env files by bubblewrap only.
	if c := s.Credential("database"); c != nil {
		s.Files["dotenv"] = "DATABASE_URL=" + s.Env["DATABASE_URL"] + "\n"
	}
	return s, nil
}

// AddExternal appends external tokens to the set: a hostname from an outside
// token service, or name=value to watch a string (an AWS key pair, a card
// number) whose use shows up in request bytes. Hostnames are trimmed,
// lowercased and deduplicated against everything already present. They must
// look like public DNS names: a token only alerts when its lookup reaches the
// token service's own nameserver, so a bare label or a name with whitespace
// or path characters cannot work. Values are deduplicated by the string
// itself.
func (s *Set) AddExternal(tokens []string) error {
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			return fmt.Errorf("empty canary token")
		}
		if name, value, ok := strings.Cut(t, "="); ok {
			if err := s.addExternalValue(name, value); err != nil {
				return err
			}
			continue
		}
		h := strings.ToLower(strings.TrimSuffix(t, "."))
		if !validTokenHost(h) {
			return fmt.Errorf("%q does not look like a canary token hostname", t)
		}
		dup := false
		for _, c := range s.Credentials {
			if c.Host == h {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		s.Credentials = append(s.Credentials, Credential{Label: "external canarytoken", Host: h, Value: h, External: true})
	}
	return nil
}

// ValidToken reports whether t can travel to the runner as one word. The
// runner expands ${CANARY_TOKENS_FLAGS} unquoted, so a token is word-split and
// globbed by the shell before canary new ever sees it: this rejects anything
// that would split, expand or read as an option, including the spaces that
// addExternalValue would otherwise strip. Paste a card number without spaces
// (dashes are removed later, so 4111-1111-1111-1111 is fine). The
// child checks its own tokens again, so this is the flag-time answer to the
// same rules rather than a separate policy.
func ValidToken(t string) error {
	if t == "" || strings.TrimSpace(t) != t {
		return fmt.Errorf("canary token %q is empty or has surrounding space", t)
	}
	// Globbing and word splitting act on the result of the runner's unquoted
	// expansion, so the character set below is checked for every byte. A word
	// that begins with a hyphen additionally reads as an option to canary new,
	// which has flags that write files (--dir, --file, --mount), so it is
	// refused whatever its characters: --allow=evil.com is a valid-looking
	// name=value token and would not be a token at all.
	if t[0] == '-' {
		return fmt.Errorf("canary token %q would read as an option to the token command", t)
	}
	if name, value, ok := strings.Cut(t, "="); ok {
		if !safeTokenName(name) || value == "" {
			return fmt.Errorf("canary token %q needs a plain name and a value (name=value)", t)
		}
	} else if !validTokenHost(strings.ToLower(strings.TrimSuffix(t, "."))) {
		return fmt.Errorf("%q does not look like a canary token hostname", t)
	}
	for i := 0; i < len(t); i++ {
		b := t[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
			strings.IndexByte("._-:/,+~=%#@=", b) >= 0 {
			continue
		}
		return fmt.Errorf("canary token %q carries %q, which the runner's shell would act on", t, b)
	}
	return nil
}

// addExternalValue adds a value token. Spaces and dashes are removed (card
// numbers are written both ways) and what remains must be plain token
// characters: the value reaches the runner through a shell expansion, so a
// shell metacharacter in it would be code, not data.
func (s *Set) addExternalValue(name, value string) error {
	name = strings.TrimSpace(name)
	if !safeTokenName(name) {
		return fmt.Errorf("canary token name %q carries a character a name cannot have", name)
	}
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if name == "" || value == "" {
		return fmt.Errorf("a value canary token needs a name and a value (name=value)")
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
			b == '.' || b == '_' || b == '~' || b == '+' || b == '/' || b == '=' || b == ':' || b == '@' || b == '#' {
			continue
		}
		return fmt.Errorf("canary token value %q carries a character a token value cannot", value)
	}
	for _, c := range s.Credentials {
		if c.External && c.Host == "" && c.Value == value {
			return nil
		}
	}
	label := "external canarytoken"
	if name != "" {
		label = "external canarytoken (" + name + ")"
	}
	s.Credentials = append(s.Credentials, Credential{Label: label, Host: "", Value: value, External: true})
	return nil
}

func (s *Set) Credential(label string) *Credential {
	for i := range s.Credentials {
		if s.Credentials[i].Label == label {
			return &s.Credentials[i]
		}
	}
	return nil
}

// Plant writes beneath dir. The runner supplies a fresh private directory in
// /tmp, outside the real home and project.
func (s *Set) Plant(dir string) error {
	for name, content := range s.Files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func Read(path string) (*Set, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Set
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.RunID == "" {
		return nil, fmt.Errorf("empty canary set")
	}
	if len(s.RunID) != 24 {
		return nil, fmt.Errorf("invalid canary run ID")
	}
	if _, err := hex.DecodeString(s.RunID); err != nil {
		return nil, fmt.Errorf("invalid canary run ID")
	}
	for _, c := range s.Credentials {
		if c.External {
			if c.Host == "" {
				// A value token: the watched string itself, no hostname.
				if c.Value == "" || !strings.Contains(c.Label, "canarytoken") {
					return nil, fmt.Errorf("invalid external canary token")
				}
				continue
			}
			if !validTokenHost(c.Host) || c.Value != c.Host || !strings.Contains(c.Label, "canarytoken") {
				return nil, fmt.Errorf("invalid external canary token")
			}
			continue
		}
		if !strings.HasSuffix(c.Host, "-"+s.RunID+".sandboxcheckr.invalid") ||
			!safeName(c.Host) || !safeName(c.Label) || !strings.HasPrefix(c.Value, "sbc_") || len(c.Value) != 52 {
			return nil, fmt.Errorf("invalid canary credential")
		}
		if _, err := hex.DecodeString(c.Value[4:]); err != nil {
			return nil, fmt.Errorf("invalid canary credential")
		}
	}
	return &s, nil
}

func safeName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.' {
			continue
		}
		return false
	}
	return true
}

// safeTokenName is the charset of a value token's name, which appears in its
// label. Names travel to the runner inside a shell expansion alongside the
// value, so the same plain-token charset applies: anything outside it would
// be code, not data.
func safeTokenName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
			b == '.' || b == '_' || b == '-' {
			continue
		}
		return false
	}
	return true
}

// validTokenHost reports whether s names a host an outside token service could
// hand out. A token only alerts when its lookup reaches that service's own
// nameserver, so an address literal is refused as well as malformed input: the
// proxy forwards the token host's lookups and connections outside the
// allow-list, and an address — 169.254.169.254 say — arriving from a project
// file would have the host fetch its own metadata endpoint for the sandbox.
// safeName already restricts to lower-case letters, digits, dot and hyphen;
// what is added here is the shape: labels, no empty ones, no leading or
// trailing hyphen, at least one dot, and a last label that is not all digits
// (the distinction resolvers themselves make between a name and an address).
func validTokenHost(s string) bool {
	if !safeName(s) || !strings.Contains(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	for i, l := range labels {
		if l == "" {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		if i == len(labels)-1 {
			digits := true
			for j := 0; j < len(l); j++ {
				if l[j] < '0' || l[j] > '9' {
					digits = false
					break
				}
			}
			if digits {
				return false
			}
		}
	}
	return true
}

func (s *Set) Write(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

type Matcher struct {
	hosts   map[string]Credential
	strings []watchedString
}

type watchedString struct {
	token      []byte
	credential Credential
}

func NewMatcher(s *Set) *Matcher {
	m := &Matcher{hosts: map[string]Credential{}}
	for _, c := range s.Credentials {
		if c.Host != "" {
			// Value tokens have no host; their use is matched in bytes.
			m.hosts[c.Host] = c
		}
		// An empty needle matches every request, so a set with a blank value
		// would deny all egress rather than none. Read and AddExternal both
		// reject blank values; this is the last line.
		if c.Value != "" {
			m.strings = append(m.strings, watchedString{[]byte(c.Value), c})
		}
		if c.Label == "cloud" && s.Env["AWS_ACCESS_KEY_ID"] != "" {
			m.strings = append(m.strings, watchedString{[]byte(s.Env["AWS_ACCESS_KEY_ID"]), c})
		}
		if c.Label == "registry" {
			auth := base64.StdEncoding.EncodeToString([]byte("canary:" + c.Value))
			m.strings = append(m.strings, watchedString{[]byte(auth), c})
		}
	}
	return m
}

func (m *Matcher) Host(host string) (Credential, bool) {
	c, ok := m.hosts[strings.TrimSuffix(strings.ToLower(host), ".")]
	return c, ok
}

func (m *Matcher) Bytes(b []byte) (Credential, bool) {
	for _, w := range m.strings {
		if bytes.Contains(b, w.token) {
			return w.credential, true
		}
	}
	return Credential{}, false
}
