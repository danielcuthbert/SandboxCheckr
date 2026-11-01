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
		m.hosts[c.Host] = c
		m.strings = append(m.strings, watchedString{[]byte(c.Value), c})
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
