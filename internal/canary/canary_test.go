package canary

import (
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
