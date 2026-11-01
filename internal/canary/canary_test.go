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
