package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

// The sandboxed program can write the workdir the proxy logs into. A symlink
// planted there must not redirect the unconfined proxy's writes.
func TestWritesRefuseSymlinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "planted")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenAppendNoFollow(link, 0o600); err == nil {
		f.Close()
		t.Error("OpenAppendNoFollow followed a symlink")
	}
	if err := WriteFileNoFollow(link, []byte("pwned"), 0o644); err == nil {
		t.Error("WriteFileNoFollow followed a symlink")
	}

	// A symlinked parent directory (scratch -> ~/.ssh) is refused as well.
	target := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "scratch")
	if err := os.Symlink(target, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileNoFollow(filepath.Join(linkDir, "ca.pem"), []byte("x"), 0o644); err == nil {
		t.Error("WriteFileNoFollow wrote through a symlinked directory")
	}
	if f, err := OpenAppendNoFollow(filepath.Join(linkDir, "proxy.log"), 0o600); err == nil {
		f.Close()
		t.Error("OpenAppendNoFollow wrote through a symlinked directory")
	}

	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Errorf("victim was modified: %q", b)
	}
	if _, err := os.Stat(filepath.Join(target, "ca.pem")); err == nil {
		t.Error("file created through symlinked directory")
	}

	// Ordinary files still work.
	plain := filepath.Join(dir, "sub", "ca.pem")
	if err := WriteFileNoFollow(plain, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenAppendNoFollow(filepath.Join(dir, "proxy.log"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestValidHostname(t *testing.T) {
	for _, h := range []string{"api.anthropic.com", "a-b.example", "x_y.example.com", "127.0.0.1", "::1", "example.com."} {
		if !ValidHostname(h) {
			t.Errorf("%q should be valid", h)
		}
	}
	for _, h := range []string{"", "$(touch /tmp/x).com", "a b.com", "a\"b.com", "a'b.com", "\x1b[31m.com",
		"-bad.com", "bad-.com", "a..b", "a;b.com", "`id`.com", "a/b.com"} {
		if ValidHostname(h) {
			t.Errorf("%q should be invalid", h)
		}
	}
	for _, p := range []string{"0", "65536", "08", "-1", "80;id", ""} {
		if ValidPort(p) {
			t.Errorf("port %q should be invalid", p)
		}
	}
}
