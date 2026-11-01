package probe

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Unconfined, every peer channel must carry. This is the negative control: if
// the harness cannot observe a signal even with no sandbox in the way, then a
// later "isolated" result would mean the test is broken rather than the sandbox
// working — the most dangerous way this check could fail.
func TestPeerChannelsCarryWhenUnconfined(t *testing.T) {
	token := "testtoken" + t.Name()
	defer CleanupPeerArtifacts(token)

	var sig bytes.Buffer
	if err := RunPeerRole(&sig, RoleSignal, token, 0); err != nil {
		t.Fatalf("signal role: %v", err)
	}

	var obs bytes.Buffer
	if err := RunPeerRole(&obs, RoleObserve, token, 0); err != nil {
		t.Fatalf("observe role: %v", err)
	}

	var res struct {
		Observed map[string]bool   `json:"observed"`
		Errors   map[string]string `json:"errors"`
	}
	if err := json.Unmarshal(obs.Bytes(), &res); err != nil {
		t.Fatalf("decoding observation: %v\n%s", err, obs.String())
	}

	// file.content and dir.name are pure filesystem and must always work here.
	for _, id := range []string{"file.content", "dir.name"} {
		if !res.Observed[id] {
			t.Errorf("channel %q did not carry unconfined; the harness cannot detect leaks", id)
		}
	}
}

// The directory-name channel must be tested independently of file contents.
// Blocking file bodies does not close it — that is how agents in the 2026
// OpenAI–Hugging Face incident rebuilt their message board after it was wiped.
func TestDirectoryNameChannelIsSeparate(t *testing.T) {
	var ids []string
	for _, ch := range peerChannels() {
		ids = append(ids, ch.id)
	}
	joined := strings.Join(ids, ",")
	if !strings.Contains(joined, "dir.name") {
		t.Error("directory-name signalling must be its own channel")
	}
	if !strings.Contains(joined, "file.content") {
		t.Error("file-content signalling must be its own channel")
	}
}

// Artifacts must not outlive the exchange: the signalling peer cannot clean up
// after itself, so the parent must.
func TestCleanupRemovesAllArtifacts(t *testing.T) {
	token := "cleanuptoken"
	var sig bytes.Buffer
	if err := RunPeerRole(&sig, RoleSignal, token, 0); err != nil {
		t.Fatalf("signal role: %v", err)
	}

	CleanupPeerArtifacts(token)

	for _, p := range []string{
		filepath.Join(peerRoot, "sandboxcheckr-peer-"+token),
		filepath.Join(peerRoot, "sandboxcheckr-peerdir-"+token),
		filepath.Join(peerRoot, "scr-"+token+".sock"),
	} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s survived cleanup", p)
		}
	}
}

// A channel that carried must explain what it allows; one that did not must
// stay quiet rather than implying a finding.
func TestDescribePeerChannels(t *testing.T) {
	out := describePeerChannels(map[string]bool{"file.content": true}, nil, nil)

	var sawCarried, sawIsolated bool
	for _, ch := range out {
		if ch.ID == "file.content" {
			sawCarried = true
			if !ch.Carried {
				t.Error("file.content should be marked carried")
			}
			if ch.Detail == "" {
				t.Error("a carried channel must explain what it allows")
			}
		}
		if ch.ID == "dir.name" {
			sawIsolated = true
			if ch.Carried {
				t.Error("dir.name should not be marked carried")
			}
			if ch.Detail != "" {
				t.Error("a channel that did not carry should not describe a leak")
			}
		}
	}
	if !sawCarried || !sawIsolated {
		t.Error("expected both channels in the description")
	}
}
