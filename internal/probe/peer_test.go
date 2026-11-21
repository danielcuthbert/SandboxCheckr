package probe

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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

func peerChannelByID(t *testing.T, id string) peerChannel {
	t.Helper()
	for _, ch := range peerChannels() {
		if ch.id == id {
			return ch
		}
	}
	t.Fatalf("no peer channel %q", id)
	return peerChannel{}
}

// "The peer has not written yet" is not measured isolation. An absent artefact
// means nothing was tested, and must come back inconclusive.
func TestFileContentAbsentIsInconclusive(t *testing.T) {
	token := "absenttoken" + t.Name()
	defer CleanupPeerArtifacts(token)
	if _, err := os.Lstat(filepath.Join(peerRoot, "sandboxcheckr-peer-"+token)); err == nil {
		t.Fatal("the artefact is already there; the token is not unique")
	}

	carried, inconclusive, err := peerChannelByID(t, "file.content").observe(token)
	if carried {
		t.Error("an absent artefact cannot have carried")
	}
	if !inconclusive {
		t.Error("an absent artefact must be inconclusive, not scored as isolation")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// A file that is there and could not be read IS an answer about the channel:
// something between the two peers closed it.
func TestFileContentUnreadableIsIsolation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not refused by file permissions")
	}
	token := "unreadabletoken" + t.Name()
	defer CleanupPeerArtifacts(token)
	p := filepath.Join(peerRoot, "sandboxcheckr-peer-"+token)
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}

	carried, inconclusive, err := peerChannelByID(t, "file.content").observe(token)
	if carried || inconclusive {
		t.Errorf("a refused read gave carried=%v inconclusive=%v, want isolation", carried, inconclusive)
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// The process-table channel must score what the peer could see, not how many
// processes the host happens to be running.
func TestProcTableJudgements(t *testing.T) {
	const token = "9a8b7c6d5e4f3a2b"

	// A table with nothing but this process in it tested nothing.
	empty := t.TempDir()
	if _, inconclusive, err := procTable(empty, token); err != nil || !inconclusive {
		t.Errorf("no other processes gave inconclusive=%v err=%v, want inconclusive", inconclusive, err)
	}
	// The observer's own row does not count as somebody else.
	self := filepath.Join(empty, strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(filepath.Join(self), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(self, "cmdline"), []byte("probe\x00--token\x00"+token+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, inconclusive, err := procTable(empty, token); err != nil || !inconclusive {
		t.Errorf("a table holding only the observer gave inconclusive=%v err=%v, want inconclusive", inconclusive, err)
	}

	// Another process is present, so its absence from the table is an answer.
	other := filepath.Join(empty, "4321")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "cmdline"), []byte("sh\x00-c\x00true\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if carried, inconclusive, err := procTable(empty, token); carried || inconclusive || err != nil {
		t.Errorf("a table without the token gave carried=%v inconclusive=%v err=%v, want isolation",
			carried, inconclusive, err)
	}

	// The peer's argv carries the token: seeing it is the finding.
	if err := os.WriteFile(filepath.Join(other, "cmdline"),
		[]byte("sandboxcheckr\x00__peer\x00--role\x00signal\x00--token\x00"+token+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if carried, inconclusive, err := procTable(empty, token); !carried || inconclusive || err != nil {
		t.Errorf("the peer's cmdline went unseen: carried=%v inconclusive=%v err=%v", carried, inconclusive, err)
	}

	// A process table we cannot read at all is not an empty one.
	if _, inconclusive, err := procTable(filepath.Join(empty, "nope"), token); err == nil || !inconclusive {
		t.Errorf("an unreadable table gave inconclusive=%v err=%v, want inconclusive", inconclusive, err)
	}
}

// The signaller's own account of the exchange belongs in the result. A channel
// it could not write to cannot support "the sandbox refused the read", and a
// signaller that never reported at all proves nothing about any of them.
func TestSignallerAccountIsInconclusive(t *testing.T) {
	empty := func() *peerResult {
		return &peerResult{
			Observed:     map[string]bool{},
			Inconclusive: map[string]bool{},
			Errors:       map[string]string{},
		}
	}

	// The signaller could not write its file: the observer's "not carried" was
	// the signaller failing, not the sandbox working.
	res := empty()
	markUnplantedChannels(res, &peerResult{Errors: map[string]string{"file.content": "permission denied"}}, true)
	if !res.Inconclusive["file.content"] || res.Observed["file.content"] {
		t.Errorf("a refused signal was still scored as isolation: %+v", res)
	}
	if res.Inconclusive["dir.name"] {
		t.Error("a channel the signaller did use must stay conclusive")
	}
	if res.Inconclusive["proc.table"] {
		t.Error("process table visibility does not depend on planting")
	}

	// The cap fired, so nothing was confirmed as planted.
	res = empty()
	markUnplantedChannels(res, nil, false)
	for _, id := range []string{"file.content", "dir.name", "unix.socket"} {
		if !res.Inconclusive[id] {
			t.Errorf("%s was trusted without a confirmed plant", id)
		}
	}
	if res.Inconclusive["proc.table"] {
		t.Error("process table visibility does not depend on planting")
	}

	// A channel that carried is evidence in its own right and stands.
	res = empty()
	res.Observed["file.content"] = true
	markUnplantedChannels(res, nil, false)
	if !res.Observed["file.content"] || res.Inconclusive["file.content"] {
		t.Error("a channel that carried must stay a finding")
	}
}
