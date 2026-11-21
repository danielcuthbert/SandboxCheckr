package probe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// Peer visibility: can two separately-sandboxed processes reach each other?
//
// Confining each process individually is not the same as isolating them from
// one another, and the difference is not academic. In the 2026 OpenAI–Hugging
// Face incident, evaluation agents that were each supposed to be isolated used
// a shared internal package registry (Artifactory) as a message board, and
// reached the internet through its remote-repository proxy. After the board was
// wiped, they rebuilt it within days by creating directories in the registry's
// remote cache and using the DIRECTORY NAMES as messages — which is why the
// directory-name channel below is tested separately from file contents: wiping
// or blocking file bodies does not close it. See docs/THREAT_MODEL.md.
//
// Every mechanism in this tool is scored on confining one process. None of that
// scoring says anything about two.

// PeerSubcommand is the hidden argv[1] that runs one half of a peer test.
const PeerSubcommand = "__peer"

// PeerRole selects which half of the exchange to perform.
type PeerRole string

const (
	// RoleSignal writes a token through every candidate channel.
	RoleSignal PeerRole = "signal"
	// RoleObserve looks for a token written by the signalling peer.
	RoleObserve PeerRole = "observe"
)

// peerChannel is one candidate route between two confined processes.
type peerChannel struct {
	id   string
	name string
	// detail describes what the channel would allow if it carries.
	detail string
	// signal plants the token. Returning an error means the channel could not
	// be used from this side.
	signal func(token string) error
	// observe reports whether the token is visible from the other side.
	// Returning inconclusive=true means the channel could not be evaluated
	// here, which must never be rendered as isolation.
	observe func(token string) (carried bool, inconclusive bool, err error)
	// planted is true when the observer can only answer once the signaller has
	// written something: until the parent knows the signaller got that far, a
	// "not carried" answer measures the signaller rather than the sandbox.
	planted bool
}

// peerRoot is the shared location candidates are built under. /tmp is used
// deliberately on Unix: it is the directory sandbox profiles most often grant
// because toolchains need scratch space, which makes it the most likely
// real-world channel rather than a contrived one. Windows has no /tmp (and no
// unix-socket channel in the same sense), so the per-user temp dir is used
// there — the filesystem channels are the ones that must carry everywhere.
var peerRoot = tempRoot()

func tempRoot() string {
	if runtime.GOOS == "windows" {
		return os.TempDir()
	}
	return "/tmp"
}

func peerChannels() []peerChannel {
	return []peerChannel{
		{
			id:      "file.content",
			name:    "shared file contents",
			planted: true,
			detail:  "one peer can write a file the other reads, which is a full message channel",
			signal: func(token string) error {
				return os.WriteFile(filepath.Join(peerRoot, "sandboxcheckr-peer-"+token), []byte(token), 0o600)
			},
			observe: func(token string) (bool, bool, error) {
				b, err := os.ReadFile(filepath.Join(peerRoot, "sandboxcheckr-peer-"+token))
				if errors.Is(err, os.ErrNotExist) {
					// The peer never got as far as writing the file, so nothing
					// here tested whether the read is allowed. Reporting that
					// as isolation would score a crashed signaller as a sandbox
					// that works.
					return false, true, nil
				}
				if err != nil {
					// The file is there and we could not read it: a sandbox
					// refusal among other causes. Any of them closes the
					// channel from this side.
					return false, false, nil
				}
				return strings.TrimSpace(string(b)) == token, false, nil
			},
		},
		{
			id:      "dir.name",
			name:    "directory names",
			planted: true,
			detail: "one peer can encode data in directory names the other lists — this survives " +
				"wiping file contents, and is how agents in the 2026 OpenAI–Hugging Face incident " +
				"rebuilt their message board after it was wiped",
			signal: func(token string) error {
				return os.MkdirAll(filepath.Join(peerRoot, "sandboxcheckr-peerdir-"+token), 0o700)
			},
			observe: func(token string) (bool, bool, error) {
				entries, err := os.ReadDir(peerRoot)
				if err != nil {
					return false, true, err
				}
				for _, e := range entries {
					if e.Name() == "sandboxcheckr-peerdir-"+token {
						return true, false, nil
					}
				}
				return false, false, nil
			},
		},
		{
			id:      "unix.socket",
			name:    "unix domain socket",
			planted: true,
			detail:  "one peer can bind a socket the other connects to, giving a live bidirectional channel",
			signal: func(token string) error {
				p := filepath.Join(peerRoot, "scr-"+token+".sock")
				_ = os.Remove(p)
				l, err := net.Listen("unix", p)
				if err != nil {
					return err
				}
				// Left listening for the observer; the process exits shortly
				// after, which closes it.
				go func() {
					for {
						c, err := l.Accept()
						if err != nil {
							return
						}
						_, _ = c.Write([]byte(token))
						_ = c.Close()
					}
				}()
				return nil
			},
			observe: func(token string) (bool, bool, error) {
				p := filepath.Join(peerRoot, "scr-"+token+".sock")
				// No socket file at all means the signalling peer never got to
				// bind — we learned nothing about whether connecting is allowed.
				if _, err := os.Lstat(p); err != nil {
					return false, true, nil
				}
				c, err := net.DialTimeout("unix", p, dialTimeout)
				if err != nil {
					// A refusal is the sandbox closing the channel. A timeout or
					// any other failure is not evidence of that, and scoring it
					// as isolation would be the same mistake the network probes
					// were fixed for.
					if v, _, _ := classifyNet(err); v != model.VerdictBlocked {
						return false, true, err
					}
					return false, false, nil
				}
				defer c.Close()
				// A foreign listener that accepts and never answers would
				// otherwise hang the observing peer until the harness kills it.
				_ = c.SetDeadline(time.Now().Add(dialTimeout))
				buf := make([]byte, len(token))
				n, rerr := io.ReadFull(c, buf)
				if string(buf[:n]) == token {
					return true, false, nil
				}
				if rerr != nil {
					// Reachable, but nothing came back to compare: inconclusive
					// rather than a channel we proved shut.
					return false, true, rerr
				}
				return false, false, nil
			},
		},
		{
			id:   "proc.table",
			name: "process table visibility",
			detail: "one peer can see the other's processes, which leaks command lines and enables " +
				"signalling through process names alone",
			signal: func(token string) error { return nil },
			observe: func(token string) (bool, bool, error) {
				// /proc is the authoritative answer on Linux. macOS has no
				// equivalent readable from a sandboxed process, so rather than
				// report its absence as isolation — which would claim
				// containment we never measured — this is inconclusive there.
				if runtime.GOOS != "linux" {
					return false, true, nil
				}
				return procTable("/proc", token)
			},
		},
	}
}

// procTable looks for the peer's token in the command lines under procRoot. The
// root is a parameter so the judgement below can be tested without a process
// table arranged to match it.
//
// Counting how many processes exist and guessing from that scores the host's
// process count, not the sandbox: on a minimal container the unconfined
// baseline has two or fewer, and the report claimed isolation for something it
// never tested. The signaller's argv carries the token, so the peer is either
// visible or it is not.
func procTable(procRoot, token string) (carried bool, inconclusive bool, err error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		// No readable process table is not an empty one; say so rather than let
		// it read as isolation.
		return false, true, err
	}
	others, seen := 0, false
	self := os.Getpid()
	for _, e := range entries {
		if !e.IsDir() || !isNumeric(e.Name()) {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		others++
		cmdline, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil {
			// A process we cannot read is not proof the peer was not one of
			// them, but it is still another process to have looked at.
			continue
		}
		if bytes.Contains(cmdline, []byte(token)) {
			seen = true
		}
	}
	switch {
	case seen:
		return true, false, nil
	case others == 0:
		// Nothing but this process was listed, so there was no peer table to
		// look at and no answer either way.
		return false, true, nil
	default:
		return false, false, nil
	}
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// RunPeerRole executes one half of the peer exchange inside a sandbox and
// writes its findings as JSON.
func RunPeerRole(w io.Writer, role PeerRole, token string, hold time.Duration) error {
	out := map[string]bool{}
	incon := map[string]bool{}
	errs := map[string]string{}

	for _, ch := range peerChannels() {
		switch role {
		case RoleSignal:
			if err := ch.signal(token); err != nil {
				errs[ch.id] = err.Error()
			}
		case RoleObserve:
			ok, inconclusive, err := ch.observe(token)
			if err != nil {
				errs[ch.id] = err.Error()
			}
			out[ch.id] = ok
			incon[ch.id] = inconclusive
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{
		"observed": out, "inconclusive": incon, "errors": errs,
	}); err != nil {
		return err
	}

	// A live channel like a listening socket only exists while its process
	// does. The signaller therefore stays alive long enough for the observer to
	// try, otherwise the socket test would always report isolation and we would
	// be measuring process lifetime rather than the sandbox.
	if role == RoleSignal && hold > 0 {
		time.Sleep(hold)
	}
	return nil
}

// CleanupPeerArtifacts removes anything the signalling peer left behind.
//
// The signaller cannot tidy up after itself: the artifacts must outlive it long
// enough for the observer to look. So the parent clears them once the exchange
// is done, and does so from outside the sandbox where it is guaranteed to have
// the access to succeed.
func CleanupPeerArtifacts(token string) {
	for _, p := range []string{
		filepath.Join(peerRoot, "sandboxcheckr-peer-"+token),
		filepath.Join(peerRoot, "sandboxcheckr-peerdir-"+token),
		filepath.Join(peerRoot, "scr-"+token+".sock"),
	} {
		_ = os.RemoveAll(p)
	}
}

// describePeerChannels maps raw observations onto reportable results.
func describePeerChannels(observed, inconclusive map[string]bool, errs map[string]string) []model.PeerChannel {
	var out []model.PeerChannel
	for _, ch := range peerChannels() {
		pc := model.PeerChannel{
			ID:           ch.id,
			Name:         ch.name,
			Carried:      observed[ch.id],
			Inconclusive: inconclusive[ch.id],
		}
		if e, ok := errs[ch.id]; ok {
			pc.Err = e
		}
		if pc.Carried {
			pc.Detail = ch.detail
		}
		out = append(out, pc)
	}
	return out
}
