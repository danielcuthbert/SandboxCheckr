package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// peerResult is the child's JSON reply.
type peerResult struct {
	Observed     map[string]bool   `json:"observed"`
	Inconclusive map[string]bool   `json:"inconclusive"`
	Errors       map[string]string `json:"errors"`
}

// signalHold is how long the signalling peer stays alive after planting its
// token. Live channels — a listening socket above all — exist only while their
// process does, so without this the socket test would always report isolation
// and we would be measuring process lifetime rather than the sandbox.
const signalHold = 3 * time.Second

// RunPeers launches two processes under the same mechanism and reports which
// channels carried a signal between them.
//
// Both peers get the SAME sandbox configuration, because that is the realistic
// deployment: you confine each agent with one profile and run several. The
// question this answers is the one single-process probing cannot — whether that
// profile isolates them from each other, or merely from the host.
func (h *Harness) RunPeers(ctx context.Context, m mechanism.Mechanism) ([]model.PeerChannel, error) {
	var tok [8]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil, fmt.Errorf("generating peer token: %w", err)
	}
	token := hex.EncodeToString(tok[:])
	// Artifacts outlive the signalling peer so the observer can find them, so
	// the parent is responsible for clearing them up afterwards.
	defer CleanupPeerArtifacts(token)

	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	// Each peer gets its own workdir. Sharing one would hand them a channel by
	// construction and guarantee a positive result that proves nothing.
	signalDir, err := os.MkdirTemp("", "sandboxcheckr-peer-a-*")
	if err != nil {
		return nil, fmt.Errorf("creating peer workdir: %w", err)
	}
	defer os.RemoveAll(signalDir)
	observeDir, err := os.MkdirTemp("", "sandboxcheckr-peer-b-*")
	if err != nil {
		return nil, fmt.Errorf("creating peer workdir: %w", err)
	}
	defer os.RemoveAll(observeDir)

	if resolved, err := filepath.EvalSymlinks(signalDir); err == nil {
		signalDir = resolved
	}
	if resolved, err := filepath.EvalSymlinks(observeDir); err == nil {
		observeDir = resolved
	}

	// Run both peers concurrently. Two agents under one profile is the real
	// deployment, and a sequential run cannot see any channel that needs both
	// ends alive at once.
	//
	// The signaller writes its report as soon as it has planted, before the hold
	// that keeps its listening socket alive, so the parent learns what was put in
	// place while the process is still running.
	signed := make(chan peerReport, 1)
	go func() {
		cmd, res, err := h.startPeer(ctx, m, signalDir, RoleSignal, token)
		signed <- peerReport{cmd: cmd, res: res, err: err}
	}()

	// Give the signaller time to plant its token and start listening before the
	// observer looks, otherwise a race would masquerade as isolation. A peer that
	// got there reports in milliseconds, so the cap below is not a delay on the
	// common path: it is what catches a signaller that never got there at all,
	// whose channels then read inconclusive rather than isolated.
	planted := true
	select {
	case r := <-signed:
		if r.err != nil {
			finishPeer(r.cmd)
			return nil, fmt.Errorf("signalling peer: %w", r.err)
		}
	case <-time.After(signalHold / 3):
		planted = false
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	res, err := h.runPeer(ctx, m, observeDir, RoleObserve, token)
	if err != nil {
		return nil, fmt.Errorf("observing peer: %w", err)
	}
	sig := <-signed
	// The observation is done and the signaller's report is already in hand. Its
	// hold exists to keep the listener alive for an observer that has already
	// looked, so waiting for the sleep to end would only pad every peer run.
	if sig.cmd != nil && sig.cmd.Process != nil {
		_ = sig.cmd.Process.Kill()
	}
	finishPeer(sig.cmd)
	if sig.err != nil {
		return nil, fmt.Errorf("signalling peer: %w", sig.err)
	}

	markUnplantedChannels(res, sig.res, planted)
	return describePeerChannels(res.Observed, res.Inconclusive, res.Errors), nil
}

// peerReport is one peer's answer together with the process that produced it,
// since the signaller's report arrives while it is still running.
type peerReport struct {
	cmd *exec.Cmd
	res *peerResult
	err error
}

// markUnplantedChannels folds the signaller's own account of the exchange into
// the observer's. A channel the signaller could not write to, or any channel
// when it never reported at all, cannot support "the sandbox refused the read":
// the observer's not-carried answer there measures the signaller, not the
// confinement, and must be rendered inconclusive. A channel that did carry is
// evidence in its own right and is left alone.
func markUnplantedChannels(res, sig *peerResult, planted bool) {
	if res == nil {
		return
	}
	if res.Observed == nil {
		res.Observed = map[string]bool{}
	}
	if res.Inconclusive == nil {
		res.Inconclusive = map[string]bool{}
	}
	if res.Errors == nil {
		res.Errors = map[string]string{}
	}
	for _, ch := range peerChannels() {
		if !ch.planted || res.Observed[ch.id] {
			continue
		}
		var reason string
		switch {
		case !planted:
			reason = "the signalling peer had not reported planting before the observation was made"
		case sig != nil && sig.Errors[ch.id] != "":
			reason = "the signalling peer could not use this channel: " + sig.Errors[ch.id]
		default:
			continue
		}
		res.Observed[ch.id] = false
		res.Inconclusive[ch.id] = true
		res.Errors[ch.id] = reason
	}
}

// runPeer runs one half of the exchange to completion and returns its report.
func (h *Harness) runPeer(ctx context.Context, m mechanism.Mechanism, dir string, role PeerRole, token string) (*peerResult, error) {
	cmd, res, err := h.startPeer(ctx, m, dir, role, token)
	if err != nil {
		return nil, err
	}
	finishPeer(cmd)
	return res, nil
}

// startPeer launches one half of the exchange and returns as soon as the child
// has written its report. That is deliberately before it exits: the signalling
// peer stays alive on purpose while the observer looks, so the report and the
// exit are different moments. The caller reaps the process with finishPeer.
func (h *Harness) startPeer(ctx context.Context, m mechanism.Mechanism, dir string, role PeerRole, token string) (*exec.Cmd, *peerResult, error) {
	argv := []string{h.SelfPath, PeerSubcommand, "--role", string(role), "--token", token}
	if role == RoleSignal {
		argv = append(argv, "--hold", signalHold.String())
	}
	cmd, err := m.Confine(ctx, mechanism.Workdir{Path: dir}, argv)
	if err != nil {
		return nil, nil, fmt.Errorf("constructing sandbox: %w", err)
	}

	var stderr bytes.Buffer
	// A pipe rather than a buffer for stdout: the signalling peer must be able
	// to report before the hold that keeps its listening socket alive, and a
	// buffer can only be read once the process is gone.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to the peer's output: %w", err)
	}
	cmd.Stderr = &stderr
	cmd.WaitDelay = ioDrainDelay
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting peer: %w", err)
	}

	var res peerResult
	if err := json.NewDecoder(stdout).Decode(&res); err != nil {
		// Reap before reading stderr: the copy into the buffer is still running
		// until Wait returns.
		finishPeer(cmd)
		return cmd, nil, fmt.Errorf("no usable result (%v): %s", err, truncate(stderr.String(), 300))
	}
	return cmd, &res, nil
}

// finishPeer reaps a peer started by startPeer. Its exit status says nothing:
// the child always exits zero so that being killed is not confused with being
// blocked.
func finishPeer(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	_ = cmd.Wait()
}
