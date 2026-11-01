package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	sigDone := make(chan error, 1)
	go func() {
		_, err := h.runPeer(ctx, m, signalDir, RoleSignal, token)
		sigDone <- err
	}()

	// Give the signaller time to plant its token and start listening before the
	// observer looks, otherwise a race would masquerade as isolation.
	select {
	case err := <-sigDone:
		if err != nil {
			return nil, fmt.Errorf("signalling peer: %w", err)
		}
	case <-time.After(signalHold / 3):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	res, err := h.runPeer(ctx, m, observeDir, RoleObserve, token)
	if err != nil {
		return nil, fmt.Errorf("observing peer: %w", err)
	}
	<-sigDone

	return describePeerChannels(res.Observed, res.Inconclusive, res.Errors), nil
}

func (h *Harness) runPeer(ctx context.Context, m mechanism.Mechanism, dir string, role PeerRole, token string) (*peerResult, error) {
	argv := []string{h.SelfPath, PeerSubcommand, "--role", string(role), "--token", token}
	if role == RoleSignal {
		argv = append(argv, "--hold", signalHold.String())
	}
	cmd, err := m.Confine(ctx, mechanism.Workdir{Path: dir}, argv)
	if err != nil {
		return nil, fmt.Errorf("constructing sandbox: %w", err)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var res peerResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("no usable result (%v): %s", runErr, truncate(stderr.String(), 300))
	}
	return &res, nil
}
