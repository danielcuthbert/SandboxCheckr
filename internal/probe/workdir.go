package probe

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// Project-directory probes (SBX-011).
//
// The workdir is writable by design, so the other file probes say nothing
// about it. These two look at the files inside it that matter most: secrets
// kept next to the code, and files another program will execute later.
//
// The harness seeds the scratch workdir with decoys BEFORE the sandbox starts
// (SeedWorkdir), for two reasons: a probe can only judge access to a file that
// exists, and bubblewrap protects only paths present at launch — seeding first
// measures the configuration a user actually gets.

// dotenvMarker is the decoy .env content. Reading it back is the only proof
// the contents were reachable: bubblewrap replaces the file with an empty one
// rather than refusing the open, so "open succeeded" is not the finding.
const dotenvMarker = "SANDBOXCHECKR_DECOY=not-a-secret\n"

// SeedWorkdir creates the decoys the workdir probes look for. It runs in the
// parent, unconfined, and only ever writes inside the scratch directory the
// harness created, which is removed afterwards.
func SeedWorkdir(dir string) error {
	for _, d := range []string{".git/hooks", ".vscode"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}
	files := map[string]string{
		".env":        dotenvMarker,
		".git/config": "[core]\n",
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// probeWorkdirSecrets reports whether a .env file in the workdir is readable.
func probeWorkdirSecrets(workdir string) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeWorkdirSecrets, Want: model.VerdictBlocked}
	if workdir == "" {
		r.Verdict, r.Detail = model.VerdictSkipped, "no scratch workdir was provided"
		return r
	}
	f, err := os.Open(filepath.Join(workdir, ".env"))
	if err != nil {
		r.Verdict, r.Errno = classify(err)
		r.Err = err.Error()
		if r.Verdict == model.VerdictBlocked {
			r.Detail = ".env files in the project directory cannot be read"
		} else {
			r.Detail = "the decoy .env could not be opened for a reason other than a permission refusal"
		}
		return r
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	_ = f.Close()
	switch {
	case err != nil:
		r.Verdict, r.Errno = classify(err)
		r.Err = err.Error()
		if r.Verdict == model.VerdictBlocked {
			r.Detail = ".env files in the project directory cannot be read"
		} else {
			r.Detail = "reading the decoy .env failed inconclusively"
		}
	case string(data) == dotenvMarker:
		r.Verdict = model.VerdictAllowed
		r.Detail = ".env files in the project directory are readable; credentials kept next to the code " +
			"(database URLs, cloud and API keys) are one command away from any model or package the agent runs"
	case len(data) == 0:
		r.Verdict = model.VerdictBlocked
		r.Detail = ".env files in the project directory are replaced with an empty file inside the sandbox"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "the decoy .env had unexpected contents; not counted either way"
	}
	return r
}

// probeDeferredExec attempts the writes that turn into unconfined execution
// later: creating a git hook, modifying git config, and adding an editor task.
// Every write is a create-exclusive of a new file or an append-open that
// writes nothing, inside the scratch workdir.
func probeDeferredExec(workdir string) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeDeferredExec, Want: model.VerdictBlocked}
	if workdir == "" {
		r.Verdict, r.Detail = model.VerdictSkipped, "no scratch workdir was provided"
		return r
	}
	attempts := []struct {
		rel    string
		create bool
	}{
		{".git/hooks/pre-commit", true},
		{".git/config", false},
		{".vscode/tasks.json", true},
	}
	var written []string
	blocked := 0
	for _, a := range attempts {
		p := filepath.Join(workdir, a.rel)
		var f *os.File
		var err error
		if a.create {
			f, err = os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		} else {
			f, err = os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		}
		if err == nil {
			_ = f.Close()
			if a.create {
				_ = os.Remove(p)
			}
			written = append(written, a.rel)
			continue
		}
		if v, _ := classify(err); v == model.VerdictBlocked {
			blocked++
		}
	}
	switch {
	case len(written) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "can write files that run outside the sandbox later (" + strings.Join(written, ", ") +
			"); a planted hook or editor task executes unconfined at your next commit or editor launch"
	case blocked == len(attempts):
		r.Verdict = model.VerdictBlocked
		r.Detail = "git hooks, git config and editor tasks in the project cannot be written"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "deferred-execution writes were inconclusive (some failed for reasons other than a permission refusal)"
	}
	return r
}
