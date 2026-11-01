// Package selfcheck answers a question that has to be settled before any other
// check runs: is SandboxCheckr itself confined?
//
// This matters because confinement is invisible from the inside unless you look
// for it. A confined process asking "can I create a sandbox here?" gets told no
// — not because the host lacks sandboxing, but because the host will not let an
// already-sandboxed process apply another profile. A detector that does not
// account for this reports "no sandboxing available" on a machine with working
// sandboxing, which is the most dangerous answer it could give: the user
// concludes they cannot contain anything and runs the untrusted thing bare.
//
// So stage 1 runs first and gates everything after it. When we are confined,
// downstream results are reported INDETERMINATE rather than ABSENT.
package selfcheck

import "github.com/danielcuthbert/sandboxcheckr/internal/model"

// Run determines whether the current process is confined, returning the
// evidence alongside the verdict so a reader can check our reasoning.
func Run() model.Confinement {
	return detect()
}

// signal is one piece of evidence gathered by a platform detector.
type signal struct {
	// present is whether this signal fired.
	present bool
	// kind labels the confinement technology, e.g. "seatbelt".
	kind string
	// detail is the human-readable evidence line.
	detail string
}

// conclude folds a set of signals into a Confinement. Any single firing signal
// is enough to call us confined: these are all positive indicators, and a false
// "confined" costs the user a warning, whereas a false "unconfined" costs them
// a silently wrong report.
func conclude(sigs []signal) model.Confinement {
	c := model.Confinement{}
	for _, s := range sigs {
		if !s.present {
			continue
		}
		c.Confined = true
		if c.Kind == "" {
			c.Kind = s.kind
		}
		c.Evidence = append(c.Evidence, s.detail)
	}
	return c
}
