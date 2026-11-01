package emit

import (
	"fmt"
	"io"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// Gaps prints only the threat-model gap list.
//
// Separated from the full report because this is the section people need to
// re-read after they have chosen a configuration, and burying it under the
// capability tables makes it easy to skip.
func Gaps(w io.Writer, rep model.Report, color bool) {
	c := palette(color)

	if rep.SelfCheck.Confined {
		fmt.Fprintf(w, "%s! SandboxCheckr was confined during this run; the list below is incomplete.%s\n\n",
			c.yellow, c.reset)
	}
	if rep.Recommended != "" {
		fmt.Fprintf(w, "Remaining exposure under %s%s%s:\n\n", c.bold, rep.Recommended, c.reset)
	}
	writeGaps(w, c, rep.Gaps)
}
