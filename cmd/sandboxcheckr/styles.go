package main

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/danielcuthbert/sandboxcheckr/internal/emit"
	"github.com/danielcuthbert/sandboxcheckr/internal/tty"
)

// summaryColumns is the width section headers fill to, the same default the
// report uses.
const summaryColumns = 74

var (
	stylesOnce sync.Once
	styles     emit.Styles
)

// summaryStyle is the palette for everything the tool says around the program
// rather than by it: setup chatter, the proxy's exit summary, the refusal
// report. Decided once, on stderr, because that is where all of it goes and a
// program's own stdout has to stay clean.
func summaryStyle() emit.Styles {
	stylesOnce.Do(func() {
		term := os.Getenv("TERM")
		// The same rule the report uses, so a summary header and a report rule
		// are drawn from the same characters on the same terminal.
		emit.ApplyGlyphs(term == "dumb" || !utf8Locale())
		styles = emit.Palette(colorEnabled(false, tty.IsTerminal(os.Stderr), term))
	})
	return styles
}

// forceNoColor turns colour off for this process and any it starts. run calls
// it for --no-color; NO_COLOR in the environment does the same without it.
func forceNoColor() {
	os.Setenv("NO_COLOR", "1")
	stylesOnce.Do(func() { styles = emit.Styles{} })
}

// runColumns is summaryColumns narrowed to fit a smaller terminal.
func runColumns() int {
	if tty.IsTerminal(os.Stderr) {
		if w := tty.Width(os.Stderr); w > 0 && w < summaryColumns {
			return w
		}
	}
	return summaryColumns
}

// line writes one line of setup chatter to stderr. It sits back in the palette
// because a reader skims past it to get to what the program printed.
func line(w io.Writer, st emit.Styles, format string, args ...any) {
	fmt.Fprintf(w, "%s%s%s\n", st.Dim, fmt.Sprintf(format, args...), st.Reset)
}

// note is line for the rows that sit under a section header, which are indented
// like everything else in the block.
func note(w io.Writer, st emit.Styles, format string, args ...any) {
	line(w, st, "  "+format, args...)
}

// lineWarn writes a line a reader has to act on, so it does not sit back.
func lineWarn(w io.Writer, st emit.Styles, format string, args ...any) {
	fmt.Fprintf(w, "%s%s%s\n", st.Yellow, fmt.Sprintf(format, args...), st.Reset)
}

// lineBad writes a line saying something went wrong with the tool itself, as
// opposed to a refusal by the sandbox, which is the tool working.
func lineBad(w io.Writer, st emit.Styles, format string, args ...any) {
	fmt.Fprintf(w, "%s%s%s\n", st.Red, fmt.Sprintf(format, args...), st.Reset)
}

func say(format string, args ...any)     { line(os.Stderr, summaryStyle(), format, args...) }
func sayWarn(format string, args ...any) { lineWarn(os.Stderr, summaryStyle(), format, args...) }

// section writes a header in the grammar the report uses.
func section(w io.Writer, st emit.Styles, title, note string) {
	fmt.Fprint(w, emit.Section(st, runColumns(), title, note))
}

// sectionNote is a header whose note carries meaning: a green "nothing used"
// against a red "2 trips" is the fastest read there is.
func sectionNote(w io.Writer, st emit.Styles, noteStyle, title, note string) {
	fmt.Fprint(w, emit.SectionNote(st, noteStyle, runColumns(), title, note))
}
