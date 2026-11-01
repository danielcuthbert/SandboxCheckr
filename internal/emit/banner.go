package emit

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

var Owner = "@danielcuthbert"

const tagline = "measured containment, not assumed"
const castle = `
        |>>>                                   |>>>
        |                                      |
    _  _|_  _                              _  _|_  _
   |;|_|;|_|;|                            |;|_|;|_|;|
   \.   .    /              |>>>          \.    .   /
    \:   .  /               |              \:  .   /
     ||:   |             _  _|_  _          ||:   |
     ||:  .|            |;|_|;|_|;|         ||:   |
     ||:   |            \.    .   /         ||:   |
     ||:   |             \:  .   /          ||:   |
     ||:   |              ||:   |           ||:   |
  ___||:   |______________||:   |___________||:   |___
 |;|_|;|_|;|_|;|_|;|_|;|_|;|_|;|_|;|_|;|_|;|_|;|_|;|_|;|
 \.    .      .      .       .      .      .     .    /
  \:      .       .      .       .      .      .     /`

const waves = ` ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`

// Banner prints the sandcastle and host context.
//
// The art is centred over the same column as the wordmark: centring the text
// on the full terminal width while the castle stayed flush left was what made
// the two look detached on wide terminals.
func Banner(w io.Writer, c colors, rep model.Report) {
	artW := 0
	for _, l := range strings.Split(castle, "\n") {
		artW = max(artW, len(l))
	}
	pad := strings.Repeat(" ", max(0, (width-artW)/2))
	for _, l := range strings.Split(strings.TrimPrefix(castle, "\n"), "\n") {
		fmt.Fprintf(w, "%s%s%s%s\n", c.yellow, pad, l, c.reset)
	}
	fmt.Fprintf(w, "%s%s%s%s\n\n", c.blue, pad, waves, c.reset)
	fmt.Fprintf(w, "%s%s%s\n", c.bold, center(spaced("SandboxCheckr"), width), c.reset)
	fmt.Fprintf(w, "%s%s%s\n\n", c.dim, center(tagline+"  ·  "+strings.ToLower(Owner), width), c.reset)

	writeSysInfo(w, c, rep)
	fmt.Fprintln(w)
}

func writeSysInfo(w io.Writer, c colors, rep model.Report) {
	host := rep.Host.OS
	if rep.Host.Version != "" {
		host += " " + rep.Host.Version
	}
	host += " (" + rep.Host.Arch + ")"

	// One compact line of context instead of six: none of it changes what
	// the reader should do, so it should not push the verdict off screen.
	line := "v" + rep.Version + "  ·  " + host
	if rep.Host.Kernel != "" {
		line += "  ·  kernel " + rep.Host.Kernel
	}
	if rep.Host.CPUs > 0 {
		line += "  ·  " + strconv.Itoa(rep.Host.CPUs) + " cpus"
	}
	kv(w, c, "host", line, "")
	if rep.Host.Hostname != "" {
		kv(w, c, "machine", rep.Host.Hostname, "")
	}
	if rep.LaunchedFrom != nil && rep.LaunchedFrom.Name != "" {
		kv(w, c, "from", rep.LaunchedFrom.Name, "")
	}
	if rep.Host.User != "" {
		// Running as root is worth flagging in red: it is the worst starting
		// point for containing an untrusted process, and easy to miss.
		if rep.Host.Elevated {
			kv(w, c, "user", rep.Host.User+"  ROOT — elevated", c.red)
		} else {
			kv(w, c, "user", rep.Host.User, "")
		}
	}
}

// kv prints one indented, aligned key/value line. valColor, when set, colours
// the value (used to flag root).
func kv(w io.Writer, c colors, key, val, valColor string) {
	if valColor == "" {
		valColor = c.reset
	}
	fmt.Fprintf(w, "    %s%-9s%s %s%s%s\n", c.dim, key, c.reset, valColor, val, c.reset)
}

func spaced(s string) string {
	var parts []string
	for _, word := range strings.Fields(strings.ToUpper(s)) {
		parts = append(parts, strings.Join(strings.Split(word, ""), " "))
	}
	return strings.Join(parts, "   ")
}

func center(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return strings.Repeat(" ", (w-len(s))/2) + s
}
