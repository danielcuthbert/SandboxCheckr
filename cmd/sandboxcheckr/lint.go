package main

import (
	"fmt"
	"os"

	"github.com/danielcuthbert/sandboxcheckr/internal/sblint"
)

// runLint statically analyses a Seatbelt profile the user points it at — their
// own, a vendor's, or one discovered on the host. It runs nothing; it only
// reads and reasons about the profile text.
//
// Exit code is 1 on a high-severity finding, so it is usable as a CI gate on a
// checked-in profile.
func runLint(args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "-help") {
		fmt.Print(lintUsage)
		return 0
	}
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, lintUsage)
		return 2
	}
	body, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading profile:", err)
		return 2
	}

	res := sblint.Lint(string(body))

	fmt.Printf("%s\n", args[0])
	fmt.Printf("  egress: %s\n", res.Egress)
	fmt.Printf("  reads:  %s\n", readsWord(res.ReadsOpen))
	if res.Cooperative {
		fmt.Printf("  note:   egress is not enforced by the sandbox — any proxy-based control is bypassable\n")
	}

	if len(res.Findings) == 0 {
		fmt.Println("\n  no anti-patterns found")
		return 0
	}

	fmt.Println()
	high := false
	for _, f := range res.Findings {
		loc := ""
		if f.Line > 0 {
			loc = fmt.Sprintf(" (line %d)", f.Line)
		}
		fmt.Printf("  [%s] %s%s\n      %s\n", f.Severity, f.Title, loc, f.Detail)
		if f.Severity == "high" {
			high = true
		}
	}
	if high {
		return 1
	}
	return 0
}

func readsWord(open bool) string {
	if open {
		return "OPEN (secrets outside the workdir are readable)"
	}
	return "restricted"
}

const lintUsage = `sandboxcheckr lint — statically audit a macOS Seatbelt (.sb) profile

USAGE
  sandboxcheckr lint <profile.sb>

Reads the profile and reports its egress posture (open / proxied / denied),
whether reads are left open, and anti-patterns such as (allow default) or an
unrestricted mach-lookup. Nothing is executed.

EXIT STATUS
  0  no high-severity findings
  1  at least one high-severity finding (usable as a CI gate)
  2  usage or read error
`
