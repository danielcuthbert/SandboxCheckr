//go:build !unix

package main

import "os/exec"

// signalled has no meaning where an exit status carries no signal: a program
// either ran and returned something or did not run at all.
func signalled(exitErr *exec.ExitError) bool { return false }
