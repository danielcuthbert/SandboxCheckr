//go:build !linux

package main

import "os/exec"

func armRunnerPdeathsig(cmd *exec.Cmd) {}
