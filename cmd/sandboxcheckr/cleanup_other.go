//go:build !unix

package main

// sweepStalePrivateDirs does nothing where the tool's scratch directories are
// not created, and where the ownership and liveness checks below would have no
// portable meaning.
func sweepStalePrivateDirs() {}
