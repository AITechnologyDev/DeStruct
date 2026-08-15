// Command unflutter-standalone is the standalone CLI entry point for the
// unflutter package (internal/flutter/unflutter-0.5.9/cmd/unflutter),
// preserved so `go install .../cmd/unflutter-standalone@latest` still
// produces a usable, independent `unflutter` binary for anyone who wants
// one - the same package is also imported directly (in-process, no
// exec.Command) by destruct's own CLI (cmd/destruct), which is the
// integration this split was made to support.
package main

import (
	"os"

	unflutter "github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/cmd/unflutter"
)

func main() {
	exitCode, _ := unflutter.Run(os.Args[1:])
	os.Exit(exitCode)
}
