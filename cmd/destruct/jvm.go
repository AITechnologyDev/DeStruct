package main

import (
	"flag"
	"fmt"

	"github.com/destruct/destruct/internal/pipeline"
)

func runJVM(args []string) error {
	fs := flag.NewFlagSet("jvm", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: destruct jvm <input.class|input.jar> [flags]

Decompiles a JVM .class file, or a whole .jar archive (streamed one class
at a time so memory use stays flat), to a tree of .java files.

Flags:
  -o, --output <dir>   output directory (default "output")
  -v, --verbose        verbose output
      --deobfuscate    enable deobfuscation
      --no-project     do not generate a project structure
`)
	}

	var output string
	stringFlag(fs, &output, "o", "output", "output", "output directory")
	var verbose bool
	boolFlag(fs, &verbose, "v", "verbose", false, "verbose output")
	var deobf bool
	fs.BoolVar(&deobf, "deobfuscate", false, "enable deobfuscation")
	var noProject bool
	fs.BoolVar(&noProject, "no-project", false, "do not generate a project structure")

	if err := parseArgs(fs, args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return fmt.Errorf("missing input file")
	}

	p := pipeline.New(pipeline.Options{
		Input:   rest[0],
		Output:  output,
		Format:  pipeline.FormatJVM,
		Verbose: verbose,
		Deobf:   deobf,
		Project: !noProject,
	})
	return p.Run()
}
