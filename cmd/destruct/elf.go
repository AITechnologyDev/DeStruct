package main

import (
	"flag"
	"fmt"

	"github.com/destruct/destruct/internal/pipeline"
)

func runELF(args []string) error {
	fs := flag.NewFlagSet("elf", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: destruct elf <binary.so> [flags]

Disassembles all code sections of a native ELF binary (ARM/ARM64/x86),
annotated with symbols from .symtab when present.

Flags:
  -o, --output <dir>   output directory (default "output")
  -v, --verbose        verbose output
`)
	}

	var output string
	stringFlag(fs, &output, "o", "output", "output", "output directory")
	var verbose bool
	boolFlag(fs, &verbose, "v", "verbose", false, "verbose output")

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
		Format:  pipeline.FormatELF,
		Verbose: verbose,
	})
	return p.Run()
}
