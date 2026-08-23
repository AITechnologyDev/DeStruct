package main

import (
	"flag"
	"fmt"
)

func runPE(args []string) error {
	fs := flag.NewFlagSet("pe", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: destruct pe <program.exe|program.dll> [flags]

Disassembles a PE binary (Windows .exe/.dll), same principle as "destruct
elf" but for PE. Not yet implemented - there's no PE parser in this
codebase yet, only the ELF one "destruct elf" uses.

Flags:
  -o, --output <dir>   output directory (default "output")
  -v, --verbose        verbose output
`)
	}

	// -o/-v are accepted (matching COMMANDS.md's documented flags and
	// destruct elf's interface) but unused: there's nothing to run yet.
	stringFlag(fs, new(string), "o", "output", "output", "output directory")
	boolFlag(fs, new(bool), "v", "verbose", false, "verbose output")

	if err := parseArgs(fs, args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return fmt.Errorf("missing input file")
	}

	return fmt.Errorf("PE disassembly is not implemented yet (no PE parser exists in this codebase - see internal/native for the ELF equivalent)")
}
