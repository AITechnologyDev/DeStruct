package main

import (
	"flag"
	"fmt"

	"github.com/destruct/destruct/internal/hermes"
)

func runPatch(args []string) error {
	fs := flag.NewFlagSet("patch", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: destruct patch <input.hbc> [flags]

Quick point-patch (or search) of Hermes bytecode by string operand: finds
the GetById using the given string and neutralizes the check that follows it.

Flags:
  -t, --patch-string <s>   patch the instruction using this string operand
  -s, --search <s>         search for a string in the bytecode; with no
                           -t given, only searches and patches nothing
  -o, --output <file>      output path (default: patch the input in place)
      --check-only         only patch CHECK instructions (safer than
                           patching every occurrence)
`)
	}

	var patchString, search, output string
	stringFlag(fs, &patchString, "t", "patch-string", "", "string operand to patch")
	stringFlag(fs, &search, "s", "search", "", "string to search for")
	stringFlag(fs, &output, "o", "output", "", "output path")
	var checkOnly bool
	fs.BoolVar(&checkOnly, "check-only", false, "only patch CHECK instructions")

	if err := parseArgs(fs, args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return fmt.Errorf("missing input file")
	}
	input := rest[0]

	file, err := hermes.ParseFile(input)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", input, err)
	}
	patcher := hermes.NewPatcher(file)

	if patchString == "" {
		if search == "" {
			fs.Usage()
			return fmt.Errorf("nothing to do: give -t/--patch-string to patch, or -s/--search to search")
		}
		results := patcher.SearchString(search, false)
		for _, r := range results {
			fmt.Printf("  func #%d %s @ 0x%08x (offset 0x%x in function)\n", r.FuncIdx, r.FuncName, r.Offset, r.RelOffset)
		}
		fmt.Printf("Found %d match(es)\n", len(results))
		return nil
	}

	n, err := patcher.QuickPatchString(patchString, "true", checkOnly)
	if err != nil {
		return fmt.Errorf("patching %q: %w", patchString, err)
	}
	fmt.Printf("Patched %d occurrence(s)\n", n)
	if n == 0 {
		return nil
	}

	outPath := output
	if outPath == "" {
		outPath = input
	}
	if err := patcher.Save(outPath); err != nil {
		return fmt.Errorf("saving %s: %w", outPath, err)
	}
	fmt.Printf("Saved: %s\n", outPath)
	return nil
}
