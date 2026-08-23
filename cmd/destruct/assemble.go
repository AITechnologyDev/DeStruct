package main

import (
	"flag"
	"fmt"

	"github.com/destruct/destruct/internal/hermes"
)

func runAssemble(args []string) error {
	fs := flag.NewFlagSet("assemble", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: destruct assemble <input.hasm> -i <original.hbc> -o <output.hbc> [flags]

Reassembles a .hasm file (produced by "destruct hermes") back into .hbc,
recompiling only the functions whose text actually changed.

Flags:
  -i, --input <file>    original .hbc/.bundle the .hasm text references (required)
  -o, --output <file>   patched .hbc output path (required)
      --hermes-dec      use the exact hermes-dec assembler (default true;
                        matches the exact-format .hasm "destruct hermes" writes
                        by default; --hermes-dec=false uses the older
                        simplified-format assembler instead)
`)
	}

	var input, output string
	stringFlag(fs, &input, "i", "input", "", "original .hbc/.bundle file")
	stringFlag(fs, &output, "o", "output", "", "output .hbc path")
	var hermesDec bool
	fs.BoolVar(&hermesDec, "hermes-dec", true, "use the exact hermes-dec assembler")

	if err := parseArgs(fs, args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return fmt.Errorf("missing .hasm input file")
	}
	hasmPath := rest[0]
	if input == "" {
		return fmt.Errorf("assemble requires -i/--input (the original .hbc/.bundle)")
	}
	if output == "" {
		return fmt.Errorf("assemble requires -o/--output")
	}

	if !hermesDec {
		sa := hermes.NewSmartAssembler()
		if err := sa.PatchFile(input, hasmPath, output); err != nil {
			return fmt.Errorf("assembling %s: %w", hasmPath, err)
		}
		fmt.Printf("Wrote %s\n", output)
		return nil
	}

	file, err := hermes.ParseFile(input)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", input, err)
	}

	asm := hermes.NewHermesDecAssembler(file)
	result, err := asm.AssembleAndPatch(hasmPath)
	if err != nil {
		return fmt.Errorf("assembling %s: %w", hasmPath, err)
	}
	if len(result.ChangedFunctions) == 0 {
		fmt.Println("No changes detected; nothing to patch")
	} else {
		fmt.Printf("Patched %d function(s), size delta %+d bytes\n", len(result.ChangedFunctions), result.SizeDelta)
	}

	if err := file.Write(output); err != nil {
		return fmt.Errorf("writing %s: %w", output, err)
	}
	fmt.Printf("Wrote %s\n", output)
	return nil
}
