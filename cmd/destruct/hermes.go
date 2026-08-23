package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/destruct/destruct/internal/hermes"
)

func runHermes(args []string) error {
	fs := flag.NewFlagSet("hermes", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: destruct hermes <input.hbc|input.bundle> [flags]

Disassembles (or decompiles) Hermes bytecode (React Native).

Flags:
  -o, --output <dir>   output directory (default "output")
  -v, --verbose        verbose output
      --decompile      decompile to readable JS instead of assembler
      --hermes-dec     exact hermes-dec text format (default true;
                       --hermes-dec=false uses the older approximate format)
  -p, --patch          simplified format for manual patching
      --patch-map      exact format plus a per-operand file-offset map
      --hex            hex-editor-friendly output, absolute file offsets
      --deobfuscate    enable deobfuscation

Precedence when several output-format flags are given: --decompile, then
-p/--patch, then --patch-map, then --hex, then --hermes-dec.
`)
	}

	var output string
	stringFlag(fs, &output, "o", "output", "output", "output directory")
	var verbose bool
	boolFlag(fs, &verbose, "v", "verbose", false, "verbose output")
	var decompile bool
	fs.BoolVar(&decompile, "decompile", false, "decompile to JS")
	var hermesDec bool
	fs.BoolVar(&hermesDec, "hermes-dec", true, "use the exact hermes-dec text format")
	var patch bool
	boolFlag(fs, &patch, "p", "patch", false, "simplified format for manual patching")
	var patchMap bool
	fs.BoolVar(&patchMap, "patch-map", false, "exact format + per-operand offset map")
	var hexOut bool
	fs.BoolVar(&hexOut, "hex", false, "hex-editor-friendly absolute offsets")
	fs.Bool("deobfuscate", false, "enable deobfuscation")

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

	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	base := filepath.Base(input)

	if decompile {
		outPath := filepath.Join(output, base+".js")
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", outPath, err)
		}
		defer f.Close()

		hermes.NewDecompiler(file).DecompileAll(f)
		fmt.Printf("Decompiled: %s\n", outPath)
		return nil
	}

	outPath := filepath.Join(output, base+".hasm")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outPath, err)
	}
	defer f.Close()

	dis := hermes.NewDisassembler(file)
	dis.Verbose = verbose

	switch {
	case patch:
		dis.DisassembleAllPatch(f)
	case patchMap:
		dis.DisassembleAllPatchMap(f)
	case hexOut:
		dis.DisassembleAllHex(f)
	case !hermesDec:
		dis.DisassembleAllHermesDec(f)
	default:
		dis.DisassembleAllExact(f)
	}

	fmt.Printf("Disassembled: %s\n", outPath)
	return nil
}
