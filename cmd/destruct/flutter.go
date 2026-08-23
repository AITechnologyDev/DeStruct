package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/destruct/destruct/internal/pipeline"
)

func runFlutter(args []string) error {
	fs := flag.NewFlagSet("flutter", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: destruct flutter <libapp.so|app.apk> [flags]

Disassembles a Flutter/Dart AOT libapp.so (an .apk has its
lib/arm64-v8a/libapp.so extracted first).

Flags:
  -o, --output <dir>   output directory (default "output")
  -v, --verbose        verbose output
      --decompile      decompile to .dart instead of assembler (not yet implemented)
`)
	}

	var output string
	stringFlag(fs, &output, "o", "output", "output", "output directory")
	var verbose bool
	boolFlag(fs, &verbose, "v", "verbose", false, "verbose output")
	var decompile bool
	fs.BoolVar(&decompile, "decompile", false, "decompile to .dart")

	if err := parseArgs(fs, args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return fmt.Errorf("missing input file")
	}
	input := rest[0]

	ext := strings.ToLower(filepath.Ext(input))
	if ext != ".so" && ext != ".apk" {
		return fmt.Errorf("input must be a .so or .apk file, got %q", input)
	}
	if _, err := os.Stat(input); err != nil {
		return fmt.Errorf("input file: %w", err)
	}
	if decompile {
		return fmt.Errorf("--decompile (.dart output) is not implemented yet; omit the flag for ARM64 disassembly output")
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  output,
		Format:  pipeline.FormatFlutter,
		Verbose: verbose,
	})
	return p.Run()
}
