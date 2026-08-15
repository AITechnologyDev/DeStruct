package unflutter

import (
	"flag"
	"fmt"
	"os"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/dartfmt"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/elfx"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/snapshot"
)

// cmdDoctor handles "unflutter doctor <libapp.so>" — diagnostic scan.
func cmdDoctor(args []string) error {
	args = reorderPositionalArg(args)
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	maxSteps := fs.Int("max-steps", 0, "global loop cap")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: unflutter doctor <libapp.so>")
	}

	libPath := fs.Arg(0)
	if resolvePositionalLib(libPath) == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}

	ef, err := elfx.Open(libPath)
	if err != nil {
		fmt.Fprintf(os.Stdout, "ELF:        FAIL (%v)\n", err)
		return fmt.Errorf("elf: %w", err)
	}
	defer ef.Close()
	fmt.Fprintf(os.Stdout, "ELF:        OK (%d bytes)\n", ef.FileSize())

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Snapshot:    FAIL (%v)\n", err)
		return fmt.Errorf("snapshot: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Snapshot:    OK\n")

	if info.Version != nil {
		fmt.Fprintf(os.Stdout, "Dart:        %s\n", info.Version.DartVersion)
		if info.Version.CompressedPointers {
			fmt.Fprintf(os.Stdout, "Pointers:    compressed (4 bytes)\n")
		} else {
			fmt.Fprintf(os.Stdout, "Pointers:    uncompressed (8 bytes)\n")
		}
		if !info.Version.Supported {
			fmt.Fprintf(os.Stdout, "Support:     UNSUPPORTED\n")
			return fmt.Errorf("unsupported dart version: %s", info.Version.DartVersion)
		}
		fmt.Fprintf(os.Stdout, "Support:     OK\n")
	}

	if info.VmHeader != nil {
		fmt.Fprintf(os.Stdout, "Hash:        %s\n", info.VmHeader.SnapshotHash)
	}

	if len(info.Diags) > 0 {
		fmt.Fprintf(os.Stdout, "Diagnostics: %d\n", len(info.Diags))
		for _, d := range info.Diags {
			fmt.Fprintf(os.Stdout, "  %s\n", d)
		}
	}

	return nil
}
