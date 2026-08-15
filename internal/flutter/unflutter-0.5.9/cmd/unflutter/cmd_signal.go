package unflutter

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/cli"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/pipeline"
)

// cmdSignalPipeline handles "unflutter signal <libapp.so>" — full pipeline through signal.
func cmdSignalPipeline(args []string) error {
	args = reorderPositionalArg(args)
	fs := flag.NewFlagSet("signal", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.unflutter/)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	k := fs.Int("k", 2, "context hops from signal functions")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	var _verbose bool // accepted for backwards compat, now default
	fs.BoolVar(&_verbose, "verbose", false, "")
	fs.BoolVar(&_verbose, "v", false, "")
	from := fs.String("from", "", "reuse existing disasm output directory")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// If --from is set, skip ELF parse and just run signal.
	if *from != "" {
		if *outDir == "" {
			*outDir = *from
		}
		sigResult, err := pipeline.RunSignalStage(*from, *k, false, quiet, os.Stderr)
		if err != nil {
			return err
		}
		printSignalSummary(sigResult, *outDir, "")
		return nil
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: unflutter signal <libapp.so> [flags]")
	}

	libPath := fs.Arg(0)
	if resolvePositionalLib(libPath) == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	result, err := pipeline.Run(pipeline.Opts{
		LibPath:  libPath,
		OutDir:   *outDir,
		MaxSteps: *maxSteps,
		Signal:   true,
		SignalK:  *k,
		Quiet:    quiet,
	})
	if err != nil {
		return err
	}

	printSignalSummary(&pipeline.SignalResult{SignalCount: result.SignalCount}, result.OutDir, libPath)
	return nil
}

func printSignalSummary(sig *pipeline.SignalResult, outDir, libPath string) {
	absOut, _ := filepath.Abs(outDir)
	signalHTML := filepath.Join(absOut, "signal.html")

	fmt.Fprintf(os.Stderr, "\n%ssignal complete%s  %s%d%s functions\n",
		cli.Pink, cli.Reset, cli.Gold, sig.SignalCount, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %ssignal.html%s     interactive signal graph\n", cli.Blue, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %ssignal.svg%s      signal graph visualization\n", cli.Blue, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %ssignal_cfg.dot%s  connected CFG\n", cli.Blue, cli.Reset)

	fmt.Fprintf(os.Stderr, "\n%snext%s\n", cli.Pink, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %sopen %s%s\n", cli.White, signalHTML, cli.Reset)
	if libPath != "" {
		fmt.Fprintf(os.Stderr, "  %sunflutter ghidra %s --from %s%s\n", cli.White, libPath, absOut, cli.Reset)
		fmt.Fprintf(os.Stderr, "  %sunflutter ida %s --from %s%s\n", cli.White, libPath, absOut, cli.Reset)
	} else {
		fmt.Fprintf(os.Stderr, "  %sunflutter ghidra <libapp.so> --from %s%s\n", cli.White, absOut, cli.Reset)
		fmt.Fprintf(os.Stderr, "  %sunflutter ida <libapp.so> --from %s%s\n", cli.White, absOut, cli.Reset)
	}
}
