package unflutter

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/pipeline"
)

// cmdIDANew handles "unflutter ida <libapp.so>" — full pipeline + IDA decompilation.
func cmdIDANew(args []string) error {
	args = reorderPositionalArg(args)
	fs := flag.NewFlagSet("ida", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.unflutter/)")
	all := fs.Bool("all", false, "decompile ALL functions")
	gui := fs.Bool("gui", false, "launch IDA GUI after generating artifacts")
	pythonBin := fs.String("python", "", "python3 binary (default: auto-detect)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	var _verbose bool
	fs.BoolVar(&_verbose, "verbose", false, "")
	fs.BoolVar(&_verbose, "v", false, "")
	from := fs.String("from", "", "reuse existing disasm output directory")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: unflutter ida <libapp.so> [flags]")
	}

	libPath := fs.Arg(0)
	absLibPath := resolvePositionalLib(libPath)
	if absLibPath == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	// Step 1: Run pipeline (disasm + signal + meta).
	var pipeResult *pipeline.Result
	if *from != "" {
		_, err := pipeline.RunSignalStage(*from, 2, false, quiet, os.Stderr)
		if err != nil {
			return fmt.Errorf("signal: %w", err)
		}
		metaPath, err := pipeline.RunMetaStage(*from, "", *all, quiet, os.Stderr)
		if err != nil {
			return fmt.Errorf("meta: %w", err)
		}
		pipeResult = &pipeline.Result{OutDir: *from, MetaPath: metaPath}
	} else {
		var err error
		pipeResult, err = pipeline.Run(pipeline.Opts{
			LibPath:   libPath,
			OutDir:    *outDir,
			MaxSteps:  *maxSteps,
			Signal:    true,
			Meta:      true,
			DecompAll: *all,
			Quiet:     quiet,
		})
		if err != nil {
			return err
		}
	}

	metaPath := pipeResult.MetaPath
	if metaPath == "" {
		metaPath = filepath.Join(pipeResult.OutDir, "flutter_meta.json")
	}

	// Step 2: Copy script into artifact directory and use that path.
	absOutDir, _ := filepath.Abs(pipeResult.OutDir)
	scriptPath := filepath.Join(absOutDir, "ida", "unflutter_apply.py")
	if copyErr := copyIDAArtifacts(pipeResult.OutDir); copyErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not copy IDA script: %v\n", copyErr)
		// Fallback: find script in original location.
		var findErr error
		scriptPath, findErr = findIDAScript()
		if findErr != nil {
			return fmt.Errorf("IDA script not found: %v (copy also failed: %v)", findErr, copyErr)
		}
	}

	// Step 3: Handle --gui (launch IDA interactive).
	if *gui {
		return launchIDAGUI(absLibPath, pipeResult.OutDir)
	}

	// Step 4: Find python3 with idapro.
	python, err := findPython(*pythonBin)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "python: %s\n", python)
	fmt.Fprintf(os.Stderr, "script: %s\n", scriptPath)

	// Step 6: Run idalib.
	decompDir := filepath.Join(pipeResult.OutDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)

	if *all {
		fmt.Fprintf(os.Stderr, "running IDA idalib analysis (decompiling ALL functions)...\n")
	} else {
		fmt.Fprintf(os.Stderr, "running IDA idalib analysis (signal functions only, use --all for everything)...\n")
	}
	fmt.Fprintf(os.Stderr, "  decompile output: %s\n", absDecompDir)

	cmd := exec.Command(python, scriptPath, absLibPath, absMetaPath, absDecompDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ida script failed: %w", err)
	}

	cCount := countDecompiledFiles(absDecompDir)
	fmt.Fprintf(os.Stderr, "decompiled %d functions → %s\n", cCount, absDecompDir)

	return nil
}

// launchIDAGUI starts IDA in interactive mode.
func launchIDAGUI(libPath, outDir string) error {
	// Try to find ida64 in PATH or common locations.
	ida, err := findIDA64()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nLaunching IDA...\n")
	fmt.Fprintf(os.Stderr, "  Binary: %s\n", libPath)
	fmt.Fprintf(os.Stderr, "  Meta:   %s/flutter_meta.json\n\n", outDir)

	cmd := exec.Command(ida, libPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

// findIDA64 locates ida64 binary.
func findIDA64() (string, error) {
	if p, err := exec.LookPath("ida64"); err == nil {
		return p, nil
	}

	// Common macOS locations.
	candidates := []string{
		"/Applications/IDA Pro.app/Contents/MacOS/ida64",
		"/Applications/IDA Pro 8.4/ida64.app/Contents/MacOS/ida64",
		"/Applications/IDA Pro 9.0/ida64.app/Contents/MacOS/ida64",
		filepath.Join(os.Getenv("HOME"), "ida/ida64"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf(`ida64 not found in PATH

Add IDA to your PATH or install it:
  export PATH="$PATH:/Applications/IDA Pro.app/Contents/MacOS"`)
}
