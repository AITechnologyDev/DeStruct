// Package unflutter is the Dart AOT snapshot analyzer, importable as a
// library (via Run) so it can run in the same process as a caller
// instead of needing to be invoked as a separate binary via exec.Command.
//
// This file used to be main.go with a standalone `package main` and a
// `func main()` that called os.Exit directly. The CLI dispatch logic
// itself (which subcommand maps to which cmdXXX function, deprecation
// warnings, etc.) is UNCHANGED from that version - only the entry/exit
// mechanism changed: Run takes args explicitly (args[0] is what used to
// be os.Args[1]) instead of reading the process-global os.Args, and
// returns an exit code and error instead of calling os.Exit, so a caller
// running unflutter in-process can decide what to do with the result
// (print the error, decide its own process exit code, etc.) rather than
// having unflutter unconditionally terminate the whole process out from
// under it.
package unflutter

import (
	"fmt"
	"os"
	"strings"
)

// Run executes one unflutter command. args corresponds to what
// os.Args[1:] used to be for the standalone binary (args[0] is the
// subcommand or, for the positional-file-path form, the file path
// itself). Output that the original implementation wrote to os.Stdout/
// os.Stderr still goes there directly (every cmdXXX function already
// did its own I/O this way; that part is unchanged) - only process
// termination changed. Returns the exit code the standalone binary
// would have used (0 for success/help, 1 for any error) and the error
// itself, if any, so a caller can log/handle it without unflutter
// having decided the whole process's fate.
func Run(args []string) (exitCode int, err error) {
	if len(args) < 1 {
		usage()
		return 1, fmt.Errorf("no command or file given")
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	// --- Primary commands (new CLI) ---
	case "meta":
		err = cmdMeta(rest)
	case "ghidra":
		err = cmdGhidra(rest)
	case "ida":
		err = cmdIDA(rest)
	case "doctor":
		err = cmdDoctor(rest)
	case "find-libapp":
		err = cmdFindLibapp(rest)
	case "parity":
		err = cmdParity(rest)
	case "inventory":
		err = cmdInventory(rest)
	case "_debug":
		err = cmdDebug(rest)

	// --- Deprecated commands (shims with warnings) ---
	case "disasm":
		deprecationWarning("disasm", "unflutter <libapp.so>")
		err = cmdDisasm(rest)
	case "signal":
		// "signal" with --in is the old form; without flags it's the new positional form.
		if hasFlag(rest, "-in", "--in") {
			deprecationWarning("signal --in", "unflutter signal <libapp.so>")
			err = cmdSignal(rest)
		} else {
			err = cmdSignalPipeline(rest)
		}
	case "decompile":
		deprecationWarning("decompile", "unflutter ghidra <libapp.so>")
		err = cmdDecompile(rest)
	case "flutter-meta", "ghidra-meta":
		deprecationWarning(cmd, "unflutter meta <libapp.so>")
		err = cmdFlutterMeta(rest)
	case "scan":
		deprecationWarning("scan", "unflutter doctor <libapp.so> or unflutter _debug scan")
		err = cmdScan(rest)
	case "dump":
		deprecationWarning("dump", "unflutter _debug dump")
		err = cmdDump(rest)
	case "objects":
		deprecationWarning("objects", "unflutter _debug objects")
		err = cmdObjects(rest)
	case "strings":
		deprecationWarning("strings", "unflutter _debug strings")
		err = cmdStrings(rest)
	case "graph":
		deprecationWarning("graph", "unflutter _debug graph")
		err = cmdGraph(rest)
	case "clusters":
		deprecationWarning("clusters", "unflutter _debug clusters")
		err = cmdClusters(rest)
	case "render":
		deprecationWarning("render", "unflutter _debug render")
		err = cmdRender(rest)
	case "thr-audit":
		deprecationWarning("thr-audit", "unflutter _debug thr-audit")
		err = cmdTHRAudit(rest)
	case "thr-cluster":
		deprecationWarning("thr-cluster", "unflutter _debug thr-cluster")
		err = cmdTHRCluster(rest)
	case "thr-classify":
		deprecationWarning("thr-classify", "unflutter _debug thr-classify")
		err = cmdTHRClassify(rest)
	case "find-libapp-batch":
		deprecationWarning("find-libapp-batch", "unflutter _debug find-libapp-batch")
		err = cmdFindLibappBatch(rest)
	case "dart2-buckets":
		deprecationWarning("dart2-buckets", "unflutter _debug dart2-buckets")
		err = cmdDart2Buckets(rest)

	case "help", "-h", "--help":
		usage()
		return 0, nil

	default:
		// If the first arg is a file on disk, treat as "unflutter <libapp.so>".
		if resolvePositionalLib(cmd) != "" {
			err = cmdRun(args)
		} else if strings.HasPrefix(cmd, "-") {
			// Flags before file path: pass all args to cmdRun which will reorder.
			err = cmdRun(args)
		} else {
			fmt.Fprintf(os.Stderr, "unknown command, or file not found on disk: %s\n", cmd)
			usage()
			return 1, fmt.Errorf("unknown command or file not found: %s", cmd)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1, err
	}
	return 0, nil
}

func deprecationWarning(old, new string) {
	fmt.Fprintf(os.Stderr, "warning: '%s' is deprecated, use '%s' instead\n\n", old, new)
}

// hasFlag checks if any arg matches one of the given flag names.
func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n {
				return true
			}
		}
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, `unflutter — Dart AOT snapshot analyzer

Usage:
  unflutter <libapp.so>                         Full analysis pipeline
  unflutter meta <libapp.so>                    Generate flutter_meta.json
  unflutter ghidra <libapp.so>                   Ghidra headless decompilation
  unflutter ida <libapp.so>                     IDA headless decompilation
  unflutter signal <libapp.so>                  Signal analysis
  unflutter doctor <libapp.so>                  Diagnostic scan
  unflutter find-libapp <apk>                   Find Dart library in APK
  unflutter parity <dir>                        Corpus parity report
  unflutter inventory <dir>                     Sample inventory
  unflutter _debug <cmd>                        Internal commands

Flags:
  --out <dir>         Output directory (default: <basename>.unflutter/)
  --quiet, -q         Suppress verbose output (verbose is default)
  --strict            Fail on structural errors
  --all               Include all functions (not just signal)
  --from <dir>        Reuse existing disasm output
  --k <n>             Signal context hops (default: 2)
  --graph             Build call graph and per-function CFGs
  --max-steps <n>     Global loop cap
`)
}
