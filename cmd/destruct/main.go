package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/destruct/destruct/internal/hermes"
	"github.com/destruct/destruct/internal/pipeline"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "jvm":
		handleJVM(os.Args[2:])
	case "hermes":
		handleHermes(os.Args[2:])
	case "assemble":
		handleAssemble(os.Args[2:])
	case "patch":
		handlePatch(os.Args[2:])
	case "interactive", "repl":
		handleInteractive(os.Args[2:])
	case "flutter":
		handleFlutter(os.Args[2:])
	case "elf":
		handleELF(os.Args[2:])
	case "pe":
		handlePE(os.Args[2:])
	case "version":
		fmt.Printf("DeStruct v%s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`DeStruct - Multi-format Decompiler
Usage: destruct <command> [options]

Commands:
  jvm       Decompile JVM .class/.jar files to Java source code
  hermes    Disassemble/decompile Hermes .hbc bytecode to JS
  assemble  Assemble .hasm back to .hbc bytecode (with address recalculation)
  patch     Search/patch Hermes .hbc bytecode
  flutter   Disassemble Flutter libapp.so to readable Dart bytecode
  elf       Disassemble ELF binaries to readable assembly (--decompile: AArch64-only pseudocode)
  pe        Disassemble PE binaries to readable assembly
  version   Show version
  help      Show this help

Options:
  -o, --output        Output file/directory
  -i, --input         Input HBC file (for assemble/patch)
  -v, --verbose       Verbose output
  --deobfuscate       Enable deobfuscation
  --decompile         Use decompiler (hermes: output .js, flutter: output .dart,
                       elf: output C-like pseudocode for every function in one
                       file - AArch64 binaries only)
  -s, --search        Search for string in bytecode
  -t, --patch-string  Quick patch: replace instruction with string operand (true/false/nop)
  -p, --patch         Generate simplified format for manual patching
  --hex               Hex-editor-friendly disassembly (absolute file offsets)
  --patch-map         Hermes-dec format plus per-operand file offset/byte map,
                       for patching in a hex editor without reassembling
  --hermes-dec        (default on "hermes") hermes-dec-exact disassembly format;
                       on "assemble", assemble THAT format instead of the
                       older simplified one (requires -i with the original
                       .hbc/.bundle - the text references its string/
                       function tables and isn't self-contained)

Workflow for manual patching (small, same-size edits):
  1. destruct hermes file.hbc -o output/ --patch-map  # Exact per-byte offsets
  2. Locate the bytes to change with a hex editor       Edit them in place
  3. No reassembly needed - the .hbc file offsets are absolute

Workflow for structural edits (add/remove/reorder instructions):
  1. destruct hermes file.hbc -o output/          # Exact hermes-dec format
  2. Edit output/file.hbc.hasm in a text editor
  3. destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc --hermes-dec
     (only functions whose text actually changed are reassembled; addresses
     are recalculated automatically, promoting Addr8 branches to their
     *Long form if an edit pushes a jump target out of byte range)

Quick patch workflow:
  destruct patch file.hbc -t "isPro" --check-only  # Only patch CHECK instructions (safe)
  destruct patch file.hbc -t "isPro"                # Patch ALL instructions (may break things)

Examples:
  destruct jvm input.jar -o output/
  destruct elf libnative.so -o output/ --decompile  # AArch64 pseudocode, one file
  destruct hermes index.android.bundle -o output/ --decompile
  destruct hermes index.android.bundle -o output/ -p  # Simplified format
  destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc --hermes-dec
  destruct assemble output/file.hbc.hasm -i file.hbc -o patched.hbc  # Simplified format
  destruct patch file.hbc -t "isPro"
  destruct flutter libapp.so -o output/ --decompile
  destruct elf libnative.so -o output/`)
}

func handleJVM(args []string) {
	opts, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input file required")
		os.Exit(1)
	}

	ext := strings.ToLower(filepath.Ext(input))
	if ext != ".class" && ext != ".jar" {
		fmt.Fprintf(os.Stderr, "Error: unsupported JVM file format: %s (expected .class or .jar)\n", ext)
		os.Exit(1)
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  opts.output,
		Format:  pipeline.FormatJVM,
		Verbose: opts.verbose,
		Deobf:   opts.deobfuscate,
		Project: opts.project,
	})

	if err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
}

func handleHermes(args []string) {
	opts, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input .hbc file required")
		os.Exit(1)
	}

	if err := os.MkdirAll(opts.output, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	file, err := hermes.ParseFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing HBC: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed Hermes bytecode v%d (%d functions, %d strings)\n",
		file.Header.Version, file.Header.FunctionCount, file.Header.StringCount)

	if opts.decompile {
		// Use decompiler
		d := hermes.NewDecompiler(file)
		dasmPath := filepath.Join(opts.output, filepath.Base(input)+".js")
		f, err := os.Create(dasmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		d.DecompileAll(f)
		fmt.Printf("Decompiled: %s\n", dasmPath)
	} else {
		// Use disassembler
		d := hermes.NewDisassembler(file)
		hasmPath := filepath.Join(opts.output, filepath.Base(input)+".hasm")
		f, err := os.Create(hasmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		// Use simplified format for patching
		if opts.patch {
			d.DisassembleAllPatch(f)
			fmt.Printf("Simplified disassembly (for patching): %s\n", hasmPath)
		} else if opts.hex {
			d.DisassembleAllHex(f)
			fmt.Printf("Hex-editor disassembly: %s\n", hasmPath)
		} else if opts.patchMap {
			d.DisassembleAllPatchMap(f)
			fmt.Printf("Hex-editor patch map (absolute file offsets per operand): %s\n", hasmPath)
		} else {
			// hermes-dec-exact format: matches the reference Python
			// hermes-dec disassembler's text output byte for byte on
			// bytecode versions 97-99 (the opcode table DeStruct ships
			// targets that range; older versions will decode structurally
			// but instruction mnemonics may not match).
			d.DisassembleAllExact(f)
			fmt.Printf("Disassembly (hermes-dec exact format): %s\n", hasmPath)
		}
	}

	// Print summary
	for i, hdr := range file.FunctionHeaders {
		name := "<unknown>"
		if int(hdr.FunctionName) < len(file.Strings) {
			name = file.Strings[hdr.FunctionName]
		}
		if opts.verbose || i < 10 {
			fmt.Printf("  Function #%d: %s (%d bytes, %d params)\n",
				i, name, hdr.BytecodeSizeInBytes, hdr.ParamCount)
		}
	}
	if len(file.FunctionHeaders) > 10 && !opts.verbose {
		fmt.Printf("  ... and %d more functions (use -v for all)\n",
			len(file.FunctionHeaders)-10)
	}
}

func handleAssemble(args []string) {
	opts, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input .hasm file required")
		os.Exit(1)
	}

	if opts.output == "output" {
		opts.output = strings.TrimSuffix(input, filepath.Ext(input)) + ".hbc"
	}

	if opts.hermesDec {
		// Exact hermes-dec-format assembly: always patches an existing
		// .hbc/.bundle (the text format references string_id/
		// function_id/bigint_id indices into that file's own tables, so
		// it's never self-contained), diffing against the file's
		// current disassembly to find and reassemble only the functions
		// that actually changed.
		if opts.inputFile == "" {
			fmt.Fprintln(os.Stderr, "Error: --hermes-dec assembly requires the original .hbc/.bundle via -i/--input (the .hasm text references that file's string/function tables and cannot be assembled standalone)")
			os.Exit(1)
		}
		f, err := hermes.ParseFile(opts.inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", opts.inputFile, err)
			os.Exit(1)
		}
		asm := hermes.NewHermesDecAssembler(f)
		result, err := asm.AssembleAndPatch(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error assembling: %v\n", err)
			os.Exit(1)
		}
		if len(result.ChangedFunctions) == 0 {
			fmt.Println("No changes detected; output is identical to the input .hbc")
		} else {
			fmt.Printf("Patched %d function(s): %v (bytecode size change: %+d bytes)\n",
				len(result.ChangedFunctions), result.ChangedFunctions, result.SizeDelta)
		}
		if err := f.Write(opts.output); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %s\n", opts.output)
		return
	}

	// Use smart assembler with address recalculation
	sa := hermes.NewSmartAssembler()
	instrs, err := sa.ParseSimple(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing HASM: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed %d instructions from %s\n", len(instrs), input)

	// Check if we have an input HBC file for full patching
	if opts.inputFile != "" {
		// Full patching mode
		if err := sa.PatchFile(opts.inputFile, input, opts.output); err != nil {
			fmt.Fprintf(os.Stderr, "Error patching: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Patched %s -> %s\n", opts.inputFile, opts.output)
	} else {
		// Standalone assembly mode
		bytecode, err := sa.AssembleWithRecalc(instrs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error assembling: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(opts.output, bytecode, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Assembled %d bytes -> %s\n", len(bytecode), opts.output)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleInteractive opens a .hbc/.bundle file and starts a radare2-style
// interactive patching session (see internal/hermes/repl.go): seek,
// hexdump, disassemble, and write commands operating on an in-memory
// buffer with explicit save via 'w'/'wq'.
func handleInteractive(args []string) {
	_, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input .hbc/.bundle file required")
		os.Exit(1)
	}

	file, err := hermes.ParseFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", input, err)
		os.Exit(1)
	}

	r := hermes.NewRepl(file, input, os.Stdout)
	if err := r.Run(os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func handlePatch(args []string) {
	opts, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input .hbc file required")
		os.Exit(1)
	}

	if opts.output == "output" {
		opts.output = strings.TrimSuffix(input, filepath.Ext(input)) + ".patched.hbc"
	}

	// Parse the HBC file
	file, err := hermes.ParseFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing HBC: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed Hermes bytecode v%d (%d functions, %d strings)\n",
		file.Header.Version, file.Header.FunctionCount, file.Header.StringCount)

	// Create patcher
	ps := hermes.NewPatcher(file)

	// Search mode
	if opts.search != "" {
		fmt.Printf("Searching for: %s\n", opts.search)
		results := ps.SearchString(opts.search, true) // exact match
		if len(results) == 0 {
			fmt.Println("No matches found")
		} else {
			fmt.Printf("Found %d matches:\n", len(results))
			for _, r := range results {
				fmt.Printf("  Function #%d (%s) @ 0x%x\n", r.FuncIdx, r.FuncName, r.Offset)
			}
		}
		return
	}

	// Quick patch mode: patch string to true/false/nop
	if opts.patchString != "" {
		patchType := "true"
		fmt.Printf("Quick patching %q to %s (checkOnly=%v)\n", opts.patchString, patchType, opts.checkOnly)
		patched, err := ps.QuickPatchString(opts.patchString, patchType, opts.checkOnly)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Patched %d occurrences\n", patched)

		// Save output
		outPath := opts.output
		if outPath == "output" {
			outPath = strings.TrimSuffix(input, filepath.Ext(input)) + ".patched" + filepath.Ext(input)
		}
		if err := ps.Save(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Saved to: %s\n", outPath)
		return
	}

	// List mode (verbose)
	if opts.verbose {
		for i := range file.FunctionHeaders {
			instrs := ps.ListFunction(i)
			name := "<unknown>"
			if int(file.FunctionHeaders[i].FunctionName) < len(file.Strings) {
				name = file.Strings[file.FunctionHeaders[i].FunctionName]
			}
			fmt.Printf("\nFunction #%d: %s (%d instructions)\n", i, name, len(instrs))
			for _, pi := range instrs {
				fmt.Printf("  %08x  %-28s %s\n", pi.Offset, pi.Inst.Name, pi.Format(file))
			}
		}
		return
	}

	// Patch mode: apply HASM file
	if opts.inputFile != "" {
		fmt.Printf("Applying patches from: %s\n", opts.inputFile)
		a := hermes.NewAssembler()
		instrs, err := a.ParseHASM(opts.inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing HASM: %v\n", err)
			os.Exit(1)
		}

		// Group instructions by function
		// The HASM file has offsets starting from 0 for each function
		// We need to figure out which function each instruction belongs to
		funcOffsets := make([]uint32, len(file.FunctionHeaders))
		for i, hdr := range file.FunctionHeaders {
			funcOffsets[i] = hdr.Offset
		}

		applied := 0
		currentFunc := 0
		for _, instr := range instrs {
			// Track which function we're in based on offsets
			// If offset is small (< first function size), it's function 0
			// Otherwise, find the function
			relOffset := instr.Offset

			// Find which function this belongs to
			// Since offsets reset to 0 for each function in the HASM,
			// we need to track based on function boundaries
			for funcIdx, hdr := range file.FunctionHeaders {
				if relOffset < hdr.BytecodeSizeInBytes {
					currentFunc = funcIdx
					break
				}
			}

			if err := ps.PatchInstruction(currentFunc, relOffset, instr.Name+" "+strings.Join(instr.Operands, ", ")); err != nil {
				fmt.Printf("  Warning: %s @ 0x%x: %v\n", instr.Name, instr.Offset, err)
			} else {
				applied++
			}
		}

		fmt.Printf("Applied %d patches\n", applied)
	}

	// Save patched file
	if err := ps.Save(opts.output); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving patched file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Patched file saved: %s\n", opts.output)
}

func handleFlutter(args []string) {
	opts, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input file required")
		os.Exit(1)
	}

	ext := strings.ToLower(filepath.Ext(input))
	if ext != ".so" && ext != ".apk" {
		fmt.Fprintf(os.Stderr, "Error: unsupported Flutter file format: %s (expected .so or .apk)\n", ext)
		os.Exit(1)
	}

	if _, err := os.Stat(input); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read %s: %v\n", input, err)
		os.Exit(1)
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  opts.output,
		Format:  pipeline.FormatFlutter,
		Verbose: opts.verbose,
		Deobf:   opts.deobfuscate,
		Project: opts.project,
	})

	if err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
}

func handleELF(args []string) {
	opts, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input file required")
		os.Exit(1)
	}

	p := pipeline.New(pipeline.Options{
		Input:     input,
		Output:    opts.output,
		Format:    pipeline.FormatELF,
		Verbose:   opts.verbose,
		Deobf:     opts.deobfuscate,
		Project:   opts.project,
		Decompile: opts.decompile,
	})

	if err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
}

func handlePE(args []string) {
	opts, input := parseFlags(args)
	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input file required")
		os.Exit(1)
	}

	p := pipeline.New(pipeline.Options{
		Input:   input,
		Output:  opts.output,
		Format:  pipeline.FormatPE,
		Verbose: opts.verbose,
		Deobf:   opts.deobfuscate,
		Project: opts.project,
	})

	if err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decompilation complete. Output: %s\n", opts.output)
}

type cliOpts struct {
	output      string
	verbose     bool
	deobfuscate bool
	project     bool
	decompile   bool
	search      string
	patch       bool
	hex         bool
	hermesDec   bool
	patchMap    bool
	inputFile   string
	patchString string
	checkOnly   bool
}

func parseFlags(args []string) (cliOpts, string) {
	opts := cliOpts{
		output:  "output",
		project: true,
	}
	var input string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-o", "--output":
			if i+1 < len(args) {
				i++
				opts.output = args[i]
			}
		case "-i", "--input":
			if i+1 < len(args) {
				i++
				opts.inputFile = args[i]
			}
		case "-v", "--verbose":
			opts.verbose = true
		case "--deobfuscate":
			opts.deobfuscate = true
		case "--decompile":
			opts.decompile = true
		case "-s", "--search":
			if i+1 < len(args) {
				i++
				opts.search = args[i]
			}
		case "-t", "--patch-string":
			if i+1 < len(args) {
				i++
				opts.patchString = args[i]
			}
		case "--check-only":
			opts.checkOnly = true
		case "-p", "--patch":
			opts.patch = true
		case "--hex":
			opts.hex = true
		case "--hermes-dec":
			opts.hermesDec = true
		case "--patch-map":
			opts.patchMap = true
		case "--no-project":
			opts.project = false
		default:
			if !strings.HasPrefix(arg, "-") {
				input = arg
			}
		}
	}

	return opts, input
}
