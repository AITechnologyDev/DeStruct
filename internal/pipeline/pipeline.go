package pipeline

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/destruct/destruct/internal/csharp"
	unflutter "github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/cmd/unflutter"
	"github.com/destruct/destruct/internal/ir"
	javagen "github.com/destruct/destruct/internal/java"
	"github.com/destruct/destruct/internal/jvm"
	"github.com/destruct/destruct/internal/native"
)

type Format int

const (
	FormatJVM Format = iota
	FormatFlutter
	FormatELF
	FormatPE
)

type Options struct {
	Input   string
	Output  string
	Format  Format
	Verbose bool
	Deobf   bool
	Project bool
}

type Pipeline struct {
	opts Options
}

func New(opts Options) *Pipeline {
	if opts.Output == "" {
		opts.Output = "output"
	}
	return &Pipeline{opts: opts}
}

func (p *Pipeline) Run() error {
	if err := os.MkdirAll(p.opts.Output, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	switch p.opts.Format {
	case FormatFlutter:
		return p.decompileFlutter()

	case FormatJVM:
		return p.decompileAndGenerateJVM()

	case FormatELF:
		return p.disassembleELF()

	default:
		prog, err := p.decompileELFOrPE()
		if err != nil {
			return fmt.Errorf("decompilation: %w", err)
		}
		gen := csharp.NewGenerator(csharp.Options{
			OutputDir: p.opts.Output,
			Project:   p.opts.Project,
			Deobf:     p.opts.Deobf,
			Verbose:   p.opts.Verbose,
		})
		return gen.Generate(prog)
	}
}

func (p *Pipeline) decompileAndGenerateJVM() error {
	ext := filepath.Ext(p.opts.Input)

	gen := javagen.NewGenerator(javagen.Options{
		OutputDir: p.opts.Output,
		Deobf:     p.opts.Deobf,
		Verbose:   p.opts.Verbose,
	})

	if ext != ".jar" {
		prog, err := jvm.DecompileClassFile(p.opts.Input)
		if err != nil {
			return fmt.Errorf("decompilation: %w", err)
		}
		return gen.Generate(prog)
	}

	total, err := jvm.CountClassEntries(p.opts.Input)
	if err != nil {
		return fmt.Errorf("reading jar: %w", err)
	}
	fmt.Printf("Found %d classes in %s\n", total, filepath.Base(p.opts.Input))

	// Stream the .jar one class at a time: read -> parse -> decompile ->
	// write .java -> discard, before moving to the next entry. This is
	// what keeps memory use flat regardless of how many classes the .jar
	// contains, instead of holding every class's parsed bytecode and
	// decompiled AST in memory simultaneously.
	//
	// current* below is watched by a background goroutine so that if any
	// single class's parse/decompile/generate ever takes an unusually
	// long time (a stall that isn't itself an infinite loop bug, or a
	// bug not yet found), the person sees which class it's stuck on
	// instead of the process silently going quiet.
	var currentMu sync.Mutex
	currentName := ""
	currentStart := time.Now()

	watchdogStop := make(chan struct{})
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastWarned := ""
		for {
			select {
			case <-watchdogStop:
				return
			case <-ticker.C:
				currentMu.Lock()
				name, since := currentName, time.Since(currentStart)
				currentMu.Unlock()
				if name == "" || name == lastWarned {
					continue
				}
				if since > 8*time.Second {
					fmt.Printf("  ... still on %s (%.0fs) - this class may be unusually large or complex\n", name, since.Seconds())
					lastWarned = name
				}
			}
		}
	}()

	count := 0
	skipped := 0
	lastReport := time.Now()
	err = jvm.DecompileJARStreaming(p.opts.Input,
		func(cf *jvm.ClassFile, prog *ir.Program) error {
			for _, class := range prog.Classes {
				currentMu.Lock()
				currentName = class.Name
				currentStart = time.Now()
				currentMu.Unlock()

				if err := gen.GenerateClass(class); err != nil {
					return err
				}
				count++

				if p.opts.Verbose {
					fmt.Printf("  [%d/%d] %s\n", count, total, class.Name)
				} else if time.Since(lastReport) > time.Second {
					fmt.Printf("  ... %d/%d classes\n", count, total)
					lastReport = time.Now()
				}
			}
			return nil
		},
		func(entryName string, reason jvm.SkipReason, entryErr error) {
			skipped++
			if p.opts.Verbose {
				if entryErr != nil {
					fmt.Printf("  [skip] %s: %s (%v)\n", entryName, reason, entryErr)
				} else {
					fmt.Printf("  [skip] %s: %s\n", entryName, reason)
				}
			}
		},
	)

	close(watchdogStop)
	<-watchdogDone

	if err != nil {
		return fmt.Errorf("decompilation: %w", err)
	}

	fmt.Printf("Decompiled %d classes\n", count)
	if skipped > 0 {
		fmt.Printf("Skipped %d classes (malformed, oversized, or failed to decompile; rerun with -v to see which)\n", skipped)
	}
	return nil
}

func (p *Pipeline) decompileFlutter() error {
	input := p.opts.Input
	ext := strings.ToLower(filepath.Ext(input))

	// If input is APK, extract libapp.so first.
	if ext == ".apk" {
		soPath, err := p.extractLibapp(input)
		if err != nil {
			return fmt.Errorf("extract libapp.so from APK: %w", err)
		}
		input = soPath
		defer os.Remove(input)
	}

	args := []string{input, "--out", p.opts.Output}
	if p.opts.Verbose {
		args = append(args, "--verbose")
	}

	if exitCode, err := unflutter.Run(args); err != nil {
		return fmt.Errorf("unflutter (exit %d): %w", exitCode, err)
	}

	// Combine per-function .txt and .bin files into output root.
	asmDir := filepath.Join(p.opts.Output, "asm")
	if err := combineAsmFiles(asmDir, p.opts.Output); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not combine asm files: %v\n", err)
	} else {
		fmt.Printf("Combined: %s/asm.txt + asm.bin\n", p.opts.Output)
	}

	fmt.Printf("Flutter disassembly complete. Output: %s/\n", p.opts.Output)
	fmt.Println("Edit asm.txt (ARM64 assembly) and use asm.bin for binary patching.")
	return nil
}

func combineAsmFiles(asmDir, outDir string) error {
	entries, err := os.ReadDir(asmDir)
	if err != nil {
		return err
	}

	type funcEntry struct {
		name string
		txt  string
		bin  []byte
	}
	var funcs []funcEntry

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") || e.Name() == "asm.txt" {
			continue
		}
		funcName := strings.TrimSuffix(e.Name(), ".txt")
		txtData, err := os.ReadFile(filepath.Join(asmDir, e.Name()))
		if err != nil {
			continue
		}
		binData, _ := os.ReadFile(filepath.Join(asmDir, funcName+".bin"))
		funcs = append(funcs, funcEntry{name: funcName, txt: string(txtData), bin: binData})
	}
	if len(funcs) == 0 {
		return fmt.Errorf("no .txt files in %s", asmDir)
	}

	txtOut, err := os.Create(filepath.Join(outDir, "asm.txt"))
	if err != nil {
		return err
	}
	defer txtOut.Close()

	binOut, err := os.Create(filepath.Join(outDir, "asm.bin"))
	if err != nil {
		return err
	}
	defer binOut.Close()

	for _, f := range funcs {
		fmt.Fprintf(txtOut, "\n; ===== %s =====\n", f.name)
		txtOut.WriteString(f.txt)
		binOut.Write(f.bin)
	}
	return nil
}

func (p *Pipeline) extractLibapp(apkPath string) (string, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "lib/arm64-v8a/") && strings.HasSuffix(f.Name, "libapp.so") {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			defer rc.Close()

			tmp, err := os.CreateTemp("", "libapp-*.so")
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(tmp, rc); err != nil {
				tmp.Close()
				return "", err
			}
			tmp.Close()
			return tmp.Name(), nil
		}
	}

	return "", fmt.Errorf("libapp.so not found in lib/arm64-v8a/")
}

func (p *Pipeline) decompileELFOrPE() (*ir.Program, error) {
	// For now, use native disassembler for ELF files
	ext := strings.ToLower(filepath.Ext(p.opts.Input))

	if ext == ".so" || ext == ".elf" || ext == "" {
		return nil, p.disassembleELF()
	}

	return nil, fmt.Errorf("PE decompilation not yet implemented")
}

func (p *Pipeline) disassembleELF() error {
	fmt.Printf("Parsing ELF file: %s\n", p.opts.Input)

	// Create output file
	outPath := filepath.Join(p.opts.Output, filepath.Base(p.opts.Input)+".asm")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	if err := native.DisassembleELFFile(p.opts.Input, f); err != nil {
		return fmt.Errorf("disassemble ELF: %w", err)
	}

	fmt.Printf("Disassembly: %s\n", outPath)
	return nil
}
