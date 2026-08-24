package destruct

import (
	"fmt"
	"path/filepath"

	"github.com/destruct/destruct/internal/csharp"
	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/jvm"
	"github.com/destruct/destruct/internal/pipeline"
)

type Options struct {
	Input    string
	Output   string
	Verbose  bool
	Deobf    bool
	Project  bool
}

func Decompile(opts Options) error {
	ext := filepath.Ext(opts.Input)

	var format pipeline.Format
	switch ext {
	case ".class", ".jar":
		format = pipeline.FormatJVM
	case ".so":
		format = pipeline.FormatFlutter
	case ".dll", ".exe":
		format = pipeline.FormatPE
	default:
		return fmt.Errorf("unsupported file format: %s", ext)
	}

	p := pipeline.New(pipeline.Options{
		Input:   opts.Input,
		Output:  opts.Output,
		Format:  format,
		Verbose: opts.Verbose,
		Deobf:   opts.Deobf,
		Project: opts.Project,
	})

	return p.Run()
}

func DecompileJVM(filename string, outputDir string) (*ir.Program, error) {
	ext := filepath.Ext(filename)

	if ext == ".jar" {
		return jvm.DecompileJAR(filename)
	}

	return jvm.DecompileClassFile(filename)
}

func GenerateCSharp(prog *ir.Program, outputDir string, project bool) error {
	gen := csharp.NewGenerator(csharp.Options{
		OutputDir: outputDir,
		Project:   project,
	})

	return gen.Generate(prog)
}
