package unflutter

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/pipeline"
)

func cmdFlutterMeta(args []string) error {
	fs := flag.NewFlagSet("flutter-meta", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	outPath := fs.String("out", "", "output JSON file (default: <in>/flutter_meta.json)")
	decompAll := fs.Bool("decompile-all", false, "decompile ALL functions (default: signal functions only)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}
	if *outPath == "" {
		*outPath = filepath.Join(*inDir, "flutter_meta.json")
	}

	_, err := pipeline.RunMetaStage(*inDir, *outPath, *decompAll, true, os.Stderr)
	return err
}
