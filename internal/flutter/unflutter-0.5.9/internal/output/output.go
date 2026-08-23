// Package output serializes disassembly and snapshot-metadata artifacts
// (per-function asm/bin files, snapshot.json, symbols.json) to disk for the
// unflutter pipeline and its debug subcommands.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/disasm"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/snapshot"
)

// SymbolEntry is one entry written by WriteSymbolsJSON: an address, its
// assigned name, and the size of the region or function it names.
type SymbolEntry struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
}

// WriteASM formats insts as annotated ARM64 disassembly and writes it to
// <outDir>/asm/<filename>.txt, creating any parent directories filename's
// own path components require (filenames may be "Owner/funcName_pcoff").
func WriteASM(outDir, filename string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	path := filepath.Join(outDir, "asm", filename+".txt")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	text := disasm.Format(insts, lookup, annotators...)
	return os.WriteFile(path, []byte(text), 0644)
}

// WriteBin writes a function's raw code bytes to <outDir>/asm/<filename>.bin,
// alongside the .txt file WriteASM produces for the same filename.
func WriteBin(outDir, filename string, data []byte) error {
	path := filepath.Join(outDir, "asm", filename+".bin")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// WriteASMSingle writes one combined disassembly listing to <outDir>/asm.txt,
// with no per-function splitting - used for single-region dumps.
func WriteASMSingle(outDir string, insts []disasm.Inst, lookup disasm.SymbolLookup) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	text := disasm.Format(insts, lookup)
	return os.WriteFile(filepath.Join(outDir, "asm.txt"), []byte(text), 0644)
}

// WriteSnapshotJSON writes the extracted snapshot metadata to
// <outDir>/snapshot.json.
func WriteSnapshotJSON(outDir string, info *snapshot.Info) error {
	return writeJSON(outDir, "snapshot.json", info)
}

// WriteSymbolsJSON writes symList to <outDir>/symbols.json.
func WriteSymbolsJSON(outDir string, symList []SymbolEntry) error {
	return writeJSON(outDir, "symbols.json", symList)
}

func writeJSON(outDir, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return os.WriteFile(filepath.Join(outDir, name), data, 0644)
}
