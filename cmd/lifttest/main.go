// Command lifttest is a small test driver for the experimental ARM64->C
// lifter (internal/arm64lift): given an ELF file and a function symbol,
// it disassembles just that function and prints what the lifter makes of
// it. Not part of the main destruct CLI - see COMMANDS.md's lifttest
// section for usage.
package main

import (
	"fmt"
	"os"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/native"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: lifttest <elf-path> <mangled-symbol-name> [param-names...]")
		os.Exit(1)
	}
	elfPath := os.Args[1]
	symName := os.Args[2]
	paramNames := os.Args[3:]

	parser, err := native.NewELFParser(elfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing ELF: %v\n", err)
		os.Exit(1)
	}

	sym, ok := findFunctionSymbol(parser, symName)
	if !ok {
		fmt.Fprintf(os.Stderr, "symbol %q not found (or has no size)\n", symName)
		os.Exit(1)
	}

	code, err := bytesForVA(parser, sym.Value, sym.Size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "locating %q's bytes: %v\n", symName, err)
		os.Exit(1)
	}

	dis, err := native.NewARM64Disassembler()
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating disassembler: %v\n", err)
		os.Exit(1)
	}
	defer dis.Close()

	insns, err := dis.DisassembleDetailed(code, sym.Value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "disassembling %q: %v\n", symName, err)
		os.Exit(1)
	}

	resolver, err := buildResolver(parser)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: PLT resolution unavailable: %v\n", err)
	}

	stmts := arm64lift.LiftFunction(insns, paramNames, resolver)
	fmt.Print(arm64lift.FormatFunction(symName, paramNames, stmts))
}

// findFunctionSymbol looks up a FUNC symbol by its exact (still-mangled)
// name, preferring one with a non-zero size (some binaries carry more
// than one symbol table entry at the same address - a local alias with
// Size == 0 alongside the real, sized definition).
func findFunctionSymbol(p *native.ELFParser, name string) (native.SymbolEntry, bool) {
	var best native.SymbolEntry
	found := false
	for _, sym := range p.Symbols {
		if p.GetSymbolName(sym) != name {
			continue
		}
		if !found || sym.Size > best.Size {
			best = sym
			found = true
		}
	}
	return best, found
}

// bytesForVA slices out size bytes starting at virtual address va, by
// finding the section whose [Addr, Addr+Size) range contains it and
// translating to that section's file offset - ELF sections aren't
// necessarily mapped 1:1 with file offset == VA (this binary, like most
// PIE executables, isn't), so the translation has to go through whichever
// section actually covers the address.
func bytesForVA(p *native.ELFParser, va, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("symbol has zero size")
	}
	for _, sec := range p.Sections {
		if sec.Addr == 0 || va < sec.Addr || va+size > sec.Addr+sec.Size {
			continue
		}
		start := sec.Offset + (va - sec.Addr)
		end := start + size
		if end > uint64(len(p.Data)) {
			return nil, fmt.Errorf("section containing 0x%x is truncated in file", va)
		}
		return p.Data[start:end], nil
	}
	return nil, fmt.Errorf("no section covers address 0x%x (+%d bytes)", va, size)
}

// buildResolver combines locally-defined FUNC symbols (address -> mangled
// name, straight from .symtab) with PLT stub resolution (address -> the
// dynamic symbol that stub jumps to) into the single SymbolResolver
// arm64lift.LiftFunction wants for naming call targets.
func buildResolver(p *native.ELFParser) (arm64lift.SymbolResolver, error) {
	byAddr := make(map[uint64]string)
	for _, sym := range p.Symbols {
		if sym.Value == 0 {
			continue
		}
		if name := p.GetSymbolName(sym); name != "" {
			byAddr[sym.Value] = name
		}
	}

	plt, err := p.ResolvePLT()
	for addr, name := range plt {
		byAddr[addr] = name
	}

	return func(addr uint64) (string, bool) {
		name, ok := byAddr[addr]
		return name, ok
	}, err
}
