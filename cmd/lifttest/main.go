package main

import (
	"fmt"
	"os"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/native"
)

func main() {
	elfPath := os.Args[1]
	symName := os.Args[2]
	params := os.Args[3:]

	p, err := native.NewELFParser(elfPath)
	if err != nil {
		panic(err)
	}

	var target *native.SymbolEntry
	for i := range p.Symbols {
		if p.GetSymbolName(p.Symbols[i]) == symName {
			target = &p.Symbols[i]
			break
		}
	}
	if target == nil {
		fmt.Fprintf(os.Stderr, "symbol not found: %s\n", symName)
		os.Exit(1)
	}

	var sec *native.SectionHeader
	for i := range p.Sections {
		s := &p.Sections[i]
		if target.Value >= s.Addr && target.Value < s.Addr+s.Size {
			sec = s
			break
		}
	}
	if sec == nil {
		fmt.Fprintf(os.Stderr, "no section contains address 0x%x\n", target.Value)
		os.Exit(1)
	}
	fileOff := sec.Offset + (target.Value - sec.Addr)
	code := p.Data[fileOff : fileOff+target.Size]

	d, err := native.NewARM64Disassembler()
	if err != nil {
		panic(err)
	}
	defer d.Close()

	insns, err := d.DisassembleDetailed(code, target.Value)
	if err != nil {
		panic(err)
	}

	resolver := p.SymbolResolver()
	strResolver := func(addr uint64) (string, bool) {
		return p.ReadCString(addr)
	}

	stmts := arm64lift.LiftFunction(insns, params, resolver, strResolver)
	fmt.Printf("// %s\n", symName)
	arm64lift.RenderStmts(os.Stdout, stmts, 1)
}
