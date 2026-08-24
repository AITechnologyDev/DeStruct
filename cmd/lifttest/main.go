package main

import (
	"fmt"
	"os"

	"github.com/destruct/destruct/internal/arm64lift"
	"github.com/destruct/destruct/internal/ir"
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

	plt, err := p.ResolvePLT()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: PLT resolution failed: %v\n", err)
		plt = nil
	}

	got, err := p.ResolveGOT()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: GOT resolution failed: %v\n", err)
		got = nil
	}

	symByAddr := make(map[uint64]string)
	for _, sym := range p.Symbols {
		if name := p.GetSymbolName(sym); name != "" {
			symByAddr[sym.Value] = name
		}
	}

	// One shared address->name oracle for both call targets (bl/tail
	// call "b") and GOT/data-slot addresses an "ldr" dereferences (see
	// liftLdr's own doc comment) - the same lookup, just fed a
	// different kind of address depending on the caller.
	resolver := func(addr uint64) (string, bool) {
		if name, ok := symByAddr[addr]; ok {
			return name, true
		}
		if name, ok := plt[addr]; ok {
			return name, true
		}
		if name, ok := got[addr]; ok {
			return name, true
		}
		return "", false
	}

	strResolver := func(addr uint64) (string, bool) {
		return p.ReadCString(addr)
	}

	stmts := arm64lift.LiftFunction(insns, params, resolver, strResolver)
	fmt.Printf("// %s\n", symName)
	printStmts(stmts, 1)
}

func printStmts(stmts []ir.Stmt, depth int) {
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "    "
	}
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.IfStmt:
			fmt.Printf("%sif (%s) {\n", indent, v.Cond)
			if v.Then != nil {
				printStmts(v.Then.Statements, depth+1)
			}
			fmt.Printf("%s}", indent)
			if v.Else != nil && len(v.Else.Statements) > 0 {
				fmt.Printf(" else {\n")
				printStmts(v.Else.Statements, depth+1)
				fmt.Printf("%s}", indent)
			}
			fmt.Println()
		case *ir.WhileStmt:
			fmt.Printf("%swhile (%s) {\n", indent, v.Cond)
			if v.Body != nil {
				printStmts(v.Body.Statements, depth+1)
			}
			fmt.Printf("%s}\n", indent)
		default:
			fmt.Printf("%s%s\n", indent, s)
		}
	}
}
