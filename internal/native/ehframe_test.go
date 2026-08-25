package native

import "testing"

// TestDiscoverFunctions_FullyStrippedExecutable covers the case
// SymbolResolver's own .dynsym fallback can't help with at all: a
// stripped EXECUTABLE (as opposed to a stripped shared library, which
// keeps its exports in .dynsym regardless - see TestParseSymbols_
// FallsBackToDynsym in elf_test.go) has zero defined function symbols
// in EITHER .symtab or .dynsym. test/arm64.sh is a real, NDK-built,
// fully stripped Android executable confirmed (via readelf) to have
// exactly this shape - DiscoverFunctions is the only way anything in
// it is decompilable at all.
func TestDiscoverFunctions_FullyStrippedExecutable(t *testing.T) {
	parser, err := NewELFParser("../../test/arm64.sh")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	const sttFunc = 2
	for _, sym := range parser.Symbols {
		if sym.Info&0xf == sttFunc && sym.Size != 0 {
			t.Fatalf("test fixture assumption broken: test/arm64.sh now has a defined function symbol (%s), so this test no longer exercises the DiscoverFunctions fallback path at all", parser.GetSymbolName(sym))
		}
	}

	funcs, err := parser.DiscoverFunctions()
	if err != nil {
		t.Fatalf("DiscoverFunctions: %v", err)
	}
	if len(funcs) == 0 {
		t.Fatalf("expected at least one discovered function")
	}

	var textSec *SectionHeader
	for i := range parser.Sections {
		if parser.getSectionName(parser.Sections[i]) == ".text" {
			textSec = &parser.Sections[i]
		}
	}
	if textSec == nil {
		t.Fatalf("expected a .text section")
	}

	prevAddr := uint64(0)
	for i, f := range funcs {
		if f.Addr < textSec.Addr || f.Addr >= textSec.Addr+textSec.Size {
			t.Errorf("function %d at 0x%x falls outside .text ([0x%x, 0x%x))", i, f.Addr, textSec.Addr, textSec.Addr+textSec.Size)
		}
		if f.Size == 0 {
			t.Errorf("function %d at 0x%x has zero size", i, f.Addr)
		}
		if f.Addr+f.Size > textSec.Addr+textSec.Size+4096 {
			// Generous slack (one page) for the very last entry's own
			// size heuristic - see DiscoverFunctions' own doc comment -
			// but no entry should extend wildly past .text's own end.
			t.Errorf("function %d at 0x%x (size %d) extends implausibly far past .text's own end", i, f.Addr, f.Size)
		}
		if f.Addr < prevAddr {
			t.Errorf("function %d at 0x%x is out of order (previous was 0x%x) - DiscoverFunctions must return them sorted", i, f.Addr, prevAddr)
		}
		prevAddr = f.Addr
	}
}
