package native

import (
	"testing"
)

func TestELFParse(t *testing.T) {
	parser, err := NewELFParser("../../test/liblun.so")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if parser.Header.Class != ELFCLASS64 {
		t.Errorf("expected 64-bit ELF, got class %d", parser.Header.Class)
	}
	if parser.Header.Machine != EM_AARCH64 {
		t.Errorf("expected EM_AARCH64 (%d), got %d", EM_AARCH64, parser.Header.Machine)
	}
	if len(parser.Sections) == 0 {
		t.Fatalf("expected at least one section")
	}

	sections := parser.GetCodeSections()
	if len(sections) == 0 {
		t.Errorf("expected at least one code section")
	}
	for _, sec := range sections {
		if sec.Size == 0 {
			t.Errorf("code section %s has zero size", sec.Name)
		}
	}
}

func TestResolveGOT(t *testing.T) {
	parser, err := NewELFParser("../../test/il2cpp_memory_dumper_main/build/il2cpp_memory_dumper")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	got, err := parser.ResolveGOT()
	if err != nil {
		t.Fatalf("ResolveGOT: %v", err)
	}

	// print_usage's "std::cerr << ..." computes this exact GOT slot
	// address via "adrp x0, #0x1d000; ldr x0, [x0, #0x168]" - verified
	// directly against the real disassembly.
	name, ok := got[0x1d168]
	if !ok {
		t.Fatalf("expected a resolved name at 0x1d168 (std::cerr's GOT slot), got none")
	}
	if name != "_ZNSt6__ndk14cerrE" {
		t.Errorf("expected std::cerr's mangled name, got %q", name)
	}
}

// TestParseSymbols_FallsBackToDynsym covers a real bug: a stripped
// shared library has no .symtab at all, but a linker can never fully
// strip .dynsym from a DYNAMICALLY LINKED binary - the dynamic linker
// needs it at load time to resolve the library's own exports. Before
// this fix, parseSymbols only ever looked at .symtab, so p.Symbols
// stayed completely empty for a binary shaped exactly like this one -
// silently hiding every one of its real, named, decompilable functions.
// test/liblun.so is a real, NDK-built, stripped Android .so (no
// .symtab, confirmed via readelf) that still exports hundreds of real
// functions through .dynsym alone.
func TestParseSymbols_FallsBackToDynsym(t *testing.T) {
	parser, err := NewELFParser("../../test/liblun.so")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	hasSymtab := false
	for _, s := range parser.Sections {
		if s.Type == SHT_SYMTAB {
			hasSymtab = true
		}
	}
	if hasSymtab {
		t.Fatalf("test fixture assumption broken: test/liblun.so now has a .symtab, so this test no longer exercises the .dynsym fallback path at all")
	}

	const sttFunc = 2
	defined := 0
	for _, sym := range parser.Symbols {
		if sym.Info&0xf == sttFunc && sym.Size != 0 {
			defined++
		}
	}
	if defined == 0 {
		t.Fatalf("expected parser.Symbols (populated from .dynsym, since there's no .symtab) to contain real, defined FUNC entries with non-zero size, got 0 among %d total symbols", len(parser.Symbols))
	}
}
