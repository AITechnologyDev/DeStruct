package native

import (
	"testing"
)

func TestELFParse(t *testing.T) {
	parser, err := NewELFParser("../../test/lunacy/liblun.so")
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
	parser, err := NewELFParser("../../test/il2cpp_memory_dumper")
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
