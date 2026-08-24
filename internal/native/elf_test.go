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
