package native

import (
	"fmt"
	"testing"
)

func TestELFParse(t *testing.T) {
	parser, err := NewELFParser("/data/data/com.termux/files/home/.cache/opencode/tmp/elf_test/test")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	fmt.Printf("ELF Header:\n")
	fmt.Printf("  Class: %d\n", parser.Header.Class)
	fmt.Printf("  Machine: %d\n", parser.Header.Machine)
	fmt.Printf("  Entry: 0x%x\n", parser.Header.Entry)
	fmt.Printf("  Section Off: 0x%x\n", parser.Header.ShOff)
	fmt.Printf("  Section Num: %d\n", parser.Header.ShNum)
	fmt.Printf("  Bits: %d\n", parser.Bits)
	fmt.Printf("  Arch: %s\n", GetArchName(parser.Arch))

	fmt.Printf("\nAll sections:\n")
	for i, sec := range parser.Sections {
		name := parser.getSectionName(sec)
		fmt.Printf("  [%d] %s type=%d flags=0x%x @ 0x%x (0x%x) %d bytes\n",
			i, name, sec.Type, sec.Flags, sec.Addr, sec.Offset, sec.Size)
	}

	// Debug: check GetCodeSections conditions
	fmt.Printf("\nDebug GetCodeSections:\n")
	for i, sec := range parser.Sections {
		name := parser.getSectionName(sec)
		isProgbits := sec.Type == SHT_PROGBITS
		hasSize := sec.Size > 0
		hasExecFlag := sec.Flags&0x4 != 0
		fmt.Printf("  [%d] %s type==SHT_PROGBITS:%v Size>0:%v ExecFlag:%v\n",
			i, name, isProgbits, hasSize, hasExecFlag)
	}

	sections := parser.GetCodeSections()
	fmt.Printf("\nCode sections: %d\n", len(sections))
	for i, sec := range sections {
		fmt.Printf("  [%d] %s @ 0x%x (%d bytes)\n", i, sec.Name, sec.Address, sec.Size)
	}

	fmt.Printf("\nSymbols: %d\n", len(parser.Symbols))
	for i, sym := range parser.Symbols[:min(10, len(parser.Symbols))] {
		name := parser.GetSymbolName(sym)
		fmt.Printf("  [%d] %s @ 0x%x (%d bytes)\n", i, name, sym.Value, sym.Size)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
