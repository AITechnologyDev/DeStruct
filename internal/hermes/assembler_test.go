package hermes

import (
	"testing"
)

func TestParseHASM(t *testing.T) {
	a := NewAssembler()
	instrs, err := a.ParseHASM("testdata/sample.hbc.hasm")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(instrs) != 2 {
		t.Fatalf("expected 2 instructions, got %d", len(instrs))
	}

	first := instrs[0]
	if first.Name != "LoadConstUInt8" {
		t.Errorf("expected name LoadConstUInt8, got %s", first.Name)
	}
	if first.Offset != 0 {
		t.Errorf("expected offset 0, got 0x%x", first.Offset)
	}
	wantOperands := []string{"r0", "5"}
	if len(first.Operands) != len(wantOperands) {
		t.Fatalf("expected operands %v, got %v", wantOperands, first.Operands)
	}
	for i, op := range wantOperands {
		if first.Operands[i] != op {
			t.Errorf("operand %d: expected %q, got %q", i, op, first.Operands[i])
		}
	}

	second := instrs[1]
	if second.Name != "Unreachable" {
		t.Errorf("expected name Unreachable, got %s", second.Name)
	}
	if second.Offset != 2 {
		t.Errorf("expected offset 2, got 0x%x", second.Offset)
	}
}
