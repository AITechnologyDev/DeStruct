package hermes

import (
    "testing"
    "fmt"
)

func TestParseHASM(t *testing.T) {
    a := NewAssembler()
    instrs, err := a.ParseHASM("/data/data/com.termux/files/home/.cache/opencode/tmp/patch_test/sample.hbc.hasm")
    if err != nil {
        t.Fatalf("Error: %v", err)
    }
    
    fmt.Printf("Parsed %d instructions\n", len(instrs))
    for i, instr := range instrs {
        if i >= 10 {
            break
        }
        fmt.Printf("[%d] Offset: 0x%x, Name: %s, Operands: %v\n", i, instr.Offset, instr.Name, instr.Operands)
    }
}
