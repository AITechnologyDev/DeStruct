package main

import (
	"fmt"
	"os"
	"github.com/destruct/destruct/internal/jvm"
)

func main() {
	jar, _ := jvm.ReadJAR(os.Args[1])
	for _, cf := range jar {
		if cf.GetSimpleClassName() == "AutoArmor" {
			for i, m := range cf.Methods {
				name := cf.GetUTF8(m.NameIndex)
				if name == "findBestArmor" {
					code, _ := cf.ParseCodeAttribute(i)
					insns := jvm.DecodeInstructions(code.Code)
					for idx, inst := range insns {
						fmt.Printf("  [%2d] [%3d] %s %v\n", idx, inst.Offset, jvm.OpcodeName(inst.Opcode), inst.Operands)
					}
				}
			}
		}
	}
}
