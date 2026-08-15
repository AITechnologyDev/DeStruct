package main

import (
	"fmt"
	"github.com/destruct/destruct/internal/jvm"
)

func main() {
	cf, err := jvm.ParseClassFile("test/Calculator.class")
	if err != nil {
		fmt.Println(err)
		return
	}

	for i, method := range cf.Methods {
		name := cf.GetUTF8(method.NameIndex)
		if name != "isPositive" {
			continue
		}
		fmt.Printf("Method: %s (index %d)\n", name, i)
		code, err := cf.ParseCodeAttribute(i)
		if err != nil {
			fmt.Println(err)
			return
		}
		instructions := jvm.DecodeInstructions(code.Code)
		for _, inst := range instructions {
			fmt.Printf("  offset=%d opcode=%d operands=%v\n", inst.Offset, byte(inst.Opcode), inst.Operands)
		}
	}
}
