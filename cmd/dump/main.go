package main

import (
	"fmt"
	"os"
	"github.com/destruct/destruct/internal/jvm"
)

func main() {
	cf, err := jvm.ParseClassFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	methodName := os.Args[2]
	for i, m := range cf.Methods {
		name := cf.GetUTF8(m.NameIndex)
		if name == methodName {
			code, err := cf.ParseCodeAttribute(i)
			if err != nil {
				continue
			}
			fmt.Printf("Method: %s\n", methodName)
			instrs := jvm.DecodeInstructions(code.Code)
			for idx, inst := range instrs {
				opName := jvm.OpcodeName(inst.Opcode)
				resolved := ""
				if len(inst.Operands) >= 2 {
					cpIdx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
					if int(cpIdx) < len(cf.ConstantPool) {
						entry := cf.ConstantPool[cpIdx]
						if entry.Methodref != nil {
							className := cf.GetClassName(entry.Methodref.ClassIndex)
							nat := cf.ConstantPool[entry.Methodref.NameAndTypeIndex].NameAndType
							mname := cf.GetUTF8(nat.NameIndex)
							mdesc := cf.GetUTF8(nat.DescriptorIndex)
							resolved = fmt.Sprintf(" → %s.%s%s", className, mname, mdesc)
						} else if entry.Fieldref != nil {
							className := cf.GetClassName(entry.Fieldref.ClassIndex)
							nat := cf.ConstantPool[entry.Fieldref.NameAndTypeIndex].NameAndType
							fname := cf.GetUTF8(nat.NameIndex)
							fdesc := cf.GetUTF8(nat.DescriptorIndex)
							resolved = fmt.Sprintf(" → %s.%s:%s", className, fname, fdesc)
						} else if entry.InterfaceMethodref != nil {
							className := cf.GetClassName(entry.InterfaceMethodref.ClassIndex)
							nat := cf.ConstantPool[entry.InterfaceMethodref.NameAndTypeIndex].NameAndType
							mname := cf.GetUTF8(nat.NameIndex)
							mdesc := cf.GetUTF8(nat.DescriptorIndex)
							resolved = fmt.Sprintf(" → %s.%s%s", className, mname, mdesc)
						}
					}
				}
				fmt.Printf("  [%d] offset=%d %s %v%s\n", idx, inst.Offset, opName, inst.Operands, resolved)
			}
		}
	}
}
