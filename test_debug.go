package main

import (
	"fmt"
	"github.com/destruct/destruct/internal/hermes"
)

func main() {
	file, err := hermes.ParseFile("index.android.bundle")
	if err != nil {
		panic(err)
	}
	
	// Check function 19680
	hdr := file.FunctionHeaders[19680]
	fmt.Printf("Function 19680:\n")
	fmt.Printf("  Offset: 0x%x\n", hdr.Offset)
	fmt.Printf("  Size: %d bytes\n", hdr.BytecodeSizeInBytes)
	
	// Get bytecode using the same method as patcher
	code := file.GetCode(19680)
	fmt.Printf("  Code length: %d\n", len(code))
	
	// Check what's at offset 3
	if len(code) > 3 {
		fmt.Printf("  Bytes at offset 3: %x\n", code[3:9])
		fmt.Printf("  Opcode: 0x%x\n", code[3])
	}
}
