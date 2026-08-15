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
	
	fmt.Printf("Total functions: %d\n", len(file.FunctionHeaders))
	
	// Check function 8881
	hdr := file.FunctionHeaders[8881]
	fmt.Printf("\nFunction 8881:\n")
	fmt.Printf("  Offset: 0x%x\n", hdr.Offset)
	fmt.Printf("  Size: %d bytes\n", hdr.BytecodeSizeInBytes)
	
	// Check first 10 bytes
	code := make([]byte, hdr.BytecodeSizeInBytes)
	copy(code, file.GetRawData()[hdr.Offset:hdr.Offset+hdr.BytecodeSizeInBytes])
	fmt.Printf("  First 10 bytes: %x\n", code[:10])
	
	// Check what's at offset 236
	if len(code) > 242 {
		fmt.Printf("  Bytes at offset 236: %x\n", code[236:242])
	}
}
