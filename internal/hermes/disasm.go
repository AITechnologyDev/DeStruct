package hermes

import (
	"fmt"
	"io"
	"math"
	"strings"
)

type Disassembler struct {
	File    *HBCFile
	Table   map[byte]*InstructionDef
	Verbose bool
}

func NewDisassembler(file *HBCFile) *Disassembler {
	return &Disassembler{
		File:  file,
		Table: buildOpcodeTableForVersion(file.Header.Version),
	}
}

func (d *Disassembler) DisassembleFunction(funcIdx int, w io.Writer) {
	if funcIdx >= len(d.File.FunctionHeaders) {
		return
	}
	hdr := d.File.FunctionHeaders[funcIdx]
	name := "<unknown>"
	if int(hdr.FunctionName) < len(d.File.Strings) {
		name = d.File.Strings[hdr.FunctionName]
	}

	fmt.Fprintf(w, "; ===== Function #%d: %s (%d bytes, %d params) =====\n",
		funcIdx, name, hdr.BytecodeSizeInBytes, hdr.ParamCount)

	code := d.File.getCode(funcIdx)
	if len(code) == 0 {
		fmt.Fprintln(w, "; (empty)")
		return
	}

	offset := uint32(0)
	for offset < uint32(len(code)) {
		remaining := code[offset:]
		pi := decodeInstruction(remaining, offset, d.Table)

		// Address
		fmt.Fprintf(w, "  %08x  ", offset)

		// Raw bytes
		instSize := pi.Inst.Size()
		if instSize > len(remaining) {
			instSize = len(remaining)
		}
		for i := 0; i < instSize && i < 8; i++ {
			fmt.Fprintf(w, "%02x ", remaining[i])
		}
		for i := instSize; i < 8; i++ {
			fmt.Fprint(w, "   ")
		}

		// Instruction
		fmt.Fprintf(w, "  %-28s", pi.Inst.Name)

		// Operands
		operands := d.formatOperands(pi)
		if operands != "" {
			fmt.Fprintf(w, "  %s", operands)
		}

		// Comment for string references
		if comment := d.commentForInst(pi); comment != "" {
			fmt.Fprintf(w, "  ; %s", comment)
		}

		fmt.Fprintln(w)
		offset = pi.NextOffset
	}
}

// DisassembleFunctionHermesDec outputs in hermes-dec compatible format
// Format: 00000000: <InstructionName>: <Type: value, ...>  # comments
func (d *Disassembler) DisassembleFunctionHermesDec(funcIdx int, w io.Writer) {
	if funcIdx >= len(d.File.FunctionHeaders) {
		return
	}
	hdr := d.File.FunctionHeaders[funcIdx]
	name := "<unknown>"
	if int(hdr.FunctionName) < len(d.File.Strings) {
		name = d.File.Strings[hdr.FunctionName]
	}

	fmt.Fprintf(w, "=> [Function #%d \"%s\" of %d bytes]: %d params, frame size=%d @ offset 0x%08x\n",
		funcIdx, name, hdr.BytecodeSizeInBytes, hdr.ParamCount, hdr.FrameSize, hdr.Offset)
	fmt.Fprintln(w)

	code := d.File.getCode(funcIdx)
	if len(code) == 0 {
		fmt.Fprintln(w, "(empty)")
		return
	}

	offset := uint32(0)
	for offset < uint32(len(code)) {
		remaining := code[offset:]
		pi := decodeInstruction(remaining, offset, d.Table)

		// Format in hermes-dec style: 00000000: <InstructionName>: <operands>
		fmt.Fprintf(w, "%08x: <%s>: ", offset, pi.Inst.Name)

		// Format operands with types
		operands := d.formatOperandsHermesDec(pi)
		if operands != "" {
			fmt.Fprint(w, operands)
		}

		// Add comments for special operands
		if comment := d.commentForInstHermesDec(pi); comment != "" {
			fmt.Fprintf(w, "  %s", comment)
		}

		fmt.Fprintln(w)
		offset = pi.NextOffset
	}
}

// formatOperandsHermesDec formats operands in hermes-dec style with types
func (d *Disassembler) formatOperandsHermesDec(pi *ParsedInstruction) string {
	var parts []string
	for i, arg := range pi.Args {
		if i >= len(pi.Inst.Operands) {
			break
		}
		op := pi.Inst.Operands[i]
		
		// Determine operand type name
		typeName := op.Name
		if i < len(pi.Inst.Meanings) {
			m := pi.Inst.Meanings[i]
			switch m {
			case MeaningStringID:
				typeName = "string_id"
			case MeaningFunctionID:
				typeName = "function_id"
			case MeaningBigIntID:
				typeName = "bigint_id"
			}
		}
		
		// Format based on type
		var value string
		switch typeName {
		case "Reg8":
			value = fmt.Sprintf("%d", arg)
		case "UInt8":
			value = fmt.Sprintf("%d", arg)
		case "UInt16":
			value = fmt.Sprintf("%d", arg)
		case "UInt32":
			value = fmt.Sprintf("%d", arg)
		case "Addr8", "Addr32":
			target := pi.Offset + uint32(int32(arg))
			value = fmt.Sprintf("0x%x", target)
		case "Double":
			bits := uint64(arg)
			f := math.Float64frombits(bits)
			value = fmt.Sprintf("%g", f)
		case "string_id":
			value = fmt.Sprintf("%d", arg)
		case "function_id":
			value = fmt.Sprintf("%d", arg)
		default:
			value = fmt.Sprintf("%d", arg)
		}
		
		parts = append(parts, fmt.Sprintf("%s: %s", typeName, value))
	}
	return strings.Join(parts, ", ")
}

// commentForInstHermesDec formats comments in hermes-dec style
func (d *Disassembler) commentForInstHermesDec(pi *ParsedInstruction) string {
	var comments []string
	
	for i, arg := range pi.Args {
		if i >= len(pi.Inst.Meanings) {
			break
		}
		m := pi.Inst.Meanings[i]
		switch m {
		case MeaningStringID:
			if int(arg) < len(d.File.Strings) {
				comments = append(comments, fmt.Sprintf("# String: '%s'", d.File.Strings[arg]))
			}
		case MeaningFunctionID:
			if int(arg) < len(d.File.FunctionHeaders) {
				fhdr := d.File.FunctionHeaders[arg]
				fname := "<unknown>"
				if int(fhdr.FunctionName) < len(d.File.Strings) {
					fname = d.File.Strings[fhdr.FunctionName]
				}
				comments = append(comments, fmt.Sprintf("# Function: [#%d %s of %d bytes]", arg, fname, fhdr.BytecodeSizeInBytes))
			}
		}
	}
	
	return strings.Join(comments, " ")
}

// DisassembleFunctionPatch outputs in a simplified format for manual patching
func (d *Disassembler) DisassembleFunctionPatch(funcIdx int, w io.Writer) {
	if funcIdx >= len(d.File.FunctionHeaders) {
		return
	}
	hdr := d.File.FunctionHeaders[funcIdx]
	name := "<unknown>"
	if int(hdr.FunctionName) < len(d.File.Strings) {
		name = d.File.Strings[hdr.FunctionName]
	}

	fmt.Fprintf(w, "# Function #%d: %s (%d bytes, %d params)\n",
		funcIdx, name, hdr.BytecodeSizeInBytes, hdr.ParamCount)

	code := d.File.getCode(funcIdx)
	if len(code) == 0 {
		return
	}

	offset := uint32(0)
	for offset < uint32(len(code)) {
		remaining := code[offset:]
		pi := decodeInstruction(remaining, offset, d.Table)

		// Simple format: address: instruction operands
		operands := d.formatOperandsSimple(pi)
		if operands != "" {
			fmt.Fprintf(w, "%06x: %s %s\n", offset, pi.Inst.Name, operands)
		} else {
			fmt.Fprintf(w, "%06x: %s\n", offset, pi.Inst.Name)
		}

		offset = pi.NextOffset
	}
}

// DisassembleFunctionHex outputs in hex-editor-friendly format with absolute file offsets
// Format: 0x%08x: %02x %02x ...  instruction operands  ; comments
func (d *Disassembler) DisassembleFunctionHex(funcIdx int, w io.Writer) {
	if funcIdx >= len(d.File.FunctionHeaders) {
		return
	}
	hdr := d.File.FunctionHeaders[funcIdx]
	name := "<unknown>"
	if int(hdr.FunctionName) < len(d.File.Strings) {
		name = d.File.Strings[hdr.FunctionName]
	}

	fmt.Fprintf(w, "; ===== Function #%d: %s (%d bytes, %d params) =====\n",
		funcIdx, name, hdr.BytecodeSizeInBytes, hdr.ParamCount)

	code := d.File.getCode(funcIdx)
	if len(code) == 0 {
		fmt.Fprintln(w, "; (empty)")
		return
	}

	offset := uint32(0)
	for offset < uint32(len(code)) {
		remaining := code[offset:]
		pi := decodeInstruction(remaining, offset, d.Table)

		// Absolute file offset
		absOffset := hdr.Offset + offset
		fmt.Fprintf(w, "0x%08x:  ", absOffset)

		// Raw bytes (variable length, up to 8 bytes shown)
		instSize := pi.Inst.Size()
		if instSize > len(remaining) {
			instSize = len(remaining)
		}
		for i := 0; i < instSize && i < 8; i++ {
			fmt.Fprintf(w, "%02x ", remaining[i])
		}
		for i := instSize; i < 8; i++ {
			fmt.Fprint(w, "   ")
		}

		// Instruction name
		fmt.Fprintf(w, " %s", pi.Inst.Name)

		// Operands
		operands := d.formatOperandsHex(pi)
		if operands != "" {
			fmt.Fprintf(w, " %s", operands)
		}

		// Comment for string references
		if comment := d.commentForInst(pi); comment != "" {
			fmt.Fprintf(w, "  ; %s", comment)
		}

		fmt.Fprintln(w)
		offset = pi.NextOffset
	}
}

// formatOperandsHex formats operands for hex-editor-friendly output
func (d *Disassembler) formatOperandsHex(pi *ParsedInstruction) string {
	var parts []string
	for i, arg := range pi.Args {
		if i >= len(pi.Inst.Operands) {
			break
		}
		op := pi.Inst.Operands[i]
		if op.IsAddr {
			target := pi.Offset + uint32(int32(arg))
			parts = append(parts, fmt.Sprintf("0x%x", target))
		} else if op.Name == "Double" {
			bits := uint64(arg)
			f := math.Float64frombits(bits)
			parts = append(parts, fmt.Sprintf("%g", f))
		} else {
			parts = append(parts, fmt.Sprintf("r%d", arg))
		}
	}
	return strings.Join(parts, ", ")
}

// formatOperandsSimple formats operands with string comments for patching
func (d *Disassembler) formatOperandsSimple(pi *ParsedInstruction) string {
	var parts []string
	var stringComment string

	for i, arg := range pi.Args {
		if i >= len(pi.Inst.Operands) {
			break
		}
		op := pi.Inst.Operands[i]
		if op.IsAddr {
			target := pi.Offset + uint32(int32(arg))
			parts = append(parts, fmt.Sprintf("0x%x", target))
		} else if op.Name == "Double" {
			bits := uint64(arg)
			f := math.Float64frombits(bits)
			parts = append(parts, fmt.Sprintf("%g", f))
		} else {
			parts = append(parts, fmt.Sprintf("r%d", arg))
		}

		// Check if this operand is a string reference
		if i < len(pi.Inst.Meanings) && pi.Inst.Meanings[i] == MeaningStringID {
			if int(arg) < len(d.File.Strings) {
				stringComment = d.File.Strings[arg]
			}
		}
	}

	result := strings.Join(parts, ", ")
	if stringComment != "" {
		result += fmt.Sprintf("  ; %q", stringComment)
	}

	return result
}

func (d *Disassembler) formatOperands(pi *ParsedInstruction) string {
	var parts []string
	for i, arg := range pi.Args {
		if i >= len(pi.Inst.Operands) {
			break
		}
		op := pi.Inst.Operands[i]
		if op.IsAddr {
			target := pi.Offset + uint32(int32(arg))
			parts = append(parts, fmt.Sprintf("%08x", target))
		} else if op.Name == "Double" {
			// Decode as float64
			bits := uint64(arg)
			f := math.Float64frombits(bits)
			parts = append(parts, fmt.Sprintf("%g", f))
		} else {
			parts = append(parts, fmt.Sprintf("r%d", arg))
			if i < len(pi.Inst.Meanings) {
				m := pi.Inst.Meanings[i]
				if m == MeaningStringID && int(arg) < len(d.File.Strings) {
					parts[len(parts)-1] = fmt.Sprintf("r%d", arg)
				}
			}
		}
	}
	return strings.Join(parts, ", ")
}

func (d *Disassembler) commentForInst(pi *ParsedInstruction) string {
	var comments []string

	for i, arg := range pi.Args {
		if i >= len(pi.Inst.Meanings) {
			break
		}
		m := pi.Inst.Meanings[i]
		switch m {
		case MeaningStringID:
			if int(arg) < len(d.File.Strings) {
				comments = append(comments, fmt.Sprintf("String: %q", d.File.Strings[arg]))
			}
		case MeaningFunctionID:
			if int(arg) < len(d.File.FunctionHeaders) {
				fhdr := d.File.FunctionHeaders[arg]
				fname := "<unknown>"
				if int(fhdr.FunctionName) < len(d.File.Strings) {
					fname = d.File.Strings[fhdr.FunctionName]
				}
				comments = append(comments, fmt.Sprintf("Function: #%d %s", arg, fname))
			}
		case MeaningBigIntID:
			comments = append(comments, fmt.Sprintf("BigInt: #%d", arg))
		}
	}

	// Jump target comment
	if pi.Inst.Name != "" {
		for i, op := range pi.Inst.Operands {
			if op.IsAddr && i < len(pi.Args) {
				target := pi.Offset + uint32(int32(pi.Args[i]))
				comments = append(comments, fmt.Sprintf("-> %08x", target))
			}
		}
	}

	return strings.Join(comments, " | ")
}

func (d *Disassembler) DisassembleAll(w io.Writer) {
	// Header
	fmt.Fprintf(w, "; Hermes bytecode v%d\n", d.File.Header.Version)
	fmt.Fprintf(w, "; %d functions, %d strings\n\n", d.File.Header.FunctionCount, d.File.Header.StringCount)

	// String table
	fmt.Fprintln(w, "; ===== String Table =====")
	for i, s := range d.File.Strings {
		fmt.Fprintf(w, "; [%d] %q\n", i, s)
	}
	fmt.Fprintln(w)

	// Functions
	for i := range d.File.FunctionHeaders {
		d.DisassembleFunction(i, w)
		fmt.Fprintln(w)
	}
}

// DisassembleAllPatch outputs in simplified format for manual patching
func (d *Disassembler) DisassembleAllPatch(w io.Writer) {
	// Simple header
	fmt.Fprintf(w, "# Hermes bytecode v%d\n", d.File.Header.Version)
	fmt.Fprintf(w, "# %d functions, %d strings\n\n", d.File.Header.FunctionCount, d.File.Header.StringCount)

	// String table as comment
	fmt.Fprintln(w, "# String Table:")
	for i, s := range d.File.Strings {
		fmt.Fprintf(w, "# [%d] %q\n", i, s)
	}
	fmt.Fprintln(w)

	// Functions
	for i := range d.File.FunctionHeaders {
		d.DisassembleFunctionPatch(i, w)
		fmt.Fprintln(w)
	}
}

// DisassembleAllHex outputs all functions in hex-editor-friendly format
func (d *Disassembler) DisassembleAllHex(w io.Writer) {
	// Header with absolute offsets
	fmt.Fprintf(w, "; Hermes bytecode v%d\n", d.File.Header.Version)
	fmt.Fprintf(w, "; %d functions, %d strings\n", d.File.Header.FunctionCount, d.File.Header.StringCount)
	fmt.Fprintf(w, "; Format: 0x<file_offset>: <hex_bytes>  <instruction>  ; <comments>\n")
	fmt.Fprintf(w, "; Patch by editing hex bytes at the file offset shown\n\n")

	// String table as comment
	fmt.Fprintln(w, "; String Table:")
	for i, s := range d.File.Strings {
		fmt.Fprintf(w, "; [%d] %q\n", i, s)
	}
	fmt.Fprintln(w)

	// Functions
	for i := range d.File.FunctionHeaders {
		d.DisassembleFunctionHex(i, w)
		fmt.Fprintln(w)
	}
}

// DisassembleAllHermesDec outputs all functions in hermes-dec compatible format
func (d *Disassembler) DisassembleAllHermesDec(w io.Writer) {
	// Header
	fmt.Fprintf(w, "Hermes bytecode version %d\n", d.File.Header.Version)
	fmt.Fprintf(w, "%d functions, %d strings\n\n", d.File.Header.FunctionCount, d.File.Header.StringCount)

	// String table
	fmt.Fprintln(w, "String table:")
	for i, s := range d.File.Strings {
		fmt.Fprintf(w, "  [%d] %q\n", i, s)
	}
	fmt.Fprintln(w)

	// Functions
	for i := range d.File.FunctionHeaders {
		d.DisassembleFunctionHermesDec(i, w)
		fmt.Fprintln(w)
	}
}

func (d *Disassembler) DisassembleFunctionByName(name string, w io.Writer) bool {
	for i, hdr := range d.File.FunctionHeaders {
		if int(hdr.FunctionName) < len(d.File.Strings) {
			if d.File.Strings[hdr.FunctionName] == name {
				d.DisassembleFunction(i, w)
				return true
			}
		}
	}
	return false
}
