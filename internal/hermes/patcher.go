package hermes

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Patcher provides binary patching capabilities for HBC files
type Patcher struct {
	File          *HBCFile
	Assembler     *Assembler
	OriginalData  []byte
	Modifications []PatchEntry
}

// PatchEntry represents a single modification
type PatchEntry struct {
	FuncIdx    int
	Offset     uint32 // Relative to function start
	OldBytes   []byte
	NewBytes   []byte
	Comment    string
}

// NewPatcher creates a new patcher for the given HBC file
func NewPatcher(file *HBCFile) *Patcher {
	return &Patcher{
		File:      file,
		Assembler: NewAssembler(),
	}
}

// SearchPattern represents a search result
type SearchPattern struct {
	FuncIdx   int
	FuncName  string
	Offset    uint32 // Absolute offset in file
	RelOffset uint32 // Relative to function start
	Match     []byte
}

// SearchBytes searches for a byte pattern in all functions
func (p *Patcher) SearchBytes(pattern []byte) []SearchPattern {
	var results []SearchPattern

	for funcIdx := range p.File.FunctionHeaders {
		code := p.File.getCode(funcIdx)
		offsets := searchBytes(code, pattern)

		name := "<unknown>"
		if int(p.File.FunctionHeaders[funcIdx].FunctionName) < len(p.File.Strings) {
			name = p.File.Strings[p.File.FunctionHeaders[funcIdx].FunctionName]
		}

		for _, relOff := range offsets {
			absOff := p.File.FunctionHeaders[funcIdx].Offset + relOff
			results = append(results, SearchPattern{
				FuncIdx:   funcIdx,
				FuncName:  name,
				Offset:    absOff,
				RelOffset: relOff,
				Match:     pattern,
			})
		}
	}

	return results
}

// SearchString searches for a string in all functions and string table
func (p *Patcher) SearchString(s string, exactMatch bool) []SearchPattern {
	var results []SearchPattern

	// Find all string IDs that match
	var matchingStringIDs []int
	for i, str := range p.File.Strings {
		if exactMatch {
			if str == s {
				matchingStringIDs = append(matchingStringIDs, i)
			}
		} else {
			if strings.Contains(str, s) {
				matchingStringIDs = append(matchingStringIDs, i)
			}
		}
	}

	fmt.Printf("Found %d matching string IDs: %v\n", len(matchingStringIDs), matchingStringIDs)

	// For each matching string ID, find all functions that reference it
	for _, stringID := range matchingStringIDs {
		for funcIdx := range p.File.FunctionHeaders {
			code := p.File.getCode(funcIdx)
			if len(code) == 0 {
				continue
			}
			offset := uint32(0)
			for offset < uint32(len(code)) {
				remaining := code[offset:]
				pi := decodeInstruction(remaining, offset, p.Assembler.Table)
				if pi == nil {
					break
				}
				// Check if this instruction references the string ID
				for j, m := range pi.Inst.Meanings {
					if m == MeaningStringID && j < len(pi.Args) && pi.Args[j] == uint64(stringID) {
						name := "<unknown>"
						if int(p.File.FunctionHeaders[funcIdx].FunctionName) < len(p.File.Strings) {
							name = p.File.Strings[p.File.FunctionHeaders[funcIdx].FunctionName]
						}
						results = append(results, SearchPattern{
							FuncIdx:   funcIdx,
							FuncName:  name,
							Offset:    p.File.FunctionHeaders[funcIdx].Offset + offset,
							RelOffset: offset,
							Match:     []byte(p.File.Strings[stringID]),
						})
					}
				}
				offset = pi.NextOffset
			}
		}
	}

	return results
}

// SearchInstruction searches for instruction patterns
func (p *Patcher) SearchInstruction(pattern string) []SearchPattern {
	var results []SearchPattern
	pattern = strings.ToLower(pattern)

	for funcIdx := range p.File.FunctionHeaders {
		code := p.File.getCode(funcIdx)
		offset := uint32(0)

		for offset < uint32(len(code)) {
			remaining := code[offset:]
			pi := decodeInstruction(remaining, offset, p.Assembler.Table)
			if pi == nil {
				break
			}

			// Check if instruction matches pattern
			if matchInstruction(pi, pattern) {
				name := "<unknown>"
				if int(p.File.FunctionHeaders[funcIdx].FunctionName) < len(p.File.Strings) {
					name = p.File.Strings[p.File.FunctionHeaders[funcIdx].FunctionName]
				}
				absOff := p.File.FunctionHeaders[funcIdx].Offset + offset
				results = append(results, SearchPattern{
					FuncIdx:   funcIdx,
					FuncName:  name,
					Offset:    absOff,
					RelOffset: offset,
				})
			}

			offset = pi.NextOffset
		}
	}

	return results
}

// matchInstruction checks if an instruction matches a pattern
func matchInstruction(pi *ParsedInstruction, pattern string) bool {
	// Simple pattern matching: "LoadConstString" matches any LoadConstString
	// "LoadConstString bonjour" matches only with that string
	parts := strings.Fields(pattern)
	if len(parts) == 0 {
		return false
	}

	// Check instruction name
	if !strings.Contains(strings.ToLower(pi.Inst.Name), strings.ToLower(parts[0])) {
		return false
	}

	// Check operands if provided
	if len(parts) > 1 {
		for i, arg := range pi.Args {
			if i+1 >= len(parts) {
				break
			}
			argStr := fmt.Sprintf("%d", arg)
			if !strings.Contains(argStr, parts[i+1]) {
				return false
			}
		}
	}

	return true
}

// PatchAt patches bytes at a specific function and offset
func (p *Patcher) PatchAt(funcIdx int, relOffset uint32, newBytes []byte) error {
	if funcIdx >= len(p.File.FunctionHeaders) {
		return fmt.Errorf("invalid function index: %d", funcIdx)
	}

	hdr := &p.File.FunctionHeaders[funcIdx]
	if relOffset+uint32(len(newBytes)) > hdr.BytecodeSizeInBytes {
		return fmt.Errorf("patch extends beyond function: offset=%d, len=%d, func_size=%d",
			relOffset, len(newBytes), hdr.BytecodeSizeInBytes)
	}

	// Get old bytes
	code := p.File.getCode(funcIdx)
	oldBytes := make([]byte, len(newBytes))
	copy(oldBytes, code[relOffset:relOffset+uint32(len(newBytes))])

	// Record modification
	p.Modifications = append(p.Modifications, PatchEntry{
		FuncIdx:  funcIdx,
		Offset:   relOffset,
		OldBytes: oldBytes,
		NewBytes: newBytes,
	})

	// Apply to rawData
	absOffset := hdr.Offset + relOffset
	copy(p.File.rawData[absOffset:], newBytes)

	return nil
}

// PatchInstruction patches a single instruction
func (p *Patcher) PatchInstruction(funcIdx int, relOffset uint32, asm string) error {
	// Parse the instruction
	lines := []string{fmt.Sprintf("  00000000  00               %s", asm)}
	instrs, err := p.Assembler.ParseHASMString(strings.Join(lines, "\n"))
	if err != nil || len(instrs) == 0 {
		return fmt.Errorf("failed to parse instruction: %s", asm)
	}

	// Assemble it
	bytes, errors := p.Assembler.Assemble(instrs)
	if len(errors) > 0 {
		return fmt.Errorf("assembly error: %s", errors[0])
	}

	return p.PatchAt(funcIdx, relOffset, bytes)
}

// NOPInstruction replaces an instruction with NOPs
func (p *Patcher) NOPInstruction(funcIdx int, relOffset uint32) error {
	code := p.File.getCode(funcIdx)
	if relOffset >= uint32(len(code)) {
		return fmt.Errorf("offset beyond function")
	}

	// Decode to get instruction size
	remaining := code[relOffset:]
	pi := decodeInstruction(remaining, relOffset, p.Assembler.Table)
	if pi == nil {
		return fmt.Errorf("failed to decode instruction")
	}

	// Replace with zeros (NOP in Hermes)
	nopBytes := make([]byte, pi.Inst.Size())
	return p.PatchAt(funcIdx, relOffset, nopBytes)
}

// PatchJump patches a jump instruction's target
func (p *Patcher) PatchJump(funcIdx int, relOffset uint32, newTarget uint32) error {
	code := p.File.getCode(funcIdx)
	remaining := code[relOffset:]
	pi := decodeInstruction(remaining, relOffset, p.Assembler.Table)
	if pi == nil {
		return fmt.Errorf("failed to decode instruction")
	}

	// Find address operand
	addrIdx := -1
	for i, op := range pi.Inst.Operands {
		if op.IsAddr {
			addrIdx = i
			break
		}
	}
	if addrIdx < 0 {
		return fmt.Errorf("no address operand in %s", pi.Inst.Name)
	}

	// Calculate relative offset
	// Target is stored as: current_offset + relative_offset
	// So: relative_offset = newTarget - current_offset
	relTarget := int32(newTarget) - int32(pi.Offset)

	// Build new operand bytes
	var newBytes []byte
	op := pi.Inst.Operands[addrIdx]
	switch op.Size {
	case 1:
		newBytes = []byte{byte(int8(relTarget))}
	case 2:
		newBytes = []byte{byte(int16(relTarget)), byte(int16(relTarget) >> 8)}
	case 4:
		newBytes = []byte{byte(relTarget), byte(relTarget >> 8), byte(relTarget >> 16), byte(relTarget >> 24)}
	}

	// Calculate offset of this operand in the instruction
	opOffset := 1 // skip opcode
	for i := 0; i < addrIdx; i++ {
		opOffset += pi.Inst.Operands[i].Size
	}

	return p.PatchAt(funcIdx, relOffset+uint32(opOffset), newBytes)
}

// PatchStringOperand patches a string ID operand
func (p *Patcher) PatchStringOperand(funcIdx int, relOffset uint32, newStringID uint32) error {
	code := p.File.getCode(funcIdx)
	remaining := code[relOffset:]
	pi := decodeInstruction(remaining, relOffset, p.Assembler.Table)
	if pi == nil {
		return fmt.Errorf("failed to decode instruction")
	}

	// Find string operand
	strIdx := -1
	for i, m := range pi.Inst.Meanings {
		if m == MeaningStringID {
			strIdx = i
			break
		}
	}
	if strIdx < 0 {
		return fmt.Errorf("no string operand in %s", pi.Inst.Name)
	}

	// Calculate offset
	opOffset := 1
	for i := 0; i < strIdx; i++ {
		opOffset += pi.Inst.Operands[i].Size
	}

	// Build new bytes
	op := pi.Inst.Operands[strIdx]
	var newBytes []byte
	switch op.Size {
	case 2:
		newBytes = []byte{byte(newStringID), byte(newStringID >> 8)}
	case 4:
		newBytes = []byte{byte(newStringID), byte(newStringID >> 8), byte(newStringID >> 16), byte(newStringID >> 24)}
	}

	return p.PatchAt(funcIdx, relOffset+uint32(opOffset), newBytes)
}

// PatchFunctionOperand patches a function ID operand
func (p *Patcher) PatchFunctionOperand(funcIdx int, relOffset uint32, newFuncID uint32) error {
	code := p.File.getCode(funcIdx)
	remaining := code[relOffset:]
	pi := decodeInstruction(remaining, relOffset, p.Assembler.Table)
	if pi == nil {
		return fmt.Errorf("failed to decode instruction")
	}

	// Find function operand
	funcIdxIdx := -1
	for i, m := range pi.Inst.Meanings {
		if m == MeaningFunctionID {
			funcIdxIdx = i
			break
		}
	}
	if funcIdxIdx < 0 {
		return fmt.Errorf("no function operand in %s", pi.Inst.Name)
	}

	// Calculate offset
	opOffset := 1
	for i := 0; i < funcIdxIdx; i++ {
		opOffset += pi.Inst.Operands[i].Size
	}

	// Build new bytes
	op := pi.Inst.Operands[funcIdxIdx]
	var newBytes []byte
	switch op.Size {
	case 2:
		newBytes = []byte{byte(newFuncID), byte(newFuncID >> 8)}
	case 4:
		newBytes = []byte{byte(newFuncID), byte(newFuncID >> 8), byte(newFuncID >> 16), byte(newFuncID >> 24)}
	}

	return p.PatchAt(funcIdx, relOffset+uint32(opOffset), newBytes)
}

// Save writes the patched file with recalculated SHA1
func (p *Patcher) Save(path string) error {
	// Recalculate SHA1 hash at the end
	if p.File.Header.Version >= 75 && len(p.File.rawData) >= sha1Size {
		dataWithoutHash := p.File.rawData[:len(p.File.rawData)-sha1Size]
		hash := sha1.Sum(dataWithoutHash)
		copy(p.File.rawData[len(p.File.rawData)-sha1Size:], hash[:])
	}

	return os.WriteFile(path, p.File.rawData, 0644)
}

// QuickPatchString searches for a string and patches the instruction that uses it
// This is the fast way to patch without parsing the whole HASM file
// Uses raw byte search for accuracy
func (p *Patcher) QuickPatchString(searchString string, patchType string, checkOnly bool) (int, error) {
	patched := 0

	// Find string ID
	var stringID int = -1
	for i, str := range p.File.Strings {
		if str == searchString {
			stringID = i
			break
		}
	}

	if stringID < 0 {
		return 0, fmt.Errorf("string %q not found", searchString)
	}

	// Find a truthy string for "true" patch
	var truthyStringID int = -1
	if patchType == "true" {
		for i, str := range p.File.Strings {
			if str == "1" || str == "true" {
				truthyStringID = i
				break
			}
		}
		if truthyStringID < 0 {
			return 0, fmt.Errorf("no truthy string found (need '1' or 'true')")
		}
	}

		// Search for GetById opcode (0x45) with the string ID
	for funcIdx := range p.File.FunctionHeaders {
		hdr := &p.File.FunctionHeaders[funcIdx]
		code := p.File.getCode(funcIdx)
		
		// Search for the pattern: 0x45 + 3 bytes (dst, obj, prop) + 2 bytes (string ID)
		for offset := uint32(0); offset+6 <= uint32(len(code)); offset++ {
			if code[offset] != 0x45 { // GetById opcode
				continue
			}
			
			// Check if string ID matches
			sid := uint32(code[offset+4]) | uint32(code[offset+5])<<8
			if sid != uint32(stringID) {
				continue
			}
			
			// Found a match! Check if it's a CHECK or READ
			isCheck := false
			if offset+6 < uint32(len(code)) {
				nextOpcode := code[offset+6]
				// Check if next instruction is a conditional jump or comparison
				switch nextOpcode {
				case 0xb3, 0xb4, // JmpFalse, JmpTrue
					0xb0, 0xb1, 0xb2, // JmpLong, JmpTrueLong, JmpFalseLong
					0xd4, 0xd5, // JStrictEqual, JmpStrictNeq
					0xd1, 0xd2, 0xd3, // JNotEqual, JStrictEqual, JmpStrictNeq
					0x13, 0x14, // Not, ToBoolean
					0xd6, 0xd7, 0xd8, 0xd9, // JmpLt, JmpLte, JmpGt, JmpGte
					0xda, 0xdb, 0xdc, 0xdd: // JmpLtLong, JmpLteLong, JmpGtLong, JmpGteLong
					isCheck = true
				}
			}
			
			// If checkOnly mode, skip READ instructions
			if checkOnly && !isCheck {
				continue
			}
			
			// Calculate absolute offset
			absOffset := hdr.Offset + offset
			
			// Patch based on type
			switch patchType {
			case "true":
				// Strategy: NOP out the conditional jump after GetById
				// by setting its offset to 0 (jump to next instruction = NOP)
				condOffset := absOffset + 6
				if condOffset >= uint32(len(p.File.rawData)) {
					continue
				}
				condOpcode := p.File.rawData[condOffset]
				
				switch condOpcode {
				case 0xb3: // JmpFalseLong: opcode + Reg8 + Addr32 (6 bytes)
					// Set Addr32 to 0 → jump goes to next instruction
					if condOffset+6 <= uint32(len(p.File.rawData)) {
						p.File.rawData[condOffset+2] = 0x00
						p.File.rawData[condOffset+3] = 0x00
						p.File.rawData[condOffset+4] = 0x00
						p.File.rawData[condOffset+5] = 0x00
						fmt.Printf("  Patched func %d: JmpFalseLong offset→0 (%s)\n", funcIdx,
							map[bool]string{true: "CHECK", false: "READ"}[isCheck])
					}
				case 0xd1: // JNotEqual: opcode + Reg8 + Reg8 + Addr8 (4 bytes)
					// Set Addr8 to 0 → jump goes to next instruction
					if condOffset+4 <= uint32(len(p.File.rawData)) {
						p.File.rawData[condOffset+3] = 0x00
						fmt.Printf("  Patched func %d: JNotEqual offset→0 (%s)\n", funcIdx,
							map[bool]string{true: "CHECK", false: "READ"}[isCheck])
					}
				case 0x13: // Not: opcode + Reg8 + Reg8 (3 bytes)
					// Replace Not with Mov r0,r0 (NOP): 0x10 0x00 0x00
					// Then find the JmpTrue after it and NOP that too
					if condOffset+3 <= uint32(len(p.File.rawData)) {
						// Replace Not with Mov (NOP)
						p.File.rawData[condOffset] = 0x10     // Mov opcode
						p.File.rawData[condOffset+2] = 0x00  // src = r0
				// Now find JmpTrue after Not (3 bytes later)
					jmpOffset := condOffset + 3
					if jmpOffset < uint32(len(p.File.rawData)) && (p.File.rawData[jmpOffset] == 0xb0 || p.File.rawData[jmpOffset] == 0xb1) { // JmpTrue (v98=0xb0, v99=0xb1)
							// Set JmpTrue offset to 3 (next instruction)
							if jmpOffset+3 <= uint32(len(p.File.rawData)) {
								p.File.rawData[jmpOffset+1] = 0x03
							}
						}
						fmt.Printf("  Patched func %d: Not→Mov + JmpTrue→next (%s)\n", funcIdx,
							map[bool]string{true: "CHECK", false: "READ"}[isCheck])
					}
				default:
					fmt.Printf("  WARNING: func %d: unknown cond opcode 0x%02x at 0x%x\n", funcIdx, condOpcode, condOffset)
				}
			case "false":
				// Replace string ID with empty string (falsy)
				copy(p.File.rawData[absOffset+4:], []byte{0, 0})
			}
			
			patched++
		}
	}

	return patched, nil
}

// isCheckInstruction checks if an instruction is followed by a conditional jump
func (p *Patcher) isCheckInstruction(funcIdx int, offset uint32, pi *ParsedInstruction) bool {
	code := p.File.getCode(funcIdx)
	nextOffset := pi.NextOffset
	
	if nextOffset >= uint32(len(code)) {
		return false
	}
	
	// Decode next instruction
	remaining := code[nextOffset:]
	nextPi := decodeInstruction(remaining, nextOffset, p.Assembler.Table)
	if nextPi == nil {
		return false
	}
	
	// Check if next instruction is a conditional jump or comparison
	switch nextPi.Inst.Name {
	case "JmpFalse", "JmpTrue", "JmpFalseLong", "JmpTrueLong",
		"JNotEqual", "JStrictEqual", "JNotEqualLong", "JStrictEqualLong",
		"JmpEq", "JmpNeq", "JmpLt", "JmpLte", "JmpGt", "JmpGte",
		"Not", "ToBoolean":
		return true
	}
	
	return false
}

// GetModifications returns all pending modifications
func (p *Patcher) GetModifications() []PatchEntry {
	return p.Modifications
}

// ClearModifications clears all pending modifications
func (p *Patcher) ClearModifications() {
	p.Modifications = nil
}

// GetInstructionAt returns the instruction at a specific offset
func (p *Patcher) GetInstructionAt(funcIdx int, relOffset uint32) (*ParsedInstruction, error) {
	if funcIdx >= len(p.File.FunctionHeaders) {
		return nil, fmt.Errorf("invalid function index: %d", funcIdx)
	}

	code := p.File.getCode(funcIdx)
	if relOffset >= uint32(len(code)) {
		return nil, fmt.Errorf("offset %d beyond function size %d", relOffset, len(code))
	}

	remaining := code[relOffset:]
	pi := decodeInstruction(remaining, relOffset, p.Assembler.Table)
	if pi == nil {
		return nil, fmt.Errorf("failed to decode instruction at offset %d", relOffset)
	}

	return pi, nil
}

// ListFunction returns all instructions in a function
func (p *Patcher) ListFunction(funcIdx int) []*ParsedInstruction {
	if funcIdx >= len(p.File.FunctionHeaders) {
		return nil
	}

	var result []*ParsedInstruction
	code := p.File.getCode(funcIdx)
	offset := uint32(0)

	for offset < uint32(len(code)) {
		remaining := code[offset:]
		pi := decodeInstruction(remaining, offset, p.Assembler.Table)
		if pi == nil {
			break
		}
		result = append(result, pi)
		offset = pi.NextOffset
	}

	return result
}

// searchBytes finds all occurrences of pattern in data
func searchBytes(data, pattern []byte) []uint32 {
	var offsets []uint32
	if len(pattern) == 0 || len(pattern) > len(data) {
		return offsets
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := range pattern {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			offsets = append(offsets, uint32(i))
		}
	}
	return offsets
}

// ParseHASMString parses HASM text (helper for assembler)
func (a *Assembler) ParseHASMString(text string) ([]*AssembledInstruction, error) {
	var instructions []*AssembledInstruction
	scanner := bufio.NewScanner(strings.NewReader(text))
	instrRe := regexp.MustCompile(`^\s+([0-9a-f]{8})\s+([0-9a-f]{2}(?:\s+[0-9a-f]{2})*)\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\s+(.*))?$`)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if matches := instrRe.FindStringSubmatch(line); matches != nil {
			offset, _ := strconv.ParseUint(matches[1], 16, 32)
			name := matches[3]
			operandStr := strings.TrimSpace(matches[4])

			var operands []string
			if operandStr != "" {
				if idx := strings.Index(operandStr, ";"); idx >= 0 {
					operandStr = strings.TrimSpace(operandStr[:idx])
				}
				if idx := strings.Index(operandStr, "//"); idx >= 0 {
					operandStr = strings.TrimSpace(operandStr[:idx])
				}
				operands = splitOperands(operandStr)
			}

			instructions = append(instructions, &AssembledInstruction{
				Offset:   uint32(offset),
				HexBytes: strings.TrimSpace(matches[2]),
				Name:     name,
				Operands: operands,
				Raw:      line,
			})
		}
	}

	return instructions, nil
}
