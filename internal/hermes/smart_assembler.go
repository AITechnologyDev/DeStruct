package hermes

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// SmartAssembler handles address recalculation when patching
type SmartAssembler struct {
	Table      map[byte]*InstructionDef
	NameToInst map[string]*InstructionDef
}

// PatchedInstruction is an instruction that may have been modified
type PatchedInstruction struct {
	Address    uint32
	OrigSize   int
	NewSize    int
	Name       string
	Operands   []string
	IsJump     bool
	IsBranch   bool
	TargetAddr uint32
	OrigOffset uint32
	NewOffset  uint32
}

func NewSmartAssembler() *SmartAssembler {
	table := buildOpcodeTable99()
	nameToInst := make(map[string]*InstructionDef)
	for _, inst := range table {
		nameToInst[inst.Name] = inst
	}
	return &SmartAssembler{
		Table:      table,
		NameToInst: nameToInst,
	}
}

// ParseSimple parses the simplified format: "000000: LoadParam r1, r1"
func (sa *SmartAssembler) ParseSimple(filename string) ([]*PatchedInstruction, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var instructions []*PatchedInstruction
	lineRe := regexp.MustCompile(`^([0-9a-f]{6}):\s+(\w+)(?:\s+(.*))?$`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := lineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		address, _ := strconv.ParseUint(matches[1], 16, 32)
		name := matches[2]
		operandStr := strings.TrimSpace(matches[3])

		// Remove comments from operands
		if idx := strings.Index(operandStr, ";"); idx >= 0 {
			operandStr = strings.TrimSpace(operandStr[:idx])
		}

		var operands []string
		if operandStr != "" {
			operands = splitOperands(operandStr)
		}

		// Check if this is a jump/branch instruction
		isJump, isBranch := isJumpOrBranch(name)

		instructions = append(instructions, &PatchedInstruction{
			Address:  uint32(address),
			Name:     name,
			Operands: operands,
			IsJump:   isJump,
			IsBranch: isBranch,
		})
	}

	return instructions, nil
}

// isJumpOrBranch checks if an instruction is a jump or branch
func isJumpOrBranch(name string) (isJump, isBranch bool) {
	switch name {
	case "Jmp", "JmpLong", "LoadConst":
		return true, false
	case "JmpEq", "JmpNeq", "JmpEqLong", "JmpNeqLong",
		"JmpLt", "JmpLte", "JmpGt", "JmpGte",
		"JmpLtLong", "JmpLteLong", "JmpGtLong", "JmpGteLong",
		"JmpStrictEq", "JmpStrictNeq",
		"JmpStrictEqLong", "JmpStrictNeqLong",
		"Call", "Construct", "ConstructWithReceiver",
		"Ret", "Throw", "ThrowIfEmpty", "ThrowIfUndefined",
		"SwitchImm", "Switch":
		return false, true
	}
	return false, false
}

// instInfo tracks instruction information for address recalculation
type instInfo struct {
	inst      *PatchedInstruction
	origSize  int
	newSize   int
	origOff   uint32
	newOff    uint32
	isJump    bool
	targetRef uint32 // original target address
}

// AssembleWithRecalc performs assembly with address recalculation
func (sa *SmartAssembler) AssembleWithRecalc(instructions []*PatchedInstruction) ([]byte, error) {
	// Phase 1: Calculate sizes and track jumps
	var infos []instInfo
	origOffset := uint32(0)

	for _, inst := range instructions {
		def, ok := sa.NameToInst[inst.Name]
		if !ok {
			return nil, fmt.Errorf("unknown instruction: %s at 0x%x", inst.Name, inst.Address)
		}

		// Calculate original size
		origSize := def.Size()

		// Calculate new size based on operands
		newSize := sa.calculateSize(def, inst.Operands)

		info := instInfo{
			inst:     inst,
			origSize: origSize,
			newSize:  newSize,
			origOff:  origOffset,
			isJump:   inst.IsJump || inst.IsBranch,
		}

		// Track jump targets
		if info.isJump && len(inst.Operands) > 0 {
			target := parseOperandSimple(inst.Operands[len(inst.Operands)-1])
			info.targetRef = target
		}

		infos = append(infos, info)
		origOffset += uint32(origSize)
	}

	// Phase 2: Calculate new offsets
	newOffset := uint32(0)
	for i := range infos {
		infos[i].newOff = newOffset
		newOffset += uint32(infos[i].newSize)
	}

	// Phase 3: Build new bytecode with recalculated jumps
	var result []byte

	for i, info := range infos {
		def, _ := sa.NameToInst[info.inst.Name]

		// Build operands with recalculated addresses
		operands := make([]string, len(info.inst.Operands))
		copy(operands, info.inst.Operands)

		// If this is a jump, recalculate the target
		if info.isJump && len(operands) > 0 {
			lastOpIdx := len(operands) - 1
			target := info.targetRef

			// Find the instruction at original target address
			newTarget := sa.findNewTarget(infos, target, i)
			if newTarget >= 0 {
				operands[lastOpIdx] = fmt.Sprintf("0x%x", infos[newTarget].newOff)
			}
		}

		// Assemble the instruction
		bytes, err := sa.assembleInstruction(def, operands)
		if err != nil {
			return nil, fmt.Errorf("error at 0x%x: %v", info.origOff, err)
		}

		// Pad to correct size
		for len(bytes) < info.newSize {
			bytes = append(bytes, 0)
		}

		result = append(result, bytes...)
	}

	return result, nil
}

// findNewTarget finds the index of instruction that was at originalTarget
func (sa *SmartAssembler) findNewTarget(infos []instInfo, originalTarget uint32, currentIdx int) int {
	// Special case: if target is 0, it's likely a null target
	if originalTarget == 0 {
		return -1
	}

	// Find instruction that was at originalTarget
	for j, info := range infos {
		if info.origOff == originalTarget {
			return j
		}
	}

	// If not found, find the closest instruction after target
	for j, info := range infos {
		if info.origOff > originalTarget {
			return j - 1
		}
	}

	return len(infos) - 1
}

// calculateSize calculates the size of an instruction
func (sa *SmartAssembler) calculateSize(def *InstructionDef, operands []string) int {
	size := def.Size()
	return size
}

// assembleInstruction assembles a single instruction
func (sa *SmartAssembler) assembleInstruction(inst *InstructionDef, operands []string) ([]byte, error) {
	if len(operands) > len(inst.Operands) {
		return nil, fmt.Errorf("too many operands: got %d, expected %d", len(operands), len(inst.Operands))
	}

	result := []byte{byte(inst.Opcode)}

	for i, opType := range inst.Operands {
		var value uint64
		if i < len(operands) {
			var err error
			value, err = parseOperand(operands[i], opType)
			if err != nil {
				return nil, fmt.Errorf("operand %d: %v", i, err)
			}
		}

		switch opType.Size {
		case 1:
			result = append(result, byte(value))
		case 2:
			result = append(result, byte(value), byte(value>>8))
		case 4:
			result = append(result, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
		case 8:
			for j := 0; j < 8; j++ {
				result = append(result, byte(value>>(uint(j)*8)))
			}
		}
	}

	return result, nil
}

// parseOperandSimple parses an operand without type info
func parseOperandSimple(s string) uint32 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	// Handle hex values
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, _ := strconv.ParseUint(s[2:], 16, 32)
		return uint32(val)
	}

	// Handle plain hex
	if isHexString(s) {
		val, _ := strconv.ParseUint(s, 16, 32)
		return uint32(val)
	}

	// Handle register (r0, r1, etc.)
	if strings.HasPrefix(s, "r") || strings.HasPrefix(s, "R") {
		val, _ := strconv.ParseUint(s[1:], 10, 32)
		return uint32(val)
	}

	// Handle decimal
	val, _ := strconv.ParseUint(s, 10, 32)
	return uint32(val)
}

// PatchFile patches an HBC file from a simplified .hasm file
func (sa *SmartAssembler) PatchFile(inputPath, hasmPath, outputPath string) error {
	// Parse HBC file
	hbc, err := ParseFile(inputPath)
	if err != nil {
		return fmt.Errorf("parsing HBC: %v", err)
	}

	// Parse simplified HASM
	instructions, err := sa.ParseSimple(hasmPath)
	if err != nil {
		return fmt.Errorf("parsing HASM: %v", err)
	}

	// Group instructions by function
	funcGroups := make(map[int][]*PatchedInstruction)
	for _, inst := range instructions {
		// Find which function this belongs to
		funcIdx := sa.findFunction(hbc, inst.Address)
		funcGroups[funcIdx] = append(funcGroups[funcIdx], inst)
	}

	// Patch each function
	for funcIdx, funcInsts := range funcGroups {
		if funcIdx < 0 || funcIdx >= len(hbc.FunctionHeaders) {
			continue
		}

		newBytecode, err := sa.AssembleWithRecalc(funcInsts)
		if err != nil {
			return fmt.Errorf("assembling function %d: %v", funcIdx, err)
		}

		// Update function bytecode
		if err := hbc.SetCode(funcIdx, newBytecode); err != nil {
			return fmt.Errorf("setting bytecode for function %d: %v", funcIdx, err)
		}
	}

	// Write patched file
	return hbc.Write(outputPath)
}

// findFunction finds which function contains the given address
func (sa *SmartAssembler) findFunction(hbc *HBCFile, addr uint32) int {
	for i := range hbc.FunctionHeaders {
		code := hbc.getCode(i)
		if addr >= 0 && addr < uint32(len(code)) {
			// Check if address is within this function's bytecode
			offset := uint32(0)
			for offset < uint32(len(code)) {
				if offset == addr {
					return i
				}
				remaining := code[offset:]
				pi := decodeInstruction(remaining, offset, sa.Table)
				offset = pi.NextOffset
			}
		}
	}
	return -1
}
