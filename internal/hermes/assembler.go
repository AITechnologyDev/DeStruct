package hermes

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unsafe"
)

// Assembler converts HASM back to bytecode
type Assembler struct {
	Table      map[byte]*InstructionDef
	NameToInst map[string]*InstructionDef
}

// AssembledInstruction is a parsed instruction from HASM
type AssembledInstruction struct {
	Offset   uint32
	HexBytes string
	Name     string
	Operands []string
	Raw      string
}

func NewAssembler() *Assembler {
	table := buildOpcodeTable99()
	nameToInst := make(map[string]*InstructionDef)
	for _, inst := range table {
		nameToInst[inst.Name] = inst
	}
	return &Assembler{
		Table:      table,
		NameToInst: nameToInst,
	}
}

// ParseHASM parses a .hasm file
func (a *Assembler) ParseHASM(filename string) ([]*AssembledInstruction, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var instructions []*AssembledInstruction
	scanner := bufio.NewScanner(f)
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

func splitOperands(s string) []string {
	var result []string
	depth := 0
	current := ""

	for _, ch := range s {
		switch ch {
		case '(':
			depth++
			current += string(ch)
		case ')':
			depth--
			current += string(ch)
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(current))
				current = ""
			} else {
				current += string(ch)
			}
		default:
			current += string(ch)
		}
	}
	if current != "" {
		result = append(result, strings.TrimSpace(current))
	}
	return result
}

// Assemble converts instructions to bytecode
func (a *Assembler) Assemble(instructions []*AssembledInstruction) ([]byte, []string) {
	var bytecode []byte
	var errors []string

	for _, instr := range instructions {
		inst, ok := a.NameToInst[instr.Name]
		if !ok {
			errors = append(errors, fmt.Sprintf("unknown instruction: %s at 0x%x", instr.Name, instr.Offset))
			continue
		}

		bytes, err := a.assembleInstruction(inst, instr.Operands)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error %s: %v", instr.Name, err))
			continue
		}

		// Pad to correct size
		for len(bytes) < inst.Size() {
			bytes = append(bytes, 0)
		}
		bytecode = append(bytecode, bytes...)
	}

	return bytecode, errors
}

func (a *Assembler) assembleInstruction(inst *InstructionDef, operands []string) ([]byte, error) {
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

func parseOperand(s string, opType OperandType) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	// Handle register operands (r0, r1, etc.)
	if strings.HasPrefix(s, "r") || strings.HasPrefix(s, "R") {
		return strconv.ParseUint(s[1:], 10, 32)
	}

	// Handle float operands (for Double type)
	if opType.Name == "Double" {
		val, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, err
		}
		// Convert float64 to uint64 bits
		bits := uint64(0)
		ptr := &bits
		*(*float64)(unsafe.Pointer(ptr)) = val
		return bits, nil
	}

	// Handle hex values (0x prefix or plain hex like 0000004a)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}

	// Handle plain hex (no prefix, but all hex chars)
	if isHexString(s) {
		val, err := strconv.ParseUint(s, 16, 64)
		if err == nil {
			return val, nil
		}
	}

	// Handle binary values
	if strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B") {
		return strconv.ParseUint(s[2:], 2, 64)
	}

	// Handle decimal values (possibly negative for signed operands)
	if opType.IsSigned {
		val, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return uint64(val), nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// isHexString checks if a string is valid hex
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
