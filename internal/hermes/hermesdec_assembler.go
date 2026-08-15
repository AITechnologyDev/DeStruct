package hermes

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// =============================================================================
// This file implements an assembler for the EXACT hermes-dec text format
// produced by DisassembleFunctionExact/FormatHermesDec in hermesdec.go -
// as opposed to assembler.go/smart_assembler.go, which read the older,
// simplified "-p" format. It is meant to close the loop with that exact
// disassembler: disassemble, edit the .hasm text, reassemble.
//
// Because the exact-format text references string_id/function_id/bigint_id
// indices into tables that live in the surrounding .hbc file (the text
// itself never contains the actual string/literal data - only the index,
// plus a human-readable comment that is not authoritative), this
// assembler always operates as a PATCH against an existing, already-
// parsed *HBCFile: it can change which bytecode instructions a function
// contains, but not introduce new strings/literals/functions that don't
// already exist in the file's tables.
//
// Scope of this first version: UIntSwitchImm/StringSwitchImm's inline
// jump table (addressed separately from the instruction stream itself)
// is not recalculated when a function's size changes. Patching a function
// containing one of those instructions where the size changes is
// rejected with an explicit error rather than silently producing a
// corrupt jump table; patching such a function with no size change (a
// pure operand-value edit) works normally.
// =============================================================================

// HermesDecAssembler assembles/patches .hbc files using the exact
// hermes-dec text format.
type HermesDecAssembler struct {
	File       *HBCFile
	Table      map[byte]*InstructionDef
	NameToInst map[string]*InstructionDef
}

// NewHermesDecAssembler creates an assembler bound to an already-parsed
// HBC file, using the opcode table for that file's actual bytecode
// version (see buildOpcodeTableForVersion) rather than a fixed version -
// assembling with the wrong table would silently produce instructions
// with the wrong opcode numbers or operand sizes for this file.
func NewHermesDecAssembler(file *HBCFile) *HermesDecAssembler {
	table := buildOpcodeTableForVersion(file.Header.Version)
	nameToInst := make(map[string]*InstructionDef)
	for _, inst := range table {
		nameToInst[inst.Name] = inst
	}
	return &HermesDecAssembler{
		File:       file,
		Table:      table,
		NameToInst: nameToInst,
	}
}

// -----------------------------------------------------------------------
// Text parsing
// -----------------------------------------------------------------------

// hasmInstruction is one parsed "==> ..." line, before any address
// recalculation: the instruction name and its raw operand values exactly
// as written in the text (Addr operands are still the original
// relative-to-this-instruction offsets from the source text, not yet
// adjusted for any size change).
type hasmInstruction struct {
	LineNo   int
	Name     string
	Operands []hasmOperand
	// Offset is this instruction's real byte position within its
	// function's CURRENT (pre-edit) bytecode, valid only for
	// instructions produced by currentFunctionInstructions (decoded
	// straight from the file). Zero/unused for instructions parsed from
	// .hasm text, since their real post-edit position isn't known until
	// the whole function's layout is resolved - see
	// assembleFunctionBytecode's use of alignment against
	// currentFunctionInstructions instead of this field for those.
	Offset uint32
	// SwitchCases holds UIntSwitchImm's jump table entries, parsed from
	// the "    case N: XXXXXXXX" lines that follow it in the text (see
	// switchCaseLineRe). Empty/nil for every other instruction, and for
	// UIntSwitchImm instructions decoded directly from the current file
	// (see currentFunctionInstructions, which fills in JumpTargetOffsets
	// instead - the two are compared during diffing/alignment via
	// switchTargetsText, not by comparing this field directly).
	SwitchCases []switchCaseEntry
}

// switchCaseEntry is one parsed "    case N: XXXXXXXX" line: the case
// index (informational/for validation only - the ORDER of these lines is
// what actually maps to the jump table's [lo, hi] range) and the target
// instruction's function-relative byte offset text, exactly as printed
// in a "# Jump table: [...]" entry.
type switchCaseEntry struct {
	LineNo    int
	CaseIndex int
	TargetHex string
}

type hasmOperand struct {
	// TypeLabel is the text before ':' inside the <...> (e.g. "Reg8",
	// "Addr8", "string_id"). Used only for validation, not for deciding
	// how to parse Value - that comes from the matching InstructionDef.
	TypeLabel string
	// Value is the raw numeric text after ':'.
	Value string
	LineNo int
}

// hasmFunction is one parsed function section from the .hasm text: its
// declared index (from "Function #N") and its instructions in order.
type hasmFunction struct {
	Index        int
	Instructions []hasmInstruction
}

var (
	funcHeaderRe     = regexp.MustCompile(`^=> \[.+ #(\d+) "`)
	instLineRe       = regexp.MustCompile(`^==> [0-9a-fA-F]{8}: <([A-Za-z0-9_]+)>: <(.*?)>`)
	switchCaseLineRe = regexp.MustCompile(`^\s{4}case (\d+): ([0-9a-fA-F]{8})\s*$`)
)

// ParseHermesDecHASM parses the exact hermes-dec text format (as produced
// by DisassembleAllExact/DisassembleFunctionExact) into a list of
// per-function instruction lists. Comments (anything from the first
// "  # " onward on an instruction line, and the exception-handler/debug-
// offset annotations on function header lines) are recognized only
// enough to be skipped; they carry no authority over what gets assembled.
func ParseHermesDecHASM(path string) ([]hasmFunction, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseHermesDecHASM(f)
}

func parseHermesDecHASM(r io.Reader) ([]hasmFunction, error) {
	var funcs []hasmFunction
	var cur *hasmFunction

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // allow long comment lines
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if m := funcHeaderRe.FindStringSubmatch(line); m != nil {
			idx, _ := strconv.Atoi(m[1])
			funcs = append(funcs, hasmFunction{Index: idx})
			cur = &funcs[len(funcs)-1]
			continue
		}

		if m := switchCaseLineRe.FindStringSubmatch(line); m != nil {
			if cur == nil || len(cur.Instructions) == 0 {
				return nil, fmt.Errorf("line %d: switch case line before any instruction", lineNo)
			}
			last := &cur.Instructions[len(cur.Instructions)-1]
			if last.Name != "UIntSwitchImm" {
				return nil, fmt.Errorf("line %d: switch case line follows a %s, not a UIntSwitchImm", lineNo, last.Name)
			}
			caseIdx, _ := strconv.Atoi(m[1])
			last.SwitchCases = append(last.SwitchCases, switchCaseEntry{
				LineNo:    lineNo,
				CaseIndex: caseIdx,
				TargetHex: m[2],
			})
			continue
		}

		if !strings.HasPrefix(line, "==> ") {
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("line %d: instruction line before any function header", lineNo)
		}

		m := instLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("line %d: malformed instruction line: %s", lineNo, line)
		}
		name := m[1]
		operandsText := m[2]

		operands, err := parseOperandList(operandsText, lineNo)
		if err != nil {
			return nil, err
		}

		cur.Instructions = append(cur.Instructions, hasmInstruction{
			LineNo:   lineNo,
			Name:     name,
			Operands: operands,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading HASM: %w", err)
	}

	return funcs, nil
}

// parseOperandList parses the comma-separated "Type: value" list inside
// the <...> following an instruction name. Empty (no operands) is valid.
func parseOperandList(s string, lineNo int) ([]hasmOperand, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := splitTopLevelCommas(s)
	operands := make([]hasmOperand, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		idx := strings.Index(p, ":")
		if idx < 0 {
			return nil, fmt.Errorf("line %d: malformed operand %q (expected \"Type: value\")", lineNo, p)
		}
		typeLabel := strings.TrimSpace(p[:idx])
		value := strings.TrimSpace(p[idx+1:])
		operands = append(operands, hasmOperand{TypeLabel: typeLabel, Value: value, LineNo: lineNo})
	}
	return operands, nil
}

// splitTopLevelCommas splits on ", " without needing to be comment-aware
// (the caller has already stripped everything from the first "  # "
// onward via instLineRe only capturing up to the matching '>'), so this
// only needs to handle the operand text itself. Operand values in this
// format are always plain numbers, so a simple split is sufficient - no
// operand value ever legitimately contains a comma.
func splitTopLevelCommas(s string) []string {
	return strings.Split(s, ", ")
}

// -----------------------------------------------------------------------
// Diffing against the current file
// -----------------------------------------------------------------------

// changedFunctions disassembles each function currently in f using the
// exact same formatter the .hasm was presumably produced by
// (FormatHermesDec), and compares it line-by-line against the
// corresponding section of parsed .hasm functions. Returns the indices
// of functions whose text differs, in ascending order. Functions present
// in the .hasm but identical to the current file's disassembly are left
// alone entirely - their bytecode is never touched, which matters for
// performance on files with many thousands of functions where only a
// handful were actually edited.
func (a *HermesDecAssembler) changedFunctions(hasmFuncs []hasmFunction) ([]int, error) {
	d := &Disassembler{File: a.File, Table: a.Table}

	var changed []int
	for _, hf := range hasmFuncs {
		if hf.Index < 0 || hf.Index >= len(a.File.FunctionHeaders) {
			return nil, fmt.Errorf("function #%d in HASM does not exist in this file (file has %d functions)", hf.Index, len(a.File.FunctionHeaders))
		}

		current := currentFunctionInstructions(d, hf.Index)
		if !instructionsEqual(current, hf.Instructions) {
			changed = append(changed, hf.Index)
		}
	}
	return changed, nil
}

// currentFunctionInstructions decodes funcIdx's current bytecode into the
// same hasmInstruction shape the text parser produces, so the two can be
// compared directly without going through text formatting/parsing twice.
func currentFunctionInstructions(d *Disassembler, funcIdx int) []hasmInstruction {
	code := d.File.getCode(funcIdx)
	fileBase := d.File.FunctionHeaders[funcIdx].Offset
	var out []hasmInstruction
	offset := uint32(0)
	for offset < uint32(len(code)) {
		pi := decodeInstructionFull(code, offset, d.Table, d.File.rawData, fileBase)
		if pi == nil || pi.Inst == nil {
			break
		}
		hi := parsedInstructionToHasm(pi)
		hi.Offset = offset
		if pi.Inst.Name == "UIntSwitchImm" && len(pi.JumpTable) > 0 {
			hi.SwitchCases = make([]switchCaseEntry, len(pi.JumpTable))
			for i, target := range pi.JumpTable {
				hi.SwitchCases[i] = switchCaseEntry{
					CaseIndex: i,
					TargetHex: fmt.Sprintf("%08x", target),
				}
			}
		}
		out = append(out, hi)
		if pi.NextOffset <= offset {
			break
		}
		offset = pi.NextOffset
	}
	return out
}

// parsedInstructionToHasm converts an already-decoded *ParsedInstruction
// into the same hasmInstruction shape the text parser produces, using
// the RAW operand values (Addr operands stay as their original relative
// offsets, not resolved absolute targets) so it compares equal to a
// freshly-parsed, unedited .hasm section for the same function.
func parsedInstructionToHasm(pi *ParsedInstruction) hasmInstruction {
	operands := make([]hasmOperand, len(pi.Inst.Operands))
	for i, op := range pi.Inst.Operands {
		var arg uint64
		if i < len(pi.Args) {
			arg = pi.Args[i]
		}
		operands[i] = hasmOperand{
			TypeLabel: op.Name,
			Value:     operandValueString(pi, i, arg),
		}
	}
	return hasmInstruction{Name: pi.Inst.Name, Operands: operands}
}

// instructionsEqual compares two instruction lists by name and operand
// value only (line numbers and type labels are not authoritative/not
// meaningful for equality).
func instructionsEqual(a, b []hasmInstruction) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return false
		}
		if len(a[i].Operands) != len(b[i].Operands) {
			return false
		}
		for j := range a[i].Operands {
			if a[i].Operands[j].Value != b[i].Operands[j].Value {
				return false
			}
		}
		// Only compare switch case targets when BOTH sides actually have
		// case lines present. b (the edited/.hasm side) having none is
		// the normal case for text produced by the default (non-
		// editable) disassembly format, and means "this switch wasn't
		// touched through the case-line mechanism," not "its jump table
		// became empty" - conflating the two would flag every function
		// containing a UIntSwitchImm as changed merely because the text
		// it's being compared against never had case lines to begin
		// with.
		if len(b[i].SwitchCases) == 0 {
			continue
		}
		if len(a[i].SwitchCases) != len(b[i].SwitchCases) {
			return false
		}
		for j := range a[i].SwitchCases {
			if a[i].SwitchCases[j].TargetHex != b[i].SwitchCases[j].TargetHex {
				return false
			}
		}
	}
	return true
}

// oneInstructionEqual compares a single pair of instructions for LCS
// alignment purposes: same name and same NON-ADDRESS operand values.
// Address operand values are deliberately excluded from this comparison:
// they're always resolved relative to the instruction's real position in
// the current file (see assembleFunctionBytecode), so a person hand-
// editing just the numeric value of an address operand - to retarget a
// branch without touching anything else about it - should still have
// that instruction recognized as "the same instruction" for alignment
// purposes, not treated as an unresolvable new insertion merely because
// one number differs.
func (a *HermesDecAssembler) oneInstructionEqual(x, y hasmInstruction) bool {
	if x.Name != y.Name || len(x.Operands) != len(y.Operands) {
		return false
	}
	def, ok := a.NameToInst[x.Name]
	for i := range x.Operands {
		if ok && i < len(def.Operands) && def.Operands[i].IsAddr {
			continue
		}
		if x.Operands[i].Value != y.Operands[i].Value {
			return false
		}
	}
	return true
}

// alignInstructions computes, for each instruction in edited (the parsed
// .hasm text for one function, possibly with instructions inserted,
// removed, or changed relative to current), the index into current (that
// function's real, already-decoded bytecode) of the SAME instruction, if
// it survived unedited - or -1 if this edited-list entry is new/changed
// and has no such counterpart.
//
// This uses the standard longest-common-subsequence algorithm, treating
// each list as a sequence of "tokens" (instructions compared by name +
// operand text via oneInstructionEqual) and finding the longest ordered
// subsequence common to both. This is the same class of algorithm behind
// tools like `diff`: it correctly handles insertions and deletions
// anywhere in the function, not just at the edited point, and - crucially
// for Addr operand resolution - it never matches an edited-list
// instruction to more than one current-list instruction (or vice versa)
// out of order, so "this Jmp is the same Jmp as before" and "this Jmp is
// a newly-inserted, coincidentally-identical-looking Jmp" are correctly
// told apart based on their surrounding context.
//
// Why this matters: an Addr operand's value in the .hasm text is only
// meaningful relative to the layout current describes (that's the layout
// the disassembler that produced the text was looking at). Once
// instructions are inserted or removed, that same numeric value no
// longer reliably identifies the same target instruction by arithmetic
// alone - resolving "which current instruction did this branch originally
// target" and then "where did that instruction end up in the edited
// list" is what stays correct regardless of how much was inserted or
// removed between a branch and its target.
func (a *HermesDecAssembler) alignInstructions(current, edited []hasmInstruction) []int {
	n, m := len(current), len(edited)
	result := make([]int, m)
	for j := range result {
		result[j] = -1
	}

	// Strip the common prefix and suffix first (O(n)): in any real edit,
	// the vast majority of a function's instructions are unchanged and
	// live in one of these two regions, however large the function is.
	// Only the (usually small) middle region that actually differs needs
	// the expensive O(n*m) LCS below - this keeps memory and time
	// bounded by the SIZE OF THE EDIT, not the size of the function.
	prefix := 0
	for prefix < n && prefix < m && a.oneInstructionEqual(current[prefix], edited[prefix]) {
		result[prefix] = prefix
		prefix++
	}

	suffix := 0
	for suffix < n-prefix && suffix < m-prefix &&
		a.oneInstructionEqual(current[n-1-suffix], edited[m-1-suffix]) {
		result[m-1-suffix] = n - 1 - suffix
		suffix++
	}

	curMid := current[prefix : n-suffix]
	editMid := edited[prefix : m-suffix]

	const maxLCSCells = 50_000_000 // ~200MB of int32 at 4 bytes each
	if int64(len(curMid)+1)*int64(len(editMid)+1) > maxLCSCells {
		// Too large to LCS-align without excessive memory: keep the
		// prefix/suffix matches already found above, leave the middle
		// region's entries as -1 (unresolved). assembleFunctionBytecode
		// only needs a resolved target for instructions that are
		// THEMSELVES Addr operands or the target of one; an edit large
		// enough to hit this limit is already far outside normal usage.
		return result
	}

	midResult := a.lcsAlign(curMid, editMid)
	for j, idx := range midResult {
		if idx >= 0 {
			result[prefix+j] = prefix + idx
		}
	}

	return result
}

// lcsAlign is the actual O(n*m)-time, O(n*m)-memory LCS alignment,
// applied by alignInstructions only to the (normally small) region
// remaining after stripping the common prefix/suffix.
func (a *HermesDecAssembler) lcsAlign(current, edited []hasmInstruction) []int {
	n, m := len(current), len(edited)

	// dp[i][j] = length of the LCS of current[:i] and edited[:j].
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a.oneInstructionEqual(current[i-1], edited[j-1]) {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	result := make([]int, m)
	for j := range result {
		result[j] = -1
	}

	i, j := n, m
	for i > 0 && j > 0 {
		if a.oneInstructionEqual(current[i-1], edited[j-1]) {
			result[j-1] = i - 1
			i--
			j--
			continue
		}
		if dp[i-1][j] >= dp[i][j-1] {
			i--
		} else {
			j--
		}
	}

	return result
}

// -----------------------------------------------------------------------
// Operand value encoding (text -> the raw uint64 bit pattern
// decodeInstruction would have produced, so it can be written back out
// with the same little-endian byte encoding logic used everywhere else
// in this package).
// -----------------------------------------------------------------------

// parseOperandValue parses one operand's text value into the raw uint64
// bit pattern for its declared type: for Double, the IEEE-754 bits of the
// parsed float; for signed integer types, the two's-complement bit
// pattern truncated to the operand's byte size; for unsigned types, the
// value itself.
func parseOperandValue(text string, op OperandType) (uint64, error) {
	if op.Name == "Double" {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid Double value %q: %w", text, err)
		}
		return math.Float64bits(f), nil
	}
	if op.IsSigned {
		v, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid signed value %q: %w", text, err)
		}
		switch op.Size {
		case 1:
			if v < math.MinInt8 || v > math.MaxInt8 {
				return 0, fmt.Errorf("value %d out of range for %s (int8)", v, op.Name)
			}
			return uint64(uint8(int8(v))), nil
		case 2:
			if v < math.MinInt16 || v > math.MaxInt16 {
				return 0, fmt.Errorf("value %d out of range for %s (int16)", v, op.Name)
			}
			return uint64(uint16(int16(v))), nil
		case 4:
			if v < math.MinInt32 || v > math.MaxInt32 {
				return 0, fmt.Errorf("value %d out of range for %s (int32)", v, op.Name)
			}
			return uint64(uint32(int32(v))), nil
		default:
			return uint64(v), nil
		}
	}
	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid unsigned value %q: %w", text, err)
	}
	maxVal := uint64(1)<<(uint(op.Size)*8) - 1
	if op.Size >= 8 {
		maxVal = math.MaxUint64
	}
	if v > maxVal {
		return 0, fmt.Errorf("value %d out of range for %s (%d bytes)", v, op.Name, op.Size)
	}
	return v, nil
}

// encodeOperand appends the little-endian byte encoding of value
// (already the raw bit pattern from parseOperandValue) for the given
// operand type.
func encodeOperand(buf *bytes.Buffer, op OperandType, value uint64) {
	switch op.Size {
	case 1:
		buf.WriteByte(byte(value))
	case 2:
		var b [2]byte
		b[0] = byte(value)
		b[1] = byte(value >> 8)
		buf.Write(b[:])
	case 4:
		var b [4]byte
		b[0] = byte(value)
		b[1] = byte(value >> 8)
		b[2] = byte(value >> 16)
		b[3] = byte(value >> 24)
		buf.Write(b[:])
	case 8:
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(value >> (uint(i) * 8))
		}
		buf.Write(b[:])
	}
}

// -----------------------------------------------------------------------
// Per-function reassembly with iterative fixed-point address
// recalculation.
// -----------------------------------------------------------------------

// asmLink is one instruction being assembled for a single function: its
// resolved *InstructionDef, its operand values (as raw bit patterns,
// EXCEPT for Addr operands - see below), and (once known) its offset
// within the function and encoded size.
type asmLink struct {
	Inst        *InstructionDef
	Values      []uint64 // raw bit patterns, except Addr operands hold the ORIGINAL text's relative offset until recalculated
	Offset      uint32   // filled in during layout
	LineNo      int
	SwitchCases []switchCaseEntry // UIntSwitchImm's jump table entries, if any (see hasmInstruction.SwitchCases)
}

// effectiveSize returns this link's actual encoded byte size: the normal
// declared-operand size for every instruction, plus - for UIntSwitchImm
// specifically - the 4-byte-aligned padding and 4-byte-per-entry jump
// table that follows it. fileBase is the absolute file offset this
// function's bytecode starts at (hdr.Offset); alignment is computed
// against the absolute file position of the byte right after this
// instruction's normal operands, mirroring real hermes-dec's own
// align_over_padding() call before it reads/writes a switch's jump
// table.
// switchTableToPlace describes one UIntSwitchImm's jump table that still
// needs to be physically placed in the file, deferred until after
// patchOneFunction's main splice (which is the point at which this
// function's final absolute file offset becomes known - needed to
// compute arg2, the byte distance from the instruction to the table).
type switchTableToPlace struct {
	// Arg2Offset is the byte offset, within the function's own encoded
	// bytecode ([]byte returned by assembleFunctionBytecode), of the
	// 4-byte arg2 field that must be overwritten with the table's actual
	// relative offset once its final position is known.
	Arg2Offset int
	// InstFuncOffset is this UIntSwitchImm's own byte offset within the
	// function's encoded bytecode (needed to compute arg2 = table
	// position - instruction position).
	InstFuncOffset int
	// TableBytes is the table's fully-encoded content (4 bytes per
	// entry, each a delta relative to InstFuncOffset - already
	// resolved, nothing left to patch in these bytes themselves).
	TableBytes []byte
}

// assembleFunctionBytecode turns one hasmFunction's parsed instructions
// into final bytecode bytes, running an iterative fixed-point pass to
// keep every Addr8/Addr32 branch operand correct even if instructions
// were added, removed, or changed size relative to what originally
// produced this function's .hasm text.
//
// The pass works because Addr operands in the *source text* are, by
// construction of the exact hermes-dec format, the offset from the
// branch instruction to its target INSTRUCTION (not to an arbitrary
// byte). So the very first thing done here is resolve each Addr operand's
// original text value into which *instruction index* it targets (by
// walking the original layout implied by the still-unedited addresses),
// and from then on, addresses are always recomputed as
// target_instruction.Offset - this_instruction.Offset, using each pass's
// current (possibly still wrong, but improving) offsets - never by
// reusing the raw text number after the first pass.
func (a *HermesDecAssembler) assembleFunctionBytecode(hf hasmFunction) ([]byte, []switchTableToPlace, error) {
	links := make([]asmLink, len(hf.Instructions))
	for i, hi := range hf.Instructions {
		def, ok := a.NameToInst[hi.Name]
		if !ok {
			return nil, nil, fmt.Errorf("line %d: unknown instruction %q for this file's bytecode version", hi.LineNo, hi.Name)
		}
		if def.Name == "StringSwitchImm" {
			return nil, nil, fmt.Errorf("line %d: %s is not supported by the assembler (it never produces a real jump table even in the real hermes-dec reference, so there is nothing meaningful to reassemble)", hi.LineNo, def.Name)
		}
		if len(hi.Operands) != len(def.Operands) {
			return nil, nil, fmt.Errorf("line %d: %s expects %d operands, got %d", hi.LineNo, hi.Name, len(def.Operands), len(hi.Operands))
		}

		values := make([]uint64, len(def.Operands))
		for j, op := range def.Operands {
			text := hi.Operands[j].Value
			if op.IsAddr {
				// Keep the raw signed text value for now; resolved to a
				// target instruction index just below, once all links
				// exist.
				v, err := strconv.ParseInt(text, 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("line %d: invalid address operand %q: %w", hi.LineNo, text, err)
				}
				values[j] = uint64(v)
				continue
			}
			v, err := parseOperandValue(text, op)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d: operand %d of %s: %w", hi.LineNo, j, hi.Name, err)
			}
			values[j] = v
		}
		links[i] = asmLink{Inst: def, Values: values, LineNo: hi.LineNo, SwitchCases: hi.SwitchCases}
	}

	// Resolve each Addr operand's target instruction. The text's numeric
	// Addr value is only meaningful relative to the layout it was
	// disassembled from - the function's CURRENT (pre-edit) bytecode -
	// not the edited instruction list, which may have a different number
	// of instructions between the branch and its target than the
	// original did. So: decode the current bytecode to get its real
	// per-instruction byte offsets, resolve each Addr operand against
	// THAT layout to find which current instruction it targets, then use
	// alignInstructions (LCS against the edited list) to find where that
	// same instruction ended up after the edit. This stays correct
	// regardless of how many instructions were inserted or removed
	// between a branch and its target - see alignInstructions' doc
	// comment for why arithmetic alone over the edited text can't do
	// this once instructions have been added or removed anywhere in the
	// function.
	d := &Disassembler{File: a.File, Table: a.Table}
	current := currentFunctionInstructions(d, hf.Index)
	currentOffsets := make([]uint32, len(current))
	for i, ci := range current {
		currentOffsets[i] = ci.Offset
	}
	alignment := a.alignInstructions(current, hf.Instructions) // alignment[editedIdx] = currentIdx, or -1

	// Reverse index: currentIdx -> editedIdx, built once rather than
	// linearly scanned per Addr operand below.
	editedIdxOfCurrent := make(map[int]int, len(current))
	for editedIdx, curIdx := range alignment {
		if curIdx >= 0 {
			editedIdxOfCurrent[curIdx] = editedIdx
		}
	}

	targetIdx := make([][]int, len(links)) // targetIdx[i][k] = instruction index (in the EDITED list) that operand k of instruction i targets, or -1 if not an Addr operand
	for i := range links {
		targetIdx[i] = make([]int, len(links[i].Values))
		for j, op := range links[i].Inst.Operands {
			if !op.IsAddr {
				targetIdx[i][j] = -1
				continue
			}

			curIdx := alignment[i]
			if curIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: this %s was inserted or changed, so its address operand can't be resolved against the file's current layout - address operands can only be edited by changing the VALUE on an unchanged instruction, not by introducing a new branch instruction with a hand-written address; insert an unconditional jump structure via existing instructions instead", links[i].LineNo, links[i].Inst.Name)
			}

			relOffset := int32(links[i].Values[j])
			targetByteOffset := int64(currentOffsets[curIdx]) + int64(relOffset)
			curTargetIdx := findInstructionIndexAtOffset(currentOffsets, targetByteOffset)
			if curTargetIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: address operand targets byte offset %d in the current file, which is not the start of any instruction in this function", links[i].LineNo, targetByteOffset)
			}

			editedTargetIdx, ok := editedIdxOfCurrent[curTargetIdx]
			if !ok {
				return nil, nil, fmt.Errorf("line %d: this %s's target instruction was removed by this edit; a branch's target must still exist somewhere in the edited function", links[i].LineNo, links[i].Inst.Name)
			}

			targetIdx[i][j] = editedTargetIdx
		}
	}

	// Resolve UIntSwitchImm jump table case targets the same way: each
	// "case N: XXXXXXXX" line's target is a function-relative byte offset
	// in the CURRENT file (that's what DisassembleFunctionExactEditable
	// printed it as), so it's resolved against currentOffsets and mapped
	// through the same alignment to find its position in the edited list.
	switchTargetIdx := make([][]int, len(links)) // switchTargetIdx[i][k] = instruction index (in the EDITED list) that case k of instruction i targets, or nil if instruction i has no switch cases
	for i := range links {
		if links[i].Inst.Name != "UIntSwitchImm" {
			continue
		}
		cases := hf.Instructions[i].SwitchCases
		curIdx := alignment[i]

		if len(cases) == 0 {
			// No case lines in the text: not edited through this
			// mechanism (the normal situation for text produced by the
			// default, non-editable disassembly format). Fall back to
			// this UIntSwitchImm's EXISTING jump table from the current
			// file, if it survived the edit unchanged - there is
			// otherwise no source of truth for what its table should
			// contain.
			if curIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: this UIntSwitchImm is new or was changed by this edit, so it needs explicit \"    case N: XXXXXXXX\" lines for its jump table (produced by DisassembleFunctionExactEditable) - it has no existing table to fall back to", links[i].LineNo)
			}
			existing := current[curIdx].SwitchCases
			if len(existing) == 0 {
				continue // genuinely an empty table (lo > hi) - nothing to resolve
			}
			resolved := make([]int, len(existing))
			for k, c := range existing {
				curTargetIdx := findInstructionIndexAtOffset(currentOffsets, mustParseHex(c.TargetHex))
				if curTargetIdx < 0 {
					return nil, nil, fmt.Errorf("line %d: this UIntSwitchImm's existing case %d target %s is not the start of any instruction in the current file (this should not happen; please report this as a bug)", links[i].LineNo, k, c.TargetHex)
				}
				editedTargetIdx, ok := editedIdxOfCurrent[curTargetIdx]
				if !ok {
					return nil, nil, fmt.Errorf("line %d: this UIntSwitchImm's existing case %d target instruction was removed by this edit; either restore it, or provide explicit \"    case N: XXXXXXXX\" lines retargeting this switch", links[i].LineNo, k)
				}
				resolved[k] = editedTargetIdx
			}
			switchTargetIdx[i] = resolved
			links[i].SwitchCases = existing
			continue
		}

		if curIdx < 0 {
			return nil, nil, fmt.Errorf("line %d: this UIntSwitchImm was inserted or changed, so its jump table's case targets can't be resolved against the file's current layout", links[i].LineNo)
		}

		resolved := make([]int, len(cases))
		for k, c := range cases {
			targetByteOffset, err := strconv.ParseUint(c.TargetHex, 16, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d: invalid case target %q: %w", c.LineNo, c.TargetHex, err)
			}
			curTargetIdx := findInstructionIndexAtOffset(currentOffsets, int64(targetByteOffset))
			if curTargetIdx < 0 {
				return nil, nil, fmt.Errorf("line %d: case target %s is not the start of any instruction in this function's current bytecode", c.LineNo, c.TargetHex)
			}
			editedTargetIdx, ok := editedIdxOfCurrent[curTargetIdx]
			if !ok {
				return nil, nil, fmt.Errorf("line %d: this case's target instruction was removed by this edit; a switch case's target must still exist somewhere in the edited function", c.LineNo)
			}
			resolved[k] = editedTargetIdx
		}
		switchTargetIdx[i] = resolved
	}

	// Iteratively lay out offsets and sizes, promoting any Addr8 branch
	// whose recomputed relative offset no longer fits in a signed byte to
	// its *Long (Addr32) form, until a pass makes no further changes.
	const maxPasses = 64
	changed := true
	for pass := 0; changed; pass++ {
		if pass >= maxPasses {
			return nil, nil, fmt.Errorf("address layout did not converge after %d passes (this should not happen; please report this as a bug)", maxPasses)
		}
		changed = false

		off := uint32(0)
		for i := range links {
			links[i].Offset = off
			off += uint32(links[i].Inst.Size())
		}

		for i := range links {
			for j, op := range links[i].Inst.Operands {
				if !op.IsAddr {
					continue
				}
				tIdx := targetIdx[i][j]
				relOffset := int64(links[tIdx].Offset) - int64(links[i].Offset)

				if op.Size == 1 {
					if relOffset < math.MinInt8 || relOffset > math.MaxInt8 {
						longDef, ok := a.longFormOf(links[i].Inst)
						if !ok {
							return nil, nil, fmt.Errorf("line %d: %s's address no longer fits in a byte after this edit, and it has no *Long form to fall back to", links[i].LineNo, links[i].Inst.Name)
						}
						links[i].Inst = longDef
						// Re-derive values for the new operand list: only
						// the Addr operand's storage size actually
						// changes shape-for-shape between an
						// instruction and its *Long counterpart (this
						// holds for every Addr8/Addr32 pair in the
						// Hermes instruction set - the rest of the
						// operand list is identical).
						changed = true
					}
				}
			}
		}
	}

	// Final encode, now that every instruction has its settled size and
	// every Addr operand's target is known.
	var buf bytes.Buffer
	var tablesToPlace []switchTableToPlace

	for i := range links {
		instFuncOffset := buf.Len()
		buf.WriteByte(byte(links[i].Inst.Opcode))

		isSwitch := links[i].Inst.Name == "UIntSwitchImm" && len(links[i].SwitchCases) > 0
		var arg2Offset int

		for j, op := range links[i].Inst.Operands {
			if isSwitch && j == 1 {
				arg2Offset = buf.Len()
			}
			var v uint64
			switch {
			case isSwitch && j == 1:
				// arg2 depends on where this table ends up getting
				// physically placed, which isn't known until
				// patchOneFunction has done its main splice (this
				// function's own final absolute file offset isn't
				// settled yet). Write a placeholder; recorded below so
				// the real value can be patched in once it is known.
				v = 0
			case op.IsAddr:
				tIdx := targetIdx[i][j]
				rel := int64(links[tIdx].Offset) - int64(links[i].Offset)
				v, _ = parseOperandValue(strconv.FormatInt(rel, 10), op)
			default:
				v = links[i].Values[j]
			}
			encodeOperand(&buf, op, v)
		}

		if isSwitch {
			var tableBuf bytes.Buffer
			for _, tIdx := range switchTargetIdx[i] {
				rel := int64(links[tIdx].Offset) - int64(links[i].Offset)
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], uint32(rel))
				tableBuf.Write(b[:])
			}
			tablesToPlace = append(tablesToPlace, switchTableToPlace{
				Arg2Offset:     arg2Offset,
				InstFuncOffset: instFuncOffset,
				TableBytes:     tableBuf.Bytes(),
			})
		}
	}

	return buf.Bytes(), tablesToPlace, nil
}

// mustParseHex parses an 8-hex-digit string produced by this package's own
// "%08x" formatting (e.g. a switchCaseEntry.TargetHex read back from the
// current file) - always valid by construction, so any error here would
// indicate an internal bug rather than bad input.
func mustParseHex(s string) int64 {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		panic(fmt.Sprintf("internal error: mustParseHex(%q): %v", s, err))
	}
	return int64(v)
}

// findInstructionIndexAtOffset returns the index i such that
// offsets[i] == target, or -1 if no instruction starts exactly there.
func findInstructionIndexAtOffset(offsets []uint32, target int64) int {
	if target < 0 {
		return -1
	}
	for i, off := range offsets {
		if int64(off) == target {
			return i
		}
	}
	return -1
}

// longFormOf returns the *Long counterpart InstructionDef for a
// short-address (Addr8) instruction, by the standard Hermes naming
// convention (append "Long" to the name), if one exists in this file's
// opcode table.
func (a *HermesDecAssembler) longFormOf(short *InstructionDef) (*InstructionDef, bool) {
	long, ok := a.NameToInst[short.Name+"Long"]
	if !ok {
		return nil, false
	}
	// Sanity check: a genuine short/long pair differs only in the size
	// of the Addr operand(s) (Addr8 -> Addr32), never in the number or
	// order of operands - if that's not the case here, "<Name>Long"
	// happens to be an unrelated instruction and must not be used.
	if len(long.Operands) != len(short.Operands) {
		return nil, false
	}
	for i := range short.Operands {
		if short.Operands[i].IsAddr != long.Operands[i].IsAddr {
			return nil, false
		}
		if !short.Operands[i].IsAddr && short.Operands[i] != long.Operands[i] {
			return nil, false
		}
	}
	return long, true
}

// -----------------------------------------------------------------------
// File-level patching.
// -----------------------------------------------------------------------

// AssemblePatchResult summarizes what AssembleAndPatch did, for reporting
// to the person driving this (e.g. from the CLI).
type AssemblePatchResult struct {
	ChangedFunctions []int // function indices whose bytecode was actually replaced
	SizeDelta        int   // net change in total bytecode-segment size, in bytes (can be negative)
}

// AssembleAndPatch reads a .hasm file in the exact hermes-dec text
// format, finds every function whose text differs from what the current
// file would disassemble to, reassembles just those functions' bytecode
// (with full iterative address recalculation - see
// assembleFunctionBytecode), and patches them into the file in place.
//
// This mutates a.File's raw bytes directly; call a.File.Write(path)
// afterward to save the result. It does not touch any function whose
// .hasm text is byte-for-byte identical to the function's current
// disassembly, which matters for performance on files with many
// thousands of functions (such as real-world React Native bundles) where
// typically only a handful were actually edited.
//
// Every function's bytecode is physically packed one after another in
// one contiguous segment of the file. Patching one function's bytecode
// to a different size shifts the position of every OTHER function's
// bytecode that comes after it in the file (not necessarily in function-
// index order - see physicalOrder below), which means every affected
// FunctionHeader.Offset must be updated, and so must the file-level
// Header.DebugInfoOffset (the debug-info section immediately follows the
// whole bytecode segment) and Header.FileLength.
func (a *HermesDecAssembler) AssembleAndPatch(hasmPath string) (*AssemblePatchResult, error) {
	hasmFuncs, err := ParseHermesDecHASM(hasmPath)
	if err != nil {
		return nil, fmt.Errorf("parsing HASM: %w", err)
	}
	return a.assembleAndPatchFuncs(hasmFuncs)
}

// assembleAndPatchFuncs is AssembleAndPatch's actual implementation,
// taking already-parsed hasmFunction values directly rather than a file
// path - this lets other callers within the package (the interactive
// patcher REPL, in particular) reuse the exact same diff/reassemble/
// patch pipeline for a single function's text without needing to write
// it to a temporary file on disk first.
func (a *HermesDecAssembler) assembleAndPatchFuncs(hasmFuncs []hasmFunction) (*AssemblePatchResult, error) {
	changedIdx, err := a.changedFunctions(hasmFuncs)
	if err != nil {
		return nil, err
	}
	if len(changedIdx) == 0 {
		return &AssemblePatchResult{}, nil
	}

	hasmByIndex := make(map[int]hasmFunction, len(hasmFuncs))
	for _, hf := range hasmFuncs {
		hasmByIndex[hf.Index] = hf
	}

	newCode := make(map[int][]byte, len(changedIdx))
	newTables := make(map[int][]switchTableToPlace, len(changedIdx))
	for _, idx := range changedIdx {
		code, tables, err := a.assembleFunctionBytecode(hasmByIndex[idx])
		if err != nil {
			return nil, fmt.Errorf("function #%d: %w", idx, err)
		}
		newCode[idx] = code
		newTables[idx] = tables
	}

	// Apply patches in ascending PHYSICAL offset order (not function
	// index order - the two need not match), so that each patch's
	// effect on the offsets of everything after it is resolved before
	// the next patch is applied.
	order := make([]int, len(changedIdx))
	copy(order, changedIdx)
	sortIntsByOffset(order, a.File)

	changedSet := make(map[int]bool, len(changedIdx))
	for _, idx := range changedIdx {
		changedSet[idx] = true
	}

	totalDelta := 0
	for _, idx := range order {
		delta, err := a.patchOneFunction(idx, newCode[idx], newTables[idx], changedSet)
		if err != nil {
			return nil, fmt.Errorf("function #%d: %w", idx, err)
		}
		totalDelta += delta
	}

	return &AssemblePatchResult{ChangedFunctions: changedIdx, SizeDelta: totalDelta}, nil
}

// sortIntsByOffset sorts function indices ascending by their CURRENT
// FunctionHeader.Offset (their physical position in the bytecode
// segment), which is the order patches must be applied in so that each
// one's downstream shift is correctly folded into the next.
func sortIntsByOffset(idx []int, f *HBCFile) {
	for i := 1; i < len(idx); i++ {
		for j := i; j > 0 && f.FunctionHeaders[idx[j-1]].Offset > f.FunctionHeaders[idx[j]].Offset; j-- {
			idx[j-1], idx[j] = idx[j], idx[j-1]
		}
	}
}

// patchOneFunction replaces one function's bytecode in a.File's raw
// bytes, updates that function's BytecodeSizeInBytes, and shifts the
// Offset of every function whose bytecode physically sits after this
// one in the file (regardless of function index). Returns the size delta
// (new size - old size) so the caller can accumulate the total shift to
// apply to file-level offsets (DebugInfoOffset, FileLength) once all
// per-function patches are done.
// bytecodeSegmentEnd returns the current absolute file offset marking the
// end of the bytecode segment (every function's Offset+BytecodeSizeInBytes
// falls at or before this point) - the first safe place to insert new
// bytes without disturbing any function's existing code. This is the
// start of the large/overflow header table if any function is
// Overflowed (that table always immediately follows the whole bytecode
// segment - see AssembleAndPatch's doc comment), or the file-level
// DebugInfoOffset otherwise (debug info also always follows the
// bytecode segment).
func (f *HBCFile) bytecodeSegmentEnd() int64 {
	end := int64(f.Header.DebugInfoOffset)
	for i := range f.FunctionHeaders {
		h := &f.FunctionHeaders[i]
		if h.Overflowed && h.LargeHeaderFileOffset > 0 && h.LargeHeaderFileOffset < end {
			end = h.LargeHeaderFileOffset
		}
	}
	return end
}

// deduplicateAliasedFunctions handles a fact of real-world Hermes bundles
// this package's earlier development discovered directly against a real
// file: distinct FunctionHeader entries can share the exact same
// Offset, because Hermes/Metro deduplicates functions with identical
// bytecode bodies. Editing one such function's bytecode in place would
// silently corrupt every other function that happens to alias the same
// bytes - their Offset would keep pointing into what is now a
// completely different (edited) instruction stream.
//
// Called before funcIdx's own bytecode is replaced: finds every OTHER
// function currently sharing funcIdx's Offset that isn't ALSO about to
// be independently edited this run (skip is the set of function indices
// already scheduled for their own patch - those will get their own
// distinct bytecode regardless, so there's nothing to protect), and
// gives each one its own physical copy of the current (pre-edit) bytes
// at the end of the bytecode segment, repointing its Offset there. Once
// this returns, funcIdx's Offset is the only FunctionHeader left
// pointing at the bytes about to be edited, so the ordinary single-
// function splice in patchOneFunction can proceed safely.
func (a *HermesDecAssembler) deduplicateAliasedFunctions(funcIdx int, skip map[int]bool) error {
	f := a.File
	hdr := f.FunctionHeaders[funcIdx]

	var aliases []int
	for i := range f.FunctionHeaders {
		if i == funcIdx || skip[i] {
			continue
		}
		if f.FunctionHeaders[i].Offset == hdr.Offset {
			aliases = append(aliases, i)
		}
	}
	if len(aliases) == 0 {
		return nil
	}

	for _, i := range aliases {
		aliasHdr := &f.FunctionHeaders[i]
		size := int(aliasHdr.BytecodeSizeInBytes)
		offset := int(aliasHdr.Offset)
		if offset < 0 || offset+size > len(f.rawData) {
			return fmt.Errorf("function #%d's bytecode range [%d, %d) is out of bounds for a %d-byte file", i, offset, offset+size, len(f.rawData))
		}
		copyOfBytes := make([]byte, size)
		copy(copyOfBytes, f.rawData[offset:offset+size])

		insertAt := f.bytecodeSegmentEnd()
		if err := a.insertBytesAt(insertAt, copyOfBytes); err != nil {
			return fmt.Errorf("de-duplicating function #%d (shares bytecode with function #%d): %w", i, funcIdx, err)
		}

		// insertBytesAt already shifted every FunctionHeader.Offset
		// (including aliasHdr's own, and funcIdx's) that was at or past
		// insertAt - but aliasHdr's OWN Offset must end up pointing at
		// the newly-inserted copy, not wherever the generic shift left
		// it (which would just be its old, now-shared position, since
		// insertAt was chosen to be past every existing function's
		// bytecode). Point it at the copy explicitly.
		aliasHdr.Offset = uint32(insertAt)
		if err := f.writeFunctionHeaderOffsetAndSize(i); err != nil {
			return fmt.Errorf("writing de-duplicated header for function #%d: %w", i, err)
		}
	}

	return nil
}

// insertBytesAt inserts newBytes into f.rawData at absolute file offset
// at (which must be at or past every function's current bytecode, i.e.
// somewhere in [bytecodeSegmentEnd(), len(rawData)]), shifting every
// FunctionHeader field (Offset, LargeHeaderFileOffset,
// SmallHeaderFileOffset) and file-level offset (DebugInfoOffset,
// FileLength) that sits at or past `at` by len(newBytes) - the same
// shift patchOneFunction applies for an ordinary edit, generalized to a
// pure insertion (oldSize=0) at an arbitrary position rather than always
// at a specific function's current bytecode.
func (a *HermesDecAssembler) insertBytesAt(at int64, newBytes []byte) error {
	f := a.File
	if at < 0 || at > int64(len(f.rawData)) {
		return fmt.Errorf("insertion point %d is out of bounds for a %d-byte file", at, len(f.rawData))
	}

	newData := make([]byte, len(f.rawData)+len(newBytes))
	copy(newData, f.rawData[:at])
	copy(newData[at:], newBytes)
	copy(newData[at+int64(len(newBytes)):], f.rawData[at:])
	f.rawData = newData

	delta := int64(len(newBytes))
	for i := range f.FunctionHeaders {
		h := &f.FunctionHeaders[i]
		if int64(h.Offset) >= at {
			h.Offset = uint32(int64(h.Offset) + delta)
		}
		if h.Overflowed && h.LargeHeaderFileOffset >= at {
			h.LargeHeaderFileOffset += delta
		}
		if h.SmallHeaderFileOffset >= at {
			h.SmallHeaderFileOffset += delta
		}
	}

	f.Header.DebugInfoOffset = uint32(int64(f.Header.DebugInfoOffset) + delta)
	f.Header.FileLength = uint32(int64(f.Header.FileLength) + delta)
	f.writeHeaderFields()

	// Re-serialize every function header whose Offset (or, for
	// overflowed functions, LargeHeaderFileOffset/SmallHeaderFileOffset)
	// just shifted - same reasoning as patchOneFunction's own trailer.
	for i := range f.FunctionHeaders {
		if err := f.writeFunctionHeaderOffsetAndSize(i); err != nil {
			return fmt.Errorf("writing shifted header for function #%d: %w", i, err)
		}
	}

	return nil
}

func (a *HermesDecAssembler) patchOneFunction(funcIdx int, code []byte, tables []switchTableToPlace, skip map[int]bool) (int, error) {
	f := a.File
	if funcIdx < 0 || funcIdx >= len(f.FunctionHeaders) {
		return 0, fmt.Errorf("function index %d out of range", funcIdx)
	}

	// Give every OTHER function currently sharing this one's bytecode
	// offset (Hermes/Metro deduplicates identical function bodies - see
	// deduplicateAliasedFunctions' doc comment) its own physical copy
	// BEFORE editing anything here, so the splice below can never
	// silently corrupt an unrelated function that happened to alias the
	// same bytes.
	if err := a.deduplicateAliasedFunctions(funcIdx, skip); err != nil {
		return 0, err
	}

	hdr := &f.FunctionHeaders[funcIdx]
	offset := int(hdr.Offset)
	oldSize := int(hdr.BytecodeSizeInBytes)
	if offset < 0 || offset+oldSize > len(f.rawData) {
		return 0, fmt.Errorf("function's current bytecode range [%d, %d) is out of bounds for a %d-byte file", offset, offset+oldSize, len(f.rawData))
	}

	// splicePoint is the single fixed reference for "did this move":
	// everything at or after the end of the OLD bytecode (in the
	// ORIGINAL, pre-splice file) shifts by delta bytes. This isn't only
	// each function's own bytecode Offset - the large/overflow header
	// table lives immediately after the whole bytecode segment (not
	// before it, as might be assumed from the metadata/string/literal
	// tables that DO precede the bytecode), so any function whose large
	// header sits past this point needs LargeHeaderFileOffset shifted
	// too, independently of whether that function's own bytecode Offset
	// also moved.
	splicePoint := int64(offset + oldSize)

	newData := make([]byte, len(f.rawData)-oldSize+len(code))
	copy(newData, f.rawData[:offset])
	copy(newData[offset:], code)
	copy(newData[offset+len(code):], f.rawData[offset+oldSize:])
	f.rawData = newData

	delta := len(code) - oldSize
	hdr.BytecodeSizeInBytes = uint32(len(code))

	if delta != 0 {
		for i := range f.FunctionHeaders {
			h := &f.FunctionHeaders[i]
			if i != funcIdx && int64(h.Offset) >= splicePoint {
				h.Offset = uint32(int64(h.Offset) + int64(delta))
			}
			if h.Overflowed && h.LargeHeaderFileOffset >= splicePoint {
				h.LargeHeaderFileOffset += int64(delta)
			}
			if h.SmallHeaderFileOffset >= splicePoint {
				h.SmallHeaderFileOffset += int64(delta)
			}
		}
	}

	// The splice above only updated rawData's bytecode-segment bytes and
	// the in-memory FunctionHeader fields. Every function whose header
	// entry now needs different bytes written - the edited one (new
	// size), plus every one whose Offset/LargeHeaderFileOffset shifted -
	// needs its header entry re-serialized to match, or the file's own
	// header table would disagree with where the bytecode actually now
	// is.
	if err := f.writeFunctionHeaderOffsetAndSize(funcIdx); err != nil {
		return 0, fmt.Errorf("writing updated header for function #%d: %w", funcIdx, err)
	}
	if delta != 0 {
		for i := range f.FunctionHeaders {
			if i == funcIdx {
				continue
			}
			if err := f.writeFunctionHeaderOffsetAndSize(i); err != nil {
				return 0, fmt.Errorf("writing updated header for function #%d: %w", i, err)
			}
		}

		f.Header.DebugInfoOffset = uint32(int64(f.Header.DebugInfoOffset) + int64(delta))
		f.Header.FileLength = uint32(int64(f.Header.FileLength) + int64(delta))
		f.writeHeaderFields()
	}

	// Place every UIntSwitchImm jump table this function needs, OUT OF
	// LINE at the end of the bytecode segment - never inline within the
	// function's own instruction stream, which is what real Hermes
	// bytecode does too (confirmed directly against real file data: the
	// instruction immediately following a UIntSwitchImm's declared
	// operands is always the next real instruction, never table data).
	// hdr.Offset is now this function's final, settled absolute file
	// position, so arg2 (the byte distance from the instruction to its
	// table) can finally be computed and patched into the already-
	// written instruction bytes.
	for _, t := range tables {
		// Align to a 4-byte boundary before the table, exactly as real
		// Hermes bytecode does (and as decodeInstructionFull's read side
		// already replicates - see its doc comment) - without this, the
		// table would be read back from the wrong (unaligned) position.
		insertAt := f.bytecodeSegmentEnd()
		pad := (4 - insertAt%4) % 4
		toInsert := t.TableBytes
		if pad > 0 {
			toInsert = make([]byte, pad+int64(len(t.TableBytes)))
			copy(toInsert[pad:], t.TableBytes)
		}
		tableStart := insertAt + pad

		if err := a.insertBytesAt(insertAt, toInsert); err != nil {
			return 0, fmt.Errorf("placing jump table for function #%d: %w", funcIdx, err)
		}
		delta += len(toInsert)

		instAbs := int64(hdr.Offset) + int64(t.InstFuncOffset)
		arg2 := uint32(tableStart - instAbs)
		arg2Abs := int64(hdr.Offset) + int64(t.Arg2Offset)
		if arg2Abs < 0 || arg2Abs+4 > int64(len(f.rawData)) {
			return 0, fmt.Errorf("function #%d: computed arg2 field position %d is out of bounds (this should not happen; please report this as a bug)", funcIdx, arg2Abs)
		}
		binary.LittleEndian.PutUint32(f.rawData[arg2Abs:], arg2)
	}

	return delta, nil
}
