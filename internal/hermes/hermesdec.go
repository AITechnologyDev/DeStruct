package hermes

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// =============================================================================
// This file reproduces the exact text output format of the reference Python
// "hermes-dec" disassembler (hbc_disassembler.py / hbc_bytecode_parser.py),
// so that a text diff between our output and hermes-dec's output is minimal,
// and so that every operand/comment can be traced back to an exact byte
// range in the .hbc file for patching in a hex editor.
//
// Reference line format (per instruction), from ParsedInstruction.__repr__:
//
//   {original_pos:08x}: <{name}>: <{Type: value, Type: value, ...}>{comment}
//
// Reference function header format, from disassemble_function():
//
//   => [{Kind} #{count} "{name}" of {size} bytes]: {n} params, frame size={fs},
//      strict={b}, exc handler={b}, debug info={b}  @ offset 0x{off:08x}{exc}{dbg}
//
//   Bytecode listing:
//
//   ==> {repr(instruction)}
//   ...
//
//   ===============
// =============================================================================

// ---------------------------------------------------------------------------
// Serialized Literal Parser (SLP) - decodes the TLV-encoded array/object
// buffer format used by NewArrayWithBuffer / NewObjectWithBuffer and their
// Long variants. Mirrors serialized_literal_parser.py exactly.
// ---------------------------------------------------------------------------

type slpTag int

const (
	slpNullTag slpTag = iota
	slpTrueTag
	slpFalseTag
	slpNumberTag
	slpLongStringTag
	slpShortStringTag
	slpByteStringTag
	slpIntegerTag
)

type slpValue struct {
	tag   slpTag
	num   float64 // valid for slpNumberTag
	ival  int64   // valid for slpIntegerTag (unsigned uint32 value, per hermes-dec's int.from_bytes(..., 'little') with signed defaulting to False) and the 3 string tags (holds the string_id)
}

type slpArray struct {
	items []slpValue
}

// toStrings renders each item the same way SLPArray.to_strings does in Python:
// null/true/false as bare words, numbers/integers via str(), and string
// references resolved against the string table and quoted via Go's %q
// (equivalent to Python's repr() for the plain-ASCII/UTF-8 case).
func (a slpArray) ToStrings(stringTable []string) []string {
	out := make([]string, 0, len(a.items))
	for _, item := range a.items {
		var s string
		switch item.tag {
		case slpNullTag:
			s = "null"
		case slpTrueTag:
			s = "true"
		case slpFalseTag:
			s = "false"
		case slpNumberTag:
			s = formatPyFloat(item.num)
		case slpIntegerTag:
			s = strconv.FormatInt(item.ival, 10)
		case slpLongStringTag, slpShortStringTag, slpByteStringTag:
			id := int(item.ival)
			if id >= 0 && id < len(stringTable) {
				s = pyRepr(stringTable[id])
			} else {
				s = fmt.Sprintf("<bad_string_id:%d>", id)
			}
		default:
			s = "<?>"
		}
		out = append(out, s)
	}
	return out
}

// slpArrayMaxItems bounds how many entries unpackSLPArray will ever produce.
// This exists purely as a safety net: numItems is normally a small operand
// value (a literal array/object's element count), but if the bytecode is
// being decoded with the wrong opcode table (e.g. a bytecode version whose
// opcode layout doesn't match DeStruct's built-in table) or the file is
// corrupt/adversarial, that operand can come out as a garbage 32-bit value.
// Without a cap, such a value drives an unbounded allocation loop and can
// exhaust memory well before the missing-bytes check below ever triggers,
// since several SLP tags (null/true/false) consume zero input bytes per
// item. No legitimate Hermes literal buffer entry comes close to this size.
const slpArrayMaxItems = 1 << 20 // 1,048,576 entries

// unpackSLPArray decodes up to numItems values from data, following the
// exact tag/length framing of unpack_slp_array() in serialized_literal_parser.py.
func unpackSLPArray(data []byte, numItems int) slpArray {
	if numItems < 0 {
		numItems = 0
	}
	if numItems > slpArrayMaxItems {
		numItems = slpArrayMaxItems
	}
	// Zero-payload tags (null/true/false) can produce output without
	// consuming input; without also bounding total output by the input
	// size, a crafted/garbage tag stream could still allocate far beyond
	// what `data` could ever legitimately encode.
	if numItems > len(data)*8+64 {
		numItems = len(data)*8 + 64
	}

	var items []slpValue
	pos := 0

	readByte := func() (byte, bool) {
		if pos >= len(data) {
			return 0, false
		}
		b := data[pos]
		pos++
		return b, true
	}

	for len(items) < numItems {
		nextTag, ok := readByte()
		if !ok {
			break
		}
		tagType := slpTag((nextTag >> 4) & 0b111)

		var length int
		if nextTag>>7 == 1 {
			lenLo, ok := readByte()
			if !ok {
				break
			}
			length = (int(nextTag&0b1111) << 8) | int(lenLo)
		} else {
			length = int(nextTag & 0b1111)
		}

		for i := 0; i < length; i++ {
			switch tagType {
			case slpNullTag:
				items = append(items, slpValue{tag: slpNullTag})
			case slpTrueTag:
				items = append(items, slpValue{tag: slpTrueTag})
			case slpFalseTag:
				items = append(items, slpValue{tag: slpFalseTag})
			case slpNumberTag:
				if pos+8 > len(data) {
					pos = len(data)
					items = append(items, slpValue{tag: slpNumberTag})
					continue
				}
				bits := leUint64(data[pos : pos+8])
				pos += 8
				items = append(items, slpValue{tag: slpNumberTag, num: math.Float64frombits(bits)})
			case slpLongStringTag:
				if pos+4 > len(data) {
					pos = len(data)
					items = append(items, slpValue{tag: slpLongStringTag})
					continue
				}
				v := leUint32(data[pos : pos+4])
				pos += 4
				items = append(items, slpValue{tag: slpLongStringTag, ival: int64(v)})
			case slpShortStringTag:
				if pos+2 > len(data) {
					pos = len(data)
					items = append(items, slpValue{tag: slpShortStringTag})
					continue
				}
				v := leUint16(data[pos : pos+2])
				pos += 2
				items = append(items, slpValue{tag: slpShortStringTag, ival: int64(v)})
			case slpByteStringTag:
				if pos+1 > len(data) {
					pos = len(data)
					items = append(items, slpValue{tag: slpByteStringTag})
					continue
				}
				v := data[pos]
				pos++
				items = append(items, slpValue{tag: slpByteStringTag, ival: int64(v)})
			case slpIntegerTag:
				if pos+4 > len(data) {
					pos = len(data)
					items = append(items, slpValue{tag: slpIntegerTag})
					continue
				}
				v := leUint32(data[pos : pos+4])
				pos += 4
				// hermes-dec's Python source decodes this via
				// int.from_bytes(data.read(4), 'little') with no
				// signed=True, which defaults to unsigned - so 0xFFFFFFFF
				// prints as 4294967295, not -1.
				items = append(items, slpValue{tag: slpIntegerTag, ival: int64(v)})
			}
		}
	}

	if len(items) > numItems {
		items = items[:numItems]
	}
	return slpArray{items: items}
}

func leUint16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func leUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func leUint64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// formatPyFloat renders a float64 the way Python's str() does for the common
// cases hit here (integral doubles print without a trailing ".0" is WRONG in
// Python - Python keeps ".0"; e.g. str(3.0) == "3.0"). strconv.FormatFloat
// with -1 precision + 'g' matches Python's repr in almost all cases; the one
// divergence (bare integers losing ".0") is corrected below.
// formatPyFloat renders a float64 exactly as Python's str()/repr() does:
// the shortest decimal digit string that round-trips back to the same
// float64, formatted in fixed-point notation when the base-10 exponent e
// (as in d.ddddEe scientific form) satisfies -4 <= e < 16, and in
// exponential notation otherwise. This threshold is CPython's own
// (PyOS_double_to_string format code 'r'); Go's strconv.FormatFloat with
// the 'g' verb picks the same shortest digit string but switches to
// exponential notation much earlier, so the two disagree on any value
// whose exponent falls in roughly [12, 16) - for example Python keeps
// 3643287777059.0 in fixed notation while Go's 'g' renders it as
// 3.643287777059e+12.
func formatPyFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "inf"
	}
	if math.IsInf(f, -1) {
		return "-inf"
	}
	if math.IsNaN(f) {
		return "nan"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}

	// 'e' with precision -1 gives the shortest round-tripping digit
	// string, in the form "d.ddddde±XX" (or "de±XX" with no fractional
	// part when only one significant digit is needed).
	sci := strconv.FormatFloat(f, 'e', -1, 64)

	neg := false
	if sci[0] == '-' {
		neg = true
		sci = sci[1:]
	}

	eIdx := strings.IndexByte(sci, 'e')
	mantissa := sci[:eIdx]  // "d" or "d.ddd"
	expPart := sci[eIdx+1:] // "+12", "-05", etc.
	exp, _ := strconv.Atoi(expPart)

	digits := strings.Replace(mantissa, ".", "", 1)

	var out string
	if exp >= -4 && exp < 16 {
		out = formatPyFixed(digits, exp)
	} else {
		out = formatPyExponential(digits, exp)
	}

	if neg {
		out = "-" + out
	}
	return out
}

// formatPyFixed renders significant-digit string `digits` (no decimal
// point, first digit is the ones place of 10^exp) in fixed-point form,
// matching Python's str(float) output for exponents in [-4, 16).
func formatPyFixed(digits string, exp int) string {
	if exp >= 0 {
		intLen := exp + 1
		if len(digits) <= intLen {
			// All digits are in the integer part; pad with zeros and
			// append the mandatory ".0" Python always shows.
			return digits + strings.Repeat("0", intLen-len(digits)) + ".0"
		}
		return digits[:intLen] + "." + digits[intLen:]
	}
	// exp < 0: value is 0.000ddd... with -exp-1 zeros after the point
	// before the first significant digit.
	return "0." + strings.Repeat("0", -exp-1) + digits
}

// formatPyExponential renders significant-digit string `digits` in
// Python's exponential form: "d.ddde+XX" / "d.ddde-XX", always at least
// two exponent digits, always a sign, and a bare "de+XX" (no decimal
// point) when there's only one significant digit.
func formatPyExponential(digits string, exp int) string {
	var mantissa string
	if len(digits) == 1 {
		mantissa = digits
	} else {
		mantissa = digits[:1] + "." + digits[1:]
	}
	sign := "+"
	e := exp
	if e < 0 {
		sign = "-"
		e = -e
	}
	expStr := strconv.Itoa(e)
	if len(expStr) < 2 {
		expStr = "0" + expStr
	}
	return mantissa + "e" + sign + expStr
}

// pyRepr renders a Go string the way Python's repr() renders a str:
// quoted (choosing the quote character exactly as CPython does - double
// quotes when the string contains a single quote but no double quote,
// single quotes otherwise, escaping the chosen quote character if it
// still appears), with backslash and common control chars using their
// short escape (\n \r \t \\), and any other non-printable code point
// escaped as \xXX (<=0xFF), \uXXXX (<=0xFFFF) or \UXXXXXXXX (beyond),
// matching CPython's unicodeobject.c reprUnicode printability rule.
func pyRepr(s string) string {
	hasSingle := strings.ContainsRune(s, '\'')
	hasDouble := strings.ContainsRune(s, '"')
	quote := byte('\'')
	if hasSingle && !hasDouble {
		quote = '"'
	}

	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case byte(r) == quote && r < 0x80:
			b.WriteByte('\\')
			b.WriteByte(quote)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsPrint(r) {
				b.WriteRune(r)
			} else {
				switch {
				case r <= 0xFF:
					fmt.Fprintf(&b, `\x%02x`, r)
				case r <= 0xFFFF:
					fmt.Fprintf(&b, `\u%04x`, r)
				default:
					fmt.Fprintf(&b, `\U%08x`, r)
				}
			}
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// ---------------------------------------------------------------------------
// Instruction formatting - matches ParsedInstruction.__repr__ exactly.
// ---------------------------------------------------------------------------

// operandTypeName returns the label used before ": value" for one operand:
// the OperandMeaning name if present (string_id / function_id / bigint_id),
// otherwise the raw OperandType name (Reg8, UInt16, Addr32, Double, ...).
func operandTypeName(meaning OperandMeaning, typ OperandType) string {
	switch meaning {
	case MeaningStringID:
		return "string_id"
	case MeaningFunctionID:
		return "function_id"
	case MeaningBigIntID:
		return "bigint_id"
	default:
		return typ.Name
	}
}

// operandValueString renders the raw operand value the way Python's %r does
// for each ctypes field: plain integers for all int types, Go's float
// formatting (%v-equivalent to Python repr of a float) for Double.
func operandValueString(pi *ParsedInstruction, index int, arg uint64) string {
	op := pi.Inst.Operands[index]
	if op.Name == "Double" {
		return formatPyFloat(math.Float64frombits(arg))
	}
	if op.IsSigned {
		// Sign-extend according to the operand's storage size.
		switch op.Size {
		case 1:
			return strconv.FormatInt(int64(int8(arg)), 10)
		case 2:
			return strconv.FormatInt(int64(int16(arg)), 10)
		case 4:
			return strconv.FormatInt(int64(int32(arg)), 10)
		default:
			return strconv.FormatInt(int64(arg), 10)
		}
	}
	return strconv.FormatUint(arg, 10)
}

// FormatHermesDec renders a single instruction exactly as hermes-dec's
// ParsedInstruction.__repr__ does:
//
//	{pos:08x}: <{Name}>: <{Type: val, Type: val, ...}>{comment}
//
// pos is the offset of the instruction relative to the start of the
// function's bytecode (matching original_pos in the Python reference).
func (d *Disassembler) FormatHermesDec(pi *ParsedInstruction) string {
	operandParts := make([]string, len(pi.Inst.Operands))
	for i, op := range pi.Inst.Operands {
		var meaning OperandMeaning
		if i < len(pi.Inst.Meanings) {
			meaning = pi.Inst.Meanings[i]
		}
		var arg uint64
		if i < len(pi.Args) {
			arg = pi.Args[i]
		}
		operandParts[i] = fmt.Sprintf("%s: %s", operandTypeName(meaning, op), operandValueString(pi, i, arg))
	}

	comment := d.buildComment(pi)

	return fmt.Sprintf("%08x: <%s>: <%s>%s", pi.Offset, pi.Inst.Name, strings.Join(operandParts, ", "), comment)
}

// buildComment reproduces the "comment" section built up in
// ParsedInstruction.__repr__: one fragment per operand_meaning (string_id /
// bigint_id / function_id), one fragment for Addr8/Addr32 jump targets, and
// then the special per-instruction array/object/builtin/switch-table
// fragments, each prefixed with two spaces and a "# " marker.
func (d *Disassembler) buildComment(pi *ParsedInstruction) string {
	var comment strings.Builder

	for i, op := range pi.Inst.Operands {
		if i >= len(pi.Args) {
			break
		}
		arg := pi.Args[i]
		var meaning OperandMeaning
		if i < len(pi.Inst.Meanings) {
			meaning = pi.Inst.Meanings[i]
		}

		switch meaning {
		case MeaningStringID:
			id := int(arg)
			if id >= 0 && id < len(d.File.Strings) {
				fmt.Fprintf(&comment, "  # String: %s (%s)", pyRepr(d.File.Strings[id]), stringKindName(d.File, id))
			} else {
				fmt.Fprintf(&comment, "  # String: <bad_string_id:%d>", id)
			}
		case MeaningBigIntID:
			id := int(arg)
			if id >= 0 && id < len(d.File.BigIntDecimal) {
				fmt.Fprintf(&comment, "  # BigInt: %s", d.File.BigIntDecimal[id])
			} else {
				fmt.Fprintf(&comment, "  # BigInt: <bad_bigint_id:%d>", id)
			}
		case MeaningFunctionID:
			id := int(arg)
			if id >= 0 && id < len(d.File.FunctionHeaders) {
				fhdr := d.File.FunctionHeaders[id]
				fname := "<unknown>"
				if int(fhdr.FunctionName) < len(d.File.Strings) {
					fname = d.File.Strings[fhdr.FunctionName]
				}
				fmt.Fprintf(&comment, "  # Function: [#%d %s of %d bytes]: %d params @ offset 0x%08x",
					id, fname, fhdr.BytecodeSizeInBytes, fhdr.ParamCount, fhdr.Offset)
			} else {
				fmt.Fprintf(&comment, "  # Function: <bad_function_id:%d>", id)
			}
		default:
			if op.IsAddr {
				target := pi.Offset + uint32(int32(arg))
				fmt.Fprintf(&comment, "  # Address: %08x", target)
			}
		}
	}

	switch pi.Inst.Name {
	case "NewArrayWithBuffer", "NewArrayWithBufferLong":
		d.appendArrayComment(&comment, pi)
	case "NewObjectWithBuffer", "NewObjectWithBufferLong":
		d.appendObjectComment(&comment, pi)
	case "CallBuiltin", "CallBuiltinLong", "GetBuiltinClosure":
		d.appendBuiltinComment(&comment, pi)
	// NOTE: no case for UIntSwitchImm here, deliberately. Real hermes-dec's
	// own comment-generation code only prints a "# Jump table: [...]"
	// comment when self.inst.name == 'SwitchImm' - the pre-rename opcode
	// name that no longer exists in the current opcode table (it's been
	// UIntSwitchImm for a long time). That condition can never be true
	// for a real UIntSwitchImm instruction, so the real tool silently
	// never prints this comment despite correctly parsing and storing
	// the table (see appendSwitchComment's doc comment for the full
	// citation). Reproducing that omission is what keeps this exact
	// disassembly format byte-for-byte identical to the real tool's
	// output - pi.JumpTable is still fully populated either way, and is
	// what DisassembleFunctionExactEditable's "case N: ..." lines (and
	// the assembler) actually read from.
	}

	return comment.String()
}

func stringKindName(f *HBCFile, id int) string {
	if id < 0 || id >= len(f.StringKindOf) {
		return "String"
	}
	switch f.StringKindOf[id] {
	case 1:
		return "Identifier"
	case 2:
		return "Predefined"
	default:
		return "String"
	}
}

// appendArrayComment reproduces the "# Array: [...]" fragment for
// NewArrayWithBuffer / NewArrayWithBufferLong. Operand layout:
// arg1=dst, arg2=numElements, arg3=numLiterals, arg4=bufferIndex.
func (d *Disassembler) appendArrayComment(comment *strings.Builder, pi *ParsedInstruction) {
	if len(pi.Args) < 4 {
		return
	}
	numLiterals := int(pi.Args[2])
	bufferIndex := int(pi.Args[3])
	if bufferIndex < 0 {
		bufferIndex = 0
	}

	buf := d.File.LiteralValues
	if bufferIndex > len(buf) {
		bufferIndex = len(buf)
	}
	arr := unpackSLPArray(buf[bufferIndex:], numLiterals)
	items := arr.ToStrings(d.File.Strings)
	fmt.Fprintf(comment, "  # Array: [%s]", strings.Join(items, ", "))
}

// appendObjectComment reproduces the "# Object: {...}" fragment for
// NewObjectWithBuffer / NewObjectWithBufferLong, using the pre-v97 dual
// key/value buffer layout when applicable, and the v97+ object shape table
// otherwise.
//
// Pre-v97 operand layout: arg1=dst, arg2=numElements, arg3=numLiterals,
// arg4=keyBufferIndex, arg5=valueBufferIndex.
// v97+ operand layout:    arg1=dst, arg2=shapeID, arg3=valueBufferIndex.
func (d *Disassembler) appendObjectComment(comment *strings.Builder, pi *ParsedInstruction) {
	if d.File.Header.Version < 97 {
		if len(pi.Args) < 5 {
			return
		}
		numLiterals := int(pi.Args[2])
		keyIndex := int(pi.Args[3])
		valIndex := int(pi.Args[4])

		keyBuf := d.File.ObjectKeys
		if keyIndex > len(keyBuf) {
			keyIndex = len(keyBuf)
		}
		valBuf := d.File.ObjectValues
		if valIndex > len(valBuf) {
			valIndex = len(valBuf)
		}

		keys := unpackSLPArray(keyBuf[keyIndex:], numLiterals).ToStrings(d.File.Strings)
		vals := unpackSLPArray(valBuf[valIndex:], numLiterals).ToStrings(d.File.Strings)

		n := len(keys)
		if len(vals) < n {
			n = len(vals)
		}
		pairs := make([]string, n)
		for i := 0; i < n; i++ {
			pairs[i] = fmt.Sprintf("%s: %s", keys[i], vals[i])
		}
		fmt.Fprintf(comment, "  # Object: {%s}", strings.Join(pairs, ", "))
		return
	}

	if len(pi.Args) < 3 {
		return
	}
	shapeID := int(pi.Args[1])
	valIndex := int(pi.Args[2])

	if shapeID < 0 || shapeID >= len(d.File.ObjectShapeKeys) {
		fmt.Fprintf(comment, "  # Object: <bad_shape_id:%d>", shapeID)
		return
	}
	keys := d.File.ObjectShapeKeys[shapeID]

	valBuf := d.File.LiteralValues
	if valIndex > len(valBuf) {
		valIndex = len(valBuf)
	}
	vals := unpackSLPArray(valBuf[valIndex:], len(keys)).ToStrings(d.File.Strings)

	n := len(keys)
	if len(vals) < n {
		n = len(vals)
	}
	pairs := make([]string, n)
	for i := 0; i < n; i++ {
		pairs[i] = fmt.Sprintf("%s: %s", keys[i], vals[i])
	}
	fmt.Fprintf(comment, "  # Object: {%s}", strings.Join(pairs, ", "))
}

// appendBuiltinComment reproduces "# Built-in function: [#N name]" for
// CallBuiltin / CallBuiltinLong / GetBuiltinClosure. Operand layout:
// arg1=dst/argc/target, arg2=builtinNumber, ...
func (d *Disassembler) appendBuiltinComment(comment *strings.Builder, pi *ParsedInstruction) {
	if len(pi.Args) < 2 {
		return
	}
	builtinNumber := int(pi.Args[1])
	name := "<unknown>"
	if builtinNumber >= 0 && builtinNumber < len(builtinNames) {
		name = builtinNames[builtinNumber]
	}
	fmt.Fprintf(comment, "  # Built-in function: [#%d %s]", builtinNumber, name)
}

// ---------------------------------------------------------------------------
// Instruction decoding with switch-table support (decodeInstruction in
// opcodes.go does not read the jump table that follows a SwitchImm-family
// instruction; decodeInstructionFull wraps it to add that).
// ---------------------------------------------------------------------------

// decodeInstructionFull decodes one instruction starting at `offset` within
// `code` (the function-relative bytecode slice), and additionally reads the
// jump table that follows UIntSwitchImm instructions, matching
// parse_hbc_bytecode()'s handling in the Python reference.
//
// UIntSwitchImm operand layout: [Reg8 arg1, UInt32 arg2, Addr32 arg3,
// UInt32 arg4, UInt32 arg5], where arg2 is the byte offset (relative to the
// instruction start) of the jump table, and arg4/arg5 are the inclusive
// [min, max] range of table entries, each a 4-byte little-endian file
// offset relative to the instruction start.
// switchJumpTableMaxEntries bounds how many entries the UIntSwitchImm jump
// table decoder will ever preallocate. lo/hi come straight from raw 32-bit
// instruction operands; if the bytecode is being decoded with the wrong
// opcode table for its actual version, or the file is corrupt/adversarial,
// hi-lo can come out close to 2^32 and an unguarded `make([]uint32, 0,
// count)` attempts a many-gigabyte allocation immediately. No legitimate
// switch statement comes close to this many cases.
const switchJumpTableMaxEntries = 1 << 20 // 1,048,576 entries

// decodeInstructionFull decodes one instruction starting at `offset`
// within `code` (the function-relative bytecode slice, as declared by
// BytecodeSizeInBytes), and additionally reads the jump table that
// follows UIntSwitchImm instructions, matching parse_hbc_bytecode()'s
// handling in the Python reference.
//
// rawData is the WHOLE file's bytes and fileBase is this function's
// absolute file offset (FunctionHeader.Offset) - both needed because a
// UIntSwitchImm's jump table is physically stored immediately after the
// function's bytecode, in file space that is NOT counted toward
// BytecodeSizeInBytes (confirmed directly against this package's test
// data: a table at the very end of a function's declared bytecode reads
// as entirely valid data sitting just past it). Reading only from `code`
// silently truncates any table whose start or entries fall past that
// boundary. If rawData is nil (some callers don't have it available),
// this falls back to reading only from `code`, which will under-read any
// table extending past the function's declared size - the same
// limitation this had before rawData/fileBase were added.
func decodeInstructionFull(code []byte, offset uint32, table map[byte]*InstructionDef, rawData []byte, fileBase uint32) *ParsedInstruction {
	pi := decodeInstruction(code[offset:], offset, table)
	if pi == nil || pi.Inst == nil {
		return pi
	}

	if pi.Inst.Name == "UIntSwitchImm" && len(pi.Args) >= 5 {
		tableByteOffset := int64(offset) + int64(int32(pi.Args[1]))
		lo := pi.Args[3]
		hi := pi.Args[4]
		if hi >= lo {
			count := hi - lo + 1
			if count > switchJumpTableMaxEntries {
				count = switchJumpTableMaxEntries
			}

			// Real hermes-dec applies align_over_padding() (round up to
			// a multiple of 4, relative to the ABSOLUTE file position)
			// immediately before reading the table - do the same.
			absTableStart := int64(fileBase) + tableByteOffset
			if mod := absTableStart % 4; mod != 0 {
				absTableStart += 4 - mod
			}

			src := code
			base := int64(0)
			if rawData != nil {
				src = rawData
				base = absTableStart
			} else {
				base = tableByteOffset
			}

			maxByRemainingBytes := uint64(0)
			if base >= 0 && base <= int64(len(src)) {
				maxByRemainingBytes = uint64(int64(len(src))-base) / 4
			}
			if count > maxByRemainingBytes {
				count = maxByRemainingBytes
			}

			pi.JumpTable = make([]uint32, 0, count)
			pos := base
			for i := uint64(0); i < count; i++ {
				if pos < 0 || pos+4 > int64(len(src)) {
					break
				}
				delta := leUint32(src[pos : pos+4])
				pi.JumpTable = append(pi.JumpTable, offset+delta)
				pos += 4
			}
		}
	}

	return pi
}

// ---------------------------------------------------------------------------
// Function / whole-file disassembly in the exact hermes-dec text layout.
// ---------------------------------------------------------------------------

var functionKindNames = map[uint8]string{
	0: "Function",
	1: "Generator function",
	2: "Async function",
}

// DisassembleFunctionExact writes one function's disassembly in the exact
// hermes-dec text layout (header line, blank line, "Bytecode listing:",
// blank line, one "==> ..." line per instruction, two blank lines, a
// separator line of 15 '=' characters, blank line), matching
// disassemble_function() in hbc_disassembler.py line for line.
func (d *Disassembler) DisassembleFunctionExact(funcIdx int, w io.Writer) {
	d.disassembleFunctionExact(funcIdx, w, false)
}

// DisassembleFunctionExactEditable is DisassembleFunctionExact plus one
// deliberate extension: after any UIntSwitchImm instruction, it also
// prints one "    case N: XXXXXXXX" line per jump table entry (N is the
// entry's index within the switch's [lo, hi] range, XXXXXXXX is that
// entry's function-relative target byte offset, in the same %08x form
// used everywhere else in this format).
//
// This is NOT part of the real hermes-dec text format and is never used
// for the default `destruct hermes` disassembly output - only
// AssembleAndPatch's own round-trip (disassemble the current file this
// way, so ParseHermesDecHASM's switch case lines have something to
// diff/align against) relies on it. The reason for the extension: every
// other operand in this format is an editable, authoritative value
// (comments aside) - but a UIntSwitchImm's jump table is otherwise only
// ever shown as an informational, non-authoritative "# Jump table: [...]"
// comment, which would leave no way to actually retarget one of a
// switch's cases through this text format at all.
func (d *Disassembler) DisassembleFunctionExactEditable(funcIdx int, w io.Writer) {
	d.disassembleFunctionExact(funcIdx, w, true)
}

func (d *Disassembler) disassembleFunctionExact(funcIdx int, w io.Writer, editable bool) {
	if funcIdx < 0 || funcIdx >= len(d.File.FunctionHeaders) {
		return
	}
	hdr := d.File.FunctionHeaders[funcIdx]
	name := "<unknown>"
	if int(hdr.FunctionName) < len(d.File.Strings) {
		name = d.File.Strings[hdr.FunctionName]
	}

	kindName, ok := functionKindNames[hdr.Kind]
	if !ok {
		kindName = "Function"
	}

	var exceptionInfo strings.Builder
	if hdr.HasExceptionHandler {
		handlers := d.File.ExcHandlers[funcIdx]
		exceptionInfo.WriteString("\n  [Exception handlers:")
		for _, h := range handlers {
			fmt.Fprintf(&exceptionInfo, " [start=0x%x, end=0x%x, target=0x%x]", h.Start, h.End, h.Target)
		}
		exceptionInfo.WriteString(" ]")
	}

	var debugInfo strings.Builder
	if hdr.HasDebugInfo {
		if dbg, ok := d.File.DebugOffsets[funcIdx]; ok {
			fmt.Fprintf(&debugInfo, "\n  [Debug offsets: source_locs=0x%x, scope_desc_data=0x%x]", dbg.SourceLocations, dbg.ScopeDescData)
		}
	}

	fmt.Fprintf(w, "=> [%s #%d \"%s\" of %d bytes]: %d params, frame size=%d, strict=%s, exc handler=%s, debug info=%s  @ offset 0x%08x%s%s\n",
		kindName, funcIdx, name, hdr.BytecodeSizeInBytes,
		hdr.ParamCount, hdr.FrameSize,
		pyBit(hdr.StrictMode), pyBit(hdr.HasExceptionHandler), pyBit(hdr.HasDebugInfo),
		hdr.Offset, exceptionInfo.String(), debugInfo.String())

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Bytecode listing:")
	fmt.Fprintln(w)

	code := d.File.getCode(funcIdx)
	fileBase := d.File.FunctionHeaders[funcIdx].Offset
	offset := uint32(0)
	for offset < uint32(len(code)) {
		pi := decodeInstructionFull(code, offset, d.Table, d.File.rawData, fileBase)
		if pi == nil || pi.Inst == nil {
			break
		}
		fmt.Fprintf(w, "==> %s\n", d.FormatHermesDec(pi))
		if editable && pi.Inst.Name == "UIntSwitchImm" && len(pi.JumpTable) > 0 {
			for i, target := range pi.JumpTable {
				fmt.Fprintf(w, "    case %d: %08x\n", i, target)
			}
		}
		if pi.NextOffset <= offset {
			break // safety net against zero-size/unknown instructions
		}
		offset = pi.NextOffset
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("=", 15))
	fmt.Fprintln(w)
}

// pyBit renders a bool as Python's repr() of the underlying c_uint8:1
// bitfield that hermes-dec reads strictMode/hasExceptionHandler/hasDebugInfo
// as: "0" or "1", not "True"/"False".
func pyBit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// DisassembleAllExact writes every function in the file using the exact
// hermes-dec text layout, one after another - equivalent to running
// hermes-dec's do_disassemble() over the whole file.
func (d *Disassembler) DisassembleAllExact(w io.Writer) {
	for funcIdx := range d.File.FunctionHeaders {
		d.DisassembleFunctionExact(funcIdx, w)
	}
}

// DisassembleAllExactEditable is DisassembleAllExact using
// DisassembleFunctionExactEditable for each function, so UIntSwitchImm
// jump tables come out as editable "    case N: XXXXXXXX" lines. Used by
// AssembleAndPatch's diffing/alignment step, not by default disassembly
// output.
func (d *Disassembler) DisassembleAllExactEditable(w io.Writer) {
	for funcIdx := range d.File.FunctionHeaders {
		d.DisassembleFunctionExactEditable(funcIdx, w)
	}
}

// ---------------------------------------------------------------------------
// Hex-editor patch map: for every instruction, print the exact absolute
// file offset and byte length of the opcode and of each operand, so that a
// hex editor can be used to patch operand bytes in place without needing to
// reassemble the file. This does NOT exist in hermes-dec (which only prints
// function-relative offsets); it exists specifically to make DeStruct's
// hermes-dec-style output directly actionable in a hex editor.
// ---------------------------------------------------------------------------

// DisassembleFunctionPatchMap writes, for one function, the exact
// hermes-dec-format line for each instruction (using the ABSOLUTE file
// offset instead of the function-relative one), followed by one indented
// line per operand giving its precise byte range in the file and its raw
// bytes, so the person can locate and edit the exact bytes in a hex editor.
func (d *Disassembler) DisassembleFunctionPatchMap(funcIdx int, w io.Writer) {
	if funcIdx < 0 || funcIdx >= len(d.File.FunctionHeaders) {
		return
	}
	hdr := d.File.FunctionHeaders[funcIdx]
	name := "<unknown>"
	if int(hdr.FunctionName) < len(d.File.Strings) {
		name = d.File.Strings[hdr.FunctionName]
	}

	fmt.Fprintf(w, "=> [Function #%d \"%s\" of %d bytes] @ file offset 0x%08x\n\n",
		funcIdx, name, hdr.BytecodeSizeInBytes, hdr.Offset)

	code := d.File.getCode(funcIdx)
	offset := uint32(0)
	for offset < uint32(len(code)) {
		pi := decodeInstructionFull(code, offset, d.Table, d.File.rawData, hdr.Offset)
		if pi == nil || pi.Inst == nil {
			break
		}

		absOpcodeOffset := hdr.Offset + offset
		// Print the hermes-dec-style line, but keyed on the absolute file
		// offset so it can be searched for directly in a hex editor.
		line := d.FormatHermesDec(pi)
		// FormatHermesDec prints the function-relative offset first;
		// replace it with the absolute file offset for this view.
		if idx := strings.Index(line, ":"); idx == 8 {
			line = fmt.Sprintf("%08x%s", absOpcodeOffset, line[8:])
		}
		fmt.Fprintf(w, "%s\n", line)
		fmt.Fprintf(w, "    opcode byte:  file offset 0x%08x, length 1, value 0x%02x\n", absOpcodeOffset, pi.Inst.Opcode)

		pos := absOpcodeOffset + 1
		for i, op := range pi.Inst.Operands {
			var meaning OperandMeaning
			if i < len(pi.Inst.Meanings) {
				meaning = pi.Inst.Meanings[i]
			}
			var arg uint64
			if i < len(pi.Args) {
				arg = pi.Args[i]
			}
			label := operandTypeName(meaning, op)
			fmt.Fprintf(w, "    operand %d (%s):  file offset 0x%08x, length %d, value %s, bytes %s\n",
				i+1, label, pos, op.Size, operandValueString(pi, i, arg), rawBytesHex(arg, op.Size))
			pos += uint32(op.Size)
		}

		fmt.Fprintln(w)

		if pi.NextOffset <= offset {
			break
		}
		offset = pi.NextOffset
	}
}

// rawBytesHex renders the little-endian on-disk byte representation of an
// operand value, exactly as it appears in the file - this is what a person
// should search for / overwrite in a hex editor.
func rawBytesHex(value uint64, size int) string {
	b := make([]byte, size)
	for i := 0; i < size; i++ {
		b[i] = byte(value >> (8 * uint(i)))
	}
	parts := make([]string, size)
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}

// DisassembleAllPatchMap writes the patch map for every function in the file.
func (d *Disassembler) DisassembleAllPatchMap(w io.Writer) {
	for funcIdx := range d.File.FunctionHeaders {
		d.DisassembleFunctionPatchMap(funcIdx, w)
	}
}
