package hermes

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Token types for the IR
type TokenType int

const (
	TokenRaw TokenType = iota
	TokenReg
	TokenAssign
	TokenLParen
	TokenRParen
	TokenDot
	TokenIndexStr
	TokenReturn
	TokenThrow
	TokenJumpCond
	TokenJumpNotCond
	TokenFuncRef
	TokenCatchStart
	TokenSwitchImm
	TokenForInInit
	TokenForInNext
	TokenGetEnv
	TokenStoreEnv
	TokenLoadEnv
	TokenNewEnv
	TokenNewInnerEnv
)

type Token struct {
	Type   TokenType
	Text   string
	Reg    int
	Target uint32
	IntVal int
}

func (t Token) String() string {
	switch t.Type {
	case TokenRaw:
		return t.Text
	case TokenReg:
		return fmt.Sprintf("r%d", t.Reg)
	case TokenAssign:
		return " = "
	case TokenLParen:
		return "("
	case TokenRParen:
		return ")"
	case TokenDot:
		return "."
	case TokenIndexStr:
		return "[\"" + t.Text + "\"]"
	case TokenReturn:
		return "return "
	case TokenThrow:
		return "throw "
	case TokenJumpCond:
		return "" // handled in output
	case TokenJumpNotCond:
		return "" // handled in output
	case TokenFuncRef:
		return t.Text
	case TokenCatchStart:
		return fmt.Sprintf("catch(r%d)", t.Reg)
	case TokenSwitchImm:
		return "" // handled specially
	case TokenForInInit:
		return "" // handled specially
	case TokenForInNext:
		return "" // handled specially
	case TokenGetEnv:
		return "" // silenced
	case TokenStoreEnv:
		return "" // silenced
	case TokenLoadEnv:
		return t.Text // replaced with var name
	case TokenNewEnv:
		return "" // silenced
	case TokenNewInnerEnv:
		return "" // silenced
	default:
		return t.Text
	}
}

type TokenString struct {
	Tokens    []Token
	Assembly  *ParsedInstruction
}

func (ts *TokenString) String() string {
	var sb strings.Builder
	for _, t := range ts.Tokens {
		sb.WriteString(t.String())
	}
	return sb.String()
}

// BasicBlock represents a control flow graph node
type BasicBlock struct {
	StartAddr uint32
	EndAddr   uint32

	IsUnconditionalJump bool
	IsConditionalJump   bool
	IsReturn            bool
	IsThrow             bool
	IsSwitch            bool
	IsYield             bool

	AnchorInst  *ParsedInstruction
	JumpTargets []uint32

	Children  []*BasicBlock
	Parents   []*BasicBlock
	StayVisible bool
}

// DecompilerState holds the state for decompiling a function
type DecompilerState struct {
	File         *HBCFile
	Table        map[byte]*InstructionDef
	FuncIdx      int
	FuncHeader   *SmallFunctionHeader
	FunctionName string
	IndentLevel  int
	CallDirectIDs map[int]bool
}

// DecompiledBody holds the decompiled function data
type DecompiledBody struct {
	FunctionID   int
	FuncHeader   *SmallFunctionHeader
	FunctionName string
	IsGlobal     bool
	Statements   []*TokenString
	BasicBlocks  []*BasicBlock
	ExcHandlers  []ExceptionHandlerInfo
	TryStarts    map[uint32][]string
	TryEnds      map[uint32][]string
	CatchTargets map[uint32][]string
	JumpAnchors  map[uint32]*ParsedInstruction
	RetAnchors   map[uint32]*ParsedInstruction
	ThrowAnchors map[uint32]*ParsedInstruction
	JumpTargets  map[uint32]bool
	IndentLevel  int
}

func NewDecompiler(file *HBCFile) *DecompilerState {
	return &DecompilerState{
		File:          file,
		Table:         buildOpcodeTableForVersion(file.Header.Version),
		CallDirectIDs: make(map[int]bool),
	}
}

// DecompileAll decompiles all functions
func (d *DecompilerState) DecompileAll(w io.Writer) {
	fmt.Fprintf(w, "// Hermes bytecode v%d\n", d.File.Header.Version)
	fmt.Fprintf(w, "// %d functions, %d strings\n\n", d.File.Header.FunctionCount, d.File.Header.StringCount)

	// Decompile global function
	globalIdx := int(d.File.Header.GlobalCodeIndex)
	d.decompileFunction(globalIdx, w)
	fmt.Fprintln(w)

	// Decompile any calldirect functions
	ids := make([]int, 0, len(d.CallDirectIDs))
	for id := range d.CallDirectIDs {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		d.decompileFunction(id, w)
		fmt.Fprintln(w)
	}
}

func (d *DecompilerState) decompileFunction(funcIdx int, w io.Writer) {
	if funcIdx >= len(d.File.FunctionHeaders) {
		return
	}

	hdr := &d.File.FunctionHeaders[funcIdx]
	name := "<unknown>"
	if int(hdr.FunctionName) < len(d.File.Strings) {
		name = d.File.Strings[hdr.FunctionName]
	}

	body := &DecompiledBody{
		FunctionID:   funcIdx,
		FuncHeader:   hdr,
		FunctionName: name,
		IsGlobal:     funcIdx == int(d.File.Header.GlobalCodeIndex),
		TryStarts:    make(map[uint32][]string),
		TryEnds:      make(map[uint32][]string),
		CatchTargets: make(map[uint32][]string),
		JumpAnchors:  make(map[uint32]*ParsedInstruction),
		RetAnchors:   make(map[uint32]*ParsedInstruction),
		ThrowAnchors: make(map[uint32]*ParsedInstruction),
		JumpTargets:  make(map[uint32]bool),
	}

	// Get exception handlers
	if hdr.HasExceptionHandler {
		if handlers, ok := d.File.ExcHandlers[funcIdx]; ok {
			body.ExcHandlers = handlers
			for i, h := range handlers {
				body.TryStarts[h.Start] = append(body.TryStarts[h.Start], fmt.Sprintf("try_start_%d", i))
				body.TryEnds[h.End] = append(body.TryEnds[h.End], fmt.Sprintf("try_end_%d", i))
				body.CatchTargets[h.Target] = append(body.CatchTargets[h.Target], fmt.Sprintf("catch_%d", i))
			}
		}
	}

	code := d.File.getCode(funcIdx)
	if len(code) == 0 {
		if !body.IsGlobal {
			fmt.Fprintf(w, "function %s() {}\n", name)
		}
		return
	}

	// Pass 1: Build CFG
	d.pass1BuildCFG(body, code)

	// Pass 2: Transform instructions to tokens
	d.pass2TransformCode(body, code)

	// Output
	d.outputCode(body, w)
}

// Pass 1: Build control flow graph
func (d *DecompilerState) pass1BuildCFG(body *DecompiledBody, code []byte) {
	// Scan all instructions to classify jump targets
	var lastNextPos uint32
	offset := uint32(0)
	for offset < uint32(len(code)) {
		remaining := code[offset:]
		pi := decodeInstruction(remaining, offset, d.Table)
		if pi == nil {
			break
		}

		lastNextPos = pi.NextOffset
		name := pi.Inst.Name

		// Jump instructions
		if name == "Jmp" || name == "JmpLong" || name == "SaveGenerator" || name == "SaveGeneratorLong" {
			body.JumpAnchors[pi.NextOffset] = pi
			if len(pi.Args) > 0 {
				target := offset + uint32(int32(pi.Args[0]))
				body.JumpTargets[target] = true
			}
		} else if strings.HasPrefix(name, "J") {
			body.JumpAnchors[pi.NextOffset] = pi
			if len(pi.Args) > 0 {
				target := offset + uint32(int32(pi.Args[0]))
				body.JumpTargets[target] = true
			}
		} else if name == "SwitchImm" || name == "UIntSwitchImm" {
			body.JumpAnchors[pi.NextOffset] = pi
			if len(pi.Args) > 2 {
				defaultTarget := offset + uint32(int32(pi.Args[2]))
				body.JumpTargets[defaultTarget] = true
			}
			for _, jt := range pi.JumpTable {
				body.JumpTargets[jt] = true
			}
		} else if name == "StringSwitchImm" {
			body.JumpAnchors[pi.NextOffset] = pi
			if len(pi.Args) > 3 {
				defaultTarget := offset + uint32(int32(pi.Args[3]))
				body.JumpTargets[defaultTarget] = true
			}
		} else if name == "Ret" || name == "Unreachable" {
			body.RetAnchors[pi.NextOffset] = pi
		} else if name == "Throw" {
			body.ThrowAnchors[pi.NextOffset] = pi
		}

		offset = pi.NextOffset
	}

	// Compute basic block boundaries
	boundaries := map[uint32]bool{
		0:            true,
		lastNextPos:  true,
	}
	for addr := range body.TryStarts {
		boundaries[addr] = true
	}
	for addr := range body.TryEnds {
		boundaries[addr] = true
	}
	for addr := range body.CatchTargets {
		boundaries[addr] = true
	}
	for addr := range body.JumpAnchors {
		boundaries[addr] = true
	}
	for addr := range body.RetAnchors {
		boundaries[addr] = true
	}
	for addr := range body.ThrowAnchors {
		boundaries[addr] = true
	}
	for addr := range body.JumpTargets {
		boundaries[addr] = true
	}

	// Sort boundaries
	sortedBounds := make([]uint32, 0, len(boundaries))
	for b := range boundaries {
		sortedBounds = append(sortedBounds, b)
	}
	sort.Slice(sortedBounds, func(i, j int) bool { return sortedBounds[i] < sortedBounds[j] })

	// Create basic blocks
	startToBlock := make(map[uint32]*BasicBlock)
	body.BasicBlocks = make([]*BasicBlock, 0)
	mayFallThrough := false

	for i := 1; i < len(sortedBounds); i++ {
		startAddr := sortedBounds[i-1]
		endAddr := sortedBounds[i]

		block := &BasicBlock{
			StartAddr:   startAddr,
			EndAddr:     endAddr,
			StayVisible: true,
		}

		startToBlock[startAddr] = block

		if mayFallThrough && len(body.BasicBlocks) > 0 {
			prev := body.BasicBlocks[len(body.BasicBlocks)-1]
			block.Parents = append(block.Parents, prev)
			prev.Children = append(prev.Children, block)
		}

		mayFallThrough = true

		// Classify block type
		if inst, ok := body.RetAnchors[endAddr]; ok {
			block.IsReturn = true
			block.AnchorInst = inst
			mayFallThrough = false
		} else if inst, ok := body.ThrowAnchors[endAddr]; ok {
			block.IsThrow = true
			block.AnchorInst = inst
			mayFallThrough = false
		} else if inst, ok := body.JumpAnchors[endAddr]; ok {
			block.AnchorInst = inst
			name := inst.Inst.Name
			if name == "Jmp" || name == "JmpLong" {
				block.IsUnconditionalJump = true
				mayFallThrough = false
				if len(inst.Args) > 0 {
					target := inst.Offset + uint32(int32(inst.Args[0]))
					block.JumpTargets = append(block.JumpTargets, target)
				}
			} else if name == "SwitchImm" || name == "UIntSwitchImm" {
				block.IsSwitch = true
				mayFallThrough = false
				if len(inst.Args) > 2 {
					target := inst.Offset + uint32(int32(inst.Args[2]))
					block.JumpTargets = append(block.JumpTargets, target)
				}
				block.JumpTargets = append(block.JumpTargets, inst.JumpTable...)
			} else if name == "StringSwitchImm" {
				block.IsSwitch = true
				mayFallThrough = false
				if len(inst.Args) > 3 {
					target := inst.Offset + uint32(int32(inst.Args[3]))
					block.JumpTargets = append(block.JumpTargets, target)
				}
			} else if name == "SaveGenerator" || name == "SaveGeneratorLong" {
				block.IsYield = true
				if len(inst.Args) > 0 {
					target := inst.Offset + uint32(int32(inst.Args[0]))
					block.JumpTargets = append(block.JumpTargets, target)
				}
			} else if strings.HasPrefix(name, "J") {
				block.IsConditionalJump = true
				if len(inst.Args) > 0 {
					target := inst.Offset + uint32(int32(inst.Args[0]))
					block.JumpTargets = append(block.JumpTargets, target)
				}
			}
		}

		body.BasicBlocks = append(body.BasicBlocks, block)
	}

	// Link jump edges
	for _, block := range body.BasicBlocks {
		for _, target := range block.JumpTargets {
			if targetBlock, ok := startToBlock[target]; ok {
				if !containsBlock(targetBlock, block.Children) {
					block.Children = append(block.Children, targetBlock)
				}
				if !containsBlock(block, targetBlock.Parents) {
					targetBlock.Parents = append(targetBlock.Parents, block)
				}
			}
		}
	}
}

func containsBlock(b *BasicBlock, list []*BasicBlock) bool {
	for _, x := range list {
		if x == b {
			return true
		}
	}
	return false
}

// Pass 2: Transform instructions to token strings
func (d *DecompilerState) pass2TransformCode(body *DecompiledBody, code []byte) {
	body.Statements = make([]*TokenString, 0)

	offset := uint32(0)
	for offset < uint32(len(code)) {
		remaining := code[offset:]
		pi := decodeInstruction(remaining, offset, d.Table)
		if pi == nil {
			break
		}

		ts := d.translateInstruction(body, pi)
		if ts != nil {
			body.Statements = append(body.Statements, ts)
		}

		offset = pi.NextOffset
	}
}

func (d *DecompilerState) translateInstruction(body *DecompiledBody, pi *ParsedInstruction) *TokenString {
	ts := &TokenString{Assembly: pi}
	name := pi.Inst.Name

	switch name {
	// Return
	case "Ret":
		ts.Tokens = []Token{
			{Type: TokenReturn},
			{Type: TokenReg, Reg: int(pi.Args[0])},
		}

	// Throw
	case "Throw":
		ts.Tokens = []Token{
			{Type: TokenThrow},
			{Type: TokenReg, Reg: int(pi.Args[0])},
		}

	// Catch
	case "Catch":
		ts.Tokens = []Token{
			{Type: TokenCatchStart, Reg: int(pi.Args[0])},
		}

	// Unconditional jumps
	case "Jmp", "JmpLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = []Token{
			{Type: TokenJumpCond, Text: "true", Target: target},
		}

	// Conditional jumps (forward = JumpNotCond, backward = JumpCond)
	case "JmpTrue", "JmpTrueLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		reg := int(pi.Args[1])
		ts.Tokens = d.makeJumpTokens(target, pi.Offset, []Token{
			{Type: TokenReg, Reg: reg},
		})

	case "JmpFalse", "JmpFalseLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		reg := int(pi.Args[1])
		ts.Tokens = d.makeJumpTokens(target, pi.Offset, []Token{
			{Type: TokenRaw, Text: "!"},
			{Type: TokenReg, Reg: reg},
		})

	case "JmpUndefined", "JmpUndefinedLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		reg := int(pi.Args[1])
		ts.Tokens = d.makeJumpTokens(target, pi.Offset, []Token{
			{Type: TokenRaw, Text: "typeof "},
			{Type: TokenReg, Reg: reg},
			{Type: TokenRaw, Text: " === 'undefined'"},
		})

	// Comparison jumps
	case "JEqual", "JEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, "==", pi.Args[1], pi.Args[2])

	case "JNotEqual", "JNotEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, "!=", pi.Args[1], pi.Args[2])

	case "JStrictEqual", "JStrictEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, "===", pi.Args[1], pi.Args[2])

	case "JStrictNotEqual", "JStrictNotEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, "!==", pi.Args[1], pi.Args[2])

	case "JLess", "JLessLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, "<", pi.Args[1], pi.Args[2])

	case "JNotLess", "JNotLessLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokensInverted(target, pi.Offset, "<", pi.Args[1], pi.Args[2])

	case "JLessEqual", "JLessEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, "<=", pi.Args[1], pi.Args[2])

	case "JNotLessEqual", "JNotLessEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokensInverted(target, pi.Offset, "<=", pi.Args[1], pi.Args[2])

	case "JGreater", "JGreaterLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, ">", pi.Args[1], pi.Args[2])

	case "JNotGreater", "JNotGreaterLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokensInverted(target, pi.Offset, ">", pi.Args[1], pi.Args[2])

	case "JGreaterEqual", "JGreaterEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokens(target, pi.Offset, ">=", pi.Args[1], pi.Args[2])

	case "JNotGreaterEqual", "JNotGreaterEqualLong":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		ts.Tokens = d.makeCompJumpTokensInverted(target, pi.Offset, ">=", pi.Args[1], pi.Args[2])

	// Typeof jump
	case "JmpTypeOfIs":
		target := pi.Offset + uint32(int32(pi.Args[0]))
		reg := int(pi.Args[1])
		bitmask := uint32(pi.Args[2])
		ts.Tokens = d.makeTypeofJumpTokens(target, pi.Offset, reg, bitmask)

	// Switch
	case "SwitchImm", "UIntSwitchImm":
		ts.Tokens = []Token{
			{Type: TokenSwitchImm, IntVal: int(pi.Args[0]), Target: pi.Offset + uint32(int32(pi.Args[2]))},
		}

	// Arithmetic
	case "Add", "AddN":
		ts.Tokens = d.makeBinOpTokens(pi, " + ")
	case "Sub", "SubN":
		ts.Tokens = d.makeBinOpTokens(pi, " - ")
	case "Mul", "MulN":
		ts.Tokens = d.makeBinOpTokens(pi, " * ")
	case "Div", "DivN":
		ts.Tokens = d.makeBinOpTokens(pi, " / ")
	case "Mod":
		ts.Tokens = d.makeBinOpTokens(pi, " % ")
	case "AddS":
		ts.Tokens = d.makeBinOpTokens(pi, " + ")

	// Bitwise
	case "BitAnd":
		ts.Tokens = d.makeBinOpTokens(pi, " & ")
	case "BitOr":
		ts.Tokens = d.makeBinOpTokens(pi, " | ")
	case "BitXor":
		ts.Tokens = d.makeBinOpTokens(pi, " ^ ")
	case "LShift":
		ts.Tokens = d.makeBinOpTokens(pi, " << ")
	case "RShift":
		ts.Tokens = d.makeBinOpTokens(pi, " >> ")
	case "URshift":
		ts.Tokens = d.makeBinOpTokens(pi, " >>> ")

	// Unary
	case "Negate":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "-"},
			{Type: TokenReg, Reg: int(pi.Args[1])},
		}
	case "Not":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "!"},
			{Type: TokenReg, Reg: int(pi.Args[1])},
		}
	case "BitNot":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "~"},
			{Type: TokenReg, Reg: int(pi.Args[1])},
		}
	case "TypeOf":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "typeof "},
			{Type: TokenReg, Reg: int(pi.Args[1])},
		}

	// Inc/Dec
	case "Inc":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: " + 1"},
		}
	case "Dec":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: " - 1"},
		}

	// Comparison
	case "Eq":
		ts.Tokens = d.makeBinOpTokens(pi, " == ")
	case "StrictEq":
		ts.Tokens = d.makeBinOpTokens(pi, " === ")
	case "Neq":
		ts.Tokens = d.makeBinOpTokens(pi, " != ")
	case "StrictNeq":
		ts.Tokens = d.makeBinOpTokens(pi, " !== ")
	case "Less":
		ts.Tokens = d.makeBinOpTokens(pi, " < ")
	case "LessEq":
		ts.Tokens = d.makeBinOpTokens(pi, " <= ")
	case "Greater":
		ts.Tokens = d.makeBinOpTokens(pi, " > ")
	case "GreaterEq":
		ts.Tokens = d.makeBinOpTokens(pi, " >= ")
	case "InstanceOf":
		ts.Tokens = d.makeBinOpTokens(pi, " instanceof ")
	case "IsIn":
		ts.Tokens = d.makeBinOpTokens(pi, " in ")

	// Move
	case "Mov", "MovLong":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
		}

	// Constants
	case "LoadConstString", "LoadConstStringLongIndex":
		strID := int(pi.Args[1])
		strVal := "<unknown>"
		if strID < len(d.File.Strings) {
			strVal = d.File.Strings[strID]
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: fmt.Sprintf("%q", strVal)},
		}

	case "LoadConstInt":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: fmt.Sprintf("%d", int32(pi.Args[1]))},
		}

	case "LoadConstDouble":
		bits := uint64(pi.Args[1])
		f := float64FromBits(bits)
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: fmt.Sprintf("%g", f)},
		}

	case "LoadConstUInt8":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: fmt.Sprintf("%d", pi.Args[1])},
		}

	case "LoadConstTrue":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "true"},
		}
	case "LoadConstFalse":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "false"},
		}
	case "LoadConstNull":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "null"},
		}
	case "LoadConstUndefined", "LoadConstEmpty":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "undefined"},
		}
	case "LoadConstZero":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "0"},
		}

	// Property access
	case "GetById", "GetByIdShort", "GetByIdLong":
		strID := int(pi.Args[3])
		strVal := ""
		if strID < len(d.File.Strings) {
			strVal = d.File.Strings[strID]
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenDot},
			{Type: TokenRaw, Text: strVal},
		}

	case "GetByIdWithReceiverLong":
		strID := int(pi.Args[4])
		strVal := ""
		if strID < len(d.File.Strings) {
			strVal = d.File.Strings[strID]
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenDot},
			{Type: TokenRaw, Text: strVal},
		}

	case "TryGetById", "TryGetByIdLong":
		strID := int(pi.Args[3])
		strVal := ""
		if strID < len(d.File.Strings) {
			strVal = d.File.Strings[strID]
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenDot},
			{Type: TokenRaw, Text: strVal},
		}

	case "PutByIdLoose", "PutByIdStrict", "PutByIdLooseLong", "PutByIdStrictLong":
		strID := int(pi.Args[3])
		strVal := ""
		if strID < len(d.File.Strings) {
			strVal = d.File.Strings[strID]
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenDot},
			{Type: TokenRaw, Text: strVal},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[2])},
		}

	case "TryPutByIdLoose", "TryPutByIdStrict", "TryPutByIdLooseLong", "TryPutByIdStrictLong":
		strID := int(pi.Args[3])
		strVal := ""
		if strID < len(d.File.Strings) {
			strVal = d.File.Strings[strID]
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenDot},
			{Type: TokenRaw, Text: strVal},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[2])},
		}

	case "PutOwnBySlotIdx", "PutOwnBySlotIdxLong":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: fmt.Sprintf("[%d]", pi.Args[2])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[3])},
		}

	case "GetByVal":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: "["},
			{Type: TokenReg, Reg: int(pi.Args[2])},
			{Type: TokenRaw, Text: "]"},
		}

	case "PutByValLoose", "PutByValStrict":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: "["},
			{Type: TokenReg, Reg: int(pi.Args[2])},
			{Type: TokenRaw, Text: "]"},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[3])},
		}

	case "GetByIndex":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: fmt.Sprintf("[%d]", pi.Args[2])},
		}

	// Object creation
	case "NewObject":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "{}"},
		}

	case "NewArray", "NewFastArray":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "[]"},
		}

	case "NewArrayWithBuffer", "NewArrayWithBufferLong":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: fmt.Sprintf("Array(%d)", pi.Args[1])},
		}

	case "NewObjectWithBuffer", "NewObjectWithBufferLong":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "{}"},
		}

	// Function calls
	case "Call":
		ts.Tokens = d.makeCallTokens(pi, "Call")

	case "Call1":
		ts.Tokens = d.makeCallTokens(pi, "Call1")

	case "Call2":
		ts.Tokens = d.makeCallTokens(pi, "Call2")

	case "Call3":
		ts.Tokens = d.makeCallTokens(pi, "Call3")

	case "Call4":
		ts.Tokens = d.makeCallTokens(pi, "Call4")

	case "Construct":
		ts.Tokens = d.makeCallTokens(pi, "New")

	case "CallBuiltin", "CallBuiltinLong":
		builtinID := int(pi.Args[1])
		builtinName := "builtin"
		if builtinID < len(builtinNames) {
			builtinName = builtinNames[builtinID]
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: builtinName + "("},
			{Type: TokenReg, Reg: int(pi.Args[2])},
			{Type: TokenRaw, Text: ")"},
		}

	// Closure creation
	case "CreateClosure", "CreateClosureLongIndex":
		funcID := int(pi.Args[2])
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenFuncRef, Text: fmt.Sprintf("Function#%d", funcID)},
		}
		d.CallDirectIDs[funcID] = true

	case "CreateGenerator", "CreateGeneratorLongIndex":
		funcID := int(pi.Args[2])
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenFuncRef, Text: fmt.Sprintf("Generator#%d", funcID)},
		}
		d.CallDirectIDs[funcID] = true

	// Parameters
	case "LoadParam", "LoadParamLong":
		paramIdx := int(pi.Args[1])
		paramName := "this"
		if paramIdx > 0 {
			paramName = fmt.Sprintf("a%d", paramIdx-1)
		}
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: paramName},
		}

	// Environment operations (silenced)
	case "CreateEnvironment", "CreateFunctionEnvironment", "CreateTopLevelEnvironment":
		ts.Tokens = []Token{
			{Type: TokenNewEnv, Reg: int(pi.Args[0])},
		}

	case "CreateInnerEnvironment":
		ts.Tokens = []Token{
			{Type: TokenNewInnerEnv, Reg: int(pi.Args[0])},
		}

	case "GetEnvironment", "GetParentEnvironment", "GetClosureEnvironment":
		ts.Tokens = []Token{
			{Type: TokenGetEnv, Reg: int(pi.Args[0])},
		}

	case "StoreToEnvironment", "StoreToEnvironmentL", "StoreNPToEnvironment", "StoreNPToEnvironmentL":
		envReg := int(pi.Args[0])
		slotIdx := int(pi.Args[1])
		valReg := int(pi.Args[2])
		varName := fmt.Sprintf("_env_r%d_slot%d", envReg, slotIdx)
		ts.Tokens = []Token{
			{Type: TokenStoreEnv, Text: varName},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: valReg},
		}

	case "LoadFromEnvironment", "LoadFromEnvironmentL":
		envReg := int(pi.Args[1])
		slotIdx := int(pi.Args[2])
		varName := fmt.Sprintf("_env_r%d_slot%d", envReg, slotIdx)
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenLoadEnv, Text: varName},
		}

	// Type conversions
	case "ToNumber", "ToNumeric", "ToInt32", "ToUint32":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
		}

	// Fast array ops
	case "FastArrayLength":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: ".length"},
		}

	case "FastArrayLoad":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: "["},
			{Type: TokenReg, Reg: int(pi.Args[2])},
			{Type: TokenRaw, Text: "]"},
		}

	case "FastArrayStore":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[1])},
			{Type: TokenRaw, Text: "["},
			{Type: TokenReg, Reg: int(pi.Args[2])},
			{Type: TokenRaw, Text: "]"},
			{Type: TokenAssign},
			{Type: TokenReg, Reg: int(pi.Args[3])},
		}

	// Declare global var
	case "DeclareGlobalVar":
		strID := int(pi.Args[0])
		strVal := ""
		if strID < len(d.File.Strings) {
			strVal = d.File.Strings[strID]
		}
		ts.Tokens = []Token{
			{Type: TokenRaw, Text: fmt.Sprintf("var %s", strVal)},
		}

	// GetGlobalObject
	case "GetGlobalObject":
		ts.Tokens = []Token{
			{Type: TokenReg, Reg: int(pi.Args[0])},
			{Type: TokenAssign},
			{Type: TokenRaw, Text: "globalThis"},
		}

	// ProfilePoint, Debugger, AsyncBreakCheck - skip
	case "ProfilePoint", "Debugger", "AsyncBreakCheck":
		return nil

	// Unreachable
	case "Unreachable":
		ts.Tokens = []Token{
			{Type: TokenRaw, Text: "throw new Error('unreachable')"},
		}

	// ThrowIfEmpty, ThrowIfUndefined - just pass through
	case "ThrowIfEmpty", "ThrowIfUndefined":
		ts.Tokens = []Token{
			{Type: TokenRaw, Text: fmt.Sprintf("// %s r%d, r%d", name, pi.Args[0], pi.Args[1])},
		}

	default:
		// Generic fallback: show as comment
		ts.Tokens = []Token{
			{Type: TokenRaw, Text: fmt.Sprintf("// %s", pi.Format(d.File))},
		}
	}

	return ts
}

func (d *DecompilerState) makeBinOpTokens(pi *ParsedInstruction, op string) []Token {
	return []Token{
		{Type: TokenReg, Reg: int(pi.Args[0])},
		{Type: TokenAssign},
		{Type: TokenReg, Reg: int(pi.Args[1])},
		{Type: TokenRaw, Text: op},
		{Type: TokenReg, Reg: int(pi.Args[2])},
	}
}

func (d *DecompilerState) makeJumpTokens(target, current uint32, condTokens []Token) []Token {
	tokens := make([]Token, 0)
	tokens = append(tokens, condTokens...)
	tokens = append(tokens, Token{Type: TokenJumpNotCond, Target: target})
	return tokens
}

func (d *DecompilerState) makeCompJumpTokens(target, current uint32, op string, reg1, reg2 uint64) []Token {
	return []Token{
		{Type: TokenReg, Reg: int(reg1)},
		{Type: TokenRaw, Text: " " + op + " "},
		{Type: TokenReg, Reg: int(reg2)},
		{Type: TokenJumpNotCond, Target: target},
	}
}

func (d *DecompilerState) makeCompJumpTokensInverted(target, current uint32, op string, reg1, reg2 uint64) []Token {
	// JNotLess r1, r2 -> !(r1 < r2)
	return []Token{
		{Type: TokenRaw, Text: "!("},
		{Type: TokenReg, Reg: int(reg1)},
		{Type: TokenRaw, Text: " " + op + " "},
		{Type: TokenReg, Reg: int(reg2)},
		{Type: TokenRaw, Text: ")"},
		{Type: TokenJumpNotCond, Target: target},
	}
}

func (d *DecompilerState) makeTypeofJumpTokens(target, current uint32, reg int, bitmask uint32) []Token {
	return []Token{
		{Type: TokenRaw, Text: fmt.Sprintf("typeof r%d & 0x%x", reg, bitmask)},
		{Type: TokenJumpNotCond, Target: target},
	}
}

func (d *DecompilerState) makeCallTokens(pi *ParsedInstruction, prefix string) []Token {
	funcReg := int(pi.Args[1])
	argCount := int(pi.Args[2])

	tokens := []Token{
		{Type: TokenReg, Reg: int(pi.Args[0])},
		{Type: TokenAssign},
		{Type: TokenReg, Reg: funcReg},
		{Type: TokenRaw, Text: "("},
	}

	// Arguments follow the function register
	for i := 0; i < argCount && (3+i) < len(pi.Args); i++ {
		if i > 0 {
			tokens = append(tokens, Token{Type: TokenRaw, Text: ", "})
		}
		tokens = append(tokens, Token{Type: TokenReg, Reg: int(pi.Args[3+i])})
	}

	tokens = append(tokens, Token{Type: TokenRaw, Text: ")"})
	return tokens
}

// Output code
func (d *DecompilerState) outputCode(body *DecompiledBody, w io.Writer) {
	indent := strings.Repeat("    ", body.IndentLevel)

	// Function signature
	if !body.IsGlobal {
		if body.FuncHeader.StrictMode {
			fmt.Fprintf(w, "%s'use strict';\n", indent)
		}
		fmt.Fprintf(w, "%sfunction %s(", indent, body.FunctionName)
		params := make([]string, 0)
		for i := uint32(0); i < body.FuncHeader.ParamCount; i++ {
			if i == 0 {
				params = append(params, "this")
			} else {
				params = append(params, fmt.Sprintf("a%d", i-1))
			}
		}
		fmt.Fprintf(w, "%s) {\n", strings.Join(params, ", "))
		body.IndentLevel++
		indent = strings.Repeat("    ", body.IndentLevel)
	}

	// Output for(;;) switch if multiple blocks
	if len(body.BasicBlocks) > 1 {
		fmt.Fprintf(w, "%sfor(var _ip = 0; ; ) switch(_ip) {\n", indent)
		body.IndentLevel++
		indent = strings.Repeat("    ", body.IndentLevel)
	}

	// Track which basic block starts we've seen
	blockStarts := make(map[uint32]bool)
	for _, bb := range body.BasicBlocks {
		blockStarts[bb.StartAddr] = true
	}

	// Output statements
	for _, ts := range body.Statements {
		if ts.Assembly == nil {
			continue
		}

		pos := ts.Assembly.Offset

		// Check for basic block start
		if len(body.BasicBlocks) > 1 && blockStarts[pos] {
			fmt.Fprintf(w, "%scase %d:\n", indent, pos)
		}

		// Check for try/catch markers
		if labels, ok := body.TryStarts[pos]; ok {
			for _, label := range labels {
				fmt.Fprintf(w, "%s// %s\n", indent, label)
			}
		}
		if labels, ok := body.TryEnds[pos]; ok {
			for _, label := range labels {
				fmt.Fprintf(w, "%s// %s\n", indent, label)
			}
		}
		if labels, ok := body.CatchTargets[pos]; ok {
			for _, label := range labels {
				fmt.Fprintf(w, "%s// %s\n", indent, label)
			}
		}

		// Output the statement
		output := ts.String()
		if output != "" {
			// Check if this is a jump/flow statement
			isJump := false
			for _, tok := range ts.Tokens {
				if tok.Type == TokenJumpCond || tok.Type == TokenJumpNotCond {
					isJump = true
					break
				}
			}

			if isJump {
				d.outputJumpStatement(body, ts, indent, w)
			} else {
				fmt.Fprintf(w, "%s%s;\n", indent, output)
			}
		}
	}

	// Close switch
	if len(body.BasicBlocks) > 1 {
		body.IndentLevel--
		indent = strings.Repeat("    ", body.IndentLevel)
		fmt.Fprintf(w, "%s}\n", indent)
	}

	// Close function
	if !body.IsGlobal {
		body.IndentLevel--
		indent = strings.Repeat("    ", body.IndentLevel)
		fmt.Fprintf(w, "%s}\n", indent)
	}
}

func (d *DecompilerState) outputJumpStatement(body *DecompiledBody, ts *TokenString, indent string, w io.Writer) {
	// Find the jump token
	var jumpTok *Token
	var condParts []string

	for _, tok := range ts.Tokens {
		if tok.Type == TokenJumpCond || tok.Type == TokenJumpNotCond {
			jumpTok = &tok
		} else if jumpTok == nil {
			// Condition tokens come before the jump token
			condParts = append(condParts, tok.String())
		}
	}

	if jumpTok == nil {
		fmt.Fprintf(w, "%s%s;\n", indent, ts.String())
		return
	}

	cond := strings.Join(condParts, "")
	target := jumpTok.Target

	if jumpTok.Type == TokenJumpCond {
		// Backward jump = loop back
		if cond == "true" || cond == "" {
			fmt.Fprintf(w, "%s_ip = %d; continue;\n", indent, target)
		} else {
			fmt.Fprintf(w, "%sif(%s) { _ip = %d; continue; }\n", indent, cond, target)
		}
	} else {
		// Forward jump = conditional
		if cond == "false" {
			fmt.Fprintf(w, "%s_ip = %d; continue;\n", indent, target)
		} else if cond == "true" {
			fmt.Fprintf(w, "%s_ip = %d; continue;\n", indent, target)
		} else {
			// Invert the condition for forward jump
			inverted := invertCondition(cond)
			fmt.Fprintf(w, "%sif(%s) { _ip = %d; continue; }\n", indent, inverted, target)
		}
	}
}

func invertCondition(cond string) string {
	cond = strings.TrimSpace(cond)
	if strings.HasPrefix(cond, "!(") && strings.HasSuffix(cond, ")") {
		return cond[2 : len(cond)-1]
	}
	if strings.HasPrefix(cond, "!") {
		return cond[1:]
	}
	return "!(" + cond + ")"
}

func float64FromBits(bits uint64) float64 {
	b := bits
	sign := (b >> 63) != 0
	exponent := int((b >> 52) & 0x7FF)
	mantissa := b & 0xFFFFFFFFFFFFF

	if exponent == 0 {
		if mantissa == 0 {
			if sign {
				return -0.0
			}
			return 0.0
		}
		val := float64(mantissa) / (1 << 52)
		val *= 0x1p-1022
		if sign {
			return -val
		}
		return val
	}

	if exponent == 0x7FF {
		if mantissa == 0 {
			if sign {
				return -1e308
			}
			return 1e308
		}
		return 0.0
	}

	val := 1.0 + float64(mantissa)/(1<<52)
	val *= float64(uint64(1) << uint(exponent-1023))
	if sign {
		return -val
	}
	return val
}
