// Package arm64lift lifts disassembled ARM64 instructions
// (native.DetailedInstruction) into this project's existing IR
// (internal/ir), the same target representation the JVM decompiler
// produces - reusing the IR means the same Java-style generator/renderer
// infrastructure could eventually render lifted ARM64 code too (as
// C-like syntax, since the IR itself is expression/statement-oriented
// and not Java-specific at the node level).
//
// Unlike JVM bytecode's stack machine, ARM64 is a register machine: a
// value doesn't get pushed/popped through an implicit stack, it lives in
// a named register (w0, x1, sp, ...) until something overwrites it. The
// lifter's central data structure is therefore a register file mapping
// register name -> the IR expression currently "in" that register,
// updated as each instruction is lifted - not an expression stack like
// the JVM side uses.
package arm64lift

import (
	"fmt"
	"strings"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// LiftFunction lifts a single function's worth of disassembled
// instructions (already isolated by the caller - e.g. by objcopy'ing
// just .text, as in the initial test, or by real function-boundary
// detection later) into IR statements.
//
// paramNames gives the source-level name for each integer/pointer
// argument register in AAPCS64 order (w0/x0 first, w1/x1 second, ...) -
// e.g. []string{"a", "b"} for "int add(int a, int b)". The lifter has no
// way to recover real parameter names on its own (nothing in the binary
// encodes them); callers without better information should just pass
// placeholder names like "a0", "a1".
// BasicBlock is a maximal straight-line run of instructions: control
// enters only at the first instruction and leaves only at the last
// (which is always a branch, conditional branch, or the function's
// final instruction) - the standard definition used throughout the rest
// of this project's JVM-side control-flow reconstruction too, just
// built from ARM64 branch instructions and absolute addresses instead
// of bytecode opcodes and offsets.
type BasicBlock struct {
	StartAddr    uint64
	Instructions []native.DetailedInstruction
	// Succs holds this block's successor addresses in the order a
	// structural matcher (see liftBlockGraph) needs to tell them apart:
	// for a conditional branch, Succs[0] is the "branch taken" target
	// and Succs[1] is the fallthrough (next instruction after the
	// branch) - for an unconditional branch or fallthrough-only block,
	// Succs has exactly one entry.
	Succs []uint64
	// LastCond, if non-nil, is the b.cond (or cbz/cbnz - not yet
	// lifted, see the TODO at the bottom of lift.go) instruction that
	// ends this block, kept alongside Instructions (which also
	// includes it) so callers building an if/else don't need to
	// re-scan for it.
	LastCond *native.DetailedInstruction
}

// buildCFG splits a straight-line instruction stream into basic blocks
// and links them into a graph, using each instruction's own address
// (from Capstone) as the block/edge identifier - unlike the JVM side,
// which works with instruction-slice indices because bytecode offsets
// aren't necessarily instruction-aligned in a convenient way, ARM64
// instructions are always exactly 4 bytes and branch targets are real
// absolute addresses, so addresses double as both.
func buildCFG(instructions []native.DetailedInstruction) []*BasicBlock {
	if len(instructions) == 0 {
		return nil
	}

	// A new block starts at instruction 0, at any branch target, and at
	// the instruction right after any branch (conditional or not) -
	// the standard basic-block leader rules.
	leaders := map[uint64]bool{instructions[0].Address: true}
	for i, inst := range instructions {
		if target, ok := branchTarget(inst); ok {
			leaders[target] = true
		}
		if isAnyBranch(inst) && i+1 < len(instructions) {
			leaders[instructions[i+1].Address] = true
		}
	}

	var blocks []*BasicBlock
	byAddr := make(map[uint64]*BasicBlock)
	var cur *BasicBlock
	for _, inst := range instructions {
		if leaders[inst.Address] {
			cur = &BasicBlock{StartAddr: inst.Address}
			blocks = append(blocks, cur)
			byAddr[inst.Address] = cur
		}
		cur.Instructions = append(cur.Instructions, inst)
	}

	// Wire up successor edges now that every block's start address is
	// known.
	for _, b := range blocks {
		last := b.Instructions[len(b.Instructions)-1]
		if target, ok := branchTarget(last); ok {
			if isConditionalBranch(last) {
				cond := last
				b.LastCond = &cond
				fallthroughAddr := last.Address + uint64(last.Size)
				// Branch-taken target first, fallthrough second - see
				// BasicBlock.Succs' doc comment for why the order
				// matters to callers.
				b.Succs = []uint64{target, fallthroughAddr}
			} else {
				b.Succs = []uint64{target}
			}
		} else if last.Mnemonic != "ret" {
			// Falls through to the next block in address order (no
			// branch at all ended this block - it just ran out of
			// leaders, meaning the next leader is reached by ordinary
			// sequential execution).
			fallthroughAddr := last.Address + uint64(last.Size)
			if _, ok := byAddr[fallthroughAddr]; ok {
				b.Succs = []uint64{fallthroughAddr}
			}
		}
	}

	return blocks
}

// branchTarget returns the absolute target address of a branch
// instruction (b, bl, b.cond) and true, or (0, false) for anything
// else. ARM64's branch instructions encode their target as a single
// immediate operand (the absolute address, since Capstone already
// resolves the PC-relative encoding for us).
func branchTarget(inst native.DetailedInstruction) (uint64, bool) {
	if isCompareBranch(inst) {
		// "cbz/cbnz Rt, label" carries its target as the SECOND operand
		// (the first is the register being tested) - unlike a plain "b"
		// or "b.cond", whose only operand IS the target.
		if len(inst.Operands) != 2 || inst.Operands[1].Type != native.OperandImm {
			return 0, false
		}
		return uint64(inst.Operands[1].Imm), true
	}
	if !isAnyBranch(inst) {
		return 0, false
	}
	if len(inst.Operands) == 0 || inst.Operands[0].Type != native.OperandImm {
		return 0, false
	}
	return uint64(inst.Operands[0].Imm), true
}

// isAnyBranch reports whether inst is any kind of direct branch this
// lifter currently recognizes as ending a basic block: unconditional
// "b", or a conditional "b.cond" (Capstone spells the mnemonic itself
// as "b.eq", "b.le", "b.gt", etc. - the condition is part of the
// mnemonic string, not a separate operand). "bl" (call) deliberately
// does NOT end a block here - a call returns control to the next
// instruction, so it doesn't change the function's own control flow the
// way a real branch does; see the TODO at the bottom of lift.go for
// when calls themselves get lifted.
func isAnyBranch(inst native.DetailedInstruction) bool {
	if inst.Mnemonic == "b" {
		return true
	}
	return isConditionalBranch(inst)
}

// isConditionalBranch reports whether inst is a conditional branch:
// b.eq/b.ne/b.le/b.gt/b.lt/b.ge/... (recognized by mnemonic prefix, since
// Capstone folds the ARM64 condition code into the mnemonic string itself
// rather than exposing it as a separate operand or field), or cbz/cbnz
// (compare-and-branch-on-zero/nonzero - a self-contained condition on one
// register, not a flags test, but still a two-successor branch the same
// as b.cond for CFG purposes; see isCompareBranch).
func isConditionalBranch(inst native.DetailedInstruction) bool {
	if isCompareBranch(inst) {
		return true
	}
	return len(inst.Mnemonic) > 2 && inst.Mnemonic[0] == 'b' && inst.Mnemonic[1] == '.'
}

// isCompareBranch reports whether inst is "cbz Rt, label" or "cbnz Rt,
// label" - ARM64's compare-and-branch instructions, extremely common for
// null/zero checks and loop conditions. Unlike b.cond, these test a
// register directly against zero and don't read the NZCV flags at all,
// so they need their own branchTarget/liftCondition handling rather than
// condOpFromMnemonic's flag-based mapping.
func isCompareBranch(inst native.DetailedInstruction) bool {
	return inst.Mnemonic == "cbz" || inst.Mnemonic == "cbnz"
}

// SymbolResolver resolves a call target's absolute address to a
// human-readable name (e.g. a demangled or mangled C++ symbol, or an
// imported libc function name via PLT resolution) - see
// internal/native's ELFParser.GetSymbolName and ResolvePLT for the two
// real sources callers combine to build one of these. Returns
// ("", false) for an address with no known name.
type SymbolResolver func(addr uint64) (name string, ok bool)

// LiftFunction lifts a single function's worth of disassembled
// instructions into IR statements. See the type's own doc comment for
// paramNames; resolver may be nil, in which case call targets are
// rendered as bare "func_<address>" placeholders.
func LiftFunction(instructions []native.DetailedInstruction, paramNames []string, resolver SymbolResolver) []ir.Stmt {
	l := &lifter{
		regs:     make(map[string]ir.Expr),
		stack:    make(map[int32]string),
		params:   paramNames,
		resolver: resolver,
	}
	l.seedParams()

	blocks := buildCFG(instructions)
	if len(blocks) <= 1 {
		// No branching at all - the original straight-line path handles
		// this case exactly as before CFG support was added.
		return l.run(instructions)
	}

	byAddr := make(map[uint64]*BasicBlock, len(blocks))
	for _, b := range blocks {
		byAddr[b.StartAddr] = b
	}
	return l.liftBlockGraph(blocks[0], byAddr, make(map[uint64]bool))
}

// liftBlockGraph structurally reconstructs if/else from the CFG,
// starting at block b, mirroring this project's JVM-side control-flow
// reconstruction: a block ending in a conditional branch whose two
// successors both eventually reach the same merge block becomes an
// if/else; anything not matching that shape yet is lifted as a flat,
// linear sequence (falls through to the next block without real
// structural recovery) - narrower than the JVM side's matchers, but
// enough for straight-line-with-one-branch functions like this
// package's current test cases.
//
// visited guards against revisiting a block already lifted along this
// path (defensive - real -O0 code without loops shouldn't need it, but
// prevents infinite recursion on unexpected/malformed input rather than
// hanging).
func (l *lifter) liftBlockGraph(b *BasicBlock, byAddr map[uint64]*BasicBlock, visited map[uint64]bool) []ir.Stmt {
	if b == nil || visited[b.StartAddr] {
		return nil
	}
	visited[b.StartAddr] = true

	var stmts []ir.Stmt

	if b.LastCond != nil && len(b.Succs) == 2 {
		// Lift everything in this block up to (but not including) the
		// conditional branch itself as ordinary straight-line code
		// first (e.g. the "cmp" that sets the flags this branch tests).
		bodyInsns := b.Instructions[:len(b.Instructions)-1]
		stmts = append(stmts, l.run(bodyInsns)...)

		cond := l.liftCondition(*b.LastCond)

		thenAddr, elseAddr := b.Succs[0], b.Succs[1]
		thenBlock, thenOk := byAddr[thenAddr]
		elseBlock, elseOk := byAddr[elseAddr]

		// Each branch gets its own copy of visited (not the shared map)
		// - both branches may independently reach the same merge block
		// (e.g. a shared epilogue both paths return through), and each
		// needs to lift it with its OWN register state, not have the
		// second arrival silently blocked because the first already
		// visited it.
		var thenStmts, elseStmts []ir.Stmt
		if thenOk {
			thenLifter := l.fork()
			thenStmts = thenLifter.liftBlockGraph(thenBlock, byAddr, cloneVisited(visited))
		}
		if elseOk {
			elseLifter := l.fork()
			elseStmts = elseLifter.liftBlockGraph(elseBlock, byAddr, cloneVisited(visited))
		}

		stmts = append(stmts, &ir.IfStmt{
			Cond: cond,
			Then: &ir.Block{Statements: thenStmts},
			Else: &ir.Block{Statements: elseStmts},
		})
		return stmts
	}

	// No conditional branch ending this block - lift it straight-line
	// and continue into whichever single successor it has (if any).
	stmts = append(stmts, l.run(b.Instructions)...)
	if len(b.Succs) == 1 {
		if next, ok := byAddr[b.Succs[0]]; ok {
			stmts = append(stmts, l.liftBlockGraph(next, byAddr, visited)...)
		}
	}
	return stmts
}

// fork returns a new lifter that inherits this lifter's current
// register/stack state as of the branch point, but can diverge from it
// independently - needed because the then/else branches of an if
// statement each continue from the SAME starting state (the condition
// hasn't told either branch anything about what's in which register
// beyond the branch itself) but may each assign registers differently
// from that point on, and those assignments must not leak into the
// other branch or back into the parent.
// cloneVisited returns a shallow copy of a visited-block-address set,
// so a branch's own traversal doesn't share mutations with a sibling
// branch's traversal (see liftBlockGraph's if/else case for why this
// matters).
func cloneVisited(visited map[uint64]bool) map[uint64]bool {
	out := make(map[uint64]bool, len(visited))
	for k, v := range visited {
		out[k] = v
	}
	return out
}

func (l *lifter) fork() *lifter {
	regs := make(map[string]ir.Expr, len(l.regs))
	for k, v := range l.regs {
		regs[k] = v
	}
	stack := make(map[int32]string, len(l.stack))
	for k, v := range l.stack {
		stack[k] = v
	}
	return &lifter{regs: regs, stack: stack, params: l.params, lastCmp: l.lastCmp, resolver: l.resolver}
}

// liftCondition lifts a b.cond instruction into the IR condition
// expression for entering the BRANCH-TAKEN path (Succs[0] - see
// BasicBlock.Succs' doc comment) - i.e. the condition as the b.cond
// instruction's own mnemonic states it, not inverted. This mirrors how
// this project's JVM-side buildCondition works: the raw branch
// instruction's condition is what's true when the branch is taken:
// building the caller's if/else around Succs[0]-as-then means using
// that condition directly, with no extra negation needed (unlike a few
// of the JVM-side matchers, which build a condition for entering an
// ordinary if's THEN when the underlying bytecode branch jumps AWAY
// from it - ARM64's b.cond jumping TOWARD the branch-taken block is the
// more direct case).
//
// The comparison operands come from whatever "cmp" instruction most
// recently ran before this branch (ARM64 conditional branches always
// test flags set by an earlier instruction, never their own operands
// directly) - liftCondition relies on l.lastCmp having been populated
// by run() while lifting that cmp, which is why liftBlockGraph lifts a
// block's body (including its own trailing cmp) before calling this.
func (l *lifter) liftCondition(inst native.DetailedInstruction) ir.Expr {
	if isCompareBranch(inst) {
		// cbz/cbnz test their own register operand against zero directly
		// - no preceding cmp involved at all (see isCompareBranch), so
		// this bypasses lastCmp entirely rather than treating a missing
		// cmp as the "not yet handled" case below does for b.cond.
		if len(inst.Operands) == 0 || inst.Operands[0].Type != native.OperandReg {
			return &ir.LocalVar{Name: "cond"}
		}
		op := "=="
		if inst.Mnemonic == "cbnz" {
			op = "!="
		}
		return &ir.BinaryExpr{Op: op, Left: l.regValue(inst.Operands[0].Reg), Right: &ir.IntLit{Value: 0}}
	}

	op := condOpFromMnemonic(inst.Mnemonic)
	if l.lastCmp == nil {
		// No preceding cmp was lifted (e.g. this branch tests flags
		// from something other than a plain "cmp", like "tst" or an
		// arithmetic instruction's own flag-setting side effect - not
		// yet handled) - fall back to a placeholder rather than
		// guessing operands that would be actively wrong.
		return &ir.LocalVar{Name: "cond"}
	}
	return &ir.BinaryExpr{Op: op, Left: l.lastCmp.lhs, Right: l.lastCmp.rhs}
}

// condOpFromMnemonic maps an ARM64 b.cond mnemonic's condition suffix
// to the Java/C-style comparison operator meaning "the branch is
// taken" - e.g. "b.le" (branch if less-or-equal) maps to "<=", matching
// liftCondition's convention of building the condition for the
// branch-taken path directly (see its doc comment).
func condOpFromMnemonic(mnemonic string) string {
	switch mnemonic {
	case "b.eq":
		return "=="
	case "b.ne":
		return "!="
	case "b.lt", "b.mi":
		// b.mi (negative) after a cmp is the signed "<" case: cmp lhs,
		// rhs sets N=1 exactly when lhs-rhs is negative, i.e. lhs < rhs.
		return "<"
	case "b.le":
		return "<="
	case "b.gt":
		return ">"
	case "b.ge", "b.pl":
		// b.pl (positive-or-zero) is signed ">=" by the same reasoning
		// as b.mi above.
		return ">="
	case "b.hi":
		// Unsigned '>' - this project's IR doesn't distinguish signed
		// from unsigned comparisons, so this renders identically to the
		// signed operator; wrong only when the operands could actually
		// be negative, which is rare for the size/length/pointer
		// comparisons that generate b.hi/b.ls/b.hs/b.lo in practice.
		return ">"
	case "b.ls":
		return "<="
	case "b.hs", "b.cs":
		return ">="
	case "b.lo", "b.cc":
		return "<"
	default:
		// b.vs/b.vc (signed overflow) and b.al/b.nv (always) don't fit
		// this lhs-op-rhs shape at all - true overflow-flag testing has
		// no plain comparison equivalent, and an unconditional-as-if-
		// conditional branch shouldn't be built from this path in the
		// first place. Left as an honest placeholder rather than a
		// guess; see the TODO at the bottom of this file.
		return "?"
	}
}

// lifter holds the running state while lifting one function.
type lifter struct {
	// regs maps a register name (as Capstone spells it: "w0", "x1",
	// "sp", ...) to the IR expression currently held there. Updated on
	// every instruction that writes a register; read whenever a later
	// instruction uses that register as a source operand.
	regs map[string]ir.Expr

	// stack maps a stack-frame displacement (the #N in "[sp, #N]") to
	// the source-level local variable name that displacement was
	// recognized as representing - populated the first time a
	// parameter-carrying register is spilled to that slot, so a later
	// reload from the same slot resolves back to the same named
	// variable instead of inventing a new one.
	stack map[int32]string

	// params holds the declared parameter names in AAPCS64 register
	// order, as given to LiftFunction.
	params []string

	// lastCmp holds the operands of the most recently lifted "cmp"
	// instruction, consumed by liftCondition when a following b.cond
	// needs to know what's actually being compared (ARM64 conditional
	// branches always test flags set by an earlier instruction, never
	// carry their own comparison operands).
	lastCmp *cmpOperands

	// resolver resolves a call target address to a human-readable name,
	// as given to LiftFunction. May be nil.
	resolver SymbolResolver
}

// cmpOperands is the lhs/rhs of a lifted "cmp" instruction, in the
// order the instruction itself specifies (cmp Rn, Rm compares Rn - Rm,
// so lhs=Rn, rhs=Rm) - condOpFromMnemonic's operator meanings assume
// this same left-to-right order.
type cmpOperands struct {
	lhs, rhs ir.Expr
}

// aapcs64IntArgRegs lists the integer/pointer argument registers in
// AAPCS64 (ARM64 procedure call standard) order - the Nth entry is
// where the Nth integer/pointer parameter arrives. 32-bit ("w") and
// 64-bit ("x") names alias the same physical register; a function
// taking `int` parameters (as in our test case) sees them as w0, w1,
// ... - one lifted local per parameter regardless of which width the
// prologue happens to use to spill it.
var aapcs64IntArgRegs = []string{"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}

// aapcs64IntArgRegs32 is the 32-bit aliasing view of the same registers,
// index-for-index with aapcs64IntArgRegs.
var aapcs64IntArgRegs32 = []string{"w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"}

// paramNameForReg returns the declared parameter name for a register if
// it's one of the AAPCS64 integer argument registers within range of
// the caller-supplied paramNames, and ok=false otherwise (a register
// that isn't a recognized argument register at all, e.g. sp or an
// argument register beyond how many parameters this function actually
// has).
func (l *lifter) paramNameForReg(reg string) (string, bool) {
	for i, r := range aapcs64IntArgRegs {
		if reg == r || reg == aapcs64IntArgRegs32[i] {
			if i < len(l.params) {
				return l.params[i], true
			}
			return "", false
		}
	}
	return "", false
}

// seedParams initializes each declared parameter's home register(s) to
// an IR reference to that parameter's name - this is what lets a
// prologue's "str w0, [sp, #12]" (spilling the first parameter to the
// stack, the standard -O0 codegen pattern) be recognized as "this stack
// slot IS parameter a", not some anonymous store. Must be called
// exactly ONCE per function (not per basic block - see LiftFunction's
// callers), since calling it again after a branch has already updated a
// register (e.g. w0 holding a computed/loaded value, not the original
// parameter) would silently discard that value and reset the register
// back to the parameter, which is exactly the bug this comment is
// warning against re-introducing.
func (l *lifter) seedParams() {
	for i, name := range l.params {
		if i >= len(aapcs64IntArgRegs) {
			break
		}
		ref := &ir.LocalVar{Name: name}
		l.regs[aapcs64IntArgRegs[i]] = ref
		l.regs[aapcs64IntArgRegs32[i]] = ref
	}
}

func (l *lifter) run(instructions []native.DetailedInstruction) []ir.Stmt {
	var stmts []ir.Stmt

	for _, inst := range instructions {
		switch inst.Mnemonic {
		case "add":
			if isSpAdjust(inst) {
				// "add sp, sp, #N" is the matching -O0 epilogue - same
				// reasoning as the sub case below.
				continue
			}
			l.liftBinaryALU(inst, "+")
		case "sub":
			// "sub sp, sp, #N" is the standard -O0 prologue reserving
			// stack frame space - not part of the source program's own
			// logic (no C statement corresponds to it), so it's
			// recognized and silently skipped rather than lifted into
			// a meaningless "sp = sp - 16" statement. Any other "sub" is
			// a real subtraction.
			if isSpAdjust(inst) {
				continue
			}
			l.liftBinaryALU(inst, "-")
		case "and":
			l.liftBinaryALU(inst, "&")
		case "orr":
			l.liftBinaryALU(inst, "|")
		case "eor":
			l.liftBinaryALU(inst, "^")
		case "mul":
			l.liftBinaryALU(inst, "*")
		case "stp":
			// "stp x29, x30, [sp, #-N]!" is the standard -O0
			// frame-pointer prologue (saving the caller's frame
			// pointer and return address before establishing this
			// function's own frame) - not part of the source program's
			// own logic, same reasoning as the sub/sp-adjust prologue
			// case above. Any other "stp" shape is deliberately NOT
			// specially handled yet - falls through unlifted; see the
			// TODO at the bottom of this file.
			if isFramePointerSave(inst) {
				continue
			}
		case "ldp":
			// "ldp x29, x30, [sp], #N" is the matching -O0
			// frame-pointer epilogue - same reasoning as stp above.
			if isFramePointerRestore(inst) {
				continue
			}
		case "mov":
			// "mov x29, sp" (establishing the frame pointer, standard
			// -O0 prologue) has no source-level meaning of its own -
			// recognized and skipped. Any other "mov" shape falls
			// through unlifted for now; see the TODO at the bottom of
			// this file.
			if isFramePointerEstablish(inst) {
				continue
			}
		case "str":
			if s := l.liftStr(inst); s != nil {
				stmts = append(stmts, s)
			}
		case "ldr":
			l.liftLdr(inst)
		case "cmp":
			l.liftCmp(inst)
		case "bl":
			l.liftCall(inst)
		case "cset":
			l.liftCset(inst)
		case "ret":
			stmts = append(stmts, l.liftRet())
		}
	}

	return stmts
}

// isSpAdjust reports whether inst is "{add,sub} sp, sp, #N" - the
// -O0 prologue/epilogue shape for reserving/releasing stack frame
// space, which carries no source-level meaning of its own.
func isSpAdjust(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 3 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "sp" {
		return false
	}
	if inst.Operands[1].Type != native.OperandReg || inst.Operands[1].Reg != "sp" {
		return false
	}
	return inst.Operands[2].Type == native.OperandImm
}

// isFramePointerSave reports whether inst is "stp x29, x30, [sp,
// #-N]!" - the standard -O0 frame-pointer prologue instruction, saving
// the caller's frame pointer (x29) and this call's return address
// (x30, the link register) onto the new stack frame being established.
// The "!" (pre-indexed writeback) means this instruction ALSO performs
// the sp adjustment itself, combining what isSpAdjust's plain "sub sp,
// sp, #N" case handles separately when a function doesn't need a full
// stack frame.
func isFramePointerSave(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 3 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "x29" {
		return false
	}
	if inst.Operands[1].Type != native.OperandReg || inst.Operands[1].Reg != "x30" {
		return false
	}
	return inst.Operands[2].Type == native.OperandMem && inst.Operands[2].Mem.Base == "sp"
}

// isFramePointerRestore reports whether inst is "ldp x29, x30, [sp],
// #N" - the matching -O0 frame-pointer epilogue, restoring the
// caller's frame pointer and this call's own return address before
// returning.
func isFramePointerRestore(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 4 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "x29" {
		return false
	}
	if inst.Operands[1].Type != native.OperandReg || inst.Operands[1].Reg != "x30" {
		return false
	}
	if inst.Operands[2].Type != native.OperandMem || inst.Operands[2].Mem.Base != "sp" {
		return false
	}
	return inst.Operands[3].Type == native.OperandImm
}

// isFramePointerEstablish reports whether inst is "mov x29, sp" -
// pointing the frame-pointer register at the just-established stack
// frame, immediately after isFramePointerSave's stp. Has no
// source-level meaning of its own.
func isFramePointerEstablish(inst native.DetailedInstruction) bool {
	if len(inst.Operands) != 2 {
		return false
	}
	if inst.Operands[0].Type != native.OperandReg || inst.Operands[0].Reg != "x29" {
		return false
	}
	return inst.Operands[1].Type == native.OperandReg && inst.Operands[1].Reg == "sp"
}

// liftStr lifts "str Rt, [Rn, #disp]" - a store to memory. Two shapes are
// recognized:
//
//  1. Rn is sp: the -O0 prologue pattern of spilling an incoming
//     parameter-carrying register to its own stack slot immediately on
//     function entry, so the register itself is free to be reused later.
//     Not lifted into a store statement at all, since it has no source-
//     level equivalent; it just teaches the lifter that this stack slot
//     means this parameter, so a later "ldr" from the same slot resolves
//     back to it (see liftLdr). Returns nil (nothing to emit).
//  2. Rn is any other register: a real pointer write - "str x1, [x0,
//     #8]" is x0->field_0x8 = x1, the standard shape for "this->member =
//     value" (or any other pointer's field write) at -O0. Unlike the
//     stack-slot case, this DOES have direct source-level meaning, so it
//     returns a real AssignStmt for run() to include in the function's
//     body. The field is named generically after its byte offset
//     (field_0xN) since nothing in the binary records the real member
//     name without DWARF; see the TODO at the bottom of this file.
//
// Any other shape (indexed addressing, a non-register source, ...) isn't
// lifted yet - returns nil, same as case 1.
func (l *lifter) liftStr(inst native.DetailedInstruction) ir.Stmt {
	if len(inst.Operands) != 2 {
		return nil
	}
	srcOp, dstOp := inst.Operands[0], inst.Operands[1]
	if srcOp.Type != native.OperandReg || dstOp.Type != native.OperandMem {
		return nil
	}
	if dstOp.Mem.Index != "" {
		return nil
	}

	if dstOp.Mem.Base == "sp" {
		if name, ok := l.paramNameForReg(srcOp.Reg); ok {
			l.stack[dstOp.Mem.Disp] = name
		}
		return nil
	}
	if dstOp.Mem.Base == "" {
		return nil
	}

	field := &ir.FieldAccess{Object: l.regValue(dstOp.Mem.Base), Name: fieldName(dstOp.Mem.Disp)}
	return &ir.AssignStmt{Target: field, Value: l.regValue(srcOp.Reg)}
}

// liftLdr lifts "ldr Rt, [Rn, #disp]" - a load from memory. Two shapes
// are recognized, mirroring liftStr:
//
//  1. Rn is sp, and this displacement was previously recorded (by
//     liftStr) as holding a named parameter: the destination register
//     now holds an IR reference to that same parameter (not a "load"
//     statement - there's nothing to say at the source level; the
//     parameter's value simply flows into the register that will use it
//     next).
//  2. Rn is any other register: a real pointer read - "ldr x1, [x0, #8]"
//     is x1 = x0->field_0x8, read into the register file the same way
//     an ordinary computed value would be (not emitted as its own
//     statement; becomes source-level meaningful once something actually
//     consumes it, same reasoning as liftBinaryALU/liftCall).
func (l *lifter) liftLdr(inst native.DetailedInstruction) {
	if len(inst.Operands) != 2 {
		return
	}
	dstOp, srcOp := inst.Operands[0], inst.Operands[1]
	if dstOp.Type != native.OperandReg || srcOp.Type != native.OperandMem {
		return
	}
	if srcOp.Mem.Index != "" {
		return
	}

	if srcOp.Mem.Base == "sp" {
		if name, ok := l.stack[srcOp.Mem.Disp]; ok {
			l.regs[dstOp.Reg] = &ir.LocalVar{Name: name}
		}
		return
	}
	if srcOp.Mem.Base == "" {
		return
	}

	l.regs[dstOp.Reg] = &ir.FieldAccess{Object: l.regValue(srcOp.Mem.Base), Name: fieldName(srcOp.Mem.Disp)}
}

// fieldName synthesizes a generic member name for a struct/class field
// access at the given byte displacement - nothing in the binary records
// the real field name without DWARF debug info (which this project
// doesn't consume), so a stable, offset-derived name is used rather than
// guessing; see the TODO at the bottom of this file.
func fieldName(disp int32) string {
	if disp < 0 {
		return fmt.Sprintf("field_neg0x%x", -disp)
	}
	return fmt.Sprintf("field_0x%x", disp)
}

// liftBinaryALU lifts a 3-operand ALU instruction ("add/sub/and/orr/eor/mul
// Rd, Rn, Rm" or "..., Rn, #imm" - register or immediate second source
// operand; ARM64 allows an immediate for add/sub but not for the others,
// though nothing here needs to enforce that distinction since a Capstone
// decode simply won't produce an immediate operand for the instructions
// that can't take one) into an IR BinaryExpr, recorded as Rd's new value
// in the register file - not emitted as a statement yet, since a bare
// arithmetic result with nothing done with it isn't source-level
// meaningful on its own; it becomes a statement once something (a return,
// a store, ...) actually consumes it.
func (l *lifter) liftBinaryALU(inst native.DetailedInstruction, op string) {
	if len(inst.Operands) != 3 {
		return
	}
	dstOp, lhsOp, rhsOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if dstOp.Type != native.OperandReg || lhsOp.Type != native.OperandReg {
		return
	}

	lhs := l.regValue(lhsOp.Reg)
	var rhs ir.Expr
	switch rhsOp.Type {
	case native.OperandReg:
		rhs = l.regValue(rhsOp.Reg)
	case native.OperandImm:
		rhs = &ir.IntLit{Value: rhsOp.Imm}
	default:
		return
	}
	l.regs[dstOp.Reg] = &ir.BinaryExpr{Op: op, Left: lhs, Right: rhs}
}

// liftCall lifts "bl <addr>" - a direct function call. The target
// address is resolved to a readable name via l.resolver if one was
// given to LiftFunction (falling back to a "func_<address>" placeholder
// otherwise), and the call expression is recorded as the new value of
// w0/x0 (AAPCS64's return-value register) - not emitted as a statement
// of its own, mirroring liftAdd's reasoning: the call's result only
// becomes source-level meaningful once something (a return, a
// comparison, ...) actually consumes it. A call whose result is never
// used (a real void call, or one made purely for side effects) is not
// yet handled - see the TODO at the bottom of this file; it would need
// to be emitted as its own ExprStmt when nothing ever reads w0/x0
// afterward.
//
// Argument recovery (reading x0-x7 as the call's own arguments, the way
// this lifter reads them for the FUNCTION currently being lifted in
// seedParams) is not implemented yet - the call is lifted as a
// zero-argument call regardless of what's actually in those registers
// at the call site. See the TODO at the bottom of this file.
func (l *lifter) liftCall(inst native.DetailedInstruction) {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandImm {
		return
	}
	target := uint64(inst.Operands[0].Imm)

	rawName := fmt.Sprintf("func_%x", target)
	resolved := false
	if l.resolver != nil {
		if n, ok := l.resolver(target); ok {
			rawName = n
			resolved = true
		}
	}
	name := demangle(rawName)

	// Collect arguments from x0-x7 (AAPCS64's integer/pointer argument
	// registers) as they stand right now, before this call overwrites
	// any of them with its own return value - stopping at the first
	// register this lifter never actually assigned a value to (see
	// regValue's own placeholder-on-miss behavior; checked directly
	// against l.regs here rather than through regValue, since regValue
	// itself can't distinguish "genuinely holds this register's raw
	// value because nothing overwrote it" from "known assigned value").
	// This is a heuristic, not a real signature lookup (nothing in the
	// binary reliably encodes how many arguments a given call actually
	// passes) - it works for the common case where a function's own
	// argument-passing code runs immediately before the call and
	// doesn't happen to also touch unrelated argument registers for
	// other reasons, but can overcount or undercount on more unusual
	// codegen. See the TODO at the bottom of this file.
	var args []ir.Expr
	for _, reg := range aapcs64IntArgRegs {
		v, ok := l.regs[reg]
		if !ok {
			break
		}
		args = append(args, v)
	}

	// A mangled Itanium C++ instance method name (recognized by the
	// standard "_ZN...E" nested-name pattern, as opposed to a free
	// function's "_Z<len><name>") always receives the implicit `this`
	// pointer as its first argument - render it as the call's receiver
	// rather than an ordinary first argument, for readability. Not
	// reliable for a STATIC member function (mangled the same way, but
	// with no real `this`) - there's no way to tell the two apart from
	// the mangled name alone without a real demangler that understands
	// the full grammar; see the TODO at the bottom of this file.
	//
	// Also excluded: args[0] itself being a call result (*MethodCall or
	// *StaticMethodCall) - without real stack-slot tracking, this
	// lifter can't tell "x0 holds a genuinely-reloaded object pointer"
	// from "x0 still holds the PREVIOUS call's leftover return value"
	// in general, but it CAN identify this one case, which is never a
	// valid `this` (a real `this` is a variable/pointer value, not
	// literally the return value of some unrelated call) - excluding it
	// avoids the worst symptom (a nonsensical call1().call2().call3()
	// dot-chain from independent sequential calls) even though the
	// underlying ambiguity for other cases remains unresolved. See the
	// TODO at the bottom of this file.
	isCallResult := false
	if len(args) > 0 {
		switch args[0].(type) {
		case *ir.MethodCall, *ir.StaticMethodCall:
			isCallResult = true
		}
	}

	var call ir.Expr
	if resolved && looksLikeInstanceMethod(rawName) && len(args) > 0 && !isCallResult {
		call = &ir.MethodCall{Object: args[0], Name: methodNameOnly(name), Args: args[1:]}
	} else {
		call = &ir.StaticMethodCall{Method: name, Args: args}
	}

	// x0-x7 (and their w-register aliases) are caller-saved per
	// AAPCS64 - the called function is free to clobber any of them, so
	// whatever was sitting in them before this call is no longer
	// trustworthy afterward. Without this, a value left over from some
	// earlier, unrelated assignment would still look "meaningfully
	// assigned" to a LATER call's own argument-collection loop above,
	// wrongly reusing stale arguments (or a previous call's own result)
	// as if they belonged to this one.
	for i := range aapcs64IntArgRegs {
		delete(l.regs, aapcs64IntArgRegs[i])
		delete(l.regs, aapcs64IntArgRegs32[i])
	}

	l.regs["w0"] = call
	l.regs["x0"] = call
}

// looksLikeInstanceMethod reports whether a raw (still-mangled) Itanium
// C++ symbol name has the "_ZN...E" nested-name shape used for
// namespace/class members - a heuristic, not a real demangler: it
// can't distinguish a STATIC member function (mangled identically, but
// with no real `this` receiver) from an instance method. See
// liftCall's own doc comment for why that's an accepted limitation for
// now.
func looksLikeInstanceMethod(rawName string) bool {
	return strings.HasPrefix(rawName, "_ZN") && strings.Contains(rawName, "E")
}

// methodNameOnly extracts the last path component of a name that may
// contain "::" separators (e.g. "utils::is_root" -> "is_root") - used
// so a MethodCall's receiver.method(...) rendering doesn't repeat the
// class/namespace qualification a real "obj.method()" call site
// wouldn't spell out redundantly. Falls back to the whole name
// unchanged if it contains no "::".
func methodNameOnly(name string) string {
	if idx := strings.LastIndex(name, "::"); idx >= 0 {
		return name[idx+2:]
	}
	return name
}

// demangle strips the Itanium C++ ABI mangling prefix/wrapper down to
// a bare, readable form for display purposes. This is NOT a real
// demangler (which would need to parse the full mangling grammar -
// template arguments, nested namespaces, cv-qualifiers, and so on) -
// it only recognizes the "_Z" prefix and, when present, falls back to
// showing the mangled name as-is rather than attempting anything more
// sophisticated that could render actively wrong output. A real
// demangler is real, non-trivial future work - see the TODO at the
// bottom of this file.
func demangle(name string) string {
	return name
}

// liftCset lifts "cset Rd, <cond>" - sets Rd to 1 if the condition
// (tested against flags from the most recently lifted cmp, the same
// mechanism liftCondition uses for b.cond) holds, 0 otherwise - the
// standard -O0 codegen for a boolean-returning comparison expression
// like "return a == b;". Unlike b.cond, Capstone doesn't expose cset's
// condition as a separate structured field or operand; it's embedded in
// OpStr as plain text (e.g. "w0, eq"), so it's extracted from there
// directly rather than through inst.Operands.
func (l *lifter) liftCset(inst native.DetailedInstruction) {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandReg {
		return
	}
	dst := inst.Operands[0]

	// OpStr is "Rd, cond" (Capstone's text form) - the condition is
	// whatever's after the last ", ".
	condText := inst.OpStr
	if idx := strings.LastIndex(condText, ", "); idx >= 0 {
		condText = condText[idx+2:]
	}
	op := condOpFromMnemonic("b." + condText)

	if l.lastCmp == nil {
		l.regs[dst.Reg] = &ir.LocalVar{Name: "cond"}
		return
	}
	l.regs[dst.Reg] = &ir.BinaryExpr{Op: op, Left: l.lastCmp.lhs, Right: l.lastCmp.rhs}
}

// regValue returns the IR expression currently associated with a
// register, or a placeholder LocalVar named after the register itself
// if the lifter never assigned it a value (e.g. a register read before
// any recognized write - this keeps lifting total/non-panicking on
// instruction shapes not yet handled, at the cost of an honestly-ugly
// "w3"-named variable in the output rather than a wrong guess).
// liftCmp lifts "cmp Rn, Rm" - not into a statement of its own (a bare
// comparison with the result discarded has no source-level meaning by
// itself), but into l.lastCmp, for a following b.cond to build its
// actual condition expression from (see liftCondition).
func (l *lifter) liftCmp(inst native.DetailedInstruction) {
	if len(inst.Operands) != 2 {
		return
	}
	lhsOp, rhsOp := inst.Operands[0], inst.Operands[1]
	if lhsOp.Type != native.OperandReg {
		return
	}
	lhs := l.regValue(lhsOp.Reg)

	switch rhsOp.Type {
	case native.OperandReg:
		l.lastCmp = &cmpOperands{lhs: lhs, rhs: l.regValue(rhsOp.Reg)}
	case native.OperandImm:
		l.lastCmp = &cmpOperands{lhs: lhs, rhs: &ir.IntLit{Value: rhsOp.Imm}}
	}
}

func (l *lifter) regValue(reg string) ir.Expr {
	if v, ok := l.regs[reg]; ok {
		return v
	}
	return &ir.LocalVar{Name: reg}
}

// liftRet lifts "ret" into a return statement carrying whatever value
// is currently in w0/x0 (the AAPCS64 return-value register) - the
// standard C calling convention's return slot.
func (l *lifter) liftRet() ir.Stmt {
	val := l.regValue("w0")
	if v, ok := l.regs["x0"]; ok {
		// Prefer x0 if it's the one that was actually written (a
		// 64-bit-returning function would write x0, not w0) - w0 is
		// just the default fallback for the common 32-bit-int-return
		// case our test targets.
		if _, w0Set := l.regs["w0"]; !w0Set {
			val = v
		}
	}
	return &ir.ReturnStmt{Value: val}
}

// TODO(next iterations): what this lifter now handles, beyond the
// original "int add(int a, int b) { return a + b; }" -O0 baseline:
// immediate and register ALU (add/sub/and/orr/eor/mul), if/else via
// cmp+b.cond AND cbz/cbnz, unsigned/negative/positive condition codes
// (b.hi/b.ls/b.hs/b.lo/b.mi/b.pl - see condOpFromMnemonic), calls, and
// pointer field access (str/ldr through a non-sp base register). Real
// growth areas still open, roughly in order of how often real-world -O0
// C++ needs them:
//
//   - Loops. liftBlockGraph only recognizes the if/else shape (both
//     successors reachable, neither looping back); a conditional branch
//     whose target is its own block's start address (or an ancestor's)
//     is a real loop, and today just gets treated as an already-visited
//     block and silently dropped instead of becoming a WhileStmt/ForStmt.
//     This is probably the single biggest gap against real code, which
//     is full of loops (see this package's own arm64lift work driven by
//     the il2cpp_memory_dumper sample: parse_maps, hex_to_u64, trim,
//     split, find_il2cpp_api all loop).
//   - Array/indexed memory access (MemOperand.Index isn't consulted by
//     liftStr/liftLdr at all yet - only [base, #disp] is handled, not
//     [base, index] or [base, index, lsl #N]).
//   - Exception-handling control flow (try/catch, __cxa_begin_catch/
//     __cxa_end_catch, landing pads reached via the LSDA/.gcc_except_table
//     rather than an ordinary branch) is indistinguishable from normal
//     control flow to this lifter right now, and gets lifted as if it
//     were - actively misleading rather than merely incomplete.
//   - Call argument recovery is a heuristic (see liftCall's own doc
//     comment) - registers left over from unrelated earlier code can be
//     misattributed as a call's arguments.
//   - tbz/tbnz (bit-test-and-branch) aren't recognized as branches at
//     all yet, unlike cbz/cbnz.
//   - A real Itanium demangler (see demangle's doc comment) instead of
//     showing mangled names as-is.
