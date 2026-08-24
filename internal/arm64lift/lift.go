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
	if !isAnyBranch(inst) {
		return 0, false
	}
	if len(inst.Operands) == 0 {
		return 0, false
	}
	// The target is always the LAST operand: "b"/"b.cond" have exactly
	// one (the target itself), "cbz"/"cbnz" put it after the tested
	// register ("cbz Rt, #target"), and "tbz"/"tbnz" put it after both
	// the tested register and the bit index ("tbz Rt, #bit, #target").
	last := inst.Operands[len(inst.Operands)-1]
	if last.Type != native.OperandImm {
		return 0, false
	}
	return uint64(last.Imm), true
}

// isAnyBranch reports whether inst is any kind of direct branch this
// lifter currently recognizes as ending a basic block: unconditional
// "b", or a conditional one (see isConditionalBranch). "bl" (call)
// deliberately does NOT end a block here - a call returns control to
// the next instruction, so it doesn't change the function's own
// control flow the way a real branch does; see the TODO at the bottom
// of lift.go for when calls themselves get lifted.
func isAnyBranch(inst native.DetailedInstruction) bool {
	if inst.Mnemonic == "b" {
		return true
	}
	return isConditionalBranch(inst)
}

// isConditionalBranch reports whether inst is a conditional branch:
// either "b.cond" (Capstone folds the ARM64 condition code into the
// mnemonic string itself, as "b.eq", "b.le", "b.gt", ... - not a
// separate operand or field), "cbz"/"cbnz" (branch if a register
// is/isn't zero - the single most common -O0 idiom for a null/zero
// check or a simple loop counter test, compiled directly from the
// comparison rather than via a separate "cmp"), or "tbz"/"tbnz"
// (branch if a single bit of a register is/isn't set - the standard
// -O0 idiom for testing one flag bit, e.g. "if (flags & (1 << 3))",
// without needing a separate "and"+"cmp" pair) - see liftCondition's
// own handling of all three.
func isConditionalBranch(inst native.DetailedInstruction) bool {
	switch inst.Mnemonic {
	case "cbz", "cbnz", "tbz", "tbnz":
		return true
	}
	return len(inst.Mnemonic) > 2 && inst.Mnemonic[0] == 'b' && inst.Mnemonic[1] == '.'
}

// SymbolResolver resolves a call target's absolute address to a
// human-readable name (e.g. a demangled or mangled C++ symbol, or an
// imported libc function name via PLT resolution) - see
// internal/native's ELFParser.GetSymbolName and ResolvePLT for the two
// real sources callers combine to build one of these. Returns
// ("", false) for an address with no known name.
type SymbolResolver func(addr uint64) (name string, ok bool)

// StringResolver resolves an absolute data address to the string
// literal stored there, if any - see internal/native's
// ELFParser.ReadCString for the real source callers use to build one
// of these. Returns ("", false) for an address that isn't a
// recognized NUL-terminated printable string (not in a data section,
// unterminated, or not text - most likely because it's some other kind
// of data, e.g. a pointer or vtable, not a string literal). May be
// nil, in which case an adrp/adr-computed address is only ever
// rendered as its raw numeric value.
type StringResolver func(addr uint64) (s string, ok bool)

// LiftFunction lifts a single function's worth of disassembled
// instructions into IR statements. See the type's own doc comment for
// paramNames; resolver may be nil, in which case call targets are
// rendered as bare "func_<address>" placeholders; strResolver may be
// nil, in which case a computed data address is rendered as a raw
// number rather than resolved text.
func LiftFunction(instructions []native.DetailedInstruction, paramNames []string, resolver SymbolResolver, strResolver StringResolver) []ir.Stmt {
	budget := blockVisitBudget
	l := &lifter{
		regs:     make(map[string]ir.Expr),
		stack:    make(map[int32]string),
		params:   paramNames,
		resolver: resolver,
		strings:  strResolver,
		addrRegs: make(map[string]uint64),
		consumed: make(map[ir.Expr]bool),
		budget:   &budget,
	}
	l.seedParams()

	blocks := buildCFG(instructions)
	if len(blocks) <= 1 {
		// No branching at all - the original straight-line path handles
		// this case exactly as before CFG support was added. This is
		// also unconditionally a leaf (nothing follows), so any call
		// this straight-line run produced but never used - most
		// commonly a trailing tail call (see liftTailCall) or a
		// mid-function void call - must be flushed as its own statement
		// now, or it would just vanish.
		stmts := l.run(instructions)
		return append(stmts, l.flushRemaining()...)
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
	// See lifter.budget's own doc comment: this bounds the exponential
	// blowup an if/else split with no merge-point sharing is otherwise
	// prone to. Once exhausted, every further call becomes this same
	// O(1) early return, so recursion actually stops quickly rather
	// than merely slowing down.
	if *l.budget <= 0 {
		return nil
	}
	*l.budget--
	visited[b.StartAddr] = true

	var stmts []ir.Stmt

	if b.LastCond != nil && len(b.Succs) == 2 {
		// Lift everything in this block up to (but not including) the
		// conditional branch itself as ordinary straight-line code
		// first (e.g. the "cmp" that sets the flags this branch tests).
		bodyInsns := b.Instructions[:len(b.Instructions)-1]
		stmts = append(stmts, l.run(bodyInsns)...)

		// liftCondition must run BEFORE flushRemaining: a b.cond's
		// operands were already consumed earlier, while running
		// bodyInsns's own "cmp" (so calling it here is a no-op change
		// to consumed either way) - but a cbz/cbnz's tested register is
		// only ever consumed by liftCondition itself (see its own doc
		// comment), and that consumption must land before
		// flushRemaining runs, or a register still holding an
		// unconsumed call result at exactly this point would get
		// flushed as its own spurious statement here and THEN embedded
		// a second time into cond below.
		cond := l.liftCondition(*b.LastCond)

		// Anything else this straight-line prefix produced but left
		// unconsumed (by cond above, or by anything else) can never be
		// reached by name from inside EITHER fork below (each gets its
		// own copy of consumed from this point on - see fork's own doc
		// comment), so it must be flushed here, once, in the parent,
		// before the split - not left for one or both forks to
		// (incorrectly, redundantly) flush independently.
		stmts = append(stmts, l.flushRemaining()...)

		thenAddr, elseAddr := b.Succs[0], b.Succs[1]

		if loopStmts, ok := l.tryLiftWhileLoop(b, cond, thenAddr, elseAddr, byAddr, visited); ok {
			return append(stmts, loopStmts...)
		}

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
			return append(stmts, l.liftBlockGraph(next, byAddr, visited)...)
		}
	}
	// A true leaf: either this block has no successor at all, or its
	// one successor address isn't a block we know how to lift (e.g. an
	// external tail-call target already handled by liftTailCall as part
	// of running b.Instructions above). Nothing downstream will ever
	// read whatever this path's straight-line run left sitting unused
	// in a register, so flush it now.
	return append(stmts, l.flushRemaining()...)
}

// findLoopBody walks the single-successor chain of ordinary
// straight-line blocks starting at startAddr (no block in the chain
// may itself end in a conditional branch - see this function's own
// return for why), looking for it to eventually reach a block whose
// sole successor is exactly headAddr - a genuine backward branch to
// headAddr, since blocks are laid out in address order and an
// ordinary forward/fallthrough successor could never reach back to an
// earlier address. This is the only loop body shape this iteration of
// the lifter recognizes: a plain "while (cond) { straight-line body }"
// with no nested branching (an if, a break/continue, or a nested loop
// inside the body) - see the TODO at the bottom of this file for
// those. Returns the chain of blocks making up the body (NOT including
// head itself), in execution order, and ok=true when found; (nil,
// false) for anything else, including startAddr being headAddr itself
// (a zero-block "loop" isn't this shape - most likely, headAddr was
// reached via a chain of blocks that never actually branches backward
// at all, i.e. this isn't a loop in the first place).
func findLoopBody(startAddr, headAddr uint64, byAddr map[uint64]*BasicBlock) ([]*BasicBlock, bool) {
	var chain []*BasicBlock
	seen := make(map[uint64]bool)
	addr := startAddr
	for {
		if addr == headAddr {
			return nil, false
		}
		blk, ok := byAddr[addr]
		if !ok || seen[addr] {
			return nil, false
		}
		seen[addr] = true
		chain = append(chain, blk)
		if blk.LastCond != nil || len(blk.Succs) != 1 {
			return nil, false
		}
		if blk.Succs[0] == headAddr {
			return chain, true
		}
		addr = blk.Succs[0]
	}
}

// tryLiftWhileLoop attempts to recognize head (a block ending in the
// conditional branch already lifted into cond, with thenAddr/elseAddr
// as its two successors - Succs[0]/Succs[1], per BasicBlock.Succs' own
// doc comment) as the standard -O0 "while (cond) { body }" shape:
// exactly one of the two successors leads, via findLoopBody's chain,
// back to head itself (the loop body), while the other is what runs
// after the loop exits. Returns ok=false (with stmts=nil) for any pair
// that isn't this shape, so the caller (liftBlockGraph) falls back to
// treating it as an ordinary if/else.
func (l *lifter) tryLiftWhileLoop(head *BasicBlock, cond ir.Expr, thenAddr, elseAddr uint64, byAddr map[uint64]*BasicBlock, visited map[uint64]bool) ([]ir.Stmt, bool) {
	var chain []*BasicBlock
	var exitAddr uint64
	var whileCond ir.Expr

	if bodyChain, ok := findLoopBody(thenAddr, head.StartAddr, byAddr); ok {
		// Branch-taken enters the body - cond (as lifted, for entering
		// Succs[0] - see liftCondition's own doc comment) IS the
		// while-condition as-is.
		chain, exitAddr, whileCond = bodyChain, elseAddr, cond
	} else if bodyChain, ok := findLoopBody(elseAddr, head.StartAddr, byAddr); ok {
		// Fallthrough enters the body - the branch-taken path is the
		// EXIT, so entering the body means the branch was NOT taken:
		// the real while-condition is cond's negation.
		chain, exitAddr, whileCond = bodyChain, thenAddr, &ir.UnaryExpr{Op: "!", Expr: cond}
	} else {
		return nil, false
	}

	// The body is lifted with its own forked lifter, exactly like an
	// if/else branch (see liftBlockGraph's own reasoning): its
	// register writes are per-iteration state that must not leak into
	// what runs after the loop, which continues below from head's OWN
	// (pre-loop) state - the simplest sound-enough approximation
	// available without real per-iteration dataflow/fixpoint analysis
	// of what's actually in each register after zero-or-more
	// iterations.
	bodyLifter := l.fork()
	var bodyStmts []ir.Stmt
	for i, blk := range chain {
		insns := blk.Instructions
		if i == len(chain)-1 {
			// The final block's own trailing branch back to head is
			// the loop's back-edge itself, not source-level code -
			// same reasoning as excluding head's own conditional
			// branch from bodyInsns in liftBlockGraph.
			insns = insns[:len(insns)-1]
		}
		bodyStmts = append(bodyStmts, bodyLifter.run(insns)...)
	}
	bodyStmts = append(bodyStmts, bodyLifter.flushRemaining()...)

	// The body chain is now fully accounted for - mark it visited in
	// the PARENT's own map (not just the fork's) so the exit
	// continuation below can't wander back into it.
	for _, blk := range chain {
		visited[blk.StartAddr] = true
	}

	stmts := []ir.Stmt{&ir.WhileStmt{Cond: whileCond, Body: &ir.Block{Statements: bodyStmts}}}
	if exitBlock, ok := byAddr[exitAddr]; ok {
		stmts = append(stmts, l.liftBlockGraph(exitBlock, byAddr, visited)...)
	}
	return stmts, true
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
	calls := make([]ir.Expr, len(l.calls))
	copy(calls, l.calls)
	consumed := make(map[ir.Expr]bool, len(l.consumed))
	for k, v := range l.consumed {
		consumed[k] = v
	}
	addrRegs := make(map[string]uint64, len(l.addrRegs))
	for k, v := range l.addrRegs {
		addrRegs[k] = v
	}
	return &lifter{regs: regs, stack: stack, params: l.params, lastCmp: l.lastCmp, resolver: l.resolver, strings: l.strings, addrRegs: addrRegs, calls: calls, consumed: consumed, budget: l.budget}
}

// liftCondition lifts a conditional branch instruction (b.cond or
// cbz/cbnz) into the IR condition expression for entering the
// BRANCH-TAKEN path (Succs[0] - see BasicBlock.Succs' doc comment) -
// i.e. the condition as the instruction's own mnemonic states it, not
// inverted. This mirrors how this project's JVM-side buildCondition
// works: the raw branch instruction's condition is what's true when
// the branch is taken: building the caller's if/else around
// Succs[0]-as-then means using that condition directly, with no extra
// negation needed (unlike a few of the JVM-side matchers, which build
// a condition for entering an ordinary if's THEN when the underlying
// bytecode branch jumps AWAY from it - ARM64's conditional branches
// jumping TOWARD the branch-taken block is the more direct case).
func (l *lifter) liftCondition(inst native.DetailedInstruction) ir.Expr {
	switch inst.Mnemonic {
	case "cbz", "cbnz":
		// Unlike b.cond, cbz/cbnz test their OWN register operand
		// directly against zero - there's no preceding "cmp" to read
		// (see cmpOperands' own doc comment for why b.cond needs one
		// and this doesn't).
		if len(inst.Operands) == 0 || inst.Operands[0].Type != native.OperandReg {
			return &ir.LocalVar{Name: "cond"}
		}
		val := l.regValue(inst.Operands[0].Reg)
		l.consume(val)
		op := "=="
		if inst.Mnemonic == "cbnz" {
			op = "!="
		}
		return &ir.BinaryExpr{Op: op, Left: val, Right: &ir.IntLit{Value: 0}}
	case "tbz", "tbnz":
		// Like cbz/cbnz, tbz/tbnz test their own operand directly -
		// no preceding "cmp" to read - but only a single bit of it
		// ("tbz Rt, #bit, #target": branch when bit #bit of Rt is
		// clear; tbnz when it's set), lifted as the same bit-test
		// expression a real "if (x & (1 << bit))" would use in C.
		if len(inst.Operands) < 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandImm {
			return &ir.LocalVar{Name: "cond"}
		}
		val := l.regValue(inst.Operands[0].Reg)
		l.consume(val)
		bit := &ir.IntLit{Value: 1 << uint(inst.Operands[1].Imm)}
		masked := &ir.BinaryExpr{Op: "&", Left: val, Right: bit}
		op := "=="
		if inst.Mnemonic == "tbnz" {
			op = "!="
		}
		return &ir.BinaryExpr{Op: op, Left: masked, Right: &ir.IntLit{Value: 0}}
	}

	// b.cond: the comparison operands come from whatever "cmp"
	// instruction most recently ran before this branch (ARM64's
	// cmp-based conditional branches always test flags set by an
	// earlier instruction, never carry their own operands) -
	// liftCondition relies on l.lastCmp having been populated by run()
	// while lifting that cmp, which is why liftBlockGraph lifts a
	// block's body (including its own trailing cmp) before calling
	// this.
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
	case "b.lt":
		return "<"
	case "b.le":
		return "<="
	case "b.gt":
		return ">"
	case "b.ge":
		return ">="
	case "b.hs":
		// Unsigned "higher or same" (carry set) - the unsigned
		// counterpart of b.ge, from an unsigned "cmp" (e.g. comparing
		// two size_t/pointer values, or after an unsigned-widening
		// load) rather than a signed one. This project's IR has no
		// separate unsigned comparison operator, so ">=" is used as-is
		// - correct for the common case where both operands are
		// already known non-negative (unsigned types), imprecise only
		// if one is a genuinely negative signed value reinterpreted as
		// unsigned, which -O0 code testing size_t/pointer values (by
		// far the common case for b.hs/b.lo/b.hi/b.ls) doesn't do.
		return ">="
	case "b.lo":
		return "<" // unsigned "lower" (carry clear) - see b.hs's own note.
	case "b.hi":
		return ">" // unsigned "higher" - see b.hs's own note.
	case "b.ls":
		return "<=" // unsigned "lower or same" - see b.hs's own note.
	default:
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

	// strings resolves a data address to the string literal stored
	// there, as given to LiftFunction. May be nil.
	strings StringResolver

	// addrRegs maps a register name to the absolute address it's known
	// to hold as of the most recently lifted instruction - populated by
	// adrp/adr (a fresh page/byte-precise address) and propagated by a
	// following "add Rd, Rn, #imm" (the adrp-page + add-offset idiom
	// AArch64 -O0 code always uses to reach a specific symbol within an
	// adrp's page). This is tracked SEPARATELY from regs (which holds
	// the ordinary IR expression for the register, e.g. a placeholder
	// IntLit of the same address) because the address only becomes
	// interesting - worth trying to resolve to a string literal via
	// strings - at the point a register holding one is actually used
	// (currently: as a call argument, in buildCall) rather than at the
	// point it's computed, since adrp/adr/add are also used for
	// perfectly ordinary integer arithmetic this lifter has no way to
	// distinguish from address computation up front.
	addrRegs map[string]uint64

	// calls holds every call expression this lifter (or an ancestor it
	// was forked from) has produced, in creation order - the ordered
	// half of the "was this call's result ever actually used" tracking
	// that flushRemaining and the inline orphan-detection in setReg/
	// clobberReg rely on to emit a void call as its own statement rather
	// than silently dropping it.
	calls []ir.Expr

	// consumed marks which entries in calls (by expression identity -
	// these are always the same *ir.MethodCall/*ir.StaticMethodCall
	// pointer stored in calls and in regs, never a copy) have been read
	// by something that embeds them into a larger expression (a call's
	// own argument, a cmp/add operand, a return value) or already
	// flushed as their own statement - either way, "already accounted
	// for" and exempt from being flushed again.
	consumed map[ir.Expr]bool

	// budget bounds the total number of liftBlockGraph calls across
	// THIS lifter and every one it's ever been forked from (a pointer,
	// so fork() shares the same underlying counter rather than copying
	// it - see fork's own doc comment) - a hard cap against the
	// exponential blowup an if/else split with no merge-point sharing
	// is inherently prone to: each nested conditional independently
	// forks and re-traverses everything downstream of it on BOTH
	// branches, so a long chain of N nested ifs (not unusual once
	// cbz/cbnz are recognized as conditional branches too - see
	// isConditionalBranch) does O(2^N) total block visits with no
	// bound otherwise. Once exhausted, liftBlockGraph stops recursing
	// and returns what it has so far for that path - an incomplete but
	// bounded-time result beats hanging indefinitely on a real,
	// large -O0 function.
	budget *int
}

// cmpOperands is the lhs/rhs of a lifted "cmp" instruction, in the
// order the instruction itself specifies (cmp Rn, Rm compares Rn - Rm,
// so lhs=Rn, rhs=Rm) - condOpFromMnemonic's operator meanings assume
// this same left-to-right order.
type cmpOperands struct {
	lhs, rhs ir.Expr
}

// blockVisitBudget is the total number of liftBlockGraph calls allowed
// across one entire LiftFunction call (all forks combined) - see the
// lifter.budget field's own doc comment for why this cap exists at
// all. 20000 is generous for any real single function's actual block
// count (typically at most a few hundred) while still keeping even a
// worst-case pathological blowup bounded to a fraction of a second.
const blockVisitBudget = 20000

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
		case "sub":
			// "sub sp, sp, #N" is the standard -O0 prologue reserving
			// stack frame space - not part of the source program's own
			// logic (no C statement corresponds to it), so it's
			// recognized and silently skipped rather than lifted into
			// a meaningless "sp = sp - 16" statement. Any other "sub"
			// (not targeting sp, or not matching this exact shape) is
			// deliberately NOT specially handled yet and falls through
			// unlifted - see the TODO at the bottom of this function.
			if isSpAdjust(inst) {
				continue
			}
		case "add":
			if isSpAdjust(inst) {
				// "add sp, sp, #N" is the matching -O0 epilogue - same
				// reasoning as the sub case above.
				continue
			}
			stmts = append(stmts, l.liftAdd(inst)...)
		case "adrp", "adr":
			stmts = append(stmts, l.liftAddr(inst)...)
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
			// recognized and skipped. Any other "mov" shape is a
			// genuine register-to-register or register-immediate move;
			// see liftMov.
			if isFramePointerEstablish(inst) {
				continue
			}
			stmts = append(stmts, l.liftMov(inst)...)
		case "str":
			l.liftStr(inst)
		case "ldr":
			stmts = append(stmts, l.liftLdr(inst)...)
		case "cmp":
			l.liftCmp(inst)
		case "bl":
			stmts = append(stmts, l.liftCall(inst)...)
		case "cset":
			stmts = append(stmts, l.liftCset(inst)...)
		case "ret":
			stmts = append(stmts, l.liftRet())
		case "b":
			// An unconditional "b" reaching run() at all (rather than
			// ending a block that buildCFG turned into an if/else or a
			// followed successor edge) is this block's own last
			// instruction with nowhere internal left to go - see
			// liftTailCall's own doc comment for why it's only lifted
			// when its target resolves to a known symbol.
			stmts = append(stmts, l.liftTailCall(inst)...)
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

// liftStr lifts "str Rt, [Rn, #disp]" - a store to memory. The only
// shape currently recognized is spilling a parameter-carrying register
// to a stack slot (the -O0 prologue pattern of copying each incoming
// argument register to its own stack slot immediately on function
// entry, so the register itself is free to be reused later) - which
// isn't lifted into a memory-store statement at all, since it has no
// source-level equivalent; it just teaches the lifter that this stack
// slot means this parameter, so a later "ldr" from the same slot
// resolves back to it (see liftLdr).
func (l *lifter) liftStr(inst native.DetailedInstruction) {
	if len(inst.Operands) != 2 {
		return
	}
	srcOp, dstOp := inst.Operands[0], inst.Operands[1]
	if srcOp.Type != native.OperandReg || dstOp.Type != native.OperandMem {
		return
	}
	if dstOp.Mem.Base != "sp" || dstOp.Mem.Index != "" {
		return
	}

	if name, ok := l.paramNameForReg(srcOp.Reg); ok {
		l.stack[dstOp.Mem.Disp] = name
	}
	// A store of anything else (a non-parameter register, or to a slot
	// not otherwise recognized) isn't lifted yet - falls through with
	// no effect, which is safe (produces no statement) but incomplete;
	// see the TODO at the bottom of this file.
}

// liftLdr lifts "ldr Rt, [Rn, #disp]" - a load from memory. The only
// shape currently recognized is reloading a value previously spilled by
// liftStr: if this displacement was recorded as holding a named
// parameter, the destination register now holds an IR reference to that
// same parameter (not a "load" statement - there's nothing to say at
// the source level; the parameter's value simply flows into the
// register that will use it next).
// liftLdr lifts "ldr Rt, [Rn, #disp]" - a load from memory. Two shapes
// are recognized:
//
//   - A stack slot previously spilled by liftStr: if this displacement
//     was recorded as holding a named parameter, the destination
//     register now holds an IR reference to that same parameter (not
//     a "load" statement - there's nothing to say at the source
//     level; the parameter's value simply flows into the register
//     that will use it next).
//   - A GOT/data slot at a known computed address: Rn is a register
//     addrRegs recorded an address for (see its own doc comment,
//     populated by adrp/adr(+add)) - if the resolver knows a name for
//     whatever's stored at that exact address (built from the
//     binary's .rela.dyn relocations - see
//     ELFParser.ResolveGOT's own doc comment for how, e.g., a
//     dynamically-linked std::cout resolves this way), the destination
//     register holds a reference to that name instead of an anonymous
//     loaded value - the common case being a GOT-loaded pointer to a
//     global object that the very next instruction typically uses as
//     an implicit `this`/first argument to some call (an operator<<
//     onto std::cout, say).
//
// Anything else (a load from a register that's neither a stack slot
// nor a known address, or one that IS a known address but doesn't
// resolve to any name) isn't lifted yet, but the destination register
// is still clobbered (see clobberReg): the real CPU DID overwrite it
// with whatever the load actually produced, so leaving its old IR
// value in place would misrepresent it as still holding that stale
// value rather than an unknown freshly-loaded one.
func (l *lifter) liftLdr(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 {
		return nil
	}
	dstOp, srcOp := inst.Operands[0], inst.Operands[1]
	if dstOp.Type != native.OperandReg || srcOp.Type != native.OperandMem {
		return nil
	}
	if srcOp.Mem.Index != "" {
		return nil
	}

	if srcOp.Mem.Base == "sp" {
		if name, ok := l.stack[srcOp.Mem.Disp]; ok {
			return l.setReg(dstOp.Reg, &ir.LocalVar{Name: name})
		}
		return l.clobberReg(dstOp.Reg)
	}

	if base, ok := l.addrRegs[srcOp.Mem.Base]; ok && l.resolver != nil {
		addr := base + uint64(srcOp.Mem.Disp)
		if name, ok := l.resolver(addr); ok {
			return l.setReg(dstOp.Reg, &ir.LocalVar{Name: demangle(name)})
		}
	}

	return l.clobberReg(dstOp.Reg)
}

// liftAdd lifts "add Rd, Rn, Rm" (register-register add) and
// "add Rd, Rn, #imm" (register-immediate) into an IR BinaryExpr,
// recorded as Rd's new value in the register file - not emitted as a
// statement yet, since a bare arithmetic result with nothing done with
// it isn't source-level meaningful on its own; it becomes a statement
// once something (a return, a store, ...) actually consumes it.
func (l *lifter) liftAdd(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 3 {
		return nil
	}
	dstOp, lhsOp, rhsOp := inst.Operands[0], inst.Operands[1], inst.Operands[2]
	if dstOp.Type != native.OperandReg || lhsOp.Type != native.OperandReg {
		return nil
	}

	switch rhsOp.Type {
	case native.OperandReg:
		lhs := l.regValue(lhsOp.Reg)
		rhs := l.regValue(rhsOp.Reg)
		l.consume(lhs)
		l.consume(rhs)
		return l.setReg(dstOp.Reg, &ir.BinaryExpr{Op: "+", Left: lhs, Right: rhs})
	case native.OperandImm:
		// "add Rd, Rn, #imm" - the standard -O0 second half of the
		// adrp+add idiom for reaching an exact symbol within an adrp's
		// page (see liftAddr), but also just ordinary immediate
		// arithmetic when Rn isn't a known address - propagate addrRegs
		// in the former case, alongside lifting the arithmetic either
		// way (nothing here can tell which this is until/unless the
		// result later gets used as a call argument - see buildCall).
		lhs := l.regValue(lhsOp.Reg)
		l.consume(lhs)
		base, isAddr := l.addrRegs[lhsOp.Reg]
		stmts := l.setReg(dstOp.Reg, &ir.BinaryExpr{Op: "+", Left: lhs, Right: &ir.IntLit{Value: rhsOp.Imm}})
		if isAddr {
			l.addrRegs[dstOp.Reg] = base + uint64(rhsOp.Imm)
		}
		return stmts
	default:
		return nil
	}
}

// liftAddr lifts "adrp Xd, #page" and "adr Xd, #addr" - both compute a
// PC-relative absolute address into Xd (Capstone resolves the
// encoded, page- or byte-relative immediate to the final absolute
// address already, the same way it does for branch targets - see
// branchTarget's own note); adrp's is page-aligned and typically needs
// a following "add Xd, Xd, #imm" to reach an exact symbol (see
// liftAdd's immediate case), while adr's is already byte-precise on
// its own. Recorded in addrRegs (see its own doc comment) for later
// resolution to a string literal when the register is actually used;
// also given an ordinary IntLit placeholder in regs so a use this
// lifter doesn't (yet) resolve to a string still degrades to a
// plausible numeric address rather than an unrelated stale value.
func (l *lifter) liftAddr(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg || inst.Operands[1].Type != native.OperandImm {
		return nil
	}
	dst, imm := inst.Operands[0], inst.Operands[1]
	stmts := l.setReg(dst.Reg, &ir.IntLit{Value: imm.Imm})
	l.addrRegs[dst.Reg] = uint64(imm.Imm)
	return stmts
}

// liftMov lifts "mov Rd, Rn" (register-to-register) and "mov Rd, #imm"
// (register-immediate) - the two shapes real -O0 code uses constantly
// to shuttle values into the callee-saved registers (x19-x28) that
// survive across calls, since AAPCS64 lets a callee clobber x0-x18
// freely. A register-to-register move does NOT count as consuming its
// source: it's a rename, not a use, so the value must remain just as
// flushable/embeddable under its new name as it was under the old one
// (see isOrphanCandidate's own reachable-under-another-name check).
func (l *lifter) liftMov(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 2 || inst.Operands[0].Type != native.OperandReg {
		return nil
	}
	dst, src := inst.Operands[0], inst.Operands[1]
	switch src.Type {
	case native.OperandReg:
		return l.setReg(dst.Reg, l.regValue(src.Reg))
	case native.OperandImm:
		return l.setReg(dst.Reg, &ir.IntLit{Value: src.Imm})
	default:
		return nil
	}
}

// buildCall resolves target to a readable name via l.resolver (falling
// back to a "func_<address>" placeholder if resolution fails or there
// is no resolver) and builds the call expression from whatever's
// currently sitting in x0-x7, shared by both liftCall ("bl", an
// ordinary call resolution is optional - an unresolved target still
// gets a placeholder name) and liftTailCall ("b" used as a tail call,
// where requireResolved must be true: an unresolved "b" target is far
// more likely an intra-function loop back-edge this lifter doesn't yet
// understand than a real call, and misreading one as a call to a
// nonsense "func_<addr>" placeholder would be actively worse than the
// current silent skip - see isAnyBranch's own note on "b" ending a
// block). Returns ok=false when requireResolved is true and resolution
// failed - the only failure case, since an ordinary unresolved call
// still produces a usable (if uninformative) placeholder call.
func (l *lifter) buildCall(target uint64, requireResolved bool) (ir.Expr, bool) {
	rawName := fmt.Sprintf("func_%x", target)
	resolved := false
	if l.resolver != nil {
		if n, ok := l.resolver(target); ok {
			rawName = n
			resolved = true
		}
	}
	if requireResolved && !resolved {
		return nil, false
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
		// If this register currently holds a known address (from
		// adrp/adr, possibly via a following add - see addrRegs' own
		// doc comment) and it resolves to an actual string literal,
		// render the literal itself rather than the raw computed
		// address - this is the whole point of tracking addrRegs in
		// the first place. Falls back to the placeholder numeric value
		// already in v when the address doesn't resolve (most likely:
		// it's some other kind of data - a pointer, a vtable - not a
		// plain C string).
		if addr, isAddr := l.addrRegs[reg]; isAddr && l.strings != nil {
			if s, ok := l.strings(addr); ok {
				v = &ir.StringLit{Value: s}
			}
		}
		l.consume(v)
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
	return call, true
}

// finishCall applies a just-built call's effect on the register file:
// x0-x7 (and their w-register aliases) are caller-saved per AAPCS64 -
// the called function is free to clobber any of them, so whatever was
// sitting in them before this call is no longer trustworthy afterward
// (each clobber flushes it first if it was itself an unconsumed call
// result - see clobberReg). w0/x0 then become the new call's own
// result. call is also recorded in l.calls so flushRemaining can still
// emit it later if nothing ever ends up reading w0/x0.
func (l *lifter) finishCall(call ir.Expr) []ir.Stmt {
	var stmts []ir.Stmt
	for i := range aapcs64IntArgRegs {
		stmts = append(stmts, l.clobberReg(aapcs64IntArgRegs[i])...)
		stmts = append(stmts, l.clobberReg(aapcs64IntArgRegs32[i])...)
	}
	l.calls = append(l.calls, call)
	stmts = append(stmts, l.setReg("w0", call)...)
	stmts = append(stmts, l.setReg("x0", call)...)
	return stmts
}

// liftCall lifts "bl <addr>" - a direct function call - into a call
// expression recorded as the new value of w0/x0 (AAPCS64's
// return-value register). Not emitted as a statement immediately:
// mirroring liftAdd's reasoning, the call only becomes its own visible
// statement once it's clear nothing will ever consume its result as a
// value - see clobberReg (superseded before anything reads it) and
// flushRemaining (never read at all before this path ends).
func (l *lifter) liftCall(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandImm {
		return nil
	}
	target := uint64(inst.Operands[0].Imm)
	call, ok := l.buildCall(target, false)
	if !ok {
		return nil
	}
	return l.finishCall(call)
}

// liftTailCall lifts a plain "b <addr>" as a tail call when its target
// resolves to a known symbol - the standard -O0 codegen for a
// function's last action being a call whose result (if any) becomes
// this function's own return value, via AAPCS64 tail-call convention
// rather than an explicit "bl"+"ret" pair. Requires a resolved target
// (see buildCall's own doc comment) so an ordinary intra-function
// branch (a loop back-edge, say - not yet understood by this lifter)
// is never misread as a call to a bogus "func_<addr>" placeholder.
//
// Unlike liftCall, the resulting call is emitted as its own ExprStmt
// immediately: by definition nothing in THIS function reads its result
// afterward (a real "ret" would have been used instead of a bare "b"
// if something did), so there's no reason to leave it pending for
// flushRemaining to pick up later.
func (l *lifter) liftTailCall(inst native.DetailedInstruction) []ir.Stmt {
	target, ok := branchTarget(inst)
	if !ok {
		return nil
	}
	call, ok := l.buildCall(target, true)
	if !ok {
		return nil
	}
	stmts := l.finishCall(call)
	l.consume(call)
	return append(stmts, &ir.ExprStmt{Expr: call})
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
func (l *lifter) liftCset(inst native.DetailedInstruction) []ir.Stmt {
	if len(inst.Operands) != 1 || inst.Operands[0].Type != native.OperandReg {
		return nil
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
		return l.setReg(dst.Reg, &ir.LocalVar{Name: "cond"})
	}
	return l.setReg(dst.Reg, &ir.BinaryExpr{Op: op, Left: l.lastCmp.lhs, Right: l.lastCmp.rhs})
}

// consume marks e as accounted for - already embedded into some larger
// expression (a call argument, a comparison operand, a return value) -
// so flushRemaining and the inline orphan-detection in clobberReg never
// emit it as its own redundant statement. Safe to call with any Expr,
// including one that was never a call in the first place (consumed's
// only reader, isOrphanCandidate, already filters by type).
func (l *lifter) consume(e ir.Expr) {
	if e == nil {
		return
	}
	l.consumed[e] = true
}

// isOrphanCandidate reports whether e is a call expression that is
// about to become truly unreachable: not yet consumed, and not sitting
// in any OTHER register besides exceptReg (the one currently being
// overwritten/cleared) - e.g. a value mov'd into a callee-saved
// register earlier is still reachable under that second name even
// after its original register gets clobbered, so it must NOT be
// flushed yet.
func (l *lifter) isOrphanCandidate(e ir.Expr, exceptReg string) bool {
	if e == nil || l.consumed[e] {
		return false
	}
	switch e.(type) {
	case *ir.MethodCall, *ir.StaticMethodCall:
	default:
		return false
	}
	for reg, v := range l.regs {
		if reg == exceptReg {
			continue
		}
		if v == e {
			return false
		}
	}
	return true
}

// clobberReg removes reg's current value, first flushing it as its own
// ExprStmt if it's an orphaned call result (see isOrphanCandidate) -
// the inline half of "a call whose result is never used still needs to
// appear in the output", covering the common case where a NEW write to
// the same register (another call's argument setup, another call's own
// return value, ...) supersedes it before anything reads it. The other
// half, flushRemaining, covers a call that survives all the way to the
// end of this lifter's path without ever being overwritten OR read.
func (l *lifter) clobberReg(reg string) []ir.Stmt {
	var stmts []ir.Stmt
	if old, ok := l.regs[reg]; ok && l.isOrphanCandidate(old, reg) {
		stmts = append(stmts, &ir.ExprStmt{Expr: old})
		l.consumed[old] = true
	}
	delete(l.regs, reg)
	// Whatever reg is about to hold next, it isn't the address this
	// entry recorded any more - a caller that DOES know the new value
	// is (or extends) a known address, e.g. liftAddr or liftAdd's
	// immediate case propagating through "add Rd, Rn, #imm", re-adds
	// its own entry immediately after calling setReg/clobberReg.
	delete(l.addrRegs, reg)
	return stmts
}

// setReg is clobberReg followed by installing val as reg's new value -
// the single entry point every instruction that writes a register
// should use (instead of assigning l.regs[reg] directly) so an
// orphaned call sitting there never gets silently overwritten without
// being flushed first.
func (l *lifter) setReg(reg string, val ir.Expr) []ir.Stmt {
	stmts := l.clobberReg(reg)
	l.regs[reg] = val
	return stmts
}

// flushRemaining returns an ExprStmt for every call this lifter (or an
// ancestor it was forked from) has produced that is still unconsumed,
// in original creation order - the calls that survived to the true end
// of this lifter's own control-flow path without ever being read or
// clobbered (see clobberReg for the complementary case: a call
// superseded mid-path). Must only be called once a caller has
// established that this path genuinely has no more instructions ahead
// of it (see LiftFunction and liftBlockGraph's own callers of this) -
// calling it at a mid-function segment boundary a later block might
// still read from would flush values a subsequent read was still going
// to legitimately consume.
func (l *lifter) flushRemaining() []ir.Stmt {
	var stmts []ir.Stmt
	for _, c := range l.calls {
		if l.consumed[c] {
			continue
		}
		stmts = append(stmts, &ir.ExprStmt{Expr: c})
		l.consumed[c] = true
	}
	return stmts
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
	l.consume(lhs)

	switch rhsOp.Type {
	case native.OperandReg:
		rhs := l.regValue(rhsOp.Reg)
		l.consume(rhs)
		l.lastCmp = &cmpOperands{lhs: lhs, rhs: rhs}
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
	l.consume(val)
	return &ir.ReturnStmt{Value: val}
}

// TODO(next iterations): calls, comparisons/if-else, generic mov,
// void-call statement emission, adrp/adr string-literal resolution,
// ldr-through-GOT global-object resolution, and plain single-condition
// "while (cond) { straight-line body }" loops (cmp+b.cond, cbz/cbnz,
// or tbz/tbnz) are now handled (see liftCall/liftMov/flushRemaining,
// liftAddr/buildCall's StringResolver use, liftLdr's addrRegs+resolver
// use with ELFParser.ResolveGOT, and tryLiftWhileLoop/findLoopBody).
// Remaining growth areas, roughly in order of how often real-world -O0
// code needs them:
//   - Loop bodies containing their own nested control flow (an if, a
//     break/continue, a nested loop) - findLoopBody currently bails
//     out the instant any block in the candidate body chain has its
//     own conditional branch. Also unhandled: compound (&&/||)
//     while-conditions, which compile to MULTIPLE chained
//     conditional-branch blocks (each able to exit the loop) rather
//     than a single one - and do/for-shaped back-edges where the
//     condition check is the LAST block of the body rather than the
//     first (this iteration only recognizes the condition-first
//     "while" shape).
//   - More ALU ops (sub/mul/and/orr/eor/...).
//   - Non-parameter stack locals (regular local variables, not just
//     spilled parameters), and loads/stores to non-stack memory (real
//     pointer dereferences, not just the stack-slot bookkeeping this
//     version does).
