package jvm

import (
	"sort"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// blockBodyBudgetExceeded is the sentinel panic value used to unwind out of
// arbitrarily deep control-flow recovery recursion once a single method's
// work budget is exhausted. It is never meant to escape decompileCode.
type blockBodyBudgetExceeded struct{}

// maxBlockBodyCallsPerMethod bounds how many times decompileBlockBody may
// be entered while decompiling a single method's control flow, before
// giving up on the recursive/structured decompilation for that method and
// falling back to a flat, guaranteed-linear pass instead.
//
// This exists as a safety net underneath the control-flow recovery logic
// in this file (if/else, while, for-each, switch, and the else-if chain
// flattening in collectElseIfChain): that logic is written to do work
// linear in the method's instruction count, but bytecode shapes not yet
// anticipated by any of the pattern-matchers here could still trigger
// exponential re-exploration of the same instruction ranges - the same
// class of bug that made some real-world methods (long chains of
// if-comparisons converging on a shared merge point, such as
// compiler/tool-generated toString()/equals() methods with many fields)
// take effectively forever to decompile before collectElseIfChain was
// added. Rather than trust that every such shape has now been found and
// fixed, this budget guarantees a hard upper bound on the work spent
// before falling back, so a single unusual method can never again hang
// the whole decompilation (of one class, or of an entire .jar) or exhaust
// memory - worst case, that one method's output is flatter/less-idiomatic
// than it could be, and everything else keeps moving.
const maxBlockBodyCallsPerMethod = 200000

// blockBodyCallBudget tracks remaining decompileBlockBody entries for the
// method currently being decompiled. It is reset at the start of every
// decompileCode call. decompileCode never runs concurrently with itself
// for a different method within this package today (see the streaming
// .jar pipeline and DecompileClassFile, both of which process one method
// at a time on a single goroutine), so a package-level counter is safe;
// if that ever changes, this should become a value threaded explicitly
// through the call chain instead.
var blockBodyCallBudget int

// lambdaInlineDepth tracks how many levels deep decompileCode is
// currently nested via lambda body inlining (see decompileInvokedynamic
// in decoder.go, which recursively calls decompileCode to turn a
// synthetic lambda$...$N method's body into an inline LambdaExpr).
// maxLambdaInlineDepth bounds this so a pathological or accidentally
// self-referential chain of lambda bodies can't recurse unboundedly;
// past the limit, decompileInvokedynamic falls back to a bare
// MethodRefExpr pointing at the synthetic method instead of inlining it
// - less readable, but always safe and always terminates.
var lambdaInlineDepth int

const maxLambdaInlineDepth = 16

// boolTypeInfo combines everything this package can determine about
// which expressions have a real boolean type in the current method,
// gathered from three independent sources: method parameters (always
// known, from the method's own descriptor), local variables (only known
// when the class wasn't stripped of its LocalVariableTable debug info),
// and this class's own fields (always known, from each field's
// descriptor). Used by simplifyBoolExpr (via isMethodLikeExpr) to decide
// whether "X == 0"/"X != 0" may be folded to "!X"/"X" - folding this for
// a non-boolean (e.g. a real int counter like a cooldown) would produce
// invalid Java, so every source here only ever adds entries it's
// certain about; an expression absent from all three is treated as "not
// known to be boolean", never assumed to be one.
type boolTypeInfo struct {
	Params map[byte]bool
	Locals map[uint16]bool
	Fields map[string]bool
	// LocalNames is Locals re-keyed by each slot's resolved display name
	// (from localVars) instead of its raw slot number - built once here
	// because by the time an expression is being checked against this
	// during decompilation, only a LocalVar's NAME survives (not its
	// slot), and re-deriving a slot from an already-resolved name only
	// works for auto-generated names like "local_N", never for a real
	// debug-info name like "enabled".
	LocalNames map[string]bool
}

func buildBoolTypeInfo(cf *ClassFile, methodIdx int, localVars map[uint16]string) *boolTypeInfo {
	locals := buildBoolLocalsSet(cf, methodIdx)
	localNames := make(map[string]bool, len(locals))
	for slot, isBool := range locals {
		if isBool {
			if name, ok := localVars[slot]; ok {
				localNames[name] = true
			}
		}
	}
	return &boolTypeInfo{
		Params:     buildBoolParamSet(cf, methodIdx),
		Locals:     locals,
		Fields:     buildBoolFieldSet(cf),
		LocalNames: localNames,
	}
}

func decompileCode(cf *ClassFile, methodIdx int, code *CodeAttribute, className string) (result *ir.Block) {
	localVars := resolveLocalVars(cf, methodIdx, code)
	localTypes := collectLocalTypes(cf, methodIdx, code)
	instructions := DecodeInstructions(code.Code)

	boolParams := buildBoolTypeInfo(cf, methodIdx, localVars)

	blockBodyCallBudget = maxBlockBodyCallsPerMethod

	var stmts []ir.Stmt
	var stack *exprStack
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(blockBodyBudgetExceeded); !ok {
					panic(r) // not ours to handle; propagate as before
				}
				// This method's control flow doesn't fit in the work
				// budget above - fall back to a flat, guaranteed-linear
				// decompilation instead of structured if/while/switch
				// recovery, so this one unusual method can never hang or
				// exhaust memory. The output is less idiomatic (closer
				// to the bytecode's own linear shape) but always
				// completes in time proportional to the method's size.
				//
				// This also covers wrapTryCatch below, which makes its
				// own independent decompileControlFlow calls (one per
				// try-block) against the same budget: if the exception
				// table's try-blocks are what exhausts it, stmts here is
				// simply replaced wholesale with the flat pass over the
				// whole method, still correct (if less structured) since
				// decompileFlat processes every instruction regardless
				// of try/catch boundaries.
				stack = &exprStack{}
				stmts = decompileFlat(cf, instructions, localVars, className)
			}
		}()
		stack = &exprStack{}
		stmts = decompileControlFlow(cf, instructions, localVars, stack, className, boolParams, code.ExceptionTable)
	}()

	block := &ir.Block{}

	// Iterate in index order for deterministic output: map iteration
	// order in Go is intentionally randomized, which without this would
	// make the local variable declarations at the top of every method
	// print in a different order on every run.
	sortedIdxs := make([]int, 0, len(localTypes))
	for idx := range localTypes {
		sortedIdxs = append(sortedIdxs, int(idx))
	}
	sort.Ints(sortedIdxs)
	for _, idx := range sortedIdxs {
		typ := localTypes[uint16(idx)]
		varName := getLocalVar(localVars, byte(idx))
		block.Statements = append(block.Statements, &ir.VarDeclStmt{
			Name: varName,
			Type: typ,
		})
	}

	block.Statements = append(block.Statements, stmts...)

	for _, expr := range stack.items {
		if _, ok := expr.(*ir.LocalVar); !ok {
			block.Statements = append(block.Statements, &ir.ExprStmt{Expr: expr})
		}
	}

	block.Statements = eliminateDeadCode(block.Statements)
	block.Statements = simplifyBoolTernariesInStmts(block.Statements)

	return block
}

// decompileFlat decompiles a method's instructions as a single guaranteed-
// linear pass: every instruction is processed exactly once via
// decompileInstruction, with no attempt at recovering if/while/switch
// structure (so conditional branches surface as their underlying
// comparison expressions rather than as reconstructed if-statements). It
// exists purely as decompileCode's fallback when the structured recovery
// in decompileControlFlow exceeds its work budget - unlike that recovery,
// this can never itself blow up, since it does exactly one pass over the
// instructions with no recursion.
// decompileFlat decompiles a method's instructions as a single guaranteed-
// linear pass: every instruction is processed exactly once via
// decompileInstruction, with no attempt at recovering if/while/switch
// structure. It exists purely as decompileCode's fallback when the
// structured recovery in decompileControlFlow exceeds its work budget -
// unlike that recovery, this can never itself blow up, since it does
// exactly one pass over the instructions with no recursion.
//
// Conditional and unconditional branch instructions (Ifxx, IfIcmpxx,
// IfAcmpxx, Ifnull, Ifnonnull, Goto, jsr, switches) are not in
// decompileInstruction's dispatch table - by design, since normally
// decompileControlFlow/decompileBlockBody consume and interpret them
// before decompileInstruction ever sees one. Left unhandled, a
// conditional's comparison operands would never be popped, silently
// leaving stale values on the stack for a later, unrelated instruction to
// consume - producing plainly incorrect output (e.g. a hardcoded return
// value) rather than merely unstructured output. Each such opcode is
// therefore given explicit, minimal handling here: pop exactly what it
// would pop, push nothing, and record an UnrecoveredBranchStmt marker so
// the dropped control flow is visible in the output instead of silently
// wrong.
func decompileFlat(cf *ClassFile, instructions []Instruction, localVars map[uint16]string, className string) []ir.Stmt {
	var stmts []ir.Stmt
	tempStack := &exprStack{}
	for _, inst := range instructions {
		if handled, result := decompileFlatBranch(inst, tempStack); handled {
			stmts = append(stmts, result...)
			continue
		}
		result := decompileInstruction(cf, nil, instructions, inst, localVars, tempStack, className)
		stmts = append(stmts, result...)
	}
	for _, e := range tempStack.items {
		if _, ok := e.(*ir.LocalVar); !ok {
			stmts = append(stmts, &ir.ExprStmt{Expr: e})
		}
	}
	return stmts
}

// decompileFlatBranch gives minimal, stack-safe handling to the branch and
// switch opcodes decompileInstruction doesn't otherwise dispatch on. It
// reports whether it handled the instruction, and if so, the (possibly
// empty) statements to emit for it.
func decompileFlatBranch(inst Instruction, stack *exprStack) (bool, []ir.Stmt) {
	switch {
	case isComp2Opcode(inst.Opcode): // IfIcmpxx, IfAcmpxx: pop 2
		stack.pop()
		stack.pop()
		return true, []ir.Stmt{unrecoveredBranch()}
	case isConditionZeroOpcode(inst.Opcode): // Ifeq/Ifne/Iflt/Ifge/Ifgt/Ifle: pop 1
		stack.pop()
		return true, []ir.Stmt{unrecoveredBranch()}
	case isCompZeroOpcode(inst.Opcode): // Ifnull/Ifnonnull: pop 1
		stack.pop()
		return true, []ir.Stmt{unrecoveredBranch()}
	case inst.Opcode == Goto:
		return true, nil
	case inst.Opcode == Tableswitch || inst.Opcode == Lookupswitch:
		stack.pop() // the switch target value
		return true, []ir.Stmt{unrecoveredBranch()}
	}
	return false, nil
}

// unrecoveredBranch marks a point where decompileFlat could not reconstruct
// the original if/switch control flow. It renders as a quoted Java string
// statement (valid, side-effect-free Java), which is visibly a
// tool-inserted marker rather than real decompiled code.
func unrecoveredBranch() ir.Stmt {
	return &ir.ExprStmt{Expr: &ir.StringLit{Value: "DESTRUCT: unrecovered control flow at this point (original branching not reconstructed)"}}
}

// tryCatchGroup is one try/catch construct: a [StartIdx, EndIdx)
// instruction-index range covered by try, and every catch handler
// registered for exactly that range (ExceptionTable entries that share
// the same StartPC/EndPC represent multiple catch clauses on the same
// try block - e.g. "catch (IOException | SQLException e)" or several
// separate catch clauses - and must become ONE TryStmt with multiple
// CatchClauses, not several independent try-blocks).
type tryCatchGroup struct {
	StartIdx int
	EndIdx   int
	Handlers []*ExceptionEntry
	// BodyEndIdx is where this whole try/catch construct (try body plus
	// every catch handler's body) ends and normal linear code resumes -
	// see findTryCatchBodyEnd's doc comment for how this is determined.
	BodyEndIdx int
}

// collectTryCatchGroups groups a method's ExceptionTable entries by their
// shared [StartPC, EndPC) try range, and resolves each group's overall
// end point (where control resumes after the whole try/catch construct).
// Returns the groups in ascending StartIdx order.
// tryGroupsByStartCache memoizes getTryGroupsByStart's result for the
// most recently seen (exceptionTable, instructions) pair. Keyed by
// each slice's own (pointer, length) identity rather than its VALUES:
// decompileControlFlow and decompileBlockBody are re-entered many
// times (up to maxBlockBodyCallsPerMethod for the latter) with the
// method's own unchanging code.ExceptionTable/DecodeInstructions
// result threaded straight through as pass-through parameters at most
// call sites - a pointer+length match there is exactly "this is
// provably the same slice as last time", safe to reuse without
// recomputing. A genuinely different slice (decompileTryCatchGroup's
// filtered tryBodyExceptionTable, a catch handler's deliberate nil,
// or a switch case body's truncated instructions[:realEnd]) has a
// different pointer and/or length, so it correctly misses the cache
// and recomputes instead of risking a stale result for the wrong
// input. No explicit reset is needed across different decompileCode
// calls either: each method's instructions/exceptionTable come from a
// fresh DecodeInstructions/ClassFile parse, so their backing-array
// pointers can never collide with a previous method's by construction.
//
// Added after profiling a real, large real-world method (gv0.class in
// a test fixture jar - a protobuf/Kotlin-generated accessor with one
// try/catch and 3744 instructions) taking minutes to decompile:
// decompileBlockBody was calling collectTryCatchGroups - itself
// allocating maps and sorting - completely redundantly on every one
// of its own many thousands of recursive entries, even though its
// (exceptionTable, instructions) arguments never actually changed
// across the overwhelming majority of those calls. Confirmed via
// profiling to be the dominant remaining cost (GC pressure from the
// resulting allocation churn) even after fixing findInstrIdx's own
// O(n) scan (see that function's doc comment) - this cache resolves
// it down to sub-second for the same input.
var (
	tryGroupsByStartCacheExcPtr *ExceptionEntry
	tryGroupsByStartCacheExcLen int
	tryGroupsByStartCacheInsPtr *Instruction
	tryGroupsByStartCacheInsLen int
	tryGroupsByStartCacheResult map[int]tryCatchGroup
)

func getTryGroupsByStart(exceptionTable []ExceptionEntry, instructions []Instruction) map[int]tryCatchGroup {
	if len(exceptionTable) == 0 || len(instructions) == 0 {
		return nil
	}
	excPtr, insPtr := &exceptionTable[0], &instructions[0]
	if excPtr == tryGroupsByStartCacheExcPtr && len(exceptionTable) == tryGroupsByStartCacheExcLen &&
		insPtr == tryGroupsByStartCacheInsPtr && len(instructions) == tryGroupsByStartCacheInsLen {
		return tryGroupsByStartCacheResult
	}

	var m map[int]tryCatchGroup
	for _, g := range collectTryCatchGroups(exceptionTable, instructions) {
		if g.StartIdx >= 0 && g.StartIdx < len(instructions) {
			if m == nil {
				m = make(map[int]tryCatchGroup)
			}
			m[g.StartIdx] = g
		}
	}

	tryGroupsByStartCacheExcPtr = excPtr
	tryGroupsByStartCacheExcLen = len(exceptionTable)
	tryGroupsByStartCacheInsPtr = insPtr
	tryGroupsByStartCacheInsLen = len(instructions)
	tryGroupsByStartCacheResult = m
	return m
}

func collectTryCatchGroups(exceptionTable []ExceptionEntry, instructions []Instruction) []tryCatchGroup {
	type key struct{ start, end uint16 }
	order := make([]key, 0)
	byRange := make(map[key][]*ExceptionEntry)
	for i := range exceptionTable {
		et := &exceptionTable[i]
		k := key{et.StartPC, et.EndPC}
		if _, seen := byRange[k]; !seen {
			order = append(order, k)
		}
		byRange[k] = append(byRange[k], et)
	}

	// All handler start PCs across the whole method, used by
	// findTryCatchBodyEnd to recognize "this is the start of another
	// try/catch construct's handler, so the previous one's last catch
	// body must end here at the latest."
	var allBoundaryPCs []int
	for i := range exceptionTable {
		allBoundaryPCs = append(allBoundaryPCs, int(exceptionTable[i].StartPC))
	}
	sort.Ints(allBoundaryPCs)

	groups := make([]tryCatchGroup, 0, len(order))
	for _, k := range order {
		startIdx := findInstrIdx(instructions, int(k.start))
		endIdx := findInstrIdx(instructions, int(k.end))
		if startIdx < 0 || endIdx < 0 || endIdx <= startIdx {
			continue
		}
		handlers := byRange[k]

		// Extend endIdx past any return/throw sitting immediately after
		// the try block's formal (exclusive) end and before its
		// handler's start - see this function's doc comment for why
		// this is always safe and why it's needed (a compiler excludes
		// a trailing return/throw from the protected range since it
		// can't itself throw, but that statement is still logically
		// part of the try body's own expression from the source's
		// perspective, e.g. "return x.getAsBoolean();").
		minHandlerPC := -1
		for _, h := range handlers {
			if minHandlerPC == -1 || int(h.HandlerPC) < minHandlerPC {
				minHandlerPC = int(h.HandlerPC)
			}
		}
		for endIdx < len(instructions) {
			inst := instructions[endIdx]
			if minHandlerPC >= 0 && inst.Offset >= minHandlerPC {
				break
			}
			switch inst.Opcode {
			case Ireturn, Lreturn, Freturn, Dreturn, Areturn, Return, Athrow:
				endIdx++
			default:
				goto doneExtending
			}
		}
	doneExtending:

		bodyEndIdx := findTryCatchBodyEnd(instructions, handlers, allBoundaryPCs)
		groups = append(groups, tryCatchGroup{
			StartIdx:   startIdx,
			EndIdx:     endIdx,
			Handlers:   handlers,
			BodyEndIdx: bodyEndIdx,
		})
	}

	sort.Slice(groups, func(i, j int) bool { return groups[i].StartIdx < groups[j].StartIdx })
	return groups
}

// findTryCatchBodyEnd finds where a try/catch construct's last catch
// handler body ends. The JVM bytecode a compiler emits for try/catch
// almost always has each catch handler's body end in either a `goto` to
// a common continuation point (when the try/catch isn't the last thing
// in the method) or a return/throw (when it is) - so the search walks
// forward from the LAST handler's start PC and stops at the first
// instruction that is: another exception handler's start (a following
// try/catch construct beginning immediately after this one), a `goto`
// (taken as "jumps past the end of this construct"), or a
// return/throw/end-of-method. This is a pragmatic heuristic - correct
// for the overwhelmingly common case of sequential (non-nested)
// try/catch blocks - not a full data-flow analysis; see decompileCode's
// budget-exceeded fallback (decompileFlat) for what happens on inputs
// unusual enough to defeat it (that fallback is always linear-time and
// always correct, if less structured).
func findTryCatchBodyEnd(instructions []Instruction, handlers []*ExceptionEntry, allBoundaryPCs []int) int {
	lastHandlerPC := 0
	for _, h := range handlers {
		if int(h.HandlerPC) > lastHandlerPC {
			lastHandlerPC = int(h.HandlerPC)
		}
	}
	startIdx := findInstrIdx(instructions, lastHandlerPC)
	if startIdx < 0 {
		return len(instructions)
	}

	for i := startIdx; i < len(instructions); i++ {
		inst := instructions[i]

		// Another try/catch construct's handler begins here: this one's
		// last catch body must have already ended.
		if i > startIdx {
			for _, bpc := range allBoundaryPCs {
				if bpc == inst.Offset {
					return i
				}
			}
		}

		switch inst.Opcode {
		case Goto:
			// The goto itself is part of this catch body (it's how
			// control leaves the catch to resume after the whole
			// construct); the body ends right after it.
			return i + 1
		case Ireturn, Lreturn, Freturn, Dreturn, Areturn, Return, Athrow:
			return i + 1
		}
	}
	return len(instructions)
}

// wrapTryCatch decompiles a method's try/catch structure. Unlike a naive
// per-ExceptionTable-entry pass, this: preserves every instruction
// OUTSIDE any try range (a method with a try/catch block is not made
// entirely of that block), merges multiple ExceptionTable entries that
// share the same try range into one TryStmt with multiple CatchClauses
// (rather than one independent try-block per entry), and actually
// decompiles each catch handler's body instead of hardcoding it to a
// bare, often-invalid "return;".
// matchTryWithResources recognizes the compiler-synthesized bytecode
// pattern for a single try-with-resources declaration (JLS 14.20.3):
// two exception table entries where the second's protected range is
// nested inside the first's handler. The outer handler closes the
// resource and re-throws the original exception (or falls through to
// the normal after-try code, on the no-exception path); the inner
// handler exists only to call addSuppressed if closing the resource
// itself throws while already unwinding from the original exception -
// a purely defensive mechanism with no representation in the original
// source at all (a person writing "try (X x = ...) {...}" never
// mentions addSuppressed anywhere).
//
// On success, returns the resource's declared type, variable name, and
// init expression (recovered from the resource-declaration code
// immediately preceding the try block, i.e. instructions[resourceDeclStart:g.StartIdx]),
// along with the index where the outer handler's own close() call ends
// (so the caller can skip re-decompiling the addSuppressed machinery as
// ordinary catch bodies).
func matchTryWithResources(cf *ClassFile, g tryCatchGroup, instructions []Instruction, exceptionTable []ExceptionEntry) (resourceType ir.Type, resourceName string, resourceInit ir.Expr, realBodyEnd int, ok bool) {
	if len(g.Handlers) != 1 {
		return nil, "", nil, 0, false
	}
	outerHandler := g.Handlers[0]
	outerHandlerIdx := findInstrIdx(instructions, int(outerHandler.HandlerPC))
	if outerHandlerIdx < 0 || outerHandlerIdx >= len(instructions) {
		return nil, "", nil, 0, false
	}

	// Find the inner handler: another exception table entry whose
	// protected range starts inside the outer handler's own body.
	var innerEntry *ExceptionEntry
	for i := range exceptionTable {
		et := &exceptionTable[i]
		startIdx := findInstrIdx(instructions, int(et.StartPC))
		if startIdx > outerHandlerIdx && startIdx <= g.BodyEndIdx {
			innerEntry = et
			break
		}
	}
	if innerEntry == nil {
		return nil, "", nil, 0, false
	}

	// Outer handler's own body (before the inner handler's protected
	// range starts) must be exactly: astore(exc) - capturing the
	// primary exception into a local slot. The actual close() call
	// that follows is itself protected by the inner exception table
	// entry (so a second exception while already unwinding routes to
	// the addSuppressed handler below), not part of the outer handler's
	// own body.
	innerStartIdx := findInstrIdx(instructions, int(innerEntry.StartPC))
	outerBody := instructions[outerHandlerIdx:innerStartIdx]
	if len(outerBody) != 1 {
		return nil, "", nil, 0, false
	}
	if !isAstoreOpcode(outerBody[0].Opcode) {
		return nil, "", nil, 0, false
	}

	// The inner protected range itself must be exactly: aload(resource),
	// invokevirtual close(), goto - the actual resource close on the
	// exception path.
	innerRangeEndPC := int(innerEntry.EndPC)
	innerRangeEndIdx := findInstrIdx(instructions, innerRangeEndPC)
	if innerRangeEndIdx < 0 {
		return nil, "", nil, 0, false
	}
	closeCallBody := instructions[innerStartIdx:innerRangeEndIdx]
	if len(closeCallBody) != 3 {
		return nil, "", nil, 0, false
	}
	if !isLoadOpcode(closeCallBody[0].Opcode) {
		return nil, "", nil, 0, false
	}
	if closeCallBody[1].Opcode != Invokevirtual {
		return nil, "", nil, 0, false
	}
	if cf.GetMethodName(uint16(closeCallBody[1].Operands[0])<<8|uint16(closeCallBody[1].Operands[1])) != "close" {
		return nil, "", nil, 0, false
	}
	resourceSlot := loadSlot(closeCallBody[0])

	// Inner handler's body must be exactly: astore(suppressed),
	// aload(exc), aload(suppressed), invokevirtual addSuppressed(),
	// aload(exc), athrow.
	innerHandlerIdx := findInstrIdx(instructions, int(innerEntry.HandlerPC))
	if innerHandlerIdx < 0 {
		return nil, "", nil, 0, false
	}
	// g.BodyEndIdx only covers the outer handler (computed without
	// knowledge of this inner handler's existence) - find the inner
	// handler's own end by scanning forward for the first terminator
	// (athrow, expected for this specific pattern).
	innerBodyEnd := -1
	for i := innerHandlerIdx; i < len(instructions) && i < innerHandlerIdx+8; i++ {
		if instructions[i].Opcode == Athrow {
			innerBodyEnd = i + 1
			break
		}
	}
	if innerBodyEnd == -1 {
		return nil, "", nil, 0, false
	}
	innerBody := instructions[innerHandlerIdx:innerBodyEnd]
	if len(innerBody) != 6 {
		return nil, "", nil, 0, false
	}
	if !isAstoreOpcode(innerBody[0].Opcode) {
		return nil, "", nil, 0, false
	}
	if innerBody[3].Opcode != Invokevirtual {
		return nil, "", nil, 0, false
	}
	if cf.GetMethodName(uint16(innerBody[3].Operands[0])<<8|uint16(innerBody[3].Operands[1])) != "addSuppressed" {
		return nil, "", nil, 0, false
	}
	if innerBody[5].Opcode != Athrow {
		return nil, "", nil, 0, false
	}

	// Recover the resource declaration: scan backward from the try
	// block's own start for the assignment to resourceSlot (the
	// compiler emits "Type varName = initExpr;" as ordinary code
	// immediately before the try starts).
	declStart := -1
	for i := g.StartIdx - 1; i >= 0; i-- {
		inst := instructions[i]
		if isAstoreOpcode(inst.Opcode) && astoreSlot(inst) == resourceSlot {
			declStart = i
			break
		}
		// A branch instruction here means the assignment isn't in the
		// immediately-preceding straight-line code - this parser only
		// handles the common case.
		if isBranchOpcode(inst.Opcode) {
			break
		}
	}
	if declStart < 0 {
		return nil, "", nil, 0, false
	}

	declStack := &exprStack{}
	var declStmts []ir.Stmt
	for i := declStart; i < g.StartIdx; i++ {
		declStmts = append(declStmts, decompileInstruction(cf, nil, instructions, instructions[i], nil, declStack, "")...)
	}
	if len(declStmts) != 1 {
		return nil, "", nil, 0, false
	}
	assign, isAssign := declStmts[0].(*ir.AssignStmt)
	if !isAssign {
		return nil, "", nil, 0, false
	}
	localVar, isLocal := assign.Target.(*ir.LocalVar)
	if !isLocal {
		return nil, "", nil, 0, false
	}

	return inferResourceType(assign.Value), localVar.Name, assign.Value, innerBodyEnd, true
}

// inferResourceType makes a best-effort guess at a resource's declared
// type from its init expression - almost always a "new Xxx(...)" call,
// whose type is exactly what the resource was declared as (Java doesn't
// allow a try-with-resources variable's declared type to differ from a
// simple "new" expression's type without an explicit cast, which would
// itself show up as part of the expression).
func inferResourceType(init ir.Expr) ir.Type {
	if ne, ok := init.(*ir.NewExpr); ok {
		return &ir.ClassType{Name: ne.Type}
	}
	return &ir.ClassType{Name: "Object"}
}

func decompileTryCatchGroup(cf *ClassFile, g tryCatchGroup, instructions []Instruction, localVars map[uint16]string, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) ([]ir.Stmt, int) {
	if resourceType, resourceName, resourceInit, realBodyEnd, ok := matchTryWithResources(cf, g, instructions, exceptionTable); ok {
		// The resource's own declaration ("Type var = init;") was
		// ordinary code immediately before the try block in the
		// instruction stream - the caller's own linear decompilation
		// already emitted it as a separate statement, since this
		// function only sees [g.StartIdx, g.EndIdx). Nothing further to
		// do here except fold it into the try-with-resources syntax:
		// build the try body from the real read loop only (the outer
		// handler's close()+goto and the entire inner
		// addSuppressed/athrow handler are the synthetic mechanism this
		// match recognized and are deliberately not decompiled at all).
		//
		// Passes the SAME, unmodified exceptionTable the enclosing
		// method already has (rather than a filtered copy with this
		// group's own entries removed) - see decompileControlFlowExcl's
		// own doc comment for why: getTryGroupsByStart's cache is keyed
		// by slice identity, and this group's own entry (which would
		// otherwise be rediscovered infinitely - see the excludeSelfStart
		// parameter below) is instead excluded via a cheap O(1) index
		// check, not a fresh O(n) filtered allocation.
		tryBody := decompileControlFlowExcl(cf, instructions[g.StartIdx:g.EndIdx], localVars, &exprStack{}, className, boolParams, exceptionTable, true)
		return []ir.Stmt{&ir.TryStmt{
			Resources: []*ir.ResourceDecl{{VarType: resourceType, VarName: resourceName, Init: resourceInit}},
			Body:      &ir.Block{Statements: tryBody},
		}}, realBodyEnd
	}

	// excludeSelfStart=true below prevents this exact group from being
	// rediscovered and reprocessed infinitely: the recursive call runs
	// on a truncated slice (instructions[g.StartIdx:g.EndIdx]) whose
	// own local pc 0 always equals this group's own StartIdx (offsets
	// are absolute, unaffected by the slice truncation) - see
	// decompileControlFlowExcl's own doc comment.
	tryBody := decompileControlFlowExcl(cf, instructions[g.StartIdx:g.EndIdx], localVars, &exprStack{}, className, boolParams, exceptionTable, true)

	catches := make([]*ir.CatchClause, 0, len(g.Handlers))
	for _, h := range g.Handlers {
		handlerStartIdx := findInstrIdx(instructions, int(h.HandlerPC))
		if handlerStartIdx < 0 {
			continue
		}
		handlerEndIdx := g.BodyEndIdx
		// Trim the trailing goto/return that just marks "leave the
		// catch body" - it has no source-level representation of
		// its own (control simply falls through to whatever follows
		// the whole try/catch in the emitted Java).
		trimmedEnd := handlerEndIdx
		if trimmedEnd > handlerStartIdx {
			last := instructions[trimmedEnd-1]
			if last.Opcode == Goto {
				trimmedEnd--
			}
		}

		var catchBody []ir.Stmt
		if trimmedEnd > handlerStartIdx {
			// The caught exception is on the stack at the handler's
			// entry point (the JVM's own contract for exception
			// handlers). decompileBlockBody always starts from an
			// empty stack, so it can't see that - but the compiler
			// almost always emits an immediate astore as the
			// handler's first instruction specifically to capture
			// it, and that's a real assignment this package can
			// recognize directly: bind that local slot to "e" (in a
			// scoped copy of localVars, not the enclosing method's
			// map - the same slot may be reused for something
			// unrelated after the try/catch ends) and skip
			// decompiling the astore itself, since decompiling it
			// normally would just assign a meaningless stack-
			// underflow placeholder instead of the real exception.
			bodyStart := handlerStartIdx
			handlerVars := localVars
			if first := instructions[handlerStartIdx]; isAstoreOpcode(first.Opcode) {
				slot := astoreSlot(first)
				handlerVars = make(map[uint16]string, len(localVars)+1)
				for k, v := range localVars {
					handlerVars[k] = v
				}
				handlerVars[slot] = "e"
				bodyStart = handlerStartIdx + 1
			}

			catchBody = decompileBlockBody(cf, instructions, bodyStart, trimmedEnd, handlerVars, className, boolParams, nil)
		}

		catches = append(catches, &ir.CatchClause{
			VarName: "e",
			VarType: resolveCatchType(cf, h.CatchType),
			Body:    &ir.Block{Statements: catchBody},
		})
	}

	if len(catches) == 0 {
		// No usable handler (shouldn't normally happen) - keep the
		// try body's code inline rather than silently dropping it.
		return tryBody, g.BodyEndIdx
	}
	return []ir.Stmt{&ir.TryStmt{
		Body:    &ir.Block{Statements: tryBody},
		Catches: catches,
	}}, g.BodyEndIdx
}

func wrapTryCatch(cf *ClassFile, code *CodeAttribute, methodIdx int, instructions []Instruction, localVars map[uint16]string, boolParams *boolTypeInfo, className string, stmts []ir.Stmt) []ir.Stmt {
	if len(code.ExceptionTable) == 0 {
		return stmts
	}

	groups := collectTryCatchGroups(code.ExceptionTable, instructions)
	if len(groups) == 0 {
		return stmts
	}

	var result []ir.Stmt
	pc := 0
	for _, g := range groups {
		if g.StartIdx < pc {
			// Overlaps a construct already emitted (e.g. nested
			// try/catch, which this pragmatic pass doesn't attempt to
			// nest correctly) - skip it rather than risk emitting
			// overlapping/duplicated statements; its instructions were
			// already covered by the enclosing construct's body.
			continue
		}

		// Linear code between the previous construct (or the start of
		// the method) and this try block.
		if g.StartIdx > pc {
			result = append(result, decompileControlFlow(cf, instructions[pc:g.StartIdx], localVars, &exprStack{}, className, boolParams, code.ExceptionTable)...)
		}

		tcStmts, newBodyEnd := decompileTryCatchGroup(cf, g, instructions, localVars, className, boolParams, code.ExceptionTable)
		result = append(result, tcStmts...)

		pc = newBodyEnd
	}

	// Whatever remains after the last try/catch construct.
	if pc < len(instructions) {
		result = append(result, decompileControlFlow(cf, instructions[pc:], localVars, &exprStack{}, className, boolParams, code.ExceptionTable)...)
	}

	return result
}

// instructionSize returns the total encoded size, in bytes, of a
// decoded instruction: 1 opcode byte plus however many operand bytes
// this specific instance has. This correctly handles variable-length
// instructions (tableswitch, lookupswitch) since Instruction.Operands
// already holds every byte that was actually decoded for that instance
// (padding and jump table included), not a fixed per-opcode size.
func instructionSize(inst Instruction) int {
	return 1 + len(inst.Operands)
}

func resolveCatchType(cf *ClassFile, catchType uint16) ir.Type {
	if catchType == 0 {
		return &ir.ClassType{Name: "java.lang.Throwable"}
	}
	return &ir.ClassType{Name: cf.GetClassName(catchType)}
}

// isAstoreOpcode reports whether inst is any form of astore (the
// wide/short forms astore_0..astore_3, or the general astore <index>).
func isLoadOpcode(op Opcode) bool {
	switch op {
	case Aload, Aload0, Aload1, Aload2, Aload3:
		return true
	}
	return false
}

// loadSlot returns the local variable slot an aload-family instruction
// reads from. isLoadOpcode(inst.Opcode) must be true.
func loadSlot(inst Instruction) uint16 {
	switch inst.Opcode {
	case Aload0:
		return 0
	case Aload1:
		return 1
	case Aload2:
		return 2
	case Aload3:
		return 3
	default: // Aload
		return uint16(inst.Operands[0])
	}
}

func isAstoreOpcode(op Opcode) bool {
	switch op {
	case Astore, Astore0, Astore1, Astore2, Astore3:
		return true
	}
	return false
}

// astoreSlot returns the local variable slot an astore-family
// instruction writes to. isAstoreOpcode(inst.Opcode) must be true.
func astoreSlot(inst Instruction) uint16 {
	switch inst.Opcode {
	case Astore0:
		return 0
	case Astore1:
		return 1
	case Astore2:
		return 2
	case Astore3:
		return 3
	default: // Astore
		return uint16(inst.Operands[0])
	}
}

func buildMethodChainExpr(cf *ClassFile, instructions []Instruction, idx int, localVars map[uint16]string) ir.Expr {
	inst := instructions[idx]
	refIdx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])

	var objExpr ir.Expr
	if idx > 0 {
		prevInst := instructions[idx-1]
		switch {
		case prevInst.Opcode == Getstatic:
			refIdx2 := uint16(prevInst.Operands[0])<<8 | uint16(prevInst.Operands[1])
			objExpr = &ir.LocalVar{Name: cf.GetFieldName(refIdx2)}
		case prevInst.Opcode == Getfield:
			objExpr = buildMethodChainExpr(cf, instructions, idx-1, localVars)
		case prevInst.Opcode == Aload || (prevInst.Opcode >= Aload0 && prevInst.Opcode <= Aload3):
			varIdx := byte(0)
			if prevInst.Opcode >= Aload0 && prevInst.Opcode <= Aload3 {
				varIdx = byte(prevInst.Opcode - Aload0)
			} else {
				varIdx = prevInst.Operands[0]
			}
			objExpr = &ir.LocalVar{Name: getLocalVar(localVars, varIdx)}
		case prevInst.Opcode == Invokevirtual || prevInst.Opcode == Invokestatic || prevInst.Opcode == Invokeinterface:
			objExpr = buildMethodChainExpr(cf, instructions, idx-1, localVars)
		}
	}

	switch inst.Opcode {
	case Getfield, Getstatic:
		return &ir.FieldAccess{
			Object: objExpr,
			Name:   cf.GetFieldName(refIdx),
		}
	default:
		return &ir.MethodCall{
			Object: objExpr,
			Name:   cf.GetMethodName(refIdx),
		}
	}
}

func removeTrailingIteratorSetup(stmts []ir.Stmt) []ir.Stmt {
	for i := len(stmts) - 1; i >= 0 && i >= len(stmts)-5; i-- {
		if va, ok := stmts[i].(*ir.AssignStmt); ok {
			if mc, ok := va.Value.(*ir.MethodCall); ok {
				if mc.Name == "iterator" {
					return append(stmts[:i], stmts[i+1:]...)
				}
			}
		}
	}
	return stmts
}

func eliminateDeadCode(stmts []ir.Stmt) []ir.Stmt {
	var result []ir.Stmt
	afterReturn := false
	for _, s := range stmts {
		if afterReturn {
			continue
		}
		result = append(result, s)
		if _, ok := s.(*ir.ReturnStmt); ok {
			afterReturn = true
		}
		if _, ok := s.(*ir.ThrowStmt); ok {
			afterReturn = true
		}
	}
	return result
}

func simplifyBoolTernariesInStmts(stmts []ir.Stmt) []ir.Stmt {
	for i, s := range stmts {
		switch v := s.(type) {
		case *ir.ReturnStmt:
			if v.Value != nil {
				v.Value = simplifyBoolTernary(v.Value)
			}
		case *ir.AssignStmt:
			if v.Value != nil {
				v.Value = simplifyBoolTernary(v.Value)
			}
		case *ir.IfStmt:
			if v.Then != nil {
				v.Then.Statements = simplifyBoolTernariesInStmts(v.Then.Statements)
			}
			if v.Else != nil {
				v.Else.Statements = simplifyBoolTernariesInStmts(v.Else.Statements)
			}
		case *ir.WhileStmt:
			if v.Body != nil {
				v.Body.Statements = simplifyBoolTernariesInStmts(v.Body.Statements)
			}
		case *ir.ForEachStmt:
			if v.Body != nil {
				v.Body.Statements = simplifyBoolTernariesInStmts(v.Body.Statements)
			}
		case *ir.TryStmt:
			if v.Body != nil {
				v.Body.Statements = simplifyBoolTernariesInStmts(v.Body.Statements)
			}
			for _, c := range v.Catches {
				if c.Body != nil {
					c.Body.Statements = simplifyBoolTernariesInStmts(c.Body.Statements)
				}
			}
		}
		stmts[i] = s
	}
	return stmts
}

func simplifyBoolTernary(e ir.Expr) ir.Expr {
	te, ok := e.(*ir.TernaryExpr)
	if !ok {
		return e
	}
	if isBoolLit(te.TrueExpr) && isBoolLit(te.FalseExpr) {
		trueVal := te.TrueExpr.(*ir.BoolLit).Value
		falseVal := te.FalseExpr.(*ir.BoolLit).Value
		if trueVal && !falseVal {
			return te.Cond
		}
		if !trueVal && falseVal {
			return &ir.UnaryExpr{Op: "!", Expr: te.Cond}
		}
	}
	if isIntOne(te.TrueExpr) && isIntZero(te.FalseExpr) {
		return te.Cond
	}
	if isIntZero(te.TrueExpr) && isIntOne(te.FalseExpr) {
		return &ir.UnaryExpr{Op: "!", Expr: te.Cond}
	}
	return e
}

func isBoolLit(e ir.Expr) bool {
	_, ok := e.(*ir.BoolLit)
	return ok
}

func isIntOne(e ir.Expr) bool {
	il, ok := e.(*ir.IntLit)
	return ok && il.Value == 1
}

func isIntZero(e ir.Expr) bool {
	il, ok := e.(*ir.IntLit)
	return ok && il.Value == 0
}

// buildBoolFieldSet builds a field-name -> isBoolean map for every field
// declared directly on cf, from each field's own descriptor (field
// descriptors are always present - unlike local variable debug info,
// they're not optional - so this is always complete for the class's own
// fields; it says nothing about inherited or other classes' fields).
func buildBoolFieldSet(cf *ClassFile) map[string]bool {
	result := make(map[string]bool, len(cf.Fields))
	for _, f := range cf.Fields {
		if cf.GetUTF8(f.DescriptorIndex) == "Z" {
			result[cf.GetUTF8(f.NameIndex)] = true
		}
	}
	return result
}

func buildBoolParamSet(cf *ClassFile, methodIdx int) map[byte]bool {
	result := make(map[byte]bool)
	if methodIdx >= len(cf.Methods) {
		return result
	}
	method := cf.Methods[methodIdx]
	desc := cf.GetUTF8(method.DescriptorIndex)
	params, _ := ParseDescriptor(desc)
	for i, p := range params {
		if p.Base == "bool" {
			result[byte(i)] = true
		}
	}
	return result
}

// buildBoolLocalsSet builds a local-variable-slot -> isBoolean map for
// one method, from its LocalVariableTable attribute (debug info, only
// present when the class wasn't stripped of it). Slots are the REAL
// JVM local variable indices (as used by iload/istore/etc and by
// buildConditionDirect's own boolParams lookup), not parameter
// positions - unlike buildBoolParamSet above, which only happens to get
// away with using positions because it's only ever consulted for
// parameters without a preceding long/double (which would shift later
// slots by one extra).
//
// Returns an empty map (never nil) when there's no LocalVariableTable to
// read - callers should treat "not known to be boolean" as the same
// safe default as "known not to be boolean" (i.e. don't fold "==0"/"!=0"
// for it), never the other way around.
func buildBoolLocalsSet(cf *ClassFile, methodIdx int) map[uint16]bool {
	result := make(map[uint16]bool)
	entries, err := cf.ParseLocalVariableTable(methodIdx)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if cf.GetUTF8(entry.DescriptorIndex) == "Z" {
			result[entry.Index] = true
		}
	}
	return result
}

func decompileControlFlow(cf *ClassFile, instructions []Instruction, localVars map[uint16]string, stack *exprStack, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) []ir.Stmt {
	return decompileControlFlowExcl(cf, instructions, localVars, stack, className, boolParams, exceptionTable, false)
}

// decompileControlFlowExcl is decompileControlFlow with one extra
// option: excludeSelfStart, set only by decompileTryCatchGroup's own
// two recursive calls for a try body's own content
// (instructions[g.StartIdx:g.EndIdx], where local pc 0 always equals
// g.StartIdx globally - see decompileTryCatchGroup's own doc comment
// on why that group must not be rediscovered and reprocessed here).
// Skipping just local pc 0 lets those two call sites pass the SAME,
// unmodified exceptionTable slice the enclosing method already has
// (instead of allocating a filtered copy with that one entry removed)
// so getTryGroupsByStart's pointer-identity cache actually applies -
// see that cache's own doc comment for why the previous filtered-copy
// approach defeated it on every single call, and profiling that
// pinned down as the dominant cost of a real, pathological real-world
// method (gv0.class in a test fixture jar, 750 independent try/catch
// groups in one method) that used to take minutes.
func decompileControlFlowExcl(cf *ClassFile, instructions []Instruction, localVars map[uint16]string, stack *exprStack, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry, excludeSelfStart bool) []ir.Stmt {
	var result []ir.Stmt

	pc := 0

	// Recognize a try/catch construct starting at the current position -
	// mirrors decompileBlockBody's own identical fix. Without this,
	// decompileControlFlow (used both for the very top of a method and
	// for the plain code between/after try/catch constructs within
	// wrapTryCatch's own pass) never itself understood try/catch at all;
	// only decompileBlockBody (nested blocks) and wrapTryCatch
	// (top-level only, and unconditionally reprocessing the WHOLE
	// exception table regardless of what decompileBlockBody already
	// handled) did.
	tryGroupsByStart := getTryGroupsByStart(exceptionTable, instructions)

	// advance moves pc to newPc if it actually makes forward progress,
	// and returns whether it did. Several of the pattern-matchers below
	// (guard clauses, compound booleans, ternaries, if/else, while-loop
	// recovery, switch, array-init) can, on unusual or obfuscated
	// bytecode, compute a newPc that doesn't advance past pc. Without
	// this check, "pc = newPc; continue" turns into an infinite loop
	// that hangs the whole process silently - the decompiler never
	// returns, never panics, never times out on its own. Falling back
	// to decoding the single instruction at pc and advancing by one
	// guarantees this loop always terminates, even if a matcher above
	// has a latent bug for some input.
	advance := func(newPc int) bool {
		if newPc > pc {
			pc = newPc
			return true
		}
		return false
	}

	for pc < len(instructions) {
		if g, ok := tryGroupsByStart[pc]; ok && g.BodyEndIdx > pc && !(excludeSelfStart && pc == 0) {
			tcStmts, newBodyEnd := decompileTryCatchGroup(cf, g, instructions, localVars, className, boolParams, exceptionTable)
			result = append(result, tcStmts...)
			pc = newBodyEnd
			continue
		}
		inst := instructions[pc]

		switch inst.Opcode {

	case Ifeq, Ifne, Iflt, Ifge, Ifgt, Ifle,
		IfIcmpeq, IfIcmpne, IfIcmplt, IfIcmpge, IfIcmpgt, IfIcmple,
		IfAcmpeq, IfAcmpne, Ifnull, Ifnonnull:
		if isConditionZeroOpcode(inst.Opcode) || isCompZeroOpcode(inst.Opcode) || isComp2Opcode(inst.Opcode) {
			if links, invertedFlags, linkPreambles, linkStacks, bodyStart, bodyEnd, ok := matchOrChainGuard(cf, instructions, pc, localVars, className, stack); ok {
				stmts, newPc := decompileOrChainGuard(cf, instructions, links, invertedFlags, linkPreambles, linkStacks, bodyStart, bodyEnd, localVars, className, boolParams, exceptionTable)
				if advance(newPc) {
					result = append(result, stmts...)
					continue
				}
			}
		}
		if (isConditionZeroOpcode(inst.Opcode) || isCompZeroOpcode(inst.Opcode)) && matchGuardClause(cf, instructions, pc, stack) {
			stmts, newPc := decompileGuardClause(cf, instructions, pc, localVars, stack, className, boolParams, exceptionTable)
			if advance(newPc) {
				result = append(result, stmts...)
				continue
			}
		}
		if (isConditionZeroOpcode(inst.Opcode) || isCompZeroOpcode(inst.Opcode)) && matchCompoundBoolean(cf, instructions, pc, localVars, stack, boolParams) {
			mergeIdx := findCompoundBooleanEnd(instructions, pc)
			if advance(mergeIdx) {
				continue
			}
		}
		if (isConditionZeroOpcode(inst.Opcode) || isCompZeroOpcode(inst.Opcode)) && matchBooleanTernary(cf, instructions, pc, stack, boolParams) {
			mergeIdx := findBooleanTernaryEnd(instructions, pc)
			if advance(mergeIdx) {
				continue
			}
		}
		if (isConditionZeroOpcode(inst.Opcode) || isCompZeroOpcode(inst.Opcode) || isComp2Opcode(inst.Opcode)) && matchGeneralTernary(cf, instructions, pc, stack, boolParams) {
			mergeIdx := findGeneralTernaryEnd(instructions, pc)
			if advance(mergeIdx) {
				continue
			}
		}
		if stmt, newPc := matchBoolToggle(cf, instructions, pc, stack, className, boolParams); stmt != nil {
			if advance(newPc) {
				result = append(result, stmt...)
				continue
			}
		}
		stmt, newPc := decompileIfElse(cf, instructions, pc, localVars, stack, className, boolParams, exceptionTable)
		if stmt != nil {
			if advance(newPc) {
				if _, ok := stmt[0].(*ir.ForEachStmt); ok {
					result = removeTrailingIteratorSetup(result)
				}
				result = append(result, stmt...)
				continue
			}
		}

	case Goto:
		offset := int16(inst.Operands[0])<<8 | int16(inst.Operands[1])
		target := inst.Offset + int(offset)
		if target < inst.Offset {
			if stmt, newPc := tryWhileLoop(cf, instructions, pc, localVars, stack, className, boolParams, exceptionTable); stmt != nil {
				if advance(newPc) {
					if _, ok := stmt[0].(*ir.ForEachStmt); ok {
						result = removeTrailingIteratorSetup(result)
					}
					result = append(result, stmt...)
					continue
				}
			}
		}

		default:
			if inst.Opcode == Tableswitch || inst.Opcode == Lookupswitch {
				if stmt, newPc := decompileSwitch(cf, instructions, pc, localVars, stack, className, boolParams, exceptionTable); stmt != nil {
					if advance(newPc) {
						result = append(result, stmt...)
						continue
					}
				}
			}
			if stmt, newPc := matchArrayInit(cf, instructions, pc, localVars, stack, className); newPc > pc {
				if stmt != nil {
					result = append(result, stmt...)
				}
				pc = newPc
				continue
			}
			stmts := decompileInstruction(cf, nil, instructions, inst, localVars, stack, className)
			result = append(result, stmts...)
		}

		pc++
	}

	return result
}

func matchCompoundBoolean(cf *ClassFile, instructions []Instruction, pc int, localVars map[uint16]string, stack *exprStack, boolParams *boolTypeInfo) bool {
	inst := instructions[pc]
	if !isConditionZeroOpcode(inst.Opcode) {
		return false
	}

	outerTarget := inst.Offset + branchOffset(inst)
	if outerTarget <= inst.Offset {
		return false
	}

	innerPc := pc + 1
	outerTargetPc := findInstrIdx(instructions, outerTarget)
	if outerTargetPc >= len(instructions) {
		return false
	}

	for innerPc < outerTargetPc && !isBranchOpcode(instructions[innerPc].Opcode) {
		innerPc++
	}
	if innerPc >= outerTargetPc {
		return false
	}
	innerInst := instructions[innerPc]
	if innerInst.Opcode == Goto || !isConditionZeroOpcode(innerInst.Opcode) {
		return false
	}

	innerTarget := innerInst.Offset + branchOffset(innerInst)
	innerTargetIdx := findInstrIdx(instructions, innerTarget)
	if innerTargetIdx >= len(instructions) {
		return false
	}
	innerTrueInst := instructions[innerTargetIdx]
	if innerTrueInst.Opcode != Iconst1 {
		return false
	}

	innerGotoIdx := innerTargetIdx + 1
	if innerGotoIdx >= len(instructions) {
		return false
	}
	innerGotoInst := instructions[innerGotoIdx]
	if innerGotoInst.Opcode != Goto {
		return false
	}

	mergeOffset := innerGotoInst.Offset + branchOffset(innerGotoInst)
	mergeIdx := findInstrIdx(instructions, mergeOffset)
	if mergeIdx >= len(instructions) {
		return false
	}

	if mergeIdx > 0 {
		falseInst := instructions[mergeIdx-1]
		if falseInst.Opcode != Iconst0 {
			return false
		}
	}

	targetCondPc := outerTargetPc
	for targetCondPc < len(instructions) && !isConditionZeroOpcode(instructions[targetCondPc].Opcode) {
		targetCondPc++
	}
	if targetCondPc >= len(instructions) {
		return false
	}
	targetInst := instructions[targetCondPc]
	targetCondTarget := targetInst.Offset + branchOffset(targetInst)
	targetCondIdx := findInstrIdx(instructions, targetCondTarget)
	if targetCondIdx >= len(instructions) {
		return false
	}
	falseTargetInst := instructions[targetCondIdx]
	if falseTargetInst.Opcode != Iconst0 {
		return false
	}

	cond1Expr := buildConditionDirect(inst, stack, boolParams)

	for i := pc + 1; i < innerPc; i++ {
		decompileInstruction(cf, nil, instructions, instructions[i], localVars, stack, "")
	}

	cond2Expr := buildConditionDirect(innerInst, stack, boolParams)

	combined := &ir.BinaryExpr{
		Op:    "||",
		Left:  cond1Expr,
		Right: cond2Expr,
	}
	stack.push(combined)
	return true
}

func buildConditionDirect(inst Instruction, stack *exprStack, boolParams *boolTypeInfo) ir.Expr {
	opcode := inst.Opcode
	if isComp2Opcode(opcode) {
		right := stack.pop()
		left := stack.pop()
		op := condOpFor(opcode)
		return &ir.BinaryExpr{Op: op, Left: left, Right: right}
	}
	left := stack.pop()
	if isCompareOpcode(left) {
		return resolveCmpExprDirect(left, opcode)
	}
	if isBoolExpr(opcode) && exprIsKnownBoolean(left, boolParams) {
		if opcode == Ifeq || opcode == Ifnull {
			return &ir.UnaryExpr{Op: "!", Expr: left}
		}
		return left
	}
	op := condOpFor(opcode)
	return &ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}
}

// exprIsKnownBoolean reports whether e is definitely known to be a real
// boolean-typed expression, from any of the three sources boolParams
// combines. A LocalVar covers both actual local variables (checked via
// LocalNames, keyed by resolved display name since that's all a LocalVar
// carries) AND the current class's own static/instance fields accessed
// without a qualifier (see decoder.go's Getstatic/Getfield handling,
// which represents "this class's own field" as a bare LocalVar rather
// than a FieldAccess specifically to avoid an unnecessary qualifier -
// both need checking here for exactly the same reason).
func exprIsKnownBoolean(e ir.Expr, boolParams *boolTypeInfo) bool {
	if boolParams == nil {
		return false
	}
	switch v := e.(type) {
	case *ir.LocalVar:
		return boolParams.LocalNames[v.Name] || boolParams.Fields[v.Name]
	case *ir.FieldAccess:
		return boolParams.Fields[v.Name]
	}
	return false
}

func resolveCmpExprDirect(e ir.Expr, branchOpcode Opcode) ir.Expr {
	be := e.(*ir.BinaryExpr)
	left := be.Left
	right := be.Right
	op := condOpFor(branchOpcode)
	return &ir.BinaryExpr{Op: op, Left: left, Right: right}
}

func isBoolExpr(opcode Opcode) bool {
	return opcode == Ifeq || opcode == Ifne
}

func getLocalVarIndex(name string) int {
	n := len(name)
	if n == 0 {
		return -1
	}
	if n > 3 && name[:3] == "arg" {
		var idx int
		for i := 3; i < n; i++ {
			if name[i] < '0' || name[i] > '9' {
				return -1
			}
			idx = idx*10 + int(name[i]-'0')
		}
		return idx
	}
	if n > 6 && name[:6] == "local_" {
		var idx int
		for i := 6; i < n; i++ {
			if name[i] < '0' || name[i] > '9' {
				return -1
			}
			idx = idx*10 + int(name[i]-'0')
		}
		return idx
	}
	return -1
}

func findCompoundBooleanEnd(instructions []Instruction, pc int) int {
	inst := instructions[pc]
	outerTarget := inst.Offset + branchOffset(inst)
	outerTargetPc := findInstrIdx(instructions, outerTarget)

	innerPc := pc + 1
	for innerPc < outerTargetPc && !isBranchOpcode(instructions[innerPc].Opcode) {
		innerPc++
	}
	if innerPc >= outerTargetPc {
		return pc + 1
	}
	innerInst := instructions[innerPc]
	innerTarget := innerInst.Offset + branchOffset(innerInst)
	innerTargetIdx := findInstrIdx(instructions, innerTarget)
	innerGotoIdx := innerTargetIdx + 1
	if innerGotoIdx >= len(instructions) {
		return pc + 1
	}
	innerGotoInst := instructions[innerGotoIdx]
	mergeOffset := innerGotoInst.Offset + branchOffset(innerGotoInst)
	return findInstrIdx(instructions, mergeOffset)
}

func buildConditionForBool(inst Instruction, stack *exprStack, boolParams *boolTypeInfo) ir.Expr {
	opcode := inst.Opcode
	if isComp2Opcode(opcode) {
		right := stack.pop()
		left := stack.pop()
		op := negateCondOp(condOpFor(opcode))
		return &ir.BinaryExpr{Op: op, Left: left, Right: right}
	}
	left := stack.pop()
	if isCompareOpcode(left) {
		be := left.(*ir.BinaryExpr)
		op := negateCondOp(condOpFor(opcode))
		return &ir.BinaryExpr{Op: op, Left: be.Left, Right: be.Right}
	}
	op := negateCondOp(condOpFor(opcode))
	expr := &ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}
	return simplifyBoolExpr(expr, boolParams)
}

func matchBooleanTernary(cf *ClassFile, instructions []Instruction, pc int, stack *exprStack, boolParams *boolTypeInfo) bool {
	inst := instructions[pc]
	if !isConditionZeroOpcode(inst.Opcode) {
		return matchBooleanTernaryNull(cf, instructions, pc, stack, boolParams)
	}

	condOffset := inst.Offset + branchOffset(inst)
	falseInst := findInstrAt(instructions, condOffset)
	if falseInst == nil || falseInst.Opcode != Iconst0 {
		return false
	}

	falseIdx := findInstrIdx(instructions, condOffset)
	if falseIdx < 2 {
		return false
	}

	gotoBackInst := instructions[falseIdx-1]
	if gotoBackInst.Opcode != Goto {
		return false
	}

	trueInstIdx := falseIdx - 2
	if trueInstIdx < 0 {
		return false
	}
	trueInst := instructions[trueInstIdx]
	if trueInst.Opcode != Iconst1 {
		return false
	}

	mergeTarget := gotoBackInst.Offset + branchOffset(gotoBackInst)
	mergeIdx := findInstrIdx(instructions, mergeTarget)
	if mergeIdx >= len(instructions) {
		return false
	}
	mergeInst := instructions[mergeIdx]

	isReturn := mergeInst.Opcode == Ireturn || mergeInst.Opcode == Lreturn || mergeInst.Opcode == Freturn ||
		mergeInst.Opcode == Dreturn || mergeInst.Opcode == Areturn

	isPutstatic := mergeInst.Opcode == Putstatic

	isInvoke := mergeInst.Opcode == Invokevirtual || mergeInst.Opcode == Invokespecial ||
		mergeInst.Opcode == Invokestatic || mergeInst.Opcode == Invokeinterface

	if !isReturn && !isPutstatic && !isInvoke {
		return false
	}

	if isPutstatic {
		putstaticFieldRefIdx := uint16(mergeInst.Operands[0])<<8 | uint16(mergeInst.Operands[1])
		putstaticFieldName := cf.GetFieldName(putstaticFieldRefIdx)
		var getstaticFieldName string
		if pc > 0 {
			prevInst := instructions[pc-1]
			if prevInst.Opcode == Getstatic {
				getstaticFieldName = cf.GetFieldName(uint16(prevInst.Operands[0])<<8 | uint16(prevInst.Operands[1]))
			}
		}
		if putstaticFieldName != getstaticFieldName {
			return false
		}
		left := stack.pop()
		negated := &ir.UnaryExpr{Op: "!", Expr: left}
		stack.push(negated)
		return true
	}

	if isInvoke {
		left := stack.pop()
		op := negateCondOp(condOpFor(inst.Opcode))
		cond := &ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}
		stack.push(cond)
		return true
	}

	op := negateCondOp(condOpFor(inst.Opcode))
	left := stack.pop()
	cond := &ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}
	stack.push(cond)
	return true
}

func findBooleanTernaryEnd(instructions []Instruction, pc int) int {
	inst := instructions[pc]
	if isCompZeroOpcode(inst.Opcode) {
		return findBooleanTernaryEndNull(instructions, pc)
	}
	condOffset := inst.Offset + branchOffset(inst)
	falseIdx := findInstrIdx(instructions, condOffset)
	gotoBackInst := instructions[falseIdx-1]
	mergeTarget := gotoBackInst.Offset + branchOffset(gotoBackInst)
	mergeIdx := findInstrIdx(instructions, mergeTarget)
	return mergeIdx
}

func matchBooleanTernaryNull(cf *ClassFile, instructions []Instruction, pc int, stack *exprStack, boolParams *boolTypeInfo) bool {
	inst := instructions[pc]
	if !isCompZeroOpcode(inst.Opcode) {
		return false
	}

	falseOffset := inst.Offset + branchOffset(inst)
	trueIdx := pc + 1
	if trueIdx >= len(instructions) {
		return false
	}
	trueInst := instructions[trueIdx]
	if trueInst.Opcode != Iconst1 && trueInst.Opcode != Iconst0 {
		return false
	}

	gotoIdx := pc + 2
	if gotoIdx >= len(instructions) {
		return false
	}
	gotoInst := instructions[gotoIdx]
	if gotoInst.Opcode != Goto {
		return false
	}

	falseIdx := findInstrIdx(instructions, falseOffset)
	if falseIdx >= len(instructions) {
		return false
	}
	falseInst := instructions[falseIdx]
	if falseInst.Opcode != Iconst0 && falseInst.Opcode != Iconst1 {
		return false
	}

	mergeOffset := gotoInst.Offset + branchOffset(gotoInst)
	mergeIdx := findInstrIdx(instructions, mergeOffset)
	if mergeIdx >= len(instructions) {
		return false
	}
	mergeInst := instructions[mergeIdx]
	if mergeInst.Opcode != Ireturn && mergeInst.Opcode != Lreturn && mergeInst.Opcode != Freturn &&
		mergeInst.Opcode != Dreturn && mergeInst.Opcode != Areturn {
		return false
	}

	if trueInst.Opcode == Iconst1 && falseInst.Opcode == Iconst0 {
		op := negateCondOp(condOpFor(inst.Opcode))
		left := stack.pop()
		if op == "==" && isCompZeroOpcode(inst.Opcode) {
			stack.push(simplifyBoolExpr(&ir.BinaryExpr{Op: "==", Left: left, Right: &ir.NullLit{}}, boolParams))
		} else if op == "!=" && isCompZeroOpcode(inst.Opcode) {
			stack.push(simplifyBoolExpr(&ir.BinaryExpr{Op: "!=", Left: left, Right: &ir.NullLit{}}, boolParams))
		} else {
			stack.push(simplifyBoolExpr(&ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}, boolParams))
		}
	} else if trueInst.Opcode == Iconst0 && falseInst.Opcode == Iconst1 {
		op := condOpFor(inst.Opcode)
		left := stack.pop()
		if op == "==" && isCompZeroOpcode(inst.Opcode) {
			stack.push(simplifyBoolExpr(&ir.BinaryExpr{Op: "==", Left: left, Right: &ir.NullLit{}}, boolParams))
		} else if op == "!=" && isCompZeroOpcode(inst.Opcode) {
			stack.push(simplifyBoolExpr(&ir.BinaryExpr{Op: "!=", Left: left, Right: &ir.NullLit{}}, boolParams))
		} else {
			stack.push(simplifyBoolExpr(&ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}, boolParams))
		}
	}

	return true
}

func findBooleanTernaryEndNull(instructions []Instruction, pc int) int {
	gotoInst := instructions[pc+2]
	mergeOffset := gotoInst.Offset + branchOffset(gotoInst)
	return findInstrIdx(instructions, mergeOffset)
}

func matchGeneralTernary(cf *ClassFile, instructions []Instruction, pc int, stack *exprStack, boolParams *boolTypeInfo) bool {
	inst := instructions[pc]
	condOffset := inst.Offset + branchOffset(inst)

	falseIdx := findInstrIdx(instructions, condOffset)
	if falseIdx >= len(instructions) {
		return false
	}

	falseInst := instructions[falseIdx]
	if falseInst.Opcode == Goto {
		return false
	}

	trueEndIdx := falseIdx
	if trueEndIdx < 1 {
		return false
	}
	gotoInst := instructions[trueEndIdx-1]
	if gotoInst.Opcode != Goto {
		return false
	}

	mergeOffset := gotoInst.Offset + branchOffset(gotoInst)
	mergeIdx := findInstrIdx(instructions, mergeOffset)
	if mergeIdx >= len(instructions) {
		return false
	}

	mergeInst := instructions[mergeIdx]
	isInvoke := mergeInst.Opcode == Invokevirtual || mergeInst.Opcode == Invokespecial ||
		mergeInst.Opcode == Invokestatic || mergeInst.Opcode == Invokeinterface
	isPutstatic := mergeInst.Opcode == Putstatic
	isPutfield := mergeInst.Opcode == Putfield
	isAstore := mergeInst.Opcode == Astore || mergeInst.Opcode == Astore0 ||
		mergeInst.Opcode == Astore1 || mergeInst.Opcode == Astore2 || mergeInst.Opcode == Astore3
	isIstore := mergeInst.Opcode == Istore || mergeInst.Opcode == Istore0 ||
		mergeInst.Opcode == Istore1 || mergeInst.Opcode == Istore2 || mergeInst.Opcode == Istore3
	isLstore := mergeInst.Opcode == Lstore || mergeInst.Opcode == Lstore0 ||
		mergeInst.Opcode == Lstore1 || mergeInst.Opcode == Lstore2 || mergeInst.Opcode == Lstore3
	isFstore := mergeInst.Opcode == Fstore || mergeInst.Opcode == Fstore0 ||
		mergeInst.Opcode == Fstore1 || mergeInst.Opcode == Fstore2 || mergeInst.Opcode == Fstore3
	isDstore := mergeInst.Opcode == Dstore || mergeInst.Opcode == Dstore0 ||
		mergeInst.Opcode == Dstore1 || mergeInst.Opcode == Dstore2 || mergeInst.Opcode == Dstore3
	isReturn := mergeInst.Opcode == Ireturn || mergeInst.Opcode == Lreturn ||
		mergeInst.Opcode == Freturn || mergeInst.Opcode == Dreturn || mergeInst.Opcode == Areturn

	if !isInvoke && !isPutstatic && !isPutfield && !isAstore && !isIstore &&
		!isLstore && !isFstore && !isDstore && !isReturn {
		return false
	}

	left := stack.pop()

	trueStack := &exprStack{}
	for i := pc + 1; i < trueEndIdx-1; i++ {
		decompileInstruction(cf, nil, instructions, instructions[i], make(map[uint16]string), trueStack, "")
	}
	var trueExpr ir.Expr
	if len(trueStack.items) > 0 {
		trueExpr = trueStack.pop()
	}

	falseStack := &exprStack{}
	for i := falseIdx; i < mergeIdx; i++ {
		decompileInstruction(cf, nil, instructions, instructions[i], make(map[uint16]string), falseStack, "")
	}
	var falseExpr ir.Expr
	if len(falseStack.items) > 0 {
		falseExpr = falseStack.pop()
	}

	if trueExpr == nil || falseExpr == nil {
		stack.push(left)
		return false
	}

	op := negateCondOp(condOpFor(inst.Opcode))
	var cond ir.Expr
	if isComp2Opcode(inst.Opcode) {
		right := left
		left = stack.pop()
		cond = simplifyBoolExpr(&ir.BinaryExpr{Op: op, Left: left, Right: right}, boolParams)
	} else {
		cond = simplifyBoolExpr(&ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}, boolParams)
	}

	ternary := &ir.TernaryExpr{
		Cond:      cond,
		TrueExpr:  trueExpr,
		FalseExpr: falseExpr,
	}
	stack.push(ternary)
	return true
}

func localVarsFromStack(stack *exprStack) map[uint16]string {
	return make(map[uint16]string)
}

func decompileBlockBody(cf *ClassFile, instructions []Instruction, start, end int, localVars map[uint16]string, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) []ir.Stmt {
	blockBodyCallBudget--
	if blockBodyCallBudget <= 0 {
		panic(blockBodyBudgetExceeded{})
	}

	// Recognize a try/catch construct that starts within this block's
	// own range - mirrors the same fix already applied for
	// Tableswitch/Lookupswitch: wrapTryCatch alone only ever ran once,
	// at the very top of a method, so a try/catch nested inside an
	// if/while/case (i.e. anywhere this function - not wrapTryCatch -
	// is what actually decompiles) was never recognized as try/catch at
	// all, and its astore/exception-handling instructions were
	// decompiled as if they were ordinary code.
	var tryGroupsByStart map[int]tryCatchGroup
	if all := getTryGroupsByStart(exceptionTable, instructions); len(all) > 0 {
		for idx, g := range all {
			if idx >= start && idx < end {
				if tryGroupsByStart == nil {
					tryGroupsByStart = make(map[int]tryCatchGroup)
				}
				tryGroupsByStart[idx] = g
			}
		}
	}

	var stmts []ir.Stmt
	tempStack := &exprStack{}
	j := start
	for j < end {
		if g, ok := tryGroupsByStart[j]; ok {
			effectiveG := g
			if effectiveG.BodyEndIdx > end {
				// This block's own boundary (end) cuts through the
				// try/catch construct's real extent - e.g. decompileIfElse
				// trimmed only the LAST of the construct's two independent
				// exits (the catch handler's own trailing goto) when
				// computing where its then-branch stops, leaving `end`
				// pointing partway through the catch body. Clamp to what
				// was actually passed in rather than reading past it.
				effectiveG.BodyEndIdx = end
			}
			tcStmts, newBodyEnd := decompileTryCatchGroup(cf, effectiveG, instructions, localVars, className, boolParams, exceptionTable)
			stmts = append(stmts, tcStmts...)
			if newBodyEnd > end {
				newBodyEnd = end
			}
			j = newBodyEnd
			continue
		}
		inst := instructions[j]
		if isBranchOpcode(inst.Opcode) && inst.Opcode != Goto {
			if isConditionZeroOpcode(inst.Opcode) || isCompZeroOpcode(inst.Opcode) || isComp2Opcode(inst.Opcode) {
				ifMatched := false
			if (isConditionZeroOpcode(inst.Opcode) || isCompZeroOpcode(inst.Opcode) || isComp2Opcode(inst.Opcode)) && matchGeneralTernary(cf, instructions, j, tempStack, boolParams) {
				mergeIdx := findGeneralTernaryEnd(instructions, j)
				if mergeIdx > j {
					j = mergeIdx
					ifMatched = true
				}
			}
				if !ifMatched {
					if stmt, newJ := matchArrayInit(cf, instructions, j, localVars, tempStack, className); newJ > j {
						if stmt != nil {
							stmts = append(stmts, stmt...)
						}
						j = newJ
						continue
					}
					stmt, newJ := decompileIfElse(cf, instructions, j, localVars, tempStack, className, boolParams, exceptionTable)
					if stmt != nil && newJ > j {
						if _, ok := stmt[0].(*ir.ForEachStmt); ok {
							stmts = removeTrailingIteratorSetup(stmts)
						}
						stmts = append(stmts, stmt...)
						j = newJ
						continue
					}
					tempStack.push(buildCondition(inst, tempStack, boolParams))
					j++
				}
				continue
			}
		}
		if inst.Opcode == Tableswitch || inst.Opcode == Lookupswitch {
			if stmt, newJ := decompileSwitch(cf, instructions[:end], j, localVars, tempStack, className, boolParams, exceptionTable); stmt != nil && newJ > j {
				stmts = append(stmts, stmt...)
				j = newJ
				continue
			}
		}
		if stmt, newJ := matchArrayInit(cf, instructions, j, localVars, tempStack, className); newJ > j {
			if stmt != nil {
				stmts = append(stmts, stmt...)
			}
			j = newJ
			continue
		}
		resultStmts := decompileInstruction(cf, nil, instructions, inst, localVars, tempStack, className)
		stmts = append(stmts, resultStmts...)
		j++
	}
	for _, e := range tempStack.items {
		if _, ok := e.(*ir.LocalVar); !ok {
			stmts = append(stmts, &ir.ExprStmt{Expr: e})
		}
	}
	return eliminateDeadCode(stmts)
}

func findGeneralTernaryEnd(instructions []Instruction, pc int) int {
	inst := instructions[pc]
	condOffset := inst.Offset + branchOffset(inst)
	falseIdx := findInstrIdx(instructions, condOffset)
	trueEndIdx := falseIdx
	gotoInst := instructions[trueEndIdx-1]
	mergeOffset := gotoInst.Offset + branchOffset(gotoInst)
	mergeIdx := findInstrIdx(instructions, mergeOffset)
	return mergeIdx
}

func matchArrayInit(cf *ClassFile, instructions []Instruction, pc int, localVars map[uint16]string, stack *exprStack, className string) ([]ir.Stmt, int) {
	if pc+2 >= len(instructions) {
		return nil, 0
	}
	inst := instructions[pc]
	if inst.Opcode != Newarray && inst.Opcode != Anewarray {
		return nil, 0
	}
	newarrayPc := pc
	newarrayInst := instructions[newarrayPc]
	if newarrayPc+1 >= len(instructions) || instructions[newarrayPc+1].Opcode != Dup {
		return nil, 0
	}
	typeByte := newarrayInst.Operands[0]
	var typeName string
	if newarrayInst.Opcode == Anewarray {
		idx := uint16(newarrayInst.Operands[0])<<8 | uint16(newarrayInst.Operands[1])
		typeName = classNameToJavaName(cf.GetClassName(idx))
	} else {
		typeName = newarrayTypeName(typeByte)
	}
	elems := []ir.Expr{}
	curPc := newarrayPc + 1
	maxElements := 32
	for i := 0; i < maxElements; i++ {
		if curPc >= len(instructions) {
			break
		}
		if instructions[curPc].Opcode == Dup {
			curPc++
			if curPc >= len(instructions) {
				break
			}
		}
		if instructions[curPc].Opcode == Areturn || instructions[curPc].Opcode == Ireturn ||
			instructions[curPc].Opcode == Lreturn || instructions[curPc].Opcode == Freturn ||
			instructions[curPc].Opcode == Dreturn || instructions[curPc].Opcode == Return {
			break
		}
		opc := instructions[curPc].Opcode
		if opc != Iconst0 && opc != Iconst1 && opc != Iconst2 && opc != Iconst3 &&
			opc != Iconst4 && opc != Iconst5 && opc != IconstM1 &&
			opc != Bipush && opc != Sipush && opc != Ldc {
			break
		}
		idxPc := curPc
		curPc++
		if curPc >= len(instructions) {
			break
		}
		valStack := &exprStack{}
		for curPc < len(instructions) {
			opcode := instructions[curPc].Opcode
			if opcode == Fastore || opcode == Iastore || opcode == Dastore ||
				opcode == Lastore || opcode == Aastore || opcode == Bastore || opcode == Sastore {
				curPc++
				break
			}
			if opcode == Dup || opcode == Areturn || opcode == Return ||
				opcode == Ireturn || opcode == Lreturn || opcode == Freturn ||
				opcode == Dreturn {
				break
			}
			decompileInstruction(cf, nil, instructions, instructions[curPc], localVars, valStack, className)
			curPc++
		}
		if len(valStack.items) > 0 {
			elems = append(elems, valStack.pop())
		} else {
			break
		}
		_ = idxPc
	}
	if len(elems) == 0 {
		return nil, 0
	}
	initExpr := &ir.ArrayInitExpr{
		ElemType: &ir.PrimitiveType{Name: typeName},
		Elems:    elems,
	}
	if curPc < len(instructions) && instructions[curPc].Opcode == Areturn {
		return []ir.Stmt{&ir.ReturnStmt{Value: initExpr}}, curPc + 1
	}
	if curPc < len(instructions) {
		nextOp := instructions[curPc].Opcode
		if nextOp == Invokestatic || nextOp == Invokevirtual || nextOp == Invokespecial || nextOp == Invokeinterface {
			stack.push(initExpr)
			return nil, curPc
		}
	}
	return []ir.Stmt{&ir.ExprStmt{Expr: initExpr}}, curPc
}

func buildCondition(inst Instruction, stack *exprStack, boolParams *boolTypeInfo) ir.Expr {
	opcode := inst.Opcode
	if isComp2Opcode(opcode) {
		right := stack.pop()
		left := stack.pop()
		op := negateCondOp(condOpFor(opcode))
		return &ir.BinaryExpr{Op: op, Left: left, Right: right}
	}
	left := stack.pop()
	if isCompareOpcode(left) {
		return resolveCmpExpr(left, opcode)
	}
	op := negateCondOp(condOpFor(opcode))
	if isCompZeroOpcode(opcode) {
		return &ir.BinaryExpr{Op: op, Left: left, Right: &ir.NullLit{}}
	}
	expr := &ir.BinaryExpr{Op: op, Left: left, Right: &ir.IntLit{Value: 0}}
	return simplifyBoolExpr(expr, boolParams)
}

func simplifyBoolExpr(expr ir.Expr, boolParams *boolTypeInfo) ir.Expr {
	be, ok := expr.(*ir.BinaryExpr)
	if !ok {
		return expr
	}
	if intLit, ok := be.Right.(*ir.IntLit); ok && intLit.Value == 0 {
		if isMethodLikeExpr(be.Left) || exprIsKnownBoolean(be.Left, boolParams) {
			switch be.Op {
			case "!=":
				return be.Left
			case "==":
				return &ir.UnaryExpr{Op: "!", Expr: be.Left}
			}
		}
	}
	return expr
}

func isMethodLikeExpr(e ir.Expr) bool {
	switch e.(type) {
	case *ir.MethodCall, *ir.StaticMethodCall:
		return true
	}
	return false
}

func isCompareOpcode(e ir.Expr) bool {
	if be, ok := e.(*ir.BinaryExpr); ok {
		switch be.Op {
		case "fcmpg", "fcmpl", "dcmpg", "dcmpl", "lcmp":
			return true
		}
	}
	return false
}

func resolveCmpExpr(e ir.Expr, branchOpcode Opcode) ir.Expr {
	be := e.(*ir.BinaryExpr)
	left := be.Left
	right := be.Right
	var op string
	switch branchOpcode {
	case Ifeq:
		op = "=="
	case Ifne:
		op = "!="
	case Iflt:
		op = "<"
	case Ifge:
		op = ">="
	case Ifgt:
		op = ">"
	case Ifle:
		op = "<="
	default:
		op = ">="
	}
	return &ir.BinaryExpr{Op: negateCondOp(op), Left: left, Right: right}
}

// fallsThroughTo reports whether instruction index `from` reaches index
// `to` by pure straight-line execution: from == to, or from < to and every
// instruction in [from, to) is a non-branching, non-terminating
// instruction (so control can't leave that span except by falling off the
// end of it). This is used to recognize that two different-looking merge
// points (one chain link's Goto lands exactly on the chain's tail, another
// lands a few instructions earlier that simply fall through to the same
// place) are really the same logical destination.
func fallsThroughTo(instructions []Instruction, from, to int) bool {
	if from == to {
		return true
	}
	if from < 0 || to < 0 || from > to || to > len(instructions) {
		return false
	}
	for i := from; i < to; i++ {
		if isBranchOpcode(instructions[i].Opcode) {
			return false
		}
		switch instructions[i].Opcode {
		case Tableswitch, Lookupswitch, Areturn, Ireturn, Lreturn, Freturn, Dreturn, Return, Athrow:
			return false
		}
	}
	return true
}

// elseIfChainLink is one detected link ("preamble; comparison; short
// then-body; goto shared-tail") in an if/else-if/.../else chain.
type elseIfChainLink struct {
	cond      ir.Expr
	preamble  []ir.Stmt
	thenStmts []ir.Stmt
}

// collectElseIfChain iteratively walks a chain of if/else-if links that all
// converge on the same final merge point (chainEnd), starting from a first
// link whose condition/then-range have already been computed by
// decompileIfElse. It returns the fully assembled (possibly deeply nested)
// *ir.IfStmt and the instruction index where control resumes after the
// whole chain - or (nil, 0) if this isn't actually a chain of 2+ links (in
// which case the caller should fall back to its normal single if/else
// handling).
//
// The property that makes this safe and correct, and that avoids
// exponential blowup: every link's preamble and then-body is decompiled
// exactly once (each is a short, non-overlapping range unique to that
// link), and the shared tail beyond the whole chain is decompiled exactly
// once at the end - never once per link. A naive recursive expansion (each
// link's "else" is "decompile everything from here to the chain's end",
// which contains the next link, whose own "else" again spans nearly the
// same remaining instructions) redoes that work once per remaining link;
// for a chain of N links that makes the total work exponential in N rather
// than linear, which is what made real-world methods with long
// value-comparison chains (a common shape for compiler/tool-generated
// toString()/equals() methods with many fields, or a switch lowered to
// if-chains) take effectively forever to decompile.
func collectElseIfChain(cf *ClassFile, instructions []Instruction, firstCond ir.Expr, firstThenStart, firstThenEnd, chainEnd int, localVars map[uint16]string, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) (ir.Stmt, int) {
	type link struct {
		cond      ir.Expr
		preambleStmts []ir.Stmt
		thenStart int
		thenEnd   int // exclusive, does not include the trailing Goto
	}

	links := []link{{cond: firstCond, thenStart: firstThenStart, thenEnd: firstThenEnd}}
	cursor := firstThenEnd + 1 // +1 skips the first link's trailing Goto

	for cursor < chainEnd && cursor < len(instructions) {
		// Scan forward from cursor through any pure stack-effect
		// instructions (loads/pushes) that build up the operands for the
		// next comparison - "if (x == N)" needs its operands pushed
		// before the actual branch opcode runs, exactly as
		// decompileBlockBody's own loop processes ordinary instructions
		// before reaching a branch. Everything scanned is captured as
		// preambleStmts so it can be emitted before the comparison,
		// exactly where it would have appeared in a normal linear walk.
		linkStack := &exprStack{}
		var preambleStmts []ir.Stmt
		scan := cursor
		ok := true
		for scan < chainEnd && scan < len(instructions) {
			in := instructions[scan]
			if isBranchOpcode(in.Opcode) {
				break
			}
			stmts := decompileInstruction(cf, nil, instructions, in, localVars, linkStack, className)
			preambleStmts = append(preambleStmts, stmts...)
			scan++
		}
		if scan >= chainEnd || scan >= len(instructions) {
			ok = false
		}

		var next Instruction
		if ok {
			next = instructions[scan]
			if !isBranchOpcode(next.Opcode) || next.Opcode == Goto {
				ok = false
			} else if !(isConditionZeroOpcode(next.Opcode) || isCompZeroOpcode(next.Opcode) || isComp2Opcode(next.Opcode)) {
				ok = false
			}
		}

		var nextElseStart int
		if ok {
			nextTarget := next.Offset + branchOffset(next)
			nextElseStart = findInstrIdx(instructions, nextTarget)
			if nextElseStart <= scan+1 || nextElseStart > chainEnd {
				ok = false
			}
		}

		var nextElseTargetIdx int
		if ok {
			nextLastThen := instructions[nextElseStart-1]
			if nextLastThen.Opcode != Goto {
				ok = false
			} else {
				nextElseTarget := nextLastThen.Offset + branchOffset(nextLastThen)
				nextElseTargetIdx = findInstrIdx(instructions, nextElseTarget)
				// A genuine link in the SAME chain must have its
				// then-body's Goto land on the chain's shared merge
				// point - either exactly, or by falling straight
				// through (no intervening branches) to it, since
				// compilers sometimes jump directly to the final merge
				// point and sometimes to an equivalent point a few
				// non-branching instructions earlier. Anything else (a
				// Goto elsewhere - e.g. a nested loop/if inside this
				// comparison's own then-body) means this isn't a peer
				// link, and the remainder must instead be decompiled
				// normally as the tail.
				if !fallsThroughTo(instructions, nextElseTargetIdx, chainEnd) {
					ok = false
				}
			}
		}

		if !ok {
			break
		}

		nextCond := buildCondition(next, linkStack, boolParams)
		links = append(links, link{
			cond:          nextCond,
			preambleStmts: preambleStmts,
			thenStart:     scan + 1,
			thenEnd:       nextElseStart - 1,
		})
		cursor = nextElseStart
	}

	if len(links) < 2 {
		// Not actually a chain (only the original single if/else) -
		// let the caller fall back to its normal handling.
		return nil, 0
	}

	// Decompile each link's own short then-body, and the shared tail
	// beyond the whole chain, each exactly once.
	tailStmts := decompileBlockBody(cf, instructions, cursor, chainEnd, localVars, className, boolParams, exceptionTable)

	compiledLinks := make([]elseIfChainLink, len(links))
	for i, l := range links {
		compiledLinks[i] = elseIfChainLink{
			cond:      l.cond,
			preamble:  l.preambleStmts,
			thenStmts: decompileBlockBody(cf, instructions, l.thenStart, l.thenEnd, localVars, className, boolParams, exceptionTable),
		}
	}

	// Assemble bottom-up: the tail becomes the innermost Else, and each
	// preceding link wraps the one after it as its Else. A link with a
	// non-empty preamble (side-effecting setup needed to evaluate its
	// condition) emits that preamble as ordinary statements immediately
	// before its IfStmt, inside the same block as the wrapping link's
	// Else - exactly where it would run in the original linear bytecode.
	var resultTail []ir.Stmt
	if len(tailStmts) > 0 {
		resultTail = tailStmts
	}
	for i := len(compiledLinks) - 1; i >= 0; i-- {
		stmt := &ir.IfStmt{
			Cond: compiledLinks[i].cond,
			Then: &ir.Block{Statements: compiledLinks[i].thenStmts},
		}
		if len(resultTail) > 0 {
			stmt.Else = &ir.Block{Statements: resultTail}
		}
		wrapped := append(append([]ir.Stmt{}, compiledLinks[i].preamble...), stmt)
		resultTail = wrapped
	}

	if len(resultTail) == 0 {
		return nil, 0
	}
	if len(resultTail) == 1 {
		return resultTail[0], chainEnd
	}
	// The outermost link had a non-empty preamble: wrap it and the IfStmt
	// together so the caller (which expects a single ir.Stmt) still gets
	// everything, in order.
	return &ir.BlockStmt{Block: &ir.Block{Statements: resultTail}}, chainEnd
}

func decompileIfElse(cf *ClassFile, instructions []Instruction, pc int, localVars map[uint16]string, stack *exprStack, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) ([]ir.Stmt, int) {
	inst := instructions[pc]
	target := inst.Offset + branchOffset(inst)
	if target <= inst.Offset {
		return nil, 0
	}

	thenStart := pc + 1
	elseStart := findInstrIdx(instructions, target)
	if elseStart <= thenStart {
		return nil, 0
	}

	lastThen := instructions[elseStart-1]

	cond := buildCondition(inst, stack, boolParams)

	if lastThen.Opcode == Goto {
		elseTarget := lastThen.Offset + branchOffset(lastThen)

		if elseTarget <= inst.Offset {
			bodyEnd := elseStart

			if fe, fePc := tryForEachLoop(cf, instructions, elseStart-1, pc, inst, bodyEnd, localVars, stack, className, boolParams, exceptionTable); fe != nil {
				return []ir.Stmt{fe}, fePc
			}

			bodyStmts := decompileBlockBody(cf, instructions, thenStart, bodyEnd-1, localVars, className, boolParams, exceptionTable)

			stmt := &ir.WhileStmt{
				Cond: cond,
				Body: &ir.Block{Statements: bodyStmts},
			}
			return []ir.Stmt{stmt}, elseStart
		}

		if elseTarget <= target {
			thenStmts := decompileBlockBody(cf, instructions, thenStart, elseStart, localVars, className, boolParams, exceptionTable)
			stmt := &ir.IfStmt{
				Cond: cond,
				Then: &ir.Block{Statements: thenStmts},
			}
			return []ir.Stmt{stmt}, elseStart
		}
		elseEnd := findInstrIdx(instructions, elseTarget)
		if elseEnd <= elseStart {
			return nil, 0
		}

		// This may be the first link of a chain of comparisons that all
		// converge on the same final merge point (elseEnd) - see
		// collectElseIfChain's doc comment for why this needs to be
		// detected and flattened iteratively rather than left to plain
		// recursion.
		if chainStmt, chainEnd := collectElseIfChain(cf, instructions, cond, thenStart, elseStart-1, elseEnd, localVars, className, boolParams, exceptionTable); chainStmt != nil {
			return []ir.Stmt{chainStmt}, chainEnd
		}

		thenStmts := decompileBlockBody(cf, instructions, thenStart, elseStart-1, localVars, className, boolParams, exceptionTable)
		elseStmts := decompileBlockBody(cf, instructions, elseStart, elseEnd, localVars, className, boolParams, exceptionTable)

		stmt := &ir.IfStmt{
			Cond: cond,
			Then: &ir.Block{Statements: thenStmts},
			Else: &ir.Block{Statements: elseStmts},
		}
	return []ir.Stmt{stmt}, elseEnd
	}

	thenStmts := decompileBlockBody(cf, instructions, thenStart, elseStart, localVars, className, boolParams, exceptionTable)

	stmt := &ir.IfStmt{
		Cond: cond,
		Then: &ir.Block{Statements: thenStmts},
	}
	return []ir.Stmt{stmt}, elseStart
}

func tryWhileLoop(cf *ClassFile, instructions []Instruction, pc int, localVars map[uint16]string, stack *exprStack, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) ([]ir.Stmt, int) {
	inst := instructions[pc]
	offset := branchOffset(inst)
	target := inst.Offset + offset

	condIdx := findInstrIdx(instructions, target)
	if condIdx >= len(instructions) {
		return nil, 0
	}

	condInst := instructions[condIdx]
	if !isBranchOpcode(condInst.Opcode) || condInst.Opcode == Goto {
		scanEnd := min(condIdx+5, len(instructions))
		found := false
		for j := condIdx; j < scanEnd; j++ {
			if isBranchOpcode(instructions[j].Opcode) && instructions[j].Opcode != Goto {
				condIdx = j
				condInst = instructions[j]
				found = true
				break
			}
		}
		if !found {
			return nil, 0
		}
	}

	condTarget := condInst.Offset + branchOffset(condInst)
	if condTarget <= condInst.Offset {
		return nil, 0
	}

	bodyEnd := findInstrIdx(instructions, condTarget)
	if bodyEnd <= condIdx+1 {
		return nil, 0
	}

	if fe, fePc := tryForEachLoop(cf, instructions, pc, condIdx, condInst, bodyEnd, localVars, stack, className, boolParams, exceptionTable); fe != nil {
		return []ir.Stmt{fe}, fePc
	}

	cond := buildCondition(condInst, stack, boolParams)

	bodyStmts := decompileBlockBody(cf, instructions, condIdx+1, bodyEnd, localVars, className, boolParams, exceptionTable)

	stmt := &ir.WhileStmt{
		Cond: cond,
		Body: &ir.Block{Statements: bodyStmts},
	}
	return []ir.Stmt{stmt}, bodyEnd
}

func tryForEachLoop(cf *ClassFile, instructions []Instruction, gotoPc int, condIdx int, condInst Instruction, bodyEnd int, localVars map[uint16]string, stack *exprStack, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) (*ir.ForEachStmt, int) {
	if condInst.Opcode != Ifne && condInst.Opcode != Ifeq {
		return nil, 0
	}

	nextIdx := -1
	for i := condIdx + 1; i < len(instructions) && i < condIdx+8; i++ {
		if instructions[i].Opcode == Invokeinterface {
			refIdx := uint16(instructions[i].Operands[0])<<8 | uint16(instructions[i].Operands[1])
			methodName := cf.GetMethodName(refIdx)
			if methodName == "next" {
				nextIdx = i
				break
			}
		}
	}
	if nextIdx == -1 {
		return nil, 0
	}
	if nextIdx+2 >= len(instructions) {
		return nil, 0
	}
	castInst := instructions[nextIdx+1]
	if castInst.Opcode != Checkcast {
		return nil, 0
	}
	castRefIdx := uint16(castInst.Operands[0])<<8 | uint16(castInst.Operands[1])
	castTypeName := cf.GetClassName(castRefIdx)
	elemType := &ir.ClassType{Name: castTypeName}

 astoreInst := instructions[nextIdx+2]
	if astoreInst.Opcode != Astore && (astoreInst.Opcode < Astore0 || astoreInst.Opcode > Astore3) {
		return nil, 0
	}
	var elemIdx byte
	if astoreInst.Opcode >= Astore0 && astoreInst.Opcode <= Astore3 {
		elemIdx = byte(astoreInst.Opcode - Astore0)
	} else {
		elemIdx = astoreInst.Operands[0]
	}
	elemVar := getLocalVar(localVars, elemIdx)

	var iterVarIdx byte = 0xff
	for j := condIdx - 1; j >= 0 && j >= condIdx-6; j-- {
		prevInst := instructions[j]
		if prevInst.Opcode == Aload || (prevInst.Opcode >= Aload0 && prevInst.Opcode <= Aload3) {
			if prevInst.Opcode >= Aload0 && prevInst.Opcode <= Aload3 {
				iterVarIdx = byte(prevInst.Opcode - Aload0)
			} else {
				iterVarIdx = prevInst.Operands[0]
			}
			break
		}
	}
	if iterVarIdx == 0xff {
		return nil, 0
	}

	var collExpr ir.Expr
	searchStart := condIdx - 2
	if searchStart < 0 {
		searchStart = 0
	}
	searchEnd := condIdx - 20
	if searchEnd < 0 {
		searchEnd = 0
	}
	for i := searchStart; i >= searchEnd; i-- {
		if instructions[i].Opcode == Invokeinterface {
			refIdx := uint16(instructions[i].Operands[0])<<8 | uint16(instructions[i].Operands[1])
			methodName := cf.GetMethodName(refIdx)
			if methodName == "iterator" {
				if i+1 < len(instructions) {
				 astoreInst2 := instructions[i+1]
					if astoreInst2.Opcode == Astore || (astoreInst2.Opcode >= Astore0 && astoreInst2.Opcode <= Astore3) {
						var storedIdx byte
						if astoreInst2.Opcode >= Astore0 && astoreInst2.Opcode <= Astore3 {
							storedIdx = byte(astoreInst2.Opcode - Astore0)
						} else {
							storedIdx = astoreInst2.Operands[0]
						}
						if storedIdx == iterVarIdx {
							if i > 0 {
								loadInst := instructions[i-1]
								if loadInst.Opcode == Getstatic {
									refIdx2 := uint16(loadInst.Operands[0])<<8 | uint16(loadInst.Operands[1])
									className2 := cf.GetFieldClassName(refIdx2)
									fieldName := cf.GetFieldName(refIdx2)
									collExpr = &ir.FieldAccess{
										Object: &ir.LocalVar{Name: className2},
										Name:   fieldName,
									}
								} else if loadInst.Opcode == Aload || (loadInst.Opcode >= Aload0 && loadInst.Opcode <= Aload3) {
									varIdx := byte(0)
									if loadInst.Opcode >= Aload0 && loadInst.Opcode <= Aload3 {
										varIdx = byte(loadInst.Opcode - Aload0)
									} else {
										varIdx = loadInst.Operands[0]
									}
									collExpr = &ir.LocalVar{Name: getLocalVar(localVars, varIdx)}
								} else if loadInst.Opcode == Invokevirtual || loadInst.Opcode == Invokestatic || loadInst.Opcode == Invokeinterface {
									collExpr = buildMethodChainExpr(cf, instructions, i-1, localVars)
								}
							}
						}
					}
				}
				break
			}
		}
	}
	if collExpr == nil {
		return nil, 0
	}

	bodyStmts := decompileBlockBody(cf, instructions, nextIdx+3, bodyEnd, localVars, className, boolParams, exceptionTable)

	return &ir.ForEachStmt{
		VarName: elemVar,
		VarType: elemType,
		Expr:    collExpr,
		Body:    &ir.Block{Statements: bodyStmts},
	}, bodyEnd
}

func isBranchOpcode(op Opcode) bool {
	switch op {
	case Ifeq, Ifne, Iflt, Ifge, Ifgt, Ifle,
		IfIcmpeq, IfIcmpne, IfIcmplt, IfIcmpge, IfIcmpgt, IfIcmple,
		IfAcmpeq, IfAcmpne, Ifnull, Ifnonnull, Goto:
		return true
	}
	return false
}

func isConditionZeroOpcode(op Opcode) bool {
	switch op {
	case Ifeq, Ifne, Iflt, Ifge, Ifgt, Ifle:
		return true
	}
	return false
}

func isComp2Opcode(op Opcode) bool {
	switch op {
	case IfIcmpeq, IfIcmpne, IfIcmplt, IfIcmpge, IfIcmpgt, IfIcmple,
		IfAcmpeq, IfAcmpne:
		return true
	}
	return false
}

func isCompZeroOpcode(op Opcode) bool {
	switch op {
	case Ifnull, Ifnonnull:
		return true
	}
	return false
}

func condOpFor(op Opcode) string {
	switch op {
	case Ifeq:
		return "=="
	case Ifne:
		return "!="
	case Iflt:
		return "<"
	case Ifge:
		return ">="
	case Ifgt:
		return ">"
	case Ifle:
		return "<="
	case IfIcmpeq, IfAcmpeq:
		return "=="
	case IfIcmpne, IfAcmpne:
		return "!="
	case IfIcmplt:
		return "<"
	case IfIcmpge:
		return ">="
	case IfIcmpgt:
		return ">"
	case IfIcmple:
		return "<="
	case Ifnull:
		return "=="
	case Ifnonnull:
		return "!="
	}
	return "=="
}

func negateCondOp(op string) string {
	switch op {
	case "==":
		return "!="
	case "!=":
		return "=="
	case "<":
		return ">="
	case ">=":
		return "<"
	case ">":
		return "<="
	case "<=":
		return ">"
	}
	return op
}

func branchOffset(inst Instruction) int {
	if len(inst.Operands) >= 2 {
		offset := int16(inst.Operands[0])<<8 | int16(inst.Operands[1])
		return int(offset)
	}
	return 0
}

func findInstrAt(instructions []Instruction, offset int) *Instruction {
	i := findInstrIdx(instructions, offset)
	if i < len(instructions) {
		return &instructions[i]
	}
	return nil
}

// findInstrIdx locates the instruction starting at the given bytecode
// offset via binary search - safe because DecodeInstructions always
// produces instructions in strictly increasing Offset order (a single
// sequential forward walk over the code array). Returns
// len(instructions) if no instruction starts exactly there, matching
// the original linear-scan behavior this replaced.
//
// This one function is on the hot path for real, large real-world
// methods: it's called (directly, or via findInstrAt above) from
// roughly 50 sites across this file, several inside loops
// (collectTryCatchGroups, matchTryWithResources) that themselves run
// on nearly every one of the up to maxBlockBodyCallsPerMethod
// recursive decompileBlockBody entries. A linear O(n) scan there
// multiplies out to O(callCount * n) - confirmed via CPU profiling to
// be the actual cause of a real-world 3744-instruction method (a
// protobuf/Kotlin-generated accessor, gv0.class in a test fixture
// jar) taking minutes instead of the sub-second this binary-search
// version produces for the exact same input. The
// maxBlockBodyCallsPerMethod budget bounds call COUNT, not per-call
// cost, so it couldn't have masked this on its own.
func findInstrIdx(instructions []Instruction, offset int) int {
	i := sort.Search(len(instructions), func(i int) bool {
		return instructions[i].Offset >= offset
	})
	if i < len(instructions) && instructions[i].Offset == offset {
		return i
	}
	return len(instructions)
}

// matchOrChainGuard recognizes a short-circuit "||" chain compiled
// without an intermediate goto between conditions - as opposed to
// collectElseIfChain's if/else-if pattern, where each link has its own
// distinct then-body followed by a goto to a common merge point, here
// there is no per-link body: every link in the chain shares ONE body,
// reached either by jumping directly into it (every link except
// possibly the last) or by falling through into it (only the chain's
// last link, when the compiler emits it inverted - see
// decompileOrChainGuard's doc comment for why both shapes occur in real
// bytecode).
//
// Only matches when the shared body provably ends in a return/throw (the
// overwhelmingly common real-world shape - a guard clause bailing out
// early) so the body's own end boundary is unambiguous; other shapes
// fall through to the normal matchers, which at least won't silently
// merge unrelated instructions the way the bug this fixes did.
func matchOrChainGuard(cf *ClassFile, instructions []Instruction, pc int, localVars map[uint16]string, className string, callerStack *exprStack) (links []Instruction, invertedFlags []bool, linkPreambles [][]ir.Stmt, linkStacks []*exprStack, bodyStart, bodyEnd int, ok bool) {
	first := instructions[pc]
	firstTarget := first.Offset + branchOffset(first)
	if firstTarget <= first.Offset {
		return nil, nil, nil, nil, 0, 0, false
	}
	bodyStart = findInstrIdx(instructions, firstTarget)
	if bodyStart <= pc+1 || bodyStart >= len(instructions) {
		return nil, nil, nil, nil, 0, 0, false
	}

	bodyEnd = -1
	// Try to find a return/throw terminator inside the body first - this
	// is the only way to know the body's end boundary when every link in
	// the chain is direct (see below), which is common (e.g. "if (!a ||
	// !b || !c) { ...; return; }"). If none is found, bodyEnd stays -1
	// for now; it may still be recoverable below from an inverted last
	// link's own branch target, which independently encodes exactly
	// where the body ends (skipping over it is precisely what that
	// branch does) - needed for a guard whose body doesn't end in a
	// terminator at all (e.g. a plain assignment: "if (a == null || b)
	// target = find();").
	terminatorBodyEnd := -1
	for i := bodyStart; i < len(instructions); i++ {
		op := instructions[i].Opcode
		switch op {
		case Ireturn, Lreturn, Freturn, Dreturn, Areturn, Return, Athrow:
			terminatorBodyEnd = i + 1
		}
		if terminatorBodyEnd != -1 {
			break
		}
		if isBranchOpcode(op) {
			break // a nested branch before any terminator - the terminator search itself can't determine the boundary this way; an inverted link (checked below) may still resolve it
		}
	}

	links = []Instruction{first}
	invertedFlags = []bool{false}
	linkPreambles = [][]ir.Stmt{nil}
	linkStacks = []*exprStack{callerStack}

	scan := pc + 1
	for scan < bodyStart {
		// Scan forward through any pure stack-effect instructions
		// (loads/pushes) that build up the operands for the next
		// condition - "if (mc.player == null)" needs mc/player pushed
		// via getstatic/getfield before the actual ifnull branch itself
		// runs, exactly as collectElseIfChain's own preamble scanning
		// handles the same situation for its (structurally different)
		// chain pattern. This link's populated stack (holding whatever
		// value the preamble left on it, e.g. mc.player) is returned
		// alongside its instructions so decompileOrChainGuard can build
		// this link's actual condition from it - re-running the
		// preamble against a fresh empty stack there would lose it.
		linkStack := &exprStack{}
		var preamble []ir.Stmt
		for scan < bodyStart && !isBranchOpcode(instructions[scan].Opcode) {
			preamble = append(preamble, decompileInstruction(cf, nil, instructions, instructions[scan], localVars, linkStack, className)...)
			scan++
		}
		if scan >= bodyStart {
			return nil, nil, nil, nil, 0, 0, false
		}

		next := instructions[scan]
		if next.Opcode == Goto {
			return nil, nil, nil, nil, 0, 0, false
		}
		if !(isConditionZeroOpcode(next.Opcode) || isCompZeroOpcode(next.Opcode) || isComp2Opcode(next.Opcode)) {
			return nil, nil, nil, nil, 0, 0, false
		}
		nextTarget := next.Offset + branchOffset(next)
		nextTargetIdx := findInstrIdx(instructions, nextTarget)

		if nextTargetIdx == bodyStart {
			links = append(links, next)
			invertedFlags = append(invertedFlags, false)
			linkPreambles = append(linkPreambles, preamble)
			linkStacks = append(linkStacks, linkStack)
			scan++
			continue
		}

		// Not a direct link - the only other shape recognized is an
		// inverted LAST link (this must be the very last instruction
		// before the body starts, so falling through - its own
		// condition being false - lands directly in the body). Its
		// target is wherever it jumps to when skipping the body
		// entirely, which is exactly the body's end boundary,
		// independent of whatever the terminator scan above found (or
		// didn't).
		if scan == bodyStart-1 && nextTargetIdx > bodyStart {
			links = append(links, next)
			invertedFlags = append(invertedFlags, true)
			linkPreambles = append(linkPreambles, preamble)
			linkStacks = append(linkStacks, linkStack)
			bodyEnd = nextTargetIdx
			scan++
			break
		}

		return nil, nil, nil, nil, 0, 0, false
	}
	if scan != bodyStart {
		return nil, nil, nil, nil, 0, 0, false
	}
	if len(links) < 2 {
		return nil, nil, nil, nil, 0, 0, false // a single condition is just an ordinary if, not a chain
	}

	// No inverted link resolved bodyEnd (every link in the chain was
	// direct) - fall back to the terminator search's result, if any.
	if bodyEnd == -1 {
		if terminatorBodyEnd == -1 {
			return nil, nil, nil, nil, 0, 0, false
		}
		bodyEnd = terminatorBodyEnd
	}

	return links, invertedFlags, linkPreambles, linkStacks, bodyStart, bodyEnd, true
}

// decompileOrChainGuard decompiles the pattern matchOrChainGuard
// recognized: builds the combined "cond1 || cond2 || ... || condN"
// expression and the shared body, and returns the resulting IfStmt plus
// where control resumes after it.
//
// Condition polarity per link kind: a DIRECT link's raw JVM branch means
// "true enters the shared body" - the opposite of buildCondition's usual
// assumption (an ordinary if, where the branch jumps AWAY from the THEN
// it's building a condition for), so buildCondition's result needs
// negateCondExpr to recover the condition that's actually true when the
// branch is taken. An INVERTED link's raw JVM branch means "true SKIPS
// the body" - which matches buildCondition's normal assumption exactly
// (the branch jumps away from what follows when its own test is true),
// so its result is used as-is, no extra negation needed.
func decompileOrChainGuard(cf *ClassFile, instructions []Instruction, links []Instruction, invertedFlags []bool, linkPreambles [][]ir.Stmt, linkStacks []*exprStack, bodyStart, bodyEnd int, localVars map[uint16]string, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) ([]ir.Stmt, int) {
	var preambleStmts []ir.Stmt
	var combined ir.Expr
	for i, link := range links {
		preambleStmts = append(preambleStmts, linkPreambles[i]...)
		raw := buildCondition(link, linkStacks[i], boolParams)
		var cond ir.Expr
		if invertedFlags[i] {
			cond = raw
		} else {
			cond = negateCondExpr(raw)
		}
		if combined == nil {
			combined = cond
		} else {
			combined = &ir.BinaryExpr{Op: "||", Left: combined, Right: cond}
		}
	}

	bodyStmts := decompileBlockBody(cf, instructions, bodyStart, bodyEnd, localVars, className, boolParams, exceptionTable)
	stmt := &ir.IfStmt{
		Cond: combined,
		Then: &ir.Block{Statements: bodyStmts},
	}
	result := append(preambleStmts, stmt)
	return result, bodyEnd
}

func matchGuardClause(cf *ClassFile, instructions []Instruction, pc int, stack *exprStack) bool {
	inst := instructions[pc]
	firstTarget := inst.Offset + branchOffset(inst)
	if firstTarget <= inst.Offset {
		return false
	}

	firstTargetIdx := findInstrIdx(instructions, firstTarget)
	if firstTargetIdx >= len(instructions) {
		return false
	}

	retInst := instructions[firstTargetIdx]
	if !isReturnOpcode(retInst.Opcode) {
		return false
	}

	return true
}

func findGuardClauseEnd(cf *ClassFile, instructions []Instruction, pc int) int {
	inst := instructions[pc]
	firstTarget := inst.Offset + branchOffset(inst)
	firstTargetIdx := findInstrIdx(instructions, firstTarget)

	if firstTargetIdx+1 >= len(instructions) {
		return firstTargetIdx + 1
	}
	return firstTargetIdx + 1
}

func negateCondExpr(e ir.Expr) ir.Expr {
	switch v := e.(type) {
	case *ir.UnaryExpr:
		if v.Op == "!" {
			return v.Expr
		}
		return &ir.UnaryExpr{Op: "!", Expr: e}
	case *ir.BinaryExpr:
		switch v.Op {
		case "==":
			return &ir.BinaryExpr{Op: "!=", Left: v.Left, Right: v.Right}
		case "!=":
			return &ir.BinaryExpr{Op: "==", Left: v.Left, Right: v.Right}
		case "<":
			return &ir.BinaryExpr{Op: ">=", Left: v.Left, Right: v.Right}
		case ">":
			return &ir.BinaryExpr{Op: "<=", Left: v.Left, Right: v.Right}
		case "<=":
			return &ir.BinaryExpr{Op: ">", Left: v.Left, Right: v.Right}
		case ">=":
			return &ir.BinaryExpr{Op: "<", Left: v.Left, Right: v.Right}
		}
	}
	return &ir.UnaryExpr{Op: "!", Expr: e}
}

func decompileGuardClause(cf *ClassFile, instructions []Instruction, pc int, localVars map[uint16]string, stack *exprStack, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) ([]ir.Stmt, int) {
	inst := instructions[pc]
	firstTarget := inst.Offset + branchOffset(inst)
	firstTargetIdx := findInstrIdx(instructions, firstTarget)

	left := stack.pop()
	rawOp := condOpFor(inst.Opcode)
	var cond ir.Expr
	if isCompZeroOpcode(inst.Opcode) {
		cond = simplifyBoolExpr(&ir.BinaryExpr{Op: rawOp, Left: left, Right: &ir.NullLit{}}, boolParams)
	} else {
		cond = simplifyBoolExpr(&ir.BinaryExpr{Op: rawOp, Left: left, Right: &ir.IntLit{Value: 0}}, boolParams)
	}

	stmt := &ir.IfStmt{
		Cond: cond,
		Then: &ir.Block{Statements: []ir.Stmt{&ir.ReturnStmt{}}},
	}

	bodyPc := pc + 1
	bodyStmts := decompileBlockBody(cf, instructions, bodyPc, firstTargetIdx, localVars, className, boolParams, exceptionTable)

	var result []ir.Stmt
	result = append(result, stmt)
	result = append(result, bodyStmts...)

	return result, firstTargetIdx + 1
}

func isReturnOpcode(op Opcode) bool {
	switch op {
	case Return, Ireturn, Lreturn, Freturn, Dreturn, Areturn:
		return true
	}
	return false
}

func matchBoolToggle(cf *ClassFile, instructions []Instruction, pc int, stack *exprStack, className string, boolParams *boolTypeInfo) ([]ir.Stmt, int) {
	inst := instructions[pc]
	if !isConditionZeroOpcode(inst.Opcode) {
		return nil, 0
	}

	target := inst.Offset + branchOffset(inst)
	if target <= inst.Offset {
		return nil, 0
	}

	elseStart := findInstrIdx(instructions, target)
	if elseStart <= pc+1 {
		return nil, 0
	}

	lastThen := instructions[elseStart-1]
	if lastThen.Opcode != Goto {
		return nil, 0
	}

	thenEndOffset := lastThen.Offset + branchOffset(lastThen)
	if thenEndOffset <= inst.Offset {
		return nil, 0
	}

	elseEnd := findInstrIdx(instructions, thenEndOffset)
	if elseEnd <= elseStart {
		return nil, 0
	}

	if elseEnd >= len(instructions) {
		return nil, 0
	}

	thenBody := instructions[pc+1 : elseStart-1]
	elseBody := instructions[elseStart : elseEnd]

	isBoolPush := func(body []Instruction) bool {
		if len(body) != 1 {
			return false
		}
		return body[0].Opcode == Iconst0 || body[0].Opcode == Iconst1
	}

	if !isBoolPush(thenBody) || !isBoolPush(elseBody) {
		return nil, 0
	}

	nextInst := instructions[elseEnd]
	if nextInst.Opcode != Putfield && nextInst.Opcode != Putstatic && nextInst.Opcode != Astore && nextInst.Opcode != Istore {
		return nil, 0
	}

	thenVal := thenBody[0].Opcode == Iconst1
	cond := buildCondition(inst, stack, boolParams)

	var targetExpr ir.Expr
	if nextInst.Opcode == Putfield {
		fieldIdx := uint16(nextInst.Operands[0])<<8 | uint16(nextInst.Operands[1])
		fieldName := cf.GetFieldName(fieldIdx)
		if stackSize := len(stack.items); stackSize > 0 {
			obj := stack.pop()
			targetExpr = &ir.FieldAccess{Object: obj, Name: fieldName}
		} else {
			targetExpr = &ir.LocalVar{Name: fieldName}
		}
	} else if nextInst.Opcode == Putstatic {
		fieldIdx := uint16(nextInst.Operands[0])<<8 | uint16(nextInst.Operands[1])
		fieldClassName := cf.GetFieldClassName(fieldIdx)
		fieldName := cf.GetFieldName(fieldIdx)
		fieldSimpleName := fieldClassName
		if i := strings.LastIndex(fieldClassName, "/"); i >= 0 {
			fieldSimpleName = fieldClassName[i+1:]
		}
		if fieldSimpleName == className {
			targetExpr = &ir.LocalVar{Name: fieldName}
		} else {
			objName := classNameToJavaName(fieldClassName)
			targetExpr = &ir.FieldAccess{Object: &ir.LocalVar{Name: objName}, Name: fieldName}
		}
	} else {
		idx := nextInst.Operands[0]
		targetExpr = &ir.LocalVar{Name: getLocalVar(nil, idx)}
	}

	ifStmt := &ir.IfStmt{
		Cond: cond,
		Then: &ir.Block{Statements: []ir.Stmt{&ir.AssignStmt{
			Target: targetExpr,
			Value:  &ir.BoolLit{Value: thenVal},
		}}},
		Else: &ir.Block{Statements: []ir.Stmt{&ir.AssignStmt{
			Target: targetExpr,
			Value:  &ir.BoolLit{Value: !thenVal},
		}}},
	}

	return []ir.Stmt{ifStmt}, elseEnd + 1
}

func decompileSwitch(cf *ClassFile, instructions []Instruction, pc int, localVars map[uint16]string, stack *exprStack, className string, boolParams *boolTypeInfo, exceptionTable []ExceptionEntry) ([]ir.Stmt, int) {
	inst := instructions[pc]
	target := stack.pop()

	var caseOffsets []int
	var caseValues []ir.Expr
	var defaultOffset int

	if inst.Opcode == Tableswitch {
		operands := inst.Operands
		if len(operands) < 12 {
			return nil, 0
		}
		defaultOffset = inst.Offset + int(int32(operands[0])<<24|int32(operands[1])<<16|int32(operands[2])<<8|int32(operands[3]))
		low := int(int32(operands[4])<<24 | int32(operands[5])<<16 | int32(operands[6])<<8 | int32(operands[7]))
		high := int(int32(operands[8])<<24 | int32(operands[9])<<16 | int32(operands[10])<<8 | int32(operands[11]))
		for i := 0; i <= high-low; i++ {
			off := 12 + i*4
			if off+4 > len(operands) {
				break
			}
			caseOffset := inst.Offset + int(int32(operands[off])<<24|int32(operands[off+1])<<16|int32(operands[off+2])<<8|int32(operands[off+3]))
			caseOffsets = append(caseOffsets, caseOffset)
			caseValues = append(caseValues, &ir.IntLit{Value: int64(low + i)})
		}
	} else if inst.Opcode == Lookupswitch {
		operands := inst.Operands
		if len(operands) < 8 {
			return nil, 0
		}
		defaultOffset = inst.Offset + int(int32(operands[0])<<24|int32(operands[1])<<16|int32(operands[2])<<8|int32(operands[3]))
		npairs := int(int32(operands[4])<<24 | int32(operands[5])<<16 | int32(operands[6])<<8 | int32(operands[7]))
		for i := 0; i < npairs; i++ {
			off := 8 + i*8
			if off+8 > len(operands) {
				break
			}
			caseVal := int(int32(operands[off])<<24 | int32(operands[off+1])<<16 | int32(operands[off+2])<<8 | int32(operands[off+3]))
			caseOffset := inst.Offset + int(int32(operands[off+4])<<24|int32(operands[off+5])<<16|int32(operands[off+6])<<8|int32(operands[off+7]))
			caseOffsets = append(caseOffsets, caseOffset)
			caseValues = append(caseValues, &ir.IntLit{Value: int64(caseVal)})
		}
	} else {
		return nil, 0
	}

	// Determine whether defaultOffset is a REAL default clause from the
	// source, or a synthetic one the compiler always emits even when
	// there's no "default:" in the source (pointing wherever control
	// resumes after the switch). Criterion: synthetic if defaultOffset
	// is physically past every case (the common shape for "nothing
	// declared, so just point past the switch") AND no case anywhere
	// makes an explicit goto to it - a real default clause's own
	// content is switch-specific, and at least one case's own trailing
	// break would target it explicitly the same way it targets any
	// other merge point (that's what "break" always compiles to);
	// pure fallthrough with no goto at all is what happens when
	// nothing in the source actually intended to reach that code as
	// part of the switch.
	isDefaultSynthetic := defaultOffset > 0
	for _, co := range caseOffsets {
		if defaultOffset <= co {
			isDefaultSynthetic = false
			break
		}
	}
	if isDefaultSynthetic {
		// Scan the default clause's OWN body (starting at defaultOffset)
		// for a goto of its own leading somewhere further out - that's
		// what a real "break;" written inside an actual default clause
		// would compile to. A goto FROM some other case TO defaultOffset
		// doesn't count (that's just an ordinary break landing on what
		// happens to be the switch's synthetic merge point, not evidence
		// the default clause itself has real content) - only a goto
		// whose own source instruction lies at or after defaultOffset
		// is default's own.
		defaultStartIdx := findInstrIdx(instructions, defaultOffset)
		hasOwnGotoOut := false
		for i := defaultStartIdx; i < len(instructions); i++ {
			op := instructions[i].Opcode
			if op == Goto {
				hasOwnGotoOut = true
				break
			}
			isTerminator := false
			switch op {
			case Ireturn, Lreturn, Freturn, Dreturn, Areturn, Return, Athrow:
				isTerminator = true
			}
			if isTerminator {
				// Reached the default body's own natural end (or the
				// end of the whole method) without finding a goto of
				// its own - confirms nothing in it exits anywhere else,
				// consistent with this being ordinary post-switch code,
				// not a real default clause with its own break.
				break
			}
		}
		if hasOwnGotoOut {
			isDefaultSynthetic = false
		}
	}

	mergeOffset := findSwitchMerge(instructions, pc, caseOffsets, defaultOffset)
	mergeIdx := findInstrIdx(instructions, mergeOffset)

	allOffsets := make([]int, 0, len(caseOffsets)+1)
	allOffsets = append(allOffsets, caseOffsets...)
	if defaultOffset > 0 && !isDefaultSynthetic {
		allOffsets = append(allOffsets, defaultOffset)
	}
	allOffsets = append(allOffsets, mergeOffset)

	// Group case labels that target the SAME offset (a common source
	// pattern - "case 1: case 2: doSomething(); break;" compiles to
	// multiple case labels sharing one body) into one CaseClause with
	// multiple Values, computed and decompiled exactly once - rather
	// than independently decompiling (and duplicating) the same body
	// once per label sharing that offset.
	type caseGroup struct {
		offset int
		values []ir.Expr
	}
	var groups []*caseGroup
	groupByOffset := make(map[int]*caseGroup)
	for i, caseOffset := range caseOffsets {
		g, ok := groupByOffset[caseOffset]
		if !ok {
			g = &caseGroup{offset: caseOffset}
			groupByOffset[caseOffset] = g
			groups = append(groups, g)
		}
		g.values = append(g.values, caseValues[i])
	}

	var cases []*ir.CaseClause
	for _, g := range groups {
		caseOffset := g.offset
		caseStartIdx := findInstrIdx(instructions, caseOffset)
		caseEndIdx := mergeIdx
		for _, otherOff := range allOffsets {
			otherIdx := findInstrIdx(instructions, otherOff)
			if otherIdx > caseStartIdx && otherIdx < caseEndIdx {
				caseEndIdx = otherIdx
			}
		}
		realEnd := caseEndIdx
		foundBreak := false
		// Find this case's own trailing break (a goto to the switch's
		// merge point) by scanning BACKWARD from the case's declared end
		// boundary, not forward from its start: a case body can contain
		// its own nested if/else where BOTH branches independently
		// break out of the switch (e.g. "if (a) { ...; break; } else {
		// ...; break; }" all within one case), and scanning forward
		// would stop at the FIRST such goto - which is the inner if's
		// own break, not necessarily where the case itself actually
		// ends. Only a goto sitting in the very last position before
		// the case's boundary can safely be treated as this case's own
		// trailing break.
		for j := caseEndIdx - 1; j >= caseStartIdx; j-- {
			if instructions[j].Opcode == Goto {
				gotoTarget := instructions[j].Offset + branchOffset(instructions[j])
				if gotoTarget == mergeOffset || gotoTarget == instructions[caseEndIdx-1].Offset || gotoTarget == defaultOffset {
					realEnd = j
					foundBreak = true
				}
			}
			break
		}
		// This case falls through into the next one (no source-level
		// "break") when its body doesn't end in a goto to the switch's
		// merge point AND it doesn't already end in its own return/throw
		// (which also exits the switch, just without needing a goto -
		// "falls through" would be misleading/redundant there, so only
		// mark it when control would otherwise visibly continue into
		// the next case).
		fallsThrough := !foundBreak
		if realEnd > caseStartIdx && realEnd <= len(instructions) {
			last := instructions[realEnd-1]
			switch last.Opcode {
			case Ireturn, Lreturn, Freturn, Dreturn, Areturn, Return, Athrow:
				fallsThrough = false
			}
		}

		if caseStartIdx < realEnd && caseStartIdx < len(instructions) {
			// Truncate the instruction slice to this case's own
			// boundary before recursing into it - see the comment above
			// this loop and this function's own findings: without this,
			// a nested if/else whose branches both jump to the switch's
			// OVERALL merge point (valid, common - "if (a) { ...; break;
			// } else { ...; break; }" within one case) lets
			// decompileIfElse's merge-point search wander past this
			// case's own end and silently absorb the next case's
			// instructions as if they were part of this one's body.
			// Truncating means findInstrIdx (which every nested matcher
			// ultimately relies on to locate a branch target) can never
			// find or return an index past this case's real end.
			body := decompileBlockBody(cf, instructions[:realEnd], caseStartIdx, realEnd, localVars, className, boolParams, exceptionTable)
			cases = append(cases, &ir.CaseClause{
				Values:      g.values,
				Body:        &ir.Block{Statements: body},
				Fallthrough: fallsThrough,
			})
		} else {
			cases = append(cases, &ir.CaseClause{
				Values:      g.values,
				Body:        &ir.Block{},
				Fallthrough: fallsThrough,
			})
		}
	}

	var defaultBody *ir.Block
	resumeIdx := mergeIdx
	if defaultOffset > 0 && !isDefaultSynthetic {
		defaultStartIdx := findInstrIdx(instructions, defaultOffset)
		defaultBodyIdx := mergeIdx
		for _, otherOff := range caseOffsets {
			otherIdx := findInstrIdx(instructions, otherOff)
			if otherIdx > defaultStartIdx && otherIdx < defaultBodyIdx {
				defaultBodyIdx = otherIdx
			}
		}
		realDefaultEnd := defaultBodyIdx
		for j := defaultStartIdx; j < defaultBodyIdx && j < len(instructions); j++ {
			if instructions[j].Opcode == Goto {
				gotoTarget := instructions[j].Offset + branchOffset(instructions[j])
				if gotoTarget == mergeOffset {
					realDefaultEnd = j
					break
				}
			}
		}
		if defaultStartIdx < realDefaultEnd {
			defaultBody = &ir.Block{Statements: decompileBlockBody(cf, instructions[:realDefaultEnd], defaultStartIdx, realDefaultEnd, localVars, className, boolParams, exceptionTable)}
		} else {
			defaultBody = &ir.Block{}
		}
	} else if defaultOffset > 0 && isDefaultSynthetic {
		// Not real switch content - resume ordinary linear decompilation
		// from here instead of treating it as (or skipping past it as)
		// part of the switch.
		resumeIdx = findInstrIdx(instructions, defaultOffset)
	}

	return []ir.Stmt{&ir.SwitchStmt{Target: target, Cases: cases, Default: defaultBody}}, resumeIdx
}

// findSwitchMerge computes the switch's real end boundary from the actual
// break targets inside case/default bodies, instead of assuming "end of
// whatever instruction slice was passed" - which is wrong whenever the
// switch is nested inside another block that has more code after it
// (confirmed via testing: a switch inside an if's then-body, where the
// then-body has code after the switch, like "switch(...) {...}
// teleportStep++;" - assuming "end of slice" pulls the merge point all
// the way to the end of the entire method, not just the switch's own
// real end).
//
// The real end is the maximum target among every case/default's own
// trailing break (goto) - each case ends wherever ITS OWN break says
// control leaves the switch, and the switch as a whole ends at the
// furthest such point (a switch's control flow can never resolve to
// something before the last case's own break target). Falls back to the
// old "end of slice" behavior only if literally no case/default has a
// goto of its own (e.g. every case ends in return/throw).
func findSwitchMerge(instructions []Instruction, pc int, caseOffsets []int, defaultOffset int) int {
	if len(instructions) == 0 {
		return 0
	}

	allOffsets := make([]int, 0, len(caseOffsets)+1)
	allOffsets = append(allOffsets, caseOffsets...)
	if defaultOffset > 0 {
		allOffsets = append(allOffsets, defaultOffset)
	}

	maxTarget := -1
	for _, off := range allOffsets {
		startIdx := findInstrIdx(instructions, off)
		if startIdx < 0 || startIdx >= len(instructions) {
			continue
		}
		// This branch's own upper bound: the next-highest offset among
		// every case/default, or the end of the slice for whichever one
		// is physically last.
		endIdx := len(instructions)
		for _, otherOff := range allOffsets {
			otherIdx := findInstrIdx(instructions, otherOff)
			if otherIdx > startIdx && otherIdx < endIdx {
				endIdx = otherIdx
			}
		}
		// Scan backward from this branch's own end for its own trailing
		// goto - same reasoning as decompileSwitch's own per-case break
		// detection: a branch's own break, if it has one, is always the
		// last instruction in its range.
		for j := endIdx - 1; j >= startIdx; j-- {
			if instructions[j].Opcode == Goto {
				target := instructions[j].Offset + branchOffset(instructions[j])
				if target > maxTarget {
					maxTarget = target
				}
			}
			break
		}
	}

	if maxTarget >= 0 {
		return maxTarget
	}

	// No case/default anywhere has its own goto - fall back to the
	// previous, coarser assumption.
	last := instructions[len(instructions)-1]
	return last.Offset + instructionSize(last)
}


