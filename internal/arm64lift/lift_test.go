package arm64lift

import (
	"testing"
	"time"

	"github.com/destruct/destruct/internal/ir"
	"github.com/destruct/destruct/internal/native"
)

// TestLiftFunction_WhileLoop lifts a hand-built instruction stream
// equivalent to the standard -O0 codegen for:
//
//	int count(int n) {
//	    int i = 0;
//	    while (i < n) {
//	        step();
//	        i = i + 1;
//	    }
//	    return n;
//	}
//
// exercising tryLiftWhileLoop/findLoopBody's recognized shape: a head
// block ending in "cmp"+"b.ge" (branch-taken exits the loop,
// fallthrough enters the body), and a body block ending in an
// unconditional "b" back to the head. The body calls a resolved
// function (step()) whose result is never used, specifically so the
// body produces a visible statement: a bare register increment like
// "i = i + 1" is (correctly, per this lifter's current scope - see the
// TODO at the bottom of lift.go on non-parameter locals) never emitted
// as a statement of its own, only step() is.
func TestLiftFunction_WhileLoop(t *testing.T) {
	insns := []native.DetailedInstruction{
		// mov w2, #0            (i = 0)
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 0},
		}},
		// head @ 0x4: cmp w2, w0   (i - n, i.e. lhs=i rhs=n)
		{Address: 0x4, Size: 4, Mnemonic: "cmp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w0"},
		}},
		// b.ge exit(0x18)        (branch-taken: i >= n -> exit)
		{Address: 0x8, Size: 4, Mnemonic: "b.ge", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x18},
		}},
		// body @ 0xc: bl step(0x100)
		{Address: 0xc, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// add w2, w2, #1   (i = i + 1)
		{Address: 0x10, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 1},
		}},
		// b head(0x4)             (loop back-edge)
		{Address: 0x14, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x4},
		}},
		// exit @ 0x18: ret
		{Address: 0x18, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		if addr == 0x100 {
			return "step", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, []string{"n"}, resolver, nil)

	var while *ir.WhileStmt
	var haveReturn bool
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.WhileStmt:
			while = v
		case *ir.ReturnStmt:
			haveReturn = true
		}
	}
	if while == nil {
		t.Fatalf("expected a WhileStmt among the top-level statements, got %v", stmts)
	}
	if !haveReturn {
		t.Errorf("expected a ReturnStmt (the loop's exit continuation) among the top-level statements, got %v", stmts)
	}

	// cond should be the negation of the branch-taken condition
	// (b.ge, ">="), since the loop body is entered via the
	// FALLTHROUGH edge, not the branch-taken one - see
	// tryLiftWhileLoop's own doc comment.
	neg, ok := while.Cond.(*ir.UnaryExpr)
	if !ok || neg.Op != "!" {
		t.Fatalf("expected cond to be a negated (\"!\") expression, got %#v", while.Cond)
	}
	cmp, ok := neg.Expr.(*ir.BinaryExpr)
	if !ok || cmp.Op != ">=" {
		t.Fatalf("expected the negated expression to be a \">=\" comparison, got %#v", neg.Expr)
	}

	if while.Body == nil || len(while.Body.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the loop body, got %v", while.Body)
	}
	exprStmt, ok := while.Body.Statements[0].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected the loop body's single statement to be an ExprStmt (the flushed step() call), got %T: %v", while.Body.Statements[0], while.Body.Statements[0])
	}
	call, ok := exprStmt.Expr.(*ir.StaticMethodCall)
	if !ok || call.Method != "step" {
		t.Errorf("expected the flushed statement to be a call to \"step\", got %#v", exprStmt.Expr)
	}
}

// TestLiftFunction_BudgetCapsExponentialBlowup builds a chain of N
// single-instruction conditional blocks where BOTH of each block's
// successors (branch-taken and fallthrough) point at the SAME next
// block - the shape liftBlockGraph's if/else forking (no merge-point
// sharing) turns into O(2^N) total liftBlockGraph calls with no other
// bound, since it has no way to recognize the two paths as trivially
// reconverging (see lifter.budget's own doc comment for the full
// reasoning). Without the budget cap, this hangs long before N=24
// (2^24 = ~16M); with it, it must return quickly regardless of N.
func TestLiftFunction_BudgetCapsExponentialBlowup(t *testing.T) {
	const n = 24
	insns := make([]native.DetailedInstruction, 0, n+1)
	for i := 0; i < n; i++ {
		addr := uint64(i * 4)
		insns = append(insns, native.DetailedInstruction{
			Address:  addr,
			Size:     4,
			Mnemonic: "cbz",
			Operands: []native.Operand{
				{Type: native.OperandReg, Reg: "w0"},
				{Type: native.OperandImm, Imm: int64(addr + 4)},
			},
		})
	}
	insns = append(insns, native.DetailedInstruction{Address: uint64(n * 4), Size: 4, Mnemonic: "ret"})

	done := make(chan struct{})
	go func() {
		LiftFunction(insns, nil, nil, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("LiftFunction did not return within 5s - the block-visit budget cap appears not to be working")
	}
}

// TestLiftFunction_LdrThroughGOT lifts a hand-built instruction stream
// equivalent to the "adrp+ldr" idiom real -O0 code uses to load a
// global object's address out of the GOT (as opposed to adrp+add,
// which computes an address without dereferencing it - e.g. a string
// literal's own address - see liftAddr's doc comment), then calls a
// resolved function with that loaded value as its argument:
//
//	std::cerr << ...   // conceptually: some_func(cerr)
//
// mirroring exactly what print_usage's real disassembly does to reach
// std::cerr (see ELFParser.ResolveGOT's own TestResolveGOT, which
// confirms the real GOT slot address this test's resolver mimics).
func TestLiftFunction_LdrThroughGOT(t *testing.T) {
	insns := []native.DetailedInstruction{
		// adrp x0, #0x1000
		{Address: 0x0, Size: 4, Mnemonic: "adrp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandImm, Imm: 0x1000},
		}},
		// ldr x0, [x0, #0x168]   (loads the GOT slot at 0x1168)
		{Address: 0x4, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "x0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "x0", Disp: 0x168}},
		}},
		// bl some_func(0x500)
		{Address: 0x8, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x500},
		}},
		{Address: 0xc, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		switch addr {
		case 0x1168:
			return "_ZNSt6__ndk14cerrE", true
		case 0x500:
			return "some_func", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, nil, resolver, nil)
	if len(stmts) != 1 {
		t.Fatalf("expected exactly 1 statement (the return), got %v", stmts)
	}
	ret, ok := stmts[0].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("expected a ReturnStmt, got %T: %v", stmts[0], stmts[0])
	}
	call, ok := ret.Value.(*ir.StaticMethodCall)
	if !ok || call.Method != "some_func" {
		t.Fatalf("expected a call to \"some_func\", got %#v", ret.Value)
	}
	if len(call.Args) != 1 {
		t.Fatalf("expected exactly 1 argument, got %v", call.Args)
	}
	arg, ok := call.Args[0].(*ir.LocalVar)
	if !ok || arg.Name != "_ZNSt6__ndk14cerrE" {
		t.Errorf("expected the argument to be a reference to the resolved GOT name, got %#v", call.Args[0])
	}
}

// TestLiftFunction_TestBitBranch lifts a hand-built instruction stream
// equivalent to:
//
//	if (flags & (1 << 3)) {
//	    return step();
//	} else {
//	    return other();
//	}
//
// exercising liftCondition's "tbnz" handling: unlike cbz/cbnz (which
// test a whole register against zero) or b.cond (which reads a
// preceding cmp), tbz/tbnz test a single bit of their own register
// operand directly.
func TestLiftFunction_TestBitBranch(t *testing.T) {
	insns := []native.DetailedInstruction{
		// tbnz w0, #3, then(0xc)   (branch-taken: bit 3 set -> then)
		{Address: 0x0, Size: 4, Mnemonic: "tbnz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 3},
			{Type: native.OperandImm, Imm: 0xc},
		}},
		// else @ 0x4: bl other(0x200); ret
		{Address: 0x4, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x200},
		}},
		{Address: 0x8, Size: 4, Mnemonic: "ret"},
		// then @ 0xc: bl step(0x100); ret
		{Address: 0xc, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		{Address: 0x10, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		switch addr {
		case 0x100:
			return "step", true
		case 0x200:
			return "other", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, nil, resolver, nil)
	if len(stmts) != 1 {
		t.Fatalf("expected exactly 1 top-level statement (the if), got %v", stmts)
	}
	ifStmt, ok := stmts[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected an IfStmt, got %T: %v", stmts[0], stmts[0])
	}

	neq, ok := ifStmt.Cond.(*ir.BinaryExpr)
	if !ok || neq.Op != "!=" {
		t.Fatalf("expected cond to be a \"!=\" comparison, got %#v", ifStmt.Cond)
	}
	masked, ok := neq.Left.(*ir.BinaryExpr)
	if !ok || masked.Op != "&" {
		t.Fatalf("expected the left side to be a \"&\" bit-mask expression, got %#v", neq.Left)
	}
	if lit, ok := masked.Right.(*ir.IntLit); !ok || lit.Value != 1<<3 {
		t.Errorf("expected the mask to be 1<<3 = 8, got %#v", masked.Right)
	}

	requireReturnedCall := func(t *testing.T, block *ir.Block, wantMethod string) {
		t.Helper()
		if block == nil || len(block.Statements) != 1 {
			t.Fatalf("expected exactly 1 statement, got %v", block)
		}
		ret, ok := block.Statements[0].(*ir.ReturnStmt)
		if !ok {
			t.Fatalf("expected a ReturnStmt, got %T: %v", block.Statements[0], block.Statements[0])
		}
		call, ok := ret.Value.(*ir.StaticMethodCall)
		if !ok || call.Method != wantMethod {
			t.Errorf("expected a call to %q, got %#v", wantMethod, ret.Value)
		}
	}
	requireReturnedCall(t, ifStmt.Then, "step")
	requireReturnedCall(t, ifStmt.Else, "other")
}

// TestLiftFunction_ALUOps lifts a hand-built instruction stream
// equivalent to:
//
//	int f(int a, int b) {
//	    return step((a - b) * b & 0xff);
//	}
//
// exercising liftALU's sub (register-register), mul (register-
// register, no immediate form), and and (register-immediate) cases.
func TestLiftFunction_ALUOps(t *testing.T) {
	insns := []native.DetailedInstruction{
		// sub w2, w0, w1     (w2 = a - b)
		{Address: 0x0, Size: 4, Mnemonic: "sub", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		// mul w2, w2, w1     (w2 = w2 * b)
		{Address: 0x4, Size: 4, Mnemonic: "mul", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		// and w0, w2, #0xff  (w0 = w2 & 0xff)
		{Address: 0x8, Size: 4, Mnemonic: "and", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 0xff},
		}},
		// bl step(0x100)
		{Address: 0xc, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		{Address: 0x10, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		if addr == 0x100 {
			return "step", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, []string{"a", "b"}, resolver, nil)
	if len(stmts) != 1 {
		t.Fatalf("expected exactly 1 statement (the return), got %v", stmts)
	}
	ret, ok := stmts[0].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("expected a ReturnStmt, got %T: %v", stmts[0], stmts[0])
	}
	call, ok := ret.Value.(*ir.StaticMethodCall)
	if !ok || call.Method != "step" || len(call.Args) == 0 {
		// Args[1:] is just whatever's left over in w1 ("b", per
		// aapcs64IntArgRegs' own arg-collection heuristic - see
		// buildCall) since this test never overwrites it; only
		// Args[0] (built from w0) is what this test actually cares
		// about checking.
		t.Fatalf("expected a call to \"step\" with at least 1 argument, got %#v", ret.Value)
	}

	and, ok := call.Args[0].(*ir.BinaryExpr)
	if !ok || and.Op != "&" {
		t.Fatalf("expected the argument to be a \"&\" expression, got %#v", call.Args[0])
	}
	if lit, ok := and.Right.(*ir.IntLit); !ok || lit.Value != 0xff {
		t.Errorf("expected the \"&\" right side to be 0xff, got %#v", and.Right)
	}
	mul, ok := and.Left.(*ir.BinaryExpr)
	if !ok || mul.Op != "*" {
		t.Fatalf("expected the \"&\" left side to be a \"*\" expression, got %#v", and.Left)
	}
	sub, ok := mul.Left.(*ir.BinaryExpr)
	if !ok || sub.Op != "-" {
		t.Fatalf("expected the \"*\" left side to be a \"-\" expression, got %#v", mul.Left)
	}
	lhs, ok := sub.Left.(*ir.LocalVar)
	if !ok || lhs.Name != "a" {
		t.Errorf("expected the \"-\" left side to be param \"a\", got %#v", sub.Left)
	}
	rhs, ok := sub.Right.(*ir.LocalVar)
	if !ok || rhs.Name != "b" {
		t.Errorf("expected the \"-\" right side to be param \"b\", got %#v", sub.Right)
	}
}

// TestLiftFunction_LoopWithNestedIf lifts a hand-built instruction
// stream equivalent to:
//
//	while (w0 != 0) {
//	    if (w1 != 0) {
//	        continue;
//	    } else {
//	        step();
//	    }
//	}
//
// exercising a loop body containing its own nested if/continue -
// previously (findLoopBody's straight-chain-only walk) this shape
// wasn't recognized as a loop at all; it now reuses liftBlockGraph
// itself for the body, with loopCtx turning the branch back to head
// into an explicit ContinueStmt. The lifter has no "un-nest code after
// an early continue" beautification pass, so step() lands nested
// inside the if's else-branch rather than flattened after a guard
// clause - a different (still fully correct) shape than a human would
// typically write by hand, not a bug.
func TestLiftFunction_LoopWithNestedIf(t *testing.T) {
	insns := []native.DetailedInstruction{
		// head @ 0x0: cbz w0, exit(0x10)
		{Address: 0x0, Size: 4, Mnemonic: "cbz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 0x10},
		}},
		// @ 0x4: cbnz w1, head(0x0)   (if (w1 != 0) continue;)
		{Address: 0x4, Size: 4, Mnemonic: "cbnz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandImm, Imm: 0x0},
		}},
		// @ 0x8: bl step(0x100)
		{Address: 0x8, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// @ 0xc: b head(0x0)
		{Address: 0xc, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x0},
		}},
		// exit @ 0x10: ret
		{Address: 0x10, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		if addr == 0x100 {
			return "step", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, nil, resolver, nil)

	var while *ir.WhileStmt
	for _, s := range stmts {
		if w, ok := s.(*ir.WhileStmt); ok {
			while = w
		}
	}
	if while == nil {
		t.Fatalf("expected a WhileStmt among the top-level statements, got %v", stmts)
	}
	if while.Body == nil || len(while.Body.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the loop body (the nested if), got %v", while.Body)
	}

	ifStmt, ok := while.Body.Statements[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected the body statement to be an IfStmt, got %T: %v", while.Body.Statements[0], while.Body.Statements[0])
	}
	if ifStmt.Then == nil || len(ifStmt.Then.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the if's then-branch, got %v", ifStmt.Then)
	}
	if _, ok := ifStmt.Then.Statements[0].(*ir.ContinueStmt); !ok {
		t.Errorf("expected the if's then-branch to be a ContinueStmt, got %T: %v", ifStmt.Then.Statements[0], ifStmt.Then.Statements[0])
	}

	if ifStmt.Else == nil || len(ifStmt.Else.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the if's else-branch (the flushed step() call - next()'s result is never consumed by anything, so it doesn't appear as its own statement), got %v", ifStmt.Else)
	}
	exprStmt, ok := ifStmt.Else.Statements[0].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected the else-branch's statement to be an ExprStmt, got %T: %v", ifStmt.Else.Statements[0], ifStmt.Else.Statements[0])
	}
	if call, ok := exprStmt.Expr.(*ir.StaticMethodCall); !ok || call.Method != "step" {
		t.Errorf("expected a call to \"step\", got %#v", exprStmt.Expr)
	}
}

// TestLiftFunction_LoopWithUnconditionalBreak lifts a hand-built
// instruction stream equivalent to:
//
//	while (w0 != 0) {
//	    if (w1 != 0) {
//	        continue;
//	    } else {
//	        step();
//	        break;
//	    }
//	}
//
// exercising an UNCONDITIONAL break (a plain "b" straight to the
// loop's exit, no enclosing if of its own - unlike the continue case,
// which liftLoopEdge handles directly at an if/else split, this one is
// only reachable through liftBlockGraph's plain single-successor
// fallback) - and specifically that step()'s call result is still
// flushed before the break, rather than silently dropped right before
// it (a real gap this test was written to catch).
func TestLiftFunction_LoopWithUnconditionalBreak(t *testing.T) {
	insns := []native.DetailedInstruction{
		// head @ 0x0: cbz w0, exit(0x14)
		{Address: 0x0, Size: 4, Mnemonic: "cbz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 0x14},
		}},
		// @ 0x4: cbnz w1, head(0x0)   (if (w1 != 0) continue;)
		{Address: 0x4, Size: 4, Mnemonic: "cbnz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandImm, Imm: 0x0},
		}},
		// @ 0x8: bl step(0x100)
		{Address: 0x8, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// @ 0xc: b exit(0x14)   (unconditional break)
		{Address: 0xc, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x14},
		}},
		// exit @ 0x14: ret
		{Address: 0x14, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		if addr == 0x100 {
			return "step", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, nil, resolver, nil)

	var while *ir.WhileStmt
	for _, s := range stmts {
		if w, ok := s.(*ir.WhileStmt); ok {
			while = w
		}
	}
	if while == nil {
		t.Fatalf("expected a WhileStmt among the top-level statements, got %v", stmts)
	}
	if while.Body == nil || len(while.Body.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the loop body (the nested if), got %v", while.Body)
	}
	ifStmt, ok := while.Body.Statements[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected the body statement to be an IfStmt, got %T: %v", while.Body.Statements[0], while.Body.Statements[0])
	}
	if ifStmt.Then == nil || len(ifStmt.Then.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the if's then-branch, got %v", ifStmt.Then)
	}
	if _, ok := ifStmt.Then.Statements[0].(*ir.ContinueStmt); !ok {
		t.Errorf("expected the if's then-branch to be a ContinueStmt, got %T: %v", ifStmt.Then.Statements[0], ifStmt.Then.Statements[0])
	}

	if ifStmt.Else == nil || len(ifStmt.Else.Statements) != 2 {
		t.Fatalf("expected exactly 2 statements in the if's else-branch (the flushed step() call, then the break), got %v", ifStmt.Else)
	}
	exprStmt, ok := ifStmt.Else.Statements[0].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected the else-branch's first statement to be an ExprStmt, got %T: %v", ifStmt.Else.Statements[0], ifStmt.Else.Statements[0])
	}
	if call, ok := exprStmt.Expr.(*ir.StaticMethodCall); !ok || call.Method != "step" {
		t.Errorf("expected a call to \"step\", got %#v", exprStmt.Expr)
	}
	if _, ok := ifStmt.Else.Statements[1].(*ir.BreakStmt); !ok {
		t.Errorf("expected the else-branch's second statement to be a BreakStmt, got %T: %v", ifStmt.Else.Statements[1], ifStmt.Else.Statements[1])
	}
}
