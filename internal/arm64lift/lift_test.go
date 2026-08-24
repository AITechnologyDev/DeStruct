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

// TestLiftFunction_CompoundAndCondition lifts a hand-built instruction
// stream equivalent to:
//
//	while (a < n && b != 0) {
//	    step();
//	}
//	return a;
//
// exercising a compiled "&&" while-condition's standard shape: a chain
// of condition-test blocks where only ONE successor per link ever
// reaches back (the "keep testing, then eventually the body" arm),
// never both - so this never even reaches tryLiftWhileLoop's ambiguous
// case (unlike the "||" case - see TestLiftFunction_CompoundOrCondition)
// and needs no special chain-collapsing logic: the second condition
// is simply an ordinary nested if/break, discovered as "the body" via
// the SAME structural matcher recursing into itself. Semantically
// identical to a real "&&", just not textually fused into one - see
// tryLiftWhileLoop's own doc comment for why that's an accepted,
// deliberate scope limit.
func TestLiftFunction_CompoundAndCondition(t *testing.T) {
	insns := []native.DetailedInstruction{
		// h1 @ 0x0: cmp a, n
		{Address: 0x0, Size: 4, Mnemonic: "cmp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		// b.ge exit(0x18)   (if a >= n, exit)
		{Address: 0x4, Size: 4, Mnemonic: "b.ge", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x18},
		}},
		// h2 @ 0x8: cbz b, exit(0x18)   (if b == 0, exit)
		{Address: 0x8, Size: 4, Mnemonic: "cbz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 0x18},
		}},
		// body @ 0xc: bl step(0x100)
		{Address: 0xc, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// @ 0x10: b h1(0x0)
		{Address: 0x10, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x0},
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
	stmts := LiftFunction(insns, []string{"a", "n", "b"}, resolver, nil)

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
		t.Fatalf("expected exactly 1 statement in the outer loop body (the nested if), got %v", while.Body)
	}
	ifStmt, ok := while.Body.Statements[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected the body statement to be an IfStmt (the second, nested \"&&\" condition), got %T: %v", while.Body.Statements[0], while.Body.Statements[0])
	}
	// cbz's condition ("b == 0") lifts as the branch-TAKEN condition
	// (see liftCondition's own doc comment) - branch-taken is Succs[0]
	// here, which is the real exit (b == 0 means the "&&" is false),
	// so the then-branch is the break and the else-branch is the body.
	if ifStmt.Then == nil || len(ifStmt.Then.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the if's then-branch, got %v", ifStmt.Then)
	}
	if _, ok := ifStmt.Then.Statements[0].(*ir.BreakStmt); !ok {
		t.Errorf("expected the then-branch to be a BreakStmt (b was 0, so exit the loop), got %T: %v", ifStmt.Then.Statements[0], ifStmt.Then.Statements[0])
	}
	if ifStmt.Else == nil || len(ifStmt.Else.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the if's else-branch (the flushed step() call), got %v", ifStmt.Else)
	}
	if call, ok := ifStmt.Else.Statements[0].(*ir.ExprStmt); !ok {
		t.Errorf("expected the else-branch's statement to be an ExprStmt, got %T: %v", ifStmt.Else.Statements[0], ifStmt.Else.Statements[0])
	} else if sc, ok := call.Expr.(*ir.StaticMethodCall); !ok || sc.Method != "step" {
		t.Errorf("expected a call to \"step\", got %#v", call.Expr)
	}
}

// TestLiftFunction_CompoundOrCondition lifts a hand-built instruction
// stream equivalent to:
//
//	while (a != 0 || b != 0) {
//	    step();
//	}
//	return a;
//
// exercising a compiled "||" while-condition's standard short-circuit
// shape: head's OWN branch-taken arm enters the body directly (a
// true), while its fallthrough continues to a second test (b) whose
// own branch-taken arm is the real exit and fallthrough enters the
// (same) body. Both of head's own successors satisfy reachesAddr here
// (the direct-entry arm loops back via the body's own back-edge; the
// second-test arm loops back via ITS eventual body-entry too) -
// tryOrChainLink is what disambiguates this from an ordinary
// (non-loop) if/else and folds the second test into a combined "||"
// condition. Before this, this exact shape either wasn't recognized
// as a loop at all, or - a real bug this test also guards against -
// silently dropped step() from whichever arm reached the
// already-visited head block first.
func TestLiftFunction_CompoundOrCondition(t *testing.T) {
	insns := []native.DetailedInstruction{
		// h1 @ 0x0: cbnz a, body(0xc)   (if a != 0, enter body directly)
		{Address: 0x0, Size: 4, Mnemonic: "cbnz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 0xc},
		}},
		// h2 @ 0x4: cbz b, exit(0x18)   (if b == 0, exit; else fall to body)
		{Address: 0x4, Size: 4, Mnemonic: "cbz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandImm, Imm: 0x18},
		}},
		// @ 0x8: b body(0xc)
		{Address: 0x8, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0xc},
		}},
		// body @ 0xc: bl step(0x100)
		{Address: 0xc, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// @ 0x10: b h1(0x0)
		{Address: 0x10, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x0},
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
	stmts := LiftFunction(insns, []string{"a", "b"}, resolver, nil)

	var while *ir.WhileStmt
	for _, s := range stmts {
		if w, ok := s.(*ir.WhileStmt); ok {
			while = w
		}
	}
	if while == nil {
		t.Fatalf("expected a single WhileStmt (the \"||\" condition folded together) among the top-level statements, got %v", stmts)
	}

	or, ok := while.Cond.(*ir.BinaryExpr)
	if !ok || or.Op != "||" {
		t.Fatalf("expected cond to be a \"||\" expression, got %#v", while.Cond)
	}
	leftCmp, ok := or.Left.(*ir.BinaryExpr)
	if !ok || leftCmp.Op != "!=" {
		t.Errorf("expected the left side to be a \"!=\" comparison (from cbnz), got %#v", or.Left)
	}

	if while.Body == nil || len(while.Body.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the loop body (the flushed step() call - previously either 0 (silently dropped) or the loop wasn't recognized at all), got %v", while.Body)
	}
	exprStmt, ok := while.Body.Statements[0].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected the body statement to be an ExprStmt, got %T: %v", while.Body.Statements[0], while.Body.Statements[0])
	}
	if call, ok := exprStmt.Expr.(*ir.StaticMethodCall); !ok || call.Method != "step" {
		t.Errorf("expected a call to \"step\", got %#v", exprStmt.Expr)
	}
}

// TestLiftFunction_DoWhileLoop lifts a hand-built instruction stream
// equivalent to the standard -O0 codegen for:
//
//	int count(int n) {
//	    int i = 0;
//	    do {
//	        step();
//	        i = i + 1;
//	    } while (i < n);
//	    return n;
//	}
//
// exercising tryLiftDoWhileLoop's single-block case: since the body has
// no branch of its own, buildCFG never splits it from the tail
// condition check - "head" and "tail" are the very same block, whose
// own conditional branch loops back to ITS OWN start address rather
// than some earlier, already-lifted block (the while-shape case
// tryLiftWhileLoop handles).
func TestLiftFunction_DoWhileLoop(t *testing.T) {
	insns := []native.DetailedInstruction{
		// mov w2, #0             (i = 0)
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 0},
		}},
		// mov w1, w0             (save n into w1 - w0 is call-clobbered,
		// and the loop body below calls step() before the comparison
		// that needs n, exactly like a real register allocator would
		// have to arrange)
		{Address: 0x4, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandReg, Reg: "w0"},
		}},
		// head/tail @ 0x8: bl step(0x100)
		{Address: 0x8, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// add w2, w2, #1          (i = i + 1)
		{Address: 0xc, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 1},
		}},
		// cmp w2, w1              (i - n)
		{Address: 0x10, Size: 4, Mnemonic: "cmp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		// b.lt head(0x8)          (back-edge: taken when i < n)
		{Address: 0x14, Size: 4, Mnemonic: "b.lt", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x8},
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

	var do *ir.DoWhileStmt
	var haveReturn bool
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.DoWhileStmt:
			do = v
		case *ir.ReturnStmt:
			haveReturn = true
		}
	}
	if do == nil {
		t.Fatalf("expected a DoWhileStmt among the top-level statements, got %v", stmts)
	}
	if !haveReturn {
		t.Errorf("expected a ReturnStmt (the loop's exit continuation) among the top-level statements, got %v", stmts)
	}

	// cond should be the branch-taken condition as-is (no negation):
	// the back-edge IS the branch-taken arm, so "taken" directly means
	// "keep looping" - see buildDoWhileLoop's own doc comment.
	cmp, ok := do.Cond.(*ir.BinaryExpr)
	if !ok || cmp.Op != "<" {
		t.Fatalf("expected cond to be a \"<\" comparison, got %#v", do.Cond)
	}

	if do.Body == nil || len(do.Body.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the loop body, got %v", do.Body)
	}
	exprStmt2, ok := do.Body.Statements[0].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected the loop body's single statement to be an ExprStmt (the flushed step() call), got %T: %v", do.Body.Statements[0], do.Body.Statements[0])
	}
	if call, ok := exprStmt2.Expr.(*ir.StaticMethodCall); !ok || call.Method != "step" {
		t.Errorf("expected the flushed statement to be a call to \"step\", got %#v", exprStmt2.Expr)
	}
}

// TestLiftFunction_DoWhileLoopMultiBlockBody is the same source shape
// as TestLiftFunction_DoWhileLoop, but with the body split across two
// basic blocks via an internal unconditional "b" (still straight-line -
// no real branching - but enough to force buildCFG to split it, so
// this exercises tryLiftDoWhileLoop's forward chain-walk rather than
// its single-block special case).
func TestLiftFunction_DoWhileLoopMultiBlockBody(t *testing.T) {
	insns := []native.DetailedInstruction{
		// mov w2, #0
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 0},
		}},
		// mov w1, w0             (save n into w1 - see
		// TestLiftFunction_DoWhileLoop's own note on why w0 can't be
		// used directly once the body calls into anything)
		{Address: 0x4, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandReg, Reg: "w0"},
		}},
		// head @ 0x8: bl step(0x100)
		{Address: 0x8, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// mov w0, #0             (step()'s result is unused and w0 gets
		// reassigned before the next call - otherwise other() below
		// would appear to take step()'s leftover return value as its own
		// argument, an unrelated existing heuristic limitation - see
		// buildCall's own doc comment - this test isn't trying to
		// exercise)
		{Address: 0xc, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 0},
		}},
		// b 0x18   (forces a block split here, still straight-line)
		{Address: 0x10, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x18},
		}},
		// @ 0x18: bl other(0x104)
		{Address: 0x18, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x104},
		}},
		// add w2, w2, #1
		{Address: 0x1c, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 1},
		}},
		// cmp w2, w1
		{Address: 0x20, Size: 4, Mnemonic: "cmp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		// tail @ 0x24: b.lt head(0x8)
		{Address: 0x24, Size: 4, Mnemonic: "b.lt", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x8},
		}},
		// exit @ 0x28: ret
		{Address: 0x28, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		switch addr {
		case 0x100:
			return "step", true
		case 0x104:
			return "other", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, []string{"n"}, resolver, nil)

	var do *ir.DoWhileStmt
	for _, s := range stmts {
		if v, ok := s.(*ir.DoWhileStmt); ok {
			do = v
		}
	}
	if do == nil {
		t.Fatalf("expected a DoWhileStmt among the top-level statements, got %v", stmts)
	}

	if do.Body == nil || len(do.Body.Statements) != 2 {
		t.Fatalf("expected exactly 2 statements in the loop body (step() then other(), from both blocks in the chain), got %v", do.Body)
	}
	first, ok := do.Body.Statements[0].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected the first body statement to be an ExprStmt, got %T: %v", do.Body.Statements[0], do.Body.Statements[0])
	}
	if call, ok := first.Expr.(*ir.StaticMethodCall); !ok || call.Method != "step" {
		t.Errorf("expected the first call to be \"step\", got %#v", first.Expr)
	}
	second, ok := do.Body.Statements[1].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected the second body statement to be an ExprStmt, got %T: %v", do.Body.Statements[1], do.Body.Statements[1])
	}
	if call, ok := second.Expr.(*ir.StaticMethodCall); !ok || call.Method != "other" {
		t.Errorf("expected the second call to be \"other\", got %#v", second.Expr)
	}
}

// TestLiftFunction_DoWhileLoopWithInternalIfElse lifts a hand-built
// instruction stream equivalent to:
//
//	int count(int n) {
//	    int i = 0;
//	    do {
//	        if (w3 == 0) {
//	            other();
//	        } else {
//	            step();
//	        }
//	        i = i + 1;
//	    } while (i < n);
//	    return n;
//	}
//
// exercising the do-while body's own internal if/else, whose two arms
// both reconverge at the tail (add+cmp+b.lt) before it - the ambiguous
// shape tryLiftDoWhileLoop's own "both arms loop back" case exists for
// (see its doc comment), and findDoWhileTail's own BFS locating the
// tail past an ordinary conditional rather than being fooled by it.
func TestLiftFunction_DoWhileLoopWithInternalIfElse(t *testing.T) {
	insns := []native.DetailedInstruction{
		// mov w2, #0              (i = 0)
		{Address: 0x0, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 0},
		}},
		// mov w1, w0              (save n - see
		// TestLiftFunction_DoWhileLoop's own note on why w0 can't be
		// used directly once the body calls into anything)
		{Address: 0x4, Size: 4, Mnemonic: "mov", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w1"},
			{Type: native.OperandReg, Reg: "w0"},
		}},
		// bodyStart @ 0x8: cbz w3, else(0x14)
		{Address: 0x8, Size: 4, Mnemonic: "cbz", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w3"},
			{Type: native.OperandImm, Imm: 0x14},
		}},
		// @ 0xc: bl step(0x100)
		{Address: 0xc, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// @ 0x10: b merge(0x18)
		{Address: 0x10, Size: 4, Mnemonic: "b", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x18},
		}},
		// else @ 0x14: bl other(0x104)
		{Address: 0x14, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x104},
		}},
		// merge/tail @ 0x18: add w2, w2, #1
		{Address: 0x18, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandImm, Imm: 1},
		}},
		// cmp w2, w1
		{Address: 0x1c, Size: 4, Mnemonic: "cmp", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w2"},
			{Type: native.OperandReg, Reg: "w1"},
		}},
		// b.lt bodyStart(0x8)
		{Address: 0x20, Size: 4, Mnemonic: "b.lt", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x8},
		}},
		// exit @ 0x24: ret
		{Address: 0x24, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		switch addr {
		case 0x100:
			return "step", true
		case 0x104:
			return "other", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, []string{"n"}, resolver, nil)

	var do *ir.DoWhileStmt
	for _, s := range stmts {
		if v, ok := s.(*ir.DoWhileStmt); ok {
			do = v
		}
	}
	if do == nil {
		t.Fatalf("expected a DoWhileStmt among the top-level statements, got %v", stmts)
	}
	cmp, ok := do.Cond.(*ir.BinaryExpr)
	if !ok || cmp.Op != "<" {
		t.Fatalf("expected cond to be a \"<\" comparison, got %#v", do.Cond)
	}

	if do.Body == nil || len(do.Body.Statements) != 1 {
		t.Fatalf("expected exactly 1 statement in the loop body (the internal if/else), got %v", do.Body)
	}
	ifStmt, ok := do.Body.Statements[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected the body statement to be an IfStmt, got %T: %v", do.Body.Statements[0], do.Body.Statements[0])
	}

	assertSingleCall := func(t *testing.T, stmts []ir.Stmt, method string) {
		t.Helper()
		if len(stmts) != 1 {
			t.Fatalf("expected exactly 1 statement, got %v", stmts)
		}
		exprStmt, ok := stmts[0].(*ir.ExprStmt)
		if !ok {
			t.Fatalf("expected an ExprStmt, got %T: %v", stmts[0], stmts[0])
		}
		if call, ok := exprStmt.Expr.(*ir.StaticMethodCall); !ok || call.Method != method {
			t.Errorf("expected a call to %q, got %#v", method, exprStmt.Expr)
		}
	}
	// Then corresponds to the branch-taken arm (cbz's target, 0x14 -
	// "other()"), Else to the fallthrough arm (0xc - "step()") - see
	// liftCondition's own doc comment on why the branch-taken path is
	// always the "then" as this lifter builds it.
	assertSingleCall(t, ifStmt.Then.Statements, "other")
	assertSingleCall(t, ifStmt.Else.Statements, "step")
}

// TestLiftFunction_ParamStackReassignment lifts a hand-built
// instruction stream equivalent to:
//
//	int f(int n) {
//	    n = n + 1;
//	    return n;
//	}
//
// exercising a real bug in an earlier version of liftStr: it matched a
// store's source register by NAME (any "w0"-shaped register) rather
// than by the VALUE currently in it, so re-storing n's own
// already-reassigned register back to n's stack slot was
// indistinguishable from the initial prologue spill and silently
// dropped as "more of the same bookkeeping" - losing the "n = n + 1;"
// assignment entirely and leaving the final reload (and thus the
// return) reading n's STALE, pre-increment value.
func TestLiftFunction_ParamStackReassignment(t *testing.T) {
	insns := []native.DetailedInstruction{
		// str w0, [sp, #12]   (prologue: spill n)
		{Address: 0x0, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 12}},
		}},
		// ldr w0, [sp, #12]   (reload n)
		{Address: 0x4, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 12}},
		}},
		// add w0, w0, #1      (n + 1)
		{Address: 0x8, Size: 4, Mnemonic: "add", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandImm, Imm: 1},
		}},
		// str w0, [sp, #12]   (n = n + 1 - a REAL reassignment)
		{Address: 0xc, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 12}},
		}},
		// ldr w0, [sp, #12]   (reload the reassigned n)
		{Address: 0x10, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 12}},
		}},
		{Address: 0x14, Size: 4, Mnemonic: "ret"},
	}

	stmts := LiftFunction(insns, []string{"n"}, nil, nil)

	var assign *ir.AssignStmt
	var ret *ir.ReturnStmt
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.AssignStmt:
			assign = v
		case *ir.ReturnStmt:
			ret = v
		}
	}
	if assign == nil {
		t.Fatalf("expected an AssignStmt for \"n = n + 1\" among the top-level statements (it was previously silently dropped), got %v", stmts)
	}
	target, ok := assign.Target.(*ir.LocalVar)
	if !ok || target.Name != "n" {
		t.Errorf("expected the assignment's target to be local var \"n\", got %#v", assign.Target)
	}
	value, ok := assign.Value.(*ir.BinaryExpr)
	if !ok || value.Op != "+" {
		t.Fatalf("expected the assignment's value to be a \"+\" expression, got %#v", assign.Value)
	}
	if lhs, ok := value.Left.(*ir.LocalVar); !ok || lhs.Name != "n" {
		t.Errorf("expected \"n + 1\"'s left side to be local var \"n\", got %#v", value.Left)
	}

	if ret == nil {
		t.Fatalf("expected a ReturnStmt among the top-level statements, got %v", stmts)
	}
	retVal, ok := ret.Value.(*ir.LocalVar)
	if !ok || retVal.Name != "n" {
		t.Errorf("expected the return value to be local var \"n\" (the reassigned value, not a stale pre-increment one), got %#v", ret.Value)
	}
}

// TestLiftFunction_NonParamStackLocal lifts a hand-built instruction
// stream equivalent to:
//
//	int f() {
//	    int total = step();
//	    other();
//	    return total;
//	}
//
// exercising a genuine non-parameter local variable: step()'s result
// is spilled to a fresh stack slot (not a parameter - the function
// takes none), given a deterministic name derived from its stack
// displacement, survives a second call that would otherwise clobber
// the register it was originally computed into, and is correctly
// reloaded by name rather than lost or conflated with anything else.
func TestLiftFunction_NonParamStackLocal(t *testing.T) {
	insns := []native.DetailedInstruction{
		// bl step(0x100)
		{Address: 0x0, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x100},
		}},
		// str w0, [sp, #8]    (total = step())
		{Address: 0x4, Size: 4, Mnemonic: "str", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 8}},
		}},
		// bl other(0x104)
		{Address: 0x8, Size: 4, Mnemonic: "bl", Operands: []native.Operand{
			{Type: native.OperandImm, Imm: 0x104},
		}},
		// ldr w0, [sp, #8]    (reload total)
		{Address: 0xc, Size: 4, Mnemonic: "ldr", Operands: []native.Operand{
			{Type: native.OperandReg, Reg: "w0"},
			{Type: native.OperandMem, Mem: native.MemOperand{Base: "sp", Disp: 8}},
		}},
		{Address: 0x10, Size: 4, Mnemonic: "ret"},
	}

	resolver := func(addr uint64) (string, bool) {
		switch addr {
		case 0x100:
			return "step", true
		case 0x104:
			return "other", true
		}
		return "", false
	}

	stmts := LiftFunction(insns, nil, resolver, nil)

	var assign *ir.AssignStmt
	var otherCall *ir.ExprStmt
	var ret *ir.ReturnStmt
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.AssignStmt:
			assign = v
		case *ir.ExprStmt:
			otherCall = v
		case *ir.ReturnStmt:
			ret = v
		}
	}
	if assign == nil {
		t.Fatalf("expected an AssignStmt for \"total = step()\" among the top-level statements, got %v", stmts)
	}
	target, ok := assign.Target.(*ir.LocalVar)
	if !ok {
		t.Fatalf("expected the assignment's target to be a LocalVar, got %#v", assign.Target)
	}
	if call, ok := assign.Value.(*ir.StaticMethodCall); !ok || call.Method != "step" {
		t.Errorf("expected the assignment's value to be a call to \"step\", got %#v", assign.Value)
	}

	if otherCall == nil {
		t.Fatalf("expected an ExprStmt for the flushed other() call among the top-level statements, got %v", stmts)
	}
	if call, ok := otherCall.Expr.(*ir.StaticMethodCall); !ok || call.Method != "other" {
		t.Errorf("expected a call to \"other\", got %#v", otherCall.Expr)
	}

	if ret == nil {
		t.Fatalf("expected a ReturnStmt among the top-level statements, got %v", stmts)
	}
	retVal, ok := ret.Value.(*ir.LocalVar)
	if !ok || retVal.Name != target.Name {
		t.Errorf("expected the return value to be the SAME local var the assignment targeted (%q), got %#v", target.Name, ret.Value)
	}
}
