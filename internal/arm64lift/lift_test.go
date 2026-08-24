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
