package jvm

import (
	"fmt"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

type exprStack struct {
	items []ir.Expr
}

func (s *exprStack) push(e ir.Expr) {
	s.items = append(s.items, e)
}

func (s *exprStack) pop() ir.Expr {
	if len(s.items) == 0 {
		return &ir.LocalVar{Name: "stack_value"}
	}
	last := s.items[len(s.items)-1]
	s.items = s.items[:len(s.items)-1]
	return last
}

func (s *exprStack) peek() ir.Expr {
	if len(s.items) == 0 {
		return &ir.LocalVar{Name: "stack_value"}
	}
	return s.items[len(s.items)-1]
}

func (s *exprStack) len() int {
	return len(s.items)
}

// buildParamNames resolves the final display name for each of a method's
// parameters (by local-variable-table slot), applying the same fallback
// chain in exactly one place: prefer a real name from the
// LocalVariableTable if the class file has one, otherwise infer a
// reasonable name from the parameter's type (inferParamName). This is
// used both for the method's declared signature (in
// decompileClassFile/pipeline.go) and for resolving local variable
// references inside the method's body (resolveLocalVars below) - using
// two independent implementations for the same question ("what is this
// parameter called?") was exactly what let a method's signature and body
// disagree on a parameter's name (e.g. `onReceive(Context context, Intent
// intent)` in the signature, but `arg0`/`arg1` used throughout the body,
// whenever the class had been stripped of debug info by a tool like
// ProGuard/R8 - common for real-world Android apps).
func buildParamNames(cf *ClassFile, methodIdx int) map[uint16]string {
	method := cf.Methods[methodIdx]
	isStatic := method.AccessFlags&0x0008 != 0
	params, _ := ParseDescriptor(cf.GetUTF8(method.DescriptorIndex))

	lvTable, _ := cf.ParseLocalVariableTable(methodIdx)
	lvNames := make(map[uint16]string, len(lvTable))
	for _, entry := range lvTable {
		lvNames[entry.Index] = cf.GetUTF8(entry.NameIndex)
	}

	names := make(map[uint16]string, len(params))
	slot := uint16(0)
	if !isStatic {
		slot = 1
	}
	for argIdx, p := range params {
		name := ""
		if n, ok := lvNames[slot]; ok && n != "" && n != "this" {
			name = n
		} else {
			name = inferParamName(p, argIdx)
		}
		names[slot] = name
		slot++
		if p.Base == "long" || p.Base == "double" {
			slot++
		}
	}
	return names
}

func resolveLocalVars(cf *ClassFile, methodIdx int, code *CodeAttribute) map[uint16]string {
	vars := make(map[uint16]string)
	method := cf.Methods[methodIdx]
	isStatic := method.AccessFlags&0x0008 != 0
	params, _ := ParseDescriptor(cf.GetUTF8(method.DescriptorIndex))

	if !isStatic {
		vars[0] = "this"
	}

	paramNames := buildParamNames(cf, methodIdx)
	for slot, name := range paramNames {
		vars[slot] = name
	}

	paramEnd := uint16(0)
	if !isStatic {
		paramEnd = 1
	}
	for _, p := range params {
		paramEnd++
		if p.Base == "long" || p.Base == "double" {
			paramEnd++
		}
	}

	lvTable, _ := cf.ParseLocalVariableTable(methodIdx)
	for _, entry := range lvTable {
		if entry.Index < paramEnd {
			continue // already named via buildParamNames above
		}
		vars[entry.Index] = cf.GetUTF8(entry.NameIndex)
	}

	return vars
}

func resolveLocalVarEnd(cf *ClassFile, methodIdx int) uint16 {
	method := cf.Methods[methodIdx]
	isStatic := method.AccessFlags&0x0008 != 0
	params, _ := ParseDescriptor(cf.GetUTF8(method.DescriptorIndex))

	offset := uint16(0)
	if !isStatic {
		offset = 1
	}
	for _, p := range params {
		offset++
		if p.Base == "long" || p.Base == "double" {
			offset++
		}
	}
	return offset
}

func collectLocalTypes(cf *ClassFile, methodIdx int, code *CodeAttribute) map[uint16]ir.Type {
	types := make(map[uint16]ir.Type)
	paramEnd := resolveLocalVarEnd(cf, methodIdx)
	method := cf.Methods[methodIdx]
	isStatic := method.AccessFlags&0x0008 != 0

	lvTable, _ := cf.ParseLocalVariableTable(methodIdx)
	for _, entry := range lvTable {
		if entry.Index >= paramEnd {
			desc := cf.GetUTF8(entry.DescriptorIndex)
			t := descriptorToIRType(desc)
			if t != nil {
				types[entry.Index] = t
			}
		}
	}

	instructions := DecodeInstructions(code.Code)
	for _, inst := range instructions {
		var localIdx byte
		var typ ir.Type
		switch inst.Opcode {
		case Istore0, Istore1, Istore2, Istore3:
			localIdx = byte(inst.Opcode - Istore0)
			typ = &ir.PrimitiveType{Name: "int"}
		case Istore:
			localIdx = inst.Operands[0]
			typ = &ir.PrimitiveType{Name: "int"}
		case Lstore0, Lstore1, Lstore2, Lstore3:
			localIdx = byte(inst.Opcode - Lstore0)
			typ = &ir.PrimitiveType{Name: "long"}
		case Lstore:
			localIdx = inst.Operands[0]
			typ = &ir.PrimitiveType{Name: "long"}
		case Fstore0, Fstore1, Fstore2, Fstore3:
			localIdx = byte(inst.Opcode - Fstore0)
			typ = &ir.PrimitiveType{Name: "float"}
		case Fstore:
			localIdx = inst.Operands[0]
			typ = &ir.PrimitiveType{Name: "float"}
		case Dstore0, Dstore1, Dstore2, Dstore3:
			localIdx = byte(inst.Opcode - Dstore0)
			typ = &ir.PrimitiveType{Name: "double"}
		case Dstore:
			localIdx = inst.Operands[0]
			typ = &ir.PrimitiveType{Name: "double"}
		default:
			continue
		}
		idx := uint16(localIdx)
		if idx >= paramEnd {
			if _, exists := types[idx]; !exists {
				types[idx] = typ
			}
		}
	}

	_ = isStatic
	return types
}

func descriptorToIRType(desc string) ir.Type {
	if len(desc) == 0 {
		return nil
	}
	switch desc[0] {
	case 'Z':
		return &ir.PrimitiveType{Name: "boolean"}
	case 'B':
		return &ir.PrimitiveType{Name: "byte"}
	case 'C':
		return &ir.PrimitiveType{Name: "char"}
	case 'S':
		return &ir.PrimitiveType{Name: "short"}
	case 'I':
		return &ir.PrimitiveType{Name: "int"}
	case 'J':
		return &ir.PrimitiveType{Name: "long"}
	case 'F':
		return &ir.PrimitiveType{Name: "float"}
	case 'D':
		return &ir.PrimitiveType{Name: "double"}
	case 'L':
		end := strings.IndexByte(desc, ';')
		if end < 0 {
			end = len(desc)
		}
		name := desc[1:end]
		return &ir.ClassType{Name: name}
	case '[':
		elem := descriptorToIRType(desc[1:])
		if elem != nil {
			return &ir.ArrayType{Elem: elem}
		}
	}
	return nil
}

func getLocalVar(vars map[uint16]string, idx byte) string {
	if name, ok := vars[uint16(idx)]; ok {
		return name
	}
	return fmt.Sprintf("local_%d", idx)
}

func classNameToJavaName(name string) string {
	switch name {
	case "java/lang/String", "java.lang.String":
		return "String"
	case "java/lang/Object", "java.lang.Object":
		return "Object"
	case "java/lang/Integer", "java.lang.Integer":
		return "Integer"
	case "java/lang/Long", "java.lang.Long":
		return "Long"
	case "java/lang/Float", "java.lang.Float":
		return "Float"
	case "java/lang/Double", "java.lang.Double":
		return "Double"
	case "java/lang/Boolean", "java.lang.Boolean":
		return "Boolean"
	case "java/lang/Character", "java.lang.Character":
		return "Character"
	default:
		name = strings.ReplaceAll(name, "/", ".")
		name = strings.ReplaceAll(name, "$", ".")
		return name
	}
}

func decompileInstruction(cf *ClassFile, code *CodeAttribute, instructions []Instruction, inst Instruction, localVars map[uint16]string, stack *exprStack, className string) []ir.Stmt {
	switch inst.Opcode {
	case Iload0, Iload1, Iload2, Iload3:
		idx := byte(inst.Opcode - Iload0)
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, idx)})
		return nil
	case Iload:
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])})
		return nil
	case Aload0, Aload1, Aload2, Aload3:
		idx := byte(inst.Opcode - Aload0)
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, idx)})
		return nil
	case Aload:
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])})
		return nil
	case Lload0, Lload1, Lload2, Lload3:
		idx := byte(inst.Opcode - Lload0)
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, idx)})
		return nil
	case Lload:
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])})
		return nil
	case Fload0, Fload1, Fload2, Fload3:
		idx := byte(inst.Opcode - Fload0)
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, idx)})
		return nil
	case Fload:
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])})
		return nil
	case Dload0, Dload1, Dload2, Dload3:
		idx := byte(inst.Opcode - Dload0)
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, idx)})
		return nil
	case Dload:
		stack.push(&ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])})
		return nil

	case Istore0, Istore1, Istore2, Istore3:
		idx := byte(inst.Opcode - Istore0)
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, idx)}, Value: val}}
	case Istore:
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])}, Value: val}}
	case Astore0, Astore1, Astore2, Astore3:
		idx := byte(inst.Opcode - Astore0)
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, idx)}, Value: val}}
	case Astore:
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])}, Value: val}}
	case Lstore0, Lstore1, Lstore2, Lstore3:
		idx := byte(inst.Opcode - Lstore0)
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, idx)}, Value: val}}
	case Lstore:
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])}, Value: val}}
	case Fstore0, Fstore1, Fstore2, Fstore3:
		idx := byte(inst.Opcode - Fstore0)
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, idx)}, Value: val}}
	case Fstore:
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])}, Value: val}}
	case Dstore0, Dstore1, Dstore2, Dstore3:
		idx := byte(inst.Opcode - Dstore0)
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, idx)}, Value: val}}
	case Dstore:
		val := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.LocalVar{Name: getLocalVar(localVars, inst.Operands[0])}, Value: val}}

	case Iconst0, Iconst1, Iconst2, Iconst3, Iconst4, Iconst5:
		stack.push(&ir.IntLit{Value: int64(inst.Opcode - Iconst0)})
		return nil
	case IconstM1:
		stack.push(&ir.IntLit{Value: -1})
		return nil
	case Lconst0:
		stack.push(&ir.LongLit{Value: 0})
		return nil
	case Lconst1:
		stack.push(&ir.LongLit{Value: 1})
		return nil
	case Fconst0:
		stack.push(&ir.FloatLit{Value: 0})
		return nil
	case Fconst1:
		stack.push(&ir.FloatLit{Value: 1})
		return nil
	case Fconst2:
		stack.push(&ir.FloatLit{Value: 2})
		return nil
	case Dconst0:
		stack.push(&ir.DoubleLit{Value: 0})
		return nil
	case Dconst1:
		stack.push(&ir.DoubleLit{Value: 1})
		return nil
	case AconstNull:
		stack.push(&ir.NullLit{})
		return nil

	case Bipush:
		stack.push(&ir.IntLit{Value: int64(int8(inst.Operands[0]))})
		return nil
	case Sipush:
		val := int16(inst.Operands[0])<<8 | int16(inst.Operands[1])
		stack.push(&ir.IntLit{Value: int64(val)})
		return nil

	case Ldc:
		idx := uint16(inst.Operands[0])
		for _, e := range decompileLdc(cf, idx) {
			if es, ok := e.(*ir.ExprStmt); ok {
				stack.push(es.Expr)
			}
		}
		return nil
	case LdcW:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		for _, e := range decompileLdc(cf, idx) {
			if es, ok := e.(*ir.ExprStmt); ok {
				stack.push(es.Expr)
			}
		}
		return nil
	case Ldc2W:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		for _, e := range decompileLdc2W(cf, idx) {
			if es, ok := e.(*ir.ExprStmt); ok {
				stack.push(es.Expr)
			}
		}
		return nil

	case Iadd, Ladd, Fadd, Dadd:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "+", Left: left, Right: right})
		return nil
	case Isub, Lsub, Fsub, Dsub:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "-", Left: left, Right: right})
		return nil
	case Imul, Lmul, Fmul, Dmul:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "*", Left: left, Right: right})
		return nil
	case Idiv, Ldiv, Fdiv, Ddiv:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "/", Left: left, Right: right})
		return nil
	case Irem, Lrem, Frem, Drem:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "%", Left: left, Right: right})
		return nil
	case Ineg, Lneg, Fneg, Dneg:
		stack.push(&ir.UnaryExpr{Op: "-", Expr: stack.pop()})
		return nil

	case Ishl, Lshl:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "<<", Left: left, Right: right})
		return nil
	case Ishr, Lshr:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: ">>", Left: left, Right: right})
		return nil
	case Iushr, Lushr:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: ">>>", Left: left, Right: right})
		return nil
	case Iand, Land:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "&", Left: left, Right: right})
		return nil
	case Ior, Lor:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "|", Left: left, Right: right})
		return nil
	case Ixor, Lxor:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "^", Left: left, Right: right})
		return nil

	case Getstatic:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		fieldClassName := cf.GetFieldClassName(idx)
		fieldName := cf.GetFieldName(idx)
		objName := classNameToJavaName(fieldClassName)
		fieldSimpleName := fieldClassName
		if i := strings.LastIndex(fieldClassName, "/"); i >= 0 {
			fieldSimpleName = fieldClassName[i+1:]
		}
		if fieldSimpleName == className {
			stack.push(&ir.LocalVar{Name: fieldName})
		} else {
			stack.push(&ir.FieldAccess{Object: &ir.LocalVar{Name: objName}, Name: fieldName})
		}
		return nil
	case Putstatic:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		fieldClassName := cf.GetFieldClassName(idx)
		fieldName := cf.GetFieldName(idx)
		val := stack.pop()
		objName := classNameToJavaName(fieldClassName)
		fieldSimpleName := fieldClassName
		if i := strings.LastIndex(fieldClassName, "/"); i >= 0 {
			fieldSimpleName = fieldClassName[i+1:]
		}
		var target ir.Expr
		if fieldSimpleName == className {
			target = &ir.LocalVar{Name: fieldName}
		} else {
			target = &ir.FieldAccess{Object: &ir.LocalVar{Name: objName}, Name: fieldName}
		}
		if isBool, ok := cf.GetFieldIsBoolean(idx); ok && isBool {
			if il, ok := val.(*ir.IntLit); ok {
				if il.Value == 0 {
					val = &ir.BoolLit{Value: false}
				} else if il.Value == 1 {
					val = &ir.BoolLit{Value: true}
				}
			}
		}
		return []ir.Stmt{&ir.AssignStmt{Target: target, Value: val}}
	case Getfield:
		fieldName := cf.GetFieldName(uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1]))
		obj := stack.pop()
		stack.push(&ir.FieldAccess{Object: obj, Name: fieldName})
		return nil
	case Putfield:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		fieldName := cf.GetFieldName(idx)
		val := stack.pop()
		obj := stack.pop()
		if isBool, ok := cf.GetFieldIsBoolean(idx); ok && isBool {
			if il, ok := val.(*ir.IntLit); ok {
				if il.Value == 0 {
					val = &ir.BoolLit{Value: false}
				} else if il.Value == 1 {
					val = &ir.BoolLit{Value: true}
				}
			}
		}
		if lv, ok := obj.(*ir.LocalVar); ok && lv.Name == "stack_value" {
			if realObj, compoundVal, ok := tryExtractCompoundAssign(val, fieldName); ok {
				return []ir.Stmt{&ir.AssignStmt{Target: &ir.FieldAccess{Object: realObj, Name: fieldName}, Value: compoundVal}}
			}
		}
		return []ir.Stmt{&ir.AssignStmt{Target: &ir.FieldAccess{Object: obj, Name: fieldName}, Value: val}}

	case Invokevirtual:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		return decompileInvoke(cf, idx, "invokevirtual", stack)
	case Invokespecial:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		return decompileInvoke(cf, idx, "invokespecial", stack)
	case Invokestatic:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		return decompileInvoke(cf, idx, "invokestatic", stack)
	case Invokeinterface:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		return decompileInvoke(cf, idx, "invokeinterface", stack)
	case Invokedynamic:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		return decompileInvokedynamic(cf, idx, stack)

	case Return:
		return []ir.Stmt{&ir.ReturnStmt{}}
	case Ireturn, Lreturn, Freturn, Dreturn, Areturn:
		return []ir.Stmt{&ir.ReturnStmt{Value: stack.pop()}}

	case New:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		stack.push(&ir.NewExpr{Type: classNameToJavaName(cf.GetClassName(idx))})
		return nil
	case Checkcast:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		expr := stack.pop()
		stack.push(&ir.CastExpr{Type: &ir.ClassType{Name: classNameToJavaName(cf.GetClassName(idx))}, Expr: expr})
		return nil
	case Instanceof:
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		expr := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "instanceof", Left: expr, Right: &ir.ClassType{Name: classNameToJavaName(cf.GetClassName(idx))}})
		return nil

	case Iinc:
		localIdx := inst.Operands[0]
		delta := int8(inst.Operands[1])
		varName := getLocalVar(localVars, localIdx)
		var deltaExpr ir.Expr
		if delta < 0 {
			deltaExpr = &ir.UnaryExpr{Op: "-", Expr: &ir.IntLit{Value: int64(-delta)}}
		} else {
			deltaExpr = &ir.IntLit{Value: int64(delta)}
		}
		return []ir.Stmt{&ir.AssignStmt{
			Target: &ir.LocalVar{Name: varName},
			Value:  &ir.BinaryExpr{Op: "+", Left: &ir.LocalVar{Name: varName}, Right: deltaExpr},
		}}

	case Athrow:
		return []ir.Stmt{&ir.ThrowStmt{Value: stack.pop()}}

	case Fcmpl:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "fcmpl", Left: left, Right: right})
		return nil
	case Fcmpg:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "fcmpg", Left: left, Right: right})
		return nil
	case Dcmpl:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "dcmpl", Left: left, Right: right})
		return nil
	case Dcmpg:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "dcmpg", Left: left, Right: right})
		return nil
	case Lcmp:
		right := stack.pop()
		left := stack.pop()
		stack.push(&ir.BinaryExpr{Op: "lcmp", Left: left, Right: right})
		return nil

	case Arraylength:
		stack.push(&ir.FieldAccess{Object: stack.pop(), Name: "length"})
		return nil

	case Iaload, Laload, Faload, Daload, Aaload, Baload, Saload:
		index := stack.pop()
		array := stack.pop()
		stack.push(&ir.ArrayAccess{Array: array, Index: index})
		return nil

	case Iastore, Lastore, Fastore, Dastore, Aastore, Bastore, Sastore:
		value := stack.pop()
		index := stack.pop()
		array := stack.pop()
		return []ir.Stmt{&ir.AssignStmt{
			Target: &ir.ArrayAccess{Array: array, Index: index},
			Value:  value,
		}}

	case Dup:
		if len(stack.items) > 0 {
			top := stack.items[len(stack.items)-1]
			stack.push(top)
		}
		return nil
	case DupX1:
		if len(stack.items) >= 2 {
			a := stack.pop()
			b := stack.pop()
			stack.push(a)
			stack.push(b)
			stack.push(a)
		}
		return nil
	case DupX2:
		if len(stack.items) >= 3 {
			a := stack.pop()
			b := stack.pop()
			c := stack.pop()
			stack.push(a)
			stack.push(c)
			stack.push(b)
			stack.push(a)
		}
		return nil
	case Dup2:
		if len(stack.items) >= 2 {
			a := stack.items[len(stack.items)-2]
			b := stack.items[len(stack.items)-1]
			stack.push(a)
			stack.push(b)
		}
		return nil
	case Dup2X1:
		if len(stack.items) >= 3 {
			a := stack.pop()
			b := stack.pop()
			c := stack.pop()
			stack.push(b)
			stack.push(a)
			stack.push(c)
			stack.push(b)
			stack.push(a)
		}
		return nil
	case Dup2X2:
		if len(stack.items) >= 4 {
			a := stack.pop()
			b := stack.pop()
			c := stack.pop()
			d := stack.pop()
			stack.push(b)
			stack.push(a)
			stack.push(d)
			stack.push(c)
			stack.push(b)
			stack.push(a)
		}
		return nil
	case Swap:
		if len(stack.items) >= 2 {
			a := stack.pop()
			b := stack.pop()
			stack.push(a)
			stack.push(b)
		}
		return nil
	case Pop:
		popped := stack.pop()
		if _, ok := popped.(*ir.LocalVar); ok {
			return nil
		}
		return []ir.Stmt{&ir.ExprStmt{Expr: popped}}
	case Pop2:
		stack.pop()
		stack.pop()
		return nil

	case Newarray:
		size := stack.pop()
		typeByte := inst.Operands[0]
		typeName := newarrayTypeName(typeByte)
		stack.push(&ir.NewArrayExpr{ElemType: &ir.PrimitiveType{Name: typeName}, Size: size})
		return nil

	case Anewarray:
		size := stack.pop()
		idx := uint16(inst.Operands[0])<<8 | uint16(inst.Operands[1])
		typeName := cf.GetClassName(idx)
		stack.push(&ir.NewArrayExpr{ElemType: &ir.PrimitiveType{Name: classNameToJavaName(typeName)}, Size: size})
		return nil

	case Tableswitch:
		target := stack.pop()
		operands := inst.Operands
		if len(operands) < 12 {
			return nil
		}
		defaultOffset := int32(operands[0])<<24 | int32(operands[1])<<16 | int32(operands[2])<<8 | int32(operands[3])
		low := int32(operands[4])<<24 | int32(operands[5])<<16 | int32(operands[6])<<8 | int32(operands[7])
		high := int32(operands[8])<<24 | int32(operands[9])<<16 | int32(operands[10])<<8 | int32(operands[11])
		numCases := int(high - low + 1)
		var cases []*ir.CaseClause
		for i := 0; i < numCases && 12+i*4+4 <= len(operands); i++ {
			caseOffset := int32(operands[12+i*4])<<24 | int32(operands[12+i*4+1])<<16 | int32(operands[12+i*4+2])<<8 | int32(operands[12+i*4+3])
			_ = caseOffset
			cases = append(cases, &ir.CaseClause{
				Values: []ir.Expr{&ir.IntLit{Value: int64(low + int32(i))}},
			})
		}
		_ = defaultOffset
		return []ir.Stmt{&ir.SwitchStmt{Target: target, Cases: cases}}

	case Lookupswitch:
		target := stack.pop()
		operands := inst.Operands
		if len(operands) < 8 {
			return nil
		}
		defaultOffset := int32(operands[0])<<24 | int32(operands[1])<<16 | int32(operands[2])<<8 | int32(operands[3])
		npairs := int32(operands[4])<<24 | int32(operands[5])<<16 | int32(operands[6])<<8 | int32(operands[7])
		var cases []*ir.CaseClause
		for i := 0; i < int(npairs) && 8+i*8+8 <= len(operands); i++ {
			caseVal := int32(operands[8+i*8])<<24 | int32(operands[8+i*8+1])<<16 | int32(operands[8+i*8+2])<<8 | int32(operands[8+i*8+3])
			caseOffset := int32(operands[8+i*8+4])<<24 | int32(operands[8+i*8+5])<<16 | int32(operands[8+i*8+6])<<8 | int32(operands[8+i*8+7])
			_ = caseOffset
			cases = append(cases, &ir.CaseClause{
				Values: []ir.Expr{&ir.IntLit{Value: int64(caseVal)}},
			})
		}
		_ = defaultOffset
		return []ir.Stmt{&ir.SwitchStmt{Target: target, Cases: cases}}

	default:
		return nil
	}
}

func newarrayTypeName(typeByte byte) string {
	switch typeByte {
	case 4:
		return "boolean"
	case 5:
		return "char"
	case 6:
		return "float"
	case 7:
		return "double"
	case 8:
		return "byte"
	case 9:
		return "short"
	case 10:
		return "int"
	case 11:
		return "long"
	}
	return "int"
}

func isMethodVoid(desc string) bool {
	for i := len(desc) - 1; i >= 0; i-- {
		if desc[i] == ')' {
			return i+1 < len(desc) && desc[i+1] == 'V'
		}
	}
	return false
}

func decompileLdc(cf *ClassFile, idx uint16) []ir.Stmt {
	if int(idx) >= len(cf.ConstantPool) {
		return nil
	}
	entry := cf.ConstantPool[idx]
	switch entry.Tag {
	case CPTypeInteger:
		if entry.Integer != nil {
			return []ir.Stmt{&ir.ExprStmt{Expr: &ir.IntLit{Value: int64(entry.Integer.Value)}}}
		}
	case CPTypeFloat:
		if entry.Float != nil {
			return []ir.Stmt{&ir.ExprStmt{Expr: &ir.FloatLit{Value: entry.Float.Value}}}
		}
	case CPTypeString:
		if entry.String != nil {
			return []ir.Stmt{&ir.ExprStmt{Expr: &ir.StringLit{Value: cf.GetUTF8(entry.String.StringIndex)}}}
		}
	case CPTypeClass:
		if entry.Class != nil {
			className := cf.GetClassName(idx)
			javaName := classNameToJavaName(className)
			return []ir.Stmt{&ir.ExprStmt{Expr: &ir.ClassLiteral{Type: javaName + ".class"}}}
		}
	}
	return nil
}

func decompileLdc2W(cf *ClassFile, idx uint16) []ir.Stmt {
	if int(idx) >= len(cf.ConstantPool) {
		return nil
	}
	entry := cf.ConstantPool[idx]
	switch entry.Tag {
	case CPTypeLong:
		if entry.Long != nil {
			return []ir.Stmt{&ir.ExprStmt{Expr: &ir.LongLit{Value: entry.Long.Value}}}
		}
	case CPTypeDouble:
		if entry.Double != nil {
			return []ir.Stmt{&ir.ExprStmt{Expr: &ir.DoubleLit{Value: entry.Double.Value}}}
		}
	}
	return nil
}

func decompileInvoke(cf *ClassFile, idx uint16, kind string, stack *exprStack) []ir.Stmt {
	if int(idx) >= len(cf.ConstantPool) {
		return nil
	}
	entry := cf.ConstantPool[idx]
	var className string
	var natIdx uint16

	switch entry.Tag {
	case CPTypeMethodref:
		if entry.Methodref == nil {
			return nil
		}
		className = cf.GetClassName(entry.Methodref.ClassIndex)
		natIdx = entry.Methodref.NameAndTypeIndex
	case CPTypeInterfaceMethodref:
		if entry.InterfaceMethodref == nil {
			return nil
		}
		className = cf.GetClassName(entry.InterfaceMethodref.ClassIndex)
		natIdx = entry.InterfaceMethodref.NameAndTypeIndex
	default:
		return nil
	}

	methodName := cf.GetUTF8(cf.ConstantPool[natIdx].NameAndType.NameIndex)
	methodDesc := cf.GetUTF8(cf.ConstantPool[natIdx].NameAndType.DescriptorIndex)
	javaClass := classNameToJavaName(className)
	params, _ := ParseDescriptor(methodDesc)
	argCount := len(params)
	isVoid := isMethodVoid(methodDesc)

	var args []ir.Expr
	for i := 0; i < argCount; i++ {
		args = append([]ir.Expr{stack.pop()}, args...)
	}
	for i, p := range params {
		if i >= len(args) {
			break
		}
		if p.Base != "bool" || p.IsArray {
			continue
		}
		if lit, ok := args[i].(*ir.IntLit); ok {
			args[i] = &ir.BoolLit{Value: lit.Value != 0}
		}
	}

	if methodName == "<init>" {
		newObj := stack.pop()
		if ne, ok := newObj.(*ir.NewExpr); ok {
			ne.Args = args
			if len(stack.items) > 0 {
				if top, ok := stack.items[len(stack.items)-1].(*ir.NewExpr); ok && top == ne {
					stack.pop()
				}
			}
			stack.push(ne)
		}
		return nil
	}

	if methodName == "<clinit>" {
		return []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Class: javaClass, Method: "static_constructor"}}}
	}

	if kind == "invokestatic" {
		if isVoid {
			return []ir.Stmt{&ir.ExprStmt{Expr: &ir.StaticMethodCall{Class: javaClass, Method: methodName, Args: args}}}
		}
		stack.push(&ir.StaticMethodCall{Class: javaClass, Method: methodName, Args: args})
		return nil
	}

	obj := stack.pop()
	if isVoid {
		return []ir.Stmt{&ir.ExprStmt{Expr: &ir.MethodCall{Object: obj, Name: methodName, Args: args}}}
	}
	stack.push(&ir.MethodCall{Object: obj, Name: methodName, Args: args})
	return nil
}

func decompileInvokedynamic(cf *ClassFile, idx uint16, stack *exprStack) []ir.Stmt {
	if int(idx) >= len(cf.ConstantPool) {
		return nil
	}
	entry := cf.ConstantPool[idx]
	if entry.InvokeDynamic == nil {
		return nil
	}

	natIdx := entry.InvokeDynamic.NameAndTypeIndex
	if int(natIdx) >= len(cf.ConstantPool) || cf.ConstantPool[natIdx].NameAndType == nil {
		return nil
	}

	methodName := cf.GetUTF8(cf.ConstantPool[natIdx].NameAndType.NameIndex)
	methodDesc := cf.GetUTF8(cf.ConstantPool[natIdx].NameAndType.DescriptorIndex)

	if className, targetMethod, ok := cf.ResolveLambdaTarget(idx); ok {
		params, _ := ParseDescriptor(methodDesc)
		argCount := len(params)
		for i := 0; i < argCount; i++ {
			stack.pop()
		}

		// A synthetic lambda body (javac's standard "lambda$enclosingMethod$N"
		// naming, shared by every mainstream JVM compiler) always lives
		// in the SAME class as the lambda expression itself - a real
		// Class::method reference the person actually wrote essentially
		// never does (and even if it coincidentally did, it wouldn't be
		// named lambda$...). Inline the real body instead of exposing
		// the generated method name, which would be unreadable and give
		// no insight into what the lambda actually does.
		if strings.HasPrefix(targetMethod, "lambda$") && className == cf.GetThisClassName() {
			// Use the real functional-interface descriptor (from the
			// bootstrap method's own samMethodType argument), not
			// methodDesc (the invokedynamic call site's descriptor,
			// which describes how to CREATE the lambda object - zero
			// arguments for a non-capturing lambda - not how the
			// resulting functional interface is CALLED). Only attempt
			// inlining when the real descriptor was actually resolved;
			// otherwise fall through to the always-safe bare
			// MethodRefExpr below rather than risk a wrong parameter
			// count from the unreliable call-site descriptor.
			if samDesc, samOk := cf.ResolveLambdaSAMDescriptor(idx); samOk {
				if expr, ok := inlineLambdaBody(cf, targetMethod, samDesc); ok {
					stack.push(expr)
					return nil
				}
			}
		}

		stack.push(&ir.MethodRefExpr{ClassName: classNameToJavaName(className), MethodName: targetMethod})
		return nil
	}

	if methodName == "makeConcatWithConstants" {
		params, _ := ParseDescriptor(methodDesc)
		argCount := len(params)
		var args []ir.Expr
		for i := 0; i < argCount; i++ {
			args = append([]ir.Expr{stack.pop()}, args...)
		}
		for i, j := 0, len(args)-1; i < j; i, j = i+1, j-1 {
			args[i], args[j] = args[j], args[i]
		}
		if len(args) == 2 {
			stack.push(&ir.BinaryExpr{Op: "+", Left: args[0], Right: args[1]})
		} else if len(args) == 1 {
			stack.push(args[0])
		} else {
			result := args[0]
			for i := 1; i < len(args); i++ {
				result = &ir.BinaryExpr{Op: "+", Left: result, Right: args[i]}
			}
			stack.push(result)
		}
		return nil
	}

	params, _ := ParseDescriptor(methodDesc)
	argCount := len(params)
	var args []ir.Expr
	for i := 0; i < argCount; i++ {
		args = append([]ir.Expr{stack.pop()}, args...)
	}
	stack.push(&ir.MethodCall{Object: &ir.LocalVar{Name: methodName}, Name: methodName, Args: args})
	return nil
}

// inlineLambdaBody finds the synthetic method named targetMethod (javac's
// "lambda$...$N" naming) in cf, decompiles its actual body, and returns
// it as a LambdaExpr - or (nil, false) if the method can't be found or
// the recursion depth guard trips.
//
// callSiteDesc is the functional interface method's descriptor as seen
// at the invokedynamic call site (e.g. "(Ljava/lang/Object;)Z" for a
// Predicate) - used only to know how many of the synthetic method's
// OWN parameters are the lambda's real, visible parameters. A lambda
// that captures variables from its enclosing scope has those captures
// silently prepended as leading parameters on the synthetic method by
// the compiler (this is exactly how capture is implemented - there's no
// separate closure object), so the visible lambda parameters are always
// the trailing N parameters of the synthetic method, where N is the
// functional interface method's own arity from callSiteDesc.
func inlineLambdaBody(cf *ClassFile, targetMethod, callSiteDesc string) (*ir.LambdaExpr, bool) {
	if lambdaInlineDepth >= maxLambdaInlineDepth {
		return nil, false
	}

	visibleParams, _ := ParseDescriptor(callSiteDesc)
	visibleCount := len(visibleParams)

	for methodIdx, m := range cf.Methods {
		if cf.GetUTF8(m.NameIndex) != targetMethod {
			continue
		}
		code, err := cf.ParseCodeAttribute(methodIdx)
		if err != nil || code == nil {
			return nil, false
		}

		ownDesc := cf.GetUTF8(m.DescriptorIndex)
		ownParams, _ := ParseDescriptor(ownDesc)
		if visibleCount > len(ownParams) {
			// Shouldn't happen for a genuine lambda body - the call
			// site's arity can never exceed the synthetic method's own
			// parameter count - but guard against it rather than
			// panicking on a malformed/unusual class file.
			return nil, false
		}
		captureCount := len(ownParams) - visibleCount

		isStatic := m.AccessFlags&0x0008 != 0
		paramNames := buildParamNames(cf, methodIdx)

		slot := uint16(0)
		if !isStatic {
			slot = 1
		}
		var names []string
		for i, p := range ownParams {
			if i >= captureCount {
				names = append(names, paramNames[slot])
			}
			slot++
			if p.Base == "long" || p.Base == "double" {
				slot++
			}
		}

		lambdaInlineDepth++
		body := decompileCode(cf, methodIdx, code, classNameToJavaName(cf.GetThisClassName()))
		lambdaInlineDepth--

		return &ir.LambdaExpr{Params: names, Body: body}, true
	}
	return nil, false
}

func jvmDescToIRType(desc string) ir.Type {
	t := parseSingleType(desc)
	return jvmParsedToIRType(t)
}

func jvmParsedToIRType(t ParsedType) ir.Type {
	if t.IsArray {
		return &ir.ArrayType{Elem: jvmParsedToIRType(ParsedType{Base: t.Base})}
	}
	switch t.Base {
	case "byte", "sbyte":
		return &ir.PrimitiveType{Name: "byte"}
	case "char":
		return &ir.PrimitiveType{Name: "char"}
	case "double":
		return &ir.PrimitiveType{Name: "double"}
	case "float":
		return &ir.PrimitiveType{Name: "float"}
	case "int":
		return &ir.PrimitiveType{Name: "int"}
	case "long":
		return &ir.PrimitiveType{Name: "long"}
	case "short":
		return &ir.PrimitiveType{Name: "short"}
	case "bool", "boolean":
		return &ir.PrimitiveType{Name: "boolean"}
	case "void":
		return &ir.PrimitiveType{Name: "void"}
	default:
		return &ir.ClassType{Name: classNameToJavaName(t.Base)}
	}
}

func tryExtractCompoundAssign(val ir.Expr, fieldName string) (ir.Expr, ir.Expr, bool) {
	if bin, ok := val.(*ir.BinaryExpr); ok {
		if fa, ok := bin.Left.(*ir.FieldAccess); ok && fa.Name == fieldName {
			return fa.Object, bin, true
		}
		if fa, ok := bin.Right.(*ir.FieldAccess); ok && fa.Name == fieldName {
			return fa.Object, bin, true
		}
	}
	if ua, ok := val.(*ir.UnaryExpr); ok {
		if fa, ok := ua.Expr.(*ir.FieldAccess); ok && fa.Name == fieldName {
			return fa.Object, val, true
		}
	}
	return nil, nil, false
}
