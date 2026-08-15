package native

/*
#cgo CFLAGS: -I/data/data/com.termux/files/usr/include
#cgo LDFLAGS: -L/data/data/com.termux/files/usr/lib -lcapstone
#include <capstone/capstone.h>
#include <stdlib.h>
#include <string.h>

// Helper to read one ARM64 operand out of a cs_insn's arch-specific union
// (cgo can't easily index into anonymous unions/nested arrays directly).
static cs_arm64_op arm64_get_operand(cs_insn *insn, int i) {
    return insn->detail->arm64.operands[i];
}

// Helper to read the ARM64-specific detail struct itself (cs_detail's
// arch info is also an anonymous union).
static cs_arm64 arm64_get_detail(cs_insn *insn) {
    return insn->detail->arm64;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Disassembler wraps Capstone's disassembly engine
type Disassembler struct {
	handle C.csh
	arch   int
	mode   int
}

// Instruction represents a disassembled instruction
type Instruction struct {
	Address uint64
	Size    uint32
	Mnemonic string
	OpStr   string
	Bytes   []byte
}

// OperandType identifies what kind of value an Operand holds.
type OperandType int

const (
	OperandInvalid OperandType = iota
	OperandReg
	OperandImm
	OperandMem
	OperandFP
)

// MemOperand is a memory-addressing operand: [base, index, #disp] (ARM64
// syntax "[base, index]" or "[base, #disp]" - Index and Disp are
// mutually exclusive in practice for the instructions a lifter cares
// about, but both are exposed since Capstone always populates both
// fields).
type MemOperand struct {
	Base  string // register name, e.g. "sp", "x0" ("" if none)
	Index string // register name for register-indexed addressing ("" if none)
	Disp  int32  // constant displacement, e.g. the 12 in "[sp, #12]"
}

// Operand is one structured instruction operand - exactly one of Reg,
// Imm, Mem, or FP is meaningful, per Type.
type Operand struct {
	Type OperandType
	Reg  string  // register name, e.g. "w0", "x1", "sp" (Type == OperandReg)
	Imm  int64   // immediate value (Type == OperandImm)
	Mem  MemOperand // memory operand (Type == OperandMem)
	FP   float64 // floating-point immediate (Type == OperandFP)
}

// DetailedInstruction is an Instruction plus its structured operands -
// what an actual instruction lifter needs, as opposed to Instruction's
// plain Mnemonic/OpStr text (kept separate, and Instruction/Disassemble/
// DisassembleAll unchanged, so existing callers like the ELF text
// listing aren't affected by turning on Capstone's detail mode, which
// has a small but real performance cost).
type DetailedInstruction struct {
	Address  uint64
	Size     uint32
	Mnemonic string
	OpStr    string
	Bytes    []byte
	Operands []Operand
	// WritesFlags is true if this instruction updates the condition
	// flags (NZCV) - needed to know whether a following b.cond/csel/etc.
	// is testing the result of THIS instruction or something earlier.
	WritesFlags bool
}

// NewDisassembler creates a new Capstone disassembler for the given architecture
func NewDisassembler(arch, mode int) (*Disassembler, error) {
	var handle C.csh
	ret := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if ret != C.CS_ERR_OK {
		return nil, fmt.Errorf("cs_open failed: %v", C.GoString(C.cs_strerror(ret)))
	}

	return &Disassembler{
		handle: handle,
		arch:   arch,
		mode:   mode,
	}, nil
}

// Close releases the disassembler resources
func (d *Disassembler) Close() {
	C.cs_close(&d.handle)
}

// Disassemble disassembles the given code bytes
func (d *Disassembler) Disassemble(code []byte, address uint64, count int) ([]Instruction, error) {
	if len(code) == 0 {
		return nil, nil
	}

	var insn *C.cs_insn
	cCode := (*C.uint8_t)(unsafe.Pointer(&code[0]))
	n := C.cs_disasm(d.handle, cCode, C.size_t(len(code)), C.uint64_t(address), C.size_t(count), &insn)
	if n == 0 {
		errCode := C.cs_errno(d.handle)
		if errCode != C.CS_ERR_OK {
			return nil, fmt.Errorf("cs_disasm failed: %v", C.GoString(C.cs_strerror(errCode)))
		}
		return nil, nil
	}

	result := make([]Instruction, int(n))
	for i := 0; i < int(n); i++ {
		inst := (*C.cs_insn)(unsafe.Pointer(uintptr(unsafe.Pointer(insn)) + uintptr(i)*unsafe.Sizeof(*insn)))
		result[i] = Instruction{
			Address:  uint64(inst.address),
			Size:    uint32(inst.size),
			Mnemonic: C.GoString(&inst.mnemonic[0]),
			OpStr:   C.GoString(&inst.op_str[0]),
			Bytes:   C.GoBytes(unsafe.Pointer(&inst.bytes[0]), C.int(inst.size)),
		}
	}

	C.cs_free(insn, C.size_t(n))
	return result, nil
}

// DisassembleDetailed disassembles code with Capstone's detail mode
// enabled, returning structured operands (register/immediate/memory)
// instead of only text - what an actual instruction lifter needs.
// Currently only implemented for ARM64 (the architecture's operand
// union is read through the arm64_get_operand C helper above); calling
// this on a Disassembler configured for another architecture returns an
// error.
func (d *Disassembler) DisassembleDetailed(code []byte, address uint64) ([]DetailedInstruction, error) {
	if len(code) == 0 {
		return nil, nil
	}
	if d.arch != ArchARM64 {
		return nil, fmt.Errorf("DisassembleDetailed: only ARM64 is currently supported")
	}

	if ret := C.cs_option(d.handle, C.CS_OPT_DETAIL, C.CS_OPT_ON); ret != C.CS_ERR_OK {
		return nil, fmt.Errorf("cs_option(CS_OPT_DETAIL) failed: %v", C.GoString(C.cs_strerror(ret)))
	}
	defer C.cs_option(d.handle, C.CS_OPT_DETAIL, C.CS_OPT_OFF)

	var insn *C.cs_insn
	cCode := (*C.uint8_t)(unsafe.Pointer(&code[0]))
	n := C.cs_disasm(d.handle, cCode, C.size_t(len(code)), C.uint64_t(address), C.size_t(0), &insn)
	if n == 0 {
		errCode := C.cs_errno(d.handle)
		if errCode != C.CS_ERR_OK {
			return nil, fmt.Errorf("cs_disasm failed: %v", C.GoString(C.cs_strerror(errCode)))
		}
		return nil, nil
	}
	defer C.cs_free(insn, C.size_t(n))

	result := make([]DetailedInstruction, int(n))
	for i := 0; i < int(n); i++ {
		inst := (*C.cs_insn)(unsafe.Pointer(uintptr(unsafe.Pointer(insn)) + uintptr(i)*unsafe.Sizeof(*insn)))

		di := DetailedInstruction{
			Address:  uint64(inst.address),
			Size:     uint32(inst.size),
			Mnemonic: C.GoString(&inst.mnemonic[0]),
			OpStr:    C.GoString(&inst.op_str[0]),
			Bytes:    C.GoBytes(unsafe.Pointer(&inst.bytes[0]), C.int(inst.size)),
		}

		if inst.detail != nil {
			arm64Detail := C.arm64_get_detail(inst)
			di.WritesFlags = bool(arm64Detail.update_flags)
			opCount := int(arm64Detail.op_count)
			di.Operands = make([]Operand, opCount)
			for j := 0; j < opCount; j++ {
				op := C.arm64_get_operand(inst, C.int(j))
				di.Operands[j] = convertARM64Operand(d.handle, op)
			}
		}

		result[i] = di
	}

	return result, nil
}

// convertARM64Operand translates one Capstone cs_arm64_op into our
// architecture-neutral Operand type.
func convertARM64Operand(handle C.csh, op C.cs_arm64_op) Operand {
	switch op._type {
	case C.ARM64_OP_REG:
		reg := *(*C.arm64_reg)(unsafe.Pointer(&op.anon0[0]))
		return Operand{Type: OperandReg, Reg: regName(handle, C.uint(reg))}
	case C.ARM64_OP_IMM:
		imm := *(*C.int64_t)(unsafe.Pointer(&op.anon0[0]))
		return Operand{Type: OperandImm, Imm: int64(imm)}
	case C.ARM64_OP_FP:
		fp := *(*C.double)(unsafe.Pointer(&op.anon0[0]))
		return Operand{Type: OperandFP, FP: float64(fp)}
	case C.ARM64_OP_MEM:
		mem := *(*C.arm64_op_mem)(unsafe.Pointer(&op.anon0[0]))
		m := MemOperand{Disp: int32(mem.disp)}
		if mem.base != C.ARM64_REG_INVALID {
			m.Base = regName(handle, C.uint(mem.base))
		}
		if mem.index != C.ARM64_REG_INVALID {
			m.Index = regName(handle, C.uint(mem.index))
		}
		return Operand{Type: OperandMem, Mem: m}
	default:
		return Operand{Type: OperandInvalid}
	}
}

func regName(handle C.csh, reg C.uint) string {
	if reg == 0 {
		return ""
	}
	cName := C.cs_reg_name(handle, reg)
	if cName == nil {
		return ""
	}
	return C.GoString(cName)
}

// Architecture constants
const (
	ArchARM   = int(C.CS_ARCH_ARM)
	ArchARM64 = int(C.CS_ARCH_ARM64)
	ArchX86   = int(C.CS_ARCH_X86)
	ArchMIPS  = int(C.CS_ARCH_MIPS)
)

// Mode constants
const (
	ModeARM   = int(C.CS_MODE_ARM)
	ModeTHUMB = int(C.CS_MODE_THUMB)
	ModeARM64 = int(C.CS_MODE_ARM)
	Mode32    = int(C.CS_MODE_32)
	Mode64    = int(C.CS_MODE_64)
	ModeLITTLE_ENDIAN = int(C.CS_MODE_LITTLE_ENDIAN)
)

// Helper functions for common architectures

// NewARM64Disassembler creates a disassembler for ARM64
func NewARM64Disassembler() (*Disassembler, error) {
	return NewDisassembler(ArchARM64, ModeARM64|ModeLITTLE_ENDIAN)
}

// NewARMDisassembler creates a disassembler for ARM (32-bit)
func NewARMDisassembler() (*Disassembler, error) {
	return NewDisassembler(ArchARM, ModeARM|ModeLITTLE_ENDIAN)
}

// NewThumbDisassembler creates a disassembler for ARM Thumb mode
func NewThumbDisassembler() (*Disassembler, error) {
	return NewDisassembler(ArchARM, ModeTHUMB|ModeLITTLE_ENDIAN)
}

// NewX86_32Disassembler creates a disassembler for x86 (32-bit)
func NewX86_32Disassembler() (*Disassembler, error) {
	return NewDisassembler(ArchX86, Mode32)
}

// NewX86_64Disassembler creates a disassembler for x86 (64-bit)
func NewX86_64Disassembler() (*Disassembler, error) {
	return NewDisassembler(ArchX86, Mode64)
}

// DisassembleAll disassembles all bytes and returns all instructions
func (d *Disassembler) DisassembleAll(code []byte, address uint64) ([]Instruction, error) {
	return d.Disassemble(code, address, 0)
}

// GetArchName returns the name of the architecture
func GetArchName(arch int) string {
	switch arch {
	case ArchARM:
		return "ARM"
	case ArchARM64:
		return "ARM64"
	case ArchX86:
		return "x86"
	case ArchMIPS:
		return "MIPS"
	default:
		return "Unknown"
	}
}
