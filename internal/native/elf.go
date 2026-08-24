package native

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// ELF constants
const (
	ELF_MAGIC    = "\x7fELF"
	ELFCLASS32   = 1
	ELFCLASS64   = 2
	ELFDATA2LSB  = 1
	ELFDATA2MSB  = 2
	ET_EXEC      = 2
	ET_DYN       = 3
	EM_ARM       = 40
	EM_AARCH64   = 183
	EM_386       = 3
	EM_X86_64    = 62
	SHT_PROGBITS = 1
	SHT_SYMTAB   = 2
	SHT_DYNSYM   = 11
	SHT_RELA     = 4
	STT_FUNC     = 2
)

// ELF file structures
type ELFHeader struct {
	Magic     [4]byte
	Class     uint8
	Data      uint8
	Version   uint8
	OSABI     uint8
	Padding   [8]byte
	Type      uint16
	Machine   uint16
	Version2  uint32
	Entry     uint64
	PhOff     uint64
	ShOff     uint64
	Flags     uint32
	EhSize    uint16
	PhEntSize uint16
	PhNum     uint16
	ShEntSize uint16
	ShNum     uint16
	ShStrNdx  uint16
}

type SectionHeader struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	AddrAlign uint64
	EntSize   uint64
}

type SymbolEntry struct {
	Name  uint32
	Info  uint8
	Other uint8
	Shndx uint16
	Value uint64
	Size  uint64
}

// ELFParser parses ELF files
type ELFParser struct {
	File     *os.File
	Data     []byte
	Header   ELFHeader
	Sections []SectionHeader
	Symbols  []SymbolEntry
	Arch     int
	Mode     int
	Bits     int
	IsEndian bool // true = little endian
	// SymStrTabNdx is the section index of the string table holding
	// symbol NAMES (as opposed to Header.ShStrNdx, which is the
	// string table for SECTION names - a different table entirely).
	// Captured from the symbol table section's own sh_link field when
	// parseSymbols runs, since that's the only correct way to find it
	// (there's no fixed/well-known index for it the way section names
	// always live at Header.ShStrNdx).
	SymStrTabNdx uint16
}

// NewELFParser creates a new ELF parser
func NewELFParser(path string) (*ELFParser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	if len(data) < 16 {
		return nil, fmt.Errorf("file too small for ELF header")
	}

	if string(data[:4]) != ELF_MAGIC {
		return nil, fmt.Errorf("not an ELF file")
	}

	p := &ELFParser{
		Data: data,
	}

	if err := p.parseHeader(); err != nil {
		return nil, err
	}

	if err := p.parseSections(); err != nil {
		return nil, err
	}

	if err := p.parseSymbols(); err != nil {
		// Symbols are optional
		fmt.Fprintf(os.Stderr, "warning: could not parse symbols: %v\n", err)
	}

	return p, nil
}

func (p *ELFParser) parseHeader() error {
	if len(p.Data) < 64 {
		return fmt.Errorf("ELF header too small")
	}

	p.Header.Class = p.Data[4]
	p.Header.Data = p.Data[5]

	// Determine endianness
	littleEndian := p.Header.Data == ELFDATA2LSB
	p.IsEndian = littleEndian

	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64

	if littleEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	p.Header.Type = binary.LittleEndian.Uint16(p.Data[16:18])
	p.Header.Machine = binary.LittleEndian.Uint16(p.Data[18:20])
	p.Header.Version2 = readUint32(p.Data[20:24])

	if p.Header.Class == ELFCLASS64 {
		p.Header.Entry = readUint64(p.Data[24:32])
		p.Header.PhOff = readUint64(p.Data[32:40])
		p.Header.ShOff = readUint64(p.Data[40:48])
		p.Header.Flags = readUint32(p.Data[48:52])
		p.Header.EhSize = binary.LittleEndian.Uint16(p.Data[52:54])
		p.Header.PhEntSize = binary.LittleEndian.Uint16(p.Data[54:56])
		p.Header.PhNum = binary.LittleEndian.Uint16(p.Data[56:58])
		p.Header.ShEntSize = binary.LittleEndian.Uint16(p.Data[58:60])
		p.Header.ShNum = binary.LittleEndian.Uint16(p.Data[60:62])
		p.Header.ShStrNdx = binary.LittleEndian.Uint16(p.Data[62:64])
		p.Bits = 64
	} else {
		p.Header.Entry = uint64(readUint32(p.Data[24:28]))
		p.Header.PhOff = uint64(readUint32(p.Data[28:32]))
		p.Header.ShOff = uint64(readUint32(p.Data[32:36]))
		p.Header.Flags = readUint32(p.Data[36:40])
		p.Header.EhSize = binary.LittleEndian.Uint16(p.Data[40:42])
		p.Header.PhEntSize = binary.LittleEndian.Uint16(p.Data[42:44])
		p.Header.PhNum = binary.LittleEndian.Uint16(p.Data[44:46])
		p.Header.ShEntSize = binary.LittleEndian.Uint16(p.Data[46:48])
		p.Header.ShNum = binary.LittleEndian.Uint16(p.Data[48:50])
		p.Header.ShStrNdx = binary.LittleEndian.Uint16(p.Data[50:52])
		p.Bits = 32
	}

	// Set architecture
	switch p.Header.Machine {
	case EM_AARCH64:
		p.Arch = ArchARM64
		p.Mode = ModeARM64 | ModeLITTLE_ENDIAN
	case EM_ARM:
		p.Arch = ArchARM
		p.Mode = ModeARM | ModeLITTLE_ENDIAN
	case EM_386:
		p.Arch = ArchX86
		p.Mode = Mode32
	case EM_X86_64:
		p.Arch = ArchX86
		p.Mode = Mode64
	default:
		return fmt.Errorf("unsupported architecture: %d", p.Header.Machine)
	}

	return nil
}

func (p *ELFParser) parseSections() error {
	if p.Header.ShOff == 0 || p.Header.ShNum == 0 {
		return nil
	}

	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64

	if p.IsEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	p.Sections = make([]SectionHeader, p.Header.ShNum)
	offset := p.Header.ShOff

	for i := 0; i < int(p.Header.ShNum); i++ {
		if offset+uint64(p.Header.ShEntSize) > uint64(len(p.Data)) {
			break
		}

		data := p.Data[offset:]
		s := SectionHeader{}

		if p.Header.Class == ELFCLASS64 {
			s.Name = readUint32(data[0:4])
			s.Type = readUint32(data[4:8])
			s.Flags = readUint64(data[8:16])
			s.Addr = readUint64(data[16:24])
			s.Offset = readUint64(data[24:32])
			s.Size = readUint64(data[32:40])
			s.Link = readUint32(data[40:44])
			s.Info = readUint32(data[44:48])
			s.AddrAlign = readUint64(data[48:56])
			s.EntSize = readUint64(data[56:64])
		} else {
			s.Name = readUint32(data[0:4])
			s.Type = readUint32(data[4:8])
			s.Flags = uint64(readUint32(data[8:12]))
			s.Addr = uint64(readUint32(data[12:16]))
			s.Offset = uint64(readUint32(data[16:20]))
			s.Size = uint64(readUint32(data[20:24]))
			s.Link = readUint32(data[24:28])
			s.Info = readUint32(data[28:32])
			s.AddrAlign = uint64(readUint32(data[32:36]))
			s.EntSize = uint64(readUint32(data[36:40]))
		}

		p.Sections[i] = s
		offset += uint64(p.Header.ShEntSize)
	}

	return nil
}

func (p *ELFParser) parseSymbols() error {
	for _, s := range p.Sections {
		if s.Type == SHT_SYMTAB {
			p.SymStrTabNdx = uint16(s.Link)
			return p.parseSymbolTable(s)
		}
	}
	return fmt.Errorf("no symbol table found")
}

func (p *ELFParser) parseSymbolTable(sec SectionHeader) error {
	var readUint32 func([]byte) uint32
	var readUint64 func([]byte) uint64

	if p.IsEndian {
		readUint32 = binary.LittleEndian.Uint32
		readUint64 = binary.LittleEndian.Uint64
	} else {
		readUint32 = binary.BigEndian.Uint32
		readUint64 = binary.BigEndian.Uint64
	}

	entSize := uint64(24) // Default for 64-bit
	if p.Header.Class != ELFCLASS64 {
		entSize = 16
	}

	if sec.EntSize > 0 {
		entSize = sec.EntSize
	}

	count := sec.Size / entSize
	p.Symbols = make([]SymbolEntry, 0, count)

	offset := sec.Offset
	for i := uint64(0); i < count; i++ {
		if offset+entSize > uint64(len(p.Data)) {
			break
		}

		data := p.Data[offset:]
		sym := SymbolEntry{}

		if p.Header.Class == ELFCLASS64 {
			sym.Name = readUint32(data[0:4])
			sym.Info = data[4]
			sym.Other = data[5]
			sym.Shndx = binary.LittleEndian.Uint16(data[6:8])
			sym.Value = readUint64(data[8:16])
			sym.Size = readUint64(data[16:24])
		} else {
			sym.Name = readUint32(data[0:4])
			sym.Value = uint64(readUint32(data[4:8]))
			sym.Size = uint64(readUint32(data[8:12]))
			sym.Info = data[12]
			sym.Other = data[13]
			sym.Shndx = binary.LittleEndian.Uint16(data[14:16])
		}

		if sym.Info&0xf == STT_FUNC {
			p.Symbols = append(p.Symbols, sym)
		}

		offset += entSize
	}

	return nil
}

// GetSymbolName returns the name of a symbol
func (p *ELFParser) GetSymbolName(sym SymbolEntry) string {
	strTabNdx := p.SymStrTabNdx
	if strTabNdx == 0 {
		// No .symtab was parsed (SymStrTabNdx never set) - fall back to
		// the section-name string table, which is wrong in general but
		// preserves this function's old behavior for callers that
		// somehow still get a SymbolEntry without a real symbol table
		// having been parsed.
		strTabNdx = p.Header.ShStrNdx
	}
	if int(strTabNdx) >= len(p.Sections) {
		return ""
	}

	strSec := p.Sections[strTabNdx]
	if uint64(sym.Name)+256 > strSec.Size {
		return ""
	}

	start := strSec.Offset + uint64(sym.Name)
	if start >= uint64(len(p.Data)) {
		return ""
	}

	// Read until null terminator
	end := bytes.IndexByte(p.Data[start:], 0)
	if end < 0 {
		end = 256
	}

	return string(p.Data[start : start+uint64(end)])
}

// maxCStringLen bounds how many bytes ReadCString will scan for a NUL
// terminator - just a sanity limit against a corrupt/adversarial file
// claiming a huge section size, not a real string-length limit (a
// literal this long would be unusual for the log/error-message strings
// this exists to recover).
const maxCStringLen = 4096

// ReadCString reads a NUL-terminated string literal stored at absolute
// virtual address vaddr - the data half of the adrp/adr(+add) address
// computation idiom arm64lift's string-literal resolution uses (an
// adrp/adr alone gives an address; this turns that address into the
// actual text sitting there, the way a real string literal would
// appear in decompiled source).
//
// Deliberately restricted to non-executable PROGBITS sections (real
// rodata/data, never .text): reading through an address that happens
// to land in code would just decode raw instruction bytes as if they
// were text, producing plausible-looking but meaningless garbage
// rather than a real literal - the isPrintableASCII check catches most
// such cases anyway, but excluding .text outright removes the failure
// mode entirely rather than relying on it being merely unlikely.
// Returns ("", false) if vaddr isn't inside such a section, has no NUL
// within maxCStringLen bytes, or the bytes before that NUL aren't
// printable text (most likely: vaddr points at binary data - a
// pointer, a vtable, a length-prefixed non-C-string - not a plain C
// string).
func (p *ELFParser) ReadCString(vaddr uint64) (string, bool) {
	for _, s := range p.Sections {
		if s.Type != SHT_PROGBITS || s.Flags&0x4 != 0 {
			continue
		}
		if vaddr < s.Addr || vaddr >= s.Addr+s.Size {
			continue
		}
		fileOff := s.Offset + (vaddr - s.Addr)
		if fileOff >= uint64(len(p.Data)) {
			return "", false
		}
		limit := s.Offset + s.Size
		if fileOff+maxCStringLen < limit {
			limit = fileOff + maxCStringLen
		}
		if limit > uint64(len(p.Data)) {
			limit = uint64(len(p.Data))
		}
		data := p.Data[fileOff:limit]
		nul := bytes.IndexByte(data, 0)
		if nul < 0 {
			return "", false
		}
		raw := data[:nul]
		if !isPrintableCString(raw) {
			return "", false
		}
		return string(raw), true
	}
	return "", false
}

// isPrintableCString reports whether b looks like genuine printable
// text (printable ASCII, plus tab/newline/carriage-return) rather than
// arbitrary binary data that happened to end in a zero byte.
func isPrintableCString(b []byte) bool {
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// GetCodeSections returns all executable sections
func (p *ELFParser) GetCodeSections() []CodeSection {
	var sections []CodeSection

	for _, s := range p.Sections {
		if s.Type == SHT_PROGBITS && s.Size > 0 {
			// Check if executable flag is set (bit 2)
			if s.Flags&0x4 != 0 {
				offset := s.Offset
				if offset+s.Size > uint64(len(p.Data)) {
					continue
				}

				code := p.Data[s.Offset : s.Offset+s.Size]
				if len(code) == 0 {
					continue
				}

				name := p.getSectionName(s)
				sections = append(sections, CodeSection{
					Name:    name,
					Address: s.Addr,
					Size:    s.Size,
					Data:    code,
					Offset:  s.Offset,
				})
			}
		}
	}

	return sections
}

// getSectionName returns the name of a section
func (p *ELFParser) getSectionName(sec SectionHeader) string {
	if int(p.Header.ShStrNdx) >= len(p.Sections) {
		return ""
	}

	strSec := p.Sections[p.Header.ShStrNdx]
	start := strSec.Offset + uint64(sec.Name)
	if start >= uint64(len(p.Data)) {
		return ""
	}

	end := bytes.IndexByte(p.Data[start:], 0)
	if end < 0 {
		end = 64
	}

	return string(p.Data[start : start+uint64(end)])
}

// CodeSection represents a section containing code
type CodeSection struct {
	Name    string
	Address uint64
	Size    uint64
	Data    []byte
	Offset  uint64
}

// DisassembleSection disassembles a code section using Capstone
func DisassembleSection(section CodeSection, arch, mode int) ([]Instruction, error) {
	d, err := NewDisassembler(arch, mode)
	if err != nil {
		return nil, fmt.Errorf("create disassembler: %w", err)
	}
	defer d.Close()

	return d.DisassembleAll(section.Data, section.Address)
}

// DisassembleELFFile disassembles all code sections in an ELF file
func DisassembleELFFile(path string, w io.Writer) error {
	parser, err := NewELFParser(path)
	if err != nil {
		return fmt.Errorf("parse ELF: %w", err)
	}

	sections := parser.GetCodeSections()
	if len(sections) == 0 {
		return fmt.Errorf("no code sections found")
	}

	fmt.Fprintf(w, "; ELF disassembly\n")
	fmt.Fprintf(w, "; Architecture: %s\n", GetArchName(parser.Arch))
	fmt.Fprintf(w, "; %d code sections\n\n", len(sections))

	for _, sec := range sections {
		fmt.Fprintf(w, "; ===== Section: %s @ 0x%x (%d bytes) =====\n",
			sec.Name, sec.Address, sec.Size)

		instructions, err := DisassembleSection(sec, parser.Arch, parser.Mode)
		if err != nil {
			fmt.Fprintf(w, "; Error disassembling: %v\n\n", err)
			continue
		}

		for _, inst := range instructions {
			// Try to find symbol name
			symName := ""
			for _, sym := range parser.Symbols {
				if sym.Value <= inst.Address && sym.Value+sym.Size > inst.Address {
					symName = parser.GetSymbolName(sym)
					break
				}
			}

			if symName != "" {
				fmt.Fprintf(w, "\n; %s:\n", symName)
			}

			// Print instruction bytes
			byteStr := ""
			for _, b := range inst.Bytes {
				byteStr += fmt.Sprintf("%02x ", b)
			}
			for len(byteStr) < 24 {
				byteStr += " "
			}

			fmt.Fprintf(w, "  %08x  %s  %-8s %s\n",
				inst.Address, byteStr, inst.Mnemonic, inst.OpStr)
		}

		fmt.Fprintln(w)
	}

	return nil
}

// RelaEntry is one Elf64_Rela relocation entry: r_offset (where the
// relocation applies - a GOT slot's address, for the JUMP_SLOT
// relocations PLT resolution cares about), r_info (packs the symbol
// table index in its upper 32 bits and the relocation type in its
// lower 32 bits), and r_addend (unused for JUMP_SLOT relocations).
type RelaEntry struct {
	Offset uint64
	Info   uint64
	Addend int64
}

// SymbolIndex returns the .dynsym index this relocation's symbol comes
// from (the upper 32 bits of Info).
func (r RelaEntry) SymbolIndex() uint32 {
	return uint32(r.Info >> 32)
}

// parseDynsym parses the .dynsym section (dynamic/import symbols,
// distinct from .symtab's locally-defined symbols) into a slice
// indexed the same way .rela.plt's relocation entries reference it -
// unlike parseSymbolTable (used for .symtab), this keeps every entry,
// including the mandatory empty entry 0 and non-function symbols,
// since RelaEntry.SymbolIndex() must be able to index directly into
// the result.
func (p *ELFParser) parseDynsym() ([]SymbolEntry, uint16, error) {
	var dynsymSec *SectionHeader
	for i := range p.Sections {
		if p.Sections[i].Type == SHT_DYNSYM {
			dynsymSec = &p.Sections[i]
			break
		}
	}
	if dynsymSec == nil {
		return nil, 0, fmt.Errorf("no .dynsym section found")
	}

	entSize := dynsymSec.EntSize
	if entSize == 0 {
		entSize = 24
	}
	count := dynsymSec.Size / entSize
	syms := make([]SymbolEntry, 0, count)

	offset := dynsymSec.Offset
	for i := uint64(0); i < count; i++ {
		if offset+entSize > uint64(len(p.Data)) {
			break
		}
		data := p.Data[offset:]
		sym := SymbolEntry{
			Name:  binary.LittleEndian.Uint32(data[0:4]),
			Info:  data[4],
			Other: data[5],
			Shndx: binary.LittleEndian.Uint16(data[6:8]),
			Value: binary.LittleEndian.Uint64(data[8:16]),
			Size:  binary.LittleEndian.Uint64(data[16:24]),
		}
		syms = append(syms, sym)
		offset += entSize
	}

	return syms, uint16(dynsymSec.Link), nil
}

// parseRelaSection parses any SHT_RELA section (.rela.plt or .rela.dyn)
// into its individual relocation entries.
func (p *ELFParser) parseRelaSection(sec SectionHeader) []RelaEntry {
	entSize := sec.EntSize
	if entSize == 0 {
		entSize = 24
	}
	count := sec.Size / entSize
	entries := make([]RelaEntry, 0, count)

	offset := sec.Offset
	for i := uint64(0); i < count; i++ {
		if offset+entSize > uint64(len(p.Data)) {
			break
		}
		data := p.Data[offset:]
		entries = append(entries, RelaEntry{
			Offset: binary.LittleEndian.Uint64(data[0:8]),
			Info:   binary.LittleEndian.Uint64(data[8:16]),
			Addend: int64(binary.LittleEndian.Uint64(data[16:24])),
		})
		offset += entSize
	}
	return entries
}

// ResolvePLT builds a map from PLT stub address to imported function
// name (e.g. 0x18d70 -> "geteuid") by cross-referencing three pieces of
// ELF metadata: .dynsym (import names), .rela.plt (which GOT slot each
// import's JUMP_SLOT relocation targets), and the .plt section's own
// machine code (disassembled to recognize each 16-byte stub's
// "adrp x16, page; ldr x17, [x16, #off]; add x16, x16, #off; br x17"
// pattern and read which GOT slot it jumps through).
//
// A caller lifting "bl <addr>" can look addr up in the returned map to
// resolve it to the real imported function's name instead of treating
// it as an unknown/internal call.
func (p *ELFParser) ResolvePLT() (map[uint64]string, error) {
	dynsyms, dynstrNdx, err := p.parseDynsym()
	if err != nil {
		return nil, err
	}
	if int(dynstrNdx) >= len(p.Sections) {
		return nil, fmt.Errorf("invalid .dynsym string table index")
	}
	dynstrSec := p.Sections[dynstrNdx]

	dynsymName := func(sym SymbolEntry) string {
		start := dynstrSec.Offset + uint64(sym.Name)
		if start >= uint64(len(p.Data)) {
			return ""
		}
		end := bytes.IndexByte(p.Data[start:], 0)
		if end < 0 {
			return ""
		}
		return string(p.Data[start : start+uint64(end)])
	}

	// Map GOT slot address -> imported function name, from .rela.plt's
	// JUMP_SLOT relocations.
	gotToName := make(map[uint64]string)
	for _, sec := range p.Sections {
		if sec.Type != SHT_RELA || p.getSectionName(sec) != ".rela.plt" {
			continue
		}
		for _, rel := range p.parseRelaSection(sec) {
			idx := rel.SymbolIndex()
			if int(idx) >= len(dynsyms) {
				continue
			}
			name := dynsymName(dynsyms[idx])
			if name != "" {
				gotToName[rel.Offset] = name
			}
		}
	}

	// Disassemble .plt itself and recognize each stub's own GOT
	// reference, mapping the stub's start address to the same name its
	// GOT slot resolved to above.
	var pltSec *SectionHeader
	for i := range p.Sections {
		if p.getSectionName(p.Sections[i]) == ".plt" {
			pltSec = &p.Sections[i]
			break
		}
	}
	if pltSec == nil {
		return gotToName, nil // no .plt - return what .rela.plt alone gave us (rare, but not an error)
	}

	d, err := NewARM64Disassembler()
	if err != nil {
		return nil, fmt.Errorf("create disassembler: %w", err)
	}
	defer d.Close()

	pltCode := p.Data[pltSec.Offset : pltSec.Offset+pltSec.Size]
	insns, err := d.DisassembleDetailed(pltCode, pltSec.Addr)
	if err != nil {
		return nil, fmt.Errorf("disassemble .plt: %w", err)
	}

	result := make(map[uint64]string)
	// Each stub is exactly 4 instructions (adrp, ldr, add, br) in the
	// standard AAPCS64 PLT stub shape this project already relies on
	// (see the ptrace PLT-stub analysis this function automates).
	for i := 0; i+3 < len(insns); i += 4 {
		adrp, ldr, br := insns[i], insns[i+1], insns[i+3]
		if adrp.Mnemonic != "adrp" || ldr.Mnemonic != "ldr" || br.Mnemonic != "br" {
			continue
		}
		if len(adrp.Operands) != 2 || adrp.Operands[1].Type != OperandImm {
			continue
		}
		if len(ldr.Operands) != 2 || ldr.Operands[1].Type != OperandMem {
			continue
		}
		page := uint64(adrp.Operands[1].Imm)
		gotAddr := page + uint64(int64(ldr.Operands[1].Mem.Disp))
		if name, ok := gotToName[gotAddr]; ok {
			result[adrp.Address] = name
		}
	}

	return result, nil
}

// ARM64 relocation types this project's GOT/data-slot resolution
// cares about (from the AArch64 ELF ABI - ordinary Elf64_Rela type
// codes, not Capstone or anything ARM64-lifter-specific).
const (
	rAARCH64_ABS64    = 257
	rAARCH64_GLOB_DAT = 1025
	rAARCH64_RELATIVE = 1027
)

// ResolveGOT builds a map from a data/GOT slot's absolute address
// (the same address a "adrp Xd, #page" + "ldr Xt, [Xd, #off]" pair
// computes and then dereferences - see arm64lift's addrRegs/liftLdr
// for the lifter side of this) to a human-readable name for whatever
// pointer is actually stored there, by reading .rela.dyn (the dynamic
// linker's relocations for ordinary data, as opposed to .rela.plt's
// function-only JUMP_SLOT entries that ResolvePLT already handles):
//
//   - R_AARCH64_RELATIVE: the slot's link-time-resolved value is
//     r_addend itself (a plain module-relative address, consistent
//     with how every other address in this package is already
//     treated as load-bias-0) - resolved to whatever named symbol (in
//     either .symtab or .dynsym) starts at exactly that address, if
//     any. This is the common case for a GOT slot holding the address
//     of some object DEFINED in this same module (e.g. a vtable, a
//     typeinfo, or - the case that matters most for readability - a
//     global object like an iostream instance that a compiler-emitted
//     alias/reference for the "same" extern symbol resolves to
//     locally).
//   - R_AARCH64_GLOB_DAT / R_AARCH64_ABS64: the slot instead refers to
//     a symbol resolved by NAME through .dynsym - typically an extern
//     global truly defined in another shared object (e.g. a
//     dynamically-linked libc++'s std::cout/std::cerr) that this
//     module only imports, so there's no local address to resolve at
//     all - only the imported symbol's own (mangled) name.
//
// Slots whose relocation type isn't one of these, or whose target
// address/symbol index doesn't resolve to any name, are simply absent
// from the result - callers should treat that the same as any other
// unresolved address (fall back to a raw numeric value).
func (p *ELFParser) ResolveGOT() (map[uint64]string, error) {
	dynsyms, dynstrNdx, err := p.parseDynsym()
	if err != nil {
		return nil, err
	}
	if int(dynstrNdx) >= len(p.Sections) {
		return nil, fmt.Errorf("invalid .dynsym string table index")
	}
	dynstrSec := p.Sections[dynstrNdx]

	dynsymName := func(sym SymbolEntry) string {
		start := dynstrSec.Offset + uint64(sym.Name)
		if start >= uint64(len(p.Data)) {
			return ""
		}
		end := bytes.IndexByte(p.Data[start:], 0)
		if end < 0 {
			return ""
		}
		return string(p.Data[start : start+uint64(end)])
	}

	// Index every named symbol (both .symtab and .dynsym - a locally
	// DEFINED object a RELATIVE relocation points at could show up in
	// either table depending on whether it's also exported) by its
	// exact address, for RELATIVE relocations to look up by target.
	byAddr := make(map[uint64]string)
	for _, sym := range p.Symbols {
		if sym.Value == 0 {
			continue
		}
		if name := p.GetSymbolName(sym); name != "" {
			byAddr[sym.Value] = name
		}
	}
	for _, sym := range dynsyms {
		if sym.Value == 0 {
			continue
		}
		if name := dynsymName(sym); name != "" {
			byAddr[sym.Value] = name
		}
	}

	result := make(map[uint64]string)
	for _, sec := range p.Sections {
		if sec.Type != SHT_RELA || p.getSectionName(sec) != ".rela.dyn" {
			continue
		}
		for _, rel := range p.parseRelaSection(sec) {
			relType := rel.Info & 0xffffffff
			switch relType {
			case rAARCH64_RELATIVE:
				if name, ok := byAddr[uint64(rel.Addend)]; ok {
					result[rel.Offset] = name
				}
			case rAARCH64_GLOB_DAT, rAARCH64_ABS64:
				idx := rel.SymbolIndex()
				if int(idx) >= len(dynsyms) {
					continue
				}
				if name := dynsymName(dynsyms[idx]); name != "" {
					result[rel.Offset] = name
				}
			}
		}
	}

	return result, nil
}

// SymbolResolver returns a single address->name lookup combining this
// ELF's own .symtab/.dynsym entries, PLT stub resolution (ResolvePLT),
// and GOT/relocation-based global-object resolution (ResolveGOT) - the
// shared oracle a caller like arm64lift.LiftFunction needs for both
// call targets (bl/blr/tail-call "b"/"br") and GOT/data-slot addresses
// an "ldr" dereferences (see arm64lift's own doc comments for why the
// same lookup serves both). PLT/GOT resolution failures are silently
// ignored here (that half of the lookup just contributes nothing) -
// callers that want to know why should call ResolvePLT/ResolveGOT
// themselves.
//
// A function symbol (STT_FUNC) with no name - real -O0 code sometimes
// emits these for hand-written assembly helpers using local rather
// than global linkage, e.g. libunwind's own low-level register-restore
// trampoline - is given a synthetic "sub_<address>" name rather than
// being silently excluded, matching how other disassemblers/
// decompilers name unnamed routines. This is what lets a tail call to
// one of these still be recognized as a genuine call instead of being
// dropped for looking unresolvable: arm64lift's own liftTailCall/
// liftBr both deliberately require a RESOLVED target (see their own
// doc comments for why - an unresolved branch is far more likely an
// intra-function control-flow edge this lifter doesn't yet understand
// than a real call), and "no name at all" would otherwise be
// indistinguishable from that.
func (p *ELFParser) SymbolResolver() func(addr uint64) (string, bool) {
	plt, _ := p.ResolvePLT()
	got, _ := p.ResolveGOT()

	const sttFunc = 2
	symByAddr := make(map[uint64]string)
	for _, sym := range p.Symbols {
		name := p.GetSymbolName(sym)
		if name == "" && sym.Info&0xf == sttFunc && sym.Value != 0 {
			name = fmt.Sprintf("sub_%x", sym.Value)
		}
		if name != "" {
			symByAddr[sym.Value] = name
		}
	}

	return func(addr uint64) (string, bool) {
		if name, ok := symByAddr[addr]; ok {
			return name, true
		}
		if name, ok := plt[addr]; ok {
			return name, true
		}
		if name, ok := got[addr]; ok {
			return name, true
		}
		return "", false
	}
}
