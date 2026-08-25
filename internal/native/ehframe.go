package native

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// DiscoveredFunction is one function boundary found without relying on
// any symbol table at all - see DiscoverFunctions' own doc comment.
type DiscoveredFunction struct {
	Addr uint64
	Size uint64
}

// DW_EH_PE_* encoding bytes (DWARF/LSB "exception header encoding") -
// only the handful this file's own decoder actually needs, not the
// full set.
const (
	dwEhPeAbsptr  = 0x00
	dwEhPePcrel   = 0x10
	dwEhPeDatarel = 0x30

	dwEhPeUdata4 = 0x03
	dwEhPeSdata4 = 0x0b
	dwEhPeOmit   = 0xff
)

// DiscoverFunctions finds function START addresses via .eh_frame_hdr's
// own binary search table - present in essentially every real AArch64
// Android/Linux binary (the ABI requires unwind tables for both C and
// C++ code), and never strippable the way .symtab/.dynsym symbol NAMES
// are, since the unwinder itself needs this table at runtime
// regardless of whether the binary has any symbols left at all. Each
// entry there is one DWARF CFI FDE's own "initial location" - which
// for ordinary compiler output is exactly one real function's first
// instruction, one entry per function - so this recovers real function
// BOUNDARIES (not names) even for a fully stripped executable with
// zero usable entries in either .symtab or .dynsym (see
// ELFParser.SymbolResolver's own dynsym fallback, which doesn't help
// at all when .dynsym is ALSO empty of defined functions, e.g. a
// stripped executable rather than a shared library).
//
// Sizes are inferred as the gap to the next entry's own start address
// (the table is guaranteed sorted by address - it's a BINARY SEARCH
// table), with the last entry bounded by .text's own end. Not exact
// (may include a few bytes of inter-function alignment padding), but
// harmless: a handful of extra trailing NOPs/unreachable bytes don't
// change what the real function's own instructions decompile to.
//
// Only the common (and by far most prevalent for AArch64 Android/Linux
// toolchains) encoding combination is supported: eh_frame_ptr as
// PC-relative sdata4, fde_count as absolute udata4, and the search
// table itself as section-relative ("datarel") sdata4 pairs - anything
// else returns an error rather than risk misreading unfamiliar encoded
// pointer bytes as addresses.
func (p *ELFParser) DiscoverFunctions() ([]DiscoveredFunction, error) {
	var hdrSec, textSec *SectionHeader
	for i := range p.Sections {
		switch p.getSectionName(p.Sections[i]) {
		case ".eh_frame_hdr":
			hdrSec = &p.Sections[i]
		case ".text":
			textSec = &p.Sections[i]
		}
	}
	if hdrSec == nil {
		return nil, fmt.Errorf("no .eh_frame_hdr section")
	}
	if hdrSec.Offset+4 > uint64(len(p.Data)) {
		return nil, fmt.Errorf(".eh_frame_hdr truncated")
	}

	data := p.Data
	pos := hdrSec.Offset
	vaddr := func(filePos uint64) uint64 { return hdrSec.Addr + (filePos - hdrSec.Offset) }

	if data[pos] != 1 {
		return nil, fmt.Errorf("unsupported .eh_frame_hdr version %d", data[pos])
	}
	ehFramePtrEnc := data[pos+1]
	fdeCountEnc := data[pos+2]
	tableEnc := data[pos+3]
	pos += 4

	// eh_frame_ptr itself isn't needed for function discovery - decoded
	// only to correctly skip past it to the fde_count field.
	_, n, err := readEncodedPtr(data, pos, ehFramePtrEnc, vaddr(pos), hdrSec.Addr)
	if err != nil {
		return nil, fmt.Errorf("decoding eh_frame_ptr: %w", err)
	}
	pos += uint64(n)

	fdeCount, n, err := readEncodedPtr(data, pos, fdeCountEnc, vaddr(pos), hdrSec.Addr)
	if err != nil {
		return nil, fmt.Errorf("decoding fde_count: %w", err)
	}
	pos += uint64(n)

	addrs := make([]uint64, 0, fdeCount)
	for i := uint64(0); i < fdeCount; i++ {
		addr, n, err := readEncodedPtr(data, pos, tableEnc, vaddr(pos), hdrSec.Addr)
		if err != nil {
			return nil, fmt.Errorf("decoding table entry %d (initial_location): %w", i, err)
		}
		pos += uint64(n)
		// Skip the FDE pointer itself (the second value of the pair) -
		// only the function's own start address is needed here.
		_, n, err = readEncodedPtr(data, pos, tableEnc, vaddr(pos), hdrSec.Addr)
		if err != nil {
			return nil, fmt.Errorf("decoding table entry %d (fde ptr): %w", i, err)
		}
		pos += uint64(n)
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf(".eh_frame_hdr table is empty")
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	var textEnd uint64
	if textSec != nil {
		textEnd = textSec.Addr + textSec.Size
	}

	result := make([]DiscoveredFunction, 0, len(addrs))
	for i, a := range addrs {
		var size uint64
		switch {
		case i+1 < len(addrs):
			size = addrs[i+1] - a
		case textEnd > a:
			size = textEnd - a
		default:
			continue // can't bound the very last entry's size at all
		}
		if size == 0 {
			continue
		}
		result = append(result, DiscoveredFunction{Addr: a, Size: size})
	}
	return result, nil
}

// readEncodedPtr reads one DW_EH_PE-encoded value from data at byte
// offset pos, returning the resolved ABSOLUTE address and how many
// bytes were consumed. fieldVAddr is this field's OWN virtual address
// (needed to resolve a PC-relative encoding); sectionBase is the
// enclosing section's own virtual address (needed to resolve a
// section-relative "datarel" encoding). Only the udata4/sdata4 value
// formats and absptr/pcrel/datarel applications are supported - the
// only combinations DiscoverFunctions' own callers need (see its doc
// comment on why that's a deliberate, real-world-validated scope
// rather than a full generic DWARF encoding decoder).
func readEncodedPtr(data []byte, pos uint64, enc byte, fieldVAddr, sectionBase uint64) (uint64, int, error) {
	if enc == dwEhPeOmit {
		return 0, 0, fmt.Errorf("DW_EH_PE_omit: no value present")
	}
	if pos+4 > uint64(len(data)) {
		return 0, 0, fmt.Errorf("encoded pointer out of bounds")
	}
	format := enc & 0x0f
	application := enc & 0x70

	raw := binary.LittleEndian.Uint32(data[pos : pos+4])
	var val uint64
	switch format {
	case dwEhPeUdata4:
		val = uint64(raw)
	case dwEhPeSdata4:
		// Sign-extend through int32/int64, then reinterpret as uint64 -
		// the modular-arithmetic addition below then correctly adds a
		// negative offset without needing separate signed/unsigned
		// paths.
		val = uint64(int64(int32(raw)))
	default:
		return 0, 0, fmt.Errorf("unsupported DW_EH_PE value format 0x%x", format)
	}

	var abs uint64
	switch application {
	case dwEhPeAbsptr:
		abs = val
	case dwEhPePcrel:
		abs = fieldVAddr + val
	case dwEhPeDatarel:
		abs = sectionBase + val
	default:
		return 0, 0, fmt.Errorf("unsupported DW_EH_PE application 0x%x", application)
	}
	return abs, 4, nil
}
