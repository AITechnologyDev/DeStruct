package hermes

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
)

var headerMagic = uint64(0x1F1903C103BC1FC6)

const sha1Size = 20

type Header struct {
	Magic                         uint64
	Version                       uint32
	SourceHash                    [sha1Size]byte
	FileLength                    uint32
	GlobalCodeIndex               uint32
	FunctionCount                 uint32
	StringKindCount               uint32
	IdentifierCount               uint32
	StringCount                   uint32
	OverflowStringCount           uint32
	StringStorageSize             uint32
	BigIntCount                   uint32
	BigIntStorageSize             uint32
	RegExpCount                   uint32
	RegExpStorageSize             uint32
	ArrayBufferSize               uint32
	ObjKeyBufferSize              uint32
	ObjValueBufferSize            uint32
	LiteralValueBufferSize        uint32
	ObjShapeTableCount            uint32
	NumStringSwitchImms           uint32
	CJSSegmentID                  uint32
	CJSModuleCount                uint32
	FunctionSourceCount           uint32
	DebugInfoOffset               uint32
	StaticBuiltins                bool
	CJSModulesStaticallyResolved  bool
	HasAsync                      bool
}

type SmallFunctionHeader struct {
	Offset              uint32
	ParamCount          uint32
	LoopDepth           uint32
	BytecodeSizeInBytes uint32
	FunctionName        uint32
	NumberRegCount      uint32
	NonPtrRegCount      uint32
	FrameSize           uint8
	ReadCacheSize       uint8
	WriteCacheSize      uint8
	PrivateNameCacheSize uint8
	ProhibitInvoke      uint8
	StrictMode          bool
	HasExceptionHandler bool
	HasDebugInfo        bool
	Overflowed          bool
	Kind                uint8
	// v<97 fields
	InfoOffset              uint32
	EnvironmentSize         uint8
	HighestReadCacheIndex   uint8
	HighestWriteCacheIndex  uint8

	// SmallHeaderFileOffset is the absolute file byte offset of this
	// function's 12-byte packed small header entry in the function
	// header table. Always valid, regardless of Overflowed.
	SmallHeaderFileOffset int64
	// LargeHeaderFileOffset is the absolute file byte offset of this
	// function's separately-stored large header, valid only when
	// Overflowed is true (see the "if hdr.Overflowed" branch in
	// readFunctions). A patcher that needs to update this function's
	// Offset/BytecodeSizeInBytes after changing its bytecode size must
	// write to this location instead of the small header's packed bits
	// when Overflowed is true.
	LargeHeaderFileOffset int64
}

type ExceptionHandlerInfo struct {
	Start  uint32
	End    uint32
	Target uint32
}

type DebugOffsets struct {
	SourceLocations  uint32
	ScopeDescData    uint32
	TextifiedCallees uint32
}

type StringKindEntry struct {
	Count uint32
	Kind  uint32
}

type OffsetLengthPair struct {
	Offset uint32
	Length uint32
}

type SymbolOffsetPair struct {
	SymbolID uint32
	Offset   uint32
}

type FunctionSourceEntry struct {
	FunctionID uint32
	StringID   uint32
}

type ShapeTableEntry struct {
	KeyBufferOffset uint32
	NumProps        uint32
}

type HBCFile struct {
	Header          Header
	FunctionHeaders []SmallFunctionHeader
	StringKinds     []StringKindEntry
	StringKindOf    []uint32 // per-string kind, expanded from the StringKinds RLE table (0=String, 1=Identifier, 2=Predefined)
	Strings         []string
	LiteralValues   []byte
	ObjectKeys      []byte
	ObjectValues    []byte
	ObjShapeTable   []ShapeTableEntry
	ObjectShapeKeys [][]string
	BigIntValues    []OffsetLengthPair
	BigIntData      []byte
	BigIntDecimal   []string // decoded decimal value of each BigInt entry, little-endian over [offset:offset+length]
	RegExpTable     []OffsetLengthPair
	RegExpStorage   []byte
	CJSModules      []SymbolOffsetPair
	FunctionSources []FunctionSourceEntry
	ExcHandlers     map[int][]ExceptionHandlerInfo
	DebugOffsets    map[int]DebugOffsets
	rawData         []byte
}

func ParseFile(path string) (*HBCFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(bytes.NewReader(data))
}

func Parse(r io.Reader) (*HBCFile, error) {
	f := &HBCFile{
		ExcHandlers:  make(map[int][]ExceptionHandlerInfo),
		DebugOffsets: make(map[int]DebugOffsets),
	}

	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	if len(buf) < 40 {
		return nil, fmt.Errorf("file too small")
	}

	f.rawData = buf
	br := bytes.NewReader(buf)

	// Read header
	if err := f.readHeader(br); err != nil {
		return nil, err
	}

	// Verify SHA1 footer
	if f.Header.Version >= 75 && len(buf) >= sha1Size {
		expected := buf[len(buf)-sha1Size:]
		actual := sha1.Sum(buf[:len(buf)-sha1Size])
		if !bytes.Equal(expected, actual[:]) {
			return nil, fmt.Errorf("SHA1 mismatch")
		}
	}

	// Align to 32 bytes after header (matches Python align_over_padding(32))
	alignPadding(br, 32)

	// Read function headers
	if err := f.readFunctions(br); err != nil {
		return nil, err
	}

	// Read string kinds
	if err := f.readStringKinds(br); err != nil {
		return nil, err
	}

	// Skip identifier hashes
	alignPadding(br, 4)
	skip := make([]byte, f.Header.IdentifierCount*4)
	if _, err := io.ReadFull(br, skip); err != nil {
		return nil, fmt.Errorf("skip identifier hashes: %w", err)
	}

	// Read small string table
	alignPadding(br, 4)
	smallTable := make([]byte, f.Header.StringCount*4)
	if _, err := io.ReadFull(br, smallTable); err != nil {
		return nil, fmt.Errorf("read small string table: %w", err)
	}

	// Read overflow string table
	alignPadding(br, 4)
	overflowTable := make([]byte, f.Header.OverflowStringCount*8)
	if _, err := io.ReadFull(br, overflowTable); err != nil {
		return nil, fmt.Errorf("read overflow string table: %w", err)
	}

	// Read string storage
	alignPadding(br, 4)
	stringStorage := make([]byte, f.Header.StringStorageSize)
	if _, err := io.ReadFull(br, stringStorage); err != nil {
		return nil, fmt.Errorf("read string storage: %w", err)
	}

	// Decode strings
	f.Strings = make([]string, f.Header.StringCount)
	for i := range f.Strings {
		entryOff := i * 4
		if entryOff+4 > len(smallTable) {
			f.Strings[i] = "<invalid>"
			continue
		}
		entry := binary.LittleEndian.Uint32(smallTable[entryOff:])

		// ctypes LittleEndianStructure packs bits from LSB:
		// isUTF16: bit 0 (1 bit)
		// offset: bits 1-23 (23 bits)
		// length: bits 24-31 (8 bits)
		isUTF16 := entry&1 != 0
		offset := int((entry >> 1) & 0x7FFFFF) // 23 bits
		length := int((entry >> 24) & 0xFF)    // 8 bits

		if f.Header.Version < 56 {
			// Older format: isIdentifier at bit 1, offset 22 bits
			isUTF16 = entry&1 != 0
			offset = int((entry >> 2) & 0x3FFFFF) // 22 bits
			length = int((entry >> 24) & 0xFF)    // 8 bits
		}

		if length == 0xFF {
			ovOff := offset * 8
			if ovOff+8 <= len(overflowTable) {
				ovOffset := binary.LittleEndian.Uint32(overflowTable[ovOff:])
				ovLength := binary.LittleEndian.Uint32(overflowTable[ovOff+4:])
				offset = int(ovOffset)
				length = int(ovLength)
			}
		}

		if isUTF16 {
			length *= 2
		}

		if offset+length > len(stringStorage) {
			f.Strings[i] = fmt.Sprintf("<out_of_range: off=%d len=%d storage=%d>", offset, length, len(stringStorage))
			continue
		}

		raw := stringStorage[offset : offset+length]
		if isUTF16 {
			f.Strings[i] = decodeUTF16LE(raw)
		} else {
			f.Strings[i] = string(raw)
		}
	}

	// Read literal values / arrays
	alignPadding(br, 4)
	if f.Header.Version < 97 {
		f.LiteralValues = make([]byte, f.Header.ArrayBufferSize)
		if _, err := io.ReadFull(br, f.LiteralValues); err != nil {
			return nil, fmt.Errorf("read arrays: %w", err)
		}
	} else {
		f.LiteralValues = make([]byte, f.Header.LiteralValueBufferSize)
		if _, err := io.ReadFull(br, f.LiteralValues); err != nil {
			return nil, fmt.Errorf("read literal values: %w", err)
		}
	}

	// Read object keys
	alignPadding(br, 4)
	f.ObjectKeys = make([]byte, f.Header.ObjKeyBufferSize)
	if _, err := io.ReadFull(br, f.ObjectKeys); err != nil {
		return nil, fmt.Errorf("read object keys: %w", err)
	}

	if f.Header.Version < 97 {
		// Read object values
		alignPadding(br, 4)
		f.ObjectValues = make([]byte, f.Header.ObjValueBufferSize)
		if _, err := io.ReadFull(br, f.ObjectValues); err != nil {
			return nil, fmt.Errorf("read object values: %w", err)
		}
	} else {
		// Read shape table
		alignPadding(br, 4)
		f.ObjShapeTable = make([]ShapeTableEntry, f.Header.ObjShapeTableCount)
		for i := range f.ObjShapeTable {
			if err := binary.Read(br, binary.LittleEndian, &f.ObjShapeTable[i]); err != nil {
				return nil, fmt.Errorf("read shape table: %w", err)
			}
		}
		f.ObjectShapeKeys = make([][]string, len(f.ObjShapeTable))
		for i, entry := range f.ObjShapeTable {
			start := int(entry.KeyBufferOffset)
			if start > len(f.ObjectKeys) {
				start = len(f.ObjectKeys)
			}
			arr := unpackSLPArray(f.ObjectKeys[start:], int(entry.NumProps))
			f.ObjectShapeKeys[i] = arr.ToStrings(f.Strings)
		}
	}

	// Read bigints (version >= 87)
	if f.Header.Version >= 87 {
		alignPadding(br, 4)
		f.BigIntValues = make([]OffsetLengthPair, f.Header.BigIntCount)
		for i := range f.BigIntValues {
			if err := binary.Read(br, binary.LittleEndian, &f.BigIntValues[i]); err != nil {
				return nil, fmt.Errorf("read bigint table: %w", err)
			}
		}
		alignPadding(br, 4)
		f.BigIntData = make([]byte, f.Header.BigIntStorageSize)
		if _, err := io.ReadFull(br, f.BigIntData); err != nil {
			return nil, fmt.Errorf("read bigint data: %w", err)
		}

		f.BigIntDecimal = make([]string, len(f.BigIntValues))
		for i, entry := range f.BigIntValues {
			start := int(entry.Offset)
			end := start + int(entry.Length)
			if start < 0 || end > len(f.BigIntData) || start > end {
				f.BigIntDecimal[i] = "0"
				continue
			}
			f.BigIntDecimal[i] = decodeLittleEndianUint(f.BigIntData[start:end]).String()
		}
	}

	// Read regex
	alignPadding(br, 4)
	f.RegExpTable = make([]OffsetLengthPair, f.Header.RegExpCount)
	for i := range f.RegExpTable {
		if err := binary.Read(br, binary.LittleEndian, &f.RegExpTable[i]); err != nil {
			return nil, fmt.Errorf("read regexp table: %w", err)
		}
	}
	alignPadding(br, 4)
	f.RegExpStorage = make([]byte, f.Header.RegExpStorageSize)
	if _, err := io.ReadFull(br, f.RegExpStorage); err != nil {
		return nil, fmt.Errorf("read regexp storage: %w", err)
	}

	// Read CJS modules
	alignPadding(br, 4)
	f.CJSModules = make([]SymbolOffsetPair, f.Header.CJSModuleCount)
	for i := range f.CJSModules {
		if err := binary.Read(br, binary.LittleEndian, &f.CJSModules[i]); err != nil {
			return nil, fmt.Errorf("read CJS modules: %w", err)
		}
	}

	// Read function sources (version >= 84)
	if f.Header.Version >= 84 {
		alignPadding(br, 4)
		f.FunctionSources = make([]FunctionSourceEntry, f.Header.FunctionSourceCount)
		for i := range f.FunctionSources {
			if err := binary.Read(br, binary.LittleEndian, &f.FunctionSources[i]); err != nil {
				return nil, fmt.Errorf("read function sources: %w", err)
			}
		}
	}

	return f, nil
}

// writeFunctionHeaderOffsetAndSize re-serializes FunctionHeaders[funcIdx]'s
// current Offset and BytecodeSizeInBytes back into f.rawData, at whichever
// location actually holds the authoritative values for this function:
//
//   - If Overflowed: the large header's plain 32-bit offset/
//     bytecodeSizeInBytes fields, at LargeHeaderFileOffset. The small
//     header's same-named fields are NOT touched - for an overflowed
//     function they don't hold real values at all; they're low/high
//     pointer components locating the large header (see the redirect
//     logic in readFunctions), and must stay exactly as they were, since
//     the large header's file position itself does not move when the
//     bytecode segment's size changes (only bytecode moves; the header
//     tables all physically precede it - see AssembleAndPatch's doc
//     comment).
//   - Otherwise: the small header's packed bit fields, at
//     SmallHeaderFileOffset, mirroring readFunctions' unpacking exactly
//     in reverse for this file's bytecode version.
func (f *HBCFile) writeFunctionHeaderOffsetAndSize(funcIdx int) error {
	hdr := &f.FunctionHeaders[funcIdx]

	if hdr.Overflowed {
		off := hdr.LargeHeaderFileOffset
		if off < 0 || off+8 > int64(len(f.rawData)) {
			return fmt.Errorf("large header file offset %d out of bounds", off)
		}
		// offset is always the first 4 bytes; bytecodeSizeInBytes's byte
		// position depends on version - see the "Read large header"
		// layout comment in readFunctions for the authoritative field
		// order per version.
		var sizeFieldOff int64
		if f.Header.Version >= 98 {
			sizeFieldOff = off + 12 // offset(4) paramCount(4) loopDepth(4) bytecodeSizeInBytes(4)
		} else {
			sizeFieldOff = off + 8 // offset(4) paramCount(4) bytecodeSizeInBytes(4)
		}
		if sizeFieldOff+4 > int64(len(f.rawData)) {
			return fmt.Errorf("large header bytecodeSizeInBytes field offset %d out of bounds", sizeFieldOff)
		}
		binary.LittleEndian.PutUint32(f.rawData[off:], hdr.Offset)
		binary.LittleEndian.PutUint32(f.rawData[sizeFieldOff:], hdr.BytecodeSizeInBytes)

		// The small header doesn't hold this function's real
		// Offset/BytecodeSizeInBytes when overflowed - it holds a
		// pointer to the large header just written above, split across
		// its (repurposed) offset and functionName fields:
		//   pointer = (functionName << shift) | offset
		// (shift is 24 for v>=98, 16 otherwise; see the decode in
		// readFunctions). That pointer must be updated to
		// LargeHeaderFileOffset whenever it moves, or a fresh parse
		// would keep seeking to the OLD large header location.
		shift := uint(16)
		if f.Header.Version >= 98 {
			shift = 24
		}
		ptr := hdr.LargeHeaderFileOffset
		if ptr < 0 || ptr > (int64(1)<<40) { // sanity bound, not a real format limit
			return fmt.Errorf("large header pointer %d is not representable", ptr)
		}
		ptrOffsetBits := uint32(ptr & 0x1FFFFFF) // low 25 bits, same field/width as a normal small-header Offset
		ptrHighBits := uint32(ptr >> shift)
		if f.Header.Version < 97 {
			return f.writeSmallHeaderOverflowPointerV96AndBelow(funcIdx, ptrOffsetBits, ptrHighBits)
		}
		return f.writeSmallHeaderOverflowPointer(funcIdx, ptrOffsetBits, ptrHighBits)
	}

	off := hdr.SmallHeaderFileOffset
	var rawSize int64 = 12
	if f.Header.Version < 97 {
		rawSize = 16
	}
	if off < 0 || off+rawSize > int64(len(f.rawData)) {
		return fmt.Errorf("small header file offset %d out of bounds", off)
	}
	raw := f.rawData[off : off+rawSize]

	if hdr.Offset > 0x1FFFFFF {
		return fmt.Errorf("function offset 0x%x no longer fits in the small header's 25-bit field; this file has grown too large in a way this assembler does not yet handle", hdr.Offset)
	}

	var sizeMask uint32 = 0x3FFF // v>=98: 14 bits
	if f.Header.Version < 98 {
		sizeMask = 0x7FFF // v97/v<97: 15 bits
	}
	if hdr.BytecodeSizeInBytes > sizeMask {
		return fmt.Errorf("function #%d's new bytecode size (%d bytes) no longer fits in the small header's size field (max %d); promoting a function from a small to a large (overflowed) header is not yet supported by this assembler", funcIdx, hdr.BytecodeSizeInBytes, sizeMask)
	}

	switch {
	case f.Header.Version >= 98:
		w1 := binary.LittleEndian.Uint32(raw[0:4])
		w1 = (w1 &^ 0x1FFFFFF) | (hdr.Offset & 0x1FFFFFF)
		binary.LittleEndian.PutUint32(raw[0:4], w1)

		w2 := binary.LittleEndian.Uint32(raw[4:8])
		w2 = (w2 &^ 0x3FFF) | (hdr.BytecodeSizeInBytes & 0x3FFF)
		binary.LittleEndian.PutUint32(raw[4:8], w2)

	case f.Header.Version >= 97:
		w1 := binary.LittleEndian.Uint32(raw[0:4])
		w1 = (w1 &^ 0x1FFFFFF) | (hdr.Offset & 0x1FFFFFF)
		binary.LittleEndian.PutUint32(raw[0:4], w1)

		w2 := binary.LittleEndian.Uint32(raw[4:8])
		w2 = (w2 &^ 0x7FFF) | (hdr.BytecodeSizeInBytes & 0x7FFF)
		binary.LittleEndian.PutUint32(raw[4:8], w2)

	default: // v < 97
		w1 := binary.LittleEndian.Uint32(raw[0:4])
		w1 = (w1 &^ 0x1FFFFFF) | (hdr.Offset & 0x1FFFFFF)
		binary.LittleEndian.PutUint32(raw[0:4], w1)

		w2 := binary.LittleEndian.Uint32(raw[4:8])
		w2 = (w2 &^ 0x7FFF) | (hdr.BytecodeSizeInBytes & 0x7FFF)
		binary.LittleEndian.PutUint32(raw[4:8], w2)
	}

	return nil
}

// writeSmallHeaderOverflowPointer writes an overflowed function's
// small-header pointer fields (v>=97: offset(25 bits) + functionName,
// where functionName is 8 bits for v>=98 or 17 bits for v97) so they
// encode ptrOffsetBits/ptrHighBits exactly as computed by
// writeFunctionHeaderOffsetAndSize, inverting readFunctions' decode of
// "newOffset = (functionName << shift) | offset" for the overflowed
// case.
func (f *HBCFile) writeSmallHeaderOverflowPointer(funcIdx int, ptrOffsetBits, ptrHighBits uint32) error {
	hdr := &f.FunctionHeaders[funcIdx]
	off := hdr.SmallHeaderFileOffset
	if off < 0 || off+8 > int64(len(f.rawData)) {
		return fmt.Errorf("small header file offset %d out of bounds", off)
	}
	raw := f.rawData[off : off+12]

	w1 := binary.LittleEndian.Uint32(raw[0:4])
	w1 = (w1 &^ 0x1FFFFFF) | (ptrOffsetBits & 0x1FFFFFF)
	binary.LittleEndian.PutUint32(raw[0:4], w1)

	w2 := binary.LittleEndian.Uint32(raw[4:8])
	if f.Header.Version >= 98 {
		if ptrHighBits > 0xFF {
			return fmt.Errorf("large header pointer's high bits (%d) no longer fit in the small header's 8-bit functionName field", ptrHighBits)
		}
		w2 = (w2 &^ (0xFF << 14)) | ((ptrHighBits & 0xFF) << 14)
	} else {
		if ptrHighBits > 0x1FFFF {
			return fmt.Errorf("large header pointer's high bits (%d) no longer fit in the small header's 17-bit functionName field", ptrHighBits)
		}
		w2 = (w2 &^ (0x1FFFF << 15)) | ((ptrHighBits & 0x1FFFF) << 15)
	}
	binary.LittleEndian.PutUint32(raw[4:8], w2)

	return nil
}

// writeSmallHeaderOverflowPointerV96AndBelow is the v<97 counterpart of
// writeSmallHeaderOverflowPointer: the high bits of the overflow pointer
// are repurposed from infoOffset (a 25-bit field at word 3) rather than
// functionName.
func (f *HBCFile) writeSmallHeaderOverflowPointerV96AndBelow(funcIdx int, ptrOffsetBits, ptrHighBits uint32) error {
	hdr := &f.FunctionHeaders[funcIdx]
	off := hdr.SmallHeaderFileOffset
	if off < 0 || off+12 > int64(len(f.rawData)) {
		return fmt.Errorf("small header file offset %d out of bounds", off)
	}
	raw := f.rawData[off : off+16]

	w1 := binary.LittleEndian.Uint32(raw[0:4])
	w1 = (w1 &^ 0x1FFFFFF) | (ptrOffsetBits & 0x1FFFFFF)
	binary.LittleEndian.PutUint32(raw[0:4], w1)

	if ptrHighBits > 0x1FFFFFF {
		return fmt.Errorf("large header pointer's high bits (%d) no longer fit in the small header's 25-bit infoOffset field", ptrHighBits)
	}
	w3 := binary.LittleEndian.Uint32(raw[8:12])
	w3 = (w3 &^ 0x1FFFFFF) | (ptrHighBits & 0x1FFFFFF)
	binary.LittleEndian.PutUint32(raw[8:12], w3)

	return nil
}

// writeHeaderFields re-serializes f.Header back into the start of
// f.rawData, mirroring readHeader's exact field order and version-
// conditional layout so the two never drift apart. This exists so that
// after a patch changes the bytecode segment's total size (which shifts
// where the debug-info section starts), the updated
// Header.DebugInfoOffset and Header.FileLength can be written back
// without re-deriving their version-dependent byte position by hand
// anywhere else.
//
// Only call this after mutating f.Header fields that are meant to be
// persisted; it does not touch anything past the header (function
// headers, string tables, bytecode, etc. are written directly into
// rawData by their own code paths).
func (f *HBCFile) writeHeaderFields() {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, f.Header.Magic)
	binary.Write(&buf, binary.LittleEndian, f.Header.Version)
	buf.Write(f.Header.SourceHash[:])
	binary.Write(&buf, binary.LittleEndian, f.Header.FileLength)
	binary.Write(&buf, binary.LittleEndian, f.Header.GlobalCodeIndex)
	binary.Write(&buf, binary.LittleEndian, f.Header.FunctionCount)
	binary.Write(&buf, binary.LittleEndian, f.Header.StringKindCount)
	binary.Write(&buf, binary.LittleEndian, f.Header.IdentifierCount)
	binary.Write(&buf, binary.LittleEndian, f.Header.StringCount)
	binary.Write(&buf, binary.LittleEndian, f.Header.OverflowStringCount)
	binary.Write(&buf, binary.LittleEndian, f.Header.StringStorageSize)

	if f.Header.Version >= 87 {
		binary.Write(&buf, binary.LittleEndian, f.Header.BigIntCount)
		binary.Write(&buf, binary.LittleEndian, f.Header.BigIntStorageSize)
	}

	binary.Write(&buf, binary.LittleEndian, f.Header.RegExpCount)
	binary.Write(&buf, binary.LittleEndian, f.Header.RegExpStorageSize)

	if f.Header.Version < 97 {
		binary.Write(&buf, binary.LittleEndian, f.Header.ArrayBufferSize)
		binary.Write(&buf, binary.LittleEndian, f.Header.ObjKeyBufferSize)
		binary.Write(&buf, binary.LittleEndian, f.Header.ObjValueBufferSize)
	} else {
		binary.Write(&buf, binary.LittleEndian, f.Header.LiteralValueBufferSize)
		binary.Write(&buf, binary.LittleEndian, f.Header.ObjKeyBufferSize)
		binary.Write(&buf, binary.LittleEndian, f.Header.ObjShapeTableCount)
		if f.Header.Version >= 98 {
			binary.Write(&buf, binary.LittleEndian, f.Header.NumStringSwitchImms)
		}
	}

	binary.Write(&buf, binary.LittleEndian, f.Header.CJSSegmentID)
	binary.Write(&buf, binary.LittleEndian, f.Header.CJSModuleCount)

	if f.Header.Version >= 84 {
		binary.Write(&buf, binary.LittleEndian, f.Header.FunctionSourceCount)
	}

	binary.Write(&buf, binary.LittleEndian, f.Header.DebugInfoOffset)

	var flags uint8
	if f.Header.StaticBuiltins {
		flags |= 1
	}
	if f.Header.CJSModulesStaticallyResolved {
		flags |= 2
	}
	if f.Header.HasAsync {
		flags |= 4
	}
	buf.WriteByte(flags)

	copy(f.rawData, buf.Bytes())
}

func (f *HBCFile) readHeader(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &f.Header.Magic); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	if f.Header.Magic != headerMagic {
		return fmt.Errorf("invalid magic: 0x%x (expected 0x%x)", f.Header.Magic, headerMagic)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.Version); err != nil {
		return fmt.Errorf("read version: %w", err)
	}

	if _, err := io.ReadFull(r, f.Header.SourceHash[:]); err != nil {
		return fmt.Errorf("read source hash: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.FileLength); err != nil {
		return fmt.Errorf("read file length: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.GlobalCodeIndex); err != nil {
		return fmt.Errorf("read global code index: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.FunctionCount); err != nil {
		return fmt.Errorf("read function count: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.StringKindCount); err != nil {
		return fmt.Errorf("read string kind count: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.IdentifierCount); err != nil {
		return fmt.Errorf("read identifier count: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.StringCount); err != nil {
		return fmt.Errorf("read string count: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.OverflowStringCount); err != nil {
		return fmt.Errorf("read overflow string count: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.StringStorageSize); err != nil {
		return fmt.Errorf("read string storage size: %w", err)
	}

	if f.Header.Version >= 87 {
		if err := binary.Read(r, binary.LittleEndian, &f.Header.BigIntCount); err != nil {
			return fmt.Errorf("read bigint count: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &f.Header.BigIntStorageSize); err != nil {
			return fmt.Errorf("read bigint storage size: %w", err)
		}
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.RegExpCount); err != nil {
		return fmt.Errorf("read regexp count: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.RegExpStorageSize); err != nil {
		return fmt.Errorf("read regexp storage size: %w", err)
	}

	if f.Header.Version < 97 {
		if err := binary.Read(r, binary.LittleEndian, &f.Header.ArrayBufferSize); err != nil {
			return fmt.Errorf("read array buffer size: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &f.Header.ObjKeyBufferSize); err != nil {
			return fmt.Errorf("read obj key buffer size: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &f.Header.ObjValueBufferSize); err != nil {
			return fmt.Errorf("read obj value buffer size: %w", err)
		}
	} else {
		if err := binary.Read(r, binary.LittleEndian, &f.Header.LiteralValueBufferSize); err != nil {
			return fmt.Errorf("read literal value buffer size: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &f.Header.ObjKeyBufferSize); err != nil {
			return fmt.Errorf("read obj key buffer size: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &f.Header.ObjShapeTableCount); err != nil {
			return fmt.Errorf("read obj shape table count: %w", err)
		}
		if f.Header.Version >= 98 {
			if err := binary.Read(r, binary.LittleEndian, &f.Header.NumStringSwitchImms); err != nil {
				return fmt.Errorf("read num string switch imms: %w", err)
			}
		}
	}

	if f.Header.Version < 78 {
		if err := binary.Read(r, binary.LittleEndian, &f.Header.CJSSegmentID); err != nil {
			return fmt.Errorf("read CJS module offset: %w", err)
		}
	} else {
		if err := binary.Read(r, binary.LittleEndian, &f.Header.CJSSegmentID); err != nil {
			return fmt.Errorf("read segment ID: %w", err)
		}
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.CJSModuleCount); err != nil {
		return fmt.Errorf("read CJS module count: %w", err)
	}

	if f.Header.Version >= 84 {
		if err := binary.Read(r, binary.LittleEndian, &f.Header.FunctionSourceCount); err != nil {
			return fmt.Errorf("read function source count: %w", err)
		}
	}

	if err := binary.Read(r, binary.LittleEndian, &f.Header.DebugInfoOffset); err != nil {
		return fmt.Errorf("read debug info offset: %w", err)
	}

	// Read bit flags (1 byte total: 3 bits used)
	var flags uint8
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return fmt.Errorf("read flags: %w", err)
	}
	f.Header.StaticBuiltins = flags&1 != 0
	f.Header.CJSModulesStaticallyResolved = flags&2 != 0
	f.Header.HasAsync = flags&4 != 0

	return nil
}

func (f *HBCFile) readFunctions(r io.Reader) error {
	f.FunctionHeaders = make([]SmallFunctionHeader, f.Header.FunctionCount)

	for i := uint32(0); i < f.Header.FunctionCount; i++ {
		var hdr SmallFunctionHeader

		// Read raw bytes for bit-field parsing
		// v>=98: 12 bytes, v>=97: 12 bytes, v<97: 16 bytes
		var rawSize int
		if f.Header.Version >= 97 {
			rawSize = 12
		} else {
			rawSize = 16
		}
		raw := make([]byte, rawSize)
		br := r.(*bytes.Reader)
		smallHeaderFileOffset := br.Size() - int64(br.Len())
		if _, err := io.ReadFull(r, raw); err != nil {
			return fmt.Errorf("read function header %d: %w", i, err)
		}
		hdr.SmallHeaderFileOffset = smallHeaderFileOffset

		// Save current position AFTER reading the small header (before_pos in Python)
		beforePos := br.Size() - int64(br.Len())

		if f.Header.Version >= 98 {
			// Word 1: offset(25) + paramCount(5) + loopDepth(2)
			w1 := binary.LittleEndian.Uint32(raw[0:4])
			hdr.Offset = w1 & 0x1FFFFFF        // 25 bits
			hdr.ParamCount = (w1 >> 25) & 0x1F // 5 bits
			hdr.LoopDepth = (w1 >> 30) & 0x3   // 2 bits

			// Word 2: bytecodeSizeInBytes(14) + functionName(8) + numberRegCount(5) + nonPtrRegCount(5)
			w2 := binary.LittleEndian.Uint32(raw[4:8])
			hdr.BytecodeSizeInBytes = w2 & 0x3FFF       // 14 bits
			hdr.FunctionName = (w2 >> 14) & 0xFF        // 8 bits
			hdr.NumberRegCount = (w2 >> 22) & 0x1F      // 5 bits
			hdr.NonPtrRegCount = (w2 >> 27) & 0x1F      // 5 bits

			hdr.FrameSize = raw[8]
			hdr.ReadCacheSize = raw[9]
			hdr.WriteCacheSize = raw[10] & 0x7F         // 7 bits
			hdr.PrivateNameCacheSize = (raw[10] >> 7) & 1 // 1 bit

			// Flags byte
			flags := raw[11]
			hdr.ProhibitInvoke = flags & 0x3
			hdr.StrictMode = flags&0x4 != 0
			hdr.HasExceptionHandler = flags&0x8 != 0
			hdr.HasDebugInfo = flags&0x10 != 0
			hdr.Overflowed = flags&0x20 != 0
			hdr.Kind = (flags >> 6) & 0x3
		} else if f.Header.Version >= 97 {
			// Word 1: offset(25) + paramCount(7)
			w1 := binary.LittleEndian.Uint32(raw[0:4])
			hdr.Offset = w1 & 0x1FFFFFF
			hdr.ParamCount = (w1 >> 25) & 0x7F

			// Word 2: bytecodeSizeInBytes(15) + functionName(17)
			w2 := binary.LittleEndian.Uint32(raw[4:8])
			hdr.BytecodeSizeInBytes = w2 & 0x7FFF
			hdr.FunctionName = (w2 >> 15) & 0x1FFFF

			hdr.FrameSize = raw[8]
			hdr.ReadCacheSize = raw[9]
			hdr.WriteCacheSize = raw[10] & 0x7F
			hdr.PrivateNameCacheSize = (raw[10] >> 7) & 1

			flags := raw[11]
			hdr.ProhibitInvoke = flags & 0x3
			hdr.StrictMode = flags&0x4 != 0
			hdr.HasExceptionHandler = flags&0x8 != 0
			hdr.HasDebugInfo = flags&0x10 != 0
			hdr.Overflowed = flags&0x20 != 0
			hdr.Kind = (flags >> 6) & 0x3
		} else {
			// v < 97
			// Word 1: offset(25) + paramCount(7)
			w1 := binary.LittleEndian.Uint32(raw[0:4])
			hdr.Offset = w1 & 0x1FFFFFF
			hdr.ParamCount = (w1 >> 25) & 0x7F

			// Word 2: bytecodeSizeInBytes(15) + functionName(17)
			w2 := binary.LittleEndian.Uint32(raw[4:8])
			hdr.BytecodeSizeInBytes = w2 & 0x7FFF
			hdr.FunctionName = (w2 >> 15) & 0x1FFFF

			// Word 3: infoOffset(25) + frameSize(7)
			w3 := binary.LittleEndian.Uint32(raw[8:12])
			hdr.InfoOffset = w3 & 0x1FFFFFF
			hdr.FrameSize = uint8((w3 >> 25) & 0x7F)

			hdr.EnvironmentSize = raw[12]
			hdr.HighestReadCacheIndex = raw[13]
			hdr.HighestWriteCacheIndex = raw[14]

			flags := raw[15]
			hdr.ProhibitInvoke = flags & 0x3
			hdr.StrictMode = flags&0x4 != 0
			hdr.HasExceptionHandler = flags&0x8 != 0
			hdr.HasDebugInfo = flags&0x10 != 0
			hdr.Overflowed = flags&0x20 != 0
			hdr.Kind = (flags >> 6) & 0x3
		}

		// If overflowed, seek to large header position
		if hdr.Overflowed {
			var newOffset int64
			if f.Header.Version < 97 {
				newOffset = int64(hdr.InfoOffset) << 16
			} else if f.Header.Version >= 98 {
				newOffset = int64(hdr.FunctionName) << 24
			} else {
				newOffset = int64(hdr.FunctionName) << 16
			}
			newOffset |= int64(hdr.Offset)

			br.Seek(newOffset, io.SeekStart)
			hdr.LargeHeaderFileOffset = newOffset

			// NOTE: below, hdr.Overflowed is deliberately never
			// reassigned from the large header's own flags byte. The
			// small header's overflowed bit (already true, or this
			// branch wouldn't run) is what decided to come here in the
			// first place; hermes-dec's Python reference likewise only
			// ever checks it once, on the small header, and never
			// re-reads it from the large one. Reusing that same flags-
			// byte bit position on the large header here does not carry
			// the same meaning and was overwriting a correct `true`
			// with a spurious `false` for every overflowed function -
			// harmless for read-only disassembly (nothing else reads
			// Overflowed), but wrong for anything that needs to know
			// whether to patch this function's Offset/BytecodeSizeInBytes
			// into the small header's packed bits or the large header's
			// plain fields.

			// Read large header.
			// v>=98 layout (36 bytes): offset(4) paramCount(4) loopDepth(4)
			//   bytecodeSizeInBytes(4) functionName(4) numberRegCount(4)
			//   nonPtrRegCount(4) frameSize(4) readCacheSize(1)
			//   writeCacheSize(1) privateNameCacheSize(1) flags(1)
			// v97 layout (23 bytes): offset(4) paramCount(4)
			//   bytecodeSizeInBytes(4) functionName(4) frameSize(4)
			//   highestReadCacheIndex(1) highestWriteCacheIndex(1) flags(1)
			// v<97 layout (31 bytes): offset(4) paramCount(4)
			//   bytecodeSizeInBytes(4) functionName(4) infoOffset(4)
			//   frameSize(4) environmentSize(4) highestReadCacheIndex(1)
			//   highestWriteCacheIndex(1) flags(1)
			// (ctypes uses _pack_=True with no padding, so these sizes are exact.)
			var largeSize int
			switch {
			case f.Header.Version >= 98:
				largeSize = 36
			case f.Header.Version >= 97:
				largeSize = 23
			default:
				largeSize = 31
			}
			largeRaw := make([]byte, largeSize)
			if _, err := io.ReadFull(r, largeRaw); err != nil {
				return fmt.Errorf("read large function header %d: %w", i, err)
			}

			// Parse large header
			hdr.Offset = binary.LittleEndian.Uint32(largeRaw[0:4])
			hdr.ParamCount = binary.LittleEndian.Uint32(largeRaw[4:8])
			if f.Header.Version >= 98 {
				hdr.LoopDepth = binary.LittleEndian.Uint32(largeRaw[8:12])
				hdr.BytecodeSizeInBytes = binary.LittleEndian.Uint32(largeRaw[12:16])
				hdr.FunctionName = binary.LittleEndian.Uint32(largeRaw[16:20])
				hdr.NumberRegCount = binary.LittleEndian.Uint32(largeRaw[20:24])
				hdr.NonPtrRegCount = binary.LittleEndian.Uint32(largeRaw[24:28])
				hdr.FrameSize = uint8(binary.LittleEndian.Uint32(largeRaw[28:32]) & 0xFF)
				hdr.ReadCacheSize = largeRaw[32]
				hdr.WriteCacheSize = largeRaw[33]
				hdr.PrivateNameCacheSize = largeRaw[34]
				flags := largeRaw[35]
				hdr.ProhibitInvoke = flags & 0x3
				hdr.StrictMode = flags&0x4 != 0
				hdr.HasExceptionHandler = flags&0x8 != 0
				hdr.HasDebugInfo = flags&0x10 != 0
				// NOTE: intentionally not touching hdr.Overflowed here -
				// see the comment on this whole if-block above.
				hdr.Kind = (flags >> 6) & 0x3
			} else if f.Header.Version >= 97 {
				hdr.BytecodeSizeInBytes = binary.LittleEndian.Uint32(largeRaw[8:12])
				hdr.FunctionName = binary.LittleEndian.Uint32(largeRaw[12:16])
				hdr.FrameSize = uint8(binary.LittleEndian.Uint32(largeRaw[16:20]) & 0xFF)
				hdr.HighestReadCacheIndex = largeRaw[20]
				hdr.HighestWriteCacheIndex = largeRaw[21]
				flags := largeRaw[22]
				hdr.ProhibitInvoke = flags & 0x3
				hdr.StrictMode = flags&0x4 != 0
				hdr.HasExceptionHandler = flags&0x8 != 0
				hdr.HasDebugInfo = flags&0x10 != 0
				hdr.Kind = (flags >> 6) & 0x3
			} else {
				hdr.BytecodeSizeInBytes = binary.LittleEndian.Uint32(largeRaw[8:12])
				hdr.FunctionName = binary.LittleEndian.Uint32(largeRaw[12:16])
				hdr.InfoOffset = binary.LittleEndian.Uint32(largeRaw[16:20])
				hdr.FrameSize = uint8(binary.LittleEndian.Uint32(largeRaw[20:24]) & 0x7F)
				hdr.EnvironmentSize = uint8(binary.LittleEndian.Uint32(largeRaw[24:28]) & 0xFF)
				hdr.HighestReadCacheIndex = largeRaw[28]
				hdr.HighestWriteCacheIndex = largeRaw[29]
				flags := largeRaw[30]
				hdr.ProhibitInvoke = flags & 0x3
				hdr.StrictMode = flags&0x4 != 0
				hdr.HasExceptionHandler = flags&0x8 != 0
				hdr.HasDebugInfo = flags&0x10 != 0
				hdr.Kind = (flags >> 6) & 0x3
			}
		} else if f.Header.Version < 97 {
			// Non-overflowed v<97 function: the small header only carries
			// an infoOffset pointer: seek there before reading exception
			// handler / debug info data, exactly as hbc_file_parser.py's
			// "elif self.header.version < 97: self.file_buffer.seek(...)".
			br.Seek(int64(hdr.InfoOffset), io.SeekStart)
		}

		f.FunctionHeaders[i] = hdr

		// Read exception handlers from current position (after large header if overflowed)
		if hdr.HasExceptionHandler {
			alignPadding(r, 4)
			var count uint32
			if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
				return fmt.Errorf("read exc handler count for func %d: %w", i, err)
			}
			handlers := make([]ExceptionHandlerInfo, count)
			for j := range handlers {
				if err := binary.Read(r, binary.LittleEndian, &handlers[j]); err != nil {
					return fmt.Errorf("read exc handler %d for func %d: %w", j, i, err)
				}
			}
			f.ExcHandlers[int(i)] = handlers
		}

		// Read debug info from current position
		if hdr.HasDebugInfo {
			alignPadding(r, 4)
			var dbg DebugOffsets
			if err := binary.Read(r, binary.LittleEndian, &dbg); err != nil {
				return fmt.Errorf("read debug offsets for func %d: %w", i, err)
			}
			f.DebugOffsets[int(i)] = dbg
		}

		// Seek back to before_pos (Python does this!)
		br.Seek(beforePos, io.SeekStart)
	}

	return nil
}

func (f *HBCFile) readStringKinds(r io.Reader) error {
	alignPadding(r, 4)
	f.StringKinds = make([]StringKindEntry, f.Header.StringKindCount)
	for i := range f.StringKinds {
		var raw uint32
		if err := binary.Read(r, binary.LittleEndian, &raw); err != nil {
			return fmt.Errorf("read string kind %d: %w", i, err)
		}
		// v>=71: count(31 bits) + kind(1 bit); v<71: count(30 bits) + kind(2 bits)
		if f.Header.Version >= 71 {
			f.StringKinds[i].Count = raw & 0x7FFFFFFF
			f.StringKinds[i].Kind = (raw >> 31) & 1
		} else {
			f.StringKinds[i].Count = raw & 0x3FFFFFFF
			f.StringKinds[i].Kind = (raw >> 30) & 3
		}
		for c := uint32(0); c < f.StringKinds[i].Count; c++ {
			f.StringKindOf = append(f.StringKindOf, f.StringKinds[i].Kind)
		}
	}
	return nil
}

func (f *HBCFile) getCode(funcIdx int) []byte {
	if funcIdx >= len(f.FunctionHeaders) {
		return nil
	}
	hdr := f.FunctionHeaders[funcIdx]
	offset := int(hdr.Offset)
	size := int(hdr.BytecodeSizeInBytes)
	if offset+size > len(f.rawData) {
		return nil
	}
	return f.rawData[offset : offset+size]
}

// SetCode replaces the bytecode for a function
func (f *HBCFile) SetCode(funcIdx int, newCode []byte) {
	if funcIdx >= len(f.FunctionHeaders) {
		return
	}
	hdr := &f.FunctionHeaders[funcIdx]
	offset := int(hdr.Offset)
	size := int(hdr.BytecodeSizeInBytes)

	// Replace in rawData
	newData := make([]byte, len(f.rawData)-size+len(newCode))
	copy(newData, f.rawData[:offset])
	copy(newData[offset:], newCode)
	copy(newData[offset+len(newCode):], f.rawData[offset+size:])

	f.rawData = newData

	// Update all function offsets after this one
	for i := funcIdx + 1; i < len(f.FunctionHeaders); i++ {
		f.FunctionHeaders[i].Offset += uint32(len(newCode) - size)
	}
}

// Write writes the HBC file to disk with recalculated SHA1
func (f *HBCFile) Write(path string) error {
	// SHA1 is at the end of the file
	if f.Header.Version >= 75 && len(f.rawData) >= sha1Size {
		dataWithoutHash := f.rawData[:len(f.rawData)-sha1Size]
		hash := sha1.Sum(dataWithoutHash)
		copy(f.rawData[len(f.rawData)-sha1Size:], hash[:])
	}

	return os.WriteFile(path, f.rawData, 0644)
}

// decodeLittleEndianUint decodes a little-endian byte slice as an unsigned
// arbitrary-precision integer, matching Python's int.from_bytes(data, 'little').
func decodeLittleEndianUint(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i, v := range b {
		be[len(b)-1-i] = v
	}
	return new(big.Int).SetBytes(be)
}

// decodeUTF16LE decodes Hermes's UTF-16LE-encoded string bytes exactly the
// way the real hermes-dec does: hermes-dec calls Python's generic 'utf-16'
// codec (not 'utf-16-le') with errors='surrogatepass', which:
//  1. inspects the first code unit for a byte-order mark and, if found,
//     both consumes it as a marker (not content) and uses it to decide
//     the byte order for the rest of the string - 0xFEFF (bytes FF FE in
//     what Hermes actually stores, little-endian) means "this data is
//     little-endian, and the marker itself is not part of the string",
//     while 0xFFFE means "the rest of this string is actually
//     big-endian". Absent either marker, defaults to little-endian, since
//     that's what Hermes always stores.
//  2. combines UTF-16 surrogate pairs (a high surrogate 0xD800-0xDBFF
//     followed by a low surrogate 0xDC00-0xDFFF) into the single code
//     point beyond the Basic Multilingual Plane they encode, rather than
//     treating each half as an independent (invalid on its own) code
//     point.
//  3. passes through any unpaired/lone surrogate as its own code point
//     rather than failing (that's what surrogatepass permits) - Go's
//     string/rune machinery accepts this the same way CPython's str does.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return string(b)
	}
	n := len(b) / 2
	if n == 0 {
		return ""
	}

	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	start := 0
	bigEndian := false
	switch units[0] {
	case 0xFEFF: // little-endian BOM: consume it, stay little-endian
		start = 1
	case 0xFFFE: // byte-swapped BOM: consume it, switch to big-endian
		start = 1
		bigEndian = true
	}

	if bigEndian {
		// Re-derive every remaining unit from the original bytes with
		// the opposite byte order.
		for i := start; i < n; i++ {
			lo := b[i*2]
			hi := b[i*2+1]
			units[i] = uint16(lo)<<8 | uint16(hi)
		}
	}

	var runes []rune
	for i := start; i < n; i++ {
		u := units[i]
		if u >= 0xD800 && u <= 0xDBFF && i+1 < n {
			next := units[i+1]
			if next >= 0xDC00 && next <= 0xDFFF {
				r := 0x10000 + (rune(u)-0xD800)<<10 + (rune(next) - 0xDC00)
				runes = append(runes, r)
				i++
				continue
			}
		}
		// Lone surrogate (or any other unit): pass through as its own
		// code point, matching errors='surrogatepass'.
		runes = append(runes, rune(u))
	}

	return string(runes)
}

func alignPadding(r io.Reader, alignment uint32) {
	if br, ok := r.(*bytes.Reader); ok {
		pos := br.Size() - int64(br.Len())
		mod := uint64(pos) % uint64(alignment)
		if mod != 0 {
			padding := make([]byte, uint64(alignment)-mod)
			br.Read(padding)
		}
	}
}
