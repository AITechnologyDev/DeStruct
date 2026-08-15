# unflutter

Static analyzer for Flutter/Dart AOT snapshots. Recovers function names, class hierarchies, call graphs, and behavioral signals from `libapp.so`, without embedding or executing the Dart VM.

## Why Not Blutter

[Blutter](https://github.com/aspect-sec/blutter) solves Flutter reverse engineering by embedding the Dart VM itself. It calls `Dart_Initialize`, creates an isolate group from the snapshot, and walks the deserialized heap with internal VM APIs. No Dart code from the snapshot is executed. The VM is used purely for introspection. But this still means Blutter must compile a matching Dart SDK for every target version and link against VM internals.

unflutter takes a different path. No VM. No SDK compilation. The snapshot is a byte stream with a known grammar. We parse it directly.

The tradeoff: Blutter gets perfect fidelity because it deserializes through the VM's own code paths. unflutter gets portability, speed, and the ability to analyze snapshots from any Dart version without building anything version-specific. The cost is that every format change across Dart versions must be handled explicitly in our parser. There is no runtime to fall back on.

## Design

Constraint elimination. We treat the snapshot as a deterministic binary grammar.

```
Omega = all possible interpretations of the byte stream

C = {
  ELF invariants,
  snapshot magic (0xf5f5dcdc),
  version hash (32-byte ASCII),
  CID table (class ID -> cluster handler),
  cluster grammar (alloc counts, fill encoding),
  instruction layout (stubs + code regions)
}

R = Omega reduced by C
```

Each constraint narrows the space. ELF validation eliminates non-ARM64 binaries. The snapshot magic eliminates non-Dart data. The version hash selects exactly one CID table and tag encoding. Cluster alloc counts fix the object population. Fill parsing recovers field values within that fixed population. What survives all constraints is the analysis result.

```
if |R| == 0  → HALT: overconstrained (bug in our model)
if |R| > 1   → HALT: underdetermined (missing constraint)
if |R| == 1  → COMMIT: the answer
```

No heuristics. No runtime fallback. No inference outside constraints.

## How It Works

### Snapshot reconstruction

Dart AOT snapshot = two-phase serialization: **alloc** then **fill**.

**Alloc** walks clusters in CID order. Each cluster declares how many objects of that class exist. This assigns sequential reference IDs to every object. No data is read yet, just counts.

**Fill** walks the same clusters again. This time it reads the actual field values: string bytes, reference IDs pointing to other objects, integer scalars. The fill encoding varies by object type and Dart version.

We replay both phases from raw bytes. The alloc phase gives us the object census. The fill phase gives us names, strings, and cross-references. Combined with the instructions table (which maps code objects to their machine code offsets), we recover the full function-name-to-address mapping that Blutter gets from the VM API.

### Code recovery

The isolate instructions image contains two regions:

**Stubs** (indices 0 through `FirstEntryWithCode-1`): runtime trampolines (type-check handlers, allocation stubs, dispatch helpers) placed before user code.

**Code** (indices `FirstEntryWithCode` onward): user functions and framework code. Each Code object maps to a PC offset via the instructions table.

We resolve both regions, producing a complete function map that covers the entire executable range.

### ARM64 disassembly and call edges

Each function's code bytes are decoded instruction-by-instruction using `arm64asm.Decode`. Branch detection handles B, B.cond, CBZ, CBNZ, TBZ, TBNZ, RET, all from raw 32-bit encodings.

**CFG construction** follows a 3-phase algorithm:
1. Collect block leaders: instruction 0, branch targets, instructions after terminators
2. Sort and partition into basic blocks
3. Walk blocks, compute successor edges from terminal instructions

**Call edge extraction** distinguishes two kinds:

- **BL (direct call)**: decode target address from imm26 field, resolve to function name via symbol map
- **BLR (indirect call)**: resolve target register provenance via `RegTracker` (sliding window W=8)

The register tracker traces how BLR target registers get their values:

| Provenance | Pattern | Description |
|------------|---------|-------------|
| PP (object pool) | `LDR Xt, [X27, #imm]` | X27 is the pool pointer. Pool index = byte_offset / 8 |
| THR (thread) | `LDR Xt, [X26, #imm]` | X26 is the thread pointer. Resolved via version-specific offset maps |
| Peephole PP | `ADD Xd, X27, #hi; LDR Xt, [Xd, #lo]` | Two-instruction PP for large pool indices |
| Dispatch table | `LDR Xn, [X21, Xm, LSL #3]` | X21 is the dispatch table register |

Each BLR gets annotated with its provenance (e.g., `PP[42] Widget.build`, `THR.AllocateArray_ep`, `dispatch_table`).

### Graph construction

Call edges and CFGs are converted to [lattice](https://github.com/zboralski/lattice) types, an architecture-neutral graph IR shared with SpiderMonkey-dumper (for JS bytecode analysis). The lattice library provides DOT rendering.

### Decompilation (Ghidra + IDA)

Both decompilers share a common metadata pipeline. `flutter-meta` generates `flutter_meta.json` with function names, class struct layouts, THR fields, string references, and pointer size metadata. Each decompiler's script consumes this file.

**Ghidra** (`unflutter decompile`) runs a headless pipeline:

1. Pre-script registers a `__dartcall` calling convention via `SpecExtension` (marks X15/X26-X28 as unaffected, kills scratch registers)
2. Post-script applies all metadata:
   - Disassembles at all known function addresses
   - Creates/renames functions
   - Creates Dart class struct types with correct field sizes (4-byte for compressed pointers, 8-byte otherwise)
   - Creates a `DartThread` struct (200 fields) for THR (X26) accesses
   - Applies typed function signatures (`this` pointer, parameter count, return type)
   - Sets EOL comments for THR fields, PP pool references, and string literals
   - **Register retyping**: renames decompiler variables for Dart-specific registers and types X26 as `DartThread*`, enabling struct field resolution:

| Register | Variable | Purpose |
| -------- | ------------------- | ----------------------------------------------- |
| X15      | `SHADOW_SP`         | Dart shadow call stack                          |
| X21      | `DT`                | Dispatch table pointer                          |
| X22      | `DART_NULL`         | Dart null object                                |
| X26      | `THR` (DartThread*) | Thread pointer, field accesses resolve to names |
| X27      | `PP`                | Object pool pointer                             |
| X28      | `HEAP_BASE`         | Compressed pointer base                         |
| X29      | `FP`                | Frame pointer                                   |
| X30      | `LR`                | Link register                                   |

**IDA** (`unflutter ida`) runs via idalib (headless):

1. Generates C header with all struct types, parsed via `idc_parse_types()` in one shot
2. Creates functions with Dart checked/unchecked entry point splitting (splits IDA-merged functions at metadata addresses)
3. Applies function signatures via `apply_type()` (IL2CppDumper pattern)
4. Sets repeatable comments (visible in Hex-Rays decompiler)
5. Hex-Rays register retyping (same register table as Ghidra)

**Ghidra vs IDA output quality:**

Ghidra wins on readability: struct field resolution (`THR->stack_limit` vs `THR + 72`), indexed access (`SHADOW_SP[-2]` vs `*(_QWORD*)(SHADOW_SP - 16)`), and no `_QWORD`/`_DWORD` casts.

IDA wins on type cleanliness: zero `undefined` types, zero `unaff_` register names, zero warnings. IDA uses `__int64` and `_QWORD` casts which are verbose but type-correct.

The THR struct field resolution gap is a Hex-Rays microcode limitation. `set_lvar_type()` doesn't restructure the decompiler's AST to use struct member syntax.

### Version handling

| Dart | Tag Style | Pointers | Key change |
|------|-----------|----------|------------|
| 2.10.0 | CID-Int32 | Uncompressed | 4 header fields, pre-canonical-split |
| 2.13.0 | CID-Int32 | Uncompressed | 5 header fields, split canonical |
| 2.14.0 | CID-Shift1 | Uncompressed | CID shifted into uint64 tag |
| 2.15.0 | CID-Shift1 | Uncompressed | NativePointer CID inserted |
| 2.16.0 | CID-Shift1 | Uncompressed | ConstMap/ConstSet added |
| 2.17.6 | CID-Shift1 | Uncompressed | Last unsigned-ref version |
| 2.18.0 | CID-Shift1 | Compressed | Signed refs, compressed pointers |
| 2.19.0 | CID-Shift1 | Compressed | 64-byte alignment |
| 3.0.5-3.3.0 | CID-Shift1 | Compressed | Progressive CID table changes |
| 3.4.3-3.10.7 | ObjectHeader | Compressed | New tag encoding, record types |

No version-conditional architecture. The version hash selects a constraint set. Same pipeline runs.

## Build and Install

Requires Go 1.24+. One external dependency: `golang.org/x/arch` (ARM64 instruction decoding).

```bash
make build          # build ./unflutter binary
make install        # install binary to /usr/local/bin, scripts to ~/.unflutter/
make test           # run tests
```

Ghidra integration requires Ghidra 11.x with Jython support. Auto-detected from `GHIDRA_HOME`, `PATH`, or common brew locations.

## Usage

### Full pipeline (default)

```bash
unflutter libapp.so
```

Runs ELF parse, disassembly, signal analysis, and metadata generation in one shot:

```text
elf Dart SDK 3.10.7

code 284352 bytes at VA 0x569a8
  instructions: 1465 entries (0 stubs + 1465 code)
  ranges: 1465 (0 stubs + 1465 code)
  classes: 402 layouts

disasm 1465 functions, pool 1511 entries (1318 resolved)
  functions: 1465 -> samples/evil-patched.unflutter/asm
  call edges: 5937 (822 BLR: 757 annotated, 65 unannotated)
  string refs: 620
  BLR annotation: 92.1%

signal 71 signal + 1076 context, 4178 edges
  net: 40
  url: 4
  base64: 1
  cloaking: 1
  asm snippets: 1142
  -> signal_graph.json (900218 bytes)
  -> signal.html (456296 bytes)
  -> signal.dot (5809 bytes)
  -> signal_cfg.dot (51 functions, 50855 bytes)
  -> signal.svg (18136 bytes)
  -> signal_cfg.svg (145979 bytes)

meta 1465 functions
  focus: 71 signal functions (use --all for everything)
  dart: 3.10.7  ptr_size: 4  thr_fields: 272
  classes: 402 layouts
  comments: 1363 from asm files
  string refs: +461 comments
  -> flutter_meta.json (577230 bytes)

summary
  output:     samples/evil-patched.unflutter
  dart:       3.10.7
  functions:  1465
  classes:    402
  signal:     71

next
  open samples/evil-patched.unflutter/signal.html
  unflutter ghidra libapp.so --from samples/evil-patched.unflutter
  unflutter ida libapp.so --from samples/evil-patched.unflutter
```

Use `--quiet` / `-q` to suppress verbose output. Use `--out` to set the output directory (default: `<basename>.unflutter/`).

### Quick scan

```bash
unflutter scan libapp.so           # print snapshot info
```

### Signal only (skip metadata)

The default pipeline already includes signal analysis. Use `unflutter signal` to run the same pipeline but skip the metadata generation stage:

```bash
unflutter signal libapp.so                    # default pipeline without meta
unflutter signal libapp.so -k 3               # custom context depth (default: 2)
unflutter signal libapp.so --from out/target   # rerun signal from existing disasm
```

### Ghidra decompilation

```bash
unflutter ghidra libapp.so                    # full pipeline + Ghidra headless
unflutter ghidra libapp.so --from out/target   # reuse existing disasm output
unflutter ghidra libapp.so --all               # decompile ALL functions
```

### IDA decompilation

```bash
unflutter ida libapp.so                       # full pipeline + IDA idalib
unflutter ida libapp.so --from out/target      # reuse existing disasm output
unflutter ida libapp.so --all                  # decompile ALL functions
```

### Metadata only

```bash
unflutter meta libapp.so                      # full pipeline, produce flutter_meta.json
unflutter meta --from out/target               # regenerate from existing disasm
```

### Output artifacts

| File | Description |
|------|-------------|
| `functions.jsonl` | Function records: name, address, size, owner, param count |
| `call_edges.jsonl` | Call edges: BL/BLR with resolved targets and provenance |
| `classes.jsonl` | Class layouts: fields, offsets, instance sizes |
| `string_refs.jsonl` | String references from PP loads |
| `dart_meta.json` | Snapshot metadata: Dart version, pointer size, THR fields |
| `flutter_meta.json` | Unified metadata for Ghidra/IDA: functions, classes, THR fields, comments |
| `asm/*.txt` | Annotated ARM64 disassembly per function |
| `cfg/*.dot` | Per-function control flow graphs (with `--graph`) |
| `callgraph.dot` | Full call graph (with `--graph`) |
| `signal.html` | Behavioral signal report |
| `decompiled/*.c` | Ghidra decompiled C output |

## Architecture

```
internal/
  elfx/       ELF validation, ARM64 symbol extraction
  snapshot/   Region extraction, header parsing, version profiles
  dartfmt/    Dart VM stream encoding (variable-length integers)
  cluster/    Two-phase snapshot deserialization (alloc + fill)
  disasm/     ARM64 decode, CFG, call edge provenance, register tracking
  callgraph/  Lattice graph builders (call graph + CFG)
  signal/     Behavioral string classification
  render/     HTML/DOT visualization
  output/     JSONL serialization
```

### Pipeline

```
libapp.so
  → ELF parse (elfx)
  → snapshot region extraction (snapshot)
  → header + version detection (snapshot)
  → cluster alloc scan (cluster)
  → cluster fill parse (cluster)
  → instructions table: stubs + code (cluster)
  → ARM64 disassembly + CFG (disasm)
  → call edge extraction with register tracking (disasm)
  → lattice graph construction (callgraph)
  → signal classification (signal)
  → Ghidra metadata + decompilation (ghidra-meta / decompile)
  → JSON / DOT / HTML artifacts
```

Each stage is a pure function from bytes to structured data. No mutable global state. No VM runtime. Same input, same output.

## Known Limitations

- **AOT only.** No JIT mode support.
- **ARM64 only.** No x86 or RISC-V.
- **No source reconstruction.** Output is function names, call edges, structs, strings, not Dart source.
- **BLR tracking window.** Register provenance uses a sliding window (W=8). Complex register chains outside the window are unresolved.
- **Dart 2.12.x not validated.** No samples available.
- **Large signal graphs.** DOT files over 1 MB are skipped for SVG rendering. Graphviz `dot` uses O(n²) hierarchical layout that hangs on graphs with thousands of nodes. Use `sfdp -Tsvg` for large graphs.
- **Every format change must be modeled.** There is no runtime to handle it automatically.
