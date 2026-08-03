# FNV zlib replacement: ownership, correctness, and performance contract

## Purpose and current status

Psycho replaces the two audited Fallout: New Vegas inflate consumers with a
hybrid decoder:

- complete TES records and provably complete small BSA members use libdeflate
  1.25.2;
- BSA members which need compressed-input refills or bounded output use a
  persistent zlib-rs 0.6.3 decoder.

The implementation is owned by `psycho-engine-fixes/src/mods/zlib/` and is
enabled by `[performance].zlib = true`. Core startup installs it before engine
streams are created. The helper DLL does not load, initialize, or own it.

The user-visible contract is faster decompression with byte-identical output.
Psycho does not transform textures, meshes, face geometry, plugin records, or
save data. Zlib framing and Adler-32 validation remain enabled on every path.

This implementation supports the FNV runtime only. GECK is deliberately
excluded because the repository has no identified editor executable and no
static proof for the old editor addresses. The old `is_editor` branch was also
unreachable from core startup, which always passed `false`.

## Executable identity and evidence

The engine contract applies to `fnv_reverse/FalloutNV.exe`:

- PE32 x86, image base `0x00400000`, file size `16084808` bytes;
- PE timestamp `0x4E0D50ED`, checksum `0x00F64BD0`;
- SHA-256
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`;
- CodeView GUID `9196089162EE4D29BF48E8D767B32DB91`.

Authoritative retained analysis is in:

- `analysis/ghidra/output/perf/zlib_full_contract_audit.txt`;
- `analysis/ghidra/output/perf/zlib_stream_lifetime_and_deflate_followup.txt`;
- `analysis/ghidra/output/perf/zlib_external_entrypoint_audit.txt`;
- `analysis/ghidra/output/perf/startup_loading_speed_audit.txt`.

A focused radare2 review of the current executable additionally confirmed the
stock initializer at `0x00B43E70`. It validates the first version byte and the
56-byte stream size, installs stock allocator callbacks only when they are
null, and then follows two ownership paths:

- if `z_stream.state` is null, `0x00B43EEE` allocates `0x1BA8` bytes and
  `0x00B43F26` writes `reserved = 1`;
- if `state` is already non-null, `0x00B43F2F` writes `reserved = 0` and uses
  the caller-provided storage without taking ownership.

The archive constructor takes the second path. This distinction is why the
replacement must clear the vanilla state pointer before asking zlib-rs to
initialize its incompatible private layout.

The comparison source is read-only under
`.research/FastDecompress-main/FalloutNewVegas/`. Relevant files are
`src/DecompressHooks.cpp`, `src/main.cpp`, and `CMakeLists.txt`.

Upstream backend references are the
[libdeflate repository](https://github.com/ebiggers/libdeflate) and the
[zlib-rs repository](https://github.com/trifectatechfoundation/zlib-rs).

## Proven engine contract

The executable has exactly two direct consumers of the stock inflate entries:

| Owner | `inflateInit_` | `inflate` | `inflateEnd` | Operation |
|---|---:|---:|---:|---|
| `TESFile::DecompressCurrentForm`, `0x004740A0` | `0x004742AC` | `0x0047434F` | `0x004742CA`, `0x00474388`, `0x004743D5`, `0x00474419` | One complete zlib member and destination. |
| `CompressedArchiveFile`, constructor/read/destructor at `0x00AFC430`, `0x00AFC0E0`, `0x00AFBFE0` | `0x00AFC537` | `0x00AFC1F4` | `0x00AFC00E`, `0x00AFC21B`, `0x00AFC552` | One persistent stream consumed through repeated bounded reads. |

The stock entrypoints are `inflateInit_` at `0x00B43FE0`, `inflate` at
`0x00B44000`, and `inflateEnd` at `0x00B45DB0`. No deflate/save callsite is
redirected.

`z_stream` is the 32-bit, 56-byte zlib ABI. `CompressedArchiveFile` owns a
pointer at object offset `+0x160` to a `0x1BE0`-byte outer allocation. The
constructor zeros `zalloc`, `zfree`, and `opaque`, then preloads public
`z_stream.state` at offset `+0x1C` with outer-allocation address `+0x38`.
Vanilla therefore borrows the remaining `0x1BA8` bytes as inflate state.

The archive object also owns:

| Object offset | Meaning |
|---:|---|
| `+0x164` | bounded decompression output buffer |
| `+0x168` | uncompressed member size |
| `+0x16C` | output-buffer capacity |
| `+0x170` | read cursor within buffered output |
| `+0x174` | valid buffered-output length |

At `0x00AFC58C`, the constructor selects
`min(uncompressed_size, DAT_011F8164)`. The global defaults to `0x20000`, so
one member can reserve at most 128 KiB of staging output. The read routine
assigns that capacity to `avail_out`, calls inflate with `Z_SYNC_FLUSH`, exposes
the produced bytes, refills compressed input when `avail_in` reaches zero, and
continues the same stream until `Z_STREAM_END`. Fatal status calls
`inflateEnd`; the destructor owns normal termination.

These facts prove that BSA continuation state belongs to the archive's
`z_stream`, not to the OS thread executing an individual call. One stream is
serialized by its owner, while distinct archive objects can be active
independently. Psycho's optional two-worker IO topology also means a stream may
be handed from one worker to another between calls; see
`docs/parallel_io_engine_contract.md`.

## Root cause of the reported corruption

The previous Psycho implementation stored both the BSA `flate2::Decompress`
object and its first-call flag in thread-local storage. `inflateInit_` reset the
thread-local decoder, repeated `inflate` calls continued it, and `inflateEnd`
only cleared a sentinel in the public stream. The engine stream did not own the
compressed bit position, Huffman tables, sliding window, checksum, or pending
output represented by that decoder.

Two valid engine schedules therefore broke the replacement:

1. Stream A made partial progress, stream B initialized or inflated on the same
   thread, and stream A resumed against B's decoder state.
2. One stream made partial progress on one IO worker and resumed on another
   worker whose TLS decoder was fresh or belonged to a different stream.

The resulting data errors and truncated or invalid archive payloads are
consistent with broken NPC faces and other asset anomalies. The supplied user
report does not name the damaged BSA member, so the exact face-asset attribution
is a reasoned inference rather than a runtime observation.

The old removal of the 128 KiB output cap was not the continuation-state root
cause. It did, however, allow one archive member to request an unbounded
contiguous allocation in a 32-bit process, so the corrected implementation does
not retain that separate risk.

## FastDecompress comparison

FastDecompress gets the essential ownership boundary right. Its TLS
libdeflate object is used only for an attempt that begins and ends inside one
call. Its fallback uses Chromium zlib, whose state is stored in the exact
`z_stream`, continued by `inflate`, and released by `inflateEnd`. It therefore
does not place persistent state in TLS.

There are important differences:

- FastDecompress eagerly initializes Chromium zlib before its first
  libdeflate attempt. Psycho defers zlib-rs initialization, so a complete-path
  hit avoids the fallback allocation and initialization entirely.
- FastDecompress uses `libdeflate_zlib_decompress`, then advances by all
  available input. Psycho uses the `_ex` entrypoint and publishes exact consumed
  and produced counts.
- FastDecompress's TLS libdeflate allocation is unchecked. Psycho reports a
  null decoder or streaming allocation as `Z_MEM_ERROR`; no Rust allocation
  failure is allowed to unwind or abort through the engine ABI.
- FastDecompress patches calls sequentially. Psycho preflights all eleven calls
  against their exact stock targets and rolls back every written instruction if
  any write fails.
- Comments in FastDecompress `main.cpp` say the archive cap is increased to
  4 MiB, but the code NOPs all eight bytes at `0x00AFC58C`. Execution then
  always falls through to the full uncompressed member size, removing the cap
  completely. Psycho preserves the native 128 KiB bound.

FastDecompress's reported 93 percent complete-path rate is an observation of
its own cap-removing implementation and test workload. It is not evidence that
the same hit rate applies while FNV's native cap is preserved.

## Corrected architecture and lifetime

### Complete-buffer path

TES `inflateInit_` installs a private tag and a pending sentinel without
allocating a streaming decoder. `inflate` borrows a thread-local libdeflate
decoder, allocating it fallibly only on first use. A same-thread recursive hook
or a call during TLS destruction receives an independently checked temporary
decoder instead of aliasing or panicking on the TLS borrow.

libdeflate validates the complete zlib member and Adler-32 checksum. The `_ex`
API supplies exact input and output progress. Psycho validates those counts
against both slices before updating `next_in`, `avail_in`, `total_in`,
`next_out`, `avail_out`, and `total_out`. The already verified trailer supplies
the public `adler` field without an extra scan over decompressed bytes.

An archive can use this path only while it is pristine and its first
`avail_out` is less than `0x20000`. Under the proven constructor contract, that
strict inequality establishes that the staging buffer is the member's complete
uncompressed size rather than the native cap. libdeflate itself establishes
whether the compressed input is also complete. A miss leaves all public
cursors untouched; the fallback restarts from byte zero and overwrites any
unspecified scratch bytes left in the output buffer.

When `avail_out` equals the cap, the implementation cannot distinguish a member
of exactly 128 KiB from a larger capped member. It conservatively uses the
streaming path. This avoids decoding the first 128 KiB twice on every known
large member.

### Persistent BSA path

BSA `inflateInit_` writes an archive tag and a pending sentinel but does not
allocate. On the first streaming need, initialization clears the constructor's
borrowed vanilla `state`, `zalloc`, `zfree`, and `opaque` fields. zlib-rs then
installs its Rust allocator and allocates its aligned state plus 32 KiB window.
The state pointer and allocator callbacks remain directly in the engine's
`z_stream`; there is no outer Rust `Box` or proxy cursor.

Compile-time size and alignment assertions bind Psycho's `ZStream` to
zlib-rs's `c_api::z_stream` on the supported target. Unit tests additionally
check the critical `state` and `reserved` offsets. The low-level backend updates
all public fields, including `msg`, `data_type`, `adler`, input cursors, and
output cursors.

zlib-rs returns `Z_BUF_ERROR` when it cannot progress. The native BSA loop does
not treat that status as fatal. If both buffers are usable and neither cursor
moves, Psycho promotes the impossible valid-stream state to `Z_DATA_ERROR` so
the engine cannot spin forever. Ordinary refill and full-output `Z_BUF_ERROR`
cases are preserved.

`inflateEnd` handles four states: pending, complete libdeflate hit, failed
streaming initialization, or active zlib-rs stream. It releases an active
backend allocation once, then clears both state and tag. A repeated end fails
closed with `Z_STREAM_ERROR` and cannot double-free replacement state. The
engine remains the owner of its unchanged `0x1BE0` outer block.

## Installation and compatibility boundary

Installation snapshots all eleven five-byte near-CALL instructions and verifies
that every opcode is `E8` with the audited stock target. Only after complete
preflight does it write replacement calls. Each write uses the shared protected
memory wrapper and flushes the instruction cache. A failure restores the
current and every prior snapshot in reverse order; restoration failures are
reported in the startup error.

This is deliberately version- and conflict-sensitive. Another executable or a
mod which already owns any callsite is rejected before mixed stock/replacement
state can be published. The archive allocation immediate, cap instructions,
global cap value, save deflate paths, and unrelated zlib callers are unchanged.

## Performance and memory review

The hot paths contain no locks, file IO, statistics atomics, or routine logs.
Complete operations perform one TLS lookup and one libdeflate call. One
libdeflate decoder is retained per thread after first use; recursive entry alone
uses a temporary decoder. A complete BSA hit performs no zlib-rs allocation.

Streaming allocates one combined zlib-rs state/window block per live fallback
stream and no memory per inflate step. Direct use of the low-level backend
removes the prior flate2 wrapper and a separate boxed state allocation. Capped
large members also skip a libdeflate attempt which cannot fit, eliminating
duplicate decompression of their first output window.

libdeflate provides runtime x86 CPU dispatch for the complete path. zlib-rs
0.6.3 dispatches its fast decoder to AVX2/BMI1/BMI2 on 32-bit x86 when
available, but some match-copy and Adler-32 SIMD implementations are currently
x86-64-only. The streaming fallback is therefore not claimed to beat
FastDecompress's Chromium zlib on every CPU. Real FNV BSA corpus measurements
are still required before making a fastest-backend claim.

Preserving the 128 KiB cap is an intentional memory/performance tradeoff. It
reduces libdeflate coverage compared with FastDecompress but bounds each engine
staging allocation in the 32-bit address space. Raising or removing it without
a measured archive-size distribution and concurrent-lifetime bound would trade
decompression time for unbounded virtual-address pressure. Such a policy change
is outside this correctness fix.

## Invariants and failure behavior

- Persistent decoder state is owned by one BSA `z_stream`, never by TLS.
- Calls for one stream are serialized; different streams share no mutable
  continuation state and can run concurrently.
- Complete TLS state never represents a continuation between hook calls.
- Zlib headers and Adler-32 trailers are always processed. Raw-deflate bypass
  is unsupported.
- All allocator failures become `Z_MEM_ERROR`; invalid ownership or ABI use
  becomes `Z_STREAM_ERROR`; corrupt data becomes `Z_DATA_ERROR`.
- Native compressed-input refill and bounded-output behavior remain unchanged.
- Hook installation is all-or-nothing for the audited callsite set.
- GECK and other FalloutNV.exe builds are unsupported until independently
  identified and proven.

## Validation and runtime acceptance

The in-crate regression suite covers:

- 32-bit ABI size, alignment, and critical offsets;
- zlib version and stream-size rejection before mutation;
- a fixed externally encoded member on the libdeflate path;
- a complete BSA member with no streaming allocation;
- a large capped member which skips the guaranteed libdeflate miss;
- incremental compressed-input refills and bounded output;
- injected streaming allocation failure;
- no-progress normalization;
- two BSA streams interleaved on one thread;
- sequential handoff of a partially consumed stream between threads;
- independent TES operations initialized before either is decoded;
- Adler-32 corruption rejection;
- repeated `inflateEnd` without a double release;
- relative-CALL encoding;
- preflight mismatch with zero writes;
- write failure followed by complete rollback.

Required repository validation is:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes
git diff --check
```

Validation completed on 2026-08-03 for `i686-pc-windows-gnu`:

- the focused zlib run passed 16 tests;
- the complete `psycho-engine-fixes` library suite passed 153 tests;
- the optimized `psycho-engine-fixes` release DLL built successfully;
- `git diff --check` passed;
- the release DLL contains libdeflate's `_ex` decoder and x86 dispatch plus
  zlib-rs's AVX2/BMI fast inflate implementation, and has no external zlib DLL
  dependency.

The build emitted the repository's existing mimalloc C warnings and MinGW
stdcall-fixup linker warnings; neither originated in the zlib module.

An in-game playtest remains mandatory because unit tests cannot prove asset
integration inside FalloutNV.exe. Acceptance is a representative save and cell
traversal with `performance.zlib = true`, including NPCs which previously
showed face corruption, with no zlib errors or visual anomalies. A real BSA
corpus benchmark should record complete-path coverage, fallback throughput, and
peak concurrent archive staging memory before changing the cap or streaming
backend.

## Evidence classification

Proven by repository source and static executable evidence: all eleven
callsites, stock targets, stream ABI, constructor/read/destructor ownership,
stock inline-state ownership flag, bounded output loop, the previous TLS state,
FastDecompress's per-stream fallback, and the corrected replacement lifetime.

Proven by automated target tests: complete and bounded decompression, checksum
failure, interleaving, sequential worker handoff, allocation failure, end
idempotence protection, and transactional patch behavior.

Reasoned inference: the reported NPC faces and other visual anomalies came from
an affected archive payload. The ownership defect can violate the decompression
contract, but no supplied runtime trace identifies the exact asset.

Awaiting runtime observation: the corrected DLL removes the visual symptoms
under the user's full mod list and Proton/Wine environment, and the selected
backend/cap policy is fastest on a representative FNV archive corpus.
