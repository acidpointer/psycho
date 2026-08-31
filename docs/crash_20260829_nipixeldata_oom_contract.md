# NiPixelData final-OOM containment contract

## Status

This document covers the August 29 `BSTaskManagerThread` crash supplied in
`.reports/mixed-logs-crash.txt`. The implemented change is an unreleased,
reporter-validation candidate under the repository's reporter-only engine-fix
exception. Static qualification cannot establish runtime acceptance. Release
requires the original workload to record at least one guard rejection and to
continue gameplay without this crash.

The root cause is proven at the native consumer: a failed 22,369,768-byte
`NiPixelData` backing allocation was stored as NULL, pointer arithmetic derived
three small non-NULL field values from it, and the constructor copied through
the derived `0x01555554` destination. The existing zero-allocation guard
correctly returned NULL but could not make this constructor propagate failure.

## Evidence and executable identity

Runtime evidence is `.reports/mixed-logs-crash.txt`. Static conclusions apply
only to `fnv_reverse/FalloutNV.exe`:

- Fallout: New Vegas 1.4.0.525, PE32 i386;
- image base `0x00400000`;
- SHA-256
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

The existing focused native output in
`analysis/ghidra/output/crash/oom_memset_crash_analysis.txt` records the two
unsafe zero-allocation providers and decompiles the `NiPixelData` constructor
at `0x00A7C190`. Addresses, instruction bytes, callers, and branches named
below were reverified directly against the supported executable before the
candidate was written.

## Runtime proof

The report establishes one continuous failure sequence:

1. The process was using 3.80 of 4.00 GiB virtual address space (95.07%). This
   is process VAS exhaustion/fragmentation, not physical-RAM or VRAM
   exhaustion.
2. At 05:57:58, the VAS walk found 225 MB total free and a 37 MB largest hole.
   The medium tier held 47 VirtualAlloc blocks: 46 partial and one empty. It
   reported 233 MB live, 752 MB committed, and 502 MB stranded in partial
   blocks.
3. Pressure retirement released the one provably empty 16 MB block. No other
   medium block was eligible for safe release.
4. At 05:58:21, a request for 22,369,768 bytes (`0x015555E8`) failed after
   page rounding to 22,372,352 bytes. Total free VAS was still 202 MB, but the
   largest contiguous hole was only 21 MB.
5. The zero-allocation provider logged that it returned NULL for the same
   22,369,768-byte request.
6. CrashLogger then recorded `C0000005` on `BSTaskManagerThread`. The fault at
   `0x00EC452A` is `rep movsd`; its return address is `0x00A7C34C`, inside the
   `NiPixelData` constructor's third metadata copy. Both EBX and EDI were
   `0x01555554` and ECX was 12 dwords.

The constructor allocation request contains 148 bytes (`0x94`) of metadata in
addition to the payload: `0x015555E8 - 0x94 = 0x01555554`. The exact equality
between that null-derived payload offset and the fault destination closes the
causal chain. The active `blackscorpion.nif`, renderer objects, and loaded mods
are workload context only; the report does not attribute the failed allocation
or VAS layout to any one asset or mod.

## Native object and call contract

`NiPixelData` construction at `0x00A7C190` calls `0x00A8F010`. That routine:

- allocates `faces * align4(payload_per_face) + mip_count * 12 + 4` bytes;
- stores the allocation result at object offset `0x50` without a NULL branch;
- derives offsets `0x54`, `0x58`, and `0x5C` from the result by arithmetic;
- returns to the constructor, which copies mip widths, heights, and offsets
  through those three fields.

The crash occurs before the constructor returns, so a converter guard alone
cannot intercept it. Guarding global `memcpy` would broaden the hot path
without a failure result. Fabricating storage would invent ownership and size
policy.

The constructor has other native callers whose final-OOM behavior is not
proven safe. The affected construction-and-conversion routine at `0x00A7A280`
is therefore the only admitted failure scope:

- `0x00A7A3DA` allocates the 116-byte destination object;
- `0x00A7A403` invokes the `NiPixelData` constructor;
- `0x00A7A412` loads the current converter vtable provider from slot `0x30`;
- destination, source, and mip `-1` are passed on the stack, converter is in
  ECX, and the `thiscall` provider returns its Boolean result in AL;
- `0x00A7A425` branches to `0x00A7A482` when AL is zero;
- the false branch releases the three source/temporary references it owns and
  returns NULL at `0x00A7A4D2`.

The false branch does not destroy the incomplete 116-byte destination. The
candidate deliberately preserves that behavior. One unpublished 116-byte leak
per rejection is bounded diagnostics debt; selecting a destructor or freeing
an object whose constructor did not complete would invent an ownership
contract and is forbidden.

The shared allocation-helper call inside the constructor is at `0x00A7C331`.
Its caller frame and epilogue are exact: before any metadata-copy arguments are
pushed, the constructor can restore EDI, ESI, EBP, EBX, its `0xC4` local frame,
and its five stack arguments, returning the destination in EAX without setting
the success field at offset `0x68`. This unwind is safe only while the exact
`0x00A7A403` caller wrapper owns a per-thread construction scope. Other callers
must retain the native path.

The native converter implementation at `0x00A7A4F0` uses the same
`thiscall(converter, destination, source, i32) -> u8` ABI, immediately consumes
the destination metadata fields, returns false at `0x00A7AE45`, and returns
true at `0x00A7AE39`. The callsite, rather than the global converter vtable, is
the shared intervention point for this incomplete-object path.

## Candidate behavior

The existing `engine_fixes.memset_null_dst_guard` setting owns the complete
candidate so the zero-allocation providers cannot be enabled without their
proven downstream containment.

Installation is transactional and exact-version fail-closed:

1. Fingerprints verify the destination allocation call, scoped constructor
   call, shared allocation-helper call, unchecked `0x50` store and derived
   fields, converter dispatch, and native false-result branch.
2. The two zero-allocation vtable slots must still point to their exact vanilla
   providers at `0x00AA2240` and `0x00AA2370`. A foreign predecessor aborts
   installation rather than being replaced.
3. An owned direct-call patch at `0x00A7A403` wraps only the affected constructor
   invocation in a nesting-safe per-thread scope keyed by the exact destination
   pointer. Valid construction calls the original constructor once with the
   exact five arguments.
4. An owned direct-call patch at `0x00A7C331` invokes the original allocation
   helper with the same three arguments. A non-NULL backing result returns to
   every constructor caller unchanged. A NULL result early-unwinds only when
   the current thread's scope contains the same destination pointer; otherwise
   it preserves native behavior.
5. One owned 13-byte code patch at `0x00A7A412` preserves the original stack
   arguments and ECX, replacing only the indirect converter dispatch with a
   direct call to the guard.
6. All three code patches and both pointer-slot hooks commit as one
   modification transaction. A partial install restores only bytes and
   pointers still owned by Psycho.

On a scoped backing-allocation failure, the allocation bridge returns the
incomplete object from the constructor before all three unsafe metadata copies.
The exact caller then reaches the converter guard below. It does not publish or
inspect the object through any other boundary first.

At conversion time the guard snapshots only destination offset `0x50` through
the established guarded current-process reader. A NULL destination, address
overflow, unreadable field, or NULL backing allocation returns native false.
The guard does not inspect source data, allocation ownership, module identity,
vtable provenance, reference counts, or destructors.

For an admitted destination, the guard repeats the exact native
`converter[0]->slot_0x30` load and invokes the provider currently installed
there once, with the original ABI, arguments, and return value. This keeps the
candidate allocator-mode agnostic and mod agnostic. It neither allowlists nor
replaces converter implementations.

Rejections are counted and logged on the first event and powers of two:

```text
[OOM] NiPixelData conversion rejected total=N destination=0x........ reason=missing backing allocation result=false
```

The diagnostic report exposes installation/all-callsite state, zero-allocation
NULL returns, conversion rejections, and the last rejection reason. There is no
allocation, blocking lock, file I/O, or module lookup on the conversion path;
`ReadProcessMemory` is dynamically resolved during installation. The cost is
a per-thread scope set/restore around the affected construction, one small
bridge and NULL branch in each `NiPixelData` backing allocation, and one
four-byte guarded snapshot per call through this specific converter callsite.
There is no work per unrelated allocation, memcpy, or frame.

## Compatibility and startup footprint

The guard installs during core engine-fix startup before xNVSE `DeferredInit`.
It changes code and static state in the early-loaded core DLL, so
`docs/nvse_startup_phase_safety.md` applies. Dynamic symbol resolution avoids a
new `ReadProcessMemory` PE import. Scoped construction uses one process-lifetime
Win32 TLS index allocated during existing core engine-fix startup; it does not
add a PE TLS variable, callback, or destructor. This is correctness state for
the active native call, not a cache. A failed set/restore permanently disables
scope admission so a stale destination cannot become a capability.

The candidate release artifact's complete import sequence, exported ABI,
eight-byte `.tls` section, and four established TLS callbacks are unchanged
from the preserved immediate pre-candidate core artifact. The inline core-only
resolver does not appear in the helper. Configuration field order, schema, and
startup callback order are also unchanged. The older accepted artifact named
by `docs/nvse_startup_phase_safety.md` is not present in this workspace, so a
direct artifact comparison against that load-to-gameplay baseline remains
unresolved. Release also retains the representative Proton load-to-gameplay
gate.

The configuration key, its default, and serialized field order remain
unchanged. Disabling `memset_null_dst_guard` disables both the existing
zero-allocation replacements and this downstream containment.

## Unresolved facts and excluded changes

The report proves the final allocation failure and unsafe consumer. It does
not prove:

- which component owns the long-lived allocations in the 46 partial blocks;
- which lifetime pattern produced 502 MB of stranded medium-block capacity;
- an allocator-placement rule that would have left a larger contiguous hole;
- a safe way to relocate live allocations or retire partial blocks;
- a particular mod or asset as the cause;
- the exact scheduling/lifetime race, if any, that selected this allocation at
  this moment;
- acceptance of the candidate in the reporter's workload.

Accordingly, this incident does not change gheap tier placement, reclaim
partial blocks, invoke broad synchronous OOM stages, identify modules, patch
another mod, or mutate ownership/reference counts. A future allocator change
requires request-size and lifetime evidence sufficient to prove placement;
aggregate block occupancy is not that evidence.

## Acceptance

Static qualification requires the focused `psycho-engine-fixes` tests, the
supported i686 release build, formatting, `git diff --check`, final diff review,
and the pre-DeferredInit footprint audit. These gates qualify only a reporter
candidate.

Runtime acceptance requires the reporter to run the original workload and
confirm both:

1. at least one `[OOM] NiPixelData conversion rejected` record; and
2. continued gameplay after the rejection without this crash.

Until that evidence and the startup-safety playtest exist, the change must not
be released, packaged, committed, or described as runtime-accepted.
