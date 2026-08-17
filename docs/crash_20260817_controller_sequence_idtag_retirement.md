# Controller-sequence IDTag retirement containment

## Purpose and status

This fix prevents the reported low unresolved string-palette representation,
and its legacy NULL sentinel, from reaching `NiControllerSequence` fixed-string
retirement. The reported sequence contained `0x0000000D`; the native destructor
subtracted its eight-byte fixed-string header and called `InterlockedDecrement`
on address `0x00000005`.

The guard is enabled by default through
`[engine_fixes].animation_sequence_idtag_retirement_guard`. It is owned by the
early-loaded `psycho-engine-fixes` core DLL, is independent of the selected
allocator, and does not require the xNVSE helper.

Static proof and the supported build are complete. Runtime reproduction and
the startup/playtest matrix remain required before release acceptance.

## Evidence

### Supplied runtime evidence

- `.reports/CrashLogger--weird-crash.log`
- `.reports/psycho-engine-fixes--weird-crash.log`

The Crash Logger report captured exception `0xC0000005` on the FalloutNV main
thread after about 40 minutes. Its relevant state was:

- `EIP = 0x7B270959`, inside Wine/Proton `InterlockedDecrement`;
- `EDI = 0x7B270950`, the imported `InterlockedDecrement` entry;
- native return address `0x00A31627`;
- decrement argument `0x00000005`;
- `EBX = 0xE9387700`, the prefixed record allocation;
- `ECX = 0xE9387704`, its record data;
- `ESI = 0xE9387768`, the 20-byte record at zero-based index five;
- an active `AnimSequenceSingle` for
  `Characters\_Male\sneakmtjumploopright.kf`.

The core log shows no allocation failure or OOM pressure. Its last complete
sample had about 1.8 GiB free virtual address space and a 1.34 GiB largest
hole. The main-thread heartbeat stopped while the native PDD queues contained
one animation retirement and one texture retirement. The animation identity
describes the workload; it does not establish which component produced the
invalid record.

In allocator mode 2, `0xE9387700` is exactly aligned to a 640-byte slot in
gheap's 640-byte pool class. The crash report does not preserve that slot's
side-metadata state, so it does not prove a live cell, freed cell, reuse, or
allocator corruption.

### Executable identity

Address-sensitive research applies to the repository's supported PE32 i386
`FalloutNV.exe`, runtime version 1.4.0.525, with image base `0x00400000`.
Radare2 was the primary binary-analysis interface.

## Proven native contract

### Destruction path and ABI

`0x00A35640` is the shared
`NiControllerSequence::~NiControllerSequence` destructor body. The derived
`BSAnimGroupSequence` destructor also calls this body, so one thiscall entry
hook covers both native retirement paths.

The destructor reads the owned record data pointer at `this + 0x18` and calls
`0x00A315B0`. That record destructor:

1. derives the allocation start as `data - 4`;
2. reads a 32-bit prefix count;
3. walks the records in reverse;
4. treats each record as five 32-bit fixed-string pointers;
5. subtracts eight from every non-NULL pointer and calls
   `InterlockedDecrement` on the resulting reference-count header.

The call at `0x00A31625`, returning to `0x00A31627`, processed the field at
record offset `+4`. The pushed argument was `0x00000005`; therefore the field
value before native `-8` arithmetic was exactly `0x0000000D`.

### Fixed-string representation

`0x00A5B690` is the fixed-string interner. New strings have this layout:

```text
returned pointer - 8    atomic reference count
returned pointer - 4    byte length
returned pointer        string bytes
```

Existing strings increment the same `pointer - 8` count. This proves that a
valid non-NULL runtime field must identify an allocated string body and cannot
be `0x0000000D`.

### Post-link representation change

Sequence post-link function `0x00A352F0` loops over the controlled-block count
at `this + 0x0C` and passes each 20-byte record to `0x00A30D40` while the
sequence's string palette at `this + 0x64` exists.

`0x00A30D40` clears all five destination fields, treats each source word as a
palette offset, maps `0xFFFFFFFF` to NULL, interns every remaining palette
string through `0x00A5B690`, and stores the resulting fixed-string pointer.
The [NifTools format schema](https://github.com/niftools/nifxml/blob/master/nif.xml)
independently identifies the same five IDTag strings and their legacy
`StringOffset` representation.

The direct fault is therefore proven: an IDTag field that did not satisfy the
runtime fixed-string contract reached the fixed-string destructor. Its exact
producer and the reason conversion was missed or later overwritten remain
unknown.

## Ownership and intervention point

The main-thread PDD animation queue owns deferred final release, but it does not
own the internal sequence representation. Hooking or purging the global queue
would affect unrelated payloads and would not repair the malformed object.

The safe intervention point is the entry of the shared destructor at
`0x00A35640`:

- `this` is still live under the native destructor contract;
- the sequence still owns `this + 0x18`;
- no IDTag reference count has yet been decremented;
- the object has no future animation behavior to preserve;
- both base and derived sequence retirement reach the same boundary.

The hook preserves the original thiscall ABI and invokes the active inline-hook
predecessor exactly once.

## Containment policy

The guard requires the exact prefixed allocation start through the active
allocator before examining records. Gheap uses authoritative side metadata.
Vanilla SBM proves the exact cell boundary and holds its native pool lock across
classification, record inspection, and any repair; because SBM has no per-cell
bitmap, the native destructor's exclusive ownership supplies the remaining
live-object lifetime contract. Non-pool vanilla allocations use cached
Windows-heap ownership. The same destructor ownership keeps exact gheap and
Windows allocations stable after classification.

The native constructor and growth path allocate both parallel arrays from the
count at `this + 0x0C`, write that same count into each allocation prefix, and
update the object count together with replacement pointers. For an admitted
IDTag allocation, the guard therefore requires its prefix count to match
`this + 0x0C` and requires the checked size `4 + count * 20` to fit its usable
size. Those independent bounds reject count-mismatched or undersized reused
storage before any record is changed. It then scans the five fields in each
record.

A record is unresolved when a field contains either:

- `0xFFFFFFFF`, the legacy raw-offset NULL sentinel; or
- a nonzero value whose required eight-byte fixed-string header would fall
  below `0x10000`, the supported process's unmapped low-address guard.

Once one field proves a record's representation ambiguous, the guard clears all
five fields in that record. Clearing only the marker could allow another raw
offset in the same record to reach native reference-count code. The complete
record repair preserves every other record and lets the native destructor free
the array normally. A genuinely mixed record can leak at most its remaining
fixed-string references; that bounded exceptional cost is safer than guessing
which words use which representation.

Recovery by pointer state is:

| State | Action |
|---|---|
| NULL array | Leave native behavior unchanged. |
| Admitted allocation, valid layout and records | Leave every byte unchanged. |
| Admitted allocation, unresolved record | Clear that complete record, then call native. |
| Known-owned free/interior/uncommitted/undersized array | Detach `this + 0x18`, then call native. |
| Impossible low or misaligned data pointer | Detach it, then call native. |
| Aligned high unowned address | Do not inspect or detach; preserve the predecessor's ownership policy. |

A detached array is deliberately leaked. The dying sequence is still released
normally, and no uncertain pointer is traversed or freed.

## Failure, concurrency, and performance

Installation is one transaction at the pre-CRT startup barrier. An
incompatible hook owner or preparation failure logs that this fix is
unavailable and does not abort unrelated engine fixes. A missing original
trampoline after successful installation is logged once; the sequence is then
leaked rather than unwinding across FFI or entering an unknown target.

The valid path is destructor-cold and performs one allocation classification
plus five integer checks per record. It performs no allocation, file IO,
palette lookup, string interning, routine logging, or OS readability probe.
Exceptional logs are limited to initial events and power-of-two totals and are
emitted only after allocator locks have been released.

The fix does not change allocator allocation, free, reuse, reclamation, OOM, or
PDD scheduling policy:

- OOM behavior is unchanged; the captured repair frees the verified array
  normally.
- UAF/corruption exposure is reduced at the exact final owner. The guard does
  not claim or repair the unknown producer.
- Steady-state animation and frame costs are unchanged because the work occurs
  only during sequence destruction.

## Compatibility boundaries

The fix is capability-based and does not inspect a plugin, actor, form, KF
path, editor ID, or mod version. It does not patch, reorder, disable, or add a
compatibility path for another mod. Structurally plausible high allocations
outside Psycho's proven domains remain under the active predecessor's policy.

The new configuration field, hook container, and code are visible before xNVSE
`DeferredInit`. They therefore require comparison against the last accepted
pre-Deferred artifact and repeated BaseObjectSwapper-enabled Proton cold
launches. Static tests and compilation cannot replace that startup gate.

## Acceptance

The candidate is accepted only after all of the following:

1. The supported 32-bit existing test suite and complete release build pass.
2. The reporting save/modlist reaches animation-sequence unload or replacement
   and emits an `[ANIM_SEQUENCE]` containment for the invalid record while
   gameplay continues.
3. The `0x00A31625 -> InterlockedDecrement(0x00000005)` signature does not
   recur during repeated sequence retirement.
4. Animation changes, cell transitions, save/load, and actor retirement show no
   missing or frozen animations and no cascading containment counter.
5. The behavior is exercised in allocator modes 0, 1, and 2; mode 2 closes the
   reported case.
6. The complete pre-Deferred footprint is compared with the last accepted
   artifact and at least three BaseObjectSwapper-enabled Proton cold launches
   reach gameplay.

Until this matrix passes, the honest status is an unaccepted, statically
verified candidate. It must not be released or packaged as complete.
