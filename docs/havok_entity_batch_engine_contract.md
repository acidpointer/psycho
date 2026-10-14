# Havok sparse entity consumption contract

Status: native NULL-consumption repair implemented; modded runtime acceptance
not established. The operation that produced the incident's NULL slot remains
unattributed. There is no diagnostic-only build or probe in this repair.

## Observed failure and defective intervention

The October 13 extreme-speed flight failed at `0x00C94DA5` on `[FNV] AI Linear
Task Thread 2`, with `ESI = ECX = 0`, `EDI = 0x1B850BC0` (`ahkpWorld`),
`EBX = 0x298FC020` (`hkpSimulationIsland`), and `ESP = 0x2556FC58`.
The native instruction writes through a NULL entity at offset `0xD4`.
It differs from the earlier terrain task cancellation failure.

Incident evidence is preserved in:

- `.reports/CrashLogger-20261013-204807-lod-stress.log`;
- `.reports/psycho-engine-fixes-20261013-204807-lod-stress.log`;
- `.reports/psycho-engine-fixes-20261013-204807-lod-stress-deployed.dll`.

The deployed artifact matched the then-current release artifact. Its log
records successful Havok entry-guard and terrain ownership installation,
followed by `[EVENT] Game engine ready`. CrashLogger records 3:48 playtime.
This establishes a load-to-gameplay baseline for that artifact; it does not
establish that earlier terrain failures can never recur.

The previous Psycho implementation scanned and compacted caller-owned pointer
arrays at batch and pending entry. It moved non-NULL elements, zeroed the tail,
and reduced only the callee's count. Native callers retained their own original
count and ownership of subsequent processing/release. Entry inspection also
could not guarantee that a later native slot load would still be non-NULL.
Only the first pending post-add read had an in-loop NULL check.

The supplied crash proves the native NULL-consumer failure. A fail-first test
of the actual Rust compaction separately proves Psycho's caller-array mutation.
Neither establishes which particular writer or thread produced this incident's
slot. Pool fallback warnings, stack actors, and mod names are not attribution.

## Executable identity and authoritative evidence

Addresses were reverified through the radare2 MCP against
`fnv_reverse/FalloutNV.exe`, FNV 1.4.0.525, PE32 x86, image base `0x00400000`,
CodeView GUID `9196089162EE4D29BF48E8D767B32DB91`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Reverify all address-sensitive facts before supporting another executable.

Raw proof:

- [initial radare2 audit](../analysis/radare2/output/perf/havok_entity_batch_crash_audit_20261014.txt);
- [consumption and reference audit](../analysis/radare2/output/perf/havok_sparse_consumption_contract_20261014.txt);
- [existing batch audit](../analysis/ghidra/output/crash/crash_00c94da5_mopp_add_entities_audit.txt);
- [existing pending-owner audit](../analysis/ghidra/output/crash/havok_pending_add_queue_audit.txt).

Existing Ghidra output was reused without regeneration. Byte-encoded offsets
and instruction lengths establish layouts; radare2's inferred local-variable
names do not.

## Native ownership, ABI, and caller coverage

`0x00C94BD0` takes world in ECX and array, signed count, and mode on the stack,
returning with `ret 0x0C`. Its four direct callers are:

| Call | Owner | Work which must survive NULL handling |
|---|---|---|
| `0x00C67551` | `0x00C674D0` pending flush | Original-range post-add processing, releases at `0x00C6767C`, then clearing at `0x00C6769D`. |
| `0x00CF7DB0` | `0x00CF7C10` deferred operation case 6 | Releases the original array/count through `0x00C90740`, then frees its backing storage. |
| `0x00CE16AA` | `0x00CE1680` collection add | Continues collection work, including optional per-slot filter updates. |
| `0x00C97FC6` | `0x00C97F80` operation processing | Dense input uses the batch. Sparse input uses per-entity `0x00C914D0`; its actual reload also requires protection. |

Pending flush at `0x00C674D0` takes manager in ECX, array/count on the stack,
and returns with `ret 8`. Six native call sites route through it:
`0x00C6B599`, `0x00C68AB0`, `0x00C6B135`, `0x00C6B2AA`, `0x00C6B475`, and
`0x00C6AECA`. Their queue count publication remains native.

The manager constructor `0x00C69010` allocates and clears the pending backing
array at manager `+0x2C` and initializes count `+0x30`. Queue insertion at
`0x00C6B0A0` retains an entity, stores it in that array, then increments count.
Flush reads and clears the same array; destruction at `0x00C6ACA0` frees it.
The entry guards therefore borrow an owning native range, not scratch storage.

A nonzero world `+0x94` selects deferred add through `0x00C91160` and
`0x00CF7690`. Deferred enqueue copies the original range and retains its
members through `0x00C90510`. Deferred execution releases the same cardinality
through `0x00C90740`, which calls `0x00C903B0`. Pending flush uses
`0x00C905B0`. All three reference helpers receive their object in ECX, have
no stack arguments, and return void with plain `ret`. They access object
`+4/+6` only inside the captured native provider. Their non-reference-counted
object paths already return without retaining/releasing anything.

The repair's reference guards inspect only whether ECX is NULL. Non-NULL
objects chain the provider already installed at the shared entry, preserving
its fields, synchronization, reference arithmetic, final destruction, and ABI.
NULL has no object/reference to operate on and returns without field access.
No additional retain, ownership classification, or destructor intervention is
introduced. This also covers the deferred retain/release path, which never
passes through the normal batch entity loop while enqueueing.

World `+0x94` is a critical-operation counter, not proof of mutual exclusion.
No new lock is introduced and no exact racing writer is claimed. Non-NULL
pointer validity, object lifetime, and backing-array lifetime remain native
caller contracts; these guards do not purport to recognize dangling objects.

## Native consumer and continuation proof

The native batch frame reserves `0x48` local bytes and saves four registers.
At the initial loop, array is `[ESP+0x5C]`, count `[ESP+0x60]`, and mode
`[ESP+0x64]`; `[ESP+0x1C]` holds the loop index. Stack index `07` in the report
contains `0x3C`, locating the fault at zero-based slot 60. The optimized EBP
contains a preceding shape pointer, so the displayed unwind is not a reliable
native caller chain. CrashLogger's [5.17 stack implementation](https://github.com/yvileapsis/yUI-NVSE/blob/5.17/CrashLogger/RegistryStack.cpp)
filters later raw words through RTTI/labels and does not preserve all arguments.

Six exact native splices handle independent slot loads:

| Site | NULL result | Valid result |
|---|---|---|
| `0x00C94D90` batch initialization | Native iteration tail `0x00C94EE2`; no entity write or world reference is created for a NULL. | Replay both loads and continue at `0x00C94D97`. |
| `0x00C95067` added callbacks | Advance ESI, then compare at `0x00C9507F`, after the skipped argument cleanup. | Continue at `0x00C9506E` with the loaded entity. |
| `0x00C67577` pending first read | Native iteration tail `0x00C67681`. | Replay the original object-type CMP and its flags; continue at `0x00C6757E`. |
| `0x00C675B0` pending second read | Native iteration tail before island/owner work; ESI still holds the array. | Replay the `+0xCC` load, continue at `0x00C675B9`. |
| `0x00CE16E0` collection filter | Native INC/CMP tail `0x00CE16F2`, before pushing filter arguments. | Replay loads and continue at `0x00CE16E6`. |
| `0x00C97FE2` sparse single-add fallback | Native INC/CMP tail `0x00C97FF4`, before either call argument is pushed. | Replay the slot load, XOR EDX, and TEST CL; continue at `0x00C97FE8` so SETNE computes the original mode. |

The sparse fallback originally compared the slot at `0x00C97FD6`, then
reloaded it at `0x00C97FE2` without checking that new value. Its owning system
holds the array at `+8`, count at `+0x0C`, and mode flag at `+0x40`.
The caller is `0x00D4C159` in `0x00D4C0C0`. A NULL reload reaches the single-add
consumer `0x00C914D0`, whose immediate path reads entity `+0x10` at
`0x00C9150F`. The single-add result is ignored in this loop. NULL handling
therefore reuses the existing NULL-slot loop tail, without enqueueing an add,
changing reference ownership, or touching the mode flag. This is a statically
proven uncovered reload, not an observed second fault or a proven concurrent
writer in that system's array.

The callback body pushes twelve argument bytes. Jumping directly to its native
`ADD ESP,12` on a skipped slot would corrupt the frame; the NULL continuation
explicitly advances the index and jumps after that cleanup. Collection filter
calls use callee cleanup, so a skipped slot reaches the unmodified loop tail
before arguments are pushed. Every bridge restores flags except where it
replays the original CMP or performs the original loop increment. It neither
calls Rust nor touches FPU/SSE state.

Native batch temporary-array counts increase only for processed/shaped entities.
The supported world's constructor calls factory `[0x011B37A0]` at
`0x00C95CB5` and stores its result at world `+0x58`. That factory is
`0x00D182A0`, whose `0x00D13BD0` constructor installs vtable `0x010CD5CC`.
The broadphase provider in vtable `0x010CD5CC`, slot `+0x18`, is `0x00D18400`.
It checks the bounds-array count at entry and returns through `0x00D19351`
when that count is below one. Thus an empty shaped batch retains a proven
native empty-input path. World counter decrement, temporary storage cleanup,
deferred processing, and the caller's post-batch work remain native.

## Implementation and activation

`havok.rs` now admits the readable array envelope without scanning, moving,
zeroing, or reducing its slots/count. Positive inaccessible/overflowing arrays
retain the existing rejection policy; an empty range forwards unchanged.
Readability is an admission snapshot, not a lifetime guarantee.

`havok_sparse.rs` owns six instruction patches, three inline reference guards,
and the requested batch/pending array-entry hooks as one
`ModificationTransaction`. It verifies every displaced span and loop/stack
continuation before writes, prepares all providers including both configured
entries, activates the complete set, commits, then publishes admission. A
rollback survivor with admission false replays native behavior or forwards its
captured provider. Entry survivors bypass array admission while unadmitted;
they cannot borrow protection from a group whose activation failed.
Captured reference providers are published before activation and retained for
process lifetime; hot calls load their addresses without hook-container work.
These settings are startup requests, not live toggles. Their shared dependency
and entry selection are explicit:

| Batch setting | Pending setting | Shared native NULL flow | Array-entry admission |
|---|---|---|---|
| false | false | Not requested; no sparse setup | Neither entry |
| true | false | Complete flow requested | Batch entry |
| false | true | Complete flow requested | Pending entry |
| true | true | Complete flow requested | Both entries |

The independent direct post-add and narrowphase settings retain their own
ownership. Configuration fields, order, types, defaults, helper ABI, workers,
and DLL TLS are unchanged at source level; setting descriptions no longer
claim that arrays are compacted.

Sparse installation failure leaves admission false and reports that requested
protection was not admitted. Ownership-aware rollback is attempted; a survivor
is not described as restored. The independent narrowphase and direct post-add
entry hooks each use their own activation transaction. Failures in any Havok
unit are reported without aborting the remaining Havok, IO, LOD, or performance
installation. No active-success message is emitted for a failed unit, and the
continued startup does not imply that every requested protection is available.

Valid paths add no allocations, blocking locks, module lookup, or routine logs.
Entry's previous per-slot compaction scan is removed. Assembly guards test the
already-loaded slot; admission is consulted only for NULL. Valid reference
operations take the captured provider unchanged. These deterministic work
changes are not an FPS measurement or a guarantee against unrelated corruption.

The pre-Deferred footprint consists of exact splice preparation, the existing
reference and configured entry-hook preparations, and process-lifetime
bridge/provider/admission state inside the core's existing startup boundary.
The additional sparse reload bridge and the transaction/failure sequencing are
core-only; no new lazy owner, TLS, thread, parser, import API, configuration
field, or core/helper ownership move is introduced by the review correction.
The two independent entry transactions add temporary Vec/Box rollback records
only during startup. The sixth splice enlarges the existing patch/replacement
arrays and adds one bridge; the runtime introduces no new per-slot allocation
or synchronization owner. Configured entry hooks are prepared before writes,
and admission publication moves after their activation, within the same
quiescent phase.
Startup compatibility follows
[the owning safety contract](nvse_startup_phase_safety.md); static import/TLS
agreement does not itself prove a new Proton startup artifact accepted.

## Qualification and limits

The supporting fail-first regression executes the actual previous Rust
compaction and observes caller-slot mutation. Its repaired counterpart
executes production array admission through the real Win32 memory query.
The affected crate suite, supported `i686-pc-windows-gnu` release build,
compiled bridge/provider inspection, formatting, startup comparison, and
final diff review provide offline qualification. They do not execute the
modded native batch or reproduce the reporter's flight.
The existing hook-provider test executes the actual Win32 inline-hook chain
and restores both predecessors. It supports the ownership primitives used by
activation and rollback; it does not execute the sparse installer at game
addresses or establish an actual game startup failure-recovery result.

The repair closes the observed NULL dereference and its statically proven
successor NULL-consumption paths without replacing valid native work. It
removes Psycho's own unowned array mutation. The exact operation/thread which
introduced the incident's NULL, any allocator involvement, and mod attribution
remain unresolved. No claim of universal crash elimination, corrected non-NULL
UAF, accepted runtime behavior, or gameplay performance is made. The owner's
existing gameplay-validation waiver remains in force; no diagnostic-only run
or diagnostic artifact is required or provided. Changes remain undeployed
unless separately authorized.
