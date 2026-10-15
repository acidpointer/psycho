# Mod-independent revision plan for the 2026-07-12 crash fixes

## Objective

Remove all mod-name, mod-version, PE timestamp, image-size, and module-owner
requirements from the two engine fixes. Enforce the proven engine contracts
while chaining any valid hook already installed at the affected point.

This plan supersedes the earlier version-bound LowProcess restoration and
function-entry task release hook. The save containment and positive-only task
dispatch pin remain valid.

`crash_20260712_mod_independent_chain_contract_audit.txt` closes all remaining
static research gates for this revision.

## Implementation status

Implemented in `psycho-engine-fixes` on 2026-07-13:

- per-vtable LowProcess predecessor capture and ownership wrapper;
- generic chaining of the save serializer and main-loop observation boundary;
- holder-call queued-task release chaining at `0x0044CC04`;
- executable private/image callback and predecessor support;
- independent dispatch-block conflict handling and diagnostics;
- idempotent call-chain installation.

The supported i686 release build passes. Runtime validation in Fallout NV/TTW
remains required.

## Compatibility guarantees

The revised implementation must handle:

- no NVSE/xNVSE mods;
- an entirely vanilla vtable;
- one mod replacing all four LowProcess slots;
- different mods replacing different slots;
- a correct replacement that already follows vanilla ownership;
- Stewie 9.90/9.95's unsafe replacement;
- an existing queued-task release detour or trampoline;
- executable callbacks and trampolines in either image or private executable
  memory.

It must never identify behavior from a DLL filename or version. Unknown code is
chained only when its entrypoint is readable and executable.

## LowProcess: chain-compatible contract wrapper

### Fixed engine layout

The four affected entries are the same virtual slot, index `0x11F` / byte
offset `0x47C`, in four related vtables:

| Class | Vtable base | Slot `+0x47C` |
|---|---:|---:|
| HighProcess | `0x01087864` | `0x01087CE0` |
| LowProcess | `0x010886E4` | `0x01088B60` |
| MiddleHighProcess | `0x0108904C` | `0x010894C8` |
| MiddleLowProcess | `0x01089BCC` | `0x0108A048` |

All vanilla slots point to `FUN_0090CC10`. The virtual ABI is
`thiscall(process, removed_ref)` with one stack argument.

### Installation

At the existing core-owned late main-loop boundary, process every slot
independently:

1. Read its current target.
2. If it already points to Psycho's wrapper, leave the stored predecessor
   unchanged.
3. Require the current target to be committed executable memory. Do not require
   `MEM_IMAGE` or FalloutNV.exe ownership.
4. Publish that target into the predecessor entry corresponding to the vtable
   base.
5. Re-read the slot; retry or abort that slot if it changed.
6. Replace only that slot with Psycho's wrapper.
7. Read it back and report per-slot `wrapped`, `already_wrapped`, or
   `unsupported` status.

Mixed targets are normal. A failure on one class must not prevent the other
three classes from being wrapped.

Use four `AtomicUsize` predecessor entries. Publish with `Release` before the
vtable write; the wrapper reads with `Acquire`. Installation occurs on the game
main thread. Observe the slots for a bounded startup window so a late plugin
write is captured, then stop polling. A later mod that chains Psycho remains
compatible; an arbitrary late overwrite that does not chain cannot be repaired
without fighting the other mod and is logged only.

### Wrapper behavior

The wrapper enforces only the broken ownership boundary before calling the
captured predecessor:

1. Identify the predecessor from `process->vtable`.
2. Remove every matching `removed_ref` entry from
   `process + 0x6C` (`genericLocationsList`).
3. Free list nodes according to the vanilla `tList` contract.
4. Never free the `TESObjectREFR*` payload.
5. Call the captured predecessor with the original `process` and `removed_ref`.

Use the exact vanilla loop contract proven by Ghidra:

```text
current = process + 0x6C
previous = NULL

while current != NULL and current->data != NULL:
    payload = current->data
    if payload == removed_ref:
        if previous == NULL:
            FUN_0063F7B0(current)
        else:
            FUN_00905330(previous, &payload)
            current = FUN_00726070(previous)
    else:
        previous = current
        current = FUN_00726070(current)
```

Helper ABIs:

- `FUN_0063F7B0`: `fastcall(node)`; removes the embedded head by copying the
  next node or clears head data when no next node exists.
- `FUN_00905330`: `thiscall(previous_node, &payload)`; removes the matching
  node after/from `previous_node`, frees only the list node, and returns with
  `ret 4`.
- `FUN_00726070`: `fastcall(node) -> node->next`.

`FUN_0063F7B0` and `FUN_00905330` free removed nodes through the game's normal
node destructor path. Neither helper frees the payload.

Pre-removal makes the unsafe Stewie branch a no-op while leaving its handling
of owned `ObjectToAcquire` records and other fields intact. Vanilla and already
correct hooks see the list in the state their own cleanup would have produced.

If predecessor lookup fails, the predecessor equals the Psycho wrapper, or the
predecessor is no longer executable, call vanilla `FUN_0090CC10` as the safe
fallback. Never recurse.

Do not hand-write node copying/freeing. Call the proven vanilla helpers so node
ownership stays identical to the engine.

### Save containment

Keep the existing direct-call containment at `0x009105BF`. It is already
mod-independent because it validates the data contract rather than the owner of
`FUN_00865DF0`:

- valid forms pass through;
- invalid non-NULL forms become NULL;
- the original/current serializer entry is still called;
- list count and stream alignment remain unchanged.

Do not require a Stewie module to install this containment.

## Queued tasks: contract-based chaining

### Dispatch guard

Keep the positive-only CAS pin at the exact vanilla dispatch block
`0x00446C48..0x00446C55`.

Revise validation:

- task and refcount must be readable/aligned;
- refcount must be strictly positive for the CAS;
- reject known dead/base `NiRefObject` vtable `0x0101DCE4`;
- vtable and slot `+0x1C` must be readable;
- callback memory must be committed and executable;
- accept both `MEM_IMAGE` and executable `MEM_PRIVATE` trampolines;
- reject a gheap free cell when metadata is available.

The instruction block itself can only be replaced when its complete vanilla
fingerprint matches. If another mod already changed the block, leave it
untouched and log a precise conflict. There is no safe generic way to compose
with an unknown rewritten instruction sequence.

### Release chaining at the precise holder call

Stop inline-hooking the `FUN_0044DD60` function entry. Function-entry ownership
conflicts with any other mod that detours the same release routine.

Instead intercept the direct release call inside `FUN_0044CBF0` at
`0x0044CC04`:

1. Require a direct `E8 rel32` call, but do not require its current destination
   to be vanilla.
2. Resolve and validate the current destination as committed executable code.
3. Store it as `previous_task_release`.
4. Replace the call destination with Psycho's checked release wrapper.
5. The wrapper validates the task/refcount/final destructor and then calls
   `previous_task_release` for valid states.

This composes with vanilla, an existing mod release hook, or a trampoline. The
holder wrapper still owns its original NULL check and stack behavior.

The audited vanilla bytes are:

```text
0x0044CBFF  8B 4D FC             mov ecx,[ebp-4]
0x0044CC02  8B 09                mov ecx,[ecx]
0x0044CC04  E8 57 11 00 00       call 0x0044DD60
```

At `0x0044CC04`, `ECX` is the non-NULL task and the release target is a
`fastcall(task)` function. Patch only the five-byte call displacement after
verifying opcode `E8` and validating the resolved current target.

Psycho's temporary dispatch pin must be released through the same checked
wrapper, which then chains the captured destination. Avoid calling the
`0x0044DD60` address directly because it may itself be detoured.

### Optional tracing

Keep the fixed allocation-free ring. Use a dedicated naked holder-call shim
that reads `[EBP+4]` before any Psycho prologue; the audited holder wrapper has
an active EBP frame, so this captures the caller of `FUN_0044CBF0`, not merely
the internal return address `0x0044CC09`. Psycho's dispatch-pin release calls a
separate Rust entry with the known dispatch callsite as provenance. Record the
resolved predecessor release target as well as the caller. Tracing remains
disabled by default.

## Required code changes

### `engine_fixes/lowprocess.rs`

- Remove Stewie build structs, PE parsing, module enumeration, and the 9.90/9.95
  allowlist.
- Add four vtable-base constants and four predecessor atomics.
- Replace `restore vanilla` with per-slot `capture and wrap`.
- Add the exact generic-list pre-sanitizer after the Ghidra helper audit.
- Replace one global repair state with per-slot statuses.

### `engine_fixes/queued_tasks.rs`

- Remove `TASK_RELEASE_HOOK` and function-entry trampoline ownership.
- Add `previous_task_release: AtomicUsize`.
- Patch and chain the direct call at `0x0044CC04`.
- Relax callback/destructor validation from image-backed executable to any
  committed executable page.
- Keep the CAS pin, base-vtable rejection, gheap state check, and caller trace.

### `engine_fixes/statics.rs` and `types.rs`

- Add the four vtable bases and slot offset.
- Remove task-release inline-hook storage/prologue fingerprint.
- Add the holder-release callsite and its audited bytes.
- Keep the exact dispatch and save-call fingerprints.

### `engine_fixes/patching.rs`

Add a helper that:

- verifies opcode `E8`;
- resolves the currently installed relative target;
- validates the target before storing it;
- rewrites only the relative displacement;
- flushes the instruction cache.

This helper deliberately accepts a non-vanilla current target for chaining.

### Configuration

Keep the public settings generic:

```toml
[engine_fixes]
lowprocess_generic_locations_fix = true
queued_task_lifetime_guard = true
```

Remove all user-visible text implying that either fix requires Stewie. Mention
Stewie only as one known producer of the broken state.

## Failure isolation

- Save containment is independent of vtable wrapping.
- Each process class wraps independently.
- An invalid predecessor falls back to vanilla only when that class's wrapper
  runs.
- A task dispatch-block conflict disables only dispatch interception.
- A holder-release call conflict disables only release interception.
- No unknown instruction block or non-executable pointer is overwritten.
- No failure aborts allocator startup or unrelated engine fixes.

## Validation matrix

Test allocator modes 0, 1, and 2 with:

1. No Stewie and no competing hooks.
2. Stewie 9.90 and 9.95.
3. One synthetic slot replacement; other three vanilla.
4. Four different synthetic predecessor targets.
5. A correct predecessor that already removes the generic list safely.
6. An existing task-release detour at the `0x0044CC04` call destination.
7. A callback thunk in executable `MEM_PRIVATE` memory.
8. A deliberately rewritten task dispatch block to verify fail-closed behavior.

For every LowProcess case, verify predecessor invocation count is exactly one,
the matching list entry is gone, list nodes remain valid, and the referenced
`TESObjectREFR` payload was not freed.

For queued tasks, verify positive pin balance, unchanged callback argument,
release predecessor invocation exactly once, queue progress, and rejection of
zero/negative tasks without resurrection.

## OOM, UAF, and performance balance

- **OOM:** unchanged. Node removal uses the same vanilla list-node lifetime and
  does not alter allocator cleanup stages.
- **UAF:** non-owned form payloads are protected before any predecessor runs;
  zero/negative task counts and known free pool cells are rejected. These
  checks do not establish task identity after allocation reuse; see below.
- **Performance:** LowProcess cleanup is cold. Task dispatch retains one
  refcount CAS and pointer validation. Tracing is opt-in. No per-allocation work
  is added.

## Random crash: reference-map lifetime and callback ABI

### Runtime evidence

The owner reported a random crash after extended play, observed while entering
the metro. That transition is context, not a reproducible trigger. The owner
explicitly requires static analysis only, with no diagnostic builds or further
runtime evidence collection. The preserved evidence is:

- [Crash report](../.reports/CrashLogger-20261014-180039-cell-transfer.log)
- [Psycho runtime log](../.reports/psycho-engine-fixes-20261014-180039-cell-transfer.log)
- [Focused binary audit](../analysis/radare2/output/crash_20261014_metro_task_reuse_abi_audit.txt)
- [Reference-map static audit](../analysis/radare2/output/crash_20261014_refmap_lifetime_static_audit.txt)
- [Candidate ABI and ownership audit](../analysis/radare2/output/crash_20261014_task_binding_candidate_static_audit.txt)

The runtime log identifies allocator mode 2, dispatch and release guards active,
and task lifetime tracing disabled. At `14:39:43.700Z`, dispatch rejects
`0xC9C58520` with a negative word at `+0x08`; the release guard records vtable
`0x01097314` at that address. Later releases repeatedly encounter the same
address. Beginning at `14:42:20.153Z`, the guard reports it as a free 80-byte
pool cell and writes its dead-task marker. The final sampled free-cell
rejection is at `14:59:19.179Z`.

The crash report later identifies `0xC9C58520` as a
`NiTextureTransformController`, vtable `0x01098184`, with reference count 1.
It records `ESI = 0x00ACBB70`, `ECX = 0xC9C58528`, and
`EIP = 0x0170F605`, close to `ESP = 0x0170F5C0`. The player cell is the
attached Chevy Chase/Vernon Square Metro. This establishes that an address
repeatedly presented as a task and previously observed free is later occupied
by an unrelated live object. An allocated cell is therefore insufficient
evidence of the original task's lifetime.

The first recorded engine return address is `0x0054835D`. In the supported
executable it follows the virtual `+0x228` call inside
`TESObjectCELL::AddReference`. The next recorded address, `0x0093C02A`, follows
a call to `0x0093C200`. The report also records a DbgHelp access-denied error;
these frames do not prove that either virtual call supplied the final invalid
callback. No crash-time dump or final successful dispatch record is available.

### Binary proof and failure mechanism

Research reconfirmed the supported executable identity recorded in the native
parallel IO contract: PE32 x86, image base `0x00400000`, timestamp
`0x4E0D50ED`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Radare2 MCP verified the native addresses and the actual deployed dispatcher.

Native dispatch `0x00446C48..0x00446C55` passes one stack argument to virtual
slot `+0x1C`. `TaskCallbackFn` declares that call as `thiscall`; the selected
callback must consume four argument bytes. Native task release `0x0044DD60`
decrements the task's word at `+0x08`. A `NiObject` instead has its reference
count at `+0x04`, as documented by the xNVSE bindings. The controller's
`+0x08` word is not the task reference count.

The production guard has two distinct gaps:

1. `gheap::pool::pin_task_refcount_locked` establishes a committed, issued,
   exact, allocated cell and increments a positive word at `+0x08`. It does
   not establish allocation generation or task type. The non-gheap path has
   the same type assumption. Pinning a word in a reused object does not retain
   the retired task or its current replacement.
2. `queued_tasks::read_callback` accepts an executable slot `+0x1C` without
   proving that it implements the task callback ABI. The controller's slot
   contains `0x00ACBB70`, a zero-returning stub ending in plain `RET`. It
   passes this executable-page check but consumes no stack argument.

The deployed `checked_dispatch` pushes its argument before the indirect call,
then releases the temporary pin and restores saved registers using fixed
stack offsets. A plain `RET` leaves four extra bytes on that stack. Its
epilogue then reads the callback local into ESI and shifts the saved-register
and return slots. The reported `ESI = 0x00ACBB70` is the callback local value
for this controller. Its final release would address the controller's
`+0x08` word, matching the reported ECX. These are concrete consequences of
the verified machine code, not a proof that the unrecorded final dispatch
actually occurred in this crash.

### Native reference-map owner and earlier mutation

The protected `0x00446B50` path is a ModelLoader reference-map traversal used
to update task priorities. It is not a completed-task dequeue. ModelLoader
initialization publishes the map at `+0x08` through `0x0044275E`; constructor
`0x0044B750` installs native map interface `0x0101747C`. Its typed lookup
provider is `0x0044BD60`, and its removal provider is `0x009062E0`.

The consumer calls `0x00906570` on this map. Its iterator returns a borrowed
reference key and a separately retained task value. First acquisition
`0x00906AF0` calls `0x0092C820` at `0x00906BC8`; next acquisition
`0x00906C10` does so at `0x00906CAE` and `0x00906D5F`. Typed lookup
`0x0044BD60 -> 0x0044C8E0 -> 0x0044D510` does so at `0x0044D546`.
The assignment helper calls `0x0092C870`, which unconditionally increments
`value + 0x08`. All these mutations precede the Psycho dispatch guard.

The native iterator does not remove a binding when it returns its task.
Psycho's current rejection path also does not remove or invalidate that
binding. This exposes a persistent stale association to later iteration and
allocation reuse, rather than containing it at its owner. The supplied log
proves repeated rejected deliveries of the same address over approximately
twenty minutes; it does not identify the map key or the initial invalidation.

Native lookup and iteration already acquire a reference. Their wrappers and
normal map modification acquire the same recursive exclusive lock at
`map + 0x20`, through `0x0040FBF0` and `0x0040FBA0`. Therefore neither a
missing iterator retain nor missing normal-map mutual exclusion is established
as the cause. The collector also preserves nodes present in its published
hazard snapshot. Moving ownership release, adding a map lock, or changing
worker topology has no patch authority from this incident.

### The negative word belongs to an interpolator

Static MSVC type metadata identifies `0x01097314` as
`NiTransformInterpolator`, not a task. The complete object locator is
`0x011232C0`, and type descriptor `0x011A8560` contains that exact class name.
Its constructor chain is
`0x00A3FA30 -> 0x00A3CA10 -> 0x00A56FF0 -> 0x00A5D3A0`.
The base constructor initializes the real reference count at `+0x04`.
`0x00A56FF8..0x00A56FFE` initializes `+0x08` with floating-point instructions
from constant `0x01015F5C`, whose bits are `0xFF7FFFFF`.

The first logged supposed task count, `-8388608`, has bits `0xFF800000`:
exactly one integer increment above that floating-point initializer. Subsequent
logged values progress through nearby integer values while the vtable remains
the interpolator's. This is wrong-layout access to a non-task object's
floating-point word, not evidence that an engine task counter overflowed.
The unconditional native retain is an executed predecessor of the reported
dispatch rejections; the positive-only Psycho pin cannot correct it afterward.

The later controller has independently verified MSVC type metadata at
`0x011239E8`, with type descriptor `0x011A88E8`. Native `QueuedReference`
metadata at `0x01105AB0` includes `BSTask<__int64>` in its ancestry; base
descriptor `0x011056E0` names task type descriptor `0x01185594`. These
structures provide concrete engine type information for admission research,
without identifying a module or allowlisting code/vtables. Metadata alone does
not pin an object or prove that it belongs to the current map binding. Missing
or unfamiliar provider metadata must not be guessed to mean an invalid task.

### Containment requirements and qualification boundary

1. Place containment before the native owning acquisition, covering both
   typed lookup and first/next iteration. Reject proven incompatible layouts
   and invalid counts, and establish the current reference-map binding before
   clearing its value. Use
   guarded snapshots through the existing core-only memory reader for external
   data; a readable allocation and an executable slot are insufficient.
   Complete native caller, output-holder, cursor, and provider-chain coverage
   before choosing the instruction seam. In particular, an iterator rejection
   must skip only the invalid entry and preserve valid entries in its bucket.
2. Prove an owner-side way to retire an invalid association without retaining,
   decrementing, or destroying its replacement object. Preserve the native
   map's node, hazard, and valid-value ownership rules. Returning a lookup miss
   while leaving the old binding in place is insufficient: reconstruction must
   be able to publish a new valid task. Do not use direct node surgery or add a
   speculative retain, lock, allocator change, or time-based purge.
3. Keep valid provider calls, callback arguments, reference balance, and
   priority semantics unchanged in allocator modes 0, 1, and 2. Preserve
   legitimate plugin task classes and executable trampolines without module
   detection or vtable/code allowlists. Review the dispatch and release
   boundaries for remaining wrong-layout accesses; a stack-cleanup-only change
   leaves earlier native object mutation intact.
4. Qualify the authorized production candidate statically:
   verified executable contracts and caller coverage, all affected ABI paths,
   deterministic work and ownership budgets, explicit supported
   `i686-pc-windows-gnu` release build, formatting, and diff review. This work
   does not schedule runtime tests, diagnostic builds, tracing, or evidence
   collection from the owner. Compilation and static proof do not establish
   accepted gameplay behavior.

The proven containment defect is persistent delivery of an invalid reference-map
value through an unconditional native retain, followed by a guard that neither
establishes type/binding identity nor corrects the owner. The final accepted
dispatch, original invalidating operation, exact lifetime interleaving,
allocator attribution, and mod attribution remain unresolved. No capacity
overflow or engine-wide overload has been established in this path. Those
unknowns are limits of the present evidence, not requests for further runtime
collection. The implementation below is an unreleased static candidate; no
gameplay or startup acceptance is claimed.

### Implemented reference-map containment

`queued_tasks/model_task_bindings.rs` is a private child of the existing
queued-task lifetime guard. The `engine_fixes.queued_task_lifetime_guard`
setting controls acquisition containment together with dispatch and release;
false skips installation of all three stages. It adds four chained
assignment callsites and two chained outer entry hooks in one ownership-aware
transaction. Providers are captured before activation, outer scope hooks are
activated first, and admission is published only after commit. An unadmitted
rollback survivor forwards through its captured provider.

Owner-side changes apply to the published `ModelLoader + 0x08` map. The
singleton word is `0x011C3B3C`; native `0x0094CFD0..0x0094CFD6` loads it and
calls the audited priority consumer. The map's keys are opaque reference
addresses. Hash `0x0044CAA0`, copy `0x0044CAC0`, ordering `0x0044C1C0`, and
equality `0x006B81D0` operate on the word without dereferencing a reference.
These shared iterator templates also serve other maps: their providers are
preserved, and no unproven key lifetime is used for deferred erasure.

The complete existing native iterator caller set is recorded in the unchanged
[task audit](../analysis/ghidra/output/crash/crash_20260712_task_base_vtable_race_audit.txt):
`0x0044849A`, `0x0044851B`, `0x0044858F`, `0x004456F6`, `0x0052802C`,
`0x0052817C`, `0x00528263`, `0x00528340`, `0x00446BC3`, and `0x00905EC0`.
The historical "pop" label in that output does not describe this operation.
Typed lookup is reached through the reference-map virtual slot `+0x08` and
`0x0044C8E0`; the guard is before its owning assignment.

| Assignment CALL | Native context local | Selected node | Return slot | Rejection tail | Native result |
|---|---|---|---|---|---|
| `0x00906BC8` | `EBP - 0x10` | context `+0x14` | `EBP - 0x1C` | `0x00906BFB` | AL = 1, empty output |
| `0x00906CAE` | `EBP - 0x08` | context `+0x18` | `EBP - 0x10` | `0x00906DA4` | AL = 1, empty output |
| `0x00906D5F` | `EBP - 0x08` | context `+0x14` | `EBP - 0x10` | `0x00906DA4` | AL = 1, empty output |
| `0x0044D546` | `EBP - 0x08` | context `+0x14` | `EBP - 0x10` | `0x0044D56D` | AL = 0, previous output preserved |

Each naked shim captures the caller's EBP in EDX and jumps to
`fastcall(destination, frame, source)`. This preserves the original
`thiscall(destination, source)` four-byte stack consumption. The compiled
shim bodies end in `RET 4`; outer lookup consumes eight argument bytes and
iteration consumes sixteen. Installation fingerprints the native local setup,
source/output argument setup, and complete cleanup epilogues before writing
any callsite. Every tail invokes native `0x00529000` to clear its three hazards.

Admission uses guarded copies of the external task header and MSVC32 RTTI.
NULL, misaligned, unreadable, non-positive, or saturated `+0x08` counts are
rejected. A supported complete-object locator and class hierarchy reject a
`NiObject` base at the current object view when no `BSTask<__int64>` base is
present at that view. Semantic base descriptors and exact mangled names are
used; vtables, callback code, modules, and allocators are not allowlisted.
Missing metadata, an unreadable descriptor, unsupported constructor/virtual
base layout, or ancestry above the bounded scan remains unknown and chains the
provider. A proven task view also chains it unchanged. This cannot establish
allocation generation or exclude a stale association to another valid task.

Before invalidating a binding, the guard verifies the selected node is exactly
the source holder's node, its value still equals the rejected snapshot, the
context's owning map matches an active reference-map scope, and this thread
owns the native exclusive lock at `map + 0x20`. It clears only node `+0x04`.
It does not release, retain, or tombstone the replacement object, and it does
not edit node links. Iteration clears its local output through the native
holder setter only when that prior output is a valid task; invalid outputs
are cleared without decrementing unrelated data. Lookup preserves the native
false-result output contract.

Native erase reuses the same per-thread cursor, so it cannot run inside the
assignment or hazard-cleanup frame. Per-thread scopes stage rejected keys in
the oldest active call for that same map. Other-map receivers are never saved
beyond their owning call. Once all native acquisition frames for that map have
returned, cleanup reacquires native `0x0040FBF0`/`0x0040FBA0`, obtains the
existing context with `0x00449F80`, hashes through the current map slot, and
performs a non-owning `0x00529030` search. Only an exact, still-empty key is
erased through the current map slot `+0x14`, after resetting search hazards.
A valid value published before the locked recheck is preserved. Native
`0x005292A0` encounters an empty holder and retains ownership of unlinking,
retiring, and collecting the node.

Iteration keeps its saved key and continues until it finds a retained task or
the original iterator reports exhaustion. Native next-iteration's missing-key
branch uses the next current node, so deleting a rejected key preserves the
remaining entries in that bucket. A top-level lookup miss completes cleanup
before returning, allowing `0x00444850` to construct and insert a new task.
That matters because `0x0044D070` refuses a duplicate key when overwrite is
false. A nested same-map miss defers repair until its enclosing cursor returns;
the native duplicate-insertion failure remains intact in that interval.

The existing dispatch and holder-release guards also perform layout admission
before pinning or decrementing `+0x08`. Existing valid callback arguments,
temporary pin balance, and captured release providers are preserved. The
allocator implementation, IO worker topology, map registration capacity,
configuration layout, helper ABI, and startup phase order are unchanged.

### Costs, failures, and static qualification

Valid reference-map acquisition adds two guarded owner-word copies, a TLS
lookup, bounded stack initialization, and task admission. A common native task
view needs six complete guarded copies: header, locator pointer, locator,
hierarchy, base array, and terminal task base. Dispatch and guarded release
each add the same admission work; this is a CPU cost, not an FPS measurement.
Other metadata scans are bounded to 64 bases and use fixed buffers. There is
no routine heap allocation, new valid-path lock, file IO, shader work, or trace
stream. Cold rejection uses the existing native lock and map operations.

One dynamically resolved Win32 TLS index is allocated during existing core
startup. Each participating thread allocates one four-byte, process-lifetime
scope-head owner on first use. Stack pointers are stored inside that owned
word, so scope restoration cannot fail through `TlsSetValue`. Up to 64 keys
are staged per owning stack scope. Allocation/publication failure or staging
overflow rejects the invalid acquisition without clearing its node; a later
acquisition can retry repair. Read/contract/native-erase failure cannot justify
forced deletion or reference-count mutation. Rare rejection and repair-failure
warnings use the existing logger, with no diagnostic build or new tracing.

The complete supported `i686-pc-windows-gnu` release set builds. Formatting and
diff checks pass. Radare2 inspection of the compiled candidate confirms all
four shim stack contracts, native-frame result/return writes, outer scope
restoration, iterator continuation, and non-owning cleanup before erasure.
The core and helper retain the deployed baseline's import/export sequences and
TLS callback contracts. The new startup-owned hook containers, admission
state, TLS slot preparation, and generated core code remain a real startup
footprint delta. Static agreement does not establish startup compatibility.

No tests execute under the owner's static-only instruction. Neither gameplay,
startup integration, image output, nor workload performance has been run.
The original invalidating owner and exact lifetime interleaving remain unknown.
This is a built containment candidate for the proven invalid-value path, not
runtime acceptance or proof that every random crash has the same cause.
