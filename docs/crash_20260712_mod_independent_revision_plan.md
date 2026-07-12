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
- **UAF:** improved without identifying a mod. Non-owned form payloads are
  protected before any predecessor runs; dead tasks cannot be pinned.
- **Performance:** LowProcess cleanup is cold. Task dispatch retains one
  refcount CAS and pointer validation. Tracing is opt-in. No per-allocation work
  is added.
