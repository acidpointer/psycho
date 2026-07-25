# LowProcess generic-location structural containment

This document owns the `engine_fixes.lowprocess_generic_locations_fix`
contract. The feature repairs corrupt `LowProcess::genericLocationsList`
state before live engine traversals and contains the same corruption during
save serialization. Its implementation is in
`psycho-engine-fixes/src/mods/engine_fixes/lowprocess.rs`; configuration is
owned by `psycho-engine-fixes/config/psycho_engine_fixes.toml`.

## Result

The 2026-07-17 autosave crash is the same LowProcess ownership failure first
observed on 2026-07-12. It is not caused by the durable-save owner hook.

The immediate fault is `FalloutNV.exe+0x5105AB` (`0x009105AB`) in
`FUN_00910450`, while serializing `MiddleHighProcess::genericLocationsList` at
process offset `+0x6C`. The current list contained two invalid payloads,
`0x0000000D` and `0x0101DE3C`, followed by an invalid next-node pointer
`0x00000003`.

The available Stewie Tweaks 9.90 and 9.95 sources both install
`LowProcess__Func011F` into all four LowProcess family vtables. Their
generic-location branch calls `GameHeapFree(gIter->data)`, even though
`gIter->data` is a borrowed `TESObjectREFR*`. Vanilla `FUN_0090CC10` removes
only the list node and never frees that payload. This identifies one confirmed
producer, but the fix must not identify or require Stewie.

Psycho currently pre-removes the matching entry before chaining the captured
predecessor and replaces invalid payloads with NULL at the save writer. That
protects new matching removals and preserves the save stream, but it does not
contain an already-corrupt list link. The save hook is at `0x009105BF`; the
game faults earlier at `0x009105AB` while dereferencing the invalid node
returned by the list accessor.

The Psycho frame at `0x100A7211` is the return address after
`hook_save_owner` calls the original save owner. It is not the faulting
instruction.

## 2026-07-25 live reference-removal crash

### Proven facts

The current executable is
`FalloutNV.exe` SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The supplied `psycho-engine-fixes/CrashLogger.log`, copied at
2026-07-25 15:24, records:

- fault EIP `0x0084E3A0`, with `ECX=0x0000000D`;
- return address `0x0090CF4B`;
- `MiddleHighProcess=0xE0A31900`;
- list head address `0xE0A3196C`, exactly `process + 0x6C`;
- a valid picked-up weapon reference and player object;
- the caller chain
  `JIP MoveToContainer -> ITR PlayerPickUp_Hook -> PlayerPickUpObject`.

Direct analysis of that exact executable proves:

- `0x0084E3A0` reads the TESForm form ID at `this + 0x0C`;
- `PlayerCharacter::PickUpObject` at `0x00953FF0` reaches
  `0x0096F450`, which dispatches process virtual slot `+0x480`;
- all four LowProcess-family `+0x480` slots point to vanilla
  `0x0090CDC0`;
- `0x0090CDC0` has ABI `thiscall(process, form_id)`, returns with
  `ret 4`, and scans the list at `process + 0x6C`;
- `0x0090CF43..0x0090CF4B` loads a list payload into `ECX`, calls
  `0x0084E3A0`, then compares the returned form ID.

The crashing payload was therefore the scalar `0x0000000D` stored where the
engine required a live `TESObjectREFR*`. The existing fix guarded cleanup
slot `+0x47C` and save serialization, but it did not guard this independent
live reference-removal slot.

The comparison source
`.research/itr-nvse-master/itr-nvse/handlers/OnPrePickUpHandler.cpp` detours
`0x00953FF0`, dispatches its event, and forwards the original
`picker, itemRef, count, playSounds` ABI. Inspection of the installed ITR and
JIP DLL call sites found the same correct argument forwarding. They exposed
the corrupt process list by invoking pickup; neither call site writes
`process + 0x6C`.

### Root cause and inference boundary

The direct root cause is invalid engine-owned list state surviving until
vanilla live traversal. ITR, JIP, and Just Loot Menu are triggers in this
trace, not the failed ownership contract.

Earlier source and binary evidence identifies a Stewie Tweaks cleanup hook as
one producer capable of freeing borrowed generic-location payloads. That is
not timestamp proof that Stewie created this particular `0x0000000D` entry.
The runtime fix consequently makes no decision based on Stewie, ITR, JIP, or
any other module.

### Implemented live-traversal containment

The same bounded startup observer now wraps both engine virtual contracts for
all process classes:

| Class | Cleanup `+0x47C` | Reference scan `+0x480` |
|---|---:|---:|
| HighProcess | `0x01087CE0` | `0x01087CE4` |
| LowProcess | `0x01088B60` | `0x01088B64` |
| MiddleHighProcess | `0x010894C8` | `0x010894CC` |
| MiddleLowProcess | `0x0108A048` | `0x0108A04C` |

Each slot is independent. Installation captures any currently executable
target, publishes it before replacing the slot, and chains it exactly once
after sanitation. Vanilla `0x0090CDC0` is used only as the recursive or
missing-predecessor fallback. There is no module enumeration, filename,
version, hash, RVA, or byte signature for a third-party DLL.

Before a reference scan receives `process, form_id`, the wrapper runs the
existing bounded structural sanitizer with no `removed_ref`. Invalid
payloads and bad links are detached before `0x0090CF46` or an equivalent
third-party predecessor can dereference them. Valid entries and the original
arguments are preserved.

The live guard performs no allocation or deallocation. Because
`removed_ref` is NULL, it cannot enter the native list-node removal branches;
corrupt nodes are orphaned by pointer repair rather than passed to an
allocator with uncertain ownership. The guard therefore has the same
behavior under allocator mode 0 (vanilla heap), mode 1 (scrap heap only), and
mode 2 (gheap plus scrap heap). The captured predecessor retains its normal
allocator behavior.

The normal empty-list path remains two direct NULL reads. Non-empty lists are
bounded to 256 nodes and use stack-local page-region caches. The startup
observer restores its main-loop call site after 120 observations, leaving no
per-frame hook.

## Fix

### 1. Enforce ownership before every cleanup predecessor

Keep the existing mod-independent four-slot wrapping model:

1. Observe each LowProcess-family vtable slot independently after plugins have
   installed their hooks.
2. Accept any committed executable target as that slot's predecessor.
3. Publish the predecessor before replacing the slot with the corresponding
   Psycho wrapper.
4. Never branch on module name, DLL version, image timestamp, RVA, or function
   byte signature.

The late boundary must run after normal plugin hook installation. During the
bounded observation window, report any later slot replacement. An arbitrary
mod that overwrites a slot after this boundary without chaining the previous
target cannot be composed safely; do not fight it with permanent per-frame
rewrites.

Once the observation window reaches a terminal state, restore the main-task
drain callsite to its captured predecessor. The startup observer must remove
itself so there is no extra wrapper, atomic load, or indirect branch in the
steady-state main loop.

Before invoking any predecessor, normalize `process + 0x6C` according to the
vanilla `tList<TESObjectREFR>` contract:

- first read the embedded head's payload and next link directly; if both are
  NULL, immediately call the predecessor without memory queries or traversal;
- rely on the live process virtual-call contract for the embedded head and
  validate every successor node before reading it;
- cache `data` and `next` once per node;
- remove every occurrence of `removed_ref` with the proven vanilla list
  helpers, which free only list nodes;
- remove invalid payload entries without ever freeing the payload;
- validate a next link before advancing;
- truncate at the last proven-good node on an unreadable, unaligned, cyclic,
  or over-budget link, without dereferencing or freeing the uncertain tail.

Only call the captured predecessor after the list is structurally safe and no
matching borrowed reference remains. A correct predecessor sees the same
post-removal state vanilla would have produced. An unsafe predecessor can no
longer find and free the borrowed reference. If the predecessor is missing,
non-executable, or recursive, call vanilla `FUN_0090CC10` as the existing safe
fallback.

The structural walk must be allocation-free and bounded. It runs only on the
cold reference-cleanup path, not per allocation or per frame.

Do not call `VirtualQuery` for every node. Keep a small stack-local cache of
validated committed regions and reuse their `[base, end)` ranges for
subsequent nodes. Query the OS only when an address falls outside those cached
regions. The normal empty-list path performs no memory query.

### 2. Contain structurally corrupt lists during save

Keep `checked_append_ref_id` at `0x009105BF` for readable list nodes with bad
payloads. Add checked wrappers to the two list traversal calls in the same
serializer:

- `0x009105A6`: checked data-node accessor. Return a stable NULL cell when the
  current node is not readable.
- `0x009105D0`: checked next-node accessor. Return NULL when the current node
  or its next link is null, unaligned, unreadable, cyclic, or beyond the
  per-serialization traversal budget.

Returning NULL terminates or skips only the corrupt part of this list. It does
not mutate the live process object, does not free uncertain memory, and leaves
the serializer's existing element-count patching intact. Valid entries and
all other process fields retain vanilla behavior.

Establish an allocation-free per-serialization traversal context at the
`FUN_00910450` owner boundary so the accessors can detect cycles and enforce a
finite node budget without scraping caller frames.

Use a small fixed table of contexts claimed by thread ID. Do not use Rust's
standard `thread_local!` storage here: the Windows-GNU backend allocates its
cell on first access, which would move an allocation into the first save.

Install each wrapper only after verifying the exact `E8 rel32` callsite.
Capture and chain any valid executable current target for the normal path, as
`checked_append_ref_id` already does. Do not require the target to belong to
FalloutNV.exe or a known plugin.

These checks execute only while the game is serializing a save. They must not
be installed at a shared `tList` helper entry because that would tax every list
operation in the game. Patch only the three audited calls inside
`FUN_00910450`.

### 3. Add crash-relevant diagnostics

Record monotonic counters for:

- cleanup predecessor calls and fallback calls;
- cleanup-time invalid payloads removed;
- cleanup-time invalid links truncated;
- invalid payloads encoded as NULL;
- invalid current nodes skipped;
- invalid next links truncated;
- cycles and traversal-budget terminations;
- callsite verification failures.

For structural failures, log the current node, next value, thread id, and
cumulative count with power-of-two sampling. The payload wrapper keeps its
existing writer and form fields. Do not scrape caller frames for process or
writer data that these callsite ABIs do not provide, and do not log on the
valid path.

## Performance contract

The fix is acceptable only with all of these properties:

- zero permanent hooks in the per-frame main-task drain after startup;
- zero changes to render, AI, Havok, allocator, or general `tList` hot paths;
- zero heap allocations and zero locks in cleanup and save containment;
- zero module discovery, version checks, symbol lookup, or byte scanning after
  installation;
- one direct NULL fast-path check for the usual empty generic-location list;
- expensive page validation only for non-empty or suspicious lists, with
  committed-region caching;
- anomaly logging only, sampled at powers of two;
- relaxed atomics only for cold diagnostic counters.

This produces no recurring FPS cost. Normal gameplay pays only when the
engine invokes the specific LowProcess cleanup or reference-removal virtual,
and the usual empty-list case adds one predictable branch. Serializer
validation runs only inside a synchronous save transaction, so it can affect
the save hitch but not ongoing frame time.

Reject the implementation if an A/B benchmark shows a reproducible increase
above `0.01 ms` in median or 99th-percentile gameplay frame time. Also record
save duration; the valid-list path should add less than `1 ms` to a normal
save and must scale linearly with the number of generic-location nodes.

## Verification

Build only the supported i686 target, then test allocator modes 0, 1, and 2.
The result must be identical whether Stewie is absent, an unknown Stewie build
is present, or another plugin owns one or more predecessors.

Required runtime cases:

1. Autosave, quicksave, and manual save in the reported Megaton cell.
2. Repeat the reported Just Loot/JIP/ITR pickup path with an injected
   `0x0000000D` generic-location payload; pickup must finish and the sampled
   invalid-payload counter must increase.
3. Repeat the same pickup with ITR absent, with the installed ITR build, and
   with a synthetic executable `+0x480` predecessor; each predecessor must be
   invoked exactly once.
4. Repeat cases 1-3 under allocator modes 0, 1, and 2.
5. Repeated reference cleanup and cell transitions before saving.
6. A valid multi-node generic-location list: every entry must round-trip.
7. Fault injection for an invalid payload, invalid current node, invalid next
   link, and self-cycle: saving must finish and the resulting save must load.
8. No plugins: all four vanilla predecessors must be invoked exactly once.
9. The installed Stewie build without relying on its reported version.
10. Four synthetic executable predecessors, including mixed per-class targets:
   each must be invoked exactly once after contract enforcement.
11. A correct predecessor that already removes the entry: it must remain
   correct and must not double-remove or double-free anything.
12. Confirm no payload is freed by Psycho's LowProcess cleanup and no uncertain
   node is freed by save containment.
13. Run identical fixed-camera and traversal benchmarks before and after the
    change with diagnostics disabled; compare median and 99th-percentile frame
    time, not FPS rounded to an integer.
14. Confirm the main-task observation callsite has been restored after the
    bounded startup window and remains direct for the rest of the session.

Implementation validation on 2026-07-25:

- the regression contract failed before implementation because the four live
  slots, wrappers, and guard did not exist;
- all three focused live-reference-scan tests pass on the supported target,
  including direct sanitation of a fake `0x0000000D` payload;
- all 62 `psycho-engine-fixes` tests pass under Wine for
  `i686-pc-windows-gnu`;
- the `psycho-engine-fixes` release target builds successfully for
  `i686-pc-windows-gnu`;
- release disassembly confirms all four wrappers preserve the process in
  `ECX`, push the original form ID for their predecessor, and return with
  `ret 4`.

The allocator-mode matrix and in-game cases above remain runtime acceptance
work. Compilation and a fake-list regression prove the intervention logic,
not Proton gameplay behavior.

UAF safety improves because every predecessor is denied access to the matching
borrowed reference. Structural containment may omit only corrupt
generic-location entries from a save. OOM behavior is unchanged. Performance
impact is limited to the cold cleanup path and save serialization, with no
steady-state frame hook.
