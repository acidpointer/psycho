# LowProcess save structural containment plan

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
engine invokes this specific LowProcess reference-cleanup virtual, and the
usual empty-list case adds one predictable branch. Serializer validation runs
only inside a synchronous save transaction, so it can affect the save hitch
but not ongoing frame time.

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
2. Repeated reference cleanup and cell transitions before saving.
3. A valid multi-node generic-location list: every entry must round-trip.
4. Fault injection for an invalid payload, invalid current node, invalid next
   link, and self-cycle: saving must finish and the resulting save must load.
5. No plugins: all four vanilla predecessors must be invoked exactly once.
6. The installed Stewie build without relying on its reported version.
7. Four synthetic executable predecessors, including mixed per-class targets:
   each must be invoked exactly once after contract enforcement.
8. A correct predecessor that already removes the entry: it must remain
   correct and must not double-remove or double-free anything.
9. Confirm no payload is freed by Psycho's LowProcess cleanup and no uncertain
   node is freed by save containment.
10. Run identical fixed-camera and traversal benchmarks before and after the
    change with diagnostics disabled; compare median and 99th-percentile frame
    time, not FPS rounded to an integer.
11. Confirm the main-task observation callsite has been restored after the
    bounded startup window and remains direct for the rest of the session.

UAF safety improves because every predecessor is denied access to the matching
borrowed reference. Structural containment may omit only corrupt
generic-location entries from a save. OOM behavior is unchanged. Performance
impact is limited to the cold cleanup path and save serialization, with no
steady-state frame hook.
