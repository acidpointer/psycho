# LowProcess generic-location structural containment

This document owns the `engine_fixes.lowprocess_generic_locations_fix`
contract. The feature repairs corrupt `LowProcess::genericLocationsList`
state before live engine traversals and contains the same corruption during
save serialization. Its implementation is in
`psycho-engine-fixes/src/mods/engine_fixes/lowprocess.rs`; configuration is
owned by `psycho-engine-fixes/config/psycho_engine_fixes.toml`.

The [2026-11-04 teardown investigation](#2026-11-04-process-teardown-crash)
below records the uncovered consumer and its scoped defensive candidate.
The candidate executes production-code regressions offline; game behavior and
the original corrupting producer remain unverified.

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

## 2026-11-04 process teardown crash

### Runtime evidence and immediate cause

The owner reports: "Companion killed mole rat, my actor just walked".
Complete inputs are preserved in
`.reports/20261104-lowprocess-teardown/{CrashLogger.log,psycho-engine-fixes-latest.log}`;
`inputs.json` records their identity and the owner's report. The crash copy is
named `CrashLogger.2026-11-04-15-02-59.log` in the original report. No local
game directory, save, or runnable reproduction was discovered. No game was
executed during this investigation.

The supplied runtime report establishes:

- access violation at `EIP=0x00470488`, with `EDX=0x00000005`;
- `ECX=EAX=0xDD6737EC`, and process storage at `0xDD673780` on the stack;
- return addresses `0x009071A3`, `0x00907026`, `0x0092CA53`,
  `0x00914A98`, `0x009145EF`, and `0x0088304A`;
- actor `0xF834E6C0`, Mole Rat reference `0606FE59`, base `0001CF9F`;
- actor cell `06001103` in the Capital Wasteland, state `Unloading`.

Reanalysis of the supported executable proves that `0x00470488` is
`mov eax, [edx+4]`: native clear follows a successor link whose value is `5`.
The implied read address is `0x00000009`; the log does not separately record
the exception's memory-address parameter. The caller loads the process and
adds `0x6C` before clear, and `0xDD673780 + 0x6C = 0xDD6737EC`.
This is the same generic-location list covered by the earlier live-scan and
save fixes, now consumed by process teardown.

The head's current successor is `5` at the fault. It is unknown whether this
was the entry-time head link or a later link advanced into the head by clear;
the original complete chain and earlier frees were not captured. There is no
allocation-identity evidence proving a freed node, freed process, double free,
or race. The immediate cause is a malformed successor consumed without
structural admission. The writer that introduced it remains unknown.

The report names the actor base's last modifying plugin and includes a
JohnnyGuitar event wrapper in the call chain. Neither identifies the writer.
Earlier Stewie source findings above establish a historical borrowed-payload
ownership bug, not the source of this incident's link value. The current log
shows cleanup predecessors captured and all eight LowProcess slots wrapped;
it records no subsequent LowProcess repair or ownership-loss event. That does
not prove a particular wrapper ran for this actor or remained in every later
provider chain. Memory statistics do not establish OOM as the cause.

### Binary contract and coverage gap

The local research image was reverified as FalloutNV `1.4.0.525`, PE32 i386,
preferred base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The crashing installation's executable and live patched bytes were unavailable;
this identity applies to the research image. Captures use radare2 with
relocations applied. Disassembly and bytes, rather than inferred decompiler
prototypes or the old xNVSE layout declarations, establish these offsets and
ABIs.

| Native boundary | Verified behavior |
|---|---|
| `0x00883048` | Dispatches the old actor process's deleting destructor; `0x0088304A` is its return. Replacement process publication follows at `0x0088305C`. |
| `0x009145E0` | Deleting destructor calls `0x00914610`; process free at `0x009145FB` follows successful destruction. |
| `0x00914A93` | Derived process destruction calls `0x0092CA00`. |
| `0x0092CA4E` | Base destruction calls `0x00906FE0`. |
| `0x00906FE0` | Writes the LowProcess vtable, invokes `0x009070A0` at `0x00907021`, then destroys embedded fields including the list at `+0x6C`. The observed LowProcess vtable is therefore consistent with derived-process teardown. |
| `0x009070A0` | Process cleanup, `thiscall(process)`, no stack arguments, plain `RET`; clears owned package state and several lists. |
| `0x00907198..0x009071A3` | Loads the process, adds `0x6C`, and calls `0x00470470` at `0x0090719E`. Bytes: `8B 4D CC 83 C1 6C E8 CD 92 B6 FF`. |
| `0x00470470` | `thiscall(head)`, no stack arguments, plain `RET`. Reads `head.next`, reads and detaches `successor.next`, destroys/frees that successor, advances `head.next`, and finally clears `head.data`. |
| `0x004702F0` | Successor deleting destructor, `thiscall(node, flags)`, `RET 4`; calls `0x0046FFB0`, then native free `0x00401030` when flags bit 0 is set. |
| `0x0046FFB0` | Calls `0x00470470` on the same node. The outer clear zeroes the successor link first, so this nested destruction does not traverse the remainder again. No borrowed payload is destroyed. |

The `aar` reference survey discovers two direct calls to `0x009070A0`:
destruction at `0x00907021`, and process reinitialization at `0x00910A78`
inside `0x00910A60`. Both reach the same generic-location clear callsite.
Indirect/plugin calls were not exhaustively enumerated. The selected internal
callsite has one process owner, unlike the shared primitive's 420 discovered
direct calls. Those other callers have not been classified for new protection.

At the incident baseline, `lowprocess.rs` protected virtual slots `+0x47C`
and `+0x480`, and serializer `0x00910450`. The destruction call above invoked
none of those guards. `list_cleanup_guard.rs` hooked only `0x00B4DF30`; its activation log
does not imply protection of the different clear at `0x00470470`. These are
direct source-level coverage facts, not proof of the original corruptor.

Raw evidence:

- [Clear instructions and bytes](../analysis/radare2/output/crash_lowprocess_clear_primitive_20261104.txt),
  [process cleanup](../analysis/radare2/output/crash_lowprocess_cleanup_owner_20261104.txt),
  [node deleting destructor](../analysis/radare2/output/crash_lowprocess_chain_deleting_node_20261104.txt),
  [node destructor](../analysis/radare2/output/crash_lowprocess_chain_node_destructor_20261104.txt).
- [Cleanup callers](../analysis/radare2/output/crash_lowprocess_clear_callers_20261104.txt),
  [complete call input/output bytes](../analysis/radare2/output/crash_lowprocess_clear_call_context_20261104.txt),
  [reinitialization caller](../analysis/radare2/output/crash_lowprocess_reset_caller_20261104.txt),
  [shared-primitive reference survey](../analysis/radare2/output/crash_lowprocess_clear_all_primitive_callers_20261104.txt).
- [Actor process replacement](../analysis/radare2/output/crash_lowprocess_retirement_chain_20261104.txt),
  [process deleting destructor](../analysis/radare2/output/crash_lowprocess_process_deleting_destructor_20261104.txt),
  [destructor cascade and callsite bytes](../analysis/radare2/output/crash_lowprocess_destructor_cascade_20261104.txt).

### Implemented candidate and owner-authorized offline gate

For this incident, the owner explicitly authorized proceeding without a game
reproduction and instructed that the issue be reproduced against executable
code offline. This supersedes the earlier proposed game-reproduction gate for
this scoped candidate. It is an incident-specific user instruction, not a
change to repository-wide policy or an assertion that the reporter-only
exception permits arbitrary ownership repair. No game run is requested or
required for this implementation handoff. Game behavior remains unverified.

`lowprocess.rs` now guards the direct call at `0x0090719E` under the existing
`lowprocess_generic_locations_fix` setting. Both discovered native cleanup
callers, destruction and reinitialization, reach this one internal site.
Installation verifies the six argument-setup bytes before the call and ten
continuation bytes after it. The ownership-aware call container captures the
current E8 provider, rechecks its instruction before activation, and changes
only that call. No destructor entry, shared primitive, vtable, third-party
module, or reference count is hooked or changed by this addition.

The provider is release-published before transactional activation. Admission
becomes active only after commit. A rollback survivor retains its provider and
forwards without uncommitted repair. An unknown caller shape leaves this
protection unavailable, with a startup warning; other LowProcess protections
remain independently installed. A later provider retains normal chaining
responsibility; the candidate performs no repeated ownership takeover.

Immediately before invoking the provider, the detour uses the production
`list_cleanup_guard::prepare_owned_clear` preflight. This is the same
implementation used by the existing shared-clear guard, whose installation
remains independent. It follows only successor topology, validates complete
writable node images, severs a verified incoming edge to an inaccessible
suffix, and cuts cycles at the exact back edge. It never follows or frees a
borrowed payload. Every unique admitted successor stays reachable for native
cleanup; intact lists are not truncated at the live/save sanitizer's 256-node
budget. Native clear still performs node destruction, and all later process
cleanup, including the embedded head's second clear, continues normally.

The empty path is a direct successor read. Nonempty preflight is linear, uses
constant storage, and introduces no allocation, lock, periodic scan, permanent
frame hook, or routine log. It preserves last-error before entering the
provider. Sampled anomaly output includes
`boundary=lowprocess-generic-clear`, the rejected edge and original memory
failure. The existing shared guard reports `boundary=shared-clear`.

The caller must retain the original native clear preconditions: a live
writable head and exclusive chain lifetime until cleanup returns. Preflight
neither pins storage nor makes a racing writer safe. It cannot distinguish a
readable stale or foreign allocation from a live successor, and an inaccessible
suffix may leak an unknown number of nodes. These limits are unchanged from
the existing preflight, not proof that the originating race or lifetime defect
has been repaired. No corrupting producer is identified by this candidate.

### Offline reproduction and qualification

The regression fixture is the unmodified 110-byte native clear body at
`0x00470470`, extracted from the verified supported executable. Its raw image
lives in `lowprocess_clear_native.bin` and is included only by the test module.
Only invalid-first-successor and empty-chain paths execute from the relocated
image. They do not reach its node-destructor call, so no relocation, mock
allocator, replacement free, or reconstructed native loop is needed.

Before production edits, the native-image test with `head.next=5` failed under
Wine with a read fault at `0x00000009`, at native-body offset `+0x18`, matching
the reported instruction. The failure and pre-change test source are preserved
in `.reports/20261104-lowprocess-teardown/implementation/`. After the change,
the regression invokes the actual production detour with that same native
provider and input. It verifies the final empty head, untouched borrowed
payload, preserved last-error, and successful second native clear. It also
executes an unadmitted detour with a valid empty chain to verify provider
forwarding on the rollback path.

A supporting production-preflight regression checks an intact 1,024-node
chain, then the same valid prefix ending in successor `5`: only the bad tail
edge changes, with every prefix link and opaque payload retained. Existing
production-preflight tests exercise complete OS page boundaries, inaccessible
and read-only successors, head aliases and cycles. These are offline code
results. The native multi-node deallocation path, actual game callsite
activation, allocator-mode matrix, live concurrency, game images and workload
latency are not executed by these tests.

Local qualification passed the focused regression, affected core suite,
supported i686 release build, formatting, `git diff --check`, final diff review,
and pre/post core/helper import and TLS comparison. Core and helper imports and
TLS layout/callback identities are unchanged. The additional startup
work is one call container and its publication/admission atomics, caller
context checks and one direct-call transaction inside the established core
pre-CRT installation. No configuration layout, parser, TLS owner, worker,
helper lifecycle or cross-DLL API is added. Code/static layout can still move;
offline artifact comparison does not establish Proton startup acceptance.

The original corrupting write remains unresolved. A durable producer repair
requires direct write/free, allocation-identity, lifetime and thread-ownership
evidence; this change does not attribute it to the companion, a content plugin,
a native plugin, an allocator, or a race. Changes remain an unreleased
candidate; deployment, packaging and commits are outside this task.

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

The save callsite wrappers resolve their existing thread-owned traversal
storage once per hook. A call-local, non-Send handle retains only the storage
address across a native provider call; mutable context borrows end before
chaining and resume after nested serialization restores the outer state.
This removes repeated thread/slot lookups without extending the lifetime of
cached memory validations or changing traversal admission. See the
[save performance research](save_integrity.md#save-guard-performance-research-and-proposed-changes)
for the static work budget and unresolved runtime timing.

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
