# Native linked-list hardening research and plan

Status: scoped implementation is an unreleased defensive candidate; broader
copy/publication and subtype proof gates remain open.
The owner separately authorized committing this unreleased candidate.
No deployment, game run or release is authorized by this work.
Prospective gaps below are not additional confirmed crash diagnoses.

Last updated: 2026-10-20.

The owner explicitly authorized a plan-specific exception to the real-runtime
reproduction gate for these prospective guards: static native-contract research
and offline production-code tests, without debug playtests. This permits
production edits for this plan but does not waive native-contract proof,
compatibility, qualification, or honest runtime reporting. The candidate now
includes C1/C2/C3, structural C4, local C5 and C6. General
subtype validation, wider mutation/copy/publication and existing-budget changes
retain their individual proof gates.

## Implemented candidate and remaining boundaries

The current unreleased candidate implements the scoped structural save capability and the
qualified cleanup/retirement additions. It does not implement the entire
prospective copy/publication program or general subtype payload validation.
The owner's plan-specific exception permits this unreleased candidate without
debug playtests; runtime integration and startup acceptance remain unverified.

- C1/C2: shared guarded range/copy admission retains the first actual failure,
  region metadata and error. Cleanup keeps its existing exact edge repair and
  native free path. Sparse per-reason counters distinguish exact cycle/head
  back-edge containment, which retains every unique successor, from an
  inaccessible/changed tail whose disconnected storage cannot be measured.
  `inspected_steps` counts successful traversal steps and can include repeated
  entries during cycle detection; it is not a leaked-node or byte count.
- C3/C4 structural coverage: `inventory_list_save_guard` defaults on and requires
  successfully installed Save file integrity. The actual snapshot establishes
  file/thread scope within the exclusive main-save owner; its audited
  record-bind call establishes buffer/form scope.
  Reference extra chains, their native cached-result membership and inventory
  Data prefixes are admitted before dependency collection. Item spines are
  admitted at the actual list serializer, only when native flags consume them. PlayerCharacter
  array and Projectile optional-entry hooks cover the other two direct entry
  serializers. Shared EntryData admission checks outer/nested spines and full
  twelve-byte entries before forwarding valid data to the native serializer.
  The native form writer accepts NULL as ID zero; structural admission preserves
  that case and checks the FormID span only for a non-NULL form.
  Reference dependency collection requires type-0x3D's scalar at +0x0C;
  reference pre-dispatch can also read type-0x41's scalar there. Both exact
  payload spans are admitted before their native getters execute.
- C5 local coverage: the existing linked-reference cleanup setting also admits
  the matched extra's child list before the native removal. Failure returns the
  same optional NULL result already tolerated by the removal owner. No child,
  extra, item or live list is detached, freed or rewritten by these admissions.
- C6: the existing dynamic-actor retirement guard checks exact uniqueness of
  every owned successor node, FormCount and optional extra allocation after its
  allocator-backed validation. This includes aliases across those roles.
  Borrowed form duplicates are allowed. A proven bad dying owner's list keeps
  the existing whole-list detach/leak policy; live-load behavior is unchanged.
- C9 integration: the new setting is appended to core/helper configuration and
  appears as **Inventory save guard**. Existing load filtering remains under
  Inventory entry guard. When that existing setting is on, its original
  main-list form predicate still applies: rejection fails the whole owned save
  before any list count or flag mutation. Outside an owned main save, legacy filtering applies
  only when its original setting is on. If save integrity or exact native
  signatures are unavailable, the new policy remains inactive with a reason.

### Save intervention and ABI

The full native snapshot body, typed alternate-owner bodies, entry serializer,
cache query/generation and native lock helpers are checked before activation.
The shared EntryData save entry has one core hook for both policies. Supporting
hooks activate transactionally, with the snapshot owner last; unadmitted
rollback survivors forward their already-published providers.

At `0x00847A86`, the native buffer/form bind has one stack argument and RET 4.
The bridge saves flags/registers, re-pushes that argument for its thiscall
helper, and restores the original register/flag state. Valid admission returns
with RET 4 to `0x00847A8B`. Rejection first latches the matching active save,
consumes the inner return and argument, and resumes native iteration at
`0x00847BD9`. The snapshot's SEH frame, iterator, buffer ownership and final
manager-bit clear/destructor remain intact. No early return from the snapshot
is introduced. A rejection without a matching failure owner never suppresses a
serializer or record callback.

Scope access requires both the exclusive main-save owner and active file thread
to match the current thread before dereferencing the stack publication. An
activation outside that outer owner cannot acquire rejection authority merely
by setting active-file tracking.

Typed PlayerCharacter/Projectile and EntryData rejections can leave a partial
record buffer; they do not claim successful framing. Their native main-save
caller continues to its ordinary record finalization and snapshot cleanup, and
the existing save-result boundary closes/discards the failed transaction
without promotion. Valid paths keep native count and flag/state handling;
the guard does not reproduce the serializer or adjust counts around skipped
payloads. Save/load/copy calls outside the authenticated snapshot/buffer scope
retain their prior provider behavior.

The extra-data preflight acquires/releases the existing reentrant engine lock
and invokes the native cache query for its proven `0x93` slots. It compares
relevant cached pointers with the actual current chain without dereferencing
an unmatched cached pointer. It preserves native epoch invalidation and does
not inspect TLS storage directly. Query/copy caches are invocation-local;
native object lifetimes must remain stable after admission, as the original
serializer already requires. This is not protection from arbitrary unsynchronized
external writers or readable stale allocations.

[Save-owner and exact byte evidence](../analysis/radare2/output/native_list_hardening_save_owner_admission_20261020.txt)
and [compiled bridge evidence](../analysis/radare2/output/native_list_hardening_compiled_abi_20261020.txt)
record the native contract. The earlier continuation capture proves record
reset, branch continuation, snapshot state clear and native buffer release.
Static ABI evidence is not native-runtime acceptance.

### Deliberately unimplemented portions

The current save guard admits list spines, complete EntryData/FormID-read spans,
reference inventory Data and cached extra membership. A twelve-byte intrusive
prefix does not validate every field in the native serializer's large subtype
switch. General subtype-owned structures, strings, arrays, custom callbacks
and unrelated noninventory fields still need their own contracts. The decoded
native type-to-case map is retained in the save-owner evidence for that work;
no unproved type-size table or fabricated empty payload was added.

C5's general extra creation/copy admission and C7 remain blocked on the actual
outer abort/rollback boundary. The new
[copy/failure-owner evidence](../analysis/radare2/output/native_list_hardening_copy_failure_owners_20261020.txt)
finds clone calls at `0x0042B837` and `0x0047D00E`. The latter passes the clone
result to `0x00575690` at `0x0047D030` without a NULL check. That setter writes
the pointer into live reference `+0x20` before its further type-dependent work.
Thus NULL is not an established failure result for the shared clone boundary.
Suppressing an inner void copy would instead return an incompletely populated
clone. Neither is a qualified universal fix.

C8's inspected insertion failure also has no caller-owned failure result.
`0x005AE3D0` is used with both owning inventory payloads and borrowed child
references, so a shared failure hook cannot choose payload destruction or
rollback policy. Its NULL-allocation path faults at `0x005AE458` before the
new successor is published; it is not evidence that NULL allocation produced
the previously observed broken links. The initialized native allocator loops
through cleanup/retry while the pointer is NULL; its early CRT fallback is a
separate nullable path. No producer/OOM attribution is established. No global
insertion no-op, guessed reclamation, silent successful clone or unqualified
copy/creation toggle was introduced.

Existing outer traversal budgets are unchanged. They are not promoted into a
native-wide maximum or evidence that a long list is corrupt. Their separate
owner/performance gates remain open.

### Save and transition pause correction

The owner reports longer pauses on every save and an approximately one-second
pause after the first visible frame of a location transition with this
candidate. The preserved session confirms the new save guard was active.
The performance defect in its admission path is repeated mapping queries:
`entry_admission` constructed a new reader for every payload, discarding the
walk's mapping knowledge, while the single cached mapping could not retain
alternating node, entry and form regions. Native extra-cache admission also
queried all `0x93` types for every list, including absent types and empty lists.
All this work runs synchronously before native serialization; reference
preflight additionally holds the existing extra-data lock during its walk.

The existing runtime logs connect an exterior render to a subsequent autosave:
terrain passes first log at `14:36:26.457`, autosave commits at `14:36:28.204`,
and the next shadow producer summary at `14:36:28.235` covers 1,784 ms with
only two transactions. A quicksave commit at `14:36:04.929` similarly precedes
a 1,252 ms summary with one transaction at `14:36:04.941`. These observations
support a common synchronous save pause after transition rendering; they are
not per-guard timings or proof that every first-frame pause has this cause.
The verified autosave owner `0x00850A40` calls the same main-save owner at
`0x00850A7C`. The native and selected runtime evidence is preserved in the
[pause investigation](../analysis/radare2/output/native_list_pause_save_calls_and_presence_20261020.txt).

The correction shares one mapping reader through each uninterrupted entry walk
and retains four recently used mapping capabilities. Cache eviction simply
queries again; it never rejects a valid list or imposes a length limit. Every
copy still executes the guarded process reader, every first mapping admission
still checks its page policy, and read/write capabilities remain distinct.
Payload bytes, object identities and successful admission are never cached.
Readers end before serializer/provider calls and are fresh for every operation.
The exact native lock/cache helpers used during admission touch their own
metadata, do not mutate these input mappings, and invoke no provider callback.
Native extra-cache queries now use only set presence bits, matching the lookup
gate at `0x00410220` / `0x0040FE80`; relevant cached membership checks remain.

Qualification uses the actual production `entry_list` on owned eight-byte
nodes, twelve-byte entries and sixteen-byte form prefixes, with empty extend
lists and five release rounds under Wine. The unchanged 65,536-entry workload
took a 166,935.0 us median (166,754.9-168,213.3 us). Scoped mapping reuse took
34,054.5 us (33,988.5-34,170.2 us), about 4.9 times faster. At 1,024 entries,
the medians were 2,566.2 us and 491.8 us. These measurements isolate structural
admission, excluding native serialization, legacy filtering, native extra
callbacks, disk IO, contention and the reporter's actual inventory population.
They cannot be converted into a promised total save time or frame-time gain.

Removing mapping queries altogether was rejected by a real-page regression:
the current Wine process reader could successfully copy a guard page and
consume its one-shot guard bit. The documented
[ReadProcessMemory access contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
alone is insufficient to preserve that admission policy on this runtime.
The final correction retains those checks and
passes guard-bit preservation, cross-region capability, inaccessible-copy,
cache-eviction/fresh-byte and existing corruption regressions. Mapping reuse
introduces no unchecked direct reads, persistent pointer cache, setting, hook,
native ABI, WinAPI wrapper, dependency or startup owner. The existing
configuration and helper descriptions remain unchanged. Runtime integration
of this performance correction is unverified; no debug playtest is requested.

### Admission at the consuming save boundary

The owner reports that the pauses remain after deploying the mapping-cache
correction. The later session shows exterior terrain rendering at
`15:15:41.693`, an autosave commit at `15:15:42.978`, and a shadow summary at
`15:15:43.033` covering 1,347 ms with two transactions. This connects the
location-entry interval with an autosave; neither that interval nor the earlier
isolated admission benchmark attributes its full duration to a particular phase.

The remaining structural defect is duplicated and unused inventory traversal.
The record-bind guard descended from every reference's type-0x15 extra into
the whole inventory, including records without inventory save flags. That
complete walk ran while holding the global extra-data lock. The shared list
hook then repeated structural admission and the enabled legacy filter made
another complete pass with three fresh mapping queries per accepted entry.

The supported executable's reference serializer `0x00562230` calls the
inventory getter `0x004BF220` and list save `0x004D4090` only when the current
buffer flags at `+0x17` intersect `0x08000020`. The getter and existing-Data
helper `0x00418520` return the Data pointer without walking its item head.
General extra serialization skips type 0x15. Reference and Actor pre-dispatch
`0x00562140` / `0x008AAEE0`, dependency collection, and the intervening
MobileObject parent save were inspected before deferring that item walk.
Actor pre-dispatch's process virtual `+0x1B8` resolves to `0x00602150`
(return process `+0x1C0`) or `0x00ACBB70` (return NULL); it does not walk items.
Reference pre-dispatch reaches `0x004228F0`, whose type-0x41 getter reads
extra `+0x0C`, so the early prefix check also covers that scalar.
The [consumer disassembly](../analysis/radare2/output/native_list_save_admission_consumers_20261020.txt)
preserves exact calls, branches, layouts and verified executable identity.

The correction retains early chain/cache membership, type-0x15 payload/Data
prefix, and type-0x3D/0x41 scalar checks. It defers the item spine to one complete
preflight at the shared list consumer, before any count, flag or stream write.
Thus the native final flags determine whether an inventory is visited, without
caching flags or admission across callbacks. The global extra lock now covers
only the relevant extra chain/cache inspection, without an enclosing item walk.
The enabled legacy form predicate shares the same outer walk and mapping
reader; its original NULL, low-address, single-region, vtable and code-range
rules remain. Its rejection fails the entire owned save. Load admission and
out-of-owner filtering remain independently configured and unchanged.
PlayerCharacter's array and Projectile's optional entry retain their own
preflights: their native contracts do not share the reference inventory mask.

An offline regression failed on the unchanged production early-admission
routine because it touched an inaccessible item head. After correction the
same early routine admits only the required prefix and the actual list
preflight rejects that head unchanged. Other regressions compare the fused
policy with the retained production load predicate using real readable process
memory, including a span split by page protection; they also retain cache,
cycle, inaccessible-memory and guard-page coverage. These tests do not execute
native save/load framing, provider composition, failure UI or disk promotion.
No reduction in whole-save or transition latency is established offline.

The existing main-save owner now publishes a stack-owned timing scope through
one inert atomic pointer. It adds no TLS, worker, lazy owner, config change,
hook installation or startup callback. Actual runtime saves measure the owner,
outermost authenticated snapshot, whole admission operations and durable commit;
no timing or counters run per entry. Raw QPC ticks accumulate before conversion,
and native LastError survives timing calls. One `[SAVE] Timing` line is emitted
at owner return. Admission is nested inside snapshot time; they must not be
added together. Commit covers completed-file validation, durable flush,
recovery and promotion, excluding the earlier native close. Unaccounted time
remains unclassified. A zero phase can mean no observed invocation; a missing
total or nonzero `clock_misses` means timing is unavailable or incomplete.
The summary is available during ordinary saves without changing hitch profiling.
It introduces no claim that guards, storage, rendering or a particular mod
explain all remaining latency. Startup and game performance remain unverified;
the existing plan-specific static/offline exception permits only an unreleased
candidate, not release or deployment acceptance.

### Costs, qualification and startup limits

Save admission adds linear guarded-copy/query work and native extra-lock
acquisitions. Cached membership uses a fixed `0x93`-pointer stack image; it does
not allocate a shadow ownership map. It adds no worker, periodic timer or PE TLS owner.
Healthy-save round trips, native failure UI, physical no-promotion integration,
lock timing and mod-provider composition have not been executed in the game.

Cold retirement alias admission uses a fallible O(n) address array and in-place
sorting. Allocation failure runs exact O(n squared) pairwise comparison rather
than treating scratch failure as corruption or weakening admission. An offline
release measurement on Wine used five rounds of actual production admission:
1,024 records had a 27.8 us median (26.5-32.5 us), and 65,536 records had a
2,809.7 us median (2,782.0-2,849.4 us). Records had no optional extras, so each
successor added its node and FormCount addresses. The executed pairwise fallback
for 1,024 records took 3,131.3 us in one round. This isolates alias admission;
it excludes the prior allocator/registry validation and does not predict frame
rate or real-world call frequency. Large fallback workloads can be expensive.

The changed list-clear preflight was measured separately using its existing
production benchmark: medians of 12.0 ns for an empty head, 1,199.1 ns for one
successor, 6,113.5 ns for 32, 162,673.2 ns for 1,024 and 5,200,112.5 ns for
32,768, five rounds per size. This is offline admission cost, without native
free or logging, not a gameplay performance measurement.

Core/helper suites, configuration round trips and the supported 32-bit release
build passed. The compiled bridge preserves its exact thiscall stack and
register contract. Native integration remains unrun. Startup changes are the
appended configuration setting, lazy hook containers, constant fingerprints and
zero-initialized capability/scope/counter atomics at the existing pre-CRT owner.
No dependency, direct Windows call, libpsycho wrapper, PE TLS variable, worker
or helper/core loading boundary was added. Import/TLS comparisons are retained
under `.reports/20261020-native-list-hardening/implementation-startup/`; these
are static comparisons, not a new accepted Proton startup baseline.

## Purpose and work ownership

The owner requests broader prevention after repeated malformed-list crashes.
The immediate inventory-reset candidate is maintained separately in
`engine_fixes/inventory_reset_guard.rs`. Its current scope is admission at
quest-item query `0x00577DE0`, inventory reset `0x00574920` and enclosing actor
refresh `0x0089FB80`. This plan does not edit that implementation, its settings,
or its incident document. Its final behavior and qualification belong to that
workstream.

The next objective is to cover additional consumers of already-demonstrated
malformed list structure and payloads. Shared byte layout does not establish
shared ownership, safe failure behavior or a common corrupting writer. A guard
must protect a whole native operation at its real ownership boundary; merely
returning NULL from a low-level accessor is insufficient.

Research uses existing reports, current source and the supported executable.
No diagnostic playtest, special build or owner-operated capture is requested.
The plan is functional hardening, with bounded support evidence as part of
each guard, rather than a diagnostics-only delivery.

## Confirmed incidents and limits

- [Fade-list destruction](crash_20261020_fast_travel_fade_list_plan.md) faults
  at `0x00B4DF43` when clear follows successor `0x51BB72C9`. The installed
  shared-clear guard later rejected `0xC5C74048` at the first successor; the
  owner reports continued gameplay. It preserves admitted entries and exact
  cycle back edges, but cannot reconstruct a missing tail.
- [Level-up inventory consumption](crash_20261020_levelup_inventory_plan.md)
  faults at `0x004D03B9` after traversal reaches node `0xD7940009` and
  consumes a supposed form with a zero vtable. The fault occurs in a live
  inventory operation, outside the earlier load/retirement guards.
- [Actor-container retirement](gheap_large_modlist_compatibility.md) records
  an invalid owning payload and an interior successor free during destruction.
  Its existing actor guard is scoped to retiring dynamic actor bases.

These prove failures in topology, owning-payload handling and payload dispatch
at different consumers. They do not prove that one writer, allocator, mod,
race, asset or save record caused all three. Pointer alignment or similar
address ranges do not establish allocation identity or a shared mechanism.

## Executable identity and evidence

FalloutNV `1.4.0.525`, PE32 i386, preferred base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`
was reconfirmed before address-sensitive research. Captures use an isolated
radare2 CLI with relocations applied, avoiding shared analysis/seek state while
the inventory agent researches the same executable.

- [Primitive and immediate-owner disassembly](../analysis/radare2/output/native_list_hardening_primitives_20261020.txt).
- [Ownership, mutation, cache and lock disassembly](../analysis/radare2/output/native_list_hardening_lifetime_and_cache_20261020.txt).
- [Discovered reference survey](../analysis/radare2/output/native_list_hardening_xrefs_20261020.txt).
- [Complete save owners, count encoding, snapshot buffer and clone owner](../analysis/radare2/output/native_list_hardening_full_save_owners_20261020.txt).
- [Extra-data cache generation, linked-child creation and copy factory](../analysis/radare2/output/native_list_hardening_full_extra_contracts_20261020.txt).
- [Record preparation, reset, child removal and rejection-continuation research](../analysis/radare2/output/native_list_hardening_record_rejection_continuation_20261020.txt).

The reference survey runs `aar` before `axtj`. Counts below are discovered
native call instructions, not call frequency, complete indirect/plugin
coverage, or authorization to patch every caller. Exact instructions establish
the local contracts; unresolved ownership and continuation remain explicit.

## List families and policy boundaries

| Representation | Verified storage/consumer | Consequence for hardening |
|---|---|---|
| Embedded-head list entries | Eight bytes: payload `+0`, next `+4`; the head belongs to its enclosing list object | Never free the head as a successor. Topology validation does not validate payloads. |
| Fade/shared clear | `0x00B4DF30` clears payload words and frees successor entries, without payload destruction | Existing edge containment can retain native cleanup. It cannot replace an owning-container destructor. |
| Base inventory | `TESContainer +4` is its head; actor bases place it at `+0x68`. Each `FormCount` is 12 bytes: count, borrowed form, owned optional extra | Validate the node, complete record, form operation and owning allocations separately. Repeated borrowed forms are distinct from repeated owning records. |
| Extra inventory | `EntryData` is 12 bytes: extend-list pointer, count delta, borrowed form. Outer save gets its first node from `[ECX]`; body save traverses the extend list | Validating the entry/form does not validate either list spine or the extra-data payloads below it. |
| Intrusive extra data | `BaseExtraList` head `+4`, presence bits `+8`; `BSExtraData` vtable `+0`, type byte `+4`, next `+8` | Eight-byte list repair would use the wrong field. Native cache, lock, presence bits and subtype callbacks are part of the contract. |

The xNVSE `NiTypes.h` declaration also describes `NiTListBase` with
`start/end/count` and nodes `{next, prev, data}`. That source declaration is
not a verified native intervention point in this audit. Doubly linked lists,
arrays such as Tile values, task queues and allocator free lists must not
inherit a repair policy from the eight-byte representation.

## Why low-level global hooks are unsuitable

| Native boundary | Local contract | Discovered direct calls |
|---|---|---:|
| `0x006815C0` | ECX returned unchanged, no stack arguments, plain RET | 5,801 |
| `0x00726070` | Return `[ECX+4]`, no stack arguments, plain RET | 3,142 |
| `0x0063F7B0` | Promote successor fields into the head, detach/free successor; plain RET | 302 |
| `0x00481700` | Destroy each owning `FormCount`, then remove/promote the head; plain RET | 2 |
| `0x004D4090` | Outer inventory save, ECX owner, one buffer argument, RET 4 | 1 |
| `0x004BED60` | Entry body save, ECX entry, one buffer argument, RET 4 | 3 |
| `0x00410220` | Extra lookup, ECX list, one type argument, RET 4 | 478 |
| `0x0040FF60` | Extra insertion, ECX list, one node argument, RET 4 | 233 |
| `0x00410020` | Extra removal, ECX list, node/free arguments, RET 8 | 123 |

`0x006815C0` is not exclusively a list accessor. The verified BSFadeNode
vtable at `0x010A8F90` also puts it at `+0x10` as the type query that returns
the object unchanged. Its 133 discovered data references reinforce that its
coverage extends beyond direct calls. Treating ECX as a list globally would
misinterpret valid scene objects. Even list callers immediately dereference
its returned slot, so NULL is not a universal safe result.

Likewise, guarding only head removal cannot protect payload destruction that
has already happened. `0x00481700` calls `0x00481760` at `0x0048173E` before
calling head removal at `0x00481752`. A refusal inside head removal can also
leave the enclosing loop without progress. The payload owner, not that helper,
must decide whether the complete operation may proceed.

## Concrete coverage gaps

### Inventory save topology and nested extra data

`entrydata.rs::hook_entrydata_list_save` checks entry/form storage after obtaining
the payload, but `node_entry` invokes the native identity helper and directly
reads its returned slot. `list_node_next` calls the raw next helper. The outer
loop has no structural cycle check. These are source-proven validation gaps;
no crash in this wrapper from a broken spine is claimed.

Its admitted body still reaches native `0x004BED60`, which writes the form and
count delta before traversing `EntryData.extend_data`. That nested loop obtains
each extra-data-list payload and calls `0x00426A30`. The latter follows the
intrusive extra chain and dispatches subtype serialization. A valid top-level
form therefore does not establish safe save traversal.

Both save layers own a serialized count. Outer count increments at
`0x004D4112..0x004D4118` after the body call; nested count increments at
`0x004BEDCC..0x004BEDD2` after extra-list serialization. Skipping a failing body,
stopping mid-entry, or silently serializing only a valid prefix can lose
inventory or break framing. The whole save transaction must report failure
when a structural inventory defect cannot be represented faithfully.

`save_integrity.rs` already owns failure latching and no-promotion behavior,
but its latch is private and tied to its active transaction. The existing
`entrydata_invalid_form_guard` and `save_integrity_fix` are independent toggles.
An added structural rejection must prove the active owner/thread/buffer and
configuration dependency; it cannot call an inert latch when the save owner is
absent. The alternate callers and actual snapshot-buffer owner are identified below.
Their rejection continuations still require qualification before interception.

### Intrusive lookup, cache and mutation

`extraownership.rs` invokes native GetByType before scrubbing the returned
ownership payload. It does not protect native traversal from a broken extra
chain. `linkedrefs.rs` guards one removal-side lookup and deliberately leaves
creation paths out because returning missing there can trigger insertion into
the same damaged list.

Native GetByType tests presence bits, then queries its existing per-thread cache
through `0x0040F9E0`. A cache hit bypasses the locked scan; cache miss traverses
`next +8` under engine lock `0x011C3920`. Changes use existing cache invalidation
helpers `0x0040F7D0` and `0x0040F860`. Validating only the scan would leave the
cached-result path outside protection.

Insertion, removal and copy are different operations. Add at `0x0040FF60`
links the node and marks its type bit. Remove at `0x00410020` relinks, can call
the node's deleting destructor, and updates cache/presence state. RemoveAll at
`0x0040FAE0` invalidates cache and may destroy nodes before clearing presence
bits. Faking an absent extra is not a complete failure policy for these owners.

The engine lock is reentrant: acquisition `0x0040FBF0` compares the owning
thread, increments recursion, and otherwise uses the native acquisition loop.
It takes ECX plus one diagnostic string argument and returns with RET 4;
release `0x0040FBA0` has plain RET. It is not a Win32 CRITICAL_SECTION.
A future guard must preserve this native synchronization and cache protocol;
neither a new Rust mutex nor a WinAPI critical-section wrapper establishes it.
Coverage of arbitrary external writers remains unknown.

### Owning aliases, not just successor cycles

`0x00481760` calls `0x00487620`, which frees `FormCount.extra` at `+8`, then
conditionally frees the FormCount itself. Thus two distinct acyclic nodes
sharing one owning FormCount, or distinct FormCounts sharing one owned extra,
are unsafe for that destruction sequence even if all initial addresses are
readable and live. This is a prospective invariant violation, not a proven
cause of either October crash.

The current actor-container validator checks structure, allocation state and
registered form identity; it does not check uniqueness of owning payloads.
Registry identity also does not independently validate the virtual slot a
consumer will call. Borrowed form/reference duplicates can be valid and must
not be rejected by a blanket duplicate-pointer rule.

Exact owning-alias detection has a cost that needs an explicit design. Brent
detects repeated nodes in a successor chain, not arbitrary equal payloads.
Pairwise payload comparison adds quadratic work; an exact membership set needs
storage and a capacity policy. Overflow cannot be called corruption, used to
truncate a valid list, or hidden behind a probabilistic ownership decision.

### Copy and publication boundaries

`TESContainer` copy at `0x00481C80` clears destination at `0x00481CB1`, then
walks/clones source through `0x00481A90`. Extra-list copy at `0x00411EC0`
first removes destination copyable extras through `0x00411FD0`, then walks the
source and adds copies. Source validation after those calls is too late to
preserve destination state. Source/destination identity and overlapping owned
nodes need explicit qualification, not just two independent cycle checks.

The FormCount clone allocates 12 bytes and copies optional extra data; its
insertion helper `0x005AE3D0` allocates an eight-byte successor. The inspected
NULL-allocation branch later writes through that NULL node. This is a static
failure-contract gap to audit at the producer's enclosing owner, not evidence
that either reported crash was OOM. Returning fabricated insertion success or
globally suppressing allocation failure would not prevent data loss.

## Additional owner contracts established for the full plan

### All discovered entry-save callers

The three direct calls to entry-body save `0x004BED60` have different owners:

| Body call | Verified enclosing owner | Required admission |
|---|---|---|
| `0x004D410D` | Outer list serializer `0x004D4090`, called by `0x00562230` at `0x00562300` | Outer spine, entry/form, nested extend-list spine and serialized extra payloads. |
| `0x00959B02` | PlayerCharacter save `0x009590F0`, array at `this+0xDF4` | Checked count, complete active pointer span and each entry. The function writes count before iteration at `0x00959AC2`. |
| `0x009C525B` | Projectile save `0x009C4FF0`, entry pointer at `this+0x144` | Optional pointer and complete entry before the presence byte written at `0x009C5241`. |

The native vtable slots and complete-object RTTI identify these two alternate
owners as PlayerCharacter and Projectile; they are not names assigned from
apparent layout. The array accessor `0x00877A30` returns `[this+4] + index*4` without a
bound check; count is `[this+8]`. Do not compact/reorder active slots, invent
capacity semantics, or treat an active NULL slot as an absent optional entry.
Their runtime object and allocation lifetimes remain original caller
preconditions; mapping admission does not establish allocation identity.

The reference owner `0x00562230` serializes its own extra data through
`0x00426A30` at `0x005622C6`, before outer inventory serialization. Guarding
only `0x004D4090` therefore cannot cover that earlier intrusive traversal.
Three discovered direct calls do not establish coverage of external/indirect
callers. No global hook of identity, next or array-count helpers follows.

The count helpers `0x00865F20` / `0x00865FF0` reserve and patch encoded counts.
The finalizer has one-, two- and four-byte encodings below `0x40000000`; its
larger-count branch logs an error. Count/span arithmetic and representability
must be checked before serialization; logging that error is not a successful
framing contract or a reason to impose an arbitrary small list limit.

### Actual snapshot-to-file binding

Main snapshot function `0x00847850` has ECX manager and one file argument,
RET 4. It constructs one stack-local buffer at `[EBP-0x248]` with
`0x008659C0` at `0x00847978`. Inside changed-form iteration it initializes
record metadata through `0x00865AD0` at `0x00847A74`, passes that same buffer
to virtual dispatches at `0x00847AA6` (slot `+0x80`) and `0x00847B97` (slot
`+0x54`), then passes buffer and actual file to `0x00865A30` at `0x00847BA3`.
The two dispatch roles are not assumed interchangeable or both named SaveGame.
There is engine bookkeeping between them, including a native branch that
skips the later dispatch/write and resumes iteration.

`0x00865A30` derives a record size, writes nine header bytes, calls
`0x00845D80` and then writes the buffer data through `0x00865C80`. The latter
conditionally writes data; its captured body does not reset or release the
buffer. Final snapshot cleanup calls `0x00847D00(manager, 0)` and destroys the
buffer through `0x00847DD0` / `0x00865C10`, which frees buffer storage. An
early return from the snapshot function would bypass native cleanup.

This identifies the actual file/buffer binding. The later continuation research
recorded above qualifies only the audited early bind-call rejection edge; it
does not authorize arbitrary virtual-call, record-writer or bookkeeping skips.
Merely claiming every same-thread buffer belongs to the active FOS save is
insufficient.

Further continuation research verifies `0x00847DB0` resets buffer cursor
words `+0x0C/+0x10` before each live-form record at `0x00847A41`. Preparation
`0x0084EB80` at `0x00847B77` is not just buffer initialization: its reference
branch reaches extra lookup `0x00422B90` / native GetByType for type `0x3D`,
then may serialize additional dependency state through `0x00562DE0`. It runs
before the later virtual dispatch. Consequently admission solely at
`0x00847B97` cannot protect even all pre-serializer extra-chain consumption.
The snapshot state helper `0x00847D00` sets/clears manager `+0x244` bit 4;
any rejected-owner continuation must retain the matching clear and buffer
release. These additional facts narrow the required early admission boundary;
they do not establish a safe arbitrary early return.

Existing `save_integrity.rs` result handling closes through the native file
destructor and rejects promotion whenever its active transaction has latched a
failure. That is the final failure owner to reuse. It does not independently
prove a safe local exit from an arbitrary serializer.

### Linked-reference child removal and creation differ

Removal owner `0x0041E600` calls the already-guarded lookup at `0x0041E614`.
If it gets NULL, it returns at `0x0041E651` before mutation. For a matching
extra of type `0x52`, it instead traverses the eight-byte embedded-head child
list at `extra+0x0C` through `0x00905330` at `0x0041E62C`. That child list is
not checked by the current outer intrusive-chain lookup.

The removal helper compares borrowed payload pointers by value; it does not
dereference them. A NULL payload with a non-NULL successor is traversable in
this helper. FormCount-specific payload/empty-head rules would reject valid
representations here. Only topology and the capabilities required by the
actual removal/free operation belong in this child-list admission.

Creation owner `0x0041E530`, RET 4, allocates a `0x14`-byte type-`0x52` extra
and adds it at `0x0041E5BD` when lookup reports missing. It then searches the
child list at `0x0041E5CC` and may insert at `0x0041E5E2`. This confirms why
removal's optional-result policy cannot be copied to creation.

### Native extra-data cache generation

Cache query `0x0040F9E0` takes list/type as cdecl arguments, with caller stack
cleanup. It calls `0x0040F900`, which compares the native thread-local epoch
with global `0x011C38E4` and clears the existing cache on mismatch. Cache
layout is last-list `+8`, epoch `+0x0C`, pointer table `+0x10` with `0x93`
entries. Presence checks permit a wider bitmap range. Neither range establishes
all valid serialized subtype sizes. A cache pointer is not ownership evidence
or proof that it remains in the current chain.

The captured extra-copy factory `0x004103D0` is a large subtype dispatch.
Its complete capture is evidence for the next audit, not a completed schema
for every subtype. A readable twelve-byte base prefix does not validate fields
or callbacks used by every serializer or copier.

## Complete change set and dependencies

This is the complete set of changes supported or motivated by the audited
families. It is not a promise to guard every list in the engine, detect every
readable stale pointer, repair overwritten links, or identify the corrupting
writer. Each work package separates an established gap from the proof still
needed before its production patch.

| Package | Deliverable | Dependency and remaining gate |
|---|---|---|
| C0 | Integrate the separate inventory-reset/query/refresh candidate | Owned by the existing incident workstream; preserve its hook ownership and load-failure integration. |
| C1 | Improve bounded rejection evidence in functional guards | Capture the actual failed read/query once; preserve valid-path cost and LastError. |
| C2 | Share narrowly matching admission mechanisms | Extract only production code needed by two real consumers; no common recovery policy. |
| C3 | Bind structural save rejection to current record and file | Exact snapshot dispatch/continuation, thread, lifetime and file-finalization proof. |
| C4 | Guard complete inventory serialization | C2/C3, all three entry-body owners, earlier reference extras and subtype field contracts. |
| C5 | Guard nested child removal; qualify extra lookup/mutation | Child-removal abort is proved; allocator/free identity, lifetime and broader caller policies still matter. |
| C6 | Detect owning aliases at retirement boundaries | Exact ownership, scratch/failure policy and measured uniqueness cost. |
| C7 | Preflight container/extra copy before destructive mutation | Enclosing owner abort/rollback and source/destination overlap contracts. |
| C8 | Prevent partial publication on qualified producer failure | Actual allocator-failure and caller-failure contracts; rollback ownership. |
| C9 | Integrate toggles, compatibility, documentation and validation | Required for each implemented package, not a separate diagnostics release. |

### C0: preserve the active inventory workstream

Use `inventory_reset_guard.rs` as the owner of the query, reset and enclosing
actor-refresh admission. Its rejection during an owned load already connects
to `save_integrity::reject_inventory_reset_during_load`; do not introduce a
second load latch or competing hook. Recheck the final diff of that candidate
before building on its typed readers. Its reported offline checks do not
qualify the future save/copy paths or intrusive extra payloads in this plan.

### C1: explain containment without claiming a leak measurement

Change `list_cleanup_guard.rs` rejection reporting to distinguish query failure,
uncommitted/guard/no-access memory, insufficient write capability, checked-range
overflow, guarded-copy failure, a changed predecessor and a successor cycle.
Capture the failed address/range, predecessor, admitted successor count and the
first failure's available region metadata/error. Record only information the
failed operation actually provides; do not fabricate an OS error for a policy
rejection or replace the first failure with a later retry's result.

Keep exact cycle-edge repair and the existing native cleanup/provider call.
For an inaccessible edge, retain existing containment. Do not attempt a second
free pass, search nearby memory for a tail, or reclaim payloads that the native
clear never owned. Better evidence cannot make an unknown tail safe to free.
For the reported first-edge rejection, the admitted allocated prefix was zero;
there is no verified disconnected-node or leaked-byte total.

Replace the single lifetime report flag with bounded repair/rejection counters
and sparse reporting, for example the first event and powers of two per reason.
A log count is the exact counter snapshot when emitted, not a session-final
count. Saturating counters must say saturated. Avoid routine allocations,
per-entry logging, a worker, timer, per-allocation history or exported dashboard
ABI changes. Preserve LastError across both guard work and reporting. Evidence
comes with functional changes, not a special build requiring another playtest.

### C2: reuse mechanics while keeping policy with the owner

Introduce a small internal `engine_fixes/list_validation.rs` only when C4 or
C5 supplies the second concrete consumer. Reuse existing guarded-copy/range
facilities and explicit readers for eight-byte embedded-head nodes and
12-byte intrusive prefixes. Return structured outcomes and local evidence;
keep `valid`, `proven invalid`, and `unsupported/unstable` distinct. Consumer
code still determines payload shape, access capability and failure behavior.

Use constant-space cycle detection without a new arbitrary healthy-length cap.
A per-invocation region cache may avoid repeated queries within a proven
lifetime interval. It must not be presented as pinning memory, allocation
identity or a ticket safe across native callbacks. Keep operation-specific form
virtual-slot checks and owning-allocation checks outside the generic spine
reader. Do not extract unrelated existing validators just for uniformity.

### C3: extend the existing save transaction owner

Keep active record context and structural failure latching in
`save_integrity.rs`. Use the audited snapshot boundaries to bind file, buffer,
current form/record and current owner thread; restore prior context on every
qualified exit and reject unsupported nesting explicitly. Do not add PE TLS,
a global pointer-keyed ownership map, or assume an arbitrary same-thread
serializer belongs to this save. Calls outside the owned main-save boundary
must remain explicitly outside this feature's coverage.

Expose a narrow internal rejection API, provisionally
`reject_current_inventory_save(buffer, reason)`, which verifies that binding
and latches a dedicated failure reason through the existing transaction.
Return an explicit unowned/mismatch result rather than silently doing nothing.
Install the record context and rejection route as one transaction with C4.
A structural guard may not return successful-looking empty inventory when
there is no functioning failure owner.

Before implementing, qualify both dispatches, their return/register ABI,
intermediate bookkeeping and the record-write continuation. Choose the first
safe owner boundary that bypasses malformed traversal while retaining native
cleanup and whole-save failure. Do not skip a void serializer and assume the
caller tolerates it, or early-return the snapshot without restoring its state.
Prove that the next record does not reuse partially written flags/count state.
Reuse the existing close/discard/no-promotion result path; do not create a
second save-file replacement implementation.

### C4: complete structural inventory-save admission

Add `inventory_save_guard.rs` for typed entry/extend-list/extra admission and
coordinate with the existing `entrydata.rs` hook. There must be one owner of
`0x004D4090`, activated for the old form filter, the new structural guard, or
both. Do not stack two independently installed detours at that entry.

Cover the list path, array path and optional single-entry path identified above,
plus reference-owned extras serialized before the inventory list. Admit each
complete typed operation before its first count, presence or payload write
where the qualified owner permits it. Check the outer and nested spines,
complete records, form identity/required dispatch, intrusive chains and the
actual fields accessed by each supported subtype serializer. Determine the
correct null/empty rules from that specific native consumer.

A structural rejection must fail the owned save. Do not promote a prefix-only
inventory, compact an active array, silently drop nested extras, adjust a count
to disguise missing items, or deserialize a saved truncated structure as a fix.
Preserve native outer/nested framing, state restoration and unchanged provider
calls for valid data. Where a callback can mutate an admitted chain, establish
the native exclusive lifetime or validate again at the next actual consumption
boundary; a preflight snapshot cannot establish that contract by itself.

Do not hook `0x004BED60` globally merely because it is shared. Choose scoped
owner/callsite admission after all three native continuations and subtype
contracts are proved. There is no claim that the current evidence already
qualifies a universal serializer detour.

### C5: child-list removal first; broader extra operations separately

The smallest local extension is in
`linkedrefs.rs::find_linked_ref_children_checked`: before returning the matching
type-`0x52` extra, validate its child head at `extra+0x0C` and its successors for
the subsequent removal operation. On proven invalid structure, use the existing
NULL return accepted by `0x0041E600` before mutation. Keep the existing setting
and owner boundary. Do not dereference borrowed child payloads or reject valid
borrowed duplicates/NULL-payload shapes.

Mapping checks alone do not establish that an admitted successor can be freed.
Qualify the owner/allocation and lifetime contract of `0x00905330` before
claiming protection against readable stale/interior nodes. Do not extend this
NULL policy to `0x0041E530` creation, where it triggers mutation.

For broader extra lookup, add a typed `extra_list_guard.rs` only after complete
cache-hit/cold-scan and consumer audits. Validate cached-result membership,
type and consumed fields as well as the scanned chain, under the native
reentrant-lock/lifetime contract. Use the engine's existing lock/cache helpers;
do not read native TLS directly or replace synchronization with a Rust mutex.
Coordinate with existing `extraownership.rs` ownership of `0x00410220` rather
than installing another global GetByType hook. Preserve presence bits and
native invalidation/generation behavior on every qualified mutation.

Required extra data, optional lookup, deletion and creation need separate
owner-specific rejection policies. Keep creation/copy support out of this
package until C7/C8 supplies an actual abort/rollback boundary. No generic
"missing extra" answer is proposed for all 478 discovered lookup callsites.

### C6: owning-payload alias admission

Extend the existing `actor_container_guard.rs` retirement policy to reject
repeated owned FormCount addresses and repeated non-NULL owned extra addresses
when the complete ownership/lifetime contract is established. Repeated borrowed
form pointers remain valid. Apply operation-specific dispatch validation at
consumers that actually call a form virtual slot. Keep this under the existing
actor-retirement toggle; do not apply dying-owner detachment to live inventory.

Choose an exact uniqueness algorithm before patching: constant-storage pairwise
comparison has quadratic cost; a fallible temporary set/sorted scratch array
has allocation, arithmetic and failure costs. Brent alone cannot solve this.
No probabilistic ownership decision, fixed-capacity overflow called corruption,
mutation of the source list to sort it, or hot global ownership map is allowed.
The candidate chooses the fallible sorted address array and exact pairwise
fallback described above. Its executed offline costs are recorded there;
native workload frequency and large fallback costs remain operational limits.

For a proven malformed dying owner's list, retain the current detach/contain
policy until independently safe reclamation is proved. A readable candidate
payload is not permission to delete it. Broader reclamation requires exact
allocation identity, unique ownership and synchronization, not just duplicate
suppression. An invalid-pointer log cannot justify eliminating all leak risk.

### C7: copy admission before destination changes

A future `container_copy_guard.rs` must validate source, destination, owning
aliases and cross-list overlap before `0x00481CB1` or `0x00411FD0` destroys
existing destination contents. Keep source-equals-destination semantics faithful
to the actual owner; do not invent a successful no-op for an unsupported copy.

The component copy functions are void and their safe caller-abort contract is
not established. The inspected outer clone `0x0047D130` allocates a new form,
invokes a virtual copy at `+0x108`, performs further virtual work and returns
the new pointer after restoring global state. This is evidence against simply
suppressing the nested component call and returning an apparently complete
clone. Qualify its rollback/rejection or another real enclosing owner before
shipping this package. Audit other proven callers rather than assuming this
one owner is exhaustive.

Where native ownership permits replacement, prepare privately, initialize all
owned fields, then commit once and retire old data. Otherwise reject the
complete operation before mutation using its proved failure path. The specific
scratch/rollback design is blocked on that owner contract, not resolved by
adding cycle checks to two destructive loops.

### C8: qualify producer failure and publication

Audit `0x00481A90` and insertion `0x005AE3D0`, then only the extra-copy factory
cases needed by the qualified operation. Prove allocator failure behavior,
all private allocations, publication points, owning callbacks, and the caller's
failure result. Check overflow, initialize private records/nodes completely,
and roll back every privately owned allocation on failure before publication.
Use each allocation's original allocator/free route.

Do not convert a failed void insertion into fabricated success, publish a NULL
node, leave an incomplete clone in a live owner, or invent fallback storage.
An allocator-wide detour is not part of this plan. These are prospective
producer hardening tasks; OOM or a specific producer is not established as the
writer responsible for the observed crashes.

### C9: settings, hook installation and existing-budget audit

Propose one new setting for qualified C3/C4:
`engine_fixes.inventory_list_save_guard = true`, helper label
**Inventory save guard**. It requires active, successfully installed
`save_integrity_fix`. If the parent is disabled/unavailable, leave this guard
inactive and log the reason; do not silently force the parent on. Install the
whole capability transactionally, with exact native signatures and clean
rollback on incompatible/failed sites. Preserve legitimate existing providers;
never patch another mod or choose behavior from a mod name/version.

The following is proposed user-facing text, matching the current comments and
helper's plain-language style. Verify against the then-current shipped strings
when implementing; do not expose native addresses, topology or transaction
mechanics in product help.

```toml
# Stop saves with broken inventory lists instead of crashing.
# Valid inventories are unchanged; a failed save keeps your previous save.
# Requires save_integrity_fix.
inventory_list_save_guard = true
```

Helper description: "Stops saves with broken inventory lists instead of
crashing. Valid inventories are unchanged; a failed save keeps your previous
save. Requires Save file integrity."

| Installed save integrity | New structural setting | Existing entry/form setting | Required behavior |
|---|---|---|---|
| Yes | On | Either | Proven structural/entry defects covered by the new policy reject the whole owned save; existing load filtering remains independently configured. |
| Yes or no | Off | On | Preserve the existing entry/form save/load filter behavior. |
| Yes or no | Off | Off | Neither of these inventory-save admission policies is active. |
| No | On | Either | New guard is unavailable with a clear activation reason; preserve the independently configured old behavior. |

The stricter save policy must explicitly take precedence over the old
save-side drop policy for the same rejected entry; no successful truncated save
may result from their combination. Document this behavior in `save_integrity.md`
and the existing inventory setting help when implemented. Leave the old load
filter's scope unchanged.

C1 uses `list_cleanup_guard`; the local C5 extension uses
`linked_ref_children_stale_list_guard`; C6 uses the existing retirement setting.
C7 may get **Container copy guard** only once a coherent independent capability
is qualified. C8 should share that capability when rollback is inseparable.
Do not add dormant configuration fields or promise a broad extra-data switch
before its actual owner-specific behavior is proved.

Append core/helper configuration fields; update defaults, load/save plumbing,
TOML, helper control/help ordering and `docs/psycho_dashboard.md` together.
Keep core activation ownership and existing exported dashboard ABI unchanged;
logs suffice for bounded evidence. The helper never loads/initializes core.
Review the current inventory agent's changes before these edits to avoid
clobbering its setting/control additions.

Audit existing budgets of 256, 1,024 and 65,536 by their owners. They are not
proven engine maxima; work exhaustion is not itself corrupt topology. Record
where an existing guard conflates those outcomes and resolve each with an
actual valid-path and cost contract. Do not remove bounds or claim arbitrary
length support without the corresponding algorithm and workload evidence.

## Delivery order, files and readiness

1. Preserve C0 as the independent incident candidate. No duplicate hooks or
   requalification claim from this research.
2. Implement C1 plus the local C5 child-removal extension after its outstanding
   free/lifetime proof. Include functional handling and bounded evidence in the
   same delivery, using existing toggles.
3. Close C3's dispatch/continuation and C4's typed owner/subtype gaps, then ship
   C2/C3/C4/C9 together as one functional save capability. A plain outer-list
   scan is not an intermediate "complete save guard."
4. Qualify C6's exact algorithm and C7's abort/rollback separately. Expand extra
   creation/copy admission only with their actual owner policy.
5. Implement C8 only after the allocator/caller failure contract is established.
   Follow up on remaining family-specific budget issues with direct evidence.

| Files | Planned responsibility |
|---|---|
| `engine_fixes/list_cleanup_guard.rs` | C1 containment evidence and bounded counts; preserve native cleanup ownership. |
| `engine_fixes/linkedrefs.rs` | C5 nested child-removal admission at the existing optional lookup. |
| Proposed `engine_fixes/list_validation.rs` | C2 small shared range/spine mechanisms, no recovery decisions. |
| `engine_fixes/save_integrity.rs` | C3 scoped record binding, structural failure reason and existing no-promotion path. |
| `engine_fixes/entrydata.rs` and proposed `inventory_save_guard.rs` | C4 single-hook ownership and complete typed save admission. |
| Proposed `extra_list_guard.rs` and existing `extraownership.rs` | Qualified C5 cache/scan admission without competing GetByType hooks. |
| `engine_fixes/actor_container_guard.rs` | C6 owning-alias admission within the existing retirement contract. |
| Proposed `container_copy_guard.rs` | Qualified C7/C8 owner-level admission and rollback/publication. |
| Core/helper config, TOML, `engine_fixes/mod.rs`, helper dashboard | C9 coherent settings, activation and plain-language help. |
| Owning save/incident docs and this plan | Contracts, behavior, evidence, costs, remaining qualification. |

All module paths above are relative to
`psycho-engine-fixes/src/mods/`, except the explicitly named core/helper files.
No libpsycho change is currently required: use its existing OS APIs. Nothing
here authorizes direct Windows-crate imports or a replacement for
`with_virtual_protect`.

The implemented candidate's bounded contracts are recorded at the top. The
remaining subtype, broad copy/publication and budget questions are explicit
implementation gates, not requests for owner debug playtests.
The next research should close those named gates, not repeat the global xref
survey or speculate about an unidentified corrupting mod.

## Shared implementation constraints

Reuse small internal validation mechanisms where their contracts match:
guarded copies, checked ranges, per-invocation capability caches, cycle
classification, and structured rejection evidence. Keep engine ownership and
policy in `psycho-engine-fixes`; do not create a universal list-repair framework
or move engine semantics into libpsycho. Readers require readable storage;
mutators/destructors require their actual write/free capabilities.

Mapping accessibility is not allocation identity, generation or synchronization.
Native callbacks can invalidate a preflight result; no validation cache may
survive them without a proven lifetime contract. An exact allocation-start
query is useful only under a proven lock/lifetime policy and never establishes
list membership by itself. The existing allocator classifier takes locks and
must not be inserted casually into shared callbacks or per-node hot paths.

Do not extend existing 256/1,024/65,536 traversal budgets into a universal
validity rule. Those current guard budgets are not a demonstrated engine-wide
maximum. New validation must distinguish a work-budget/unsupported result from
proven corruption and preserve valid long chains. Auditing existing budget
policies is separate from changing them without runtime/performance evidence.

Keep hot paths free of routine allocation, global scanning, additional
blocking locks and per-node logs. Cold retirement scratch and the save
preflight's original engine extra lock are the scoped exceptions documented
with their failure and cost contracts above. No per-allocation history, global shadow
ownership map, broad quarantine or third-party-mod patch is justified by these
incidents. Never guess a missing successor, free a readable lookalike, or make
unknown pages writable. Use only existing libpsycho OS APIs, including
`with_virtual_protect` for scoped test protections; add no direct Windows crate
use or redundant wrappers.

Extend existing settings only when their ownership contract matches. Each new
guard remains restart-only and togglable through core TOML and the helper,
with descriptions following the current plain-language text style and stating
normal behavior and any loss/leak tradeoff. Append configuration fields and
keep activation in the core; the helper never loads or initializes it. Do not
split an inseparable failure/rollback capability into independently active
switches.

Diagnostics accompany the functional fix: separate bad links, cycles, payload
failures, owning aliases and uncertain lifetime; capture the first actual query
or copy failure, retained-prefix length and bounded aggregate counts. Repairs
are not leaked-node/byte counts. Better logs cannot recover overwritten links
or replace safe whole-operation handling.

## Acceptance for future implementation

Before code changes, define the real owner boundary and expected native result.
Offline tests may execute actual production admission code with owned mappings
and evidence-backed layouts; mocks, mirrored validators and source assertions
are not substitutes. Runtime-only integration remains unverified without actual
reporter evidence; no playtest or reproduction request is made by this plan.

Qualification must cover intact empty/single/long chains; inaccessible,
read-only and cross-region storage as appropriate to the operation; bad nested
payloads and callback slots; head aliases, self and longer cycles; owning
payload aliases versus valid borrowed duplicates; and copy overlap before any
destination mutation. Shape/cycle checks alone are not complete acceptance.

Save acceptance additionally requires exact outer/nested counts, preserved
buffer flags/state, intact item counts and per-item extra state after valid
round trips, and failure without promotion for structurally rejected saves.
Extra-data acceptance includes cold/cache-hit lookup, locked add/remove/copy,
presence-bit/cache coherence and provider compatibility. Producer acceptance
requires a real failed-allocation/owner path and absence of partial publication;
do not add synthetic success/failure models.

Measure the executed production admission cost on declared offline workloads;
do not infer runtime frequency or FPS from reference counts. Read [startup safety](nvse_startup_phase_safety.md) before any
hook/config/static change, use transactional
installation and exact native signatures, run the affected suites and supported
32-bit release build once, and preserve honest runtime limits. The [reporter exception](psycho_engine_fix_exception.md) must be explicitly
applicable to the named incident before it can authorize an unreproduced
defensive candidate; it is not blanket authorization
for every prospective guard in this document.

No native integration is qualified by these offline checks alone. The explicit
plan-specific authorization at the top permits the current unreleased candidate;
it does not waive remaining native-contract proof or establish runtime/startup
acceptance. This work requests no owner debug playtests and performs no release.

Research artifacts retain raw binary evidence. Implemented portions require the
focused production-admission checks, affected suites, supported release build,
formatting, document checks and final diff review described above. No game run,
deployment or packaging was performed. Commit authorization does not establish
native-runtime acceptance. The independent inventory-reset
and unrelated Atom/OMV changes remain preserved.
