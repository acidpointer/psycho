# Level-up completion: malformed NPC base inventory

Status: implemented as an unreleased defensive candidate under the
reporter-only engine-fix exception, authorized by the owner's instruction to
proceed with this incident's universal fix and add a toggle. Offline
qualification passed. Gameplay and startup acceptance remain pending.
The corrupting writer remains unknown.
The owner explicitly authorized committing this unreleased candidate with
runtime acceptance still pending.

Owner requirement: a universal production fix, with no diagnostics-only
builds. The fix must address the shared invalid-container contract across its
callers, independent of perk, NPC, save, allocator mode or installed mod.

Last updated: 2026-10-20.

## Report and evidence

The owner gained a level, selected skills and the Commando perk, and crashed
when pressing Done. The owner subsequently identified Commando; the crash log
does not identify the selected perk or attribute the corruption to its mod.

The matching complete CrashLogger, Psycho, Atom and OMV logs and deployed
Psycho configuration are retained in `.reports/20261020-levelup-done/`.
`provenance.json` records their discovered sources and timestamps. The game
directory was recovered from the existing CrashLogger symlink, then confirmed
with `psycho_env.py`; no developer path was assumed.

CrashLogger's header, `14:04:42`, is the session start. Its archived incident
filename is `CrashLogger.2026-10-20-14-28-41.log`, with playtime `00:23:59`.
The matching Psycho session starts at `11:04:42Z`. Player data names
`Vault112a`, cell `0601852C`, and world `TranquilityLane`, `060244A7`.

The installed executable and research executable were independently checked
and match FalloutNV `1.4.0.525`, PE32 i386, image base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Native addresses below apply to that image. No incident-time code-page capture
is available to establish every installed hook or concurrent modification.

Raw radare2 evidence:

- [Faulting inventory predicate](../analysis/radare2/output/crash_20261020_levelup_inventory_predicate_20261020.txt).
- [Native completion and inventory chain](../analysis/radare2/output/crash_20261020_levelup_native_chain.txt).
- [Caller coverage, owner access and ABI](../analysis/radare2/output/crash_20261020_levelup_callers_and_owner.txt).
- [Menu continuation and mutation boundary](../analysis/radare2/output/crash_20261020_levelup_mutation_boundary.txt).

Disassembly and exact bytes are authority; decompiler output is supplementary.
Committed captures normalize whitespace-only blank lines; original tool output
is retained with the local report.
Unaligned exploratory windows and data interpreted as instructions in the raw
capture are not used as evidence. The later function disassemblies and word
dumps establish the corresponding boundaries.

## Confirmed immediate cause

The engine traverses an NPC's base `TESContainer` list, takes a `FormCount`
record's form pointer, reads that object's virtual table, and gets zero. It
then reads virtual slot `+0x94` through that zero pointer.

```text
004D03A6  mov ecx, [eax]          ; current node.data
004D03A8  mov [ebp-0x0C], ecx    ; FormCount local
004D03AB  mov edx, [ebp-0x0C]
004D03AE  mov eax, [edx+0x04]     ; FormCount.form
004D03B1  mov ecx, [ebp-0x0C]
004D03B4  mov ecx, [ecx+0x04]
004D03B7  mov edx, [eax]          ; supposed form's vtable
004D03B9  mov eax, [edx+0x94]     ; crash: EDX = 0
004D03BF  call eax
```

CrashLogger records `EIP=0x004D03B9`, `EDX=0`, `EBP=0x0170F83C` and
`ESP=0x0170F820`. Thus the failing read is at `0x00000094`, before the
indirect call. The retained stack and verified local assignments establish:

| Location | Role | Captured value |
|---|---|---|
| `[EBP-0x1C]`, stack `00` | `ExtraContainerChanges::Data*` | `0xD7FF8FC0` |
| `[EBP-0x0C]`, stack `04` | Current `FormCount*` | `0x10D7D73C` |
| `[EBP-0x04]`, stack `06` | Current base-container node | `0xD7940009` |
| Caller `[0x0170F854-0x10]`, stack `09` | Character being processed | `0xF8449C00` |

The current node is unaligned. The loop nevertheless read it and consumed a
supposed form whose vtable was zero. This proves malformed base-inventory
traversal, not a valid form object with a missing optional method.

The Character is reported as Talon Company Merc reference `0607119E`, editor
ID `FFHitSquadDCTalonLeader`, with runtime NPC base `FF001DF9` and process
level Low. The reference belongs to `Fallout3.esm`. Its current package is
`FFHitSquadWaitForPlayerLeader`, last modified by
`TTW Dialogue and Interactions Expansion Overhaul.esp`. These identify the
object and package; they do not identify a corrupting writer.

The additional TESNPC-labelled stack value `0xD83B5464` is at `[EBP-0x18]`.
This local has not been assigned on the faulting first-loop path. Moreover,
its reported vtable `0x0104A270` is installed at NPC `+0x64` by the native
constructor/destructor. It must not be treated as the proven actor-base
allocation address. The actual item-form pointer and its allocation history
are absent from the log.

## Why Done reaches another NPC

The captured return addresses match this native chain:

| Boundary | Verified operation |
|---|---|
| `0x00785CF6`, return `0x00785CFB` | Continue advances the LevelUpMenu page through `0x00785830`. |
| `0x00785866`, return `0x0078586B` | The `_EndPage` branch calls completion owner `0x007851D0`. |
| `0x007851F2`, return `0x007851F7` | Completion calls player level-state owner `0x008D5270`. |
| `0x008D52BA`, return `0x008D52BF` | That owner calls process-manager traversal `0x00975EA0` with `ECX=0x011E0E80`. |
| `0x00975F7F`, return `0x00975F81` | Traversal dispatches actor virtual `+0x208` with argument byte `1`. |
| Character vtable `0x01086A6C+0x208` | Native target is `0x0089FB80`, thiscall, one argument, `ret 4`. |
| `0x0089FC1F`, return `0x0089FC24` | Actor callback calls inventory owner `0x00574920`, forwarding the argument. |
| `0x0057493E`, return `0x00574943` | Inventory owner calls `0x00577DE0`. |
| `0x00577E10`, return `0x00577E15` | That helper passes inventory Data to `0x004D0360`, the faulting predicate. |

`0x00975EA0` walks process groups `3` then `2` using the manager's group
bounds. The xNVSE process enum identifies these as Low and MiddleLow. Its
existing virtual predicates gate each actor dispatch. This explains why a
remote Low-process mercenary is processed while the player completes a menu.
The log also contains the visible LevelUpMenu and its `LUM_ContinueButton`.

`0x004BFFB0` follows Data.owner at `+0x04` to the reference's container through
`0x0055D310`. For an NPC/creature, that helper obtains the base through
`0x007AF430` and returns base `+0x64`; `0x00717E50` adds four to reach the
embedded list head at base `+0x68`. Nodes are `{data +0, next +4}`;
`FormCount` is `{count +0, form +4, extra +8}`. `0x006815C0` returns the
node address, and `0x00726070` returns its successor. All three fault-path
helpers use ECX for `this`, no stack arguments and plain `ret`.

## Existing protection and limits

The deployed configuration enables `save_integrity_fix` and
`actor_container_retirement_guard`; allocator mode `2` is active. The session
log confirms both guard families activated. Current source scopes protection
as follows:

- `engine_fixes/actor_container_guard.rs` validates retiring dynamic actor
  containers before destructor `0x005F77B0`. Detachment there is restricted
  to dying actors.
- `engine_fixes/save_integrity.rs` validates live dynamic actor bases at
  Character-load callsites `0x00562B8C` and `0x00562B98`, under the active
  changed-record load owner. Failure rejects the load; it does not repair or
  detach live inventory.
- This incident enters through `0x0089FC1F`, outside those two protected
  load callsites and the destructor. It has no established load rollback.

`aar; axt` finds one direct native caller of `0x004D0360`, four of
`0x00577DE0`, four of `0x00574920`, and one of `0x00975EA0`. These are
discovered direct calls, not exhaustive indirect or external-plugin coverage.
A shared-function replacement would affect more than this menu path.

The validator is reusable mechanism, not an automatic recovery policy or a
lifetime pin. Its nested-form identity check currently reads the FormID and
checks registry equality; it does not independently validate a vtable. The
available crash data does not establish its exact rejection for this incident.

The last Psycho memory sample reports 444 MB free VAS and a 202 MB largest
hole. Earlier pool refusals were accompanied by allocator fallback counters;
they do not prove a terminal allocation failure here. OMV's final reliability
record is four seconds before the archived crash time, with no world-pipeline
failures. Neither memory exhaustion nor rendering is established as the cause
of this specific fault. Other earlier corruption warnings in the session
lack an ownership/write link to this container.

## Fix plan and acceptance

### Shared intervention and caller results

`engine_fixes/inventory_reset_guard.rs` owns three shared entry hooks and two
inseparable native callsite hooks. They protect the base-list contract across callers,
without a perk, NPC, save, dynamic-FormID, allocator or mod selector:

| Entry | ABI | Rejected-input policy |
|---|---|---|
| `0x00577DE0` | thiscall(reference), byte in AL, plain RET | Return true, conservatively retaining uncertain quest inventory. |
| `0x00574920` | thiscall(reference, byte mode), void, RET 4 | Return before the query, inventory changes or base-list traversal. |
| `0x0089FB80` | thiscall(actor, byte mode), void, RET 4 | Return before process callbacks, inventory reset and subsequent equipment work. |

These are operation-entry rejections, not a NULL check followed by continued
processing. A rejected reset leaves the existing inventory intact; it cannot
complete a rebuild from an invalid list. Native updates for admitted input
remain with the original provider. No live list is detached, truncated,
reconstructed or freed, and no item or reference count is changed by the guard.

The standalone query has four direct native callers. True avoids the deletion
branch at `0x0054E17E`, the corpse cleanup branch at `0x0054E417`, and the
process cleanup candidate at `0x009772AB`. Its fourth caller is inventory reset.
That exact call at `0x0057493E` forwards to its captured CALL target, the
shared query entry, under a stack-owned rejection scope. It does not bypass
providers installed at that entry later. Its helper returns the original
query byte in AL and private rejection in bit 8. The callsite bridge tests
bit 8: success resumes at `0x00574943`; rejection executes the exact reset
epilogue from `0x00574A7A` (`mov esp, ebp; pop ebp; ret 4`). At this first
query boundary the verified reset frame has no saved registers, SEH frame or
local cleanup obligations. Its preceding flags-reader call has returned.
Thus a late conservative query result cannot send a rejected reset into
native inventory mutation. All Rust scope/provider frames return normally
before this native early return; none is bypassed.

The four direct native reset calls are at `0x0055F434`, `0x00562B8C`,
`0x00562B98` and `0x0089FC1F`. All consume a void result. Native reset already
has a no-container return, and the surrounding native owners conditionally
omit or select this operation. The enclosing actor hook additionally prevents
the later equipment consumers in `0x0089FB80` from receiving the same rejected
base list. After its process callbacks, the exact reset call at `0x0089FC1F`
uses `reset_with_result`, which calls the captured reset entry under another
stack-owned rejection scope. The shared entry retains its admission and
later provider chain. Its private Boolean reports scoped rejection, not a
new native reset result. The callsite bridge tests AL: success consumes its
original mode argument and resumes at `0x0089FC24`; rejection executes the
exact actor epilogue from `0x0089FCE8` (`mov esp, ebp; pop ebp; ret 4`).
The verified actor has no callee-saved register pushes, SEH frame or pending
local cleanup at that boundary. Its plain pointer locals need no destruction.
Thus rejection after the process callbacks skips both equipment consumers,
`0x0089FCC3` and `0x0089FCE3`, without changing any native caller's void ABI.
Already-executed callbacks are not rolled back. No admission is reused across
those callbacks.

The private Win32 TLS slot points only to Psycho-owned stack frames while
their providers execute synchronously. A rejection marks all enclosing frames
on that thread with the same reference address, including reset when its query
rejects. Different references and other threads do not share that decision.
Each scope restores its preceding pointer before its frame expires; nested
calls restore the outer scope. Win32 last error is preserved around TLS work.
No engine object is pinned or retained after return. Scope installation or
restoration failure poisons admission before another frame can be read; active
bridges return early and later operations reject until restart. Allocation of
the process-lifetime TLS index must succeed before any hook activates.

On the active save-integrity load-owner thread, every rejection also latches
the existing whole-load error without reading or marking a changed record.
Thus the load owner returns failure rather than accepting a partial load after
a skipped reset. Gameplay, other threads and an inactive save-integrity owner
do not borrow or initialize a load transaction. Save integrity owns this
notification through `reject_inventory_reset_during_load`; the new guard
never accesses a load-owner pointer or record directly. Shared reset/query
calls have no record ownership: `ACTIVE_CHANGED_RECORD` remains published
after record application returns. The precise existing Character-load guards
retain their separate record-rejection policy. This notification uses the
established whole-load failure policy for errors without record ownership.

The actor implementation has three native vtable references, at
`0x0108445C`, `0x01086C74` and `0x010872B4`. An executable-section scan of all
register-load/direct-displaced-call encodings at offset `+0x208`, followed by
receiver and ABI classification, found these ten reference dispatch sites:

```text
0054E023  0054E071  0054E511  0055F44B  00562BAF  00574034
005DAC79  008864FD  0089FA45  00975F7F
```

Each dispatch supplies one stack argument and ignores the return value.
Continuations advance a loop, inspect existing reference/process state, or
perform their own subsequent operations; none consumes a returned pointer or
claims ownership of a result. This establishes the void rejection ABI, not a
guarantee that an already-corrupt actor is safe for every future engine use.
Two other dispatch matches, `0x0089FEDE` and `0x0097F693`, are excluded:
their receiver comes from `0x008D8520` (actor `+0x68`, the process pointer),
they supply two arguments, and their floating-point result is consumed by
`0x00EC62C0`. They do not call the guarded actor implementation. Remaining
offset matches are ordinary data fields. External callers and computed dispatch cannot
be exhaustively enumerated from the unmodified executable; they must retain
the same native input lifetime and void-result contract.

New raw evidence:

- [Reset, equipment and base-list consumers](../analysis/radare2/output/crash_20261020_levelup_shared_reset_research.txt).
- [Direct query/reset caller windows](../analysis/radare2/output/crash_20261020_levelup_reset_caller_windows.txt).
- [Existing inventory getter and dispatch](../analysis/radare2/output/crash_20261020_levelup_data_and_dispatch.txt).
- [Extra-data lookup, reset and resurrection continuations](../analysis/radare2/output/crash_20261020_levelup_reset_continuations.txt).
- [Complete offset-encoding scan](../analysis/radare2/output/crash_20261020_levelup_complete_dispatch_scan.txt).
- [Additional void-call continuations](../analysis/radare2/output/crash_20261020_levelup_void_call_continuations.txt).
- [Existing-Data cache](../analysis/radare2/output/crash_20261020_levelup_existing_data_cache.txt).
- [Cache lifetime and fill helper](../analysis/radare2/output/crash_20261020_levelup_cache_lifetime.txt).
- [Compiled hook and continuation ABI](../analysis/radare2/output/crash_20261020_inventory_reset_corrected_compiled_abi.txt).
- [Reset prefix, read-only flags helper and actor epilogue](../analysis/radare2/output/crash_20261020_inventory_reset_correction_boundaries.txt).
- [Classified receiver paths and load error predicate](../analysis/radare2/output/crash_20261020_inventory_reset_correction_callers.txt).
- [Process dispatch result and continuations](../analysis/radare2/output/crash_20261020_inventory_reset_review_continuations.txt).
- [Actor process getter and load scope](../analysis/radare2/output/crash_20261020_inventory_reset_review_load_scope.txt).
- [Nested reset caller ownership](../analysis/radare2/output/crash_20261020_inventory_reset_review_nested_owners.txt).

### Admission, lifetime and costs

Admission guarded-copies the reference's base field and type, then the embedded
base list head. Native `0x0055D310` establishes head offsets `+0x34` for a
container form (`0x1B`) and `+0x68` for NPC/creature (`0x2A`/`0x2B`). Other
types and a NULL base retain native no-container handling.

Each visited node must expose its two words, each nonempty record its complete
12-byte FormCount prefix, and each item its vtable and virtual `+0x94` slot.
The callback address must be on an executable page; its module or identity is
not classified. A native empty terminal node is accepted. A NULL data word
with a successor is rejected because `0x008256D0` does not consider it empty
and reset would dereference it. Brent cycle detection imposes no item limit.

For a reference with a container, the existing-Data getter at `0x00418520`
reads its embedded ExtraDataList (`+0x44`). The getter has no arguments beyond
ECX and plain RET; it returns NULL without creating missing inventory. Its
lookup at `0x00410220` preserves the native presence-bit/cache/lock contract.
It may populate lookup cache state, but does not create, reset or own inventory.
The cache helpers at `0x0040F9E0`, `0x0040FA40` and `0x0040F900` use the
existing game TLS block: they read/write the current-list and epoch words and
the fixed extra-data pointer array. Clearing that array uses the established
native memory-fill wrapper at `0x00403D30`, not an inventory allocation. The
call inherits the engine's initialized game-TLS precondition.
If Data exists, guarded-copy its owner at `+0x04` and validate that owner's base
as well. An identical owner reuses this invocation's just-completed base check.
A different owner is not rejected merely for differing: its consumed base is
checked independently. A Data owner without a container is rejected because
the Data predicate's head accessor unconditionally adds four to that result.

The native caller must keep the reference, initialized ExtraDataList, Data,
base form and list alive for admission and the original call. This retains the
existing synchronization precondition; snapshots do not pin objects or repair
a race. The getter retains its existing native lock/cache behavior. The new
code adds no allocator-ownership classifier, object allowlist, reference-count
mutation or destructor hook.

Admitted input calls each process-lifetime trampoline exactly once with the
original arguments and preserves its native result. Admission preserves Win32
last error before forwarding or rejecting. All three complete native bodies
are fingerprinted before activation; a changed body leaves the whole fix
inactive. Entry and CALL providers are published before one rollback
transaction activates all five hooks. With admission inactive, a surviving
callsite bridge forwards and resumes the native continuation; it cannot apply
an isolated early-return policy. There is no object cache or rejection state
that survives its synchronous operation scope.

Work is linear in visited base entries with constant stack storage. Actor
refresh validates before callbacks, again at reset, and again at the query.
Each boundary can have an intervening provider, so the checks are retained
instead of bypassing that provider or reusing an earlier snapshot. With the
ordinary identical Data owner, the chain can perform twelve guarded copies
and three executable-page queries per nonempty base entry, plus fixed
reference/owner reads and existing-Data lookups. TLS work adds fixed entry/exit
cost at both callsites; scope traversal occurs only on rejection and follows
the real synchronous call depth. No object pointer is cached across calls. OS
memory copies, executable-page queries, TLS and existing-Data lookup have
unmeasured workload cost; there is no FPS claim. Normal admission allocates no
memory, emits no log, creates no worker and retains no object pointer. Only
the first rejection emits a warning.

This guards the proven base-item-list path. It does not validate every nested
inventory-extra object, repair readable stale objects, undo pre-existing
corruption or protect every later consumer outside the three guarded owners.
The original writer and any race/allocator/mod attribution remain unknown.

### Configuration and helper

`[engine_fixes].inventory_reset_guard` defaults to true. False skips the
installer before reader preparation, trampoline creation or code changes.
The setting is appended to the private core/helper configuration structures;
the published dashboard ABI is unchanged. The helper reads and saves it
through the existing comment-preserving, restart-only editor.

The shipped TOML uses the neighbouring imperative comment style:

```toml
# Skip inventory resets with broken base-item lists instead of crashing.
# Valid inventories are unchanged; rejected resets leave items untouched.
inventory_reset_guard = true
```

The helper label is "Inventory reset guard". Its tooltip uses the same
third-person, player-facing style as the other guard descriptions:
"Skips inventory resets with broken base-item lists instead of crashing.
Valid inventories are unchanged; rejected resets leave items untouched."

### Qualification and remaining acceptance

Focused checks execute the production admission's guarded-copy boundary on
unreadable/wrapping input, rejection with Win32 last-error preservation, real
Win32 scope propagation/restoration and thread isolation, and the core/helper
configuration parsers and editor. Scope tests use actual Psycho-owned metadata,
not fabricated engine objects or providers. They support the game failure, not an
offline recreation of an NPC or proof of gameplay. No mocked provider,
reconstructed engine function or synthetic inventory establishes acceptance.

The affected core and helper suites, formatting, supported complete 32-bit
release build, startup-footprint comparison and final diff review passed.
Compiled hook inspection confirms ECX forwarding, AL/plain RET for the query,
and byte-mode forwarding with RET 4 for both void owners. The core and helper
retain their imported DLL/symbol sequences, TLS raw size and TLS callback set
relative to the retained on-disk comparison. Results are retained in
`.reports/20261020-levelup-done/implementation/`; build success never proves
that the game exercised the guard.

Startup deliberately adds one appended Boolean setting, three inert lazy entry
hook containers, two lazy callsite containers, entry/CALL provider pointers,
admission/report/scope-health flags and one OnceLock holding a Win32 TLS index.
The existing
pre-CRT core installer prepares them after actor-container retirement and
before animation/save guards. The index is allocated there using the existing
core-only dynamic Win32 TLS wrapper. No dependency, thread, PE TLS variable, worker,
new startup phase or helper/core ownership change is introduced. Configuration
layout and native patch work still change the pre-deferred footprint, so the
startup contract's Proton acceptance remains pending. Current on-disk image
identity and PE evidence are retained separately from the reported session;
they are not promoted to a new accepted runtime baseline.

Reporter acceptance requires a guard rejection and continued gameplay through
Done, with the expected level, selected skill increases and Commando rank.
Valid NPC inventories and native level-dependent updates must remain correct;
a rejected corrupt reset must leave existing items intact. Verify save/reload
persistence and ordinary creation/load, corpse cleanup and Low/MiddleLow
processing with the production fix. The pre-level-up replay save and exact
skill choices remain unavailable locally. Neither gameplay, helper visual
presentation nor startup acceptance was run by the agent. Deployment remains
user-only; this is a functional fix candidate, not a diagnostics-only build.
