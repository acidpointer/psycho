# LOD streaming and handoff engine-fix plan

## Goal

Improve native LOD demand, task service, real-model attachment, replacement
in both directions, and retirement in `psycho-engine-fixes`, independently
of allocator mode. The implemented foundation has two separately installable
but complementary changes:

1. Request terrain, object, and tree LOD before the vanilla visibility boundary
   and retain loaded blocks across small camera reversals.
2. Replace the broken lifetime-total handoff gate with current-generation,
   reference-identity readiness.

The implementation must keep the native LOD task constructors, dependency
graph, IO manager, completion queues, native publication phases, scene roots, and
fade/retirement phase. It must not add a custom loading thread, uncap the
global completed-task budget, or patch generic NiLOD, NiRangeLODData,
NiScreenLODData, NiSwitchNode, or BSFade behavior.

The xNVSE helper remains optional and does not install, own, or initialize the
fix.

## Current demand and membership contract

The unreleased implementation covers stages 1-6 of the complete change set:
correct native demand inputs, identity accounting and recovery, ordinary
coverage guards, native-stage measurements, attachment budgeting and owning
queued-task promotion. Pressure-based admission, draw-distance tuning and
earlier whole-cell eviction remain the evidence-dependent stage 7.

### Runtime evidence and qualification boundary

The supplied latest Psycho log, dated 2026-10-11, reports streaming, handoff,
and demand-aware priority active, with object/tree margins `1.35/1.50` and
terrain margins `1.10/1.20`. It also reports a membership removal mismatch,
followed by stale ready publications for the same cell. Those observations
prove that the ledger became uncertain and rejected later readiness; they do
not identify a missing insertion or prove a particular lifetime race. Trace
was disabled in that run.

For this task the owner explicitly authorized proceeding without gameplay
validation and supplied the latest logs as evidence. That task-specific
exception does not prove runtime transitions, image quality, startup
compatibility, or performance. The candidate is qualified offline only.

### Native demand proof

The supported executable is the FalloutNV `1.4.0.525` image identified in the
stale-retention audit below. Its identity was reconfirmed before using these
addresses. The primary interface for the focused verification was radare2
MCP. Raw instruction evidence is preserved in
[the demand and membership audit](../analysis/radare2/output/perf/lod_streaming_membership_publication_audit.txt).

Four incorrect Psycho contracts previously prevented a reliable extension:

| Native contract | Correct Psycho access |
|---|---|
| Predicates `0x006FE550`, `0x006FE620`, `0x006FE780` define their result in AL. Upper EAX contains unrelated data. | Declare and consume `u8`, preserving a nonzero predecessor result. |
| `0x01017A10` contains a double representing 4096 world units. Native code multiplies an unsigned node level by that double and stores a float. | Read `f64`, perform the multiplication, then convert to `f32`. |
| Node `+0x34/+0x38` is the block center. Constructor `0x006FD210` adds half the block size to the cell origin; metric `0x006FE830` subtracts that half before testing square bounds. | Compute distance to the centered square. |
| Object and tree native callers put setting objects `0x011D877C` and `0x011D8788` directly in ECX for getter `0x00403E20`. | Pass the setting address rather than interpreting its first word as a pointer. |

Terrain has an additional structural exclusion: `0x006FE550` compares node
`+0x04` with its manager's root level, returned by `0x00441110` from manager
`+0x1C`. Equality returns false before any distance calculation. Psycho keeps
that exclusion instead of treating it as a distance rejection to extend.

Settings and extra geometry are now read only after native demand returns
false. A native true result avoids the additional setting-getter call.
Invalid geometry, unavailable settings, or an excluded terrain root preserve
the native false result. The safe production distance function was exercised
with constructor-backed inputs before correction: a level-one block centered
at `(2048, 2048)` incorrectly placed camera `(0, 0)` 2896.3093 units away.
The corrected function returns zero and passes edge, corner, negative-cell,
and invalid/overflowing-input checks.

The existing multipliers and their validation remain authoritative. These
repairs enable the intended earlier requests and retention bands; they do
not extend the engine's draw/fade distance, generate missing LOD assets, or
establish new optimal margins. Effective prefetch can increase concurrent
asset residency, so no FPS or memory improvement follows from the repair
alone.

### Reference publication boundary

Native insertion `0x00548230` increments cell `+0xA8` before the exterior path
calls removal `0x0054CA90` on the previous cell owner. A same-cell reinsertion
can therefore have a zero net counter change. Native attachment also runs
before the outer insertion returns. Observing only its final counter delta
can omit an actual insertion or observe readiness first.

The handoff transaction instead captures the two native prepend providers:

| Publication call | Caller-owned inputs | Native predecessor |
|---|---|---|
| Interior `0x005482AB` | List in ECX, reference-slot pointer on the stack, cell at `[EBP-0x1C]`. | `0x005AE3D0` |
| Exterior `0x00548344` | Same ABI and caller frame. | `0x005AE3D0` |

Both callsites execute under the cell reference lock entered by `0x00541AC0`
and released by `0x00541AE0`, using cell `+0x80`. List accessor `0x009604F0`
returns cell `+0xAC`. The prepend accepts a pointer to the caller's reference
argument, publishes that reference at the list head, and cleans four stack
bytes. Its caller consumes no return value. The naked bridges copy the live
caller frame into EDX, call a fastcall observer, then preserve ret-4. The
observer obtains the reference-slot address and cell from the verified frame
and forwards that original slot address to the installed provider.

The body forwards the installed call provider once with the original list
and argument. Only after successful head publication does it record the
physical reference, before parent assignment and real-3D attachment. Counter
enrollment is reserved at the actual `0x0054827F` store, after native VWD
predicate `0x00564E60` and initially-disabled predicate `0x00440DA0` have
selected it. This preserves base-form VWD eligibility and correlates the
same-cell insertion even when old-owner removal cancels its net counter delta.

The observer owns only sidecar identities. It does not write native lists,
counts, parent pointers, intrusive references, scene state, or task ownership.
Its lock order is cell reference lock followed by ledger lock; ledger
consumers do not call native engine functions while holding the ledger lock.
Ledger allocation occurs at lifecycle observations, outside demand predicates.
Counter retirement, physical removal, readiness, reload/teardown and worldspace
invalidation retain their installed providers.
Concurrent or unobserved lifecycle changes leave the ledger fail-closed; this
candidate does not recover unidentified external mutations by guessing
ownership or credits. The full-flow contracts below define the accounting
and hide guards used after transition start.

Installation verifies both instruction contexts and relative-call opcodes,
captures executable predecessors, and uses the owning handoff transaction's
rollback. A provider that does not publish the supplied head marks the cell
uncertain and records a sampled failure. There is no module identification
or vtable allowlist. Current provider addresses and publication failures
appear in `PsychoInfo` diagnostics.

### Optional accounting and evidence boundaries

`diagnostics.lod_streaming_trace` also enables per-kind demand accounting.
`PsychoInfo` reports predicate calls, unloaded-node early admissions,
loaded/pending-block retention admissions, and evaluated retention-boundary
release decisions. The existing helper ABI receives the corresponding
aggregate calls/early/retained counts. Disabled tracing performs no demand
counter updates, clocks, allocations, or log writes. Counts survive
worldspace changes and are observations rather than scheduling inputs.
Release decisions are not completion events and do not measure reclaimed
memory. Optional native-stage observers are implemented; no candidate gameplay
measurements or same-route performance results have been collected.

The broader roadmap has the following evidence boundaries:

| Flow stage | Implemented behavior or remaining requirement |
|---|---|
| Distance and early loading | Correct native inputs and centered geometry; retain the existing validated margins. Visual draw-distance tuning remains separate. |
| Membership and forward handoff | Publication and enrollment observers distinguish physical membership and genuine current-instance credits, with recovery, ordinary completion and scoped selection guards. |
| Task service | Constructor priority remains active. The native owning iterator, existing thread-context admission and root/texture dependency lifecycle now support bounded queued promotion. |
| Real-model replacement | Queue `+0x1C` drains before the generic IO deadline. A verified ordinary-frame chain, native pending query and partial-drain epilogue now support budgeting between callbacks. |
| Return to LOD | `0x00557C40` clears the hidden flag before cell-task cancellation and real-reference retirement. Actual segment visibility remains conditional on native manager updates and existing geometry. |
| Block retirement | Native demand-false handling releases blocks through the existing manager. The retention band intentionally retains residency and is not a faster whole-cell eviction policy. |
| Whole-cell unloading and caches | IO/task, physics, and renderer ownership barriers remain required. Earlier detach, batch retirement, and cache eviction need complete ownership and cost evidence. |
| Memory admission | A bounded priority-provenance set is not a bound on in-flight bytes. Pressure-based admission requires measured native asset residency and a proven safe sampling boundary. |

A raw task lookup from the demand hook is specifically unsafe to add on the
current evidence. IOManager worker slot-2 dispatch at `0x00C3FCA0` can call
object-block completion `0x006F6150` or tree completion `0x006F88E0`, which
clear the block's intrusive task holder through `0x006F74F0`. Reading the
holder and incrementing the task afterward is not a proven atomic acquisition.
Do not implement promotion using a non-owning cached task pointer, assume
that completed-array ownership covers every cancellation path, or retain
tasks indefinitely merely to avoid closing that contract.

Qualification executes the production distance, ledger, coverage decision,
deadline, association and aggregation paths outside the game, plus affected
core/helper/shared-library suites and the supported 32-bit release build.
Native addresses and ABI are checked against the supported executable and
compiled bridges. Native hook execution, full-scene handoff in both directions,
startup compatibility and same-route performance have not been run. The owner
waived gameplay validation for this task; no runtime acceptance or FPS/memory
improvement follows from offline qualification.

## Implemented candidate ownership and limits

The core owns every engine observer and policy. The helper adds only the
restart-required `Attach budget` preference through its existing TOML editor.
`[lod].attachment_budget_enabled` defaults to true and uses the existing native
ordinary-service deadline; it does not introduce a guessed millisecond budget.
The other LOD switches remain independent, under `lod.enabled`. Priority-only
and trace-only demand observation preserve native demand without enabling
prefetch. Constructor priority survives a queued-observer installation failure.

Each group prepares at the existing quiescent core startup boundary and uses
transactional rollback. Membership, readiness, completion, both scoped geometry
queries and all ordinary/forced mode observers form the handoff transaction.
The first/next acquisition and completion-result patches form the service
transaction. Required task/node lifetime observers and optional measurement
hooks have separate transactions. Queue promotion requires installed demand,
world reset, service and task lifetime observation. A failed prerequisite keeps
the existing constructor policy and native queue ownership.

| Component | Bounded work and failure behavior |
|---|---|
| Demand | No allocation, mutex, clock or log call. Native true skips distance/settings work. Actual native demand publishes copied visibility separately from speculative provenance. |
| Ledger | Separates physical occurrence, enrollment invocation, ready instance and reset epoch. New sidecars are uncertain until a complete locked-list reconciliation. Unknown/duplicate identity cannot create a credit. Known credits survive unrelated uncertainty. Cheap denial states skip membership scanning. |
| List observation | At most 4096 native nodes per scan, including an exactly full terminating list; full snapshots use 16 KiB of stack and sort once for identity matching. Overflow blocks retirement. An incomplete reload snapshot ends native reset execution but retains explicit recovery debt. Reload observation never reconstructs 3D. |
| Geometry publication | 4096 slots, at most 32 probes. One AtomicU64 packs the supported 32-bit cell identity, lifecycle mode and permission; lookup uses that same load for identity and verdict. Concurrent publication cannot create a torn/untracked fallback. Ordinary completion requires current identity readiness and a currently allowed published slot; overflow or a later reservation cannot authorize a hide. |
| Queued promotion | At most 32 owning acquisitions and one priority-provider request per ordinary service, with deadline checks between calls. Iterator reset/destruction precedes rekey; every pin clears through the native intrusive helper. One native acquisition/provider call is unpreemptible. |
| Task associations | At most 16384 task records and 8192 parent links. Child/parent adjacency and node/root indexes let generation/node reuse and cancellation invalidate only affected associations. Shared textures retain other parents' interests. All directions reserve capacity before publication; capacity or allocation failure clears every index and disarms queued promotion until world reset, without changing native tasks. |
| Optional trace | Each correlation array has 2048 slots and 32 probes. Nonblocking publication drops optional observations on contention. A lost lifetime/burst invalidation disarms existing spans before the next publisher, preventing address reuse from fabricating elapsed time. Reporting allocates only at the existing explicit diagnostic boundary. |

Identity keys never retain engine objects. Engine providers run outside sidecar
mutexes. Actual list inspection takes CellRefLock before the ledger; no ledger
consumer enters native locking or task APIs while holding that mutex. Required
membership and task metadata can allocate during native lifecycle callbacks;
queued scanning, demand, geometry decisions and graph invalidation do not
allocate. Reverse indexes add bounded metadata at root/link publication.
Invalidation visits the affected adjacency lists rather than every association;
a heavily shared texture can still require substantial local work. These are
CPU work bounds, not an FPS or gameplay-performance claim.

Native ABI details corrected during implementation are preserved in
[the focused candidate ABI audit](../analysis/radare2/output/perf/lod_streaming_candidate_abi_audit.txt):

- `0x0054CB1E` pushes `&[EBP+0x08]`, and `0x00905330` dereferences it.
  The remover receives the reference-slot address, not the reference value.
  It remains a void first-match operation with ret-4.
- `0x00C3E029 -> 0x00C3E1B0 -> 0x00C3E286` passes IOManager unchanged to
  the owning iterator. Worker `+0x30` points to this manager; it is not a
  queue field within the manager.
- Slot-7 `0x00C3CAE0` preserves AL through `0x00C3DF40` from
  `0x00C3E690`. Counters report native acceptance/rejection, without rereading
  the concurrently mutable key or claiming that accepted work reached a worker.
- Deferred attachment tasks use `0x004404C0 -> 0x00440540 -> 0x00449090`
  and destruction `0x00440680 -> 0x004406B0 -> 0x00440640 -> 0x004490E0`.
  Their trace observes that separate family, rather than assigning the
  `0x00C3C590/0x00C3C620` IO-task lifetime to it.

TLS preflight reads only an already registered current-thread slot. The wrapper
preserves LastError because
[Microsoft documents its clearing by TlsGetValue](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue).
It allocates no slot and does not invoke the iterator's unchecked registration
fallback. The real Windows TLS behavior is exercised through Wine.

`PsychoInfo` reports native submit/dependency/worker/publication spans, direct
and deferred attachment calls, callback outcomes, ready-to-hide and
reverse-to-selection observations, retained cancellation bodies, release calls, node/kind churn,
and service/promotion cost. Drain observations count returned native slot-5
callbacks between first acquisition and actual empty-holder exit; this mixed
native queue is not LOD-exclusive. The measured drain excludes holder setup and
final SEH cleanup. The locked pending count is a dated expiration-query sample;
unpaired enqueue observations are explicitly not a current queue-size claim.
Missing clocks, missed events and absent samples remain unavailable, rather
than becoming zero latency. Shared-texture work is associated with LOD parents,
not attributed exclusively to LOD. Existing process RSS/commit samples are
process totals and may be unavailable; no GPU or LOD-byte sampler was added.

Budgeting preserves first-callback progress, the complete callback, native
cleanup and the incomplete AL result. It yields only on strict native deadline
expiration with a proven positive pending count under the owning queue lock.
An unknown pop/count contract, unsupported frame, missing clock or blocking
load retains the full native drain. Reduced burst work can increase deferred
attachment wait; measurements must assess both. Native real-reference retirement,
physics/script barriers, cache eviction and actual draw/fade distances remain
native. Existing distance margins are retained; the candidate does not establish
faster whole-cell unloading, reclaimed bytes, FPS or optimal distance settings.

The production zero-counter and completion-publication regressions were failed
before their corrections; the TLS LastError regression likewise reproduced the
WinAPI side effect before preservation. Evidence is retained under `.reports/`.
These tests execute shipped Rust/WinAPI behavior, not substitute engine queues.
The remaining game-only integration, images, startup and performance behavior
are unrun under the owner's explicit waiver. Stage 7 requires measured costs
and any additional engine ownership proof, rather than invented tuning values.

### Extreme-speed flight cancellation crash

The owner reported crashes during extreme-speed flight around the map. The
initial runtime baseline is preserved in
[CrashLogger](../.reports/CrashLogger-20261012-193826-lod-stress.log) and
[the Psycho log](../.reports/psycho-engine-fixes-20261012-193826-lod-stress.log).
The run had streaming, handoff and priority enabled, with stage trace disabled.
It does not establish a save-load or explicit cell-purge trigger.

The recurrence is preserved in
[the second CrashLogger report](../.reports/CrashLogger-20261013-lod-stress.log)
and [its Psycho log](../.reports/psycho-engine-fixes-20261013-lod-stress.log).
It faults at the same `0x00C3CE21` read with ECX `4` and EDX `1`. The
deployed code contains the cancellation observer correction described below;
that correction alone is insufficient. Double-free warnings again precede
the crash, including `0xD5072370`, which also appears in the stack scan. The
scan does not establish which release invalidated the task or array.

The stack word identities are now decoded, rather than attributed from an
unrelated register. [CrashLogger 5.17's stack printer](https://github.com/yvileapsis/yUI-NVSE/blob/5.17/CrashLogger/RegistryStack.cpp#L223)
prints zero-based hexadecimal indices of `ESP[i]`. The verified native
`0x00C3CB70` frame has `ESP = EBP - 0xB0` at the fault. Therefore:

| Stack row | Native local | Recurrence value |
|---|---|---|
| `02` | Saved cancellation task `[EBP-0xA8]` | `0xC73B65E0`, vtable `0x01017138` (`BSTask`). |
| `0C` | Computed child-slot address `[EBP-0x80]` | `4`, matching the faulting ECX. |
| `28` | Previously processed child `[EBP-0x10]` | `0xD5072370`, matching the final double-free warning. |

The terrain constructor publishes vtable `0x0106E1DC`; base destruction
`0x00C3C620` writes `0x01017138` after deleting its dependency storage.
The supplied task has therefore left the expected fully constructed terrain
task lifetime. The earlier report's row `02` likewise identifies its actual
cancellation task as `0xC73E5920`, with an interpolator vtable. Neither report
proves which destructor or subsequent address reuse produced that state.
The native dependency-array destructor clears its data pointer at
`0x00C3DA16` and count at `0x00C3DA34`; cancellation keeps its loop count in
a separate stack local. Destruction thus supplies a concrete native path to
the observed null data pointer with a still-active cancellation loop.

The native fault is the child-slot read at `0x00C3CE21` in IOTask cancellation
`0x00C3CB70`. The stack follows terrain-block destruction
`0x006FA420 -> 0x0044AC40 -> Psycho -> 0x00C3CB70`. The faulting slot address
is `4`, so the native child-array input is invalid at that read. Repeated
double-free warnings precede the crash, but neither log identifies the earlier
invalidating operation. The owner confirmed these are the only available
reports; no minidump is available. CrashLogger's classification of a register
does not prove the task's original type or allocator ownership.

#### Binary proof and Psycho ordering correction

Executable identity was reconfirmed against the same supported FalloutNV
`1.4.0.525` image. The deployed observer was inspected because its return
address appears in the crash stack. It forwards the original task, flag and
parent with the correct thiscall ABI; a swapped argument is not established.
The focused native evidence is linked in
[the cancellation lifetime audit](../analysis/radare2/output/perf/lod_stress_cancellation_lifetime_audit_20261012.txt),
with the fault-path observer preserved in
[the deployed-code inspection](../.reports/lod-stress-deployed-observer-20261012.txt).

The old Psycho entry observer acquired its registry mutex and invalidated
associations before calling native cancellation. Native cancellation acquires
its self-reference only at `0x00C3CB89`. That added potentially blocking work
before the native retain is a proven ordering hazard in the faulting path.
Whether this delay caused the observed invalidation remains unresolved.

| Boundary | Proven contract and candidate behavior |
|---|---|
| Native entry | `0x00C3CB70` saves ECX at `[EBP-0xA8]`; flag and parent remain at `[EBP+8]` and `[EBP+0x0C]`. The exact frame/setup bytes are required before installation. |
| Self-retain | `0x00C3CB89` calls the live IAT provider at `0x00FDF1C0` with the already-pushed task `+8` address. The splice executes that original stdcall retain once before any Psycho work and resumes at `0x00C3CB8F`. |
| Observation | After retain, copy the saved task and opaque parent identities from the live native frame. Invalidate associations under the existing registry mutex; no native provider runs under that mutex. |
| Self-release | All normal cancellation branches converge at `0x00C3CE44`. The exit splice preserves registers/flags, finishes optional timing, restores ECX from `[EBP-0xA8]`, then resumes the original release at `0x00C3CE4A`. Native ret-8 remains unchanged. |
| Installation failure | Both cancellation splices belong to the complete task-lifetime transaction. Unknown frame or site bytes roll it back and leave the existing constructor-priority policy available. |

The correction removes the Psycho cancellation entry detour. It does not add
a reference, revive a task, replace child arrays, alter task states, suppress
native cancellation, change allocator behavior, or modify another provider.
The original IAT retain and final native release remain the ownership
operations. Native callers, including derived terrain cancellation, reach
the shared body; their arguments and native completion behavior are preserved.

Optional cancellation timing now measures `cancel-retained-body`: after the
initial registry observer, before the final native self-release. It excludes
the entry retain, initial observer and final release, and includes nested
cancellation work within the body. A bounded 2048-slot correlation array uses
the live frame only as an opaque invocation key. Reuse, reset and lost lifetime
events discard old spans; observations use the existing nonblocking trace
lock. Trace-disabled runs do not initialize this storage or sample its clock.

#### Terrain retirement ownership gap

The supported executable proves an earlier lifetime gap on this same path.
The complete instruction evidence is in
[the terrain ownership audit](../analysis/radare2/output/perf/lod_terrain_retirement_ownership_audit_20261013.txt).

| Native owner | Lifetime and ABI proof |
|---|---|
| Block construction `0x006FA210` | Initializes the task holder at block `+0x24`. Stores/retains the completed task through `0x006F74F0` at `0x006FA349`, then invokes slot 8 at `0x006FA367` to start dependencies. The block holder exists before worker admission. |
| Block destruction `0x006FA420` | Thiscall, no stack arguments, void. Reads `+0x24` through raw getter `0x00559450`, then calls cancellation at `0x006FA51C` without acquiring a reference for that borrowed pointer. It clears the holder at `0x006FA56F`; member destruction later uses `0x0044CBF0`. |
| Cancellation `0x0044AC40` | Thiscall on IOManager, task and opaque parent as two stack arguments, ret-8. Polls running states 3/4, then CAS-reserves eligible work as state 6 before virtual cancellation. The observed state-5 branch has no entry retain. |
| Worker publication | `0x00C41255/0x00C41272` execute both task phases with a worker-owned reference. Terrain slot 2 `0x006FC020` reaches block publication `0x006FA990` only at `0x006FC39F`. |
| Publication `0x006FA990` | Thiscall on the block, no stack arguments, void. Transfers geometry from the current task, clears block `+0x24` at `0x006FAA03`, then still writes block readiness and the owning node's flags. Its complete body must be protected, rather than only its holder store. |
| Completion/release | After slot 2 returns, `0x00C3FCA0` publishes state 5 and removes queue ownership through `0x0044E050`; `0x00C412A4` releases worker ownership. The block holder and worker reference can therefore both disappear while the native cancellation owner is using its raw borrow. |
| Owning capture | `0x00528CB0` initializes a pointer-sized local holder and retains task `+8` through `0x0092C870`, ret-4. `0x006F74F0` clears that holder and releases exactly its reference, ret-4. Reading a holder and retaining it later is safe only under the same publication exclusion. |
| Final storage owner | Scalar-delete `0x006FD8F0` calls `0x006FA420` before freeing block storage. Its native callers are node retirement `0x006FD7B0` and node destruction `0x006FDA10`; each clears its block field after scalar-delete returns. |

The concrete defect is holding an unowned task borrow across a worker wait.
Cancellation's self-retain occurs after that wait; moving a Psycho observer
after this retain cannot protect the earlier interval. A worker can complete
publication, drop the block/queue/worker references, and enter destruction
before the waiting cancellation caller acquires its own reference. This is
a proven native ownership gap. The reports do not capture the precise
interleaving or prove that it accounts for every preceding double free.

`lod/terrain_lifetime.rs` owns the correction at the two complete block
boundaries:

1. Serialize `0x006FA990` publication with retirement acquisition using one
   of 64 fixed mutex stripes selected from the block address. Protect its
   holder clear and remaining block/node writes in the same interval.
2. At `0x006FA420` entry, clone the native task holder while the same stripe
   excludes worker mutation. No task pointer is retained from an earlier
   demand observation, frame, generation, or sidecar lookup.
3. Leave the stripe before calling the cancellation provider already installed
   at `0x006FA51C`, with the live IOManager, owning task and original null
   parent. Native cancellation retains its worker waits, CAS, dependency
   traversal and cleanup. Publication must finish or be cancelled before
   native scene teardown starts.
4. Clear the joined block holder through the provider already installed at
   `0x006FA56F`. This prevents a second cancellation call on a raw borrow.
   Release the temporary owner outside the stripe while the block/node remain
   live, then call the original block destructor once. Native teardown still
   owns geometry, caches, scene removal, members and final storage release.

Both hooks prepare and activate in one rollback transaction at the existing
quiescent core boundary. A shared admission atomic is published only after
both activations commit. Restoration is best-effort: an entry detour left
installed after rollback failure remains inert, forwarding its immutable
original provider before any priority change, lock or holder inspection.
The ownership repair is independent of LOD optimization switches,
tracing and allocator mode; it does not change configuration layout or worker
topology. Null block input chains the original provider without inspection.
An unavailable manager retains native teardown with the temporary owner held
until return. Installation failure reports that the ownership capability is
unavailable and never admits ownership intervention.

The stripe table is static and cannot overflow or lose a required event. A
collision can serialize unrelated terrain publications, while different
stripes remain concurrent. Each retirement uses one stack-local intrusive
holder; it adds no task, cache, indefinite retention, clock, allocation, or
normal-path diagnostic. The existing supplemental-worker priority guard
temporarily raises a background lock owner to avoid priority inversion.
No stripe or sidecar mutex spans cancellation's worker wait, final task
destruction, or block teardown. This ordering avoids a worker waiting for the
same lock held by a main thread that is joining that worker.

The repair is scoped to the observed terrain-block retirement path. It does
not assert that every object/tree block replacement or shared dependency
mutation has the same acquisition contract; those paths require their own
complete ownership proof before changing them.

#### Attribution and acceptance boundary

The reports prove the repeated invalid read and rejection of the first
observer-only correction. The executable proves the raw-borrow/worker-release
gap and the earlier ownership boundary used by the new correction. Neither
report identifies the exact winning release, origin of every double free,
allocator attribution, or mod attribution. This ownership repair cannot
restore a task or child array already invalidated by another operation before
its synchronized acquisition. No guard rejection, recovered invalid array,
or reclaimed-memory claim follows from the change.

The owner authorized proceeding without gameplay validation. Offline tests
exercise the existing production LOD policies and correlation handling;
compiled-code inspection checks the new thiscall hooks and native owning-helper
calls. Terrain publication, cancellation and destruction require the game and
are not replaced by a modeled queue or mock ownership test. The correction is
offline-qualified only; post-change stress behavior, native integration,
startup compatibility and performance are unrun. The owner alone decides when
to provide further gameplay evidence. Changes remain unreleased.

### Publication and reload recovery invariants

Geometry classification uses one packed atomic decision per slot. Cell identity
occupies the low 32 bits; mode and permission occupy the next three bits. The
ledger retains the full epoch and computes permission from its current state.
Writers publish before the native enrollment, reload or forced-mode mutation
they protect. A reader consumes identity and verdict from the same load: it
cannot mistake an in-progress update of a pending ordinary cell for an
untracked lifecycle. Missing slots retain native classification, and capacity
failure still prohibits the ordinary completion branch from hiding a cell.

The survivor snapshot at `0x00550AF0` precedes native unlock. Failure there
does not mean native reset execution is still active. `resetting` therefore
ends on both outcomes, while `reload_recovery` keeps ordinary retirement
blocked. Each member observed before the reset is tagged as a possible reload
survivor; a new or duplicated publication revokes that tag. Later recovery
holds CellRefLock and the ledger in the existing order, accepts only a complete
list explained by old candidates and current observed enrollment/exemption,
and rejects unknown members. It removes absent old candidates, preserves
genuine new credits and never manufactures readiness. Duplicates, reservation
overlap and native-counter mismatches continue to prohibit retirement.

Readiness rejects cheap denial states before counting members. Task association
invalidation uses copied generation tokens in both adjacency directions and a
node/root index. Cancellation removes just the supplied parent's edge in both
directions; root destruction or node reuse removes its remaining edges and
node association. An address reused for another generation cannot inherit an
old edge. These indexes own metadata only and do not retain native objects.
Their storage is bounded by the existing task/edge limits and all indexes are
cleared together on failed reservation, overflow or world reset.

Offline regressions execute the production Rust publication and state paths,
including concurrent ordinary/forced publication, delayed survivor recovery,
shared textures and real association-capacity exhaustion. Test-only counters
observe actual member/association visits without changing policy; work budgets
do not establish native frame time. Native hook activation, rollback failure,
list traversal, terrain ownership and the stress workload remain game-only
integration qualified from the existing engine contracts and compiled ABI.

## Complete planned change set

This is the implementation sequence for the full request. Stages 1-6 are
defined by the verified contracts below. Stage 7 supplies the distance and
unloading decisions that require measurements; its evidence conditions are
explicit rather than guessed defaults. The existing foundation
is the starting point, and unrelated workspace changes must be preserved.
This plan does not authorize a commit or deployment.

| Stage | Delivered behavior | Main code ownership | Dependency |
|---|---|---|---|
| 1. Integrate the foundation | Correct AL ABI, native distance inputs, centered bounds and publication-before-attachment remain active. | Existing `lod/mod.rs`, `distance.rs`, `membership.rs`, engine `types.rs/statics.rs`. | Existing IO safety gates. |
| 2. Correct accounting | Recovery uses physical membership, counter enrollment and genuine current-epoch credits. | Existing `lod/state.rs` and `membership.rs`. | Stage 1; exact mutation contexts. |
| 3. Close handoff coverage | Ordinary hide decisions recheck current readiness; forced lifecycle behavior remains native. | Implemented `lod/coverage.rs`, existing `mod.rs/state.rs`. | Stage 2; all forced observers in the same transaction. |
| 4. Measure native stages | Queue delay, work, transitions, cancellation and release are separate observations. | Extend existing `lod/metrics.rs` and core diagnostics. | Stage 2 lifecycle identity; root/texture identity from stage 6 where needed. |
| 5. Budget real attachment | Ordinary deferred bursts yield between callbacks using the existing native deadline. | Implemented `lod/service.rs`; engine bindings. | Native completion/queue contracts; new setting. |
| 6. Promote queued visible LOD | Previously speculative roots and waiting texture dependencies can receive visible priority. | Extend `lod/scheduler.rs`; implemented `lod/task_observation.rs`; reuse `service.rs`. | Stage 1 demand/reset observation, stage 5 service boundary. |
| 7. Tune distance and retirement | Choose supported distance/residency tradeoffs and any further unload optimization from actual cost. | Existing distance/configuration and proven native retirement boundaries. | Stage 4 observations and any additional owner contract required by the measured cost. |

Proposed files are responsibilities, not a request for a generic framework.
Keep safe decision logic separate from native access within each module.
All engine behavior belongs to the core. The helper only edits settings and
forwards existing diagnostics; it must not install these hooks or load the core.

### 1. Integrate the existing distance foundation

Keep the already implemented demand fixes and their production regressions.
Retain object/tree prefetch and retention defaults `1.35/1.50`, terrain
`1.10/1.20`, native terrain-root exclusion, and existing finite/range/order
validation. These values are the current baseline, not newly established
optima.

Make demand observation a shared prerequisite for prefetch and queued priority.
A priority-only configuration must observe the predecessor's native demand
without extending it. Add an explicit runtime admission flag so installation
of the observer cannot accidentally enable prefetch when its option is off or
its IO safety gates fail. Native true still avoids extra distance/settings
work.

Prepare worldspace reset whenever handoff, prefetch or queued association needs
it. Enable shared observers once, through their owning transaction, and report
each policy's requested versus installed state separately. Constructor priority
must retain its current supported fallback if queued promotion cannot install.

Acceptance: production distance regressions continue to pass; observations with
prefetch off preserve the native result; no policy uses an uninstalled reset or
a failed IO safety capability.

### 2. Replace incomplete ledger accounting

Change `ReferenceState/CellState` to distinguish physical occurrences,
counter-enrolled insertion instances, readiness and native physical-only
exemptions. Add insertion-invocation tokens for same-cell reinsertion and an
explicit stable/resetting epoch phase. Keep native engine addresses as identity
keys; do not extend their ownership.

Extend `membership.rs` with the proven canonical enrollment, alternate
physical insertion and locked first-match removal observers. Replace the
outer removal counter-delta policy and reinterpret `0x0055DE32` as disabled
enrollment retirement. Observe reload reset and retained branches inside the
owning native transaction; teardown still invalidates the complete epoch.

Preserve known identities/credits when uncertainty begins. Admit a genuine
known credit during uncertainty, rejecting reset overlap, duplicate credit and
unknown identity. Reconcile unexplained state against the actual locked list
and observed enrollment lifecycle. Recovery requires identity completeness,
not just matching counters. Permit the fully observed empty-epoch case subject
to the native signed-counter contract.

Acceptance: execute the actual production ledger for reinsertion, physical-only
remove, retained reload members, disable retirement, known credit during
uncertainty, duplicate membership/credit, reset overlap, empty epoch and
teardown/reuse. Preserve baseline failures wherever that Rust path exists
before changing it. Unknown evidence never creates a ready credit.

### 3. Install complete ordinary handoff guards

Add `coverage.rs` for bounded atomic publication of cell identity, epoch,
ordinary/forced lifecycle mode and ordinary retirement permission. Publishers
run at proven native events; geometry readers allocate nothing and wait on no
ledger lock. Inconsistent entries never authorize an ordinary completion;
ambiguous forced classification preserves the native provider's decision.
Invalidate records before epoch reset/teardown and reuse.

Install the ordinary completion guard at `0x00551AAA`, both scoped object
hidden queries at `0x006FEFD1/0x006F5A39`, and the forced loading/save/grid
publication observers as one coherent handoff transaction. Observe ordinary
start and reverse clear. Preserve existing timer progression, native segment
admission, LODdata writes and reverse-before-cleanup order.

This covers both a new member during a fade and a new member after an earlier
hide. Keep the shared hidden getter and its other consumer unchanged.
Do not shorten the fade constants to substitute for scheduling work.

Acceptance: the actual coverage policy preserves loading/save/forced modes,
blocks incomplete ordinary completion, restores eligibility on complete
current-epoch readiness and invalidates it on later membership. Compiled
bridges preserve the proven AL, register, stack and continuation contracts.
Image overlap, visible holes and rendered transition quality remain game-only
behavior, not outcomes established by the offline tests.

### 4. Add focused stage measurements

Extend `metrics.rs` using fixed observations and aggregates, sharing required
lifecycle identities with scheduling rather than maintaining another task
owner. Use the existing trace switch and logger. Add correlated queue wait,
worker/attachment duration, ready-to-hide delay, reverse-to-selection delay,
cancellation duration and release/churn counts at the boundaries below.

Distinguish direct real attachment from deferred attachment, and distinguish
ready credit from completion of attachment's scene/physics tail. Record
cancelled, failed, existing-3D and uncorrelated outcomes separately. Report
pending/oldest work, dropped correlations and observer overflow; never count a
missing event as zero latency.

Publish detailed summaries through `PsychoInfo`. Preserve the existing binary
dashboard snapshot ABI; do not append fields solely to display more counters.
Use the established process-residency sampler where available, at its existing
safe diagnostic boundary. A new byte/GPU sampler requires its own proven
contract.

Acceptance: the production aggregation executes with observed outcomes;
required policy/lifecycle work remains bounded with trace off, and optional
timing/reporting work is absent. Correlation losses stay visible and cannot
affect native task ownership or readiness.

### 5. Budget the ordinary attachment drain

Add `service.rs` for live completion-frame validation, a copied native
deadline value, the two pop bridges and result-store patch. This module owns
native service access and yields only between complete callbacks. The deadline
policy must be executable independently as production Rust; no reconstructed
queue is needed or permitted as a substitute.

Apply the three changes at `0x00448C53/0x00448C86/0x00448C8D` in one
transaction. Always allow first-callback progress. Yield only when strict
native expiration and a proven locked positive pending count both hold.
Release only the completed local holder; keep pending tasks in the native queue
and return the existing incomplete result. Invalid frame/provider/clock and
blocking contexts retain the full drain.

Acceptance: production deadline decisions cover equality, expiration,
arithmetic/clock failure, unsupported scope, progress and actual-pending
requirements. Qualify the compiled bridges and native epilogue contract.
Measure validation and clock/query work, callback bursts and queue wait
separately; one expensive callback remains unpreemptible.

### 6. Promote roots and texture dependencies safely

Add bounded `task_observation.rs` for constructor generations, live
root-to-node identity, shared texture associations and required invalidation.
Extend existing constructor observers before native dependency start, and
observe common task construction/cancellation/destruction plus native
dependency linking and node/worldspace reuse. These observers only publish
sidecar facts and chain providers; they never pin a block, change destructor
cleanup, or change native ownership behavior.

Update `scheduler.rs` so only an actual native visible-demand event can mark
an observed current root visible. Psycho-only retention must not promote it.
Track a shared texture's active parent associations, so cancelling one root
does not discard another visible root's interest.

Within the verified ordinary service scope, preflight the existing ordered
queue TLS context, acquire native strong candidates and finish traversal before
calling the installed priority provider. Begin with one candidate per service
and the remaining native deadline. Bound scan work, release every pin on all
exits, avoid repeat promotion of the same observed instance, and record actual
native success/failure. Increasing that quantum is a later measured decision.

Required lifecycle invalidation must complete or disarm the affected
association; it cannot be dropped like optional telemetry. Capacity loss,
unknown provider, missing thread context and expired generation preserve native
scheduling, with a distinct degraded status. Do not create another engine
thread, expand TLS participation, pause workers or acquire through raw holders.

Acceptance: executable production association logic covers shared textures,
parent cancellation, node/task reuse, worldspace reset, duplicates and overflow.
Native ownership/iterator/priority behavior is qualified from the supported
binary and compiled ABI; a mock queue does not prove integration.

### Configuration and installation

Add one independent `[lod].attachment_budget_enabled` boolean, planned
candidate default `true`, under the existing `lod.enabled` master switch.
This is a capability default, not a tuned millisecond value. Continue using
`priority_boost_enabled` for constructor and queued visible priority,
`handoff_fix_enabled` for accounting/coverage, `prefetch_enabled` for demand
extension, and `diagnostics.lod_streaming_trace` for optional measurements.

Update core `LodConfig/RawLodConfig`, shipped TOML, helper
`dashboard_config.rs` read/write/default handling and its dashboard control.
Use label `Attach budget`; maintain the current restart-required configuration
lifecycle. Do not add per-frame config parsing or claim live application through
the core's existing OnceLock.

Use `mod.rs` for orchestration and status. Reuse engine `statics.rs/types.rs`
for exact bindings; a cohesive native module may own its local call patches
and verified contexts, as `membership.rs` already does. Add only a safe
`libpsycho` TLS-value wrapper if needed; existing QPC/VirtualQuery wrappers
are sufficient for the other planned access.

Shared service bridges can support queued promotion with attachment budgeting
off; the drain then remains full. Missing promotion association leaves
attachment budgeting independently available. Lifecycle, forced-mode and
epilogue subpatches must never install partially. Preserve captured providers,
installation rollback and the current core/helper startup boundary.

Read the startup-safety contract before the new configuration/static/import
footprint. The task-specific gameplay exception remains in effect; do not
request another runtime approval. Report startup/game integration as unrun
rather than claiming that the release build proves them.

### 7. Choose distance and unloading changes from evidence

The goal includes useful distance coverage and timely return to LOD. Assess
each kind separately using early-hit rate, visible queue age, loads/releases
on reversals, attachment bursts and residency. Use the current multipliers as
the comparison baseline; change prefetch and retention separately so the effect
of each is attributable. Keep visible native demand unconditional.

Actual draw distance is a separate boundary from early request distance.
If the desired improvement requires geometry beyond native draw/cull reach,
first prove the setting consumers, available generated block levels, bounds,
cull admission and asset coverage. A core streaming multiplier cannot generate
missing assets. Record any asset-generation requirement rather than silently
claiming that earlier loading extended draw distance.

Use reverse-clear-to-selection and selection-to-model-retirement measurements
to identify which unloading stage needs improvement. Native LOD block release
already happens on a demand-false update. Choose smaller retention only when
its reduced residency is supported against additional reload churn.

Only a demonstrated bottleneck opens these further changes:

| Evidence | Follow-on change and prerequisite |
|---|---|
| Speculative work displaces visible work despite promotion | Bounded speculative admission, after complete demand/task admission and cancellation coverage. Visible demand always wins; count budgets are not bytes. |
| Retirement repeatedly scans a costly physical list | Batch first-match removal after duplicate, provider and concurrent-owner semantics are proven. Preserve real cleanup and ownership barriers. |
| Full-cell retirement starts too late | Earlier eligibility only after actors, scripts, physics, active-cell and task lifetime contracts are complete. Radius alone cannot authorize it. |
| Cache residency prevents needed reclamation | Pressure policy after actual residency and cache-owner/release contracts are proven. Never force the shared collector as an assumed LOD-only operation. |

These are explicit evidence-dependent work items in the full plan. Their
numeric policies and performance acceptance cannot be finalized from the
supplied untimed log. Your runtime-validation exception permits the earlier
implementation stages; it does not create timing or memory results. If no
fresh measurements are supplied, deliver the earlier stages as offline-qualified
and leave these decisions identified rather than inventing gains or values.

### Qualification and completion

Run focused executable production regressions while iterating. At the end,
run affected core/helper suites through Wine and one supported release build:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes -p psycho-engine-fixes-helper
cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Include the affected `libpsycho` suite if its wrapper changes. Check formatting,
compiled bridge ABI, instruction/provider context, `git diff --check` and the
final scoped diff. Do not rerun unrelated OMV/shader checks for this core work.

Acceptance separates correctness from performance: production policy results
and bounded work are offline evidence; game transitions, native hook execution,
startup and same-route frame/memory results remain unrun unless provided.
No FPS, latency or reclaimed-memory improvement is established by a build.

The complete deliverable is the qualified core implementation, matching helper
setting, trace/report support, current engine-contract documentation, and an
honest disposition of the measurement-dependent distance/retirement items.
Keep changes uncommitted and uninstalled unless separately authorized.

## Full-flow implementation contracts

The focused follow-up closed the intervention contracts needed to implement
the next stages. It did not prove new distance defaults, an earlier whole-cell
eviction policy, or a runtime performance improvement. The supported executable
identity was reconfirmed before address-sensitive research. Primary evidence is
[the full-flow audit](../analysis/radare2/output/perf/lod_streaming_full_flow_followup_audit.txt)
and [the implementation closure audit](../analysis/radare2/output/perf/lod_streaming_implementation_closure_audit.txt).
Existing Ghidra output is unchanged. Direct xrefs prove named callers, not
exhaustive indirect or external-provider coverage.

The owner-authorized gameplay exception remains in effect. Implementation may
proceed under it; gameplay is not a requested prerequisite. Qualification must
separate executable Rust behavior, compiled hook ABI and native static proof
from game-only image, integration, startup and performance behavior.

### Current-generation accounting and recovery

Physical membership, native counter enrollment and actual readiness are three
different facts. The next ledger must record them separately:

| Boundary | Proven behavior | Required observation |
|---|---|---|
| Canonical insertion `0x00548230` | Eligible, non-disabled VWD references increment `+0xA8` at `0x0054827F` before CellRefLock and physical publication. | Observe enrollment and invalidate ordinary retirement permission before the increment; confirm physical publication at the existing locked observers. |
| Alternate insertion `0x00548740` | Publishes at `0x00548785/0x00548801` under CellRefLock. It does not increment `+0xA8`. | Record physical membership without manufacturing enrollment or readiness. Caller frame owns cell at `[EBP-0x08]` and reference at `[EBP+0x08]`. |
| Canonical removal `0x0054CA90` | VWD counter decrement precedes CellRefLock. Actual first-match removal is call `0x0054CB2C -> 0x00905330`. | Observe that cell-specific list mutation under its existing lock. Caller cell is `[EBP-0x1C]`; reference is `[EBP+0x08]`. |
| Disable enrollment retirement `0x0055DE32` | The reference initialization branch tests disabled mask `0x800`, VWD eligibility and parent cell, then decrements the parent's counter through `0x0055E1D0`. It does not remove the list member. | Retire counter enrollment while preserving physical membership. Replace the current interpretation as physical removal. |
| Reload `0x005508B0` | Resets `+0xA8/+0xAA` under CellRefLock at `0x005508E5/0x005508F1`, removes some members and deliberately retains others. | Publish a resetting phase before the native stores; finish the new epoch after the locked retained-member transaction. |
| Teardown `0x0054CD20` | Resets counters and drains membership under CellRefLock. | Invalidate the entire cell epoch rather than applying reload retention. |
| Attachment credit `0x004520C4 -> 0x00452390` | Increments `+0xAA` after the attachment path has obtained and configured real 3D, before its remaining scene/physics tail. | Observe a genuine identity credit; do not replace it with a non-null pointer test. |

The embedded list at cell `+0xAC` has item and next words. CellRefLock is
`0x00541AC0/0x00541AE0`, operating on cell `+0x80`. The generic removal
provider takes the address of the reference slot, returns no success boolean
and removes only the first matching identity. Compare the identity's physical occurrences before and after the
cell-specific call while that caller holds its lock. Duplicate occurrences
must remain explicit; an identity must never receive multiple synthetic ready
credits. Do not hook every use of the generic list remover.

Canonical same-cell reinsertion needs an insertion-invocation token in addition
to the reference identity. Its new counter enrollment precedes removal of the
old physical occurrence. Reserve the new pending token before the increment,
remove the old occurrence's enrollment at its actual removal, then bind the
reserved token at the locked publication. A single reference-key overwrite
would lose the new enrollment again. The native insertion frame identifies
this live invocation; retain it only as a temporary correlation key, never as
a pointer to dereference after that callback. Failed or unexplained publication
keeps the reservation uncertain until reconciliation or lifecycle invalidation.

Reload retention is a proven native exemption from the new counter epoch.
References retained by the loop advance through `0x00550AC7` without a new
total increment. Admission uses `0x005653D0`, or a non-null result from
`0x00484E60(reference, -1)` for which `0x00471C20` is false.
`0x005653D0` also has a reference-flag `0x400` fallback. These predicates
do not establish that retained references are non-VWD.

The accessor `0x00484E60` walks a reference-associated list obtained through
`0x00460140`; it is not proven to be a real-model getter. Its returned
object's bit test and the native retained branch are sufficient to observe
the exemption. The concrete type and preservation of every retained model
remain unproven and are unnecessary for this observer. Never copy previous
ready credits or create new credits from that returned pointer.

Implement the ledger correction with these invariants:

1. Physical-only members from the alternate insertion and retained reload
   branch do not become pending counter-enrolled references. A physical-only
   removal is a valid lifecycle event, not automatically a missing-enrollment
   error.
2. Uncertainty preserves known current-epoch identities and genuine credits.
   A genuine later credit for a known member remains useful evidence.
   Unknown identities, duplicates and resetting epochs remain blocked.
3. Credit observation captures the epoch before forwarding the installed
   increment provider once and accepts it only if the same stable epoch
   survives afterward. The reset observer publishes its resetting phase
   before the actual counter stores, so reset overlap cannot become a new
   epoch's credit. Do not add an engine lock to the attachment path.
4. Recovery reconciles the actual list under its owning lock with observed
   enrollment, physical-only exemptions, removals and current-epoch credits.
   Restore certainty only when this explains the complete current membership
   and the native total. Counter agreement alone cannot recover missing
   identities or credits. Unexplained membership remains fail-closed.
5. Native totals are signed 16-bit values in the readiness predicate
   `0x005495A0`. Negative or inconsistent counts remain blocked. A fully
   observed stable epoch with zero enrollments may complete, subject to the
   native predicate; the current unconditional nonempty requirement is wrong
   for that proven empty case.
6. Never modify native counts, ownership, list nodes or reference lifetimes.
   Keep lock order CellRefLock then ledger. Release ledger ownership before
   any native call. Membership changes before native counter mutation must
   invalidate the published retirement decision.

This closes how to improve recovery without guessing the cause of the
October 11 mismatch. It does not authorize rebuilding unknown credits from
a timeout, `+0xAA`, or a scene pointer.

### Forward and reverse coverage

Readiness authorizes a transition start, but ordinary completion currently
does not repeat it:

| Boundary | Contract and implementation |
|---|---|
| `0x00557AA0` | Starts ordinary transition: `+0xCE = 1`, `+0xCF = 0`, timer `+0xC8 = 0`, unless already started. Observe an actual new start. |
| `0x00551AAA` | Ordinary fade-completion admission, before native LODdata/cell hide publications. Recheck the current stable epoch here. If blocked, continue at `0x00551B0C`, preserving the native timer increment and later update. |
| `0x006FEFD1` | Segmented object selection calls cell hidden getter `0x00557D30`. Capture and forward this call provider; veto an ordinary hide for a tracked pending/uncertain epoch. |
| `0x006F5A39` | Non-segmented object geometry uses the same hidden getter. Apply the same scoped observation and veto. |
| `0x00557C40` | Reverse transition clears `+0xD0` before walking real-reference fade controllers. Clear ordinary sidecar transition permission here, preserving native work. |

Both scoped hidden queries return AL and have no stack arguments. A native
false result remains false. The extra decision runs only for a native true
result; it must allocate nothing, call no engine provider while holding the
ledger, and use a non-blocking sidecar read. An unavailable or inconsistent
tracked ordinary decision preserves LOD coverage. An untracked lifecycle has
no positive authorization to alter a forced native transaction.

Publish lifecycle mode together with ordinary permission and cell identity in
one atomic word before native forced writes. Selection must consume the full
decision from that load; it has no torn-snapshot fallback. Use bounded atomic
publication rather than waiting on the membership mutex in geometry selection.
Keep epoch invalidation in the ledger-derived decision and teardown invalidation
in the publication contract. The ordinary completion guard itself remains
fail-closed because its branch is already proven ordinary.

The scoped queries address membership that becomes pending after a previous
ordinary hide. The completion guard alone would not address that case.
Retirement decisions are snapshots at their publication boundary; later
mutations invalidate them for subsequent native selection. Do not globally
hook `0x00557D30`: it also has a caller at `0x006D66EC` whose complete
consumer contract is unnecessary for this scoped change and remains unmodified.

Preserve the following forced native behavior:

- Attachment bypass `0x00549502` is selected by the loading-menu predicate
  `0x00705E80` or save-state predicate `0x0042CE10`. The former consults
  menu ID `0x3EF`; the latter reads `0x011DDF38 + 0x244`, mask `2`.
- `0x00557AE0` forces reference fades, publishes hidden `+0xD0 = 1`
  and pending forced flag `+0xD2 = 1`. Its grid wrapper `0x00557BE0`
  is called at `0x00518E1F` inside the actual deferred callback
  `0x00518CF0`. Producer `0x00518B70` queues that callback. An older
  analysis merged these two function spans; do not copy that caller alias.
- Follow-up `0x005519E6` requires `+0xD2`, a worldspace and cell state
  6, then publishes hidden state and clears `+0xD2` at `0x00551A6D`.

Observe the forced publication before its native write and retain its
sidecar classification after `+0xD2` clears. End it on a proven new ordinary
transition, reverse transition or lifecycle invalidation. Loading/save bypass
and forced grid-fade behavior must remain native even when ordinary identity
accounting is uncertain. Install forced observers, both scoped selection
providers and the ordinary completion guard together; partial coverage is
not the intended candidate.

The cell accessor `0x0054DDD0` returns exterior cell `+0xC0`, its
worldspace, not its scene root. `0x00586170` follows the parent worldspace
when LOD inheritance is enabled and returns LODdata at `+0x3C`.
`0x00929260` writes that object's `+0x28` byte. Preserve these shared
native writes and their providers; do not describe or patch them as private
scene-node cull flags. The ordinary guard precedes both this write and the
cell hidden write at `0x00551AEB`.

Object selection `0x006FEE90` additionally requires existing geometry and
native cell-state acceptance. Predicate `0x006FEDE0` tests block overlap
with the active cell grid; it is not the LODdata flag getter. Outside that
overlap the engine shows the existing segments through its native path.
Within it, the cell hidden decision participates in per-segment selection.
Preserve that overlap test, segment flag `0x006FF0A0`, cell acceptance
`0x004511E0`, and the nonzero-geometry requirement of `0x00A86FF0`.
The non-segmented path traverses geometry and selects its cell from the bound.
A veto cannot create missing LOD assets or prove that the renderer drew them.

The native duration globals contain 1.2 and 1.0. Timer increment uses engine
`secondsPassed` through `0x0084D030`, with completion checked first.
Keep them unchanged: the evidence does not establish their INI mapping or
show that duration is the measured bottleneck.

Reverse retirement `0x00552BD0` changes eligible states 5/6 to 4, calls
`0x00557C40`, then cancels model tasks through `0x00445670`.
Cell cleanup `0x00462290` follows. Preserve that order and measure hidden
clear, actual segment selection and real-model retirement separately.

### Ordinary-frame real attachment budgeting

The supported path is:

```text
0x0086E897 ordinary frame -> IOManager completion service 0x00C3DBF0
  -> manager +0x74 callback 0x00446E40
     -> 0x00448C10 real attachment queue drain
     -> 0x00448CC0 neighboring map drain
  -> generic completed IO queue +0x64 and native deadline checks
```

Producer `0x00440310` compares the current thread with the owning engine
thread. The owner calls `0x00451EF0` directly; another thread creates an
AttachDistant3DTask and publishes through `0x00440710/0x00449240`.
This is not a cache-hit/disk-miss distinction. The attachment task is a
0x20-byte BSTask with reference `+0x18` and 3D holder `+0x1C`, not
an IOTask with dependencies at `+0x20`.

The drain owns a strong local task at `[EBP-0x10]`. Pop calls
`0x00448C53/0x00448C86 -> 0x00449280` replace that holder; slot 5
dispatch is `0x00448C7A`. The complete native drain has no deadline.
Native empty acquisition releases the previous holder through
`0x006F74F0(output, 0)` and leaves output null. Its destructor is
`0x0044CBF0`.

Queue construction `0x0044B500` publishes into ModelLoader `+0x1C`.
Queue `+0x20` lock wraps native enqueue/dequeue, and virtual slot 4
`0x009611E0` reads item count `+0x18`. Native slot 2 increments after
publication; slot 3 decrements after extraction. A pending query must use
the same lock and a proven count-provider contract. An unproven replacement
queue/provider keeps the full native drain.

Implement a transaction containing these three changes:

1. Bridge first pop at `0x00448C53`. Supply native EBP in EDX while
   preserving queue ECX, output stack argument and ret-4 ABI. Initialize
   result byte `[EBP-0x11]` to true and forward the installed pop provider
   once. Always permit the first complete callback for progress.
2. Bridge subsequent pop at `0x00448C86`. Budget only the verified ordinary
   frame chain and normal manager mode. Between callbacks, use the native
   start and allowance copied in the live completion-service frame.
   Expiration is strictly elapsed ticks greater than allowance, matching
   native comparison `0x00C3DDBC`; equality does not expire.
3. Replace only the four-byte unconditional true store at `0x00448C8D`
   with NOPs. Preserve the native SEH state update, holder destructor,
   AL result and epilogue. The first-pop bridge now owns initialization.

The live frame chain is drain return `0x00446E59`, wrapper return
`0x00C3DD2C`, and completion-service return `0x0086E89C`.
Completion-service EBP owns start low/high at `-0x2C/-0x28`, allowance
at `-0x24/-0x20`, and manager at `-0x90`. Require its mode
`+0x68 == 6` and the observed ModelLoader queue identity. Validate only
these fixed ancestor frames for alignment, increasing addresses, committed
readable stack allocation and exact return boundaries before dereferencing
them. Use the existing VirtualQuery and QPC wrappers. Do not scan the stack,
persist native frame pointers, or introduce a TLS/global active-scope pointer.
Unexpected wrapper frames, mode, clock failure or invalid timing chain the
full installed native pop path.

When the deadline has expired, query pending count under the queue lock.
Positive pending work permits clearing only the already-completed local
holder through the native helper, setting the result false and returning
null output. Queued nodes and tasks stay untouched. Zero pending work still
forwards the native pop provider once and preserves its empty result.
Never pop then discard a pending task to discover backlog. Preserve cleanup
and other queue consumers.

Blocking caller `0x00C3DFA0` uses a different return boundary, sets its
requested mode and waits for both native work count and combined callback
completion. It retains the full drain even when its requested mode happens
to equal 6. Wrapper `0x00446E40` combines the two drains' AL results.
The completion service's existing reentrancy guard remains native.

This borrows the existing normal completion deadline rather than inventing a
new time default. Neighboring drain `0x00448CC0` retains its native 5 ms
normal / 100,000 ms other-mode behavior. One callback cannot be preempted;
this is not a hard frame-time cap. Budgeting can reduce bursts and increase
queue wait, so qualification must report both. Include frame validation, clock
queries and locked pending queries in the scheduling cost measurement; the
static contract does not establish that their runtime cost is negligible.

### Promotion of already-queued visible work

There is a native owning acquisition boundary:

| Native interface | ABI and lifetime |
|---|---|
| `0x00C40E70` | Thiscall on IOManager itself, which owns the ordered queue interface; iterator, key-output, intrusive task-output and shard-advance flag are four stack arguments. AL result, ret-16. Holds owner `+0x20` recursive lock during acquisition. Worker `+0x30` points to this manager; it is not a queue field in the manager. `0x00C3E029 -> 0x00C3E1B0 -> 0x00C3E286` forwards the same ECX unchanged. |
| `0x00C42380/0x00C42560` | First/next acquisition retains task `+0x08` before clearing hazard protection and restarts deleted results. Traversal is nondestructive. |
| `0x00C42060` | Initializes the shard cursor and resets flags/key through the iterator's virtual provider. Native callers initialize the 0x1C-byte iterator inline; table `0x010C1664`, reset provider `0x00C40B20`. |
| `0x00C3F750` | Checks the ordered queue's thread-registration owner at `+0x14`, whose TLS index is `+0x04`. Existing TLS context serves its shards. |
| `0x00C41610` | Registers a new context using a bounded slot. Exhaustion returns null; iterator callers do not guard it. |
| Task virtual slot 7 | Native provider `0x00C3CAE0` updates dependencies then self through `0x00C3DF40 -> 0x00C3E690`. Rekeying reserves only pre-running states. |

Preflight the current queue TLS context using its published index. A missing
context skips promotion and preserves native service; do not register a new
thread, expand capacity or call the iterator's unchecked registration path.
This is one context for the ordered queue, not a separate registration per
shard. Native worker dispatch acquires the task, then CAS-reserves state 1
to 3 at `0x00C4121B` before worker phases. States 3/4 cannot be preempted.

Dependency lifecycle is now bounded enough for the native priority provider:

- Object root start `0x006F7070` and terrain start `0x006FBBD0` request
  two DDS texture dependencies through `0x004436C0`. Initialization flag
  `+0x30` is published after those calls. Completion provider waits for
  initialization and dependency completion before submitting a state-0 root.
  The NIF load remains in the root worker phase.
- Tree start `0x006F94C0` publishes its initialized state without adding
  those dependencies.
- Dependency insertion `0x00C3C700` has native callers
  `0x00443AD6` and `0x00C3C913`, covering new and cached texture links.
  Cancellation `0x00C3CB70` and completion `0x00C3C930` change parent
  ownership links `+0x1C/+0x24`; they read, rather than append/remove,
  their own dependency array `+0x20`.
- Texture constructors `0x0043BD10/0x0043BE60/0x0043BEF0` initialize
  leaf IOTasks with no child dependencies. Their start/worker providers
  `0x0043C050/0x0043C150` do not build another dependency graph.
  Cached child links do not append dependencies to that child.
- Common base construction `0x00C3C590`, cancellation
  `0x00C3CB70` and destruction `0x00C3C620` supply observation
  boundaries. Root destructors chain the common teardown through
  `0x00C3CEA0`. Object/tree teardown cancels its observed task holders.
  Terrain teardown `0x006FA420` cancels its pending task when geometry is
  unpublished, then releases its holder before free through `0x006FD8F0`.
  This is not proof of unconditional terrain-task cancellation in every state.

Implement a bounded sidecar association for observed root instances and their
texture children. Record constructor generation, kind and demand-node identity
while the native constructor owns them; observe child links while parent and
child are live. Shared textures retain associations with all observed active
LOD parents. Constructor, cancellation, destruction, node reuse and worldspace
invalidation must invalidate stale generations. Lifecycle invalidation cannot
be dropped as an optional trace event. Native node construction `0x006FD210`
supplies reuse invalidation before a new owner can publish demand; common task
construction supplies the corresponding task-address reuse boundary.

Publish visible demand only from an actual nonzero native demand result.
Psycho-only retention and a consumed speculative mark are not proof of current
visibility. Separate this state from the existing provenance set, which is
cleared for several unrelated reasons.

Service promotion inside the verified ordinary completion callback scope,
using its remaining native deadline. Acquire native strong candidates,
finish/reset traversal, then invoke each candidate's installed priority
provider once outside sidecar ownership. Never rekey while retaining a raw
iterator node. A bounded first implementation can process one candidate per
service and restart safely after a key change; measure scan cost and promotion
delay before increasing its quantum. All native searches must terminate on
deadline/visited-work limits; one native acquisition/provider call itself
cannot be preempted.

Queue-owned pins protect the task, not its raw block. Never read
object/tree/terrain block task holders and then increment them: workers clear
those holders concurrently. Never follow a root's raw block/node pointer
after acquisition. Match copied sidecar generations instead. Release pins
through native intrusive helpers on every exit.

This promotes waiting texture dependencies as well as queued roots. It uses
native priority zero, matching the existing visible-constructor policy.
It does not pause workers, manually change task states, remove cancellation
waits or use native bulk reprioritization `0x00C3E1B0`, which waits for
worker acknowledgements. Missing association, bounded-registry overflow,
unproven provider contracts or expired observation preserve native scheduling;
report them distinctly from successful promotion.

### Retirement, residency and distance policy

Object manager `0x006FDFC0` already releases a demand-false block in the
same update through `0x006FE1C0 -> 0x006FD920` and clears node
`+0x14`. Tree release `0x006FD950` clears `+0x18`.
Terrain retirement remains a parent/child morph transaction. There is no
proven extra object release timer to remove.

Retention postpones release to avoid camera-reversal churn. A larger distance
band and earlier memory return are competing policies. Preserve native visible
demand and native reverse-before-cleanup ordering. Do not use a LOD radius to
evict active cells or treat the 4096-slot provenance set as bytes/resident blocks.

Cancellation `0x0044AC40` removes queued work with native ownership and
waits for running states to finish. `0x0044ADA0` only changes an IO flag;
it is not a wait/suspension primitive. Pending cleanup `0x00452490` and
global collector `0x00868D70` have shared model/physics/render ownership.
Forced collection is not a private LOD eviction operation.

The native list remover is linear, but no supplied timing attributes frame cost
to it. Faster batch retirement, earlier whole-cell unload and byte-pressure
admission remain conditional on measured cost plus their additional owner
contracts. This is a deliberate implementation boundary, not a reason to block
the proven accounting, scheduling and measurement work.

### Measurements and acceptance

Extend existing trace-controlled, allocation-free observations at actual stages:

| Observation | Native boundary |
|---|---|
| LOD queue wait, texture wait and root work | Constructor/dependency/submission, normal worker phase dispatch `0x00C3FC80/0x00C3FCA0`, kind-specific block publication and cancellation. |
| Deferred real-model wait and callback bursts | `0x00440710/0x00449240`, dispatch `0x00448C7A`, callback return and locked pending count. |
| Actual attachment and readiness | Shared `0x00451EF0` entry/return plus identity credit `0x004520C4`; distinguish failure/already-3D/cancelled exits. |
| Forward transition | Last required genuine credit, actual ordinary start, completion admission, hidden publication and geometry selection. |
| Reverse transition | `0x00557C40` hidden clear, geometry selection, model cancellation and reference retirement. |
| Unload and residency | Cancellation duration, physical removal, block release, pending collection and independently sampled process residency. |

All six discovered direct attachment callers matter; timing only the deferred
task callback misses direct attachment. Preserve bounded task identities across
reused pointers through observed generations. Missing events are uncorrelated,
not invented latency. Process memory is not GPU memory, release is not reclaimed
bytes, selection is not proof of drawing, and ready credit precedes the remaining
attachment tail. Trace-off observers perform only required policy/lifecycle
work, without clocks, log formatting or per-event allocation. Summaries use the
existing logger and stable LOD tag.

The complete planned change set above defines code ownership, configuration,
installation dependencies and evidence-dependent distance/retirement work.
Use that sequence rather than the historical implementation order below.

Before each production stage, exercise the actual executable Rust policy with
evidence-backed inputs wherever it runs offline. Regressions must distinguish
physical-only removal, retained reload members, duplicates, known credits during
uncertainty, reset overlap, empty epochs and forced/ordinary transitions.
Deadline behavior must exercise the production policy for strict expiration,
invalid timing, first-callback progress, real pending work and native fallback.
These are not replacement tests for native queues or a reconstructed engine.

Validate changed core/helper crates through Wine, the supported explicit
`i686-pc-windows-gnu` release target, formatting, diff checks and compiled
bridge ABI/instruction context. Review startup safety before new configuration,
static ownership, imports or lifecycle observers. Native integration and
performance remain unrun under the owner's exception; report the candidate
accordingly. No new production change was made by this research.

## Historical implementation status

The design and acceptance sections below preserve earlier revisions and their
evidence. The current full-flow contracts above supersede their assumptions
about physical removal, empty epochs, reload recovery and transition coverage.

The initial implementation is present and has entered runtime stress
validation. The three original Ghidra audits closed the LOD producer,
scheduler, task ABI, reference publication, counter lifetime, cell transition,
and generic scene-graph virtual gaps needed for that implementation.

The first high-speed stress test exposed a pre-existing BSTree destruction
lifetime failure and an independent handoff-ledger resynchronization gap. The
three crash audits prove the native SpeedTree clone-lifecycle race, the exact
unlocked owner-vector and shared-refcount mutations, and the complete scalar
destruction/free edge.

The crash fix is now implemented in the core DLL. Clone construction at
`0x00B036D0` and scalar destruction at `0x00666910` are serialized by the
engine's reentrant SpeedTree critical section at `0x011F8BC4`. The destructor
validates clone membership under that lock and skips the complete scalar
destructor, including physical free, if the object is already corrupt. Hook
installation is transactional and prefetch remains vanilla if the lifetime
hooks cannot be owned. The supported i686 release build passes.

The later priority and two-worker performance extension exposed a separate
constructor ABI defect in Psycho's hooks during save-load terrain creation.
The native object, tree, and terrain task constructors return the constructed
task in `EAX`; their callers publish that exact return value into an intrusive
holder and immediately increment `task + 0x08`. Psycho originally declared
the three detours as returning `void`, so the priority call was allowed to
replace `EAX` with an incidental value. The save-load crash at `0x0040B467`
was the holder attempting `InterlockedIncrement` through that corrupted
return value. The hook types and implementations now preserve and return the
constructor result after applying priority. Priority remains enabled at the
proven state-zero key-update point, and both IO workers remain enabled.

The next save-load stress crash is a distinct `C0000417` contract failure.
The final coverage audit proves that no SpeedTree constructor, scalar
destructor, owner insertion, or owner erase path remains outside the lifetime
lock. The remaining historical worker signature reaches the secure CRT read
at `0x00ECB144` from `BSFile` open-state initialization at `0x00AFF490`.
That initializer allocates an optional file cache and passes it to the raw
read at `0x00AA1570` without checking for a null allocation. The two-worker
configuration raises concurrent cache pressure but does not invalidate file
ownership.

The parallel-IO transaction now replaces that initializer with the same
native state machine plus the missing allocation branch. Successful caches
and whole-file preloads are unchanged. If only the optional cache allocation
fails, the hook sets cache capacity to zero and retains the valid `FILE*`;
the audited native buffered-read path then performs direct reads. Loading,
priority, and both workers remain active. The transaction will not publish
the worker-count patch unless this fallback and all three TLS-capacity hooks
are owned together.

The first non-crashing two-worker build exposed a distant-geometry regression:
terrain, object, and tree LOD tasks were assigned priority `255`. The final
queue audit proves that the engine orders each native task chain in ascending
packed-key order and workers consume the first entry, so lower numeric
priority values execute first. Blocking load drains also partition the queue
into four buckets per priority and reject a task whose decoded priority lies
above the active load boundary. `255` was therefore an out-of-contract
deprioritization, not a boost. Psycho now assigns native priority `0`, keeping
the priority feature and dependency propagation active while restoring LOD
eligibility during load and normal worker service.

The following exterior stress crash exposed the remaining generic-worker
contract. `ExteriorCellLoaderTask` publishes its active cell through the
process-global pointer at `0x011C3F30`. Two instances could overlap on the two
workers, allowing one task to clear that pointer after another task's null
check but before its reload at `0x004686F4`. Psycho now serializes only the
per-form publication/clear transaction at `0x00550500`. Terrain, object, tree,
file, and other safe IO work still use both workers.

The 2026-07-27 Capital Wasteland stress crash then exposed an independent
AutoWater owner. The worker faulted at `0x0049F24C` while copying a point
returned from process-global owner `0x011C57AC`. Outer AutoWater function
`0x0049C860` destroys, initializes, consumes, and publishes that owner plus
`0x011C57B0`, and is reached by three direct callers including exterior-cell
loading. Psycho now serializes that exact complete AutoWater transaction in
the parallel-IO installation transaction. The full proven path, ABI, lifetime,
and runtime acceptance test are maintained in
`docs/parallel_io_engine_contract.md`.

Release acceptance remains blocked on runtime stress validation and the
separate handoff-ledger resynchronization work. Runtime tuning is no longer
the only remaining work.

## 2026-07-27 bounded-scheduling correction

This section supersedes the earlier implementation descriptions below where
they say that both workers freely drain at equal priority, that every LOD task
uses priority zero, that the complete exterior task is locked, or that release
builds maintain per-operation IO/SpeedTree timing and contention counters.
Those sections remain as investigation history.

A tester reported traversal stutter that stopped when Parallel IO was
disabled, with allocator modes `0` and `1` amplifying the FPS loss. Static
analysis found that the original patch changed only the constructor count
while the IOManager selector still targeted the vanilla `return 0` stub. That
build therefore did not prove worker-one execution, and the report remains a
correlation rather than proof of an allocator or two-worker defect. Before
explicitly admitting worker one, Psycho nevertheless had to define admission,
drain quantum, OS priority, speculative LOD priority, and the cost of its
process-global safety locks and hot-path diagnostics.

The implemented contract is now:

1. Worker zero remains the vanilla primary. Worker one is selected only while
   the primary is executing, through the IOManager vtable slot at
   `0x010C165C`.
2. An atomic idle/reserved/running state prevents double admission. Submission
   `0x00C3FB50` releases a reservation when native insertion fails.
3. The supplemental worker returns to cleanup/wait at `0x00C41307` after one
   task instead of following the vanilla backlog-drain branch at
   `0x00C41302 -> 0x00C41148`.
4. Worker constructor `0x00C3EE70` identifies the primary and supplemental
   Win32 threads. The supplemental thread is below normal priority before its
   caller resumes it. It is temporarily restored to normal only while owning
   a Psycho process-global safety lock to avoid priority inversion.
5. Demand hooks keep a fixed, allocation-free provenance set for unloaded
   nodes admitted only by Psycho's extended radius. Object block `+0x00`, tree
   block `+0x44`, and terrain block `+0x00` recover the demand node at task
   construction. Visible work receives priority zero; speculative work keeps
   its native priority. Collision/capacity failure deliberately fails
   visible-safe.
6. Exterior-owner serialization moved from complete task `0x00527CB0` to the
   exact per-form publication/clear transaction `0x00550500`.
7. AutoWater teardown, construction, and publication are serialized across
   the exact outer transaction `0x0049C860`, covering all three native callers
   without locking the complete exterior-cell task.
8. Static geometry's outer allocation entry uses its proven native
   deferred-pack failure result as a non-blocking retry boundary. Direct
   allocation and retirement remain serialized.
9. Routine LOD demand, successful IO, model postprocess, static-geometry,
   SpeedTree materialization/Compute, contention, waiter, and timing counters
   were removed from release hot paths. Rare installation, allocation,
   postcondition, and corruption failures remain observable.

Allocator modes still own their documented allocation domains. They neither
enable nor bypass this scheduler; mode-dependent severity is expected because
native heap and scrap contention differ, but scheduling and safety behavior
are identical in modes `0`, `1`, and `2`.

The complete executable identity, ABI, ownership, failure behavior, tests, and
runtime acceptance criteria are maintained in
`docs/parallel_io_engine_contract.md`.

## Evidence baseline

### Streaming demand

`BGSTerrainManager` loads `Data\LODSettings\%s.DLODSettings` during
construction. If the settings object is absent, the distant manager remains
inert and Psycho must preserve that behavior.

The camera/worldspace update owner at `0x006FCA90` dispatches:

- terrain updates through `0x006FDAA0`;
- distant object updates through `0x006FDFC0`;
- distant tree updates through `0x006FE330`;
- worldspace reset through `0x006FCE00` and `0x00572160`;
- the post-update phase through `0x006FCDB0` and `0x006FEA70`.

Object and tree blocks use the same predicate to create and release their
native block objects. There is no prefetch boundary or retention hysteresis:

- object demand is `0x006FE620`, using `fBlockLoadDistance` at `0x011D877C`;
- object quality selection is `0x006FE6D0`, using the separate
  `fBlockLoadDistanceLow` at `0x011D8724`;
- tree demand is `0x006FE780`, using `fTreeLoadDistance` at `0x011D8788`;
- terrain demand is `0x006FE550`, using the per-node threshold at `+0x44`.

The shared metric at `0x006FE830` is a two-dimensional point-to-square
distance. A block requested at the vanilla boundary must still pass through
dependency loading, IO completion, and main-thread publication. This explains
late appearance without requiring a slow or broken global scheduler.

### Native task pipeline

Terrain, object, and tree producers construct their native block and task,
publish the intrusive task pointer, and invoke task slot 8. The proven phase
sequence is:

```text
LOD producer
  -> task slot 8: create dependencies
  -> task slot 10: dependency-ready scheduling
  -> IOManager +0x48: insert into priority queue
  -> task slot 1: load/file work
  -> task slot 2: finalize and publish completion
  -> completed-task queue
  -> main-frame drain at 0x00C3DBF0
  -> task slot 5
```

The global completed-task drain is called every frame from `0x0086E650` and
has a time budget. Psycho must move LOD demand earlier instead of increasing or
removing that global budget.

Real-reference publication uses a distinct `AttachDistant3DTask` contract.
`0x00440310` attaches directly only on the owning thread; otherwise slot 5 at
`0x0043FC40` performs the real main-thread publication. Cancellation or
failure receives no ready credit.

### Broken cell handoff

`TESObjectCELL +0xA8` is the current 16-bit VWD total. It is incremented during
reference insertion at `0x00548230` and decremented during removal at
`0x0054CA90` or the alternate helper `0x0055E1D0`.

`TESObjectCELL +0xAA` is a 16-bit successful-real-3D counter. Its only
increment is `0x00452390`, called from `0x004520C4` after successful VWD real
3D publication. It is reset only during construction or reload and is never
decremented when a ready reference is removed.

The gate at `0x005495A0` is only:

```text
cell.vwd_total <= cell.vwd_ready_total
```

Both gate callers additionally require `ready_total > 0`, then arm the timed
transition at `0x00557AA0`. The per-frame cell update at `0x00551890` later
retires the distant representation when the timer expires.

This allows stale success credit to retire a later population. For example:

```text
ready reference present:       total=1 ready=1
ready reference removed:       total=0 ready=1
different reference inserted:  total=1 ready=1
```

The different reference has not published real 3D, but vanilla considers the
cell ready. Conversely, one slow, cancelled, or failed current reference can
hold the cell-wide distant representation indefinitely. Keeping distant
coverage is the only safe terminal-failure fallback exposed by the audited
contract; forcing retirement would create a visible hole.

## Public configuration

Add a dedicated additive section:

```toml
[lod]
enabled = true
prefetch_enabled = true
handoff_fix_enabled = true

object_prefetch_multiplier = 1.35
object_retention_multiplier = 1.50

tree_prefetch_multiplier = 1.35
tree_retention_multiplier = 1.50

terrain_prefetch_multiplier = 1.10
terrain_retention_multiplier = 1.20
```

Add one default-off diagnostic option:

```toml
[diagnostics]
lod_streaming_trace = false
```

Configuration is resolved once at startup. Hot paths must not query global
configuration or parse settings.

Validation rules:

- reject non-finite values;
- clamp multipliers to `1.0..=2.0`;
- require each retention multiplier to be at least its prefetch multiplier;
- replace invalid values with defaults and emit one startup warning;
- keep terrain margins smaller because recursive quadtree expansion grows
  work and memory faster than object/tree block expansion.

The values above are initial profiling values. Final release defaults must be
chosen from runtime timing and memory telemetry. The two subordinate enable
switches are diagnostic A/B controls, not alternate fixes.

## Change 1: native LOD prefetch and retention

### Demand hooks

Install three pure predicate hooks:

| Contract | Address | Native loaded/pending field |
|---|---:|---:|
| Terrain chunk demand | `0x006FE550` | node `+0x10` |
| Distant object-block demand | `0x006FE620` | node `+0x14` |
| Distant tree-block demand | `0x006FE780` | node `+0x18` |

Each detour performs this sequence:

1. Call the captured predecessor.
2. Return true immediately when the predecessor already requests the node.
3. Validate the node, camera coordinates, live base threshold, and configured
   multiplier.
4. Reproduce the audited two-dimensional point-to-square metric.
5. Use the prefetch threshold when the native block pointer is NULL.
6. Use the farther retention threshold when the block is loaded or pending.
7. Return the predecessor result for unsupported, unreadable, or non-finite
   state.

The resulting state is:

```text
inside vanilla distance     -> native demand
outside vanilla, prefetch   -> start the native task early
outside prefetch, retained  -> keep the existing task/block
outside retention           -> allow native release
```

Object and tree thresholds are derived from the live engine settings so INI
and compatible setting owners retain authority. Terrain derives its threshold
from the current node. `fBlockLoadDistanceLow` remains unchanged because it is
an object quality-tier selector, not a prefetch distance.

The predicate detours must be allocation-free and lock-free. They must not
invoke task constructors, attach scene nodes, or perform IO themselves. Their
only behavioral change is returning true earlier or retaining a native block
longer.

### Reset behavior

Observe the distant-manager worldspace reset at `0x006FCE00`. It clears LOD
diagnostic epochs and all handoff sidecar state before chaining the native
reset. No prefetched task is directly cancelled or released by Psycho; native
worldspace teardown retains ownership.

## Change 2: identity-correct real-object handoff

### Sidecar state

Add a sparse map keyed by `TESObjectCELL*`:

```text
CellState
  generation: monotonically increasing integer
  certain: whether exact current membership is known
  references: map<TESObjectREFR*, Pending | Ready>
```

Engine pointers are identity keys only. Never retain an engine intrusive
reference or dereference a key after its engine callback ends.

Use one `parking_lot::Mutex` around the sparse ledger. Never hold it while
calling an engine predecessor. Streaming demand does not use this lock.

### Membership hooks

Observe reference insertion at the two list-publication calls inside
`0x00548230`, as specified by the current membership contract above. The
previous outer net-counter observer is superseded because it can miss
same-cell reinsertion and runs after real-3D attachment.

Hook reference removal at `0x0054CA90`. Remove the exact reference
only if vanilla decremented `+0xA8`. Measuring the native counter transition
is the current observer policy. The follow-up above proves that the decrement
precedes the list lock and is not an identity-removal success result; this
policy still needs replacement after the complete mutation contract closes.

The initial implementation intercepted the cell-only decrement helper at
`0x0055E1D0` and treated the transition as identity-less. It increments that
cell's generation, clears membership, marks it uncertain, and keeps distant
coverage. The 2026-07-23 follow-up audit below supersedes that intervention:
the helper's sole caller still owns the exact reference at `0x0055DE32`.
Patch that callsite and remove the exact identity instead. Continue to mark a
cell uncertain only when a real identity or counter mismatch remains; never
guess which reference disappeared.

### Successful ready publication

Redirect the sole ready call at `0x004520C4` through an i686 naked thunk. The
audited callsite contract is:

- `[EBP+0x08]`: real `TESObjectREFR*`;
- `[EBP+0x0C]`: owning `TESObjectCELL*`;
- `ECX`: the cell argument for `0x00452390`.

The thunk preserves the original register and stack contract, calls the
captured executable predecessor, then marks that exact cell/reference ready.
If the reference is absent, removed, uncertain, or belongs to an older
generation, ignore it and count a stale publication.

Recording readiness at this callsite guarantees that state is published after
successful real 3D creation and before the caller can invoke a cell update or
retirement gate.

### Correct gate

Hook `0x005495A0`. Call the predecessor for diagnostics, but return sidecar
readiness instead of trusting lifetime totals.

Retirement is allowed only when:

- the cell has tracked state;
- membership is certain;
- the current reference set is non-empty;
- every current reference is `Ready` in the same generation.

Missing or uncertain state returns false. The native `+0xA8` and `+0xAA`
counters remain untouched for compatibility. Native total consistency is an
additional ledger check; the counters alone do not authorize transition start.

Keep the existing `0x00557AA0` transition timer and the per-frame retirement
logic at `0x00551890`. Psycho corrects the readiness decision, not the native
fade/state transition. The follow-up above identifies hide publications that
occur after or outside this start decision; full-flow coverage remains open.

### Reload, teardown, and pointer reuse

- At `0x005508B0`, advance and clear the cell generation before vanilla
  resets counters and conditionally removes or retains references. The
  retained-member recovery contract is addressed in the follow-up above.
- At `0x0054CD20`, erase the cell entry during teardown so a reused cell
  address cannot inherit readiness.
- At `0x006FCE00`, advance the global epoch and clear every cell entry before
  the native worldspace reset.

A cancelled or failed current reference remains pending. Prefetch gives normal
slow work more lead time, while terminal failure safely retains distant
coverage.

## Runtime patch manifest

Keep streaming landmarks and inline hook containers in
`engine_fixes/statics.rs` and their signatures in `engine_fixes/types.rs`.
`lod/membership.rs` owns the two publication calls, their exact instruction
contexts, captured providers, and bridge signatures.

| Contract | Address | Intervention |
|---|---:|---|
| Terrain demand | `0x006FE550` | predecessor-chaining predicate hook |
| Object demand | `0x006FE620` | predecessor-chaining predicate hook |
| Tree demand | `0x006FE780` | predecessor-chaining predicate hook |
| Worldspace LOD reset | `0x006FCE00` | clear sidecar, then chain |
| Cell reference insertion | `0x005482AB`, `0x00548344` | observe native list publication before attachment |
| Cell reference removal | `0x0054CA90` | observe native counter delta |
| Alternate reference removal | current `0x0055E1D0`; repair `0x0055DE32` | replace function hook with exact-identity call thunk |
| Ready publication call | `0x004520C4` | exact `E8 rel32` thunk patch |
| Readiness gate | `0x005495A0` | sidecar decision hook |
| Cell reload reset | `0x005508B0` | advance generation, then chain |
| Cell teardown | `0x0054CD20` | erase identity, then chain |

Do not hook `0x006FCA90`, the LOD block constructors/finalizers, task vtables,
the IO manager, the global completed queue, `0x0043FC40`, or generic scene
graph virtuals. Those are contract landmarks, not required intervention
points.

## Installation and compatibility

Install two independent `ModificationTransaction` groups:

1. Streaming: terrain, object, and tree predicates plus worldspace reset.
2. Handoff: insertion, removal, alternate decrement, ready callsite, gate,
   reload reset, teardown, and worldspace reset observation.

Prepare every member of a group before enabling any member. Verify the
supported FalloutNV `1.4.0.525` instruction or callsite state, publish callable
predecessors before activation, and chain existing executable owners where the
contract remains compatible.

If any member fails preparation or activation, roll back that entire group.
A partially installed identity ledger must never control the readiness gate.
The other independent group may remain active and its state must be reported
clearly.

No new WinAPI calls are required. If installation later needs a missing OS
operation, add a `libpsycho::os::windows::winapi` wrapper instead of calling
WinAPI directly.

## Failure behavior

- Disabled configuration installs no hooks and preserves vanilla behavior.
- A missing `.DLODSettings` object remains inert.
- Invalid camera, node, setting, or multiplier state returns the predecessor
  demand result.
- A streaming-hook conflict disables and rolls back the whole streaming group.
- A handoff-hook conflict disables and rolls back the whole handoff group.
- Missing, uncertain, or stale identity state keeps distant coverage.
- Cancelled or failed real-reference publication does not receive synthetic
  readiness.
- Psycho never forces a timeout retirement without proven real coverage.
- No terminal error path frees, retries, duplicates, or attaches an
  engine-owned object.

## Diagnostics

Expose a compact `PsychoInfo`/hang-report snapshot containing:

- installation state for both transaction groups;
- predecessor addresses and callsite ownership;
- native and extended terrain/object/tree demand decisions;
- retention decisions and native releases;
- current and peak tracked cells and references;
- membership inserts and removals;
- successful, duplicate, and stale ready publications;
- sidecar gates allowed and blocked;
- vanilla/sidecar gate disagreements;
- prevented stale-credit retirements;
- uncertain InitItem/error cells;
- reloads, teardowns, and worldspace resets;
- oldest pending-reference age;
- maximum observed ledger-lock duration.

The optional fixed ring retains the last 256 meaningful events with event
kind, cell, reference, generation, native counts, sidecar counts, tick, and
thread ID. It is disabled by default. Normal operation logs only installation,
summary, anomalies, and power-of-two sampled failures.

## Performance and memory contract

The implementation is acceptable only with all of these properties:

- no custom worker, queue, or global IO-manager hook;
- no change to the global completed-task frame budget;
- no allocation or lock in the three streaming predicates;
- no engine call while the handoff ledger lock is held;
- no per-frame scan of every tracked cell or reference;
- spatially bounded residency through finite request and retention distances;
- immediate sidecar erasure on cell/worldspace teardown;
- no verbose log on a valid hot path.

Prefetch intentionally trades additional temporary RAM/VRAM and IO work for
lead time. Object/tree coverage grows approximately with the square of the
distance multiplier, while terrain can grow faster through recursive splits.
Release defaults must therefore be conservative and validated on a huge
modpack.

OOM risk increases with the retained LOD ring and must be measured. UAF safety
must not regress because native task and scene ownership are unchanged and raw
pointers are stored only as non-dereferenced identities. Performance improves
when IO and completion work are moved before visible demand, but overly large
distances can replace late loading with sustained memory pressure or IO
backlog.

Reject release defaults that cause unbounded VAS growth, prevent memory from
returning to a stable plateau after transitions, or measurably worsen normal
frame pacing.

## Historical implementation order

1. Add `LodConfig`, raw deserialization, validation, defaults, and TOML
   documentation.
2. Add audited ABIs, addresses, hook containers, and installation snapshots.
3. Implement allocation-free distance and threshold helpers.
4. Install and validate object/tree prefetch and retention.
5. Add terrain prefetch with its smaller independent limits.
6. Implement the generation/membership ledger without engine calls under its
   lock.
7. Add insertion, exact alternate removal, reset, and teardown tracking.
8. Add the ready-publication thunk and predecessor chaining.
9. Replace the readiness gate and add vanilla/sidecar disagreement counters.
10. Add aggregate diagnostics and the optional trace ring.
11. Install each subsystem transactionally and verify rollback behavior.
12. Format and build the supported i686 release target.
13. Complete the staged runtime matrix before selecting final defaults.

## Verification

Build only the supported target:

```bash
cargo build --release --target i686-pc-windows-gnu \
  -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Run runtime validation in this order.

### Handoff with prefetch disabled

1. Remove a ready VWD reference and insert a different not-ready reference.
   The stale credit must not arm retirement.
2. Dynamically enable, disable, move, create, and remove references through
   normal engine and xNVSE paths.
3. Remove a reference while its AttachDistant3DTask is pending. A late
   completion must be ignored.
4. Reload a save, fast travel, cross worldspaces, and revisit unloaded cells.
   No generation may inherit state.
5. Exercise the InitItem/error decrement through `0x0055DE32`. The exact
   reference must be removed while the cell remains certain. A deliberately
   invalid identity or counter delta must still become uncertain and retain
   distant coverage.
6. Confirm a fully ready current population arms the native transition no
   later than the next normal cell update.

### Object and tree prefetch

1. Walk, sprint, teleport, and use high-speed free camera toward unloaded
   regions.
2. Oscillate around the vanilla boundary. Blocks must not repeatedly
   construct and release.
3. Reverse direction abruptly and confirm retention remains bounded.
4. Exercise missing LOD assets and task cancellation without forced holes.
5. Confirm the native priority queue, task dependencies, main completion
   queue, and slot-5 publication remain the only owners.

### Terrain prefetch

1. Traverse long exterior routes and high-altitude views.
2. Repeatedly cross adjacent-cell and terrain split boundaries.
3. Enter an interior and change worldspaces; terrain memory must return toward
   a stable plateau.
4. Compare terrain task counts, completion backlog, frame-time percentiles,
   RAM, VRAM, and VAS before and after each multiplier change.

### Compatibility matrix

1. Allocator modes `0`, `1`, and `2`.
2. Lightweight and huge modpacks.
3. Helper present and absent.
4. Queued-task lifetime guard enabled.
5. Worldspaces with and without valid `.DLODSettings`.
6. Full feature disabled, prefetch-only, handoff-only, and both enabled.
7. Earlier compatible hooks and deliberate instruction conflicts to verify
   predecessor chaining and transaction rollback.

## Acceptance criteria

- No removed reference can contribute ready credit to a later population.
- No old-generation completion can authorize current retirement.
- Distant coverage retires promptly after every current eligible reference is
  ready.
- Missing real coverage never produces a forced visibility hole.
- Object, tree, and terrain tasks start before vanilla visible demand.
- Small boundary reversals do not destroy and recreate the same blocks.
- The global IO completion budget and generic task behavior are unchanged.
- Memory reaches a bounded plateau and recedes after cell/worldspace teardown.
- Fixed-camera median and 99th-percentile frame time do not regress outside
  measurement noise.
- Disabling the feature restores vanilla behavior.

## Stress-test crash follow-up: 2026-07-19

### Confirmed failure boundary

The crash is not OOM. CrashLogger reports `C0000417` at `0x00EC7C62` with
1.31 GiB of 4 GiB VAS in use. Psycho telemetry immediately before the crash
reports about 1.1 GiB commit, 1.0 GiB total free VAS, and a 637 MiB largest
free region. No OOM cleanup stage ran, and periodic blocking PDD purge was
disabled.

The main-thread call chain is:

```text
FUN_0086FF70
  -> FUN_00C458F0 completed-task processing
  -> completed-task array release
  -> BSTreeNode deleting destructor 0x0066B680
  -> BSTreeModel deleting destructor 0x006667D0
  -> core SpeedTree destructor 0x00B03B30
  -> registration-container erase helper 0x00B0DF00
  -> CRT invalid-parameter failure 0x00EC7C62
```

The destroyed node is `\WastelandUndergrowth01.spt`; CrashLogger shows the
`BSTreeNode` and several `NiRefObject` instances at reference count zero. This
is the exact asset and crash family already documented beside gheap's
zero-cooldown LIFO reuse path. The 80-byte pool used by `BSTreeModel` also
expanded during the final high-churn interval.

The first crash audit proves the exact immediate violation. The core SpeedTree
object has non-null payload field `+0x34` and owner field `+0x38`, but its
address is absent from the owner's pointer vector at `[owner+0x0C,
owner+0x10)`. `0x00B03B30` searches that vector, receives the end iterator,
and unconditionally passes it to erase helper `0x00B0DF00`. The helper detects
`erase(end)` and reaches the CRT invalid-parameter failure. The destructor's
other, global-registry branch checks for end before erasing; this per-owner
branch does not.

The normal release chain is also proven. Completed-task processing releases a
`BSTreeNode`; destruction of its arrays releases `BSTreeModel`; field `+0x0C`
then releases the nested core SpeedTree allocation. `0x0066AC40` constructs a
base core object for first load and destroys it only on load failure before
publishing it into `BSTreeModel`; it is not a live-model replacement path.

The follow-up audits prove that the base core constructor `0x00B02EF0` sets
payload `+0x34` to zero. The crashing nonzero-payload state therefore comes
from clone constructor `0x00B036D0`, reached through allocation wrapper
`0x00B05210` by `BSTreeModel` clone path `0x0066A650`.

The clone constructor copies the base object's shared refcount pointer `+0x30`
and shared owner pointer `+0x38`, pushes the clone into the owner's vector with
`0x00B0DDC0`, increments the shared refcount, allocates payload `+0x34`, and
increments the global tree count. None of those operations is locked. The
clone destructor performs the inverse shared-refcount decrement, vector
search/erase, payload free, and global-count decrement without a lock. The
generic vector insertion helper has only two callers: locked base-registry
insertion and this unlocked clone insertion. The erase helper has only the two
destructor branches. The base branch uses SpeedTree critical section
`0x011F8BC4` and checks for end; the clone branch uses neither protection.

The root defect is therefore a native SpeedTree clone-lifecycle race. Worker
model loading can publish a clone while main-thread completed-task processing
destroys clones sharing the same owner vector and refcount. The crash is the
clone destructor observing a missing member and passing `end` to erase. Gheap
zero-cooldown reuse and increased LOD churn shorten the timing window and add
an ABA risk, but they are amplifiers of the missing engine synchronization,
not justification for an allocator-wide quarantine or an `erase(end)` patch.

The LOD handoff ledger is not the direct corruptor. It stores engine pointers
only as integer identities, never releases them, and fails closed when state is
uncertain. Its warnings can retain distant coverage but cannot invoke the
BSTree destructor. The audited distant-tree task vtable loads and owns only a
`BGSDistantTreeBlock`; it has no path to `BSTreeManager`, `BSTreeModel`, or
`.spt` ownership. Prefetch can amplify native task and allocator churn but is
not the corruptor and must not be disabled as the fix.

### Research gate result

The three crash audits close the constructor, insertion, refcount, owner,
destructor, physical-free, task-release, and distant-tree separation gaps. No
additional static audit is required before implementation.

Do not patch the missing end check. Skipping erase while continuing to free
payload `+0x34` can double-free a stale clone or free payload belonging to a
reused live clone.

### Fix plan

1. Add a small `speedtree_lifetime` owner to `psycho-engine-fixes` core. Hook
   clone constructor `0x00B036D0` and the only core scalar-destruction wrapper
   `0x00666910`. Install both hooks atomically; refuse this fix if either target
   is already owned or either trampoline is unavailable.
2. Extend the engine's existing SpeedTree critical section at `0x011F8BC4`
   over the whole clone constructor and whole scalar destructor. Use
   `BorrowedCriticalSection`; the native critical section is reentrant, so the
   base destructor may safely enter it again. This covers owner-vector
   insertion/removal, shared-refcount increment/decrement, payload
   publication/free, last-owner cleanup, and the global tree count as one
   lifecycle transaction.
3. In the scalar-destructor hook, while holding the same lock, validate clone
   owner-vector bounds and membership before calling vanilla. Valid objects
   always take the original path. If a clone is already absent, fail closed by
   skipping the entire scalar destructor, including its physical free, and
   emit a power-of-two diagnostic. Leaking one already-corrupt clone is safer
   than guessing ownership; this guard is a last-resort safety net, not the
   synchronization fix.
4. Record sampled proof counters: clone constructs, clone destroys, maximum
   owner-vector length, missing-member rejects, invalid bounds, and lock wait
   time. When gheap is active, include `ptr_info` state only before native
   destruction. Do not dereference or inspect the object after the original
   destructor returns.
5. Keep the DTL predicate, native task graph, completed-task budget, and LOD
   multipliers unchanged. Tree prefetch increases load but does not own `.spt`
   clones and must not be disabled as the fix.
6. Do not change gheap reuse policy in the first fix. If synchronized stress
   runs still produce a missing-member reject and telemetry proves a free or
   reused gheap cell, design a second, tree-provenance quarantine around the
   exact 80-byte `BSTreeModel` and 160-byte core clone lifetimes. Do not add a
   size-class-wide cooldown, global quarantine, or PDD freeze.
7. Repair the separate handoff resynchronization gap at the exact
   `0x0055DE32` callsite. The caller retains the reference at `[EBP-0x68]` and
   the cell in `ECX`; route both through a predecessor-chaining thunk and
   publish an exact removal only after the native minus-one counter delta.
   Keep genuine mismatches fail-closed and never fall back to lifetime totals.
8. Remove proof-only verbose telemetry after the lifetime assertion stays
   clean, retaining aggregate and power-of-two diagnostics.

### Engineering balance

- UAF protection is the primary objective. The native SpeedTree lock closes
  the partial-construction, vector mutation, shared-refcount, and last-owner
  windows without relying on reuse timing.
- OOM safety is improved relative to quarantine proposals: normal objects are
  never retained. Only an already-corrupt clone rejected by the safety guard
  leaks, with an explicit counter. Any later quarantine requires separate
  proof and a finite release boundary.
- Performance cost is limited to tree clone construction and destruction.
  There is no per-allocation, render-callback, generic IO, or completed-task
  overhead. One native critical section is simpler and safer than a per-owner
  lock map whose keys have the same lifetime problem.

### Validation matrix for the crash fix

1. Reproduce the original high-speed Wasteland route with allocator mode `2`,
   full LOD, and trace enabled for proof runs.
2. Repeat with tree multipliers `1.0/1.0` while object, terrain, and handoff
   remain enabled. This measures workload amplification without presenting a
   disable as the fix.
3. Repeat with allocator modes `1` and `0` using the same LOD settings to
   isolate gheap physical reuse from the native ownership path.
4. Oscillate across tree and cell boundaries, then allow queues and memory to
   settle. Require zero missing-member rejects, zero invalid vector bounds,
   balanced clone construction/destruction after settling, bounded retained
   memory, and no PDD or task-drain hang.
5. Run substantially longer than the 4:10 failing playtime on both lightweight
   and huge modpacks. Acceptance requires no `C0000417`, no stale BSTree
   destructor telemetry, a stable VAS plateau, and preserved early LOD/handoff
   behavior.
6. Compare fixed-camera and high-speed-route frame time before and after the
   lock. Lock contention must remain negligible outside load bursts, and no
   render callback may block on this critical section.

## Save-load cache-allocation follow-up: 2026-07-19

### Proven contract

- `0x00AFF300` successfully opens the CRT `FILE*` at `BSFile + 0x24` before
  calling the open-state initializer at `0x00AFF490`.
- A cache capacity of `0xFFFFFFFF` requests a whole-file cache. The initializer
  obtains the concrete file size through vtable slot `+0x1C`, allocates that
  size through `GameHeap::Allocate`, and stores the result at `BSFile + 0x20`.
- Vanilla does not test that result before calling `0x00AA1570`. A null cache
  becomes a null `_DstBuf` in `_fread_s`, whose invalid-parameter path raises
  `C0000417` at `0x00ECB144`.
- The object is still inside its open transaction, so its `FILE*` has not been
  published to another task and cannot be concurrently closed. With element
  size one, multiplication overflow is also excluded. The missing allocation
  check is the failing contract.
- The native read function at `0x00AA1750` explicitly uses direct `fread` when
  the cache capacity at `+0x10` is smaller than the requested transfer. A zero
  capacity with null cache is therefore the class's supported unbuffered mode,
  not a skipped model or failed task.

### Implemented fix

1. Hook `0x00AFF490` in the same transaction as all three LockFreeMap capacity
   hooks and the exact two-worker instruction patch.
2. Preserve native open-state, dynamic file-size resolution, cache allocation,
   whole-file preload, short-read rejection, and game-heap ownership.
3. On cache allocation failure only, clear cache capacity/fill/cursor while
   keeping the open flag and `FILE*`. Later reads continue through the native
   direct-IO branch.
4. Count direct-cache fallbacks in `PsychoInfo`. Do not log or allocate on the
   allocation-failure branch.
5. Keep two workers, LOD task priority, prefetch, handoff, and SpeedTree
   lifetime synchronization enabled.

### Engineering balance

- OOM recovery improves: an optional read cache no longer converts recoverable
  pressure into a fatal CRT exception.
- UAF protection is unchanged: the fix neither extends object lifetime nor
  changes publication or destruction ownership.
- Performance is unchanged while cache allocation succeeds. Under allocation
  pressure only, the affected file uses slower direct reads instead of losing
  the task or process. No generic allocation or steady-state read hook is
  added.

### Runtime acceptance

1. Repeatedly load saves while traversing LOD-heavy exterior cells with both
   workers active. Require no `C0000417` and no task-constructor ABI crash.
2. Verify `PsychoInfo` reports two active workers and file-cache fallback `ON`.
3. If the fallback counter rises, require successful completion of the same
   save load and continued LOD publication. A rising counter without memory
   pressure requires a fresh allocation-size audit.
4. Repeat with allocator modes `0`, `1`, and `2`. The fallback must remain
   allocator-domain independent and every successful cache must still be
   freed by the game heap.

## BSTree TLS-slot exhaustion follow-up: 2026-07-19

### Proven contract

- The crash at `0x006EC846` is a null scratch-map dereference reached from
  `0x00449530` after `0x00449F80` fails to register the calling thread.
- `BSTreeManager` constructs its map at `BSTreeManager + 0x1C` through the
  private constructor at `0x00665CB0`, passing a per-thread capacity of two.
  This specialization does not call either generic LockFreeMap constructor
  already hooked by the parallel-IO transaction.
- The only two direct callers of the tree find/load owner at `0x00664F50` are
  queued tree execution at `0x0043DA00` and main-thread QueuedReference
  completion at `0x0050F810`.
- With two IO workers, both workers can occupy the two native slots before
  main-thread save-load completion registers. The third registration returns
  null and the native caller dereferences it. This is capacity exhaustion,
  not a missing tree key, stale model, or allocator ownership failure.

### Implemented fix

1. Hook private constructor `0x00665CB0` and expand its per-thread capacity by
   exactly one, changing the native BSTree map from two slots to three.
2. Own this hook in the same transaction as both generic capacity hooks, the
   BSFile fallback, and the exact two-worker instruction patch. Any failure
   rolls the complete parallel extension back to the native one-worker path.
3. Refuse installation if either IOManager at `0x01202D98` or BSTreeManager at
   `0x011D5C48` already exists. Recheck both owners immediately before commit
   so no manager can publish a map built with old capacity.
4. Expose private BSTree-map expansions separately in `PsychoInfo`. Do not add
   a null guard at the crash site, skip tree loads, or disable a worker.

### Engineering balance

- UAF protection is unchanged: no object lifetime, reuse, or free edge moves.
- OOM cost is bounded to one additional 12-byte BSTree scratch record and its
  constructor-owned slot metadata. No allocator-wide retention is added.
- Performance keeps both IO workers and removes the failed-registration path.
  Constructor interception has no per-load overhead after the map is built.

### Runtime acceptance

1. Start a fresh process and verify `PsychoInfo` reports two active workers,
   one Tree TLS map expansion, and zero capacity failures.
2. Repeatedly load saves while both worker threads process exterior tree LOD.
   Require no `0x006EC846` crash and continued real-tree publication.
3. Stress cell transitions and rapid save-load cycles longer than the prior
   failing runs. Require stable queue drain, no SpeedTree ownership rejects,
   and no growth in scheduler failures.
4. Repeat with allocator modes `0`, `1`, and `2`; the result must be independent
   of allocator domain and preserve the two-worker throughput improvement.

## Missing distant-geometry priority regression: 2026-07-19

### Proven contract

- The task key stores priority as an unsigned byte at bits 16-23. Runtime
  priority replacement at `0x00C3DF40` updates that exact field and preserves
  the task class, secondary key, and sequence.
- The queue comparator at `0x00C3F6B0` reports the first existing key greater
  than or equal to the requested key. Insertion at `0x00C3FFB0` places the new
  node at that predecessor edge, producing ascending key order.
- Worker traversal at `0x00C40E70` begins at the first queue bucket, and
  `0x00C42380` returns the first live node. Smaller numeric priority values are
  therefore serviced before larger values when the surrounding key fields
  match.
- Blocking load ownership at `0x00C3E1B0` starts after `state * 4 + 3` and
  stops when a decoded task priority exceeds the active load state. The
  companion count at `0x00C3E860` covers exactly the buckets through that
  boundary.
- Native LOD priority is normally `1` or a bounded dynamic archive priority
  plus four. Psycho's value `255` was outside the scheduler's active priority
  contract and could leave all three LOD task types unserviced across load.
- Terrain, object, and tree demand predicates, resource lookup, worker loads,
  completed-task drain, and main-thread publication remain intact. The
  regression is shared scheduler eligibility, not missing LOD data or a
  publication hook failure.

### Implemented fix

1. Change the LOD boost from priority `255` to native priority `0`.
2. Continue calling the engine's dependency-aware update at `0x00C3CAE0`, so
   the task and its dependencies move together and queued state still uses the
   native remove-and-requeue transaction.
3. Preserve both IO workers, all three TLS-capacity expansions, the BSFile
   fallback, early demand, handoff state, and SpeedTree lifetime locking.
4. Report the installed numeric priority in the startup log and retain the
   per-type boost counters in `PsychoInfo`.

### Engineering balance

- Performance is corrected: LOD work receives the engine's actual highest
  scheduling priority instead of being placed behind eligible native work.
- UAF protection is unchanged: no task, model, tree clone, or scene object
  lifetime edge moves.
- OOM behavior is unchanged: queue nodes, cache allocation, direct-read
  fallback, and allocator ownership are untouched.

### Runtime acceptance

1. Start a new process and require the log to report priority `0`, two workers,
   three TLS capacity families, and the BSFile fallback installed.
2. Load the save that showed flying grass. Require distant terrain first, then
   object and tree LOD, without waiting for a cell reload or console command.
3. Traverse exterior cells at speed and repeat save-load cycles. Require rising
   terrain/object/tree boost counters, continued publication, and no scheduler
   or capacity failures.
4. Repeat the prior crash stress route. Acceptance requires both corrected LOD
   visibility and no return of the constructor ABI, `C0000417`, or BSTree TLS
   crashes.

## Exterior-cell global-owner stress crash: 2026-07-19

### Proven contract

- The crash is `C0000005` on a `BSTaskManagerThread` executing an
  `ExteriorCellLoaderTask`. The chain ends at `0x0044DDC0`, which reads
  `ECX + 8`, with `ECX = 0`.
- `0x005516C0` forwards its own `this` pointer unchanged to that leaf. At the
  crashing call site, `0x004686F4` loads `this` from global `0x011C3F30` and
  `0x004686FA` calls `0x005516C0`.
- The same caller checks `0x011C3F30` for null at `0x004686D3`, but reloads it
  later. This is a concrete check/reload race, not a corrupt task pointer or
  allocator failure.
- Per-form loader `0x00550500` writes the current cell to `0x011C3F30` at
  `0x0055065D`, performs form construction, then clears the global at
  `0x00550862`. The owner is process-global, not TLS or task-local, and the
  audited call path has no enclosing lock.
- Exterior demand owner `0x00452580` may submit multiple cell tasks while
  crossing a grid edge. Generic dispatch at `0x00C3FC80` sends independently
  dequeued tasks to either worker, so two execute bodies can overlap.
- Vanilla passes exactly one worker at `0x00C3DA7A`. The execute method at
  `0x00527CB0` is the only vtable entry that reaches the shared form-loading
  path, and it performs no wait on another IO task. Serializing this method
  restores the native ordering without changing task creation, queue
  ownership, completion, or destruction.

### Implemented fix

1. Hook `ExteriorCellLoaderTask::execute` at `0x00527CB0` and hold one blocking
   worker mutex across the complete original method.
2. Keep the task payload processing and its final native release in the
   original method. Do not replace, cancel, delay-publish, or destroy a task.
3. Own the serialization hook in the same all-or-nothing transaction as the
   three TLS-capacity hooks, BSFile fallback, and two-worker patch. Failure to
   own any contract retains vanilla one-worker IO.
4. Report installation, executed cell tasks, and contended entries in
   `PsychoInfo`.
5. Preserve priority `0`, both workers, early LOD demand, identity handoff,
   SpeedTree lifetime locking, and direct-read fallback.

### Engineering balance

- UAF protection improves because two cell loaders can no longer overwrite or
  clear each other's process-global form owner.
- OOM behavior is unchanged. The mutex has no per-task allocation and no
  queue, payload, cache, or allocator ownership changes.
- Performance retains two workers. Exterior-cell form parsing runs at its
  vanilla concurrency of one, while terrain, object, tree, model, and safe file
  tasks remain eligible on the other worker.

### Runtime acceptance

1. Start a new process and require the startup log to include serialized
   exterior-cell loading with two workers and priority `0`.
2. Repeat the exact exterior stress route. Require rising cell-loader runs;
   waits may rise during grid transitions and are expected.
3. Require no `0x0044DDC0` crash, no `0x011C3F30` null-owner signature, and no
   return of the prior save-load or BSTree failures.
4. Confirm distant terrain, objects, and trees remain visible and all three
   priority counters continue rising.

## LandLOD static vertex-buffer lifetime crash: 2026-07-19

### Proven contract

- The crash at `0x00E8C00D` occurs before Direct3D `Lock`. The instruction
  dereferences the first argument passed to `0x00E8BFF0`; that argument is
  `NiVBChip + 0x08`, and it is null while the `NiVBChip` itself is non-null.
- `0x00E941A0` does not allocate a Direct3D resource. It only initializes the
  static block usage and mode fields. The actual `CreateVertexBuffer` call is
  in `0x00E94580`, which returns null when the HRESULT reports failure.
- `0x00E98660` constructs a non-null chip by copying the parent block's
  Direct3D buffer from block `+0x08` to chip `+0x08`. It does not validate the
  copied pointer.
- `NiStaticGeometryGroup` allocation at `0x00E94C20`, retirement at
  `0x00E94770`, its block map, sorted free list, chip pool, accounting, and COM
  release path own no lock. Terrain worker execution can enter renderer
  prepacking, so two IO workers expose this shared lifetime race.
- The common wrapper at `0x00E8BFA0` retires the old stream, allocates a new
  chip, publishes it, and returns success based only on the chip pointer. The
  shader-declaration caller then reads chip `+0x08` without another guard.
- A genuine `CreateVertexBuffer` failure has a second native bug:
  `0x00E94C20` dereferences the null chip at `0x00E94CDD` instead of returning
  allocation failure to `0x00E8BFA0`.
- Vanilla `NiGeometryBufferData::IsVBChipValid` at `0x00E8EEB0` checks every
  stream and requires both a chip and chip `+0x08`. Stewie's rendering inline
  checks only stream zero, so it can admit partially invalid multi-stream
  geometry.

### Implemented fix

1. Serialize `NiStaticGeometryGroup` allocation and retirement with one
   reentrant lock. The outer `0x00E8BFA0` transaction holds the same lock for
   static geometry, while direct slot calls are also covered.
2. Patch the null return at `0x00E94CDB` to unwind the existing stack frame and
   return null. The common wrapper and all audited callers then use their
   native deferred-pack path, so the next request retries allocation.
3. Validate the published stream chip and chip `+0x08` before reporting
   success. Retire an invalid publication immediately while the static
   lifetime lock is still held, then return false for a clean retry.
4. Restore all six audited call sites to vanilla `0x00E8EEB0` all-stream
   validation, including when Stewie's weaker rendering inline is active.
5. Keep two IO workers, priority zero, all terrain/object/tree tasks, early
   demand, handoff, and renderer features enabled. Only the unsafe shared
   static vertex-buffer allocator is serialized.
6. Report lifetime-guard state, transactions, allocations, retirements, and
   safe create/publication retries in the compact `PsychoInfo` report.

### Engineering balance

- UAF/race protection improves because static block, free-list, chip, and COM
  lifetime transitions are one transaction and invalid resources are never
  exposed to pack callers.
- OOM behavior improves because Direct3D allocation failure becomes a
  retryable deferred pack instead of a null dereference. No geometry or LOD
  category is removed.
- Performance retains both IO workers. Safe file, model, cell, object, tree,
  and terrain work remains parallel; only the proven non-thread-safe static VB
  ownership path is serialized.

### Runtime acceptance

1. Start a new process and require the LOD startup line to report `vb=true`,
   priority zero, and two workers. `PsychoInfo` must show the lifetime guard ON.
2. Repeat the long exterior stress route beyond the prior crash time. Require
   no `0x00E8C00D` null-VB fault and no `0x00E94CDD` null-chip fault.
3. Require distant terrain, objects, and trees throughout the run. A rising
   safe-retry counter is acceptable; missing distant geometry is not.
4. Repeat save-load and rapid cell-transition stress. Require stable worker
   counts, continued LOD priority activity, and no return of the prior
   exterior-owner, BSTree TLS, or SpeedTree failures.

## Stale-retention and lighting-continuity audit: 2026-07-23

### Outcome

This audit found a real stale-LOD root cause and separated it from two
independent OMV LandLOD lighting defects. The exact handoff repair, continuous
half-vector math, and draw-scope texture revalidation were implemented on
2026-07-23.

| Observation | Status | Owner |
|---|---|---|
| Distant representation survives indefinitely | Fixed at the identity-preserving callsite | Psycho handoff ledger |
| Survival within configured retention distance | Intentional | Psycho demand hysteresis |
| Object block remains after demand becomes false | Rejected for the native manager | Native release is immediate |
| LandLOD switches between OMV PBR and vanilla | Proven in the current runtime | OMV draw admission |
| LandLOD/TerrainFade BRDF can jump near opposite view/light vectors | Fixed with continuous half-vector math | OMV shader math |
| The user's visible shape change is an actual projected-shadow defect | Not proven | Needs visual A/B or capture |

The stale-retention defect is not a native unload delay. The current runtime
log records a cell becoming uncertain after the hook at `0x0055E1D0`.
`mark_uncertain` clears every reference identity and sets `certain=false`.
`ready_gate` then blocks distant-representation retirement until a cell reload,
teardown, or worldspace reset. This fail-closed behavior prevents holes when
identity truly is unknowable, but the new executable audit proves identity is
available at the only callsite and Psycho discards it by hooking too late.

### Alternate-decrement root cause and repair

The current executable is PE32 i386, image base `0x00400000`, file size
`16,084,808`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The radare2 evidence is preserved in
`analysis/radare2/output/perf/lod_streaming_stale_retention_audit.txt`.

`0x0055E1D0` receives only the cell in `ECX` and decrements cell `+0xA8`.
Its sole direct call is `0x0055DE32` inside the TESObjectREFR-family function
at `0x0055D760`. That caller saved the exact reference at `[EBP-0x68]`, obtains
its current cell through `0x008D6F30`, leaves the cell in `ECX`, and then calls
the decrement. The information contract at the callsite is therefore:

```text
ECX         current cell
[EBP-0x68] exact TESObjectREFR
```

The function-entry hook cannot recover the caller's frame after `0x0055E1D0`
creates its own `EBP`. The implemented repair is an exact callsite patch:

1. Replace the relative call at `0x0055DE32` with a naked fastcall bridge.
2. Preserve `ECX`, load `EDX = [EBP-0x68]`, and enter a
   `fastcall(cell, reference)` body.
3. Capture and chain the current executable predecessor, as the existing ready
   publication call patch does.
4. Observe the native total before and after the predecessor. Publish
   `observe_remove` only for an exact minus-one transition.
5. Validate the fixed prefix and suffix, the relative-call encoding, and an
   executable predecessor; include the patch in the handoff transaction.
6. Remove the `0x0055E1D0` function-entry hook and its unconditional
   `mark_uncertain` path.
7. Keep fail-closed behavior for an absent identity, an untracked reference, or
   an invalid predecessor/counter delta. Never guess which reference left.

`alternate_remove_entry` is a naked fastcall bridge. Release disassembly
proves its complete ABI boundary is `mov edx,[ebp-0x68]` followed by a direct
jump to `alternate_remove_body`; no compiler prologue changes the caller frame.
The body chains the captured predecessor and publishes the reference removal
only when the native counter changes by exactly minus one. Every other outcome
marks that cell uncertain and remains fail-closed.

The current warning at
`psycho-engine-fixes/psycho-engine-fixes-latest.log:309` proves the broken path
ran for cell `0xF1CC3180`. It does not prove that this address owned the exact
visible stale block reported by the user; correlating geometry to the cell
still requires trace or a frame capture.

### Native unloading and retention

The object manager at `0x006FDFC0` calls demand predicate `0x006FE620`. When
demand is false, `0x006FE1C0..0x006FE1F7` releases a non-null object block
through `0x006FD920` and clears node `+0x14` in the same manager update. There
is no native post-demand grace timer to shorten.

The configured `1.35` object/tree prefetch and `1.50` retention multipliers are
therefore doing the intended work. In area-order terms they can expose about
`1.35^2 = 1.82` times the vanilla request footprint and retain up to
`1.50^2 = 2.25` times it; hierarchical overlap means those are not measured
memory multipliers. Terrain remains narrower at `1.10/1.20`. Final defaults
still require a long traversal showing a resident-memory and 32-bit-VAS
plateau. Reducing these values would hide load, not fix indefinite retention.

### LandLOD lighting evidence

The current OMV log provides two direct facts:

- LandLOD PBR became active at `14:43:54.293`.
- At `14:43:54.721`, OMV kept a LandLOD draw vanilla because a required native
  sampler was unbound.

OMV performs this check from the intercepted Direct3D draw call, after the
engine has had the opportunity to bind textures, so this is not merely
`SetShaders` running before texture setup. The native `SLS2003.pso` bytecode in
every one of the 16 installed shader packages declares and samples
`s0/s1/s4/s6/s7`. OMV's five-stage requirement exactly matches that ABI.
There is no proven reduced native variant to emulate. The old warning did not
report the missing stage, so whether the bad state originates in base, normal,
parent diffuse, parent normal, or noise ownership remains open. The repaired
build logs a bounded missing-stage bitmask and the full required mask on the
first failure of each terrain family.

This produces a visible continuity hazard: nearby draws can use materially
different OMV PBR and vanilla equations. The safe next investigation is to
record the missing sampler mask and pass/draw identity, then prove the engine
owner that should bind that exact stage. Do not invent a white, flat-normal,
child-as-parent, or other fallback texture before that ownership is closed.

There was a second source-proven defect. Both production shaders
`native_pbr_pplighting_landlod.hlsl` and
`native_pbr_pplighting_terrainfade.hlsl` used:

```hlsl
SafeNormalize(view_dir + sun_dir, normal)
```

When the view nearly opposes the sun, this switched discontinuously from the
normalized half-vector to the surface normal. LandLOD and TerrainFade now use
the same zero-safe `StableHalfway` equation as object and close terrain. A
numerical negative-control test reproduces the old step and proves the new
camera sweep remains continuous; the complete OMV shader suite compiles the
affected programs.

Neither base LandLOD nor TerrainFade PBR samples a shadow texture. Native
LandLOD projected-shadow rendering is a separate shader family and native
transition owner. Consequently the current evidence proves lighting/material
instability, not that OMV is changing a projected shadow map. Stale overlap
from the handoff defect can also change silhouettes and native shadow coverage,
but linking either mechanism to the user's exact visual symptom remains an
inference until an A/B capture.

### Implemented repair and remaining runtime closure

1. **Exact handoff identity: implemented.** The transaction patches
   `0x0055DE32`, chains the current predecessor, removes the identity-losing
   function-entry hook, and preserves fail-closed mismatch handling.
2. **Ledger regression tests: implemented.** Pure state tests cover exact
   removal, duplicate insertion/publication, missing identity, native-count
   agreement, and retirement gating. Existing reload, teardown, and world
   reset paths remain the only recovery boundary for genuinely uncertain
   cells.
3. **Uncertainty telemetry: implemented.** `PsychoInfo` reports exact and
   mismatched alternate removals, current uncertain-cell count, and oldest
   uncertainty age separately from lifetime event totals.
4. **Half-vector continuity: implemented.** LandLOD and TerrainFade use
   `StableHalfway`; the source/numerical regression covers both shaders, and
   all registered variants compile within the existing suite.
5. **Missing-stage isolation: implemented; native-owner repair awaits one
   runtime mask.** The fallback now reports exact missing and required sampler
   masks independently for LandLOD and TerrainFade. The gate remains strict;
   the next reproduced mask identifies the engine binding owner to trace.
6. **Draw-scope ownership: implemented without shader churn.** Only LandLOD
   and TerrainFade publish required-sampler masks. A non-null replacement on a
   required stage keeps the active shader pair unchanged. A required stage
   becoming null restores the native pair once; rebinding is retried only when
   a recorded missing stage becomes non-null. Object and close-terrain draws
   publish no direct-transition mask. If the texture hook is unavailable, the
   safe compatibility path re-evaluates every draw.
   The normal `SetTexture` path adds one relaxed mask load and an immediate
   zero-mask exit for unrelated families. It performs no atomic
   read-modify-write, allocation, lock, file I/O, or shader rebinding for a
   valid texture swap.
7. **Measure before scheduler retuning.** Priority `0` is the proven highest
   valid native priority and fixes the earlier `255` starvation. The bounded
   scheduling correction preserves native priority for proven speculative
   constructor work. Capture queue wait/completion latency and non-LOD
   starvation before adding queued-task promotion or changing priority tiers.

Do not add a timeout-based forced handoff, uncap the completed-task drain,
increase worker count, or remove object/tree/terrain coverage. Those changes do
not repair either proven defect and can reintroduce holes, races, or 32-bit
address pressure.

### Runtime acceptance

1. Run a clean process with LOD trace enabled. Exercise the former alternate
   decrement path. Exact alternate-removal counters must rise while current
   uncertain cells remain zero.
2. Cross the object/tree retention boundary and remain outside it. The native
   block pointers and distant representations must retire without requiring a
   cell reload; memory and VAS must plateau over a long route.
3. Reverse direction repeatedly across prefetch and retention bands. Require
   no holes, stale-ready publication, or unbounded request/release oscillation.
4. Rotate and approach the reported LandLOD/TerrainFade scene. Require no
   missing-sampler fallback, no PBR/vanilla style switch, and no half-vector
   brightness/shape jump.
5. If a true cast-shadow edge still changes with PBR disabled and the handoff
   ledger certain, capture the draw. That result belongs to native projected
   shadow/geometry handoff research, not another speculative streaming patch.

### Validation evidence

- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes`: 41 unit
  tests and doctests passed.
- `cargo test --target i686-pc-windows-gnu -p omv`: 292 tests passed,
  including all registered shader compilation, half-vector continuity,
  sampler-mask ABI, and bounded sampler-transition ownership regressions.
- The complete supported release command for `syringe`,
  `psycho-engine-fixes`, `psycho-engine-fixes-helper`, and `omv` passed for
  `i686-pc-windows-gnu`.
- Release PE32 disassembly of `alternate_remove_entry` is exactly
  `mov edx,[ebp-0x68]` then `jmp alternate_remove_body`.

Runtime traversal and the next missing-sampler mask remain playtest evidence,
not static proof.

## Research authority

- `analysis/ghidra/output/perf/lod_streaming_pipeline_contract_audit.txt`
- `analysis/ghidra/output/perf/lod_replacement_visibility_contract_audit.txt`
- `analysis/ghidra/output/perf/lod_handoff_scheduler_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_bstree_crash_ownership_audit.txt`
- `analysis/ghidra/output/crash/bstree_speedtree_owner_registration_followup_audit.txt`
- `analysis/ghidra/output/crash/bstree_speedtree_clone_registration_final_audit.txt`
- `analysis/ghidra/output/crash/lod_multiworker_save_load_ownership_final_audit.txt`
- `analysis/ghidra/output/crash/lod_save_load_c0000417_origin_and_coverage_audit.txt`
- `analysis/ghidra/output/crash/lod_bstree_tls_slot_exhaustion_root_cause_audit.txt`
- `analysis/ghidra/output/perf/lod_missing_distant_geometry_regression_audit.txt`
- `analysis/ghidra/output/perf/lod_priority_queue_boundary_final_audit.txt`
- `analysis/ghidra/output/crash/lod_exterior_cell_multiworker_null_owner_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_landlod_vertex_buffer_lifetime_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_vertex_buffer_geometry_group_allocation_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_allocation_failure_final_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_creation_leaf_retry_audit.txt`
- `analysis/radare2/output/perf/lod_streaming_stale_retention_audit.txt`

The matching source scripts are:

- `analysis/ghidra/scripts/lod_streaming_pipeline_contract_audit.py`
- `analysis/ghidra/scripts/lod_replacement_visibility_contract_audit.py`
- `analysis/ghidra/scripts/lod_handoff_scheduler_followup_audit.py`
- `analysis/ghidra/scripts/lod_bstree_crash_ownership_audit.py`
- `analysis/ghidra/scripts/bstree_speedtree_owner_registration_followup_audit.py`
- `analysis/ghidra/scripts/bstree_speedtree_clone_registration_final_audit.py`
- `analysis/ghidra/scripts/lod_multiworker_save_load_ownership_final_audit.py`
- `analysis/ghidra/scripts/lod_save_load_c0000417_origin_and_coverage_audit.py`
- `analysis/ghidra/scripts/lod_bstree_tls_slot_exhaustion_root_cause_audit.py`
- `analysis/ghidra/scripts/lod_missing_distant_geometry_regression_audit.py`
- `analysis/ghidra/scripts/lod_priority_queue_boundary_final_audit.py`
- `analysis/ghidra/scripts/lod_exterior_cell_multiworker_null_owner_crash_audit.py`
- `analysis/ghidra/scripts/lod_landlod_vertex_buffer_lifetime_crash_audit.py`
- `analysis/ghidra/scripts/lod_vertex_buffer_geometry_group_allocation_followup_audit.py`
- `analysis/ghidra/scripts/lod_static_vertex_buffer_allocation_failure_final_audit.py`
- `analysis/ghidra/scripts/lod_static_vertex_buffer_creation_leaf_retry_audit.py`
