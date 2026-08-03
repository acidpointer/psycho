# Native parallel IO and SpeedTree engine contract

Status: bounded scheduling, contention corrections, and AutoWater transaction
serialization implemented on 2026-07-27. Static validation is recorded below;
the tester's exact mod list and traversal still require the runtime acceptance
matrix.

This document is the durable contract for Psycho's native IOManager
parallelism. It owns the bounded two-worker scheduler extension and every
shared-state guard required to keep that extension safe. LOD is one consumer
of native IO, but parallel IO is not an LOD feature and does not belong to the
LOD module or configuration section.

## Executable identity

All virtual addresses in this document apply to the current executable at
`fnv_reverse/FalloutNV.exe`:

| Property | Value |
|---|---|
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |
| Format | PE32, x86, little-endian |
| File size | `16,084,808` bytes (`0x00F56F48`) |
| Image base | `0x00400000` |
| PE timestamp | `0x4E0D50ED` (2011-07-01 07:45:33) |
| PE checksum | `0x00F64BD0` |
| Debug GUID | `9196089162EE4D29BF48E8D767B32DB91` |

The metadata, the direct `0x0066AFCE -> 0x00B044A0` call reference, and the
checked record access at `0x00B142BE` were reconfirmed with the radare2 MCP on
2026-07-20. Existing generated analysis listed below remains supporting
evidence and was not changed.

## User-visible behavior and ownership

The public switch is:

```toml
[io]
parallel_enabled = true
```

It creates exactly two native `IOManager` workers, but does not expose both as
an unrestricted equal-priority drain pool. Worker zero remains the primary.
Worker one is a below-normal-priority supplemental worker, is selected only
while the primary is executing a task, and returns to the native wait path
after one task. There is intentionally no compatibility alias under `[lod]`:
configuration ownership moved rather than being duplicated. The
implementation is likewise owned by
`psycho-engine-fixes/src/mods/engine_fixes/io/`:

| File | Responsibility |
|---|---|
| `io/mod.rs` | Installs shared-state safety before enabling parallel scheduling and publishes subsystem status. |
| `io/scheduler.rs` | Owns worker construction, bounded admission and quantum, priority, per-thread map capacity, BSFile recovery, per-form cell-owner serialization, and the AutoWater build transaction. |
| `io/speedtree_lifetime.rs` | Serializes the two slow BSTree materializers, SpeedTree clone lifetime, and process-global Compute state while leaving published-tree lookup concurrent. |
| `io/vertex_buffers.rs` | Owns static vertex-buffer allocation, retirement, and publication safety. |
| `../model_postprocess.rs` | Independently serializes process-global EditorMarker traversal for vanilla and parallel I/O. |

`engine_fixes::install` installs IO safety before LOD. It passes the resulting
`SafetyStatus` to LOD because LOD prefetch uses the same engine paths. The LOD
scheduler now owns only native LOD task priority; it does not own the worker
topology or the shared-state guards.

## Stutter root cause and corrected scheduling contract

### Runtime observation

A tester reported new traversal stutter with Parallel IO enabled and reported
that allocator modes `0` and `1` made the FPS loss substantially worse.
Disabling Parallel IO removed the stutter. There is no supplied frame profile,
so no individual content pack or task body can be selected from runtime
evidence. The repository and executable nevertheless expose several
deterministic amplification mechanisms that existed for every workload:

- changing the constructor count to two did not define a second-worker
  admission policy, drain quantum, or OS priority;
- the IOManager selector slot still targeted `0x008D0560`, a vanilla
  `return 0` stub, so the count-only build did not prove that worker one ever
  received a task; its reported stutter remains a runtime correlation rather
  than evidence of two workers executing concurrently;
- once Psycho installed an explicit selector, unrestricted equal-priority
  draining would have allowed CPU-heavy construction to compete with the game
  and render threads, so admission, quantum, and priority all had to be
  bounded before real supplemental execution was enabled;
- every early-prefetched LOD task was raised to priority zero, allowing
  speculative terrain, object, and tree bursts to compete with visible work;
- safety locks were necessarily process-global, and the former exterior-cell
  boundary covered file reads and an entire cell rather than the exact
  conflicting per-form transaction;
- successful operations, lock contention, and wait duration were counted on
  heavily exercised paths.

These mechanisms define the hazards Psycho must cover, but they do not by
themselves prove the original tester's content-specific stutter source.
Allocator modes `0` and `1` retain more native engine-heap and scrap-heap
contention than mode `2`; that can amplify streamed-object cost, but allocator
correlation does not establish a scheduler or allocator defect. The bounded
selector is the first implementation that deliberately admits worker one, so
its safety contract must stand independently of the earlier report.

### Proven native scheduler path

New radare2 analysis of the executable identified the complete safe
intervention boundary:

| Address | Proven contract |
|---|---|
| `0x00C3DA50` | IOManager constructor. |
| `0x00C3DA7A` | Verified `push 1` worker-count immediate. |
| `0x00C3E4F0` | Base manager constructs workers and resumes each only after `0x00C3EE70` returns. |
| `0x00C3EE70` | Worker constructor; object `+0x04` is its Win32 handle, `+0x08` its thread ID, and `+0x30` its manager. Thread numbers two and three identify primary and supplemental workers. |
| `0x010C165C` | IOManager vtable worker-selector slot used by submission. |
| `0x008D0560` | Vanilla selector target returning zero. This is a shared generic stub and must not be hooked globally. |
| `0x00C3FB50` | Submission calls vtable `+0x58`; successful insertion then increments the queue count and signals `manager + 0x50[index]`. |
| `0x00C3FC80`, `0x00C3FCA0` | Manager task phases used to observe worker activity without replacing task execution. |
| `0x00C41302` | Post-task branch in the worker loop. Vanilla jumps to `0x00C41148` and continues draining; `0x00C41307` is cleanup/wait. |

Psycho patches only the IOManager vtable slot, not shared function
`0x008D0560`. The selector reserves worker one with an atomic
`idle -> reserved` transition only while worker zero is inside a task phase.
The submission wrapper returns a reservation to idle if native priority-queue
insertion fails. Phase hooks publish `running` and `idle`, and the post-task
branch sends the supplemental worker to cleanup/wait after one task. A
reservation made after phase two is preserved so an already-signaled next wake
is not lost.

The supplemental thread is set to Win32 below-normal priority while it is
still suspended. Around a process-global Psycho safety lock only, it is
temporarily restored to normal priority and restored by an RAII guard on exit.
This prevents a normal-priority engine thread from waiting behind a
deliberately backgrounded lock owner while keeping ordinary supplemental CPU
and allocation work in the background.

The policy is deliberately work-conserving only up to one supplemental task:
the primary retains vanilla ownership, the supplemental worker cannot be
double-selected, and a queue burst cannot turn one wake into an unbounded
second equal-priority drain loop.

## Atomic installation contract

Vanilla constructs the IOManager with one worker using `push 1` at
`0x00C3DA7A`. Psycho verifies those exact bytes and transactionally changes the
instruction to `push 2`.

The worker-count patch is committed only with all scheduler prerequisites:

| Address | Native owner | Required intervention |
|---|---|---|
| `0x0044C040` | LockFreeMap constructor family A | Expand per-thread capacity for the additional worker. |
| `0x0044C270` | LockFreeMap constructor family B | Expand per-thread capacity for the additional worker. |
| `0x00665CB0` | BSTree private LockFreeMap constructor | Expand capacity from two participating threads to three: main thread plus two workers. |
| `0x00AFF490` | BSFile open/cache initialization | Preserve an open stream and use native direct reads if optional whole-file cache allocation fails. |
| `0x00550500` | Per-form cell construction | Serialize the exact transaction that publishes and clears the process-global current-cell owner. |
| `0x0049C860` | BGSAutoWater cell build | Serialize teardown, initialization, geometry construction, and publication of both process-global AutoWater scratch owners. |
| `0x00C3EE70` | Worker construction | Capture native identity and establish supplemental priority before resume. |
| `0x00C3FB50` | IOManager submission | Release an unused supplemental reservation on queue-insertion failure. |
| `0x00C3FC80`, `0x00C3FCA0` | Task phases | Track primary activity and supplemental reservation state. |
| `0x010C165C` | IOManager selector slot | Install primary-first, single-owner supplemental admission. |
| `0x00C41302` | Worker post-task branch | Limit the supplemental worker to one task per wake. |
| `0x00C3DA7A` | IOManager worker-count immediate | Change the verified one-worker instruction to exactly two workers. |

The allocator-independent model postprocess guard at `0x0043AFAC` must also
report ready. Its process-global state is reachable with vanilla I/O as well
as two workers, so the guard always installs; readiness is only consumed here
to prevent the optional second worker from widening an unprotected window.
See `docs/model_postprocess_serialization_engine_fix.md`.

Both the IOManager singleton at `0x01202D98` and BSTreeManager singleton at
`0x011D5C48` must still be null before hook preparation and immediately before
commit. This guarantees that no manager was constructed with old per-thread
capacity. If ownership is already published or any prerequisite cannot be
installed, the transaction does not publish a partially safe two-worker
topology.

The feature does not remove tasks, tree loading, LOD categories, renderer
work, or the second worker. Proven non-thread-safe critical regions are made
safe while unrelated IO tasks remain parallel.

## Shared-state guards

### Per-thread LockFreeMap capacity

The native LockFreeMap families allocate fixed per-thread scratch slots during
construction. Adding a worker adds a participating thread; leaving the native
capacity unchanged previously caused registration failure and a later null
scratch-map dereference.

BSTree specifically has two native participants under the one-worker model:
the main thread and one worker. With two workers it needs exactly three. Psycho
increases the constructor-provided capacity by one without changing map value
layout, key semantics, or lookup behavior.

### BSFile cache allocation

The whole-file buffer created during `0x00AFF490` is an optimization, not the
ownership of the file stream. If allocation fails, Psycho clears buffer
capacity, fill, cursor, and pointer while retaining the native open flag and
`FILE*`. Subsequent reads take the existing raw-read path at `0x00AA1570`.

Successful cache allocation, short-read rejection, game-heap ownership, and
native cleanup stay intact. The failure path performs no logging or allocation
in the allocation context. This converts optional-cache OOM into slower IO,
not a missing task or process termination.

### Exterior-cell loading

The exterior loader reaches a process-global form owner at `0x011C3F30`.
`0x00550500` publishes the current cell there, performs construction, then
clears it. A consumer checks the global for null and reloads it later, so two
workers can interleave a clear between the check and use.

Psycho holds one reentrant lock only across original per-form transaction
`0x00550500`. Both known exterior-cell caller paths reach this function, and
the conflicting global is published and cleared inside it. File reads, task
setup, iteration between forms, task release, queue ownership, and completion
remain native and no longer occupy the lock. Reentrancy preserves nested
same-thread form construction.

### AutoWater cell construction

#### Runtime evidence

The 2026-07-27 exterior traversal stress run crashed after 12 minutes and
3 seconds in the Capital Wasteland with `C0000005` at `0x0049F24C`.
`psycho-engine-fixes/CrashLogger.log` recorded `EDX = 0`, an
`ExteriorCellLoaderTask` object in `EDI`, and this worker call chain:

```text
0x0049F24C
  <- 0x0049DC12
  <- 0x0049C902
  <- 0x00528768
  <- 0x00527CC9
  <- 0x00C3FC94
  <- psycho_engine_fixes
  <- 0x00C41257
  <- 0x00C42DBF
```

The corresponding engine-fixes log proves that the bounded selector,
supplemental quantum, two-worker count, and prior shared-state guards were
active. The crash report used 1.54 GiB of the 4 GiB virtual address space; the
engine log still reported 894 MiB total free and a 637 MiB largest free
region. This is not an OOM signature.

#### Proven native ownership and ABI

Radare2 analysis of the executable identity above proves:

- `0x0049F210` appends a 12-byte point copied from its sole stack argument.
  The faulting `mov eax, [edx]` at `0x0049F24C` dereferenced that null source.
- BGSAutoWater build child `0x0049DB60` obtains the source by loading global
  `0x011C57AC`, calling indexed accessor `0x006A7AF0`, and passing the result
  to `0x0049F210`. The crash return at `0x0049DC12` is immediately after that
  append.
- Outer function `0x0049C860` first destroys the existing
  `0x011C57AC` and `0x011C57B0` owners, then calls initialization
  `0x0049C930`, build `0x0049DB60`, and final publication/cleanup
  `0x0049E410`.
- Those three children are called only by `0x0049C860`. The only code owners
  of both globals are the outer function and those children.
- `0x0049C860` has exactly three direct callers at `0x00451C78`,
  `0x00528763`, and `0x005D3506`. The exterior-cell caller pushes the cell,
  calls it, and adds four to `ESP`; the function ends in plain `ret` at
  `0x0049C92E`. Its recovered ABI is therefore
  `unsafe extern "C" fn(cell: *mut c_void)`.

The dump does not preserve the peer thread at the exact interleaving, so its
identity is not a directly observed fact. The unprotected lifetime is proven,
however: one call can destroy or replace the process-global owner while
another call is between its accessor and point copy. That is the
high-confidence explanation for a valid native path producing a null point
at the exact copy. A malformed cell remains a fallback hypothesis only if the
same signature recurs after serialized transactions.

#### Safe intervention and cost

Psycho hooks the complete outer transaction at `0x0049C860` and holds a
process-wide `Mutex<()>` through the original call. Hooking the
faulting append or one child is insufficient because another caller could
replace the globals before or after that leaf. Hooking the complete
`ExteriorCellLoaderTask` is unnecessarily broad because it would serialize
file IO, form iteration, and unrelated cell work.

The AutoWater hook is enabled in the same all-or-nothing scheduler transaction
as the per-form owner guard, capacity hooks, selector, quantum, and two-worker
patch. The lock is non-reentrant because a nested build would destroy its
caller's live globals; the audited call graph contains no recursive owner
path. It is static and allocation-free. The supplemental worker is temporarily
raised to normal priority while holding it to avoid priority inversion. No
task is skipped, no water result is fabricated, and all three native callers
retain original behavior.

### Static vertex-buffer lifetime

`NiStaticGeometryGroup` allocation and retirement share an unprotected block
map, free list, chip pool, accounting, and Direct3D buffer ownership. Terrain
worker execution can reach renderer prepacking, which makes this state unsafe
under two workers.

The IO subsystem therefore owns these interventions:

| Address | Contract |
|---|---|
| `0x00E8BFA0` | Attempt the outer geometry-stream allocation/publication transaction; return retryable failure immediately when another transaction owns the lock. |
| `0x00E94C20` | Serialize direct static allocation and make null Direct3D-buffer creation unwind safely. |
| `0x00E94770` | Serialize direct retirement under the same reentrant lock. |
| `0x00E8EEB0` | Restore native all-stream chip validation at six audited call sites. |

A non-null chip whose Direct3D pointer at chip `+0x08` is null is never
published as success. The outer caller already treats false as deferred-pack
retry, so lock contention returns through that native retry boundary instead
of blocking a render-side caller. Direct allocation and retirement retain the
blocking lock because they have no independently proven deferral contract.
Both workers and every geometry category remain enabled.

### SpeedTree clone ownership

SpeedTree clone construction at `0x00B036D0` and scalar destruction at
`0x00666910` mutate an owner vector and shared reference count. The native
registry critical section at `0x011F8BC4` is borrowed for the complete
constructor/destructor transaction. Before destructive mutation, Psycho
validates allocation state, owner-vector bounds, membership uniqueness,
pointer freshness, and reference count.

Relevant recovered offsets are:

| Structure | Offset | Meaning |
|---|---:|---|
| SpeedTree core | `+0x30` | Shared reference count. |
| SpeedTree core | `+0x34` | Clone payload. |
| SpeedTree core | `+0x38` | Clone owner pointer. |
| Owner | `+0x0C` | Clone-vector begin. |
| Owner | `+0x10` | Clone-vector end. |
| Owner | `+0x14` | Clone-vector capacity. |

These guards close lifetime races between worker-side clone creation and
main-thread completed-task destruction. They do not, by themselves, protect
SpeedTreeRT's separate process-global Compute scratch state.

### Demand-aware LOD priority

Native LOD task constructors at `0x006F6D10`, `0x006F9360`, and
`0x006FB980` receive their owning object, tree, or terrain block as argument
one. Static analysis proves the demand-node pointer at object block `+0x00`,
tree block `+0x44`, and terrain block `+0x00`.

The demand hooks record only unloaded nodes admitted by Psycho's extended
prefetch radius in a fixed 4,096-slot, allocation-free atomic table. Native
visible demand clears a stale mark. A task constructor consumes a matching
mark once: speculative work retains its native priority, while unmarked
visible work and its dependencies use native priority zero. Leaving the
extended range or resetting the worldspace clears provenance.

The table probes at most 32 slots. Collision or capacity failure deliberately
fails visible-safe: the eventual task receives priority zero rather than being
lost or delayed. This avoids speculative priority-zero bursts without
changing demand, task classes, dependencies, queue ownership, or publication.

## Save-load crash: SpeedTree Compute

### Runtime observation

The autosave load crashed after 72 seconds in `ArefuExterior`, Wasteland, with
exception `C0000417`. CrashLogger recorded:

- instruction pointer `0x00EC7C62`;
- raw stack return `0x00B142E7`;
- call trace `0x00B13ED7 -> 0x00B134BE -> 0x00B124DA -> 0x00B1263E`;
- `EBX` resolving to `BSTaskManagerThread<__int64>` RTTI;
- virtual memory use of only 1.05 GiB out of 4.00 GiB.

The same run's engine-fixes log proved that two IO workers, BSTree capacity,
BSFile recovery, exterior-cell serialization, clone lifetime protection, and
static vertex-buffer safety were installed. This signature is not an OOM
failure and is not the prior BSTree null-slot or vertex-buffer crash.

### Proven native path

The worker path is:

```text
BSTaskManagerThread
  -> queued tree task 0x0043DA00
  -> BSTreeManager find/load 0x00664F50
  -> BSTree reload/replacement 0x0066AC40
  -> SpeedTreeRT Compute 0x00B044A0
  -> 0x00B2AF80
  -> 0x00B11050
  -> 0x00B13100
  -> 0x00B13C10
  -> checked record access 0x00B14280
  -> CRT invalid-parameter wrapper 0x00EC7C56
```

Radare2 finds one direct caller of Compute: the call at `0x0066AFCE` inside
`0x0066AC40`. Compute's recovered ABI is:

```rust
unsafe extern "thiscall" fn(
    this: *mut c_void,
    transform: *const c_void,
    seed: u32,
    final_pass: u8,
) -> u8
```

`0x00B2AF80`, called by Compute at `0x00B0452F`, publishes the active model's
record owner through process-global `0x011F8BF4`. Downstream routines also use
global scratch vectors at `0x011F8C24/0x011F8C28` and
`0x011F8C74/0x011F8C78`.

At `0x00B142BE`, the checked accessor reloads `0x011F8BF4`. It derives the
record count as:

```text
record_count = (owner[+0x20] - owner[+0x1C]) / 0x54
```

It compares the supplied index to that count at `0x00B142DD`. An out-of-range
index calls `0x00EC7C56` at `0x00B142E2`; the successful branch resumes at the
crash log's raw return address `0x00B142E7`. The exception is therefore the
engine's checked-container invalid-parameter path, not an arbitrary top-frame
guess.

### Root-cause conclusion

The following facts are directly proven:

- the failing thread is an IO worker processing a queued tree load;
- the failure is a `0x54`-stride SpeedTree record bounds check;
- Compute publishes and repeatedly consumes process-global model and scratch
  state;
- the two-worker extension permits two independent tree Compute calls;
- the pre-crash clone registry guard does not cover this Compute state.

The crash dump does not contain the second worker's simultaneous stack, so the
exact instruction interleaving is an inference. The high-confidence failure
model is that worker A derives an index from model A, worker B replaces the
global active model/scratch state with model B, and worker A validates its
index against model B's record table. That explains a valid local index
reaching the exact native invalid-parameter check immediately after two-worker
tree loading became possible.

If the identical bounds failure occurs while Compute transactions are proven
serialized, malformed tree input becomes the next hypothesis. It is not
supported by the current runtime evidence and must not be used to weaken or
disable parallel IO.

### Safe intervention

Psycho hooks the complete `0x00B044A0` Compute function and holds a process-wide
`parking_lot::ReentrantMutex<()>` while calling the original trampoline. The
lock begins before any model/scratch publication and ends only after the
original returns, so every global read and write in one Compute transaction is
atomic with respect to the other worker.

The mutex is reentrant because a tree materializer has nested clone and Compute
calls and must not self-deadlock. It is created once, performs no
routine allocation, and is not taken from a render callback. Independent
file, terrain, object, and cell tasks can still run on the other worker.

The clone-model materializer, reload-model materializer, Compute,
clone-construction, and scalar-destruction hooks are enabled in one SpeedTree
modification transaction and reuse the same reentrant lock. IOManager is
changed to two workers only after both SpeedTree and static vertex-buffer
safety report ready. This preserves the feature and fixes its shared-state
contract; rejected approaches include using one worker, disabling tree or LOD
tasks, swallowing the invalid-parameter exception, or clamping an index after
the global model has already changed.

## Infinite save-load report and materialization-boundary hardening

### Runtime evidence

`.reports/psycho-engine-fixes-latest--not-loading.log` is a non-crashing hang
from commit `ff22c1ec9a2130004b9aeb78dc6c689011986f17`. That build predates
commit `b16a430d428cf1ede9e175931561b9c31653915f`, which added the SpeedTreeRT
Compute guard. Its startup evidence is decisive:

- line 186 reports only clone-lifetime serialization;
- line 211 enables exactly two IO workers;
- line 471 first reports the main thread stalled in
  `changed-form-owner-enter` with ModelLoader state `5` and 4,491 accepted
  state-0 tasks;
- line 494 shows all but five tasks retired ten seconds later;
- line 628 still shows the same five tasks after 152 seconds, with
  `drain_complete=0` and no completion callback active;
- line 632 still reports 1.155 GiB free virtual address space and a 960 MiB
  largest free region.

These observations directly prove a native ModelLoader drain stall, not a
crash, display failure, post-load loop, or OOM. Existing binary analysis proves
the main-thread chain:

```text
changed-form owner 0x00847DF0
  -> load finalization 0x008492B0
  -> wrapper 0x00456520 (mode 5)
  -> blocking ModelLoader drain 0x00C3DFA0
```

`0x00C3DFA0` loops until the selected queue count, active count, external
count, and completion processing all report quiescence. The unchanged count
of five therefore means accepted native tasks failed to retire; clearing that
count or forcing the loop to exit would violate native task ownership and can
publish incomplete save state.

The old log has no per-task vtables or worker stacks, so it cannot directly
identify which of the five task bodies stopped. The underlying attribution to
concurrent SpeedTree loading is a high-confidence inference, not a fact from
the log alone: the affected build enabled two workers while guarding clone
lifetime only; a later crash from the same topology proved unguarded
process-global Compute state; and tree find/load is reachable on both workers
and the main completion path.

### July 22 old-build abrupt termination

`.reports/psycho-engine-fixes-latest--unknown_crash.log` does not support the
tester's description of a literal startup crash. It reports commit metadata
`cf806c95b2fa8e13b82a4d88c5d327fce46139f0` and establishes this timeline:

- line 259 completes Psycho initialization;
- line 403 publishes `Game engine ready` after about 46 seconds;
- lines 480-481 show a later top-level save load in
  `changed-form-owner-enter`, with ModelLoader state `5` and 4,723 accepted
  tasks;
- lines 507-508 show state `6`, zero active tasks, and
  `drain_complete=1` ten seconds later;
- line 517 is emitted only after the original changed-form owner returns and
  reports one locally skipped record for unavailable content;
- the final sample at line 522 still has 996 MiB free process VAS and an
  856 MiB largest hole.

There is no Psycho error, allocation failure, exception address, worker stack,
or shutdown marker. The abrupt end therefore does not by itself prove whether
the process crashed, was killed, or exited. It does prove that initialization
succeeded, ordinary frames ran, the ModelLoader drain completed, and execution
reached the remainder of the top-level load. The contained ExtraOwnership, LOD
stale-publication, linked-reference, and unavailable-content reports identify
invalid or stale inputs but none records a terminal failure.

The startup line at 187 says only `SpeedTree Compute and clone lifetime
serialized`. That deployed contract predates the slow-materializer boundary
described below. An interleaving elsewhere in BSTree clone/reload
materialization is consequently the leading repository-local candidate because
the exact topology and omitted boundary are proven, but the supplied log cannot
attribute the terminal instruction to it. The remaining evidence window also
includes the native calls after changed-form return inside `0x00850760` and the
successful-load reconciliation prepass; neither can be selected without an
exception context or newer phase telemetry.

This old-build report is not evidence of a current regression. A valid retest
must use a build whose startup log contains the current `BSTree materialization`
contract below. Preserve the exact save and cosave. On recurrence, retain the
Psycho log plus CrashLogger output or a minidump. Historical `[HANG_LOAD]`
transaction counters were useful during contract discovery but were removed
from release hot paths by the 2026-07-27 scheduling correction.

### Native lookup and materialization boundary

Radare2 reconfirmed that `0x00664F50` has exactly two direct callers:

- queued tree execution at `0x0043DA00`, call site `0x0043DA59`;
- main-thread QueuedReference completion at `0x0050F810`, call site
  `0x0050F856`.

The `__thiscall` owner takes the manager in `ECX`, an optional existing model,
and the requesting reference. Radare2 proves that it first performs a published
model lookup: the successful branch at `0x00665046` retrieves the model and
returns through `0x00665083`. That path does not enter either slow
materializer. Only a miss continues to the sole direct calls of clone-model
materialization at `0x00665152 -> 0x0066A650` or file/reload materialization at
`0x006651C8 -> 0x0066AC40`. The latter is the sole owner of the proven
`0x0066AFCE -> 0x00B044A0` Compute call.

The first whole-transaction implementation locked `0x00664F50`. A deployed
playtest then reproduced a severe location-dependent FPS regression: a
main-thread published-tree lookup could wait behind a worker doing slow tree
file/model construction. That runtime result invalidated the broad scope as an
acceptable performance contract. It did not invalidate the proven need to
serialize materialization, Compute, and clone lifetime.

Psycho now hooks both slow materializers, `0x0066A650` and `0x0066AC40`, and
holds the shared reentrant transaction lock across each complete original
call. The inner Compute, clone, and scalar-destructor hooks take the same lock,
so nested calls are reentrant and direct leaf calls remain protected. The
lookup/cache-hit prefix and per-reference finalization after materialization no
longer take that lock. Failure to prepare or enable any of the five hooks
leaves SpeedTree safety unavailable, so the scheduler retains the native
one-worker topology. Raw address, xref, branch, and ABI evidence is recorded in
`analysis/radare2/output/perf/speedtree_find_load_lock_scope_audit.txt`.

This hardening does not add cancellation or a timeout. No safe generic
recovery exists once an opaque engine task is executing: retiring it early can
cause UAF, double completion, or partial save publication. The 2026-07-27
correction also removes routine IO and LOD demand totals, transaction,
contention, waiter, and timing updates from these hot hooks. Existing helper
ABI fields remain reserved and read as zero. Rare corruption rejects and
installation failures remain counted because they are not normal-path work.

### Safety and cost balance

- UAF protection is preserved: clone/reload materialization, clone-vector
  construction/destruction, and Compute cannot interleave across two workers
  or main-thread completion. Existing corrupt-object rejection remains
  unchanged.
- OOM behavior is unchanged. Locks and admission state are static and
  allocation-free; no allocation, retention, or cleanup edge was added to
  gheap.
- Published-tree lookup and per-reference finalization remain concurrent.
  Clone/reload materialization stays serialized because it reaches the proven
  process-global Compute and shared lifetime state. The supplemental worker is
  temporarily normal priority while it owns this lock, preventing a
  normal-priority waiter from suffering priority inversion. Routine protected
  operations perform no counters, timers, logging, or file IO.

## Diagnostics

Startup must include lines equivalent to:

```text
[IO] BSTree materialization, SpeedTree Compute, and clone lifetime serialized; cache-hit lookup remains concurrent; native registry lock 0x011F8BC4
[IO] Bounded two-worker IOManager armed: primary-first selection, one-task supplemental quantum, below-normal supplemental priority, per-form cell-owner and AutoWater transaction serialization, three-thread BSTree TLS, and BSFile cache fallback
[LOD] Demand-aware task priority installed: visible=0, Psycho-only speculative=native
[IO] Active parallel=true speedtree=true vertex_buffers=true model_postprocess=true
```

The helper dashboard's Runtime Fixes page exposes the observed native worker
count, bounded scheduling policy, rare fallback counts, current LOD ownership
state, and guard installation. It intentionally does not sample routine LOD
demand, successful cell, materialization, Compute, lock, or wait operations.
The corresponding fields remain in dashboard ABI version 3 for binary
compatibility and return zero. See `docs/psycho_dashboard.md` for the UI/ABI
contract.

## Static validation

The implementation was validated on the supported target with:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes -p libpsycho -p psycho-engine-fixes-helper --lib
cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes -p psycho-engine-fixes-helper
cargo fmt -p libpsycho -p psycho-engine-fixes -p psycho-engine-fixes-helper -- --check
git diff --check
```

The concurrency regressions prove that two Compute operations and two
AutoWater build transactions cannot overlap, an independent Compute blocks
behind a tree materializer, and nested SpeedTree hooks preserve the
materialization scope without self-deadlocking. Scheduler tests also prove
single-owner supplemental reservation and exact control-flow patch targets.
LOD tests prove one-shot speculative provenance, category separation,
visible-demand cancellation, and worldspace reset. Configuration tests prove
`[io].parallel_enabled` ownership and the enabled default without retaining
the removed LOD key.

Compilation and unit synchronization prove ABI type-checking, hook wiring, and
mutual exclusion. They do not prove that the complete game workload is fixed.

## Runtime acceptance

1. Start a fresh process and require all startup lines above, exactly two
   observed workers, primary and supplemental readiness, and no
   hook-installation or priority failure.
2. Load the exact autosave that produced the 2026-07-20 crash, then repeat save
   loads and exterior traversal beyond the prior 72-second failure window.
3. Require IO queues to continue draining after loading, with no permanent
   ModelLoader wait and no repeated priority-guard warning.
4. Require no `C0000417` at `0x00EC7C62`, no `0x00B142E7` checked-record
   signature, and no recurrence of the earlier BSTree, exterior-owner, clone,
   or static vertex-buffer signatures.
5. Require terrain, objects, and trees to remain visible and publish normally.
   Missing content, a worker-count reduction, or disabled work is a failure.
6. Repeat under allocator modes `0`, `1`, and `2`; Compute serialization and
   native IO ownership must not depend on allocator mode.
7. At the reported tree-heavy regression location, compare a warm stationary
   view and a repeatable traversal against the prior unrestricted two-worker
   build. Require recovery of sustained FPS and frame pacing without reducing
   the two-worker count or hiding trees.
8. During rapid movement, require immediately visible LOD to publish ahead of
   Psycho-only speculative prefetch. A missing LOD category, a supplemental
   worker draining continuously without returning to wait, or a visible load
   delayed behind speculative work is a failure.
9. Repeat the Capital Wasteland exterior stress route beyond 12 minutes and
   3 seconds. Require no `0x0049F24C <- 0x0049DC12` AutoWater point-copy
   crash, while exterior water continues to construct and render normally.

## Evidence and reuse index

Primary implementation:

- `psycho-engine-fixes/src/mods/engine_fixes/io/mod.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/io/scheduler.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/io/speedtree_lifetime.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/io/vertex_buffers.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/statics.rs`
- `psycho-engine-fixes/src/config.rs`
- `psycho-engine-fixes/config/psycho_engine_fixes.toml`

Runtime evidence:

- `psycho-engine-fixes/CrashLogger.log` (2026-07-27 AutoWater stress crash)
- `psycho-engine-fixes/psycho-engine-fixes-latest.log` (matching runtime state)
- `.reports/CrashLogger-2026-07-20-191755.log`
- `.reports/psycho-engine-fixes-2026-07-20-191754.log`
- `.reports/psycho-engine-fixes-latest--not-loading.log`

Existing generated engine evidence, retained unchanged:

- `analysis/ghidra/output/crash/lod_save_load_c0000417_origin_and_coverage_audit.txt`
- `analysis/ghidra/output/crash/lod_bstree_tls_slot_exhaustion_root_cause_audit.txt`
- `analysis/ghidra/output/crash/bstree_speedtree_owner_registration_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_exterior_cell_multiworker_null_owner_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_landlod_vertex_buffer_lifetime_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_vertex_buffer_geometry_group_allocation_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_allocation_failure_final_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_creation_leaf_retry_audit.txt`
- `analysis/ghidra/output/crash/save_missing_content_root_cause_audit.txt`
- `analysis/ghidra/output/crash/model_loader_pending_ownership_audit.txt`
- `analysis/ghidra/output/crash/save_to_same_save_hang_contract_audit.txt`
- `analysis/ghidra/output/crash/lod_bstree_tls_slot_exhaustion_root_cause_audit.txt`
- `analysis/ghidra/output/perf/startup_loading_pipeline_deep_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_portable_light_classification_audit.txt`

Current radare2 lock-scope evidence:

- `analysis/radare2/output/perf/speedtree_find_load_lock_scope_audit.txt`

Related feature history and earlier contracts:

- `docs/lod_streaming_handoff_engine_fix_plan.md`

Future work involving `IOManager`, `BSTaskManagerThread`, BSFile,
`BSTreeManager`, SpeedTreeRT Compute, exterior cell parsing, terrain prepacking,
or static vertex-buffer ownership should start here. Reconfirm the executable
identity before reusing an address; if it differs, use radare2 MCP xrefs and
call-graph evidence to port the contract rather than copying addresses.
