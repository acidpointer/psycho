# Native parallel IO and SpeedTree engine contract

Status: implemented and statically validated on 2026-07-20; post-fix runtime
playtest is still required.

This document is the durable contract for Psycho's native IOManager
parallelism. It owns the two-worker scheduler extension and every shared-state
guard required to keep that extension safe. LOD is one consumer of native IO,
but parallel IO is not an LOD feature and does not belong to the LOD module or
configuration section.

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

It uses exactly two native `IOManager` workers. There is intentionally no
compatibility alias under `[lod]`: configuration ownership moved rather than
being duplicated. The implementation is likewise owned by
`psycho-engine-fixes/src/mods/engine_fixes/io/`:

| File | Responsibility |
|---|---|
| `io/mod.rs` | Installs shared-state safety before enabling parallel scheduling and publishes subsystem status. |
| `io/scheduler.rs` | Owns worker count, per-thread map capacity, BSFile recovery, and exterior-cell serialization. |
| `io/speedtree_lifetime.rs` | Owns SpeedTree clone lifetime and Compute transaction serialization. |
| `io/vertex_buffers.rs` | Owns static vertex-buffer allocation, retirement, and publication safety. |

`engine_fixes::install` installs IO safety before LOD. It passes the resulting
`SafetyStatus` to LOD because LOD prefetch uses the same engine paths. The LOD
scheduler now owns only native LOD task priority; it does not own the worker
topology or the shared-state guards.

## Two-worker installation contract

Vanilla constructs the IOManager with one worker using `push 1` at
`0x00C3DA7A`. Psycho verifies those exact bytes and transactionally changes the
instruction to `push 2`.

The two-worker patch is committed only with all scheduler prerequisites:

| Address | Native owner | Required intervention |
|---|---|---|
| `0x0044C040` | LockFreeMap constructor family A | Expand per-thread capacity for the additional worker. |
| `0x0044C270` | LockFreeMap constructor family B | Expand per-thread capacity for the additional worker. |
| `0x00665CB0` | BSTree private LockFreeMap constructor | Expand capacity from two participating threads to three: main thread plus two workers. |
| `0x00AFF490` | BSFile open/cache initialization | Preserve an open stream and use native direct reads if optional whole-file cache allocation fails. |
| `0x00527CB0` | `ExteriorCellLoaderTask::execute` | Serialize the complete original method because it publishes through a process-global current-cell owner. |
| `0x00C3DA7A` | IOManager worker-count immediate | Change the verified one-worker instruction to exactly two workers. |

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

Psycho holds one blocking worker mutex across the complete original
`ExteriorCellLoaderTask::execute` at `0x00527CB0`. The task payload, native
release, queue ownership, and completion remain native. Exterior form parsing
retains vanilla concurrency of one while the other worker may execute safe
task classes.

### Static vertex-buffer lifetime

`NiStaticGeometryGroup` allocation and retirement share an unprotected block
map, free list, chip pool, accounting, and Direct3D buffer ownership. Terrain
worker execution can reach renderer prepacking, which makes this state unsafe
under two workers.

The IO subsystem therefore owns these interventions:

| Address | Contract |
|---|---|
| `0x00E8BFA0` | Serialize the outer geometry-stream allocation/publication transaction. |
| `0x00E94C20` | Serialize direct static allocation and make null Direct3D-buffer creation unwind safely. |
| `0x00E94770` | Serialize direct retirement under the same reentrant lock. |
| `0x00E8EEB0` | Restore native all-stream chip validation at six audited call sites. |

A non-null chip whose Direct3D pointer at chip `+0x08` is null is never
published as success. Allocation failure remains retryable through the native
deferred-pack path. Both workers and every geometry category remain enabled.

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

The mutex is reentrant because Compute owns a large third-party call graph and
future or indirect same-thread reentry must not self-deadlock. It is created
once, performs no routine allocation, and blocks only worker-side tree Compute;
it is not taken from a render callback. Independent file, terrain, object,
cell, and non-Compute tree tasks can still run on the other worker.

The Compute hook is enabled in the same SpeedTree transaction as clone
construction and destruction. IOManager is changed to two workers only after
both SpeedTree and static vertex-buffer safety report ready. This preserves
the feature and fixes its shared-state contract; rejected approaches include
using one worker, disabling tree or LOD tasks, swallowing the invalid-parameter
exception, or clamping an index after the global model has already changed.

## Diagnostics

Startup must include lines equivalent to:

```text
[IO] SpeedTree Compute and clone lifetime serialized; native registry lock 0x011F8BC4
[IO] Native IOManager configured for exactly two workers with serialized exterior-cell loading, three-thread BSTree TLS, and BSFile cache fallback
[IO] Active parallel=true speedtree=true vertex_buffers=true
```

`PsychoInfo` exposes scheduler, cache, cell-loader, SpeedTree, and vertex-buffer
state. The SpeedTree fields include total Compute transactions, contended
entries, and maximum lock wait. Contention is expected under simultaneous tree
loads; failures, missing publication, or permanent queue stalls are not.

## Static validation

The implementation was validated on the supported target with:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib
cargo build --release --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo fmt --all -- --check
git diff --check
```

The library suite passed all three tests. It includes the regression
`compute_transactions_cannot_overlap_across_workers`, which drives two worker
threads into the guard and proves that the protected operation never overlaps.
Configuration tests prove `[io].parallel_enabled` ownership and the enabled
default without retaining the removed LOD key.

Compilation and unit synchronization prove ABI type-checking, hook wiring, and
mutual exclusion. They do not prove that the complete game workload is fixed.

## Runtime acceptance

1. Start a fresh process and require all three IO startup lines above, exactly
   two observed workers, and no hook-installation failure.
2. Load the exact autosave that produced the 2026-07-20 crash, then repeat save
   loads and exterior traversal beyond the prior 72-second failure window.
3. Require rising Compute transaction counts. Contention may rise; maximum wait
   must remain bounded and IO queues must continue draining.
4. Require no `C0000417` at `0x00EC7C62`, no `0x00B142E7` checked-record
   signature, and no recurrence of the earlier BSTree, exterior-owner, clone,
   or static vertex-buffer signatures.
5. Require terrain, objects, and trees to remain visible and publish normally.
   Missing content, a worker-count reduction, or disabled work is a failure.
6. Repeat under allocator modes `0`, `1`, and `2`; Compute serialization and
   native IO ownership must not depend on allocator mode.

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

- `.reports/CrashLogger-2026-07-20-191755.log`
- `.reports/psycho-engine-fixes-2026-07-20-191754.log`

Existing generated engine evidence, retained unchanged:

- `analysis/ghidra/output/crash/lod_save_load_c0000417_origin_and_coverage_audit.txt`
- `analysis/ghidra/output/crash/lod_bstree_tls_slot_exhaustion_root_cause_audit.txt`
- `analysis/ghidra/output/crash/bstree_speedtree_owner_registration_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_exterior_cell_multiworker_null_owner_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_landlod_vertex_buffer_lifetime_crash_audit.txt`
- `analysis/ghidra/output/crash/lod_vertex_buffer_geometry_group_allocation_followup_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_allocation_failure_final_audit.txt`
- `analysis/ghidra/output/crash/lod_static_vertex_buffer_creation_leaf_retry_audit.txt`
- `analysis/ghidra/output/perf/graphics_fnv_close_terrain_portable_light_classification_audit.txt`

Related feature history and earlier contracts:

- `docs/lod_streaming_handoff_engine_fix_plan.md`

Future work involving `IOManager`, `BSTaskManagerThread`, BSFile,
`BSTreeManager`, SpeedTreeRT Compute, exterior cell parsing, terrain prepacking,
or static vertex-buffer ownership should start here. Reconfirm the executable
identity before reusing an address; if it differs, use radare2 MCP xrefs and
call-graph evidence to port the contract rather than copying addresses.
