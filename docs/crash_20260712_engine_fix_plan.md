# 2026-07-12 crash engine-fix change set

> **Historical plan:** the version-bound LowProcess restoration and
> function-entry task-release ownership described here are superseded by
> [crash_20260712_mod_independent_revision_plan.md](crash_20260712_mod_independent_revision_plan.md).
> The mod-independent revision is the implemented compatibility design.

## Goal

Ship two independent, allocator-agnostic engine fixes in
`psycho-engine-fixes`:

1. Repair Stewie Tweaks 9.90/9.95's invalid ownership handling for
   `LowProcess::genericLocationsList` and contain already-corrupt list entries
   during save.
2. Prevent the main task-queue consumer from dispatching an object whose
   intrusive reference has already reached zero, while preserving normal queue
   ownership and callback behavior.

The xNVSE helper remains optional. It may request the late check through
`DeferredInit`, but it must not install, own, or initialize either fix.

## Implementation status

Implemented in `psycho-engine-fixes` on 2026-07-12:

- byte-verified LowProcess save containment;
- late audited Stewie 9.90/9.95 four-slot restoration;
- allocator-independent queued-task release guard;
- positive-only CAS dispatch pin and callback validation;
- optional fixed-ring lifetime provenance with caller capture;
- legacy config migration and allocator-independent `PsychoInfo` reporting.

The supported i686 release build passes. Runtime game validation remains
required for the compatibility and stress matrix below.

## Evidence baseline

### LowProcess crash

- The crash at `0x00865DFB` receives `TESForm* = 0x0000000D` from the list walk
  in `FUN_00910450`.
- The direct list-element `AppendRefID` call is at `0x009105BF`; the serialized
  list is `LowProcess + 0x6C`.
- Stewie Tweaks 9.90 and 9.95 install `LowProcess__Func011F` into four process
  vtables. The relevant source body and four writes are unchanged in 9.95. Its
  `genericLocationsList` branch still frees `gIter->data` before removing the
  node.
- The 9.95 `bSaveLoad` `SaveLoadFormBuffer__AppendRefID` replacement is also
  unchanged from 9.90. It accepts NULL but still dereferences every non-NULL
  pointer at `form + 0x0C`, so it does not contain an already-corrupt list.
- Ghidra proves all four vanilla slots point to `FUN_0090CC10`. Vanilla removes
  the list node without freeing its non-owned `TESObjectREFR` payload.

### Queued-task crash

- The crash is the indirect call at `0x00446C53` with task
  `0xBB7CF740`, base `NiRefObject` vtable `0x0101DCE4`, and refcount zero.
- `FUN_00906570` transfers an owned queue reference into the consumer's local
  holder. Both pop paths retain through `FUN_0092C820`/`FUN_0092C870`.
- The consumer releases that holder after dispatch through the call at
  `0x00446C5C`.
- Therefore the observed zero-refcount object violates the queue lifetime
  contract. It is not a legitimate unowned dequeue.

## Public configuration

Add these default-on settings to `[engine_fixes]`:

```toml
lowprocess_generic_locations_fix = true
queued_task_lifetime_guard = true
```

Add this default-off setting to `[diagnostics]`:

```toml
task_lifetime_trace = false
```

Configuration migration rules:

1. A present `engine_fixes.queued_task_lifetime_guard` is authoritative.
2. Otherwise accept `memory.gheap_task_safety`.
3. Otherwise accept the older `memory.gheap_task_release_guard` alias.
4. Otherwise default the new engine-fix setting to `true`.
5. Stop serializing `gheap_task_safety` as an active `MemoryConfig` field. Keep
   both old names only in `RawMemoryConfig` for read compatibility.

This migration is resolved once during deserialization. Hot task paths must not
query global configuration.

## Runtime patch manifest

Keep every address and expected byte sequence together in
`engine_fixes/statics.rs`. Each patch must validate the complete affected
instruction or pointer range before writing.

| Contract | Address | Exact expected bytes/state | Replacement |
|---|---:|---|---|
| LowProcess vtable slots | `0x01087CE0`, `0x01088B60`, `0x010894C8`, `0x0108A048` | all vanilla `0x0090CC10`, or all one verified Stewie target | vanilla `0x0090CC10` only for the verified Stewie case |
| Generic-location save call | `0x009105BF` | `E8 2C 58 F5 FF`, resolving to `0x00865DF0` | `E8 <checked-writer rel32>` |
| Main-loop late boundary | `0x0094CFD6` | `E8 75 9B AF FF`, resolving to `0x00446B50` | `E8 <late-drain-wrapper rel32>` |
| Task virtual dispatch block | `0x00446C48..0x00446C55` | `8B 55 C8 8B 02 8B 4D C8 8B 50 1C FF D2` | `8B 4D C8 E8 <checked-dispatch rel32> 90 90 90 90 90` |
| General task release | `0x0044DD60` | prologue prefix `55 8B EC 83 EC 14 89 4D F0 8B 45 F0 83 C0 08 50 E8 2B 3C FB FF 83 C4 04` | existing inline release hook, moved to engine-fix ownership |

The implementation must record the exact byte arrays in source rather than
checking only an opcode or call destination. Use one helper that compares,
writes under `with_virtual_protect`, flushes the instruction cache, and returns
a contextual error. Add the helper to `libpsycho` only if its current
`patch_bytes`/`replace_call` wrappers cannot perform compare-before-write as one
operation.

### Verified patch gate

`crash_20260712_patch_manifest_audit.txt` closes the FalloutNV.exe byte gate for
the supported x86 `1.4.0.525` program. It also confirms the four vanilla
vtable pointers and records this 64-byte prefix for `FUN_0090CC10`:

```text
55 8B EC 83 EC 3C 89 4D D0 8B 45 D0 83 78 64 00
74 42 8B 4D D0 8B 51 64 8B 02 3B 45 08 75 35 8B
4D D0 8B 51 64 89 55 E4 8B 45 E4 89 45 E8 83 7D
E8 00 74 0F 6A 01 8B 4D E8 E8 52 73 EA FF 89 45
```

The LowProcess repair does not require disassembly or a function-byte signature
of the Stewie DLL. The checked-in Stewie Tweaks 9.90 and 9.95 sources prove that
`bProcess` writes one `LowProcess__Func011F` pointer to all four slots and prove
the invalid `GameHeapFree(gIter->data)` operation. The original crash log
identifies `nvse_stewie_tweaks.dll` version 990. The currently installed mod
metadata and readme identify 9.95, and its active INI still has `bProcess=1` and
`bSaveLoad=1`.

The core DLL does not depend on xNVSE and therefore must not query xNVSE's
plugin-version API. Match only source-audited builds through their loaded PE
headers:

| Build | Machine/magic | COFF timestamp | Image size | Entry RVA | File provenance |
|---|---|---:|---:|---:|---|
| 9.90 | i386/PE32 (`0x014C`/`0x010B`) | `0x6A085032` | `0x0010B000` | `0x0008AC61` | 1,052,160 bytes; SHA-256 `e16081a18897cb742cc31c4a107d2fa3c0128029694de63ebcae780fbbea412d` |
| 9.95 | i386/PE32 (`0x014C`/`0x010B`) | `0x6A48E1EC` | `0x0010E000` | `0x0008D0C1` | 1,062,400 bytes; SHA-256 `2cff504c43f41b6228de65d84f09f7434e7d726b04970802aaf15860fb6ec703` |

File sizes and hashes are release provenance only. Runtime matching reads the
already-loaded PE header and does not hash or reopen the DLL.

Automatic restoration therefore requires all of these runtime facts:

1. All four slots contain the same non-vanilla pointer.
2. `virtual_query` places that pointer inside the loaded
   `nvse_stewie_tweaks.dll` image.
3. The loaded image matches one of the audited PE-header fingerprints above.
4. All four slots still contain that pointer immediately before writing.

This identifies the exact source-backed replacement without depending on a
compiler-specific function byte sequence. Mixed slots, another module, another
version, or a changing pointer are unknown replacements and remain untouched.
Save containment remains independent.

## Change 1: LowProcess ownership repair

### New module

Add `psycho-engine-fixes/src/mods/engine_fixes/lowprocess.rs` with three
separate responsibilities:

- install the save-call containment patch;
- observe and repair the four LowProcess vtable slots at a late boundary;
- expose counters and a compact status snapshot.

Do not reproduce Stewie's cleanup function in Rust. The correct implementation
already exists in FalloutNV.exe at `0x0090CC10`.

### Late vtable repair state machine

Use an atomic state with explicit terminal results:

- `Waiting`
- `Vanilla`
- `RepairedKnownStewie`
- `UnsupportedReplacement`
- `Disabled`

At core startup, record the four observed values for diagnostics only. Do not
derive the vanilla target from that snapshot; startup ordering against other
early DLLs is not a correctness contract.

`ensure_late_repair()` performs this sequence:

1. Return immediately for a terminal state.
2. Read all four slots with unaligned-safe 32-bit loads.
3. If all four equal `0x0090CC10`, mark `Vanilla`.
4. If the values are mixed, mark `UnsupportedReplacement` and change nothing.
5. If all four share one non-vanilla target:
   - resolve the allocation base and module name through `virtual_query` and
     the `libpsycho` module wrappers;
   - require `nvse_stewie_tweaks.dll`;
   - require one of the audited loaded-image PE-header fingerprints.
6. Re-read all four slots immediately before writing. Abort if any value
   changed.
7. Write `0x0090CC10` to each slot with protected 32-bit writes.
8. Read all four back. Mark `RepairedKnownStewie` only if every read matches.

Run the check only on the game main thread. Individual 32-bit slot writes are
atomic on the supported i686 target. A temporary mixture is safe because both
the verified Stewie function and vanilla target are callable, but no unknown
target is ever overwritten.

Do not disable `bProcess`, patch Stewie's function body, or touch any of its
other inlines.

### Core-owned late boundary

Replace the direct main-loop call at `0x0094CFD6` with a `thiscall` wrapper that:

1. invokes `lowprocess::ensure_late_repair()` before the first queue drain;
2. calls the original `FUN_00446B50` with the original `ECX` and stack
   argument;
3. becomes a near-zero-overhead pass-through after the LowProcess state reaches
   a terminal result.

`engine_fixes::observe_event(DEFERRED_INIT)` calls the same idempotent function
as an optional earlier trigger. Correctness does not depend on the helper or
`OnFramePresent`.

If testing shows a plugin can write the slots after the first main-loop drain,
keep the state in `Waiting` for a bounded 120-frame observation window. Do not
perform permanent per-frame polling.

### Save containment

Replace only the list-element call at `0x009105BF`. The checked wrapper keeps
the original `thiscall` ABI and the original third argument:

```text
checked_append_ref_id(writer, form, flags)
```

Behavior:

1. `NULL` remains valid and is forwarded.
2. A non-NULL form must be readable for the fields actually inspected.
3. Its vtable must be readable, image-backed, and contain an executable first
   virtual target.
4. Valid forms are forwarded unchanged to `0x00865DF0`.
5. Invalid forms are replaced with `NULL` and still forwarded.

Never skip the original call. `FUN_00910450` increments the element count after
the call and later patches the count into the stream. Forwarding `NULL`
preserves count/buffer alignment and matches the loader's tolerated unresolved
reference behavior.

Do not scrape the caller's `EBP` to claim a process, node, or actor identity.
The direct-call ABI does not provide those values. Log the bad form, writer,
flags, thread id, and cumulative count using power-of-two sampling.

### LowProcess counters

Expose monotonic atomics for:

- late checks;
- vanilla observations;
- successful Stewie repairs;
- unsupported/mixed replacements;
- invalid save forms converted to NULL;
- patch verification failures.

## Change 2: queued-task lifetime guard

### New engine-fix owner

Add `psycho-engine-fixes/src/mods/engine_fixes/queued_tasks.rs`. It owns:

- the task dispatch block patch;
- the `FUN_0044DD60` release hook;
- task pointer/vtable/callback validation;
- the optional lifetime trace ring;
- all task-lifetime counters.

Move the general logic from
`heap_replacer/gheap/task_release.rs` into this module. There must be exactly one
hook container and one installer for `FUN_0044DD60`.

### Atomic dispatch pin

The replacement for `0x00446C48..0x00446C55` receives the task in `ECX`; the
callback argument is already on the stack. Its ABI must consume that argument
exactly as the original virtual call did.

The checked dispatcher performs:

1. Reject NULL, unreadable, or misaligned task/refcount addresses.
2. Treat `task + 0x08` as `AtomicI32` only after alignment validation.
3. Pin with a compare-exchange loop:
   - load with `Acquire`;
   - accept only `1..i32::MAX`;
   - increment with `AcqRel` success and `Acquire` failure ordering;
   - never increment zero or a negative value.
4. After the pin, validate the current vtable and slot `+0x1C`.
5. Dispatch the captured callback with the original `thiscall` ABI and argument.
6. Release the temporary pin through the guarded `FUN_0044DD60` path even if
   callback validation fails after pinning.
7. Return normally. The caller retains its original local-holder release at
   `0x00446C5C`.

The pin must occur before reading the callback. A read/check followed by a
normal increment leaves a final-release race and is not acceptable.

### Validation policy

After a successful pin:

- reject the known base/dead `NiRefObject` vtable `0x0101DCE4`;
- reject unreadable vtables and unreadable slot `+0x1C`;
- require the callback page to be committed and executable;
- require the callback to be backed by a loaded image allocation;
- when gheap metadata is available, reject a cell already marked free.

Do not require every callback to reside in FalloutNV.exe. Plugin-defined task
classes may have legitimate image-backed executable callbacks. Log module
ownership when rejecting or tracing a target.

If pinning fails because the count is non-positive, skip the callback. The
caller's normal local-holder release then reaches the release guard, which must
also refuse to decrement a non-positive count.

### General release guard

Preserve these existing behaviors after moving the code:

- unreadable tasks are not released;
- non-positive refcounts are not decremented;
- a final release requires a readable vtable and executable destructor;
- normal positive non-final releases call vanilla unchanged;
- valid final releases call vanilla unchanged;
- logging remains power-of-two sampled.

Change these behaviors:

- use the already-resolved `EngineFixesConfig` boolean instead of querying
  `MemoryConfig` in the hook;
- install in allocator modes 0, 1, and 2;
- keep gheap tombstoning optional rather than making the common guard depend on
  pool internals;
- move task diagnostic counters into `engine_fixes`.

### Narrow gheap interface

Add a small `pub(crate)` adapter under `heap_replacer`, for example:

```text
task_pool_state(task) -> Unknown | Live | Free
tombstone_free_task(task, dead_vtable, dead_refcount) -> Option<TaskCellInfo>
```

It returns `Unknown` unless full gheap is active. `queued_tasks.rs` must not
reach into slab bitmaps or duplicate pool layout logic. Modes 0 and 1 simply
use pointer/refcount/vtable validation.

Keep `model_task_fix.rs` gheap-specific for now. Its 80-byte free-cell contract
is allocator-specific and is separate from the general dispatch/release fix.

### Optional lifetime provenance ring

When `diagnostics.task_lifetime_trace` is false, the hot path performs one
cached boolean branch and no ring writes.

When enabled, use a fixed power-of-two ring with no heap allocation and no
locks. Each record contains:

- publication sequence;
- task address;
- vtable;
- refcount before and after;
- thread id;
- operation (`retain`, `release`, `dispatch_pin`, `dispatch`, `reject`);
- caller return address;
- callback/destructor target when applicable.

Use an atomic global sequence to reserve a slot and a per-slot sequence field
to publish it. Readers ignore a slot if its sequence changes while copied.
Dump only records for the rejected task, newest first, from the cold rejection
path.

Capturing the true caller at the release function requires an i686 entry shim
that reads the original `[ESP]` before a Rust prologue and forwards it to the
Rust body. Do not use fragile frame-pointer assumptions. The tracing shim is an
optional diagnostic subfeature; inability to implement it safely must not
block the production dispatch/release guards.

### Task counters

Expose monotonic atomics for:

- dispatch attempts and successful callbacks;
- pin successes and non-positive pin failures;
- invalid pointers, vtables, and callbacks;
- base-vtable rejections;
- release guards;
- valid final releases;
- gheap free-cell detections and tombstones;
- trace records and trace dumps.

## Source-file change inventory

### Add

- `psycho-engine-fixes/src/mods/engine_fixes/lowprocess.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/queued_tasks.rs`
- Optional: `libpsycho` compare-before-patch helper if current wrappers cannot
  provide the required atomic validation API.

### Modify

- `psycho-engine-fixes/src/config.rs`
  - add both engine-fix booleans and the trace boolean;
  - migrate legacy task keys with new-key precedence;
  - remove the active task flag from `MemoryConfig`.
- `psycho-engine-fixes/config/psycho_engine_fixes.toml`
  - document the two fixes and opt-in trace setting.
- `psycho-engine-fixes/src/mods/engine_fixes/mod.rs`
  - register both modules;
  - install each feature independently;
  - route `DeferredInit` to LowProcess late repair;
  - aggregate new diagnostic snapshots.
- `psycho-engine-fixes/src/mods/engine_fixes/statics.rs`
  - add the patch manifest, hook storage, verified bytes, and game constants.
- `psycho-engine-fixes/src/mods/engine_fixes/types.rs`
  - add exact i686 function types for the save writer, task drain, task release,
    and task callback.
- `psycho-engine-fixes/src/mods/heap_replacer/install.rs`
  - remove initialization/enabling of the general task release hook;
  - leave the gheap-only model-task destructor hook in place.
- `psycho-engine-fixes/src/mods/heap_replacer/mod.rs`
  - expose only the narrow optional task-cell adapter.
- `psycho-engine-fixes/src/mods/heap_replacer/gheap/hitch.rs`
  - stop reading counters from `gheap::task_release`;
  - consume the aggregated engine-fix task counters.
- `psycho-engine-fixes/src/mods/heap_replacer/gheap/hang.rs`
  - include compact task-guard state only if useful to the existing hang line.
- `psycho-engine-fixes/src/mods/heap_replacer/mem_stats.rs`
  - append an `Engine fixes` section to every allocator-mode `PsychoInfo`
    report, not only the gheap report.
- `psycho-engine-fixes/src/startup.rs`
  - pass diagnostics trace enablement into engine-fix initialization, or cache
    it before hook installation;
  - retain memory initialization before engine fixes so the optional gheap
    adapter is ready.
- `libpsycho/src/os/windows/winapi.rs`
  - only if needed, add safe wrappers for image-backed executable validation or
    compare-before-patch; no direct WinAPI calls in the new engine-fix modules.

### Move/remove

- Move common code out of
  `psycho-engine-fixes/src/mods/heap_replacer/gheap/task_release.rs`.
- Remove that module after all imports, counters, and hook storage have moved.
- Remove `TASK_RELEASE_HOOK` and `TASK_RELEASE_ADDR` from gheap statics after the
  engine-fix manifest owns them.

### No changes

- No patching logic in `psycho-engine-fixes-helper`.
- No changes to `syringe` or `syringe-api`.
- No allocator cleanup-stage, IO-barrier, Havok-lock, quarantine, or slab reuse
  policy changes.
- No global disable of Stewie `bProcess` or `bSaveLoad`.

## Installation and failure isolation

`engine_fixes::install` must treat the two new features independently:

1. If a setting is false, log one disabled line and install nothing for it.
2. If byte verification or hook creation fails, log the exact observed bytes or
   pointers and disable only that feature.
3. A LowProcess vtable mismatch must not disable save containment.
4. A dispatch-block mismatch must not create a second release hook or leave a
   partial block patch.
5. A release-hook failure disables queued-task dispatch patching too; the
   dispatch guard depends on the guarded release path for its temporary pin.
6. Never abort allocator initialization or unrelated engine fixes because one
   crash fix is incompatible.

For the queued-task feature, install in this order:

1. initialize and enable the release hook;
2. verify the dispatch block again;
3. patch the dispatch block;
4. publish `Active` only after both succeed.

If step 3 fails after the release hook is active, leaving the conservative
release hook active is safe, but report the feature as `ReleaseOnly` rather
than fully active.

## Implementation phases

### Phase 0: freeze signatures

- Keep the approved FalloutNV.exe patch bytes above synchronized with
  `crash_20260712_patch_manifest_audit.txt`.
- Keep the Stewie module-name and PE-header allowlist synchronized with each
  audited source release, installed binary provenance, and CrashLogger module
  evidence.
- Keep the confirmed wrapper ABIs and stack cleanup synchronized with the
  Ghidra output.
- Do not enable a write whose signature is still unknown.

### Phase 1: configuration and ownership move

- Add configuration fields and legacy migration.
- Move the release hook and counters to `engine_fixes`.
- Add the optional gheap adapter.
- Build and confirm allocator modes 0/1/2 install exactly one release hook.

### Phase 2: queued-task dispatch guard

- Add the CAS pin and validation body.
- Add the byte-verified 13-byte dispatch patch.
- Test without provenance tracing first.
- Add tracing only after production behavior is stable.

### Phase 3: save containment

- Add the checked list-element writer and direct-call patch.
- Verify invalid entries write NULL while preserving the final patched list
  count.
- Confirm the resulting save reloads.

### Phase 4: late LowProcess root repair

- Add the main-loop wrapper and event trigger.
- Start with observe-only signature logging.
- Enable four-slot restoration only after the Stewie module name, an audited PE
  header, common-pointer, and pre-write revalidation gates all pass.
- Verify the repair is one-shot and idempotent.

### Phase 5: diagnostics and cleanup

- Add `PsychoInfo` status for every allocator mode.
- Redirect hitch diagnostics to the new counter owner.
- Remove obsolete gheap task-release code and config access.
- Run formatting, diff checks, and the supported release build.

## Validation matrix

### Static/build gates

Run:

```text
cargo fmt --check
cargo build --release --target i686-pc-windows-gnu -p syringe -p psycho-engine-fixes -p psycho-engine-fixes-helper
```

Also verify:

- no second owner of `0x0044DD60` exists;
- no new direct WinAPI call exists outside allowed allocator hot paths;
- all detours use `extern "thiscall"`/`fastcall` matching the proven x86 ABI;
- every code write has a complete original-byte fingerprint;
- the pre-existing dirty `libnvse/xnvse` submodule is untouched.

### Compatibility matrix

Test each allocator mode `0`, `1`, and `2` with:

- Stewie 9.90 and 9.95, `bProcess=1`, `bSaveLoad=1`;
- Stewie present with `bProcess=0`;
- Stewie absent;
- an intentionally unknown vtable replacement to prove fail-closed behavior;
- helper present and helper absent.

Expected results:

- task guard active in all allocator modes;
- gheap pool details appear only in mode 2;
- vanilla LowProcess slots remain untouched;
- the approved Stewie replacement is restored once;
- unknown replacements are logged and untouched;
- helper absence does not change correctness.

### LowProcess/save tests

1. Reproduce the Hidden Valley path that produced the original save crash.
2. Save before and after a reference removal that touches
   `genericLocationsList`.
3. Confirm no `TESObjectREFR` payload is freed by the repaired vtable path.
4. Inject or retain one known-invalid optional list payload and confirm:
   - one NULL form reference is written;
   - the serialized element count matches the stream;
   - the save completes and reloads;
   - later saves do not accumulate structural corruption.
5. Repeat save/load and cell-transition cycles for at least 30 minutes.

### Queued-task tests

Stress:

- Freeside impact/effect workloads from the original crash context;
- model and texture streaming;
- rapid cell transitions and fast travel;
- repeated load/save cycles;
- shutdown to main menu and reload;
- gheap OOM cleanup stages with IO barriers active.

Verify:

- live callbacks execute once and receive the unchanged argument;
- queue order and drain progress are unchanged;
- the temporary pin returns the refcount to the expected value;
- zero/negative tasks are skipped and never resurrected;
- the caller's local-holder release still executes;
- no double release or leaked permanent pin occurs;
- plugin-image callbacks are accepted when otherwise valid;
- provenance tracing off adds no allocation or lock;
- trace dumps identify matching task history when enabled.

### Performance acceptance

With tracing off, measure task-drain time and frame hitches before/after. The
accepted steady-state cost is:

- one cached enabled-state branch;
- one positive-only CAS pin;
- pointer/vtable/callback validation;
- one guarded release per dispatched callback.

No work is added to general allocation/free paths. If repeated `virtual_query`
calls are measurable, cache immutable loaded-image ranges outside the callback
hot path; do not weaken callback validation.

## OOM, UAF, and performance balance

- **OOM:** unchanged. No cleanup stage, commit accounting, pressure trigger,
  quarantine, or IO barrier changes.
- **UAF:** improved. LowProcess stops freeing a non-owned reference; task
  dispatch cannot pin or call an object whose reference count is already dead.
- **Performance:** save validation is off the frame hot path. Task dispatch adds
  a CAS, validation, and paired release. Trace recording is opt-in and
  allocation-free. No per-allocation overhead is introduced.

The task pin can extend a live task's lifetime only through its callback. This
costs at most one temporary reference and is the required UAF protection; it is
not a quarantine or long-lived memory retention policy.
