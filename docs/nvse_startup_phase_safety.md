# Pre-DeferredInit startup compatibility and BaseObjectSwapper crash contract

Status: mandatory repository-wide compatibility contract.

Last updated: 2026-08-10 after the rejected libnvse phase-capability and
dashboard-relocation experiment failed its Proton playtest.

## Purpose

This document records the exact BaseObjectSwapper crash observed repeatedly
while testing Psycho changes and defines how this repository must prevent its
own future changes from exposing that crash again.

The protection is deliberately mod agnostic. Psycho must control only its own
DLLs, imports, initialization order, configuration layout, workers, and engine
hooks. It must never inspect, identify, patch, hook, reorder, disable, or add a
compatibility path for BaseObjectSwapper or any other third-party mod.

The relevant safety boundary is the complete process interval from Windows
loading an NVSE plugin through the start of xNVSE `DeferredInit`. A Psycho
change can perturb this interval without calling Fallout or another plugin.
PE imports, TLS, static storage, CRT work, allocation order, configuration
parsing, worker startup, and code or data moved between DLLs all count.

This document is the authority when the observed fault signature is:

- `EXCEPTION_ACCESS_VIOLATION`;
- BaseObjectSwapper DLL RVA `0x4990` at the top of the trace;
- `ConditionalInput::IsValid +0x88`, historically reported as
  `ConditionalData.cpp:95`, immediately below it;
- no successful Psycho/OMV `DeferredInit` marker before the fault.

## Non-negotiable architecture boundary

The presence of a third-party defect is not permission to enter that mod's
scope. The following responses are prohibited:

- detecting `BaseObjectSwapper.dll` by name, hash, version, import, export, or
  instruction signature;
- scanning, writing, detouring, guarding, or otherwise changing its code or
  data;
- intercepting its constructors, visitor, vtable hook, or exception;
- reserving a plugin name, changing plugin order, or adding a BOS-specific
  configuration option;
- disabling BOS, suppressing conditional swaps, or treating its absence as a
  Psycho requirement;
- redesigning `libnvse`, `libpsycho`, the core/helper boundary, or another
  shared API as a purported repair for this external object;
- moving established functionality between Psycho DLLs merely to change the
  probability of the external fault.

The only appropriate Psycho correction is the smallest change that restores
Psycho's last load-to-gameplay-playtested pre-DeferredInit footprint while
preserving the feature under development. A direct fix for the uninitialized
members described below belongs in BaseObjectSwapper's own source and release,
not in this repository.

## Terminology and attribution

Use these terms precisely:

- **Fault site**: the instruction which raised the access violation. It is
  proven to be inside BaseObjectSwapper.
- **External defect**: BaseObjectSwapper's constructor leaves optional pointer
  members indeterminate on valid control-flow paths. This is proven from the
  available source and the tested binary.
- **Psycho-side trigger**: a Psycho delta which changes loader work, stack or
  allocation history, startup ownership, or timing so the external undefined
  behavior becomes observable. A failing/passing A/B test can establish a
  trigger without proving the exact byte-level coupling.
- **Direct corruption**: Psycho writes into memory owned by BaseObjectSwapper.
  No retained evidence proves this happened.
- **Accepted baseline**: an exact source and artifact state which completed a
  representative Proton load from process start into gameplay. Passing tests
  or compilation alone never creates an accepted baseline.

Do not describe the trace as a "corrupt std::variant". `std::visit` is the
dispatch path which reaches `ConditionalInput::IsValid`; the failing
instruction dereferences an independent raw `currentWorldspace` member. The
variant itself has not been proven corrupt.

Likewise, CrashLogger's `(Corrupt stack or heap?)` unwind annotations are not
proof of a broad overwrite. They are a warning produced after unwinding out of
optimized native code. They do not identify an owning writer.

## Exact external defect

### Source object and initialization paths

The reference snapshot is read-only:

- `.research/BaseObjectSwapperNV-master/src/ConditionalData.h`;
- `.research/BaseObjectSwapperNV-master/src/ConditionalData.cpp`;
- `.research/BaseObjectSwapperNV-master/src/Manager.cpp`;
- `.research/BaseObjectSwapperNV-master/src/Hooks.cpp`;
- `.research/BaseObjectSwapperNV-master/main.cpp`.

`ConditionalInput` has five consecutive 32-bit pointer members:

| Object offset | Member | Constructor behavior |
|---:|---|---|
| `+0x00` | `ref` | Always initialized from `a_ref`. |
| `+0x04` | `base` | Always initialized from `a_form`. |
| `+0x08` | `currentCell` | Always assigned from `a_ref->GetParentCell()`. |
| `+0x0C` | `currentWorldspace` | Assigned only inside `if (currentCell)`. |
| `+0x10` | `currentRegionList` | Assigned only if both the cell and region-list extra data exist. |

The source supplies no default member initializer for the final two pointers
and does not include them in the constructor initializer list. Therefore:

1. If `GetParentCell()` returns null, both `currentWorldspace` and
   `currentRegionList` contain indeterminate stack data.
2. If a parent cell exists but has no `ExtraCellRegionList`,
   `currentRegionList` still contains indeterminate stack data.
3. A cell with a null `worldSpace` explicitly stores null and is safe for the
   worldspace branch.
4. A found region extra explicitly stores its `regionList` value, including a
   possible null, and is safe for that branch.

Reading an indeterminate pointer already violates the C++ object contract.
Testing a small nonzero value and then dereferencing it produces the observed
access violation.

### Call ownership and lifetime

BaseObjectSwapper installs a `TESObjectREFR::InitItem` vtable detour during its
own `NVSEPlugin_Load`; the source targets vtable `0x0102F55C`, slot `0x22`.
Its PostLoad and PostPostLoad message cases do not defer that installation.
The thunk performs this order:

1. read `a_ref->baseForm`;
2. load BOS configuration once;
3. call `FormSwap::Manager::GetSwapData(a_ref, base)`;
4. apply a selected base and optional properties;
5. only then call the original Fallout `TESObjectREFR::InitItem`.

`GetSwapData` enters both conditional owners:

- `GetSwapFormConditional` constructs a stack-local `ConditionalInput` for
  conditional form swaps;
- `GetObjectPropertiesConditional` constructs another stack-local
  `ConditionalInput` for conditional property overrides.

Both instances are evaluated synchronously and die before their manager call
returns. The logs place the crash while game forms/references are being
initialized and before Psycho/OMV DeferredInit, but CrashLogger did not name
the faulting thread. There is no retained evidence of cross-thread access to
either `ConditionalInput` instance.

Calling BOS before the original `InitItem` is important context: a reference
without an established parent cell is a normal input to this hook path. It is
not evidence that Psycho removed the cell.

### Tested binary identity

The installed artifact researched on 2026-08-10 was:

- path: `mods/Base Object Swapper/NVSE/Plugins/BaseObjectSwapper.dll`;
- SHA-256:
  `4838096fbd6f650435c7268ac6fad610018b42814caaea82e93a25cf8d933633`;
- size: `540672` bytes;
- format: PE32 Intel i386, five sections;
- preferred image base: `0x10000000`;
- PE image size: `0x00089000`;
- `.text`: RVA `0x00001000`, code size `0x00026E00`, raw file offset
  `0x00000400`;
- linker timestamp: 2026-02-09 03:48:55 as displayed by the PE tools;
- CodeView debug GUID: `05A09C641FC94DBCB458B0B380F869C61`;
- compiler/linker generation: MSVC 14.50 as reported by its debug paths and PE
  metadata.

Addresses below are module RVAs and remain meaningful under ASLR. They are
evidence only; Psycho must not consume them at runtime.

### Compiled constructor proof

The binary contains two inlined constructor sequences, one in each conditional
manager path:

| Owner | Function RVA | Constructor RVA | Cell test | Null convergence |
|---|---:|---:|---:|---:|
| Conditional form swap | `0xF720` | `0xF7F2` | `0xF803` | `0xF82C` |
| Conditional properties | `0xF8E0` | `0xF9B2` | `0xF9C3` | `0xF9EC` |

For both instances, the generated stack object is:

| Stack slot | Member |
|---:|---|
| `[esp+0x24]` | `ref` |
| `[esp+0x28]` | `base` |
| `[esp+0x2C]` | `currentCell` |
| `[esp+0x30]` | `currentWorldspace` |
| `[esp+0x34]` | `currentRegionList` |

The binary stores `currentCell`, tests it, and jumps directly to condition
evaluation when it is null. It never initializes `[esp+0x30]` or
`[esp+0x34]` on that path. On the non-null path it stores the cell's
worldspace, but it stores the region list only when the extra-data lookup
succeeds. This exactly matches the source defect; it is not a source-only
hypothesis.

The essential instructions are identical in both inlined instances:

```text
mov [esp+0x2C], ecx          ; currentCell
test ecx, ecx
je   condition_evaluation   ; skips both optional pointer stores
mov eax, [ecx+0xC0]
mov [esp+0x30], eax          ; currentWorldspace
...
test eax, eax
je   condition_evaluation   ; skips currentRegionList store
mov eax, [eax+0x0C]
mov [esp+0x34], eax          ; currentRegionList
```

### Failing visitor proof

The compiled `IsValid(FormID)` visitor uses the object layout above:

- RVA `0x4985` loads `currentWorldspace` from `[edi+0x0C]`;
- RVA `0x4988` rejects null;
- RVA `0x498C` compares it with the requested worldspace;
- RVA `0x4990` executes `cmp dword ptr [eax+0x70], ecx`, comparing the
  candidate's parent worldspace after dereferencing `currentWorldspace`;
- RVA `0x49B9` separately loads `currentRegionList` from `[edi+0x10]` and
  traverses its list when non-null.

Every retained exact crash stopped at RVA `0x4990`. The invalid `eax` values
changed with the surrounding build:

| Captured run | `eax` at `0x4990` |
|---|---:|
| 2026-08-04 retained CrashLogger report | `0x00000006` |
| 2026-08-10 15:52 and 17:05 | `0x00000006` |
| 2026-08-10 18:23, 18:24, and 18:28 | `0x00000004` |
| 2026-08-10 20:06 and 20:08 | `0x00000001` |

At the same time, `ecx` consistently resolved to the valid Big MT
`TESWorldSpace`. Values `1`, `4`, and `6` cannot be aligned pointers to a
`TESWorldSpace`; they are consistent with an uninitialized stack slot whose
previous contents changed as Psycho's process/startup footprint changed.

The retained 2026-08-04 trace identifies the reference being conditionally
processed as `Mug N.000 - Vanilla`, FormID `06045869`, from `Fallout3.esm`,
with base `CoffeeMug01`, FormID `0003406C`, last modified by `Mugs.esp`. This
TTW/content context helps recognize the same workload, but it does not make the
defect specific to that record, Fallout 3, TTW, Mugs, or Big MT. Other cells,
worldspaces, and regions listed deeper in CrashLogger's stack scan are not
proven to be the `ConditionalInput` object's current parent data.

The region-list path has the same statically proven uninitialized-member
hazard, but no retained crash is known to stop at its traversal. Record it as a
latent sibling defect, not as an observed second crash.

## Retained runtime evidence

Repository evidence:

- `.reports/CrashLogger-2026-08-04-194321-pbr-startup-crash.log` contains the
  complete `0x4990` trace with `eax = 6`, no player cell/world, 11 seconds of
  playtime, and only 558.5 MiB of virtual memory in use;
- `.reports/omv-2026-08-04-233226-deferred-boundary-crash.md` records another
  failing artifact and the missing DeferredInit boundary;
- `.reports/baseobjectswapper-helper-registry-import-2026-08-10.txt` records
  three consecutive 2026-08-10 crash names, the helper import leak, artifact
  hashes, and the attribution limit;
- `.reports/omv-2026-08-10-155159-motion-blur-startup-crash.log` records the
  latest successful OMV messages before a separate occurrence.

The user's playtest installation retained further raw traces under
`FalloutNV/Crash Logs/`, including the 2026-08-10 runs listed in the table.
Those external files are supporting runtime evidence, not repository inputs.

Across these failures:

- xNVSE loaded BOS and the Psycho plugins successfully and reached its normal
  plugin initialization completion;
- the game had not established a player cell or world;
- OMV had not logged its DeferredInit world publication, resident graphics
  hooks, scene transaction, or Present path;
- the failures occurred around 9-11 seconds into startup;
- memory exhaustion was not present;
- the same BOS instructions failed while the small invalid pointer value
  changed between Psycho builds.

These facts exclude post-Deferred render code, shader behavior, D3D resources,
normal gameplay hooks, and OOM recovery from the executed failing path.

## Psycho-side trigger history

The external defect is stable, but Psycho changes have repeatedly altered
whether it manifests. The exact low-level coupling is usually allocation or
stack-history inference; the relevant Psycho delta and phase are still usable
for surgical A/B correction.

| Date | Psycho delta before DeferredInit | Evidence and result | Attribution |
|---|---|---|---|
| 2026-07-18 | OMV first-published the focused world `LazyLock` owner from `NVSEPlugin_Load`. | Failing build stopped at the BOS signature; moving only that first publication to DeferredInit passed into gameplay and Present. | OMV-side trigger proven by A/B; direct BOS corruption not proven. |
| 2026-07-23 | Radio work introduced an eager `0xE01C` tasklet/batch image object and new pre-deferred lifecycle forwarding. | The worker and native tasklet route had not executed. Lazy post-deferred ownership and message gating passed the former crash point. | New pre-deferred deltas identified; exact coupling inferred. |
| 2026-07-27 | A PBR cache added Rust `thread_local!` storage and a DLL TLS callback. | The crash preceded all terrain/render work. The TLS owner was removed in favor of zero-initialized atomics. | TLS was the only new load-time construct and strongest trigger candidate; no direct-write proof. |
| 2026-08-04 | A broad staging-only experiment changed pre-deferred ownership/order. | The retained report shows the exact BOS signature before DeferredInit. The experiment was discarded. | Phase and artifact proven; individual lower-level trigger not isolated. |
| 2026-08-10 | Motion-blur cleanup changed nested config layout, schema, preset payload, and startup migration work. | Restoring schema 1 and the inert serialized field preserved the feature and passed the user's load-to-gameplay playtest. | New OMV startup delta and successful surgical correction proven; byte-level coupling inferred. |
| 2026-08-10 | Core-only registry wrappers leaked five `Reg*` imports into the helper through static-library code generation. | PE inspection and a regression check proved the imports. Three consecutive launches showed the BOS signature. Isolating the wrappers removed the imports without removing registry repair. | Import leak and removal proven; import-to-BOS coupling remains trigger inference. |
| 2026-08-10 | An uncommitted phase-capability API and dashboard relocation broadly changed libnvse, helper, core, and OMV layout/ownership. | Static tests and release builds passed, but Proton crashed again at `0x4990`; later traces used `eax = 1`. | Runtime rejection proven. No individual component is isolated, so the entire experiment is not an accepted baseline. |

Detailed OMV incidents remain in
`docs/graphics_fnv_atmosphere_startup_crash_errata.md`. This document owns the
repository-wide causal and response contract.

## Mandatory future-change protocol

### 1. Establish the accepted baseline first

Before changing any pre-DeferredInit footprint, record:

- the last commit and exact DLL hashes that passed a representative Proton
  load into gameplay;
- the relevant successful log markers and their order;
- the configuration/preset schema and shipped payload version;
- the owning DLL's imports, TLS size/callbacks, and relevant static sections;
- which process-owned preparation, scans, workers, and engine publication
  already occur before DeferredInit.

For OMV, commit `9975b2e` is the load-to-gameplay-playtested startup baseline
established by the 2026-08-10 motion-blur correction unless a later accepted
baseline is recorded. The current uncommitted phase-capability/dashboard
relocation is explicitly not a baseline regardless of its static test results.

### 2. Diff the complete footprint, not only executed Rust calls

A review must list every added, removed, reordered, or first-touched item in
the plugin-load-to-DeferredInit interval:

- direct and transitive PE imports, delay imports, and loaded DLLs;
- `.tls` size, TLS callbacks/destructors, and `thread_local!` values;
- CRT constructors/destructors and static initialization;
- `LazyLock`, `OnceLock`, mutex, condition variable, or other owner first use;
- `.data`/`.bss` growth from large embedded state;
- allocation-heavy parsing, serialization, migrations, maps, strings, and
  filesystem scans;
- thread creation, worker wakeups, task queues, log consumers, and timers;
- configuration struct layout, schema, manifest, preset, shipped TOML, and
  migration changes;
- atomics/mailboxes that publish engine ownership, readiness, hook admission,
  or scene requirements;
- helper/core/module ownership moves and static-library feature changes;
- message registration/forwarding and startup callback order;
- linker settings, dependency feature changes, LTO/codegen changes, or broad
  shared-wrapper additions which can alter final PE images.

"The new function is never called" is not a safety argument. The registry
incident proved that a shared wrapper can change the helper import table with
no helper source call. The TLS incident proved that render-only intent can
change process startup before a render callback executes.

### 3. Preserve established phase and ABI shape

- Keep the pre-Deferred path frozen unless the feature strictly requires a
  change there.
- Stage engine-facing state and publish it only at its already-proven lifecycle
  boundary.
- Preserve released configuration fields, order, types, schema, built-in
  payloads, and migrations unless explicit schema evolution has its own
  startup-safety design and runtime acceptance.
- Keep compatibility-only fields inert rather than deleting them from the
  startup value graph.
- Do not add TLS or first-touch a lazy owner merely to cache future runtime
  work.
- Keep large runtime state lazy and owned only after the established boundary.
- Keep core-only FFI wrappers isolated so static linking cannot add imports to
  another final DLL.
- Keep the xNVSE helper thin and preserve its accepted load callback, import
  table, TLS footprint, and event order.

An xNVSE lifecycle API can express local ownership, but it cannot repair or
stabilize an unrelated plugin's stack object. Do not introduce a repository-
wide type-system or phase-token redesign in response to this crash.

### 4. Correct only the new delta

When a previously accepted build begins failing with this signature:

1. Stop feature expansion.
2. Confirm the fault address and the last successful startup log marker.
3. Prove whether DeferredInit was reached.
4. Compare the failing artifact with the accepted parent artifact, including
   imports, TLS, sections, exported ABI, config shape, and startup call order.
5. Enumerate only changes capable of occurring before the missing marker.
6. Remove or restage the smallest new unsafe delta while keeping the requested
   feature and all previously accepted preparation/order.
7. Do not tune code that never executed and do not intervene in the external
   faulting mod.
8. Build once after focused checks, then require a new Proton playtest.

Broadly moving established workers, parsers, shader preparation, dashboard
ownership, or APIs later is not a surgical correction. It creates another
unreviewed footprint and can merely change which garbage value occupies the
external stack slot.

### 5. Treat static validation as necessary but insufficient

For an affected code change, static acceptance must include:

- focused source-order and ownership tests;
- strict config/preset round trips and compatibility shape checks when
  configuration is touched;
- tests or PE inspection for imports, TLS callbacks, sections, exports, and
  core/helper ownership when linkage changes;
- the affected supported-target suites;
- the complete `i686-pc-windows-gnu` release build;
- `cargo fmt --all -- --check` and `git diff --check`;
- a final diff against the accepted baseline's complete pre-deferred footprint.

Tests must enforce a known invariant; they are not a substitute for the actual
guard, which is preserving the accepted startup footprint.

### 6. Require runtime closure

No pre-Deferred footprint change is startup-safe until the user completes a
normal Proton load-to-gameplay playtest with the representative large modlist,
including BaseObjectSwapper as an environmental stressor rather than a Psycho
dependency.

Acceptance requires:

- the deployed DLL hashes match the reviewed release artifacts;
- xNVSE completes plugin initialization;
- Psycho logs reach `[EVENT] Game engine ready`;
- OMV logs reach its DeferredInit world publication and deferred-hook marker
  when OMV is in scope;
- the game reaches normal gameplay and the changed feature works;
- CrashLogger contains no `BaseObjectSwapper +0x4990` failure;
- at least three cold starts pass when the preceding failure was intermittent
  or stack-layout-sensitive.

Record the accepted commit, hashes, log paths, and playtest result in the
owning feature document and, when the startup baseline changes, in this
contract. A passing launch is runtime observation for that artifact and
modlist; it does not prove the external C++ defect ceased to exist.

## Triage exclusions

If the log stops before DeferredInit, do not investigate or change:

- shaders, render-target formats, D3D9 state, depth providers, RESZ, or GPU
  policy;
- Present, Reset, scene, draw, or gameplay hooks which were not installed;
- post-Deferred workers, engine publications, or UI behavior;
- allocator OOM recovery when memory use is plainly low;
- BaseObjectSwapper code, data, configuration, or load order.

Investigate only the failing Psycho artifact's pre-Deferred delta until that
delta is restored or directly proven irrelevant.

## Proven facts, inference, and open limits

### Proven

- The faulting instruction is BaseObjectSwapper RVA `0x4990` and dereferences
  `currentWorldspace` as a `TESWorldSpace`.
- The researched source and installed binary have two constructor paths which
  leave `currentWorldspace` and/or `currentRegionList` indeterminate.
- Observed invalid worldspace values include `1`, `4`, and `6`.
- The fault occurs before DeferredInit and before OMV render hooks execute.
- Multiple Psycho changes altered whether the external defect manifested.
- Static tests and successful release builds did not predict the latest
  failure.
- No evidence requires or authorizes Psycho to change another mod.

### Reasoned inference

- Psycho's loader, TLS, layout, allocation, parsing, or worker deltas changed
  the prior contents of BOS's uninitialized stack slot or its timing.
- The changing small values across builds strongly support uninitialized data
  rather than a stable dangling `TESWorldSpace` pointer.
- Each documented surgical A/B correction removed the relevant Psycho-side
  trigger without repairing the external object.

### Not proven

- Psycho directly wrote into BaseObjectSwapper-owned memory.
- The `std::variant` object itself was corrupt.
- Wine/Proton implements the relevant C++ behavior incorrectly.
- One allocator mode, display mode, GPU, monitor count, or registry value is
  the root cause.
- A generic libnvse API can make arbitrary third-party native code safe.
- A single successful launch guarantees every future binary layout is safe.

## Maintenance rule

This contract must not be weakened, replaced by a mod-specific workaround, or
reduced to a test-only rule. Update it only with new source, binary, log, A/B,
or playtest evidence, and keep fact, inference, and runtime observation
separate.

The durable Psycho guarantee is narrow and enforceable: future changes must
preserve the accepted pre-DeferredInit footprint or prove and playtest the
smallest necessary delta. Psycho remains mod agnostic and never intervenes in
the third-party faulting module.
