# OMV NVIDIA/AMD Close-Terrain Performance Correction

Date: 2026-08-11

Status: implemented and statically validated in the worktree. Cold-start
compatibility, image acceptance, the AMD control, and affected NVIDIA
measurements remain required. This document does not claim runtime closure.

## Purpose and current causal position

The first supplemental-selector removal was not a complete performance fix.
Affected NVIDIA systems remained extremely slow with and without DXVK. The
RX 6800 XT control still rendered near 120 FPS, but its tester subsequently
reported a repeatable loss of roughly 5-10 FPS with the candidate. That AMD
regression invalidates the assumption that moving supplemental records to a
texture was free when a draw had no supplemental lights.

Static compilation explains the cross-vendor cost that the earlier review
missed. The candidate declared `c91` and `s14`, retained the supplemental loop,
and compiled the two supplemental texture reads into every close-terrain pixel
program. A runtime count of zero prevented loop iterations, but it did not
restore the smaller native-only program or its lower register pressure. On the
repository compiler, the one-layer/zero-native-light row occupied 419
instruction tokens, four texture instructions, and 24 temporary registers.
The corrected native-only program occupies 248 instructions, two texture
instructions, and 11 temporaries.

This is direct compiler evidence for avoidable work and a strong explanation
for the measured AMD loss. The magnitude of the NVIDIA driver multiplier
remains an inference until the exact artifact is playtested.

The rejected split-constant-array design remains in
`graphics_fnv_omv_nvidia_close_terrain_shader_fix_plan.md`. Both supported
compiler routes lower shader-model-3 dynamic constant indexing to selector
work, so that design must not be revived from source appearance alone.

## Shader specialization without new engine rows

The existing 56 close-terrain pixel resources already form 28 even/odd pairs.
OMV uses each pair as two internal specializations regardless of whether the
engine selected the even base row or odd canopy companion:

- the even SLS resource is the native-only fast program;
- the odd SLS resource defines `OMV_SUPPLEMENTAL_LIGHTS=1` and is the
  supplemental program;
- the engine render-state cache always owns the even fast handle;
- OMV changes to the odd handle only across a nonempty-payload mode transition
  and restores the fast handle before the next engine `SetShaders` boundary.

This does not add a logical shader slot or D3D shader resource. It does make
the formerly byte-identical pair two distinct compiler inputs. There are still
57 close-terrain resources including the vertex shader, while total unique PBR
compiler groups increase from 132 to 160. Both members must be ready before the
family can activate, so partial preparation fails the complete family closed.

The fast HLSL preprocesses out all supplemental ownership:

- no `c91` declaration or read;
- no `s14` declaration or texture instruction;
- no supplemental loader;
- no supplemental loop or count branch;
- for native-capacity-zero rows, no point-light loop at all.

The supplemental program retains every portable-light feature. Native and
supplemental lights remain native-first, share the total cap of 24, use the
same RGB-only contribution equation, and retain all one-through-seven-layer
and `0/6/12/24` native-light coverage. Native canopy projected-shadow sampling
remains intentionally excluded because its matching OMV vertex ABI is not
proven.

The prepared Smith geometry equation also cancels two per-light divisions by
carrying the view and light denominators and the original
`NdotV * NdotL` numerator. The outer epsilon clamp is retained exactly; fully
cancelling the numerator would change grazing-angle output. A numeric sweep
compares the rewritten equation with the prior implementation.

## Supplemental texture ABI

Native VPT ownership is unchanged:

| Binding | Meaning |
|---|---|
| `c39..c62` | native point-light colors |
| `c63..c86` | native point-light positions/radii |
| `c88.x` | native point-light count |
| `c89/c90` | OMV terrain material controls |
| `c91.x` | supplemental count, supplemental program only |
| `s14` | temporary supplemental data texture, nonempty draws only |

The OMV-owned texture is one-mip `D3DFMT_A32B32G32R32F`, 64x1, dynamic, and
default-pool. Light `i` occupies adjacent texels:

- texel `2*i`: position XYZ and radius;
- texel `2*i+1`: RGB color and reserved alpha;
- texels after the last accepted light: exact zero.

The shader samples the exact centers `(2*i+0.5)/64` and `(2*i+1.5)/64` at
Y `0.5` with explicit LOD zero. OMV captures and owns `MINFILTER`, `MAGFILTER`,
and `SRGBTEXTURE` for each nonempty draw, selects point filtering and linear
color, then restores the exact prior values. The complete rollback record and
active marker are published before the first mutating D3D call, so a partial
setter failure cannot make an untracked state change. Address and mip modes
cannot affect an interior, explicit-LOD, one-mip lookup and are deliberately
not queried or changed.

The resource owner keeps the last complete 1 KiB image as exact float bits.
For a repeated payload, a bounded comparison skips payload serialization,
`LockRect`, the memory copy, and `UnlockRect`. A changed payload is serialized
only after that comparison, uploaded with `D3DLOCK_DISCARD`, and published to
the cache only after upload succeeds. Exact comparison rather than a hash
prevents collision-based light reuse and includes the zeroed tail.

## Draw and device-state transaction

For every close-terrain geometry, OMV performs this ordered transaction:

1. Restore any prior borrowed s14 texture and sampler fields. A failed restore
   retains the ownership marker and rejects the draw.
2. Repair a prior vanilla fallback before selecting geometry-specific state.
   Restoring afterward is forbidden because it would overwrite a newly chosen
   supplemental pixel shader before submission.
3. Validate the engine wrappers and required material texture mirror.
4. Capture or reuse the supplemental light result.
5. If the result is empty, require the fast program and do no supplemental
   texture, sampler, serialization, upload, or binding work.
6. If nonempty, require a known engine s14 identity, bind the cached or newly
   uploaded payload, own the three physical sampler inputs, and select the
   supplemental program only when the active mode differs.
7. Upload `c89..c91`; native geometry setup can rewrite constants between
   submissions, so this final writer remains per draw.
8. After submission, restore s14 texture and sampler ownership. Retain the
   supplemental shader across compatible geometries, but restore fast at the
   next `SetShaders`, batch finish, fallback, disable, reset, or resource drop.

Raw shader transitions are therefore bounded by payload-mode changes, not by
geometry count. The engine cache remains authoritative for the fast pair. A
successful native fallback clears the supplemental-active marker because the
native pixel bind supersedes either internal program.

Reset lifetime is keyed by both device pointer and lifecycle generation. A
failed restore marker is forgotten only after a proven generation transition,
when the old D3D state is invalid. Render callbacks use `try_lock` only; busy
ownership rejects a draw rather than blocking the serialized renderer.

## CPU hot-path corrections

The review also removes independent CPU costs which could mask the shader
result:

- The terrain draw cache is four-entry and direct-mapped rather than one-entry.
  Its index folds upper aligned-pointer bits before masking, so an A/B/A
  geometry sequence can retain both exact semantic snapshots. Each entry uses
  an even/odd atomic publication and exact native-light membership validation;
  a hash is never accepted as proof.
- The scene-wide terrain publication is copied from up to 64 atomic records
  once per exact publication/render/device epoch into a fixed POD snapshot.
  Later geometries borrow that snapshot through a nonblocking mutex.
- The texture generation was removed from the terrain cache key because the
  required material mirror is validated independently and texture identity
  does not change supplemental light selection.
- Equal engine `SetTexture` observations now return after read-only atomics;
  they no longer rewrite the tracker or advance a global generation.
- A disabled draw returns immediately; it no longer attempts device-resource
  release on every geometry. Disable/recreate ownership remains at its
  established lifecycle boundary.
- Repeated nonempty light payloads no longer materialize a 1 KiB stack image or
  enter the driver upload path.

These caches add no per-thread storage, heap allocation, blocking render lock,
file I/O, state logging, or unbounded scan. All keys include the generations
which can invalidate their underlying data.

## Comprehensive review disposition

| Reviewed cost or risk | Disposition |
|---|---|
| Supplemental shader work on empty draws | Fixed by fast/supplemental compile-time pair |
| Supplemental work inside native-capacity-zero programs | Fixed; the fast point loop preprocesses out |
| 1 KiB serialization and discard upload on repeated payload | Fixed by exact resource-image reuse |
| Inherited s14 filtering/color decode | Fixed by transactional ownership of the three relevant sampler fields |
| One-entry A/B/A terrain cache thrash | Fixed by four-entry upper-bit-mixed direct map |
| Texture identity invalidating light selection | Removed from the semantic cache key |
| Up to 64 atomic light-record loads per geometry | Fixed by exact-epoch POD snapshot |
| Equal texture binds causing atomic writes | Fixed by read-only equal-value fast return |
| Disabled geometry triggering resource-release attempts | Fixed; lifecycle owner remains responsible |
| Redundant Smith divisions per point light | Fixed with epsilon-equivalent denominator form |
| Restore-after-admission overwriting supplemental program | Fixed by restoring fallback before per-draw selection |
| Native `0/6/12/24` constant selector | Retained: ps_3_0 offers no legal relative c# addressing for this ABI; intercepting engine constant writes would add an unproven hook |
| Native membership reconstruction before cache lookup | Retained: the render pass has no proven mutation generation, so skipping the read could reuse stale membership |
| `c89..c91` upload per geometry | Retained: native setup may rewrite these registers between DIPs |
| s14 texture bind/restore and three sampler reads on a changed nonempty draw | Retained for exact engine-state ownership; empty draws pay none of it |

The retained items are explicit safety boundaries, not claims that their cost
is zero. Further optimization requires new executable or runtime evidence for
the missing mutation/ownership contract.

## Measured static budgets

Repository-compiler results after specialization are:

| Program | Bytes | Instructions | Texture ops | Temporaries |
|---|---:|---:|---:|---:|
| 1 layer, 0 native, fast (`SLS2092`) | 4,368 | 248 | 2 | 11 |
| 1 layer, 0 native, supplemental (`SLS2093`) | 6,952 | 419 | 4 | 24 |
| 1 layer, 24 native, fast (`SLS2098`) | 8,756 | 574 | 2 | 24 |
| 1 layer, 24 native, supplemental (`SLS2099`) | 9,428 | 612 | 4 | 28 |
| 7 layers, 0 native, fast (`SLS2140`) | 5,724 | 333 | 14 | 11 |
| 7 layers, 0 native, supplemental (`SLS2141`) | 8,308 | 504 | 16 | 23 |
| 7 layers, 24 native, fast (`SLS2146`) | 10,112 | 659 | 14 | 24 |
| 7 layers, 24 native, supplemental (`SLS2147`) | 10,784 | 697 | 16 | 28 |

The previous candidate made the 419/504-instruction supplemental programs the
only programs for the corresponding zero-native rows. The corrected common
path uses 248/333 instructions and removes both supplemental texture ops. The
tests impose exact texture counts and upper bounds for byte size, instructions,
and temporary registers so static bloat cannot silently return.

Persistent GPU payload storage is 1,024 bytes plus driver object overhead. The
four-entry draw cache stores fixed atomic identities and 24 fixed light records
per entry; the manager snapshot stores 64 ordinary copied records. These are
bounded static owners.

## Module ownership

| File | Ownership |
|---|---|
| `omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl` | compile-time fast/supplemental boundary, ABI, BRDF, and combined light cap |
| `omv/src/effects/pbr/shader_registry.rs` | even/odd specialization, ABI tests, compiler controls, and static budgets |
| `omv/src/effects/pbr/compiler.rs` | distinct precompiled inputs and group-count contract |
| `omv/src/effects/pbr/terrain_lights.rs` | exact semantic cache, light merge, and 64x1 serialization |
| `omv/src/fnv_local_lights.rs` | coherent atomic publication and render-epoch POD snapshot |
| `omv/src/effects/pbr/device_resources.rs` | paired handles, exact payload reuse, device generation, upload, and reset lifetime |
| `omv/src/effects/pbr/hooks.rs` | engine-cache ownership, mode transitions, s14 transaction, and fallback ordering |
| `omv/src/effects/pbr/samplers.rs` | authoritative texture mirror and equal-bind fast path |
| `omv/src/effects/pbr/constants.rs` | `c89..c91` final-writer upload |

Each owner has module-level documentation. Public or cross-module APIs have
docstrings, while source comments record the non-obvious safety, compiler, and
performance decisions beside their enforcement points.

## Startup and compatibility boundary

There is no config field, schema/preset change, hook, worker, TLS value, draw,
pass, vendor branch, imported DLL, or other-mod inspection. `.research` remains
read-only. No established initialization operation is moved later.

The embedded source and compiler cache inputs do change before DeferredInit:
28 formerly aliased close-terrain programs become distinct compiler jobs. The
fixed manager snapshot also adds a `LazyLock<Mutex<_>>` to the final binary. It
is forced during the established DeferredInit hook-install boundary so the
first terrain draw does not pay initialization; it remains untouched during
plugin/data loading. These are real load-visible/preparation-footprint deltas.
The last load-to-gameplay-playtested startup baseline remains `9975b2e` until
the exact release artifact passes three cold starts with BaseObjectSwapper and
the representative mod list. Static tests and a release build cannot waive
that gate.

## Static validation

Validation completed under explicit target `i686-pc-windows-gnu`. The complete
OMV suite passed 468 tests with no failures or ignored tests, including:

- all close-terrain variants and fast/supplemental compiler inputs;
- zero supplemental texture operations in fast bytecode;
- exact representative byte, instruction, texture, and temporary budgets;
- numeric equivalence of the BRDF denominator rewrite;
- exact 64x1 payload layout, zero tail, and bitwise cache identity;
- A/B/A multi-entry draw-cache retention and every stale semantic key;
- exact publication snapshot epoch matching;
- shader-mode transition count and fallback-before-selection ordering;
- transactional texture and sampler restoration.

The supported optimized OMV build also passed. The reviewed candidate is
`target/i686-pc-windows-gnu/release/omv.dll`, SHA-256
`a8e653355240a6295c52440f6a4ba25487b7fa0d51909d97fc245756e030a4c0`.
The complete compiler test was then forced through the native x86 Microsoft
`d3dcompiler_47.dll`, SHA-256
`b35b96b1eb5539a3748b98643172681f9b74d0ec726b05f8c2c248c10888e9a5`,
rather than Wine's compatibility compiler. All 162 logical PBR templates,
covering 160 unique compiler inputs, compiled successfully in 200.48 seconds.
This closes the compiler-compatibility gate which previously rejected a
source-valid selector design; it does not substitute for GPU runtime evidence.

The candidate PE was also compared with the installed preceding test artifact,
SHA-256
`9a811b6c0c918fed0147ff728e27cc3f083614fe341916ded372a2bf21de9eb0`.
That artifact exposed the AMD regression; it is not the accepted startup
baseline. Both DLLs have the same nine sections, import-table size (`0x33fc`),
IAT size (`0x6b8`), imported DLL and symbol lists, three named NVSE exports and
ordinals, four-byte TLS raw-data range, `0x18` TLS directory, and absence of
delay imports. The current image grows by 12,288 bytes overall. Its material
section deltas are `.text` +6,272 virtual/+6,144 raw, `.data` +3,136/+3,072,
`.rdata` -2,208/-2,048, `.eh_fram` +12 virtual/unchanged raw, `.bss` +3,072
virtual, and `.reloc` -600/-512. This audit establishes the exact static
footprint delta; only the required cold-start playtest can establish startup
compatibility.

`cargo fmt --all -- --check` and `git diff --check` are the final hygiene gates.
Compiler proof establishes removed work; it does not establish gameplay FPS or
image correctness.

## Runtime acceptance

Use the same save, camera, resolution, weather, time, mod list, configuration,
and warm-up for each sample. Record at least 300 warm gameplay frames and
report median, p95, p99, worst non-transition frame, and consecutive frames
over 100 ms. Test:

- the original NVIDIA exterior through normal Proton/DXVK;
- the same NVIDIA system without DXVK where reproducible;
- the RX 6800 XT control;
- daylight with no portable-light contribution;
- night with Pip-Boy off/on, including a native-zero-light row;
- canopy companion geometry, an interior control, and alt-tab/reset recovery.

Accept only when the NVIDIA cliff is gone, visual output and portable-light
coverage remain correct, the AMD median returns within normal run-to-run noise
of its pre-candidate control rather than retaining the reported 5-10 FPS loss,
and all three cold starts reach gameplay. If either vendor gate fails, preserve
the static corrections but do not call this the complete performance fix.
