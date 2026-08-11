# OMV NVIDIA Close-Terrain Shader-Lowering Implementation

Date: 2026-08-11

Status: implemented and statically validated in the worktree. Cold-start
compatibility, visual acceptance, AMD control, and the affected NVIDIA A/B
remain required. This document does not claim that the NVIDIA performance
defect is fixed at runtime.

## Purpose and result

OMV's close-terrain pixel shader retained expensive per-pixel constant
selection after earlier hook, lifecycle, light-cache, and shader-tree fixes.
The cost was structurally present on every GPU, but the observed multiplier was
vendor-specific: an RX 6800 XT sustained about 120 FPS while tested NVIDIA
systems remained catastrophically slow both with and without DXVK.

The implementation removes the OMV supplemental-light constant selector from
the shader. It stores the same fixed light records in an OMV-owned 32x2
RGBA32F texture and reads two texels for each supplemental light. Native terrain
lights retain the established VPT constant ABI and compile-time row shapes.
The engine still selects one replacement shader pair and issues one native
draw. No feature, light, terrain layer, material equation, or fallback row is
removed.

The original split-constant-array plan is preserved in
`graphics_fnv_omv_nvidia_close_terrain_shader_fix_plan.md` as a rejected design
record. This document is the authority for the implemented design.

## Evidence classification

### Runtime observations

- The same OMV native-PBR workload performs normally on the RX 6800 XT control
  and poorly on the tested NVIDIA systems.
- The NVIDIA result is unchanged with and without DXVK. This rejects DXVK
  alone as the owner, but it does not identify proprietary driver machine code
  or a particular GPU stall.
- Earlier hook/state ownership and binary selector-tree corrections were
  necessary correctness changes but did not materially improve the affected
  NVIDIA result.

These observations motivate the intervention. They do not prove that the new
artifact fixes the runtime defect.

### Compiler proof

The planned separate arrays looked like the closest HLSL equivalent to modern
NVR, but the Phase 0 experiment rejected them. A permanent compiler micro-test
compiles both split and interleaved dynamic constant-array programs under the
production `ps_3_0` flags. The repository Wine/VKD3D compiler route emits no
relative constant read for either form; it lowers both to compare/select work.
The exact `d3dcompiler_47.dll` from the game prefix produced the same negative
result for the split-array prototype. Flow-control flags did not change that
outcome.

`dynamic_constant_arrays_do_not_compile_to_relative_reads` preserves this
negative result. A future cleanup must not restore split dynamic arrays merely
because the HLSL source looks direct; the compiled bytecode is the contract.

The production regression reconstructs the old interleaved `c92..c139` lookup
inside the otherwise current shader. Under the repository compiler it requires
at least 80 more `cmp` instructions than the texture implementation. The
production program has no supplemental relative constant reads and exactly two
supplemental `texldl` operations in source, which compile to two additional
texture instructions per program path.

### Reasoned inference

The remaining best causal model is that NVIDIA lowers or executes OMV's
shader-model-3 constant-selection/control-flow shape far less efficiently than
the tested AMD path. Replacing a per-pixel, per-light constant selector with
two direct texture reads removes that shape without a vendor branch. Static
bytecode establishes the removed work but cannot prove the final NVIDIA GPU
time. The controlled A/B remains the attribution gate.

## Shader and CPU ABI

Native VPT ownership is unchanged:

| Binding | Meaning |
|---|---|
| `c39..c62` | native point-light colors |
| `c63..c86` | native point-light positions and radii |
| `c88.x` | native point-light count |
| `c89/c90` | OMV terrain material controls |
| `c91.x` | OMV supplemental point-light count |
| `s14` | temporary OMV supplemental shader-data texture |

The former OMV payload at `c92..c139` no longer exists. `c91` is uploaded on
every admitted close-terrain draw, including zero, so a later empty draw cannot
reuse an earlier count.

The 32x2 texture has this exact layout:

- row 0, columns `0..23`: position XYZ and radius;
- row 1, columns `0..23`: RGB light color and reserved alpha;
- columns `24..31` in both rows: zero.

All 64 texels are initialized for every upload. Clearing the unused columns is
defensive containment: even a corrupt count cannot reveal a previous draw's
light record. It does not expand the accepted count beyond 24.

The shader reads column `i` at normalized X `(i + 0.5) / 32` and the two row
centers at Y `0.25` and `0.75`, using explicit LOD zero. Width 32 is a power of
two, so these centers are exactly representable. The reads therefore remain on
one texel even when the engine-owned sampler inherits linear filtering; wrap
mode is irrelevant at an interior texel center. OMV does not mutate sampler
filter or address state.

Native lights still use the existing compile-time constant-index selector
because those constants belong to the engine ABI and vary by the native
`0/6/12/24` row family. Supplemental lights use the texture loader. Both feed
one `PointLightContribution` helper and retain:

- native-first order;
- combined cap 24;
- identical position, radius, RGB, attenuation, tangent transform, and PBR
  evaluation;
- RGB-only visibility semantics;
- the same `0.001` attenuation gate;
- one combined dynamic light loop.

## Resource and draw ownership

`effects/pbr/device_resources.rs` owns one
`DynamicRgba32fTexture9` beside the close-terrain shader family. The texture:

- is one mip, `D3DFMT_A32B32G32R32F`, `D3DUSAGE_DYNAMIC`, and
  `D3DPOOL_DEFAULT`;
- is keyed by both D3D device identity and lifecycle generation;
- consumes one slot from the existing four-resource-per-frame creation budget;
- is required before close-terrain family readiness is published;
- is dropped and recreated with the other default-pool resources on reset;
- fails the complete close-terrain family closed if creation fails.

The reusable Direct3D wrapper records immutable dimensions at construction.
`write_discard` validates the exact texel count, locks level zero with
`D3DLOCK_DISCARD`, honors the returned row pitch, copies two bounded rows, and
always attempts `UnlockRect`. It performs no descriptor query in a draw
callback. The public wrapper, format constant, constructor, and upload method
are documented in `libpsycho/src/os/windows/directx9.rs`.

At an admitted close-terrain draw:

1. OMV restores any stale temporary s14 binding from an earlier failed
   boundary. If restoration still fails, the draw falls back rather than
   submitting mixed ownership.
2. The existing sampler contract and native wrapper ownership are validated.
3. Supplemental lights are reconstructed or loaded from the fixed atomic draw
   cache.
4. When the supplemental count is nonzero, OMV requires s14 to be either a
   known engine binding or known-null in the `SetTexture` mirror. Unknown state
   fails closed because clearing it after the draw could overwrite a binding
   installed before the observer hook existed.
5. A 1 KiB stack payload is encoded, discard-uploaded, and bound to s14 through
   a raw D3D call.
6. OMV publishes one atomic bit recording that s14 is temporarily borrowed.
   It deliberately does not update the engine `SetTexture` mirror.
7. `c89..c91` are uploaded and the native draw proceeds with the engine-owned
   replacement shader pair.
8. Draw completion restores the exact engine-owned s14 identity from the
   authoritative mirror, or clears s14 when the mirror records known-null.

Native fallback, batch completion, runtime disable, and resource release all
perform the same restoration. A failed restoration retains the ownership bit
and prevents a successful fallback claim. This prevents vanilla terrain from
being submitted with OMV's data texture and prevents an OMV texture from
escaping its draw scope. Only a proven D3D lifecycle-generation transition may
discard that retained marker, because the old device state is then invalid.

Render callbacks never acquire a blocking resource lock. Texture upload uses
the existing resource owner's `try_lock`; contention or a stale device
generation rejects only the draw and retains native behavior.

## Module ownership

| File | Ownership |
|---|---|
| `omv/shaders/embedded/native_pbr_pplighting_close_terrain.hlsl` | native ABI, texture lookup, common point-light evaluation, and combined light cap |
| `omv/src/effects/pbr/terrain_lights.rs` | fixed light selection/cache and 32x2 payload serialization |
| `omv/src/effects/pbr/constants.rs` | `c89..c91` final-writer upload |
| `omv/src/effects/pbr/device_resources.rs` | per-device texture creation, readiness, upload, and reset lifetime |
| `omv/src/effects/pbr/hooks.rs` | draw-scoped s14 transaction, fallback, and restoration |
| `omv/src/effects/pbr/shader_registry.rs` | ABI, negative compiler controls, bytecode inspection, and budgets |
| `libpsycho/src/os/windows/directx9.rs` | narrow dynamic RGBA32F texture abstraction |

The module-level documentation in these owners describes the same boundaries.
Complex state and lowering decisions are also recorded beside the code that
enforces them; public Direct3D APIs carry docstrings and safety contracts.

## Performance and memory costs

The persistent GPU allocation is 1,024 bytes of texel data plus driver object
overhead. A nonempty supplemental draw uses a 1,024-byte stack buffer, one
discard lock/unlock, one temporary `SetTexture`, and one restoring
`SetTexture`. Empty supplemental draws perform none of that texture work and
still upload `c91 = 0`.

The trade is intentional: a bounded CPU upload and two texture reads replace a
large constant selector executed per pixel and per supplemental-light
iteration. No shader variant, draw, render pass, material sample, blocking
lock, allocation, state query, file I/O, compilation, or repeated log is added
to the draw path.

Repository-compiler metrics for representative base rows are:

| Row | Meaning | Before bytes / instructions / textures | Current bytes / instructions / textures |
|---|---|---:|---:|
| SLS2092 | 1 layer, 0 native lights | 8,236 / 538 / 2 | 6,940 / 419 / 4 |
| SLS2098 | 1 layer, 24 native lights | 10,580 / 726 / 2 | 9,416 / 612 / 4 |
| SLS2140 | 7 layers, 0 native lights | 9,592 / 623 / 14 | 8,296 / 504 / 16 |
| SLS2146 | 7 layers, 24 native lights | 11,936 / 811 / 14 | 10,772 / 697 / 16 |

The current control-flow counts are respectively `cmp/ifc/rep` = `36/2/1`,
`62/26/1`, `48/2/1`, and `74/26/1`. The remaining comparisons and branches
belong primarily to the retained native ABI selector and material/light
control. The supplemental constant selector itself is absent.

## Compatibility and startup boundaries

No configuration field, schema version, preset payload, HLSL compiler flag,
shader template, hook, worker, TLS value, dynamic draw, vendor detection, or
other-mod compatibility path is added. `.research` remains read-only.

This change does add code and one D3D resource type to the final OMV binary, so
the complete pre-Deferred footprint differs from the last load-to-gameplay
accepted baseline even though the resource is created only by the established
post-Deferred Present service. Static tests and a release build cannot certify
startup compatibility. The prior accepted baseline remains authoritative until
the exact release artifact passes at least three cold starts with the
representative modlist and BaseObjectSwapper installed. Do not update the
startup errata or claim a new accepted baseline before that result.

## Static validation

Validation completed on 2026-08-11 under the explicit supported
`i686-pc-windows-gnu` target. The complete OMV suite passed 465 tests with no
failures or ignored tests. Its PBR coverage includes:

- every registered PBR shader variant compiling through the repository route;
- the split/interleaved dynamic-array negative control;
- rejection of the old production constant cascade;
- exact c91/s14 HLSL ABI and payload layout;
- native/supplemental combined-cap and membership equivalence;
- resource lifetime, generation, readiness, and nonblocking architecture;
- draw-scoped upload/publication/restoration ordering;
- representative bytecode size, instruction, texture, and control-flow
  budgets.

The optimized OMV build completed successfully. The reviewed candidate is
`target/i686-pc-windows-gnu/release/omv.dll`, SHA-256
`f274016f75f400025cad9f585744039d54091a0475d94ecebfdf568de5840eff`.

The exact native x86 Microsoft compiler artifact used for the compatibility
sweep was
`/home/acidpointer/.local/share/lutris/runtime/d3d_extras/v2/x32/d3dcompiler_47.dll`,
SHA-256
`b35b96b1eb5539a3748b98643172681f9b74d0ec726b05f8c2c248c10888e9a5`.
With native loading forced, all 33 PBR shader-registry tests passed in 238.34
seconds. That includes every registered PBR variant, every close-terrain
base/canopy row, the removed-cascade control, the split-array negative control,
and representative bytecode budgets. A separate native Microsoft compile of
all 28 unique close-terrain layer/light programs also passed.

The installed pre-change comparison DLL, whose production source matches the
documented `9975b2e` load-to-gameplay baseline, has SHA-256
`2b132f7047b71f65c3f1dd3a2e26cccbe54c449eb40336d4b5812899bc4b0ca0`.
The PE audit against it found:

- the same import DLL list and no delay-import change;
- the same three exports, names, and ordinals;
- the same eight-byte zero-initialized `.tls` section and TLS-directory size;
- unchanged `.bss` size;
- `.text` +3,904 bytes, `.data` +1,120 bytes, `.rdata` -2,912 bytes,
  `.eh_fram` +728 bytes, and `.reloc` +1,120 bytes;
- `SizeOfImage` increased by one 4 KiB page.

The source audit found no config/schema/preset, hook, worker, compiler-flag,
template-count, `LazyLock`, mutex, or TLS-owner addition. The new atomics and
resource-owner fields are the expected state delta. The resource itself is
created only by the existing post-Deferred Present service.

`cargo fmt --all -- --check` and `git diff --check` are the final repository
hygiene gates. Compiler, PE, and repository validation establish static
integration; they do not replace startup, image, or runtime performance proof.

## Runtime acceptance

Use the controlled matrix from
`graphics_fnv_omv_nvidia_1fps_remediation_plan.md` with the exact reviewed DLL.
At minimum capture the original exterior, a no-portable-light daylight scene,
a Pip-Boy night scene including a native-zero-light row, canopy geometry, an
interior control, and reset/alt-tab recovery on:

- the affected NVIDIA system through normal Proton/DXVK;
- the same NVIDIA system without DXVK when reproducible;
- the RX 6800 XT control.

Record at least 300 warm gameplay frames per sample and report median, p95,
p99, worst non-transition frame, and consecutive frames over 100 ms. Accept
only if the catastrophic NVIDIA PBR cliff is gone, NVIDIA PBR-on median is no
more than 1.5 times the same-scene PBR-off median, AMD does not regress by more
than five percent without investigation, all lights/materials remain visually
correct, reset restores rendering, and three required cold starts succeed.

If the affected NVIDIA gate still fails, retain these correctness and bytecode
improvements but do not call them the performance fix. Preserve the results
and isolate the next longest driver-facing interval before changing coverage
or quality.
