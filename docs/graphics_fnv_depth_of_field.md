# FNV depth-of-field pipeline

## Purpose and user-visible behavior

OMV provides an engine-side near/far depth-of-field effect with automatic or
manual focus, vanilla-DOF arbitration, round or soft blur shapes, and balanced,
high, or ultra gather quality. It runs after its required scene inputs are
available, preserves the engine target's alpha, and never replaces native
Fallout New Vegas DOF while `respect_vanilla_dof` grants native ownership.

Configuration belongs to
`graphics.embedded_effects.depth_of_field` in `omv.toml` and the OMV workbench.
It is visual configuration and may participate in presets. The selected depth
provider is a separate machine-local option and is never captured by a preset.

The RTX 5060 tester measured approximately 4-5 FPS of incremental DOF cost at
3440x1440. That is a runtime observation on one machine, not a universal
performance result. Static source proves the work described below but cannot
predict the delivered FPS improvement.

## Architecture and ownership

`omv/src/effects/depth_of_field.rs` owns shader preparation, device shader
objects, focus history, intermediate targets, pass ordering, D3D state, and
runtime sanitization. HLSL sources under `omv/shaders/embedded/dof_*.hlsl` own
the per-pass equations. `omv/src/runtime.rs` owns applicability preflight, the
outer all-state/attachment transaction, scene-color copy, device reset, and
master-off resource teardown.

Shader bytecode is prepared by the named `omv-dof-compile` worker. Device
objects are created on the render thread only after all variants are ready.
An unavailable input, active native DOF owner, compile failure, or target
creation failure rejects the OMV pass without weakening settings or silently
selecting a lower quality.

The complete pass graph is:

1. update the 1x1 focus history;
2. derive signed full-resolution CoC from world and optional first-person
   depth;
3. prefilter scene color and CoC to half resolution;
4. when near blur is enabled, reduce, dilate, and smooth a conservative near
   mask;
5. gather the far layer when requested;
6. gather the near premultiplied layer when requested;
7. for soft style, filter each requested layer twice;
8. bilateral-upsample far, upsample near, and composite over scene color.

Focus history uses two scalar 1x1 render targets. Full CoC uses the supported
R16F scalar format, falling back to G16R16F. Prefilter, far, and near layers use
A16B16G16R16F at half resolution. Near mask intermediates use the scalar
format. Targets are recreated only when size or scalar format changes and are
released on device loss, individual DOF disable, or master disable.

## GPU and D3D9 performance contract

The optimization preserves the pass graph, resolution, formats, gather tap
counts, blur radii, focus/CoC equations, and alpha composition.

The CPU-side command path now uploads common frame and projection constants
once. Each pass changes only c8 when its target dimensions change, plus its
documented c9/c10 pass constants. The proven sampler ABI is s0-s4; target
changes clear only those five stages instead of s0-s9. Pipeline setup explicitly
defines clamp, filter, mip, sRGB, cull, blend, alpha-test, depth, stencil,
scissor, color-write, and sRGB-write state. The enclosing all-state transaction
restores engine state after the effect.

Every pass uses one three-vertex full-screen triangle with the D3D9 half-pixel
offset. Rasterized pixel-center UVs remain identical to the previous strip,
while the fourth transformed vertex and diagonal strip boundary are removed.

Gather shaders are specialized by quality and blur style. Round variants do
not evaluate the soft exponential or a per-pixel uniform shape branch. Soft
variants retain the configured softness interpolation but use the fixed
rotation required by the soft contract. Soft-layer filters are specialized as
near or far, so compatibility selection is not repeated inside every tap.

High/ultra near composition retains the exact separable
`[1 2 1]^2 / 16` reconstruction kernel. The shader derives the fractional
full-to-half-resolution phase, combines the four resulting discrete weights
into two positive linear reads on each axis, and takes their Cartesian product.
This produces the same clamped nine-sample result with four texture
instructions. Fixed half-texel offsets are intentionally not used because they
would change weights on alternating full-resolution pixels. The equivalence
relies on the explicitly bound linear near-layer sampler and is covered by a
deterministic CPU reference test across subpixel phases and image borders.

No D3D query, allocation, file I/O, shader compilation, log formatting, or
blocking lock occurs in the admitted steady-state draw.

## Failure and compatibility boundaries

World camera availability, depth convention, and at least one near/far
consumer are mandatory. First-person depth is optional; its strength applies
only when that texture and camera snapshot are both valid. Vanilla DOF
arbitration resets the OMV resume mix and then eases back over the documented
resume interval when native ownership ends.

All temporary resources are OMV-owned COM references. OMV never patches the
game's DOF shader, changes engine target formats, evicts device-global managed
resources, or reads back GPU data. The outer render transaction restores all
render targets and depth/stencil attachments before applying the captured
state block.

## Validation and runtime acceptance

The OMV shader suite compiles every focus, CoC, prefilter, near-mask, round/soft
gather, near/far soft-filter, and compose variant for `ps_3_0`. Static tests
also cover applicability and the enclosing transaction ordering. The supported
commands are:

```text
cargo test --target i686-pc-windows-gnu -p omv
cargo build --release --target i686-pc-windows-gnu -p omv
git diff --check
```

On 2026-07-29, all 417 OMV tests passed under Wine, including every DOF shader
variant, static work budgets, and the phase-and-border CPU equivalence test for
the four-sample near reconstruction. The optimized `i686-pc-windows-gnu` OMV
release target built successfully.

Runtime acceptance must use the same save, camera, resolution, depth provider,
and presentation mode before and after the build. Measure balanced, high, and
ultra separately with near-only, far-only, and near+far subjects; repeat round
and soft styles. Verify automatic/manual focus, weapon/first-person separation,
sky and distant blur, odd target dimensions, vanilla DOF handoff/resume,
forward/reversed depth, device reset, and master off/on. Static validation
does not replace this image and frame-time playtest.
