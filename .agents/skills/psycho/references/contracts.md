# Contracts and checklists

## Hook selection

| Mechanism | Use when | Do not use when |
|---|---|---|
| Inline hook | You must intercept a shared function entry and call the predecessor. | The target is a provider boundary whose predecessor must never run while replaced. |
| Callsite hook | One exact `E8 rel32` call site owns the behavior and the current target must be chained. | The call is indirect, the target is not `E8 rel32`, or ownership cannot be proven. |
| Pointer-slot hook | A stable engine function-pointer or dispatch slot is the contract. | The slot is not proven stable, aligned, or live for the hook lifetime. |
| Replacement hook | A complete provider entry is replaced and the predecessor must not be callable. | Callers or the engine still need the original implementation. |
| Owned code patch | A fixed instruction block must change and exact restoration is required. | The bytes are not an exact signature or the instruction cannot be kept quiescent. |
| IAT hook | The contract explicitly owns an import-table edge. | The provider can be chained at a safer call or pointer boundary. |
| VMT hook | A live vtable slot is the proven contract and all callers tolerate replacement. | The object lifetime, slot identity, or thread ownership is unproven. |

Prefer the least invasive mechanism that proves the contract. Never overwrite
another component's provider without preserving it.

## Hook installation checklist

1. Verify the binary identity and exact signature.
2. Define the native function type with the correct calling convention.
3. Prepare every fallible allocation, trampoline, and signature check before
   enabling any behavior-changing hook.
4. Record the predecessor/current target and validate it.
5. Install related hooks and patches inside one `ModificationTransaction`.
6. Commit only after every required activation succeeds.
7. On failure, roll back owned changes and preserve the valid state.
8. Log the stable subsystem tag, the installed hook name, and the fallback.
9. Add a dashboard feature bit and counters only when support needs them.
10. Ensure the disabled path does no work and passes through unchanged.
11. Keep installation at the documented lifecycle boundary.
12. Re-check ownership on enable/disable; never blindly restore bytes.

## Config ownership

| Layer | Owns |
|---|---|
| `psycho-engine-fixes/src/config.rs` | Immutable process config, defaults, raw migration, validation. |
| `psycho-engine-fixes/config/psycho_engine_fixes.toml` | Shipped user-facing defaults and comments. |
| `psycho-engine-fixes-helper/src/dashboard_config.rs` | Restart-only editing of the same TOML. |
| `omv/src/config.rs` | OMV TOML, presets, Current Look, sanitization. |
| `atom/src/config.rs` | Read-only `Atom.ini` snapshot. |
| `atom/mcm/Atom.json` | MCM Extender UI and persistence keys. |

Rules:

- Core config is parsed once and published immutably.
- The helper never mutates the running core's config. Dashboard saves apply on
  the next launch.
- Atom and MCM settings apply from `MCMExtUpdate` after the INI save.
- Unknown keys are preserved where the owner supports forward compatibility.
- Deprecated fields retain serialized position and round-trip.
- Sanitize every untrusted float: reject NaN/Inf, then bound.
- Keep native defaults and MCM/JSON defaults equal.
- Keep every visible MCM string to one to three words.
- Never poll configuration every frame.

## Dashboard and helper ABI

- `psycho-engine-fixes/src/command_api.rs` is the core ABI.
- `psycho-engine-fixes-helper/src/engine_fixes.rs` is the exact mirror.
- Bump `DASHBOARD_ABI_VERSION` on layout changes.
- Preserve the published prefix; append new fields.
- Reject a mismatched size or version as unavailable.
- Every crossing field is a fixed-width scalar.
- No Rust allocation, pointer, enum, or `String` crosses the DLL boundary.
- The helper resolves exact exports with `GetModuleHandle`/`GetProcAddress`.
- The helper never loads or initializes the core DLL.
- Command output uses a caller-owned buffer; `written` is the full length even
  when truncated.

## D3D9 state

Set every state the pass depends on; never inherit it accidentally. Cover:

- pixel/vertex shader and constants;
- vertex declaration or FVF, stream sources, stream frequencies, indices;
- viewport, scissor, topology, half-pixel mapping;
- render target 0, unused MRTs, depth-stencil surface;
- depth/stencil enable, test, write, compare, clear;
- cull mode, winding, fill mode;
- alpha blend, alpha test, coverage, color write mask, multisample mask;
- sRGB write and texture decode;
- every used sampler: texture, filter, address mode, sRGB, mip LOD;
- texture-stage color/alpha ops and arguments;
- render-target feedback hazards.

Restore state through the owning transaction. Prove the exact invariants from
the real boundary or complete engine evidence. Do not add a mocked Rust test as
a substitute.

## Shader rules

- Compile every production entry point, macro family, quality tier, depth mode,
  and feature combination. Base-source compilation is insufficient.
- Inspect each compiled variant. Enforce shader-model, instruction, texture-op,
  sampler, flow-control, and prohibited-opcode budgets independently.
- Compilation proves syntax and ABI only, never image correctness.
- Do not reconstruct depth or normals with `ddx`/`ddy` after divergent control
  flow, early return, or clipping without seam-free proof.
- For point-sampled resources, reconstruct from the actual texel center.
- Respect D3D9 half-pixel and resolution mapping.
- Handle standard/reversed depth, clear/sky endpoints, invalid samples,
  quantization, and near/far limits explicitly.
- Reject NaN/Inf at the source; do not clamp over an unknown coordinate bug.
- Keep variants specialized. Disabled families do no hidden work.
- Preserve accepted equations, sample distributions, filters, temporal
  behavior, and composition unless the change proves equal or better quality.
- Render callbacks never compile shaders, read files, allocate routinely,
  log per draw/pixel, or block.

## Logging

Use `libpsycho::logger::Logger` and the `log` facade.

| Level | Use |
|---|---|
| `debug` | Validated addresses, hook ownership, technical detail. |
| `info` | Lifecycle milestones, configuration, user-requested summaries. |
| `warn` | Recoverable degradation and the resulting fallback. |
| `error` | A requested capability cannot remain available or correctness is lost. |

- Include a stable subsystem tag, for example `[MEMORY]` or `[SHADERS]`.
- State the consequence, not only the low-level failure.
- Initialize logging only at the subsystem's documented safe boundary.
- No `println!` or `eprintln!` in production.
- No per-frame or per-draw logging.
- Aggregate high-frequency telemetry; file output flushes every record.

## Unsafe code

- Keep `unsafe` in the smallest auditable boundary.
- Document the safety contract: pointer validity, size, alignment, lifetime,
  aliasing, initialization, ABI, and thread conditions.
- Validate external data and engine pointers before dereference.
- Use `checked_add`, `try_into`, and bounded reads.
- Never unwind across FFI. Release builds use `panic = "abort"`.
- An `unwrap` or `expect` in production needs a locally proven invariant and a
  comment explaining why recovery is impossible or incorrect.
- Never use `unsafe` to bypass a sound ownership design.

## Documentation template

Authoritative feature/contract documents use:

```markdown
# <Feature> contract

Status: <implemented | static-only | runtime-accepted | superseded>
Last updated: <YYYY-MM-DD>

## Purpose and scope
## User-visible behavior
## Evidence
## Native contract
## Ownership and lifecycle
## Failure behavior
## Performance
## Configuration and compatibility
## Validation
## Unresolved
```

Reverse-engineered documents additionally record executable identity, addresses
or call chain, layouts, ABI, intervention point, and evidence paths. Separate
runtime proof, binary proof, static observation, and unresolved facts.
