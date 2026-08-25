# Atom mod-compatibility contract

Status: contract and capability definitions are current for the implemented
Input, first-person camera, third-person camera, and native Ballistics
systems, including admission-time runtime-helper validation and the
post-activation ownership audit.

## Purpose and scope

This document defines what "compatible with Atom" means, which mod classes are
guaranteed compatible, which combinations coexist under stated rules, and
which behaviors are fully incompatible. It is the authoritative compatibility
reference; `docs/atom.md` records implementation state and runtime evidence.

Two guarantees are distinct:

- **Crash safety**: another mod's presence never causes undefined behavior,
  memory corruption, or a crash through Atom's hooks.
- **Capability preservation**: Atom's features keep working alongside another
  mod.

Crash safety is guaranteed for every mod class below except the hard
incompatibilities, whose writers violate shared-code ownership rules that no
hooking framework can survive. Capability preservation is always scoped: when
a required seam is unavailable or displaced, exactly that capability degrades
to native behavior and every other capability stays active.

Atom never identifies, inspects, patches, reorders, disables, or adds a
compatibility path for another mod by name. Every rule here is
capability-based; plugin names appear only as examples of a class.

## Guaranteed-compatible classes

| Class | Mechanism | Notes |
|---|---|---|
| Content and data mods (weapons, projectiles, ammo, perks) | Runtime classification from live form type, flags, explosion link, and launch arguments (`docs/atom_ballistics_core_plan.md`). No ESP, load-order slot, or form-ID dependency exists. | Mod-added discrete hitscan/physical rounds participate automatically; beams, flames, continuous emitters, explosives, grenades, and thrown projectiles remain native by capability. |
| Animation packs and graph providers (kNVSE-class) | The hip-fire adapter chains whatever complete entry owner exists at `AnimData::MorphToSequenceIDOrGroup`; immutable interior fingerprints reject only unsupported executable bodies. | kNVSE's internal custom path and blend hooks stay in the same resolution chain. |
| Script-driven projectile spawns (script extenders, quest scripts) | The same launch callsite and thread/form-scoped policy slots serve any source. Unknown sources, targeted launches, `always-hit`, and `ignore-gravity` launches remain native. | Observed callback-thread sets are handled; policy slots are keyed by Windows thread ID with nested-frame restoration. |
| Graphics wrappers and deferred graphics plugins | First-person render callsites install at the first post-Deferred `MainGameLoop`, capturing every deferred wrapper as typed predecessor so Atom's pose encloses the whole graphics transaction. | Proven with OMV in both plugin orders (`.reports/atom-omv-camera-chain-2026-08-16.txt`). |
| Earlier hook owners at any hooked address | Callsite hooks capture the live call target; entry hooks relocate a complete existing entry jump into the trampoline; pointer-slot hooks CAS-chain the current value. Installation order does not matter. | Field-proven against trampoline-based predecessors on UpdateCamera, bound actions, movement scope, hip-fire pose, keyboard sampling, and the ranged-launch chain. |

## Coexistence rules

One owner per output. When two mods can own the same output, these rules
decide who acts:

| Output | Rule |
|---|---|
| Ranged-fire launch seam (`0x005245BD`) and hitscan-policy seam (`0x009B7D08`) | Native aim/fire patchers (Third-Person-Aim-Fix-class DLLs that hook these interior calls) must initialize **before** Atom so Atom captures them as chained predecessors. A provider that re-asserts its hooks after Atom — typically a Detours-style restore-cached-original then re-patch at first game load — displaces both capabilities; the `[INTEGRITY]` WARNs then name them with the live call target, and the ballistics summary's `Detour entries` counters prove whether execution survives (advancing counter = chained; frozen = bypassed). Remediation is load order only: move the provider above Atom. Atom never overwrites a later writer back. |
| Ranged aim convergence | One convergence owner. Atom admits muzzle convergence only when both native aim callsites are unowned at DeferredInit; otherwise interaction alignment alone is offered and convergence stays with its existing owner. |
| Projectile flight policy | Composable. A foreign forced-physical result reads as `AlreadyPhysical`; unmatched forms and contexts stay untouched. |
| Third-person camera ownership | Native hard-owner states (VATS, menus, TFC, POV, death, furniture, disabled controls) always win. Arbitrary scripted or vehicle owners must claim ownership through `AtomCamera_SetExternalOwner(u32 token, u8 active)` — a stable nonzero token acquires, `active = 0` releases, return `1` means accepted. While any token is active Atom performs no camera, movement, facing, or aim write. An owner that takes camera control without native owner state and without this token will fight third-person follow; that combination is unsupported until its author adopts the token. |
| Player locomotion policy | Mechanically composable via chained movement calls, but two semantic rewrites of locomotion direction (Atom 360 Movement plus a script/skeleton 360 system) double-apply intent. Use one. Joint playtest is required before claiming coexistence with a specific provider class. |
| Keyboard event stream | Atom mirrors ordered events to later consumers and answers later normal/peek requests in order while enabled. Other `GetDeviceData` consumers keep receiving their data; a second consumer that drains the same DirectInput buffer outside FNV's sample competes for events rather than duplicating them. |
| XInput state | Atom writes only FNV's current XInput slot after the engine copies processed state, and only while its controller transform is active. External slot writers race last-writer-wins per frame; no corruption is possible. |

## Fully incompatible behaviors

A mod with any of these behaviors is incompatible regardless of name:

1. **Unchainable patching of shared engine locations.** Blindly overwriting a
   function entry, an interior call instruction, or a vtable slot without
   preserving the previous owner breaks whichever component installed later:
   if it installs after Atom, Atom's capability silently stops applying
   (detours stop firing; no stale bytes are ever restored); if it installs
   before Atom with a partial or non-relocatable patch, Atom fails closed and
   leaves that capability native. Neither direction crashes, but the affected
   features cannot coexist.
2. **In-place edits of directly-called helper bodies are diagnosed, not
   fatal.** Atom validates only that each fixed helper entry (projectile
   launch, termination, clearance raycast, effective speed) is mapped
   executable memory before calling it; a failure disables ricochet's child
   path while Physical Rounds stay active. Interior-body differences from
   the researched binary are reported as one named WARN per helper and
   never disable anything: ecosystem patchers either hook entries with
   ABI-preserving jumps or edit instructions in place, and both remain safe
   to call through. An ABI-breaking rewrite of these four helpers is the
   one residual unsupported case — recorded here as accepted risk with
   visibility rather than a crash-safety claim.
3. **Runtime self-unloading or byte-restoring hook providers.** Atom's typed
   predecessors must remain mapped and unmodified for process lifetime. A
   framework that unloads itself or restores saved vanilla bytes at game
   start violates that contract and is unsupported.
4. **Second forced-owner conflicts.** Running another global flight-policy
   converter that mutates completed projectile objects or forms, or another
   unconditional camera-position writer without native owner state, cannot be
   reconciled by Atom because correctness requires exactly one owner; see the
   coexistence table for the boundary each one observes.

## Ownership audit

Every committed hook registers an auditor at installation. The audit runs off
the hot path — once after post-Deferred render installation and on each
requested diagnostics summary — and classifies each location as owned,
dormant (never activated), or lost (another writer took it after activation).

An all-owned result is logged at `DEBUG`. Each lost capability is one `WARN`
naming the capability and, for pointer slots, the observed replacement value;
it never names the displacing module. Displacement is inert by design: Atom
never restores bytes over a later writer and never crashes because of it, but
the affected behavior stays inactive until restart. A WARN therefore means
"this Atom capability is not applying in this session", not instability.

## Residual non-guarantees

Stated explicitly so users and maintainers know what is proved versus
assumed:

- The ricochet child spawn rebuilds base-form, source, weapon, and cell
  pointers from snapshots taken inside one synchronous impact callback and
  verifies them unchanged across the predecessor execution before use. Within
  vanilla semantics this proves liveness. It is a proven invariant, not an
  absolute guarantee against a chained predecessor that frees and reallocates
  identical-looking objects inside that single call; no known mod does this.
- Concurrent writers to a shared pointer slot resolve last-writer-wins. Atom
  detects the outcome through the ownership audit; it cannot prevent it.
- Ballistics telemetry has observed two callback threads in one session. All
  shared Ballistics structures are atomic and thread-keyed, but sessions with
  many concurrent launcher threads could exhaust the eight policy slots;
  exhausted scopes leave that round native.

## Evidence

- Fail-closed field behavior: `.reports/atom-2026-08-22-child-hook-install-failure.log`
  (fingerprint mismatch left Ballistics native), `.reports/atom-2026-08-22-launch-owner-gate-failure.log`
  (non-vanilla seams kept ricochet observe-only).
- Chained-predecessor field evidence: predecessor addresses recorded in those
  logs show trampolines, xNVSE wrappers, d3d9 wrappers, and foreign launch
  owners captured and preserved.
- Hook-chaining proof: `libpsycho` inline/callsite tests demonstrate
  second-owner chaining in both directions plus ownership tri-state checks.
- Runtime-helper body evidence: `analysis/radare2/output/perf/fnv_ballistics_runtime_helper_contract.txt`.

## Acceptance and unresolved items

Static gates follow `docs/atom.md`. The following remain owner-run runtime
acceptance and are not claimed by static evidence:

- One cold Proton load-to-gameplay replay of the artifact containing helper
  validation and the ownership audit, expecting an all-owned `[INTEGRITY]`
  DEBUG line and unchanged gameplay.
- Optional displacement drill: with a deliberately blind patcher installed
  after Atom, confirm the matching `[INTEGRITY]` WARN identifies exactly the
  affected capability and gameplay continues.
