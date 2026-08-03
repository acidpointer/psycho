# Encounter-zone invalid form guard

## Status and purpose

Implemented and playtested on 2026-08-03 in `psycho-engine-fixes`. The first
live run reached game-ready and exposed a parent-cell handoff race in the repair
path. A second run with the final captured-cell/compare-exchange hardening
contained the affected load, sustained save/reload gameplay, and exited cleanly.

The guard prevents an unresolved, mistyped, unregistered, or otherwise invalid
form pointer from crossing the engine's optional encounter-zone boundary as a
`BGSEncounterZone*`. It repairs only an exact invalid source, re-runs the native
reference -> cell -> worldspace priority lookup, and returns NULL only when no
valid fallback remains or a safe repair cannot be proven. Valid zones and
unrelated extra data are unchanged.

The feature is owned by the early-loaded core DLL. The optional helper only
edits its restart-only setting and displays core-owned telemetry; it must not
load or initialize the core. The default-on configuration is:

```toml
[engine_fixes]
encounter_zone_invalid_form_guard = true
```

## Crash report and root cause

The supplied evidence is:

- `.reports/CrashLogger--menu-crash.log`;
- `.reports/psycho-engine-fixes-latest--menu-crash.log`.

CrashLogger records `EXCEPTION_ACCESS_VIOLATION` at `0x00567ECC` with
`EAX=ECX=0x00035AAA`. The native instruction is:

```asm
movzx ecx, word [eax + 0x2c]
```

It attempted to read `0x00035AD6`. The owning reference visible on the stack is
Fallout3.esm Filing Cabinet `06045097`, based on `FilingCabinetDC` `06014BD3`,
in interior cell Craterside Supply `06003A2A`. The cell is not loaded and is
last modified by `Cyberware TTW.esp`.

The direct defect is a non-NULL invalid value crossing
`FUN_00567D20 -> FUN_00567E10` as `BGSEncounterZone*`. `0x00035AAA` is
unaligned and cannot be a live x86 object. `FUN_00567EC0` then reads the zone's
16-bit field at `+0x2C` without another identity check.

The Psycho log independently records several small or FormID-shaped invalid
`ExtraOwnership.owner` values and skips one changed record whose source content
is unavailable. That supports a wider stale or unresolved form-reference
producer class, but it does not prove which component first wrote this
encounter-zone value. Memory pressure is excluded: the final watchdog sample
has about 2.4 GiB of free process address space and no allocator failure.

## Executable identity and evidence

The researched executable is `fnv_reverse/FalloutNV.exe`:

- format: PE32 x86;
- fixed image base: `0x00400000`;
- size: 16,084,808 bytes;
- COFF timestamp: 2011-07-01;
- SHA-256:
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.

Radare2 MCP was the primary research interface. The focused static audit is
preserved in
`analysis/radare2/output/encounter_zone_guard_contract.txt`. Existing analysis
also corroborates the surrounding load and form-reference contracts:

- `analysis/ghidra/output/crash/extraownership_load_contract_deep_audit.txt`;
- `analysis/ghidra/output/crash/extraownership_access_boundary_audit.txt`;
- `analysis/ghidra/output/crash/crash_00865dfb_stack_contract_deep_audit.txt`;
- `analysis/ghidra/output/crash/crash_00559456_callsite_fanout_audit.txt`.

### Reported call chain

```text
0x0086B669 main loop
  -> 0x00877658 cell transition / load owner
  -> 0x0084A867 changed-form load
  -> 0x008491AA reconstruction finalization
  -> 0x00843B62 TESForm InitItem loop (virtual slot +0x88)
  -> 0x0055E12E TESObjectREFR::InitItem
  -> 0x004D14D2 inventory-change initialization
  -> 0x00567E43 encounter-level selection
  -> 0x00567ECC invalid BGSEncounterZone field read
```

The reported reconstruction chain runs on the game main thread. The guard does
not assume that every other resolver caller is main-thread-only; exceptional
extra-list mutation uses the engine's own reentrant synchronization.

## Native resolver contract

`FUN_00421C30` calls `BaseExtraList::GetByType(0x74)` and returns the pointer at
`ExtraEncounterZone + 0x0C`. `FUN_00567D20` is a side-effect-free lookup in
this exact priority order:

1. reference `BaseExtraList` at `TESObjectREFR + 0x44`;
2. parent cell `BaseExtraList` at `TESObjectCELL + 0x28`;
3. parent worldspace encounter-zone field at `TESWorldSpace + 0xD0`.

The returned non-NULL object must be a registered `BGSEncounterZone` with:

- an aligned and readable TESForm header;
- primary vtable `0x0102CBBC` in the supported executable;
- `TESForm.typeID == 0x61` at `+0x04`;
- a `TESForm.refID` at `+0x0C` that resolves through `FUN_004839C0` back to the
  same pointer.

Registry equality proves current engine identity. It is not a lifetime pin
against a future out-of-contract concurrent destruction; native callers retain
their existing object-lifetime responsibility.

### NULL behavior of every consumer

`FUN_00567D20` has exactly nine direct call sites:

| Call site | Proven NULL behavior |
|---|---|
| `0x0054CACE` | May install the cell/default zone through `0x00567DD0`. |
| `0x0054E235` | Takes the accepted/continue path at `0x0054E25F`. |
| `0x00567848` | Skips zone use and can fall back through the parent cell. |
| `0x00567A50` | Skips zone use and can fall back through the parent cell. |
| `0x00567E23` | Reaches global encounter-level fallback `0x0087F9F0`. |
| `0x00881CD6` | Produces a true predicate result. |
| `0x0096EF20` | Skips the zone flag read at `0x00526320`. |
| `0x0099F108` | Substitutes `NoZoneZone` through `0x00546A90`. |
| `0x0099F116` | Substitutes `NoZoneZone` through `0x00546A90`. |

No direct consumer dereferences NULL. NULL is therefore the proven native
optional representation, not merely a convenient crash suppression value.
Guarding only `FUN_00567EC0` would leave the corrupt source available to the
other eight consumers and would not fix the shared contract.

## Load, save, and NULL propagation

Two type-`0x74` load paths have different ownership behavior:

- The master/plugin ExtraData loader resolves at `0x00417D4C`, performs RTTI
  at `0x00417D57`, stores at `0x00417D65`, and removes the extra after a NULL
  result at `0x00417D97`.
- The changed-form reader resolves at call site `0x00429F24`, performs RTTI at
  `0x00429F2F`, and stores at `0x00429F3D`. It can retain a type-`0x74` extra
  whose payload is NULL; it does not use the master/plugin removal branch.

The load defense wraps the changed-form call before RTTI. Returning NULL there
is still safe for both deeper paths:

1. `FUN_00421C30` reads a retained NULL payload as an absent reference, so
   `FUN_00567D20` continues to the cell and worldspace fallbacks.
2. The changed-form serializer passes `extra + 0x0C` to `FUN_00865DF0`, which
   tests NULL at `0x00865DF9` and writes FormID zero without dereferencing an
   object.

Runtime repair removes a non-NULL invalid reference/cell extra through the
canonical setter, so newly repaired state does not retain or reserialize the
bad pointer. Thus the fix contains the reported dereference without propagating
an unsafe sentinel into a later load, resolver, or save layer.

## Repair architecture

The shared hook validates the original resolver result. On rejection it traces
the same source priority and mutates storage only after exact equality proves
that a typed slot still contains the rejected pointer.

### Reference and cell extras

`BaseExtraList::GetByType(0x74)` locates the typed extra. The guard holds the
engine's reentrant extra-list lock at `0x011C3920` across lookup, equality, and
removal. The lock API is:

- acquire `FUN_0040FBF0` (`ECX=lock`, one stack diagnostic label, `ret 4`);
- release `FUN_0040FBA0` (`ECX=lock`).

`FUN_00421C60` is the canonical encounter-zone setter. Its NULL path calls
`FUN_00410140`, which removes and destroys type `0x74`. An outer lock is valid
because the engine lock is reentrant, and it closes the conforming-writer race
between pointer comparison and the setter's own nested mutation.

### Worldspace field

The native worldspace setter at `0x00584BC0` is a direct store to `+0xD0`.
The guard therefore clears that field only after readable and writable checks,
using an aligned compare-exchange whose expected value is the exact rejected
pointer. A concurrent legitimate replacement is never overwritten. No
independent heap object is owned by the field.

Worldspace resolution traverses the parent cell and reads `cell+0x24` and, for
an exterior, `cell+0xC0`. The exceptional path captures `owner+0x40` once,
proves the full `0xC4` cell range, and derives the worldspace from that same
captured pointer. It deliberately does not call `FUN_00575D70`, which would
re-read mutable ownership after the proof. A NULL, unreadable, interior, or
truncated cell stops repair; the guard never converts one rejected zone into a
deeper cell-pointer fault.

### Re-resolution and bound

After an exact repair, the hook calls the original pure resolver again. This is
necessary because removing a corrupt reference-level zone may reveal a valid
cell zone, and removing a corrupt cell zone may reveal a valid worldspace zone.
Returning NULL immediately would incorrectly hide those native fallbacks.

There are exactly three source levels, so the exceptional path performs at
most three resolution and repair attempts. If a source cannot be identified or
repaired, the guard returns NULL immediately. The bound also prevents a plugin
that continually repopulates a slot from causing an unbounded loop.

## Source ownership and startup ordering

Source ownership is:

- `psycho-engine-fixes/src/mods/engine_fixes/encounter_zone.rs`: module-level
  contract, validation, load-call chaining, resolver detour, synchronized
  repair, bounded re-resolution, and diagnostics;
- `psycho-engine-fixes/src/mods/engine_fixes/statics.rs`: fixed addresses and
  the typed inline-hook container;
- `psycho-engine-fixes/src/mods/engine_fixes/types.rs`: documented x86 ABIs;
- `psycho-engine-fixes/src/mods/engine_fixes/mod.rs`: configuration gate and
  startup installation;
- `psycho-engine-fixes/src/config.rs` and
  `psycho-engine-fixes/config/psycho_engine_fixes.toml`: public/default config;
- `psycho-engine-fixes/src/command_api.rs`: version-3 core dashboard counters;
- `psycho-engine-fixes-helper/src/engine_fixes.rs`, `dashboard.rs`, and
  `dashboard_config.rs`: late-bound ABI mirror, Runtime Fixes presentation,
  and restart-only config editing.

Installation occurs in the core engine-fix transaction after the existing
ExtraOwnership guard and before game-engine-ready publication. The shared
resolver hook is required because it protects all consumers. The changed-form
call wrapper is defense in depth; inability to install it emits a warning but
does not disable the required runtime boundary.

Both hook ABIs are fixed x86 contracts:

- `FUN_00567D20`: `thiscall(TESObjectREFR*) -> BGSEncounterZone*`;
- the call at `0x00429F24`: `cdecl(u32 saved_form_id) -> TESForm*`.

The load wrapper publishes the captured predecessor before patching the CALL.
It accepts an executable replacement target for capability-based chaining, but
it verifies the surrounding changed-form reader bytes so a direct CALL in an
unrelated executable revision cannot be mistaken for the audited ABI.

## Invariants and failure behavior

The implementation enforces these invariants:

1. Native NULL remains NULL and reaches no inspection or registry lookup.
2. A non-NULL candidate must be aligned, readable, exact-vtable type `0x61`,
   and identical to the engine registry entry for its FormID.
3. Invalid storage changes only after typed-slot and exact-pointer equality.
4. Reference/cell comparison and removal are one engine-lock transaction.
5. Lower-priority traversal occurs only after the layout it will read is
   proven accessible.
6. Successful repair preserves native priority through bounded re-resolution.
7. Failed proof returns NULL without speculative mutation.

If the original runtime trampoline is unavailable, the hook logs once and
returns NULL. If a captured load predecessor becomes recursive or
non-executable, the load wrapper logs once and uses native `FUN_004839C0`.
Warnings include the owner, cell, rejected value, reason, and repair source for
the first 16 events and power-of-two totals thereafter.

The guard never deletes an owning reference, cell, worldspace, or unrelated
extra. It does not special-case the reported FormID, save, or plugin name.

## Performance, memory, and compatibility

NULL returns immediately. A normal non-NULL result performs one page query,
fixed header reads, an exact vtable/type check, and one native FormID registry
lookup. It performs no allocation, blocking lock, file I/O, or logging.

Source tracing, the reentrant extra-list lock, writability checks, native
removal, worldspace compare-exchange, re-resolution, and formatted diagnostics
occur only after rejection.
Permanent memory consists of the inline trampoline, seven atomics for chaining,
telemetry, installation state, and once-only warnings, plus one static
diagnostic label; no per-form history exists.

The fix is allocator-independent and belongs in `psycho-engine-fixes`, not the
helper or gheap. The entry hook uses the repository's standard displaced-code
trampoline. The changed-form wrapper preserves any executable ABI-compatible
predecessor without plugin-name or version checks.

All fixed addresses remain specific to FalloutNV 1.4.0.525. Required runtime
hook installation fails rather than guessing when its trampoline contract is
unavailable. The optional load defense verifies exact surrounding bytes,
direct-CALL shape, and an executable predecessor before patching.

## Validation

Regression coverage includes:

- reported unaligned `0x00035AAA` rejection before memory inspection;
- aligned unreadable candidate rejection;
- wrong-vtable and wrong-type rejection before registry lookup;
- rejection of a correctly shaped but unregistered object;
- acceptance only when registry identity matches;
- repaired reference source revealing a valid cell fallback;
- immediate NULL after an unrepaired source;
- a strict three-source bound under repeated corruption;
- captured-cell worldspace repair and exact compare-exchange ownership;
- race recovery never chaining the load wrapper to itself or non-code;
- load-predecessor single-call and NULL preservation;
- config default-on and explicit-disable behavior.

Validation completed on 2026-08-03:

```bash
cargo fmt -p psycho-engine-fixes -p psycho-engine-fixes-helper \
  --all -- --check                                                # passed
cargo test --target i686-pc-windows-gnu \
  -p psycho-engine-fixes --lib                                    # 134 passed
cargo test --target i686-pc-windows-gnu \
  -p psycho-engine-fixes-helper                                   # 14 passed
cargo build --release --target i686-pc-windows-gnu \
  -p psycho-engine-fixes -p psycho-engine-fixes-helper            # passed
git diff --check                                                  # passed
```

The unfiltered package test was also attempted during implementation. Its
library phase passed, while rustdoc failed on three pre-existing assembly
examples in `havok.rs` and `navmesh.rs` that are parsed as Rust; those files
are outside this change.

### Live observation

The 2026-08-03 live logs establish:

- `encounter_zone_invalid_form_guard` initialized and enabled at 12:31:07Z;
- at 12:31:16Z the guard rejected unaligned FormID-shaped `0x06035ABB` for
  owner form `0x06076936` and reported a worldspace clear;
- at 12:31:24Z the process published `[EVENT] Game engine ready`;
- `CrashLogger.log` contains only its six-line no-crash header, with no
  exception record;
- normal watchdog and gameplay diagnostics continued through at least
  12:34:12Z.

The first implementation logged `cell=0` and `source=worldspace-cleared` in
the same event. Static proof shows `FUN_00575D70` re-reads `owner+0x40`; the
pair therefore exposed a cell handoff between the diagnostic capture and that
helper call. The final implementation no longer performs that second ownership
read and uses exact compare-exchange for the worldspace field. Because this run
preceded the hardening, it proves containment and progression only for the first
implementation.

The second 2026-08-03 run used deployed core and helper DLLs whose SHA-256
hashes matched the final release artifacts. It establishes:

- the guard initialized at 12:52:10Z and the affected load did not reproduce
  the `0x00567ECC` crash;
- the first 16 detailed rejections all contained unaligned `0x06035ABB` with a
  captured NULL cell and `source=source-not-recovered`;
- no rejection claimed a worldspace mutation from a NULL cell. Exact source
  ownership was unavailable, so the guard correctly returned the native NULL
  fallback without changing deeper storage;
- game-ready published at 12:52:25Z, followed by an autosave, three quicksaves,
  a named save, and subsequent reload activity;
- Psycho and OMV diagnostics continued normally through 13:02:55Z, more than
  ten minutes after containment, and the user confirmed an intentional clean
  exit.

CrashLogger appended only a bare `EXCEPTION_ACCESS_VIOLATION` label during that
intentional exit, four seconds after the last normal diagnostic. It recorded no
address, registers, stack, module, or dump, and the user observed no crash. It
is therefore retained as an exit-time logger artifact rather than evidence of
a reproduced runtime failure.

This pass did not directly exercise an exact reference/cell repair revealing a
different valid lower-priority zone. That fallback remains covered by the
bounded resolver regression tests and the static native-source contract.

## Evidence classification

Proven by the reports and current executable:

- the fault instruction and invalid pointer value;
- resolver source order, purity, layout, and all nine callers;
- NULL behavior at each caller and in changed-form serialization;
- the distinct master/plugin and changed-form load ownership paths;
- exact vtable, type, registry lookup, native setter, lock, and world field;
- safe common intervention and bounded source-repair points.

Reasoned inference:

- `0x00035AAA` is likely an unresolved FormID rather than arbitrary damage;
- simultaneous invalid form references make stale/unresolved saved data the
  leading producer class.

Not proven:

- which of the reference, cell, or worldspace slots supplied the reported
  value;
- which save, plugin, or runtime writer first stored it;
- that `Cyberware TTW.esp` caused the defect merely because it last overrides
  the parent cell;
- reporter-save runtime behavior after this fix.
