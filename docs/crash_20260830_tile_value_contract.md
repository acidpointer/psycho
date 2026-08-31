# Tile value NULL-slot containment

## Purpose and approval

This is an unreleased reporter-validation candidate for the 2026-08-30
startup crash. The owner requested a Psycho-side, mod-agnostic fix. It
contains a proven broken Fallout UI container; it does not identify or patch
the component that created the invalid entry.

It must not be released, packaged, or committed as runtime-accepted until the
reporter validates the affected workload, records a containment event, and
confirms continued gameplay.

## Executable and runtime evidence

The supplied crash report identifies FalloutNV 1.4.0.525. Its faulting EIP is
`0x09853A4C`, resolved to `nvse_stewie_tweaks!Inlines::UI::TileGetValue_ +
0x1C`. Fault registers are `EAX = 0`, `ESI = 0`, `ECX = 8`, and `EDI = 17`.
The active tile is a `TileRect` at `MenuRoot/Strings`.

Stewie Tweaks 10.00 source shows the fault instruction is `cmp [eax], edx` in
a binary search over `tile->values`. The bounds zero through 17 and midpoint
eight prove that active slot eight is a NULL `Tile::Value*`.

The stack returns through Fallout `0x00A01026` into `0x00A01384`, the native
string-setter path. The supplied Psycho log reaches `[INIT] Engine fixes
initialized` and the crash stack has no Psycho frame. Neither artifact
identifies who inserted the NULL entry.

## Native contract proof

Radare2 analysis of the supported executable proves this Fallout 1.4.0.525
contract:

* `0x00A01000` is `Tile::GetOrCreateValueWithID(Tile* this, UInt32 trait)`;
  it is `thiscall`, returns `Tile::Value*`, and executes `ret 4`.
* Its direct native callers are `0x00A012D0` (float setter), `0x00A01350`
  (string setter), and `0x00A09130` (reference-value action construction).
* The function enters the host critical section at `0x011F3330`, searches the
  array, allocates when absent, and inserts the new value while holding it.
* `Tile + 0x10` is a `BSSimpleArray<Tile::Value*>`: data `+0x14`, active size
  `+0x18`, capacity `+0x1C`. `Tile::Value` begins with its trait ID at `+0x00`.
* The native comparator at `0x00A01160`, native insertion, and the Stewie
  inline lookup require a dense, non-NULL active range.

Stewie Tweaks sources 9.90, 9.95, and 10.00 alter the body beginning at
`0x00A0101B`, not the entry. The core installs at the pre-CRT barrier and the
researched Stewie patch installs on xNVSE `PostPostLoad`; an entry hook thus
prepares the same array for vanilla or the researched inlined provider.

## Intervention

The candidate verifies the vanilla entry bytes and owns one hook at
`0x00A01000`. It takes a non-owning reference to the already-live tile critical
section and holds it through the trampoline call, serializing the repair with
native search and insertion.

The guard defaults on and is independently toggleable through
`engine_fixes.tile_value_null_slot_guard`. While enabled, a fingerprint,
trampoline, or hook-activation failure propagates through core initialization;
Psycho must not log successful engine-fix startup while this reported path
remains uncontained. An explicit disable leaves the native path unchanged for
hook-conflict isolation.

For non-NULL data, nonzero size, `size <= capacity`, and checked byte
arithmetic, it stably compacts only NULL pointer slots and updates active size.
It does not free, retain, substitute, classify, or inspect a non-NULL value.
Dense arrays are forwarded unchanged. It has no Stewie-version, module,
allocator-mode, or allocation-owner branch.

Headers outside that proved case, including NULL data with nonzero size,
`size > capacity`, and overflowing byte length, are not repaired and are
forwarded unchanged. No safe native fail-closed result is proven for broader
corruption.

## Unresolved facts and acceptance

The report does not prove the inserting owner, a lifetime race, allocator
attribution, or mod attribution. The candidate remains agnostic to all of
them.

Static qualification requires affected crate tests, the supported
`i686-pc-windows-gnu` release build, formatting, `git diff --check`, and final
diff review. The pre-DeferredInit footprint requires the startup-safety release
gate in `docs/nvse_startup_phase_safety.md`.

Reporter validation must run the actual affected workload with Stewie inlining
enabled and show a `[TILE_VALUES]` repair plus continued gameplay. It must also
run with Stewie absent or its inlining disabled. Until then this is only a
reporter-validation candidate.
