# Resolution fixes: native contract and repair plan

Status: shared sizing repair implemented; source and native contracts reviewed
statically. The revised code has not been built or executed. Image correctness
remains unverified.
Last updated: 2026-10-20.

## Purpose and scope

One restart-only feature improves Pip-Boy, terminal, and character creation
screen resolution and fade coverage at every supported resolution. Lower display
resolutions must retain native image detail, layout, clipping, and input
alignment. There is no ultrawide-only gate or resolution whitelist.

Public control remains `engine_fixes.resolution_fixes = true`, with dashboard
label `Resolution fixes`. The core owns the feature independently of allocator
mode, OMV, and helper availability. Native rendering, resource ownership,
window/display policy, fonts, and independently owned FOV choices remain owned
by their existing systems.

The owner authorized repair implementation with static evidence only. No game
execution, debug runs, builds, or tests are part of this work. The shared sizing
contract below supersedes the six-site design. Deployment remains user-only;
release qualification remains outstanding.

## Evidence and confidence

Reverified executable: `fnv_reverse/FalloutNV.exe`, supported 1.4.0.525,
PE32 x86, preferred image base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
The discovered game executable has the same identity.

Primary evidence:

- [Screen sites](../analysis/radare2/output/fnv_resolution_screen_sites_20261020.txt).
- [Fader and tile callers](../analysis/radare2/output/fnv_resolution_fader_and_ui_contract_20261020.txt).
- [Current instruction contexts](../analysis/radare2/output/fnv_resolution_context_signatures_20261020.txt).
- [Resolution-range review](../analysis/radare2/output/fnv_resolution_full_range_review_20261020.txt).
- [Terminal producer/consumer trace](../analysis/radare2/output/fnv_terminal_render_regression_20261020.txt).
- [Static repair contracts and native menu assets](../analysis/radare2/output/fnv_terminal_static_repair_contract_20261020.txt).

Targeted radare2 CLI inspection supplied exact instructions and cross-references.
Decompiler output is exploratory. Misaligned range starts and invalid/interior
function decompilations in the raw record are not authority; the contracts below
use verified instruction boundaries and native call sites. Raw `aar` results
cover identified direct references, not arbitrary external or indirect writes.

## Report and proven defect

The owner reports blurred text in all terminals at 3440x1440 fullscreen.
Headers remain visible; option labels are invisible. Hover sounds, clickable
areas, and page transitions still work. This report defines the failure to
repair. It does not identify the exact installed width-bridge revision or the
values of native globals in that frame.

The superseded implementation combined three incompatible choices:

1. Target width reads `[0x011F9430]` as if it were an unconditional current
   display width. It is a letterbox extent, initially zero. At
   `0x004DAFAC..0x004DAFC1`, native initialization copies the mode flag to
   `[0x011F9426]` and skips directly to `0x004DB0A6` when the flag is zero.
   The width/height writes at `0x004DB08F` and `0x004DB0A0` lie inside that
   conditional block. Other native dimension branches check the mode flag
   before reading this extent; the superseded bridge did not.
2. The superseded minimum-width bridge turns a zero letterbox width into 1280,
   irrespective of a larger real backbuffer. Meanwhile the forced-false tile
   predicate selects current display dimensions for clipping. The producer and
   consumer therefore need not describe the same target. The 1280 floor fixes
   target undersizing relative to native detail, but cannot repair this mismatch.
3. The unconditional hit-test branch bypass assumes menu coordinates already
   equal display coordinates. That assumption fails whenever the native 1280
   minimum exceeds display width, and is not a general coordinate transform.

The underlying code defect is inconsistent extent ownership across allocation,
clip generation, and input conversion. The letterbox-only read is proven from
native control flow, not merely a possible settings-timing issue. The previous
description of that field as an unconditional configured-width snapshot was
incorrect and is superseded here.

The earlier direct-width revision has a separate zero-width consequence:
`0x00B6D5E0` uses default-group dimensions when either requested dimension is
zero (`0x00B6D849..0x00B6D8B8`). Do not equate it with the minimum-width revision
or claim that zero necessarily allocates a zero-sized texture. Neither revision
provides the explicit, shared extent contract required by this feature.

The mismatch can reject clipped option geometry while leaving unclipped headers
and independent input handling intact. It also prevents the minimum-width
revision from increasing raster detail when the letterbox field stays zero.
These are established failure mechanisms. Static evidence does not identify
which complete mechanism produced every pixel of the reported frame, prove an
actual image-quality comparison, or exclude a later external code change.
No claim of a visually validated fix follows from this investigation.

## Terminal rendering and clipping contract

The terminal constructor `0x00705FE0` installs vtable `0x0106EBE4`.
Its draw override `0x007FF7C0` calls shared rendered-menu draw `0x007FBA00`
at `0x007FF814`, with the third argument zero. The shared draw selects target
type `0x31` at `0x007FBB33`, then calls factory `0x00B6E110`.
This proves that the width branch being changed affects terminals.

The shared draw saves the native UI camera state, temporarily installs the
logical 1280 by 960 orthographic frustum at `0x007FBBD7..0x007FBC08`, submits
menu geometry, applies the native final image-space effect through `0x007FBEE0`,
and restores camera/target ownership. A physical target-size increase must not
replace those logical frustum constants or scale XML traits and glyph metrics.

`0x00B6BEE0` and `0x00B6C0D0` perform native geometry submission/flush work;
they are not evidence of two image-downsampling passes. The final effect reads
native menu parameters and source color through `0x004BC320`, then invokes
effect 10 through `0x004E3270`. This investigation does not establish a need to
change its shader, sampler, font atlas, scanlines, noise, or blur parameters.

The native menu predicate at `0x00A03C60` resolves the tile's menu through
`0x00A03C90` and returns menu byte `+0x1C` in AL. It selects clipping dimensions;
it is not a font-resolution control. Three identified callers consume it:
`0x00A063E2`, `0x00A065DF`, and `0x00A07B3B`.

Their rendered-menu branch uses:

- `0x00706E80`: float width 1280, returned in x87 ST(0), no stack arguments.
- `0x00706E90`: float width times default-group height/width, also returned
  in ST(0). It calls `0x00706E80` at `0x00706F0B`.

Their other branch uses current display dimensions through `0x00706E40` and
`0x00706E10`, ultimately `[0x0118947C/0x01189480]`. Logical UI extent getters
`0x00715D40/0x00715DA0` are a separate coordinate space. These owners must not
be substituted for each other merely because some resolutions make them equal.

Clip generation converts tile positions/dimensions using the selected menu
extent and logical UI extent. Recursive writer `0x00A07A40` takes four stack
floats, returns with `ret 0x10`, and writes TileShaderProperty rectangle fields
`+0x9C/+0xA0/+0xA4/+0xA8`, enabling them through `+0xAC`. The sibling path
writes the same fields at `0x00A06895..0x00A068BB`.

TileShader pass setup `0x00BCA980` consumes those fields. Its native letterbox
adjustment applies only when the current group equals the default group.
Offscreen menu rendering passes the rectangle through `0x00B97D20` to D3D9
`SetScissorRect` without automatically repairing a changed coordinate basis.
Thus an allocation/clip mismatch reaches the real clipping boundary.

Native `menus\computers_menu.xml`, extracted read-only from the game's
`Fallout - Misc.bsa`, distinguishes headers from options directly. Headers
and option text both use font 5. Options include `list_box_template.xml`;
that native prefab enables clipping, click sounds, and hover sounds. Header
text is outside that list-item clipping boundary. The terminal depth rectangle
uses screen height times 0.75 and a 4:3 width. Preserve these layout semantics;
removing prefab clipping or replacing the XML would hide the engine defect
and could break custom menus.

## Shared sizing and input contract

Dimension selector `0x00B6C2C0` dispatches on the second stack argument and
returns with `ret 0x20`. The first argument is the renderer; the next two are
width/height output pointers. Types `0x2D/0x31` reach `0x00B6CD24`; type `0x30`
reaches `0x00B6CEBB`.

Both original branches store width 1280, then query renderer virtual `+0xC8`
for the default group and group virtuals `+0x8C/+0x90` for color-buffer width
and height. Native height is proportional to the chosen width, with x87
truncation and control-word restoration. Flags remain `4` for `0x2D/0x31`
and `0x40` for `0x30`.

Verified group getters `0x00EE8490/0x00EE84B0` read color buffer 0 dimensions
at `+0x08/+0x0C`. Use the default group, not the currently bound offscreen menu
group: using the latter would make repeated draws feed their own output size
back into the sizing policy.

The repair policy is `max(1280, default_group_color_width)`. Both allocation
splices and the menu-width getter must obtain that value from one shared
implementation. Preserve native aspect calculation, float height getter,
height truncation, camera, viewport, and final sampling behavior. In particular,
do not introduce new clip rounding: the original float height and truncated
allocation height already differ by their native rounding rules.

Requested menu extent and physical texture extent are not universally identical.
`0x00B6D170` retains requested dimensions when its native capability flag is set;
otherwise it creates square power-of-two storage. Keep native padding, texture
mapping, pool keys, and device handling intact. Do not replace all coordinate
getters with a raw allocated-texture size or silently add a new resource cap.

The native input path at `0x00712BA3..0x00712C15` converts stored rectangles by
current display width divided by `0x00706E80`. Its two preceding conditions at
`0x00712B8C` and `0x00712BA1` remain native in the repair. Once that width getter
shares the allocation policy, input retains the native inverse conversion,
including below the 1280 minimum. Skipping the conversion is unnecessary.

Identified direct width-getter callers are the height helper, input call
`0x00712BAE`, and clip calls `0x00A063EE/0x00A065EB/0x00A07B47`. Identified
height-getter callers are `0x00A063F9/0x00A065F6/0x00A07B4F`.
These narrow shared boundaries coordinate the existing consumers without a new
per-frame loop, global dimension override, or terminal-specific XML handling.

## Repair implementation

1. Both width splices call one bounded `screen_render_width` resolver using
   the native renderer/default-group width and 1280 minimum. The bridge
   preserves the live EBP output pointer, general registers, EFLAGS, stack
   depth, x87 state, and the displaced renderer call. EDI supplies the renderer
   at the splice sites. Renderer state is read only when the native sizing
   path executes, never during pre-CRT installation.
2. The native width getter at `0x00706E80` jumps to `menu_width_getter`, using
   that same resolver and returning float width in ST(0). It obtains its
   renderer through native accessor `0x0043C4B0`. The native height getter
   already calls this entry and remains intact. The shared 1280 camera constant
   is not modified.
   Its complete original function is the eleven bytes
   `55 8B EC D9 05 38 EC 06 01 5D C3`; a five-byte entry jump must consume
   whole instructions and verify the entire original function. An eleven-byte
   descriptor containing the jump and six NOPs avoids a partial-instruction
   footprint. This is a replacement entry, not a trampoline that executes the
   old constant load. The replacement returns directly to the original caller.
3. Installation no longer writes the predicate or targeting branch. The native
   predicate, all three identified clip-selection callers, complete height
   helper, and input conditions/conversion are read-only required contexts.
   No running-game restoration or external-owner undo is performed.
4. Descriptors, common preflight, rollback ownership, final verification,
   deferred observation, and status reporting cover five writes: two sizing
   splices, one width getter, and the existing two fade sites. Complete original
   instruction footprints and exact bridge destinations are verified. An old
   incompatible predicate/input patch fails context validation before any write.
5. The public boolean, config placement, helper persistence, and text retain
   their existing behavior and style. Module documentation names the actual
   default-group owner instead of a settings snapshot.

Owning production file:
`psycho-engine-fixes/src/mods/engine_fixes/resolution_fixes.rs`.
The config/helper mappings already provide the requested common switch.
No core/helper ABI, loader phase, worker, TLS, dependency, resource owner,
per-draw allocation, lock, file access, diagnostics, or shader compilation is
part of this implementation. Source-level bridge ABI review is recorded below;
no generated-code or runtime qualification is claimed.

### Bridge ABI, lifetime, and resource ownership

`screen_render_width` receives the renderer in ECX and returns u32 width in EAX.
The native default-group getter is `0x00E69600` (`renderer+0x884`, plain RET).
Group width getter `0x00EE8490` receives index zero on the stack, returns EAX,
and executes `ret 4`. These verified integer routines do not touch x87. The
resolver follows those native virtual interfaces without retaining pointers,
changing reference counts, inspecting provider identity, or caching state.

The sizing bridge saves EFLAGS and all general registers with PUSHFD/PUSHAD,
passes EDI as ECX, stores EAX through the existing EBP output pointer, restores
the saved state, and consumes only its splice return address. Native sizing
already dereferences this renderer/default group immediately afterward for
aspect calculation; the correction adds no new object lifetime or thread owner.

The getter replacement enters by JMP, so the original caller's return address
remains on top of its incoming stack. It saves the same general state, queries
the established renderer accessor, and calls the shared resolver. A zero-extended
eight-byte temporary lets FILD load the unsigned width as positive signed i64.
FSTP/FLD through f32 supplies one ST(0) result, matching the original float
getter while preserving underlying x87 stack entries. The temporary and saved
state are removed before plain RET; no stack arguments or FFI unwind exist.

Target construction remains in `0x00B6D170/0x00B6B610/0x00B6B380`. Group binding
remains in `0x00B6B8D0/0x00B6B7D0/0x00B6B2A0`, including renderer virtual
`+0x194`. No padding, UV, viewport, bind, release, or reset instruction is
changed. The shared terminal draw acquires type `0x31` for each automatic-target
draw and returns it through `0x00B6DA10`; explicit target lifetimes remain with
their native caller. Cached-target recreation and uncommon capability paths
have not been exercised. Their image/lifecycle correctness is not inferred
from unchanged native ownership alone.

Both existing fixed-size lazy owners remain at the same installation boundary;
the replacement-byte owner now includes the eleven-byte getter jump. The patch
array shrinks from six descriptors to five, with additional read-only native
contexts. The three status atomics, config layout, event forwarding, and
transaction mechanism are unchanged. Binary layout/startup safety has not been
qualified without a build and game run.

## Resolution and quality invariants

For every valid native mode whose default-group width is at most 1280, the
resolver returns exactly 1280. Both target branches, the menu-width getter,
height helper, clipping predicate, input conditions, camera, fonts, and final
effects consequently retain their native behavior. This is the static
no-degradation design requirement; the superseded forced-display clipping path
did not meet it. Visual preservation remains unverified.

For larger widths, allocation and menu clip conversion increase together using
the same default-group source. The input path retains its inverse conversion.
No aspect category, fullscreen setting, XML menu name, or fixed screen size
selects admission. Native default-group height/width supplies the aspect for
wide, narrow, square, portrait, and odd-sized supported modes alike.

No persistent width cache is introduced. Native sizing and getter calls consult
the current default group when executed. Existing resource acquisition,
return-to-pool, device reset, and camera restoration stay native. Static review
must trace all relevant lifecycle callers before claiming complete recreation
coverage; refreshing a getter alone does not recreate a cached resource.

Do not fix option visibility by disabling clipping, widening XML rectangles,
forcing alpha, changing font metrics, overriding FOV, or turning off the feature.
Do not claim that a larger target alone proves sharper final text.

## Fade contract within the common feature

The two fade sites remain a separate native path. Geometry owner `0x00700960`
is thiscall with three stack arguments and `ret 0x0C`; adjacent `0x007006C0`
initializes parent nodes and is not the geometry owner. The current corrected
entry guard uses `0x00700960`.

At `0x00700AB2/0x00700ACC`, removing the six-byte multiply by 0.5 doubles local
quad magnitudes on both axes. Width/height come from `0x004DC1F0/0x004DC200`.
Texture coordinates stay 0..1, including the native textured-overlay path.
This proves local overscan, not universal full-view coverage or preservation of
patterned-overlay framing after parent scaling and projection.

The terminal trace supplies no evidence for a new fade edit. Keep this path
separate during the screen repair. Universal coverage and lower-resolution
textured-overlay quality remain open contracts for the whole feature; do not
advertise them as proven by unconditional patch installation.

## Compatibility and ownership

Preserve the existing core pre-CRT installation boundary and
[startup safety contract](nvse_startup_phase_safety.md). Never install later
to win load order, detect another mod, patch third-party code, or repatch every
frame. Unknown externally owned code is not an authorized restoration target.

Preflight the complete revised write set and all retained native contracts
before any write. Use the existing `OwnedCodePatch` and
`ModificationTransaction` machinery:

- Original supported code is eligible for an owned write.
- An exact verified required result is already satisfied; acquire no write or
  rollback ownership. A detour opcode alone does not prove equivalence.
- Unknown code or an incompatible retained predicate/input branch is preserved
  and reported as a conflict. Do not install a partial screen contract.

The old forced-false predicate, unconditional input bypass, and letterbox-based
width replacements are not equivalent to the repaired contract. Do not accept
them merely because their bytes were accepted by the earlier implementation.
Removing our old descriptors on the next launch does not remove independently
installed changes at those addresses. Such a configuration needs static proof
of a compatible boundary; this plan does not certify it or authorize an override.

Rollback restores only recorded Psycho writes while ownership still matches.
Final verification must cover the complete revised contract. Existing one-shot
deferred observation may report a later change; it must never rewrite live
instructions. Config off performs no Psycho writes and cannot undo externally
supplied behavior. The helper never loads or initializes the core.

## Configuration text

Keep the established imperative TOML style:

```toml
# Improve Pip-Boy, terminal, and character creation screen resolution, and
# fade coverage at all resolutions.
resolution_fixes = true
```

Helper label: `Resolution fixes`. Preserve its short third-person tooltip:

> Improves Pip-Boy, terminal, and character creation screen resolution and fade
> coverage at all resolutions.

Restart behavior continues through Save for next launch. Product text exposes
no patch addresses, diagnostics, or implementation details.

## Static review and remaining limits

This research deliverable requires direct evidence for the failing contract,
the proposed shared boundary, lower-resolution preservation, input conversion,
resource ownership, compatibility policy, and the unqualified parts of the
whole feature. Document/link checks and diff review are sufficient for this
documentation. The source change received formatting and diff review, with
native bytes and bridge state transitions checked statically. No build, test,
debug session, or game run was performed, requested, or scheduled.

The bridge has not been compiled or disassembled from a revised artifact.
Static inspection cannot establish the final reported image, arbitrary external
or indirect callers, cached-target recreation across every reset, or complete
viewport/padding composition on both resource-capability paths. An unresolved
external hook remains unresolved rather than being guessed compatible. No
mirrored formulas, source assertions, or synthetic rendering qualify behavior.

The required final behavior remains visible terminal headers and options,
aligned hover/click targets, no text-quality loss relative to native behavior
at lower resolutions, improved detail at larger resolutions, and complete fade
coverage without overlay degradation. Actual images, runtime coexistence,
reset behavior, startup, and performance have not been qualified by this static
investigation. Their absence is a limit on the conclusion, not a request for
a debug-only run or build. The implementation remains unqualified for release.
