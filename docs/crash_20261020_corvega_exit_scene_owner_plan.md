# Corvega exit: invalid scene-owner base-form read

Status: implemented as an unreleased defensive candidate under the reporter-only
engine-fix exception, authorized by the owner's instruction to proceed with
this plan and add a toggle. Offline qualification passed. The invalidating
writer remains unknown; runtime and startup acceptance are pending.

Last updated: 2026-10-20.

## Report and retained evidence

The owner reports: "Just go to exit door and game crashed". CrashLogger shows
`CorvegaFactory02`, cell `06017F66`, in the unloading state, and the player
without a current cell. This supports an exit/teardown incident. The report
does not establish a repeatable save, the precise door, or a complete replay.

Complete CrashLogger, Psycho, OMV and Atom logs and the deployed Psycho
configuration are preserved in `.reports/20261020-corvega-node-unload/`.
`evidence-manifest.json` records their sources and timestamps. The installed
lookup payload is also retained there as `installed-reference-lookup.bin`.
No game, deployment script, or third-party build was run during this work.

CrashLogger's header time is the session start, `01:11:56` local. The archived
crash filename is `CrashLogger.2026-10-20-01-20-19.log`; playtime is `00:08:22`.
Psycho's matching UTC session begins at `2026-10-19T22:11:56Z`. Use the archived
filename and log timestamps rather than treating the header as the crash time.

## Confirmed immediate cause

A scene-to-reference lookup follows the `BSFadeNode` linked-owner field and
consumes a non-NULL, invalid base-form address. It tests the supposed form's
type byte without validating that address.

| Boundary | Captured value or verified operation |
|---|---|
| EIP | `0x0056F975` |
| Current node, ESI and ECX | `0xC6343100`, reported `BSFadeNode`, `UtlCat1way01` |
| Linked owner, EDI | `0xFE8FF488`, loaded from the fade node's `+0xCC` field |
| Base-form pointer, EAX | `0x00000001`, loaded from the linked owner's `+0x20` field |
| Fault instruction | `cmp byte [eax + 4], 0x29` |
| Attempted read | `0x00000005` |

The instructions establishing the bad-pointer chain are:

```text
0056F957  mov edi, [eax + 0xCC]
0056F96E  mov eax, [edi + 0x20]
0056F971  test eax, eax
0056F973  je <return linked owner>
0056F975  cmp byte [eax + 4], 0x29
```

The immediate cause is the unchecked invalid base-form pointer during scene
owner resolution. This does not prove whether the linked owner is stale, the
owner's field was overwritten, or a concurrent lifetime transition occurred.
No allocation/free history, invalidating write, or thread trace is available.

CrashLogger additionally reports 62600 children and cannot retrieve the node's
owner. These are observations, not a safe child-count rejection threshold or
proof of a particular corruption mechanism. Its corrupt-stack annotation and
DbgHelp-copy error do not identify the invalidating writer.

### Why the original executable alone gives the wrong instruction

At `0x0056F975`, the original game contains a read of the player singleton,
not the failing base-form type test. The installed Stewie module contains an
exact replacement payload and a verified copy routine that writes it to
`0x0056F930`. Mapping those exact installed bytes at their destination places
the type test at the reported EIP and matches the captured registers.

The source cross-check is
`.research/Stewie Tweaks 10.00 Source/code/Features/Inlines/Scripts.cpp`:
`TESObjectREFR__FindReferenceFor3D` and its deferred `SafeWriteBuf` call.
Installed machine code verifies the source payload and destination; source
resemblance alone was not used to identify the fault. Runtime code bytes were
not captured independently. This establishes the consuming implementation,
not responsibility for creating the invalid object state.

Raw evidence:

- [Installed payload and copy routine](../analysis/radare2/output/crash_20261020_corvega_installed_lookup.txt).
- [Exact payload mapped at the crash address](../analysis/radare2/output/crash_20261020_corvega_mapped_lookup.txt).
- [Native callers, ABI and continuation](../analysis/radare2/output/crash_20261020_corvega_native_contract.txt).

## Verified native path and scope

The installed and research executables match: FalloutNV `1.4.0.525`, PE32
i386, image base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Addresses below apply to that executable.

1. Havok listener dispatch calls vtable `+0x08` at `0x00D00603`, returning to
   the captured `0x00D00605`.
2. `BGSAcousticSpaceListener` vtable `0x0104D8E8` has `0x0061F630` in that slot.
   This callback uses ECX for the listener, one stack argument, and `ret 4`.
3. The callback obtains an embedded address at argument `+0x10` through
   `0x00460140`, then calls `0x0062B4E0` at `0x0061F68C`. Its return address is
   the captured `0x0061F691`.
4. `0x0062B4E0` calls scene resolver `0x00C7FA90`, then passes its non-NULL
   scene result to the reference lookup through the call at `0x0062B50C`.
   The stack contains that call's return address, `0x0062B511`, and the
   `Rails01` node whose reported parent is `UtlCat1way01`.
5. The reference lookup walks parents at `+0x18`, obtains a fade node through
   virtual `+0x10`, and reads its owner at `+0xCC`. Both the original game and
   replacement trust a non-NULL owner; the replacement consumes `+0x20` and the
   base form's type byte directly. Returning to the original implementation
   does not establish a lifetime repair.

The proposed scene-lookup seam, `0x0062B50C`, is a cdecl call with one scene
pointer on the stack and a pointer result in EAX. The caller removes four
bytes; both original and installed lookup implementations return with plain
`ret` and preserve the callee-saved registers.

For the reported acoustic callback, NULL is a proven immediate continuation:
the result is compared with the non-NULL player singleton. An unequal result
returns from the callback without invoking `0x0082EB70(0)`. This avoids a
reference dereference there, but runtime acoustic-state behavior still needs
validation.

The seam is shared: `aar; axt` finds 25 direct native callers of `0x0062B4E0`
and 83 direct calls to the original `0x0056F930`, including its recursive call.
These are discovered direct references, not exhaustive indirect or mod caller
coverage. A process-wide replacement of `0x0056F930` is not justified.

[Caller windows](../analysis/radare2/output/crash_20261020_corvega_resolver_callers.txt)
show NULL checks, player comparisons, paired lookups and delayed consumers.
[Delayed-consumer follow-up](../analysis/radare2/output/crash_20261020_corvega_resolver_delayed_consumers.txt)
records the delayed windows. The
[admission-contract audit](../analysis/radare2/output/crash_20261020_corvega_admission_contract.txt)
closes their native NULL consumption and verifies the accessors used below.
All 25 discovered direct native helper callers are classified here:

| Callsite(s) | NULL result consumption |
|---|---|
| `0x0061F68C` | Compare with the non-NULL player; return without reset. |
| `0x0061F723`, `0x0061F754` | Merge at the NULL check at `0x0061F75F`. |
| `0x0061F737` | Player comparison; the resulting selected owner is NULL-checked. |
| `0x0061F7F3`, `0x0061F824` | Merge at the NULL check at `0x0061F82F`. |
| `0x0061F807` | Player comparison; the resulting selected owner is NULL-checked. |
| `0x0062746E` | NULL check at `0x0062748C` skips owner dispatch. |
| `0x00627558` | Store to local `-0xBC`; the result is not subsequently consumed. |
| `0x00628ED3` | NULL check at `0x00628EDE` skips owner dispatch. |
| `0x00628FFB` | Forward to `0x006296D0`; all owner use is NULL-gated. |
| `0x0062CE7E`, `0x0062D09F` | NULL checks skip the corresponding owner transaction. |
| `0x0062DA46`, `0x0062DBC5` | NULL checks skip the corresponding event/dispatch. |
| `0x0062DCA2`, `0x0062DCB4`, `0x0062DD42`, `0x0062DD54` | Both resolved owners are NULL-checked before use. |
| `0x0062EFE1` | NULL check at `0x0062EFEC` skips reference processing. |
| `0x0062F6C4` | NULL enters the existing player-physics fallback; the second result is checked. |
| `0x0062F6FE`, `0x0062F7C0`, `0x0062F926` | NULL returns false. |
| `0x0062F914` | NULL enters the existing player-physics fallback or returns false. |

At `0x006296D0`, the forwarded reference is the first stack argument at
`[EBX+8]`. Checks at `0x00629700`, `0x00629752` and `0x006297F3` dominate its
uses; its actor-only alias is initialized to NULL and separately checked.
The final position fallback does not dereference the rejected reference.

## Existing guard and attribution limits

The deployed log confirms that `fade_linked_owner_guard` is active. Its
[implementation](../psycho-engine-fixes/src/mods/engine_fixes/fade_linked_owner_guard.rs)
guards only the actor-alpha call at `0x00B4E772`, checking readability of the
owner/vtable/type-slot prefix. It does not intercept this scene lookup or read
the owner's base form. This incident demonstrates a separate consumer; it does
not establish that the earlier guard failed on its own protected path.

The [Vault 108 incident](crash_20261019_vault108_fade_owner_plan.md) also involves
an invalid fade-owner chain. A common invalidating writer is not proven.

Allocator mode 2 was active. The final VAS sample, about 22 seconds before the
crash, reports 679 MB free and a 213 MB largest hole. Earlier pool-capacity
refusals and memory-pressure reclamation are logged, but none is tied to this
node or owner. These samples do not prove or exclude a final allocation
failure, and do not attribute the bad pointer to gheap. OMV and Atom initialized
and ran; neither log proves a write to the failing fields. Plugin names and
the cell's last modifying plugin are not causation evidence.

## Implementation and configuration ownership

The implementation is
[`scene_reference_owner_guard.rs`](../psycho-engine-fixes/src/mods/engine_fixes/scene_reference_owner_guard.rs).
The core installs one `Rel32CallHookContainer` at `0x0062B50C`, preserving the
live target. The exact caller input is `83 7D F8 00 74 0F 8B 4D F8 51`; its
output is `83 C4 04 89 45 FC`. Both must match before preparing the E8 call.
The provider is published before activation; admission starts after transaction
commit. Rollback survivors chain the retained provider without admission.
Installation failure leaves this guard unavailable and other fixes running.

`[engine_fixes].scene_reference_owner_guard` defaults to true. A false value
skips its installer before memory-reader preparation or code changes. The
helper's **Scene owner guard** checkbox reads and saves this same restart-only
TOML value. Its text follows the adjacent engine-fix settings. The core owns
activation; the helper never installs or live-toggles the hook. The private
core and helper configuration structures append one bool; the fixed diagnostics
ABI does not change.

Admission uses guarded OS copies and the native non-mutating type-query
contract:

1. A NULL scene preserves provider behavior. The player singleton and its
   `+0x694` scene pointer establish the existing player-node early result.
   Native `0x00950BB0(1)` reaches that same field through `0x00559450`.
2. Copy the current node's vtable and virtual `+0x10` slot. Require accessible
   executable code, then invoke that live thiscall type query. Native NiNode
   uses `0x00ACBB70` (NULL), and BSFadeNode uses `0x006815C0` (this unchanged).
   Those identities are evidence only; the guard has no code/vtable allowlist.
3. For a returned fade node, copy its `+0xCC` owner. A non-NULL owner requires a
   readable `+0x20` base-form slot. A non-NULL base requires exactly one readable
   byte at `+4`. NULL bases remain admitted because the native provider returns
   their owner. A readable non-ammo base ends admission.
4. Missing owners and ammo bases continue through node `+0x18`. Iteration
   validates the parent work reached by the native loop and ammo recursion;
   the provider retains the actual player/owner/ammo-fallback result. Brent
   cycle detection uses already visited pointers, constant storage and no
   arbitrary depth budget or second virtual-query pass.
5. An inaccessible required read, unavailable query or parent cycle returns
   NULL before entering the reference provider. Readable chains forward the
   original node exactly once. Restore last-error before forwarding or
   returning; retain changes made by the provider itself. The first rejection
   logs `[SCENE_OWNER]` and the consequence; valid calls perform no logging,
   counting, allocation or blocking lock acquisition.

This adds guarded reads and executable-page queries proportional to visited
parents. API cost and game performance are unmeasured. The extra native type
queries require the same non-mutating accessor ABI and live node/code lifetime
as the original lookup. A readable corrupt pointer, an invalid arbitrary
virtual implementation, or invalidation after admission is outside this guard's
proof. Snapshots do not retain an object, establish allocation identity or
close a race. No link, refcount, destructor, allocator policy or other mod is
modified. Third-party caller and provider internals are not exhaustively audited.

## Qualification and remaining acceptance

The owner authorized this candidate by instructing us to proceed with the
named plan and add the toggle. The
[reporter-only exception](psycho_engine_fix_exception.md) supplies the limited
fail-first/same-test/no-production-edit override. The retained crash is the
real-runtime failure; supporting offline tests execute production owner
admission and the OS reader, including base pointer 1, NULL bases, an exact
type byte at a page boundary, inaccessible and partial reads, and arithmetic
overflow. Configuration checks exercise real core parsing and helper TOML
round trips. They do not reproduce the complete game transition.

The pre-Deferred delta is one small zero-initialized hook container and its
atomic state, one appended configuration bool on each side, one core installer
and one helper control. No new dependency, WinAPI wrapper, import request,
thread, TLS owner, callback phase or diagnostics ABI is introduced. Existing
core startup and helper TOML ownership remain in place. Observed installed
baseline identities and PE output are retained in
`.reports/20261020-corvega-node-unload/implementation-startup-baseline.json`
and adjacent `*-baseline-pe.txt`; independent hashes of the DLLs loaded during
the crash session were not captured.

Focused production-reader/configuration checks, both affected crate suites,
formatting and the complete supported 32-bit release build pass. The core and
helper import sets, TLS template sizes and TLS callback counts match the
observed installed baseline; this does not prove runtime startup safety.
Qualification logs and the comparison are retained with the report. A later
owner-run session logs guard activation at `2026-10-19T23:00:47.911Z`,
`Game engine ready` at `23:01:13.869Z`, and subsequent runtime activity. Its
commit-review copy is retained beside the original report. No guard rejection
is recorded, and the Corvega exit result has not been supplied. These markers
do not independently satisfy the complete startup or incident acceptance gate.
Runtime acceptance requires the reported exit to complete, a captured guard
rejection, and continued gameplay with collision and acoustic transitions
working. The [startup contract](nvse_startup_phase_safety.md) retains its Proton
load-to-gameplay gate. Deployment remains user-only.

After the offline-qualified candidate and pending runtime status were reported,
the owner explicitly requested this commit. That request authorizes committing
the unreleased candidate; it does not establish runtime or release acceptance.

A root ownership repair still requires direct evidence of the invalidating
write or retirement edge and its lock/thread contract. Existing Set3D and
conditional owner-clear evidence does not authorize a destructor hook or an
unconditional link clear.
