# AI patrol retained-owner FormID containment

## Purpose and status

This fix prevents wrong-subtype FormID reuse in `ExtraPatrolRefInUseData` from
dispatching a `TESObjectREFR`-only virtual method through a different live
form. The reported AI-thread crash resolved the weak saved ID to a
`CombatController`, then loaded `0x7F7FFFFF` beyond that object's vtable as a
function pointer.

The fix is owned by the early-loaded `psycho-engine-fixes` core DLL, is
allocator-independent, and is controlled by the default-on restart-only
setting:

```toml
[engine_fixes]
patrol_owner_form_id_guard = true
```

The optional xNVSE helper edits that setting for the next launch and reports
whether the core hook installed; it never installs or initializes the guard.
The implementation is a runtime candidate until the reporting workload
rejects the stale alias and continues gameplay. Static validation and a
release build cannot satisfy that gate.

## Evidence

Supplied runtime evidence:

- `.reports/CrashLogger--ai-linear-task-thread.log`
- `.reports/psycho-engine-fixes-latest--ai-linear-task-thread.log`

The complete address-sensitive audit is preserved in
`analysis/radare2/output/ai_patrol_ref_in_use_contract.txt`. It applies to the
repository's supported PE32 FalloutNV.exe 1.4.0.525. Radare2 MCP was the
primary binary-analysis interface.

The crash report proves:

- `EXCEPTION_ACCESS_VIOLATION` on the AI Linear Task Thread;
- EIP and EAX equal to `0x7F7FFFFF`;
- ECX points to a live `CombatController` with vtable `0x0108CE74`;
- the first native return is `0x00437B00` immediately after the unsafe virtual
  call in the patrol-owner validator;
- the active objects include `ExtraPatrolRefInUseData`,
  `PatrolActorPackageData`, Character `FF000BA8`, package `0D0024D0`, patrol
  markers `0D0076D2`/`0D0076D3`, and wilderness cell `0D000A22`.

The Psycho log records `ai_start=242978`, `ai_join=242977`, and
`ai_active=true` after the worker fault. The main-thread heartbeat stall was a
consequence of waiting for that incomplete AI batch. Available address space
and allocator reserves exclude OOM. An invalid interior free rejected almost
three hours earlier has no retained ownership or call-path connection to this
failure.

## Native defect and lifetime

`ExtraPatrolRefInUseData` stores only an occupying actor's FormID at `+0x0C`.
Its validator at `0x00437AB0` first accepts a matching current actor. For a
different or absent current actor, it resolves the saved ID through the global
loaded-form lookup at callsite `0x00437ADD`.

NULL takes a complete native recovery path: the validator clears the saved ID
and returns success. A non-NULL result instead reaches vtable slot `+0x22C`
before the later actor-type gate. That order assumes every resolved saved ID
still identifies an actor reference.

The assumption is invalid because the extra owns no pointer or reference.
Reference destruction releases its FormID for reuse. Runtime-created
`CombatController` objects inherit `TESPackage`, participate in `TESForm`
registration, and have form type `0x49`. Character and Creature references
use types `0x3B` and `0x3C`. Resolving a retained actor ID to a controller is
therefore a valid global-form result but an invalid patrol-owner subtype.

The immediate subtype confusion and dispatch are proven. The exact former
actor and retirement event are inferred because the report does not preserve
the saved ID. This fix does not claim to identify the content or plugin that
created the patrol extra.

## Ownership and intervention

The package chain obtains extra type `0x88` from each candidate patrol marker
and calls the validator from the standard AI linear-task worker. Vanilla
already owns clearing the extra field while evaluating that marker. Psycho
must not add extra-list mutation, locks, or cross-thread repair.

The safe boundary is the one cdecl resolver call at `0x00437ADD`:

- the saved FormID is the sole argument;
- the result has not reached the unsafe virtual call;
- NULL already means "clear stale owner and accept marker";
- all callers of this validator receive the same protection;
- every other global FormID lookup remains untouched.

The call's current executable target is chained without identifying a plugin
or version. Fixed bytes around the call and at the NULL repair prove the exact
supported control flow before patching.

## Containment policy

The resolver wrapper calls its captured predecessor exactly once. NULL passes
through. A non-NULL result is admitted only when:

1. the pointer is above the low-address guard, 4-byte aligned, and its base
   field range does not wrap;
2. `TESForm.typeID` is Character `0x3B` or Creature `0x3C`;
3. `TESForm.refID` equals the requested saved ID.

An invalid result becomes NULL. Vanilla then clears the stale field and
continues package selection. Psycho does not reproduce the remaining flags,
life-state, package, or marker policy and does not change a valid actor.

The extra carries no generation token. Reuse by another Character or Creature
therefore passes this subtype and identity guard. That case preserves safe
virtual dispatch but may retain vanilla's stale occupancy semantics; the guard
cannot distinguish it from the original actor without changing engine state.

The current-actor equality fast path precedes the redirected call, so an actor
still using its own marker pays no wrapper cost.

## Failure, concurrency, and performance

Installation verifies the complete callsite contract before writing. An
incompatible patch owner or fingerprint mismatch logs that the guard is
unavailable and does not abort unrelated engine fixes. An ABI-compatible
direct-call owner is preserved as the predecessor. Installation publishes the
predecessor before the callsite while startup still excludes game work.

The valid path performs one existing resolver call and two base-form reads.
It performs no allocation, free, lock, OS query, file IO, RTTI traversal, or
logging. Rejection diagnostics are bounded to the first events and
power-of-two totals.

Allocator tradeoffs are unchanged:

- OOM policy, reserves, and recovery are untouched.
- Allocation and FormID reuse policy are untouched; the stale weak ID is
  contained only at its proven consumer.
- No allocator classification or hot-path synchronization is added.

## Compatibility and startup boundaries

`engine_fixes.patrol_owner_form_id_guard` defaults on. Setting it to `false`
skips callsite verification and redirection completely and logs that the guard
is disabled. That restores the vulnerable native validator and is intended
only for isolating a confirmed hook conflict. A full process restart is
required after changing it.

The helper preserves comments and unknown keys while editing the same TOML
field. Its Runtime Fixes page reads additive `active_features` bit 12 to
distinguish a saved preference from a guard that actually installed. No
dashboard structure field, ABI version, export, or core/helper ownership rule
changes.

The new configuration field changes the pre-Deferred value graph, and the new
code and atomics are visible before xNVSE `DeferredInit`. Core and helper
imports, TLS callbacks, exports, configuration shape, sections, and hook order
must therefore be compared with their pre-change artifacts under
`docs/nvse_startup_phase_safety.md`. Section movement from code, fixed atomics,
and the additive boolean is expected; new imports, TLS owners, workers,
migrations, or configuration scans are not.

## Acceptance

The candidate is accepted only after all of the following:

1. Existing affected checks, strict helper/core configuration round trips, and
   the supported 32-bit release builds pass.
2. One disabled cold start logs `[AI_PATROL] Patrol owner FormID guard disabled
   by config` and reports feature bit 12 off; the setting is then restored to
   `true` before crash-reproduction work.
3. The reporting save and modlist exercise package `0D0024D0` and patrol
   markers `0D0076D2`/`0D0076D3` in cell `0D000A22` through repeated cell
   transitions, waiting, save/load, and actor retirement/recreation.
4. `[AI_PATROL]` records a wrong-subtype rejection, preferably the reported
   type `0x49`, and gameplay continues.
5. Patrol movement remains functional and the same stale state does not cause
   an unbounded rejection loop.
6. The `0x7F7FFFFF` dispatch and AI-worker exception do not recur, and the
   main loop does not stall with one unmatched AI batch.
7. At least three representative BaseObjectSwapper-enabled Proton cold starts
   reach normal gameplay, closing the pre-Deferred startup gate.

The reported allocator mode is sufficient because this guard never consults
allocator state. Until the stale alias is observed and contained in gameplay,
the implementation remains an unaccepted candidate and must not be released,
packaged, or described as complete.
