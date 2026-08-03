# Dead-corpse cell render-list retirement fix

## Purpose and user-visible behavior

This fix prevents a use-after-free when a retired reference remains in an
exterior cell's render-phase list. The reported trigger was shooting an already
dead corpse. The later engine phase followed the stale corpse pointer and
crashed while obtaining its 3D state.

The fix is enabled by default through
`[engine_fixes].cell_render_reference_retirement_fix`. It applies to every
`TESObjectREFR` subclass and does not inspect a form type, plugin, editor ID, or
mod identity. It works with vanilla allocation, Psycho scrap-heap-only, and
Psycho gheap plus scrap heap. Runtime protection belongs entirely to the
early-loaded core DLL; the xNVSE helper is an optional configuration and
telemetry consumer.

## Evidence

### Supplied runtime evidence

- `.reports/psycho-engine-fixes-latest--dead-corps.log`
- `.reports/CrashLogger.2026-08-03-01-19-12--dead-corps.log`

The crashing main thread reached the phase consumer corresponding to native
`0x0054C740`. The current exterior cell and its list node were live. The node's
payload `0xF7C00D80` occupied an exact 448-byte gheap pool slot, matching a
`TESCreature`, but the slot had already been freed. This proves a live borrowed
list retained a reference beyond the payload lifetime; it is not an
out-of-memory failure.

The installed Stewie rendering inline moves the final `Get3D` instruction but
does not create the stale membership. ActorCauseSaveBloatFix source at
`.research/ActorCauseSaveBloatFix - Source/ActorCauseSaveBloatFix/main.cpp`
patches actor-cause save and load state only; it does not own the cell render
list or this retirement path.

### Executable identity

Static research used `fnv_reverse/FalloutNV.exe`:

- PE32 x86, image base `0x00400000`
- image timestamp `0x4E0D50ED`
- file size `16,084,808` bytes
- SHA-256
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`

Addresses in this document are valid only for that supported executable.

## Proven native contract

### Layout and ownership

- `TESObjectREFR` is `0x68` bytes.
- `TESObjectREFR::parentCell` is at `+0x40`.
- `TESObjectREFR::renderState` is at `+0x64`.
- `TESObjectCELL::renderData` is at `+0xC4`.
- The affected embedded `tList<TESObjectREFR>` begins at
  `CellRenderData + 0x4C`.
- Each list node is eight bytes: borrowed payload pointer followed by the next
  node pointer.
- Cell render-data teardown at `0x00545030` clears the list nodes through
  `0x00470470`; it does not own or free reference payloads.

The canonical list operations are:

- `0x00545560`: add one reference to `CellRenderData + 0x4C` through
  `0x005AE3D0`;
- `0x00545590`: remove one exact reference through `0x00905330` and the
  engine-owned node destructor/free path.

The primitive insertion helper does not deduplicate, and one removal call
deletes only the first matching membership. Higher-level cell ownership is
expected to publish one render membership per reference transaction; the
supplied crash contained one stale membership. Psycho deliberately invokes the
same one-node native helper once at the missing owner edge. It does not add a
speculative duplicate scan, manipulate list nodes, or claim to repair arbitrary
list corruption.

### Failing lifecycle asymmetry

When cell render data exists, `TESObjectCELL::AddReference` at `0x00548230`
first evaluates the reference virtual at vtable `+0x100`. A false result, or a
true result followed by `0x00440DA0` returning true, reaches mutable predicate
`0x005656D0` at `0x005483B8`. A true predicate result inserts the reference
through `0x00545560` at `0x005483CB`; the other paths do not insert it.

`TESObjectREFR` base teardown at `0x0055A430` invokes
`TESObjectCELL::RemoveReference` at `0x0054CA90` while the cell and reference
arguments still satisfy that method's ABI. The removal owner deletes the
reference from the primary cell list under `CellRefLock`, then handles render
data. A true global condition from `0x004121B0` reaches render-list removal
directly. Otherwise, `0x0054CB8F` re-evaluates `0x005656D0`; the `JE` at
`0x0054CB99` skips the render-list call at `0x0054CBA2` when the current result
is false.

This is not a valid ownership test: list membership was established from the
predicate's earlier value. A true-to-false transition can make removal skip a
borrowed pointer that is still present. Native function `0x005750A0` separately
snapshots the same predicate around one operation and calls `0x00545590` when
it observes a true-to-false transition, proving that the engine recognizes the
membership must follow mutable state. Not every transition is routed through
that corrective path.

### Consumer and propagation

Phase function `0x0054C740` acquires `CellRefLock`, traverses the embedded list,
and calls `TESObjectREFR::Get3D` at `0x0054C7BB`. Stock `Get3D` at `0x0043FCD0`
reads `reference + 0x64`, then `renderState + 0x14`.

A NULL 3D result does not end the consumer. The phase continues through
`0x00440DA0` and can call `0x00565870`, which performs further reference and
virtual dispatch operations. Guarding `Get3D`, `renderState`, or one downstream
call would therefore propagate the invalid lifetime into deeper code. A page
readability check would also accept a freed-but-still-committed pool slot.

## Intervention

Implementation is owned by
`psycho-engine-fixes/src/mods/engine_fixes/cell_render_retirement.rs`.

Installation at Syringe's quiescent pre-CRT boundary verifies one control-flow
seam:

1. Verify the global override branch, predicate argument, direct-call argument
   setup, and post-call continuation in `0x0054CA90`.
2. Decode the live predicate and cleanup call targets for diagnostics without
   requiring a plugin name, module, version, or xNVSE service.
3. When native bytes `0F B6 D0 85 D2 74 0C` remain at `0x0054CB94`, replace the
   complete seven-byte predicate-result block with one relative call and two
   padding NOPs.
4. When an existing provider has already changed only the final branch to
   `90 90`, preserve that provider and its direct-call invocation domain rather
   than inserting Psycho into its chain.

Psycho's branch-aware dispatcher reproduces the displaced `movzx edx, al` and
`test edx, edx` instructions. A true result returns through the two padding
bytes and reaches the existing direct call at `0x0054CBA2`; Psycho never changes
that call target. A false result pushes the proven `TESObjectREFR*` from
`[EBP+8]`, loads the proven cell from `[EBP-0x1C]`, calls canonical native
`0x00545590`, and advances its own return address to `0x0054CBA7` so the
existing call is not executed a second time.

This routing preserves the exact domain of a compatible mod owner already at
`0x0054CBA2`: global-override and true-predicate paths still call it, while the
formerly skipped false path enters the audited canonical address `0x00545590`.
A normal entry hook on that function therefore remains in the engine-wide
chain. The patch does not capture a predecessor and publishes only one
instruction block, so there is no partial two-site state or rollback chain that
can retain the wrong function pointer after a failed install.

All four native calls to `0x00545560` and all three native calls to `0x00545590`
mutate the render list outside `CellRefLock`. The phase consumer holds the lock,
but the executable does not establish it as the render-list writer lock. Psycho
therefore adds no residual scan and acquires no new lock. The missing removal
runs synchronously inside the original `TESObjectCELL::RemoveReference` frame,
before later retirement work, using the same native threading and allocator
contract as the original true branch. The retiring pointer remains an opaque
comparison key and is never dereferenced.

## Compatibility boundaries

- The core does not import or initialize xNVSE and does not require a helper
  lifecycle event.
- A pre-existing direct-call owner retains its original global-override and
  true-predicate invocation domain; Psycho does not redirect that call.
- A pre-existing exact NOP provider already makes the removal call
  unconditional and is preserved as the active capability.
- A normal later entry hook remains compatible when it calls the original
  `TESObjectCELL::RemoveReference`; the internal branch and callsite remain in
  that original body.
- A normal later direct-call hook sees the same original invocation domain and
  can chain the call owner that preceded it.
- Dashboard sampling compares the active seven-byte provider block with the
  startup shape. A later replacement clears feature bit 11 and records one
  ownership-loss event; Psycho reports the loss but never repatches live code.
- A plugin that completely replaces `TESObjectCELL::RemoveReference` without
  chaining its original behavior removes the native ownership boundary itself.
  No generic patch can safely compose with such a replacement; Psycho does not
  identify or fight plugins by name.
- The optional LOD subsystem has its own entry hook at `0x0054CA90`. This fix
  deliberately patches the internal removal site so both features share the
  original function without competing entry hooks, including when LOD is
  disabled.

## Runtime and performance behavior

True and global-override retirement retain their existing cost. Only a false
predicate result that previously skipped cleanup adds work: one canonical
native exact-removal call and one relaxed telemetry increment. Reference
retirement is a lifecycle path, not the per-frame phase consumer. The dispatch
performs no form lookup, RTTI, page walk, allocator query, file I/O, allocation,
lock acquisition, or routine logging.

The native remover performs one linear list search. Retiring many false-state
references from one large cell can therefore contribute quadratic total work
in the worst case, as native removal already can for many true-state members.
Avoiding that search would require a second membership index or weakening the
ownership invariant, neither of which is justified by the supplied crash. No
cost is added to ordinary render frames, and playtesting must still check cell
transition and save/load latency on a large reporting modlist.

## Tests and acceptance criteria

Automated coverage includes:

- exact native and already-forced branch classification;
- rejection of an unknown competing branch encoding;
- relative-call encoding for Psycho's dispatch entry;
- exact true-path fallthrough and false-path continuation addresses;
- default-on and explicit-disable configuration behavior;
- helper configuration round-tripping;
- versioned core/helper dashboard layout identity.

Validation executed on 2026-08-03:

- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes -p
  psycho-engine-fixes-helper --lib`: 153 core and 14 helper tests passed;
- the affected i686 release build for both DLLs passed;
- release disassembly confirmed that the naked dispatcher emits the exact
  `movzx`/`test` branch, loads `[EBP+8]` and `[EBP-0x1C]`, advances the false
  return by `0x0E`, and that the Rust `thiscall` helper returns with `ret 4`;
- `cargo fmt --all -- --check` and `git diff --check` passed;
- clippy reported only pre-existing warnings outside this feature.

Required build target:

```text
i686-pc-windows-gnu
```

Runtime acceptance requires shooting dead humanoid and creature corpses with
hitscan, projectile, explosive, and dismembering damage; looting, waiting,
changing cells, saving/loading, returning to the main menu, and exiting. Run
the corpse trigger with allocator modes 0, 1, and 2, with and without the
helper, and with both a minimal xNVSE environment and the reporting modlist.
With Psycho owning the native branch, the dashboard must show the protection
active, forced-cleanup calls increasing for exercised false-state retirements,
and ownership losses remaining zero. A preserved pre-existing NOP provider is
active but does not pass through Psycho's counter. Any non-zero ownership loss
must clear the feature's active state. Large-cell transitions must not introduce
an observable retirement hitch.

The reporting-modlist playtest completed on 2026-08-03 with Psycho gheap plus
scrap heap. The user exercised the dead-corpse damage reproduction without a
crash. The core log recorded `previous=Native provider=PsychoDispatch` with the
expected predicate and cleanup targets, no later ownership-loss diagnostic,
and normal activity through the end of the session. xNVSE loaded the helper
successfully, and CrashLogger contained only its no-crash header. The core log
does not periodically persist dashboard counters, so this run does not prove
the exact false-path counter value. Allocator modes 0 and 1, a minimal xNVSE
environment, and the complete damage/transition matrix remain pending.

## Evidence classification

Proven by crash data and static analysis:

- the stale payload was a freed creature-sized allocation;
- the cell and list node were live;
- insertion and final removal use the same borrowed list;
- final removal incorrectly depends on current mutable eligibility;
- the phase consumer continues into deeper reference work after a NULL 3D;
- the chosen helper removes exact membership without owning the payload.

Reasoned inference pending targeted runtime observation:

- damage to the dead corpse caused an eligibility transition not covered by
  the engine's other transition-specific cleanup path.

Observed in the reporting-modlist playtest:

- the branch-aware missing cleanup prevents the supplied corpse-hit reproduction
  with gheap plus scrap heap and retains its patch ownership for the session.

Still awaiting runtime observation:

- allocator modes 0 and 1, the minimal xNVSE environment, and the complete
  damage, save/load, cell-transition, menu, and exit matrix.
