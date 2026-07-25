# Model postprocess serialization engine fix

Status: implemented and statically validated on 2026-07-25. Runtime replay of
the supplied save/modlist is still required.

This is the durable engine contract for
`psycho-engine-fixes/src/mods/engine_fixes/model_postprocess.rs`. It documents
the model scene postprocessor crash at `0x004B5E11`, the safe intervention, and
the compatibility requirements for native I/O and all allocator modes.

## Purpose and user-visible behavior

The fix prevents concurrent model loads from corrupting the engine's
process-global `EditorMarker` traversal state. It does not remove a model,
skip scene traversal, suppress an exception, change model queue ownership, or
move work to another thread. One complete postprocess traversal runs at a time;
unrelated file and model-loading work remains concurrent.

The restart-only configuration owner is:

```toml
[engine_fixes]
model_postprocess_serialization_fix = true
```

The setting defaults on. It is independent of:

```toml
[io]
parallel_enabled = true # or false
```

The fix is needed with vanilla I/O because one native model worker can overlap
synchronous main-thread model loading. Psycho's optional second I/O worker
widens the set of possible interleavings but is not the origin of the shared
state.

## Executable identity

All addresses and byte fingerprints apply to
`fnv_reverse/FalloutNV.exe`:

| Property | Value |
|---|---|
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |
| Format | PE32, x86, little-endian |
| File size | `16,084,808` bytes (`0x00F56F48`) |
| Image base | `0x00400000` |
| PE timestamp | `0x4E0D50ED` |

Reconfirm this identity before reusing the addresses in another executable.

## Runtime evidence

The supplied CrashLogger report records:

- `EXCEPTION_ACCESS_VIOLATION (C0000005)`;
- `EIP = 0x004B5E11`;
- `ECX = 0x00000000`;
- a `BSTaskManagerThread<__int64>` worker;
- `QueuedModel` and `BSStream` for
  `DLC03\Traps\DLC03RadiationTrapLight.NIF`;
- live `EditorMarker`, `EditorMarker:0`, and parent scene nodes;
- 1.19 GiB process virtual usage out of 4.00 GiB.

The same run's Psycho log reports two installed IOManager workers and all
existing SpeedTree and static-geometry prerequisites. Memory pressure and an
allocator failure do not match the exception state: the failing instruction
dereferenced a NULL value reloaded from an engine global.

## Proven native contract

### Caller and ABI

The model-loader path is:

```text
BSTaskManagerThread
  -> QueuedModel / BSStream
  -> model loader 0x0043CCF0
  -> helper 0x0043AAF0
  -> scene/model post-loader 0x0043ACE0
  -> external CALL at 0x0043AFAC
  -> recursive postprocessor 0x004B5D10
```

The callsite is:

```asm
0043AFA0  mov  ecx,[ebp-60h]
0043AFA3  add  ecx,0Ch
0043AFA6  call 00559450
0043AFAB  push eax
0043AFAC  call 004B5D10
0043AFB1  add  esp,4
```

The external ABI is therefore:

```rust
unsafe extern "C" fn(scene_root: *mut c_void) -> u8
```

The scene root is passed on the stack, the caller restores four stack bytes,
and the callee returns a byte in `AL`. `0x0043ACE0` does not consume that
return. The recursive call at `0x004B5EFB` uses the same cdecl ABI and remains
inside the outer transaction.

Direct xrefs establish that `0x0043AFAC` is the sole external direct call to
`0x004B5D10`; `0x004B5EFB` is its recursive self-call. That distinction is the
performance basis for wrapping the callsite instead of the recursive function
entry.

### Shared fields, ownership, and lifetime

`0x004B5D10` owns two process-global fields:

| Address | Recovered role |
|---|---|
| `0x011C6328` | Root of the currently active traversal. |
| `0x011C6324` | Current target used for four virtual calls at vtable offset `+0x90`. |

The root is published near function entry. If the root owns the current
operation, completion clears both globals. The target is published at
`0x004B5D8A` and cleared at `0x004B5E9C`, `0x004B5F22`, or `0x004B5F48`.
Direct xrefs prove that this function is the writer of the target field.

The target-use sequence is:

```asm
004B5DDC  cmp  dword ptr [011C6324h],0
004B5DE3  je   004B5E5D
004B5DED  mov  ecx,[011C6324h]
004B5DF3  mov  edx,[ecx]
...
004B5E0B  mov  ecx,[011C6324h]
004B5E11  mov  edx,[ecx]       ; supplied crash, ECX == NULL
```

The function checks the global once and then independently reloads it before
each virtual call. There is no lock or second NULL check. A different
traversal can own the same globals and clear the target between
`0x004B5DF3` and `0x004B5E0B`.

### Root-cause conclusion

Directly proven:

- the crash is a NULL dereference at the second target use;
- the failed thread is executing a queued model load;
- the model has a valid live scene graph and `EditorMarker` branch;
- the target is process-global rather than task-local;
- the function reloads it after a successful earlier use;
- the same function clears the target on multiple completion paths;
- one external callsite encloses the complete recursive traversal.

Reasoned inference:

- another overlapping traversal cleared the target between its first and
  second use. The dump does not contain the clearing thread's simultaneous
  instruction pointer, but this is the only observed state transition that
  explains a successful `0x004B5DF3` dereference followed by NULL at
  `0x004B5E11`.

Runtime observation:

- the supplied run had two Psycho I/O workers. This makes the inferred
  interleaving easier to reach, but the engine contract also permits overlap
  between its native worker and synchronous main-thread loading.

## Safe intervention

### Boundary choice

Psycho changes only the direct call at `0x0043AFAC`. Its wrapper:

1. acquires a process-wide `parking_lot::ReentrantMutex<()>`;
2. calls the exact executable predecessor captured at installation;
3. keeps the lock across every recursive node visit and global clear;
4. returns the predecessor's byte unchanged;
5. releases the lock after the complete traversal returns.

This is narrower than an inline hook at `0x004B5D10`. An entry hook would run
on every recursive scene node and add lock/TLS work proportional to scene
graph size. The sole external call provides the same exclusion with one
uncontended lock acquisition per complete model postprocess transaction.

The mutex is reentrant because an already-installed predecessor may
synchronously re-enter model loading. A non-reentrant mutex could deadlock the
same thread in that compatible hook chain.

### Fingerprint and ABI protection

Installation verifies:

| Address | Bytes | Meaning |
|---|---|---|
| `0x0043AFA0` | `8B 4D A0 83 C1 0C` | Produce the scene-owner argument. |
| `0x0043AFAB` | `50` | Push the returned scene root. |
| `0x0043AFAC` | `E8 rel32` | Audited direct call; displacement may be mod-owned. |
| `0x0043AFB1` | `83 C4 04` | cdecl one-argument stack restoration. |

The helper call displacement at `0x0043AFA6` is deliberately not
fingerprinted. A compatible mod may own that independent helper while
preserving the argument and postprocessor ABI. The `E8` target itself is
accepted when its page is executable.

### Startup and dependency order

`engine_fixes::install` runs this fix in Syringe's pre-CRT activation barrier,
before native model tasks can execute. At that quiescent point the module:

1. verifies the surrounding ABI fingerprint;
2. reads the current direct-call target;
3. validates that target as executable;
4. constructs the static lock;
5. publishes the predecessor;
6. redirects the callsite;
7. publishes ready status.

Only successful ready status is passed to the native I/O subsystem.
Psycho's two-worker patch and LOD prefetch require model-postprocess readiness
in addition to their existing SpeedTree and static vertex-buffer guards. A
failed or explicitly disabled model guard therefore retains vanilla worker
topology and vanilla LOD demand; it does not leave a partially enabled
concurrency extension.

The model guard itself remains installed when `[io].parallel_enabled = false`
and when LOD is disabled.

## Mod-agnostic hook ownership

Compatibility is based on the executable call capability, not a mod identity:

- vanilla target present: capture and call `0x004B5D10`;
- earlier direct-call hook present: capture and call that executable target;
- later function-entry hook at `0x004B5D10`: the captured address reaches it
  under the Psycho transaction lock;
- later direct-call hook: a normal owner captures Psycho as its predecessor,
  so its chain still enters the serialized wrapper;
- no expected `E8`, invalid surrounding ABI, or non-executable predecessor:
  fail without patching the callsite.

At `DEFERRED_INIT`, Psycho observes callsite ownership. If a later executable
owner is present, Psycho preserves it. Rewrapping it is unsafe because a
well-behaved later owner already chains Psycho; forcing
`Psycho -> later owner -> Psycho` would recurse forever.

No native patch can guarantee compatibility with a destructive mod that
overwrites the same callsite and intentionally discards the previous owner.
Psycho reports that ownership transition and never guesses based on a DLL
name. This is the narrow unavoidable boundary of mod-agnostic call chaining.

The inspected ITR source only calls its `ModelLoaderQueueReference` engine
helper from command implementations. It contains no address or symbol match
for `0x0043AFAC`, `0x004B5D10`, `0x004B5E11`, `0x011C6324`,
`0x011C6328`, or `EditorMarker`. The engine fix neither patches nor builds ITR.

## Allocator and performance contract

The protected path:

- does not call the game heap, scrap heap, or gheap;
- does not inspect allocation metadata;
- does not free or retain a model object;
- does not change which thread owns or completes a queued task;
- performs no file I/O or routine logging;
- uses static lock/counter storage;
- performs one lock acquisition and two counter operations per complete
  uncontended postprocess transaction, with contention/waiter counters only on
  the blocking path.

The uncontended lock path performs no allocation. Any process-internal parking
bookkeeping needed by the lock implementation under contention is outside the
game/scrap allocator domains and is never paired with a game-object free.

The behavior is therefore allocator-agnostic across:

| `memory.allocator` | Mode | Contract |
|---:|---|---|
| `0` | Vanilla heap | Same static serialization; no allocator calls. |
| `1` | Scrap heap only | Same static serialization; no scrap allocation or free. |
| `2` | gheap plus scrap heap | Same static serialization; no pool/PDD interaction. |

Only simultaneous postprocess transactions wait. Recursive scene visits stay
inside the owning transaction without reacquiring through the external
callsite, and unrelated model/file work remains parallel.

## Failure behavior and diagnostics

Startup success includes:

```text
[MODEL_POSTPROCESS] EditorMarker transaction serialized at 0x0043AFAC; predecessor=0x........ (vanilla|chained)
```

The core diagnostic report exposes:

- installed state and direct/later/invalid owner classification;
- captured predecessor address;
- transactions started and completed;
- cumulative contentions and current waiters.

The helper dashboard uses additive `active_features` bit 9 for installed
status. The config checkbox and active bit are separate: changing config
requires a full process restart, and the active bit proves actual installation.

The wrapper does not swallow faults from the original engine/mod owner. If the
predecessor cannot be established, it does not call an assumed hard-coded
fallback. That avoids running the wrong ABI or bypassing another owner.

## Static validation

The focused suite includes:

- two model-postprocess transactions on different threads cannot overlap;
- the waiting transaction increments contention before it can enter;
- nested same-thread transactions complete without deadlock;
- the guard defaults on even when parallel I/O is explicitly off;
- explicit guard disable remains independent of an enabled parallel-I/O
  preference (runtime gating still retains the native worker topology).

Validation commands:

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes-helper --lib
cargo build --release --target i686-pc-windows-gnu \
  -p psycho-engine-fixes -p psycho-engine-fixes-helper
cargo fmt --all -- --check
git diff --check
```

Compilation and concurrency tests prove hook wiring, ABI type-checking, config
ownership, reentrancy, and mutual exclusion. They cannot replay the exact game
workload.

## Runtime acceptance matrix

Use the same save and model workload that produced the July 25 crash.

For each allocator mode `0`, `1`, and `2`:

1. run with `[io].parallel_enabled = false`;
2. run with `[io].parallel_enabled = true`;
3. require the model-postprocess startup success line and active dashboard bit;
4. load/traverse beyond the previous 6:34 playtime failure window and repeat
   save loads;
5. require no `C0000005` at `0x004B5E11`;
6. require model transaction completions to converge with starts and waiters
   to return to zero after loading;
7. require models, `EditorMarker` removal/processing, lights, and materials to
   remain correct;
8. with parallel I/O on, require two observed workers and all other scheduler
   prerequisites;
9. compare model-heavy loading time and frame pacing against the prior build;
   bounded contention is acceptable, permanent waiters or disabled model work
   is not.

Also test a clean vanilla-content setup and the user's full modlist. For any
pre-existing direct-call owner, require the startup line to report `chained`
and verify that owner's behavior still occurs.

## Evidence and reuse index

Implementation:

- `psycho-engine-fixes/src/mods/engine_fixes/model_postprocess.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/mod.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/io/mod.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/lod/mod.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/statics.rs`
- `psycho-engine-fixes/src/mods/engine_fixes/types.rs`
- `psycho-engine-fixes/src/config.rs`
- `psycho-engine-fixes/config/psycho_engine_fixes.toml`

Runtime evidence:

- `.reports/CrashLogger-2026-07-25-160311-model-postprocess.log`
- `.reports/psycho-engine-fixes-2026-07-25-160311-model-postprocess.log`

Existing generated analysis, retained unchanged:

- `analysis/ghidra/output/perf/graphics_fnv_native_render_state_fog_color_contract_audit.txt`
  (`0x004B5D10` body, globals, recursion, and call xrefs);
- `analysis/ghidra/output/perf/graphics_fnv_material_texture_slot_layout_followup_audit.txt`
  (`0x0043ACE0` caller and sole external call);
- `.research/itr-nvse-master/itr-nvse/internal/EngineFunctions.h`
  (`ModelLoaderQueueReference` helper used only for compatibility comparison).

Future changes to model loading, EditorMarker processing, I/O worker topology,
or this callsite must start from this contract and reconfirm executable
identity, caller ABI, global ownership, and direct-call xrefs.
