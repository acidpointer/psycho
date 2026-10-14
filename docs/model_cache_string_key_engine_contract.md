# Native model-cache string key contract

Status: shared NULL-consumer repair implemented as an unreleased
reporter-validation candidate. The operation which produced the NULL stored
key remains unresolved. New-candidate gameplay and startup acceptance are not
established; the owner's existing gameplay-validation waiver remains in force.

## Runtime evidence

The owner's extreme-speed exterior flight reached an access violation at
`0x00EC6DB0` inside native `strcmp`. The report records `EDX=0`,
`ECX=0x0170F2D8`, and return address `0x004496E4` at the top of the raw stack.
The receiver is classified as `LockFreeCaseInsensitiveStringMap<Model*>`,
with vtable `0x01017154`. The supplied playtime is `00:08:17`.

Preserved incident inputs:

- `.reports/CrashLogger-20261014-001726-lod-stress.log`;
- `.reports/psycho-engine-fixes-20261014-001726-lod-stress.log`;
- `.reports/psycho-engine-fixes-20261014-001726-lod-stress-deployed.dll`.

The deployed artifact matches the preceding normal release build. Its log
reaches core initialization and game-ready notification. The new fault is a
stored string key, distinct from the prior Havok entity consumers. Longer
survival does not prove that every prior defect or the upstream invalidation
has been corrected. Memory-pressure warnings, unrelated zero-reference objects
on the stack, and core profiling frames do not establish allocator or mod
attribution.

The report is the real-runtime failure evidence. The engine call chain cannot
execute in the local game runtime; implementation uses the owner's existing
exception and binary proof, rather than a diagnostic-only artifact or another
request for a dump/game run.

## Executable and native proof

The supported input is `fnv_reverse/FalloutNV.exe`, Fallout New Vegas
`1.4.0.525`, PE32 x86, image base `0x00400000`, executable SHA256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
CodeView GUID `9196089162EE4D29BF48E8D767B32DB91`.

Primary disassembly and layouts were reverified through radare2 MCP. Its
section-search operation reported a restricted search range; a read-only
local radare2 section search supplements the function-pointer inventory.
The authoritative focused output is
[the native NULL-key audit](../analysis/radare2/output/perf/model_cache_null_key_crash_audit_20261014.txt).
Existing comparison evidence is retained in
`analysis/ghidra/output/crash/lockfree_model_map_contract_audit.txt` and
`analysis/ghidra/output/crash/lod_bstree_tls_slot_exhaustion_root_cause_audit.txt`.

The incident chain is:

`ModelLoader 0x00445300 -> case-fold lookup 0x004493D0 -> locked lookup
0x00449530 -> map lookup 0x006EC830 -> result publication 0x006EC9B0 ->
search 0x006662A0 -> ordering 0x004496D0 -> strcmp 0x00EC6DA0`.

`0x004493D0` reserves a stack buffer at `EBP-0x3F0`, lowercases the incoming
query, and terminates it before calling locked lookup. The reported query
address equals that buffer in the reported wrapper frame. The first argument
to `strcmp`, not this query, is NULL: search loads the current node's key into
`[EBP-0x14]`, pushes the query and then this saved key, and dispatches ordering
through map vtable slot `+0x34`.

| Native boundary | ABI and result |
| --- | --- |
| `0x004496D0` string ordering | `__thiscall(map, stored_key, query)`, Boolean in AL, `RET 8`; native result is `strcmp(stored_key, query) >= 0`. |
| `0x00449880` string equality | Same argument ABI and stack cleanup; result consumed in AL. |
| `0x00EC6DA0` CRT comparison | Cdecl, two string arguments, caller cleans eight bytes; `0x00EC6DB0` reads the NULL first string. |
| `0x006662A0` and `0x00529030` generic searches | Thiscall search context, hash/query arguments, AL result, `RET 8`. |

The ordering/equality providers occur in six native string-map vtables:
`0x01017154`, `0x010171EC`, `0x0101723C`, `0x010172DC`, `0x0101732C`, and
`0x0101737C`. Ordering is slot `+0x34`, equality `+0x38`. The repair hooks the
shared ordering entry; it does not classify a receiver by vtable at runtime.

Both generic search templates dispatch those slots. Their key snapshots and
native false branches are equivalent:

| Search | Ordering / equality calls | Ordering false | Continue iteration |
| --- | --- | --- | --- |
| `0x006662A0` | `0x0066641B` / `0x0066643B` | `0x00666442` | `0x006664CA -> 0x0066632C` |
| `0x00529030` | `0x005291AB` / `0x005291CB` | `0x005291D2` | `0x0052925A -> 0x005290BC` |

Each false branch retains the native current node, advances the predecessor to
its next link, publishes the existing hazard slot, copies next to current, and
re-enters the native validation loop. It does not return an immediate map miss.
Equality receives the same stored-key snapshot and is reached only after
ordering returns nonzero. Rejecting that NULL snapshot at ordering therefore
also protects the following equality call in both templates; no independent
equality hook is needed.

Native direct caller coverage of the search templates is:

- `0x006662A0`: insertion `0x0044D2A8`, lookup/key update `0x0044EBA7`, removal
  `0x006660A5` and `0x0066617A`, result publication `0x006EC9C4`;
- `0x00529030`: insertion `0x0044D0D8`, result publication `0x0044D524`, key
  update `0x0044E6AC` and `0x00906C37`, removal `0x00528D05` and `0x00528DDA`.

These callers already use each search's native cursor and found/not-found
result. Skipping an invalid key preserves their search state, subsequent
insertion position, removal decisions, and native publication/cleanup. The
guard never returns a fabricated value/model or edits the output pointer.
Generic map entry points also serve integer/pointer keys, where zero can be
valid, so those generic entry points are not NULL-guarded.

## Ownership, lifetime, and concurrency

For the faulting template, a node has key at `+0`, model value at `+4`, and
tagged next link at `+8`. The search context contains map at `+0`, native
publication pointers at `+4/+8/+0xC`, predecessor link at `+0x10`, current at
`+0x14`, and next at `+0x18`. Pointer helpers mask the native deletion bit.
The native lookup acquires/releases map lock `+0x20`; no-lock lookup
`0x004498B0` remains governed by its native caller contract. Native result
publication retains `0x00529000` context cleanup on both search results.

The guard reads none of these fields. It only tests the stored-key argument
already supplied by the native consumer. It owns no key bytes, node, hazard
slot, model, reference count, lock, or allocator state. For every non-NULL
stored key, the captured provider retains its original string validity,
receiver, lifetime, synchronization, and query preconditions. The guard does
not probe or repair dangling non-NULL pointers.

The native case-fold key clone at `0x004492F0` allocates and copies its string
before publishing it through node construction `0x006ECBD0`. A NULL clone
allocation would fault while copying; the supplied report does not establish
that this path produced the NULL node key. The invalidating owner/thread,
whether a node was reclaimed or reused, the exact lifetime race, allocator
involvement, and mod involvement remain unknown. No destructor or reclamation
hook, ownership mutation, provider allowlist, or third-party patch is justified
by this evidence.

## Intervention and failure containment

`psycho-engine-fixes/src/mods/engine_fixes/model_cache_keys.rs` installs one
core-owned entry guard at `0x004496D0` before IO/LOD setup. The entry's existing
provider is captured and retained. Non-NULL keys chain it with unchanged map,
key, query, and byte result; an admitted NULL stored key returns AL=0 with the
original stack cleanup. Native traversal then advances normally.

The installer verifies both native argument/predicate blocks and cursor
advance/restart stores before preparing the entry hook. It does not require
vanilla entry bytes: an already-installed ordering provider must be preserved.
Activation uses the existing ownership-aware transaction. The provider is
published before enable; admission is published after commit. A failed or
unadmitted rollback survivor forwards unchanged through its process-lifetime
trampoline. An installation failure logs that NULL-key protection is
unavailable while allowing independent engine fixes to continue.

The repair is allocator-mode agnostic and retains every existing engine-fix
and LOD setting. It adds no configuration field or core/helper ABI. A first
rejection emits `[MODEL_CACHE] NULL stored string key skipped; native search
continues` once per process, from the established core logger. Later rejects
return the same native false result without repeated warning output.

## Cost, startup, and qualification

The valid path adds one NULL test, one captured-provider load, a small stack
frame setup/restore, and a tail jump to that provider. It introduces
no routine allocation, lock, timer, model copy, memory query, reference change,
or successful-call counter. A NULL entry costs an existing native iteration;
multiple invalid entries cost multiple iterations rather than an immediate
whole-map miss. No FPS or stress-survival improvement is claimed from this
deterministic work budget.

The pre-Deferred change is one core-owned lazy hook owner, two admission/log
flags, a cached provider, immutable fingerprints, and startup hook preparation
at the existing quiescent barrier. It adds no thread, parser, TLS owner, startup
callback, import API, or cross-DLL ownership. Startup comparison follows
[the owning safety contract](nvse_startup_phase_safety.md) against the deployed
artifact from this incident. Static agreement is not a new Proton startup
acceptance result.

The focused offline regression calls the actual production detour with a NULL
stored key. It observes native AL=false without a provider or receiver access,
including repeated rejection. It does not simulate a native map, reference
implementation, or modded game workload. The affected crate tests, supported
32-bit release build, compiled thiscall/provider inspection, formatting,
`git diff --check`, and final diff review qualify the candidate statically.

The original native failure is established by the supplied CrashLogger report.
The rebuilt candidate has not run the owner's flight or load-to-gameplay path.
It closes the proven NULL-consumer contract; it does not establish why the key
became NULL or prove complete stress-test stability. Reporter confirmation of
an actual rejection followed by continued gameplay remains the acceptance
condition for this defensive candidate before any release claim. No game run
is requested or required of the owner by this work. The candidate is not
installed, packaged, or released.
