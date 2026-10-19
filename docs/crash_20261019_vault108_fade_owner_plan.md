# Vault 108 invalid fade-node owner: investigation and containment

Status: implemented as an unreleased invalid-owner-read containment candidate
under the reporter-only engine-fix exception. Reviewed offline checks, the
affected crate suite and the supported 32-bit release build pass. The upstream
invalidating writer remains unknown; runtime behavior has not been accepted.

Last updated: 2026-10-19.

## Report and preserved evidence

The owner reported an intermittent crash while travelling through Vault 108
and could not reproduce it. The report does not identify a repeatable save or
action sequence. Research used the existing failure; no game was launched.

The original logs are symlinks into the installed game. Copies of both complete
logs and the deployed configuration are preserved under
`.reports/20261019-vault108-owner-link/` so another launch cannot replace this
incident's evidence:

- `CrashLogger.log`: crash at 2026-10-19 14:59:37 local time, after 9:07 playtime;
- `psycho-engine-fixes-latest.log`: corresponding UTC session;
- `psycho_engine_fixes.toml`: allocator mode 2, occlusion planes enabled,
  grid radius 0, maximum 128 planes.

The exception happened during gameplay in `Vault108a`, cell `0601852D`, at
position `(2337.88, -561.01, 7168.08)`. Startup completed and the game-engine-ready
event ran. This is a rendering-time incident.

## Confirmed failure

The rendered `BSFadeNode` named `StreetLitter02` contains an invalid linked
reference at offset `+0xCC`. The actor-alpha callback treats that non-NULL
pointer as a game object and tries to read its type-test vtable slot. Its first
word is `0x65727453`, whose little-endian bytes spell `Stre`, rather than a
usable vtable address. That read raises the access violation.

| Boundary | Captured value or verified operation |
|---|---|
| Node argument and ESI | `0xD0ECAA00`, vtable `0x010A8F90`, reported refcount 2 |
| Node's linked reference, ECX | `0xFE9F8F68`, loaded from `node + 0xCC` |
| Supposed reference vtable, EAX | `0x65727453`, loaded from `[ECX]` |
| Faulting instruction | `cmp dword [eax + 0x100], 0x008D0360` |
| Faulting read address | `0x65727553` |
| Runtime EIP | `0x0A700030` |
| Installed callback location | module base `0x0A6D0000`, RVA `0x30030` |

The installed Stewie callback is the fault site. This establishes its unsafe
consumption of the invalid link; it does not establish that Stewie created the
invalid link. Only four bytes of the pointed-to payload are known. The complete
string, whether it is the node's name, the allocation identity, and any
free/reuse history are unknown. A use-after-free is not yet proven.

Exact installed instructions, register arithmetic, binary identity, and the
source cross-check are in the
[fault-boundary evidence](../analysis/radare2/output/crash_20261019_vault108_fault_boundary.txt).
The third-party source and installed binaries were read only.

## Verified native contract

The installed executable and repository research executable match: FalloutNV
1.4.0.525, PE32 i386, image base `0x00400000`, SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`.
Addresses below are for that executable. Corrected CLI captures configure
relocations before loading; the initial audit retains its configuration warning.

The reliable stack entries and exact instructions establish this path:

1. Native visibility traversal reaches the node through `0x00C39A37`, returning
   to the reported `0x00C39A3C`.
2. The fade update calls native alpha helper `0x00B4DF80` at `0x00B4E772`.
3. The helper passes the node in a stack argument to the callback stored at
   `0x011F9134`. The crash stack contains its return address `0x00B4DF91`.
4. The installed callback loads `node + 0xCC`, then the supposed reference's
   vtable, then faults at vtable offset `+0x100`.

The helper uses ECX for the node and returns alpha in x87 ST(0), with no stack
arguments of its own. The callback is cdecl with one node argument and an x87
floating-point return. Its caller removes that argument. Native registration
`0x0086BDE0` writes the callback slot.

The unmodified game callback at `0x0086A050` has the same non-NULL owner trust:
it calls the owner's virtual at `+0x100`, then actor alpha at `+0x420` for an
actor. It returns `1.0` for a NULL owner or a non-actor. Replacing the installed
callback with vanilla therefore does not repair the invalid-owner contract.
See the [vanilla callback audit](../analysis/radare2/output/crash_20261019_vanilla_fade_alpha_20261019.txt).

Ownership evidence already rules out a guessed unconditional-clear patch:

- `BSFadeNode` construction at `0x00B4E150` initializes `+0xCC` to zero.
- Setter `0x0056C7D0` writes its argument directly to `+0xCC`, uses ECX for the
  node, and returns with `ret 4`; the setter does not retain the reference.
- `TESObjectREFR::Set3D` at `0x005702E0` contains both an old-node clear at
  `0x005707A7` and a new-node association at `0x00570D97`.
- Helper `0x009B28A0` compares the existing link with its supplied reference
  and clears only a matching link at `0x009B28D2`.

The setter has seven discovered direct native callers:
`0x0056BA84`, `0x005707A7`, `0x00570D97`, `0x00577F73`, `0x0081E691`,
`0x009ACC67`, and `0x009B28D2`. This inventory does not prove coverage of
third-party writes, inlined stores, or indirect calls. The alpha helper
`0x00B4DF80` has one discovered direct native caller, `0x00B4E772`. The generic
owner getter has other consumers, so alpha containment would not repair every
use of a bad link.

Supporting evidence:
[native path and Set3D](../analysis/radare2/output/crash_20261019_vault108_owner_link_audit.txt),
[constructor, destructor and clone](../analysis/radare2/output/crash_20261019_vault108_owner_link_followup.txt),
[setter callers](../analysis/radare2/output/crash_20261019_fade_owner_setter_callers_20261019.txt),
[conditional owner clearing](../analysis/radare2/output/crash_20261019_node_owner_retirement_20261019.txt).
No capture proves the invalidating thread, write order, or a safe ownership
repair point.

## Correlation and attribution limits

The final Psycho entry at `11:59:36.482Z` installs ten cached occlusion planes
for cell `0601852D` and removes eight from the previous set. The previous
transition at `11:59:30.552Z` selected cell `06018533`. This establishes a nearby
cell transition and plane reconciliation, not a plane write into the fade node.
The logged observer position also differs from CrashLogger's player position;
the reason is unresolved. Do not use the logs as an exact frame-order trace.

The inspected collector reads reference/mesh data; the injector creates plane
objects and mutates its occluder-list membership. No retained write trace or
controlled comparison connects it to `node + 0xCC`. This inspection does not
exclude an indirect lifetime or concurrency defect.

The last VAS sample reports 770 MB free with a 408 MB largest hole. The earlier
allocator summary reports no block or virtual allocation failures. These
samples do not establish final OOM as the cause, and do not exclude memory
corruption. Mode 2 being enabled does not attribute the bad link to gheap.
CrashLogger's unwind annotations and its DbgHelp-copy error are not evidence
of the invalidating writer.

## Static closure and chosen implementation boundary

The owner's follow-up excludes diagnostic-only game builds. No debug build,
instrumented playtest, new dump, or repeatable reproduction is a prerequisite
for this analysis or for designing the bounded candidate below. The
[reporter-only exception](psycho_engine_fix_exception.md) explicitly permits
the invalidating owner and exact race to remain unresolved for a separately
authorized defensive implementation. This is the appropriate contract for the
available evidence; an ownership repair is not established by it.

The selected intervention is the five-byte native direct call at
`0x00B4E772`, inside `BSFadeNode` visibility/fade processing at `0x00B4E490`.
Use an ownership-aware `Rel32CallHookContainer` to capture and chain the live
callee. Do not replace the callback at `0x011F9134`: native registration writes
that slot from WinMain, and the existing helper already loads its current
value on every call. Chaining the helper preserves that late registration and
later callback changes without discovering or patching their owners.

The new [complete consumer audit](../analysis/radare2/output/crash_20261019_fade_alpha_consumer_closure.txt)
contains the full fade function, helper, registration, direct references and
absolute address searches. It establishes:

- One direct native call to `0x00B4DF80`, at the selected callsite. The mapped
  binary search finds no stored absolute pointer to `0x00B4DF80`.
- The callback-slot address occurs in its native registration write, the
  helper's NULL check and its indirect call. The sole discovered registration
  caller is `0x0086AA28`. The default callback address is stored as the immediate
  argument at `0x0086AA24`.
- At the selected call, ECX is loaded from ESI, the current fade node. No stack
  argument is pushed for this helper. Its floating-point result is immediately
  stored with `fstp dword [esp+0x18]`.
- Alpha `1.0` bypasses the special `0 < alpha < 1` actor-opacity path and keeps
  native distance fading and child visibility processing. It does not detach
  the node or force its distance-fade fields to one.
- The remaining fade function does not reload `node+0xCC`. Its ordinary alpha
  writeback walks geometry/material properties, and child visibility traverses
  child nodes. Neither helper consumes the rejected parent owner pointer.
  Each visible child fade node reaches its own alpha boundary.

The last point is supported by the
[native alpha writeback](../analysis/radare2/output/crash_20261019_fade_alpha_writeback_20261019.txt)
and [child traversal](../analysis/radare2/output/crash_20261019_fade_child_visibility_20261019.txt)
audits. This proves the immediate native continuation for a valid render node
with an unusable linked owner. It does not validate a corrupt node, child array,
material, or arbitrary third-party callback body.

### Exact patch and ABI

Qualify the input and output context separately from the live call target:

| Address | Required native context |
|---|---|
| `0x00B4E764` | `8B 0D 38 91 1F 01 89 8E C8 00 00 00 8B CE` |
| `0x00B4E772` | Complete `E8 rel32` instruction; capture its live target |
| `0x00B4E777` | `D9 5C 24 18` |

The original direct call is `E8 09 F8 FF FF`. Do not require its displacement
to stay vanilla when a compatible provider already owns this native caller.
The container compares all five captured bytes before activation and restores
only a still-owned instruction. Signature or preparation failure leaves the
feature inactive and other engine fixes running.

The detour and captured callee type are
`unsafe extern "thiscall" fn(*mut c_void) -> f32` on
`i686-pc-windows-gnu`: node in ECX, no stack parameters, ordinary `ret`, and one
alpha value in x87 ST(0). EBX, ESI, EDI and EBP remain ABI-preserved. The caller
overwrites ECX after the call and consumes no integer return value. The hook
does not replace the enclosing visibility method, which has its own argument
and `ret 4`. `libpsycho::ffi::fnptr::Function` supports this exact function
pointer shape. The emitted candidate ABI is reviewed below; that review does
not certify game-runtime behavior.

### Exact admission behavior

Keep the candidate specific to the reported unreadable owner-vtable prefix.
It must not classify form identity, allocator ownership or code ownership.
Use the existing
[guarded reader](../libpsycho/src/os/windows/guarded_memory.rs), with stack-local
four-byte buffers and checked address arithmetic:

Every four-byte read must also reject overflow of its inclusive last address
(`address.checked_add(3)`); all address calculations use the supported 32-bit
pointer width.

1. Copy the owner pointer at `node + 0xCC`. Reject an arithmetic overflow or
   failed/incomplete copy. The guard itself never dereferences the engine
   address directly.
2. A NULL owner is a valid input: call the captured callee unchanged. Do not
   short-circuit its provider-specific behavior.
3. For a non-NULL owner, copy its first four bytes, the vtable address. Reject
   a failed/incomplete copy or NULL vtable.
4. Copy exactly four bytes at `vtable + 0x100`, after checking both the offset
   and range-end arithmetic. Reject a failed/incomplete copy. This is the
   precise read that faulted in the supplied report. Do not interpret or invoke
   the copied type-test callback.
5. On admission, call the captured callee once with the original node and
   return its result unchanged. On rejection, return exactly `1.0f32` without
   invoking that callee. Never clear or replace `node+0xCC`.

For the captured state, the third copy requests `0x65727553..0x65727556`, the
four-byte range whose native read faulted. If that captured state is present
at admission, the failed copy takes the established neutral-alpha result.
This is a direct correspondence to the executed invalid read, not a guessed
form-type, vtable alignment, heap-size or module test.

Do not add a check of `vtable+0x420` for every owner: the native callback reads
that slot only after its actor predicate succeeds. Doing so would impose a
new requirement on valid non-actor owners. Do not call the type predicate an
extra time, allowlist the engine's return-true function, or inspect callback
machine code to infer its behavior. Those choices would change provider
semantics. A readable but semantically wrong owner, invalid actor-specific
state, or a bad executable callback remains outside this narrow candidate.

The reader already checks API success and exact byte count. Microsoft's
[ReadProcessMemory contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
defines a failed read for an inaccessible requested range. A page-readability
probe followed by a direct Rust read would leave an unsafe race between them;
it is not the selected mechanism. Microsoft also documents
[IsBadReadPtr](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-isbadreadptr)
as obsolete and unsuitable as an object-validity guarantee.

Preserve the entry thread's last-error value around validation with existing
`winapi::get_last_error_code` and `winapi::set_last_error` wrappers. Restore it
immediately before calling the predecessor; do not overwrite changes made by
the predecessor afterward. On rejection, restore it after any rejection
reporting and before returning. This prevents the new Win32 copies from
altering a valid provider's input thread state. The semantics are documented
by [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)
and [SetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setlasterror).

### Lifetime and concurrency scope

Each guarded copy fails safely if its requested range becomes inaccessible
during the copy. It does not retain or pin the object. The three snapshots do
not form an atomic object snapshot, and the native provider can still encounter
invalidation after admission. Do not claim to close that race, cache a
readability result across calls, or replace the node with a fabricated snapshot.

This limit is consistent with the established
[source-texture containment contract](source_texture_cache_publication_guard.md).
The intervention needs no new claim about which thread owns reference
retirement: its new reads use the guarded-copy API, all local state is on the
stack, it changes no native object, and an admitted provider retains its
existing engine lifetime/threading contract. The supplied report does not
prove the invalidator, and static analysis has not identified one. That fact
is an upstream attribution limit, not a reason to require a debug build before
implementing this bounded consumer guard under the reporter-only exception.

### Installation, rollback and scope

The production changes are one new engine-fix module,
`psycho-engine-fixes/src/mods/engine_fixes/fade_linked_owner_guard.rs`, and its
private declaration/nonfatal installer call in `engine_fixes/mod.rs`.
Follow the existing always-installed model-cache guard rather than adding a
configuration field, helper ABI, dashboard controls or dependency.

Install through the existing core startup chain:
`entry::activate_from_loader` -> `startup::initialize` ->
`install_engine_fix_hooks` -> `engine_fixes::install`. The entry refuses
activation without Syringe's pre-CRT barrier. Do not install on a live frame
or add a new lifecycle event.

Preparation resolves the existing guarded reader and copies both complete
instruction-context ranges before comparing them. It does not substitute a
one-byte probe followed by direct foreign reads. It then creates the hook and
obtains its typed predecessor before any code write. Publish a process-lifetime
predecessor pointer before activation.
Enable the callsite in one `ModificationTransaction`; publish admission only
after transaction commit. An unadmitted rollback survivor must chain its
retained predecessor unchanged. The static hook and predecessor are never
destroyed or reset while the detour can be reached.

`Rel32CallHookContainer::original` uses its initialized predecessor storage
without the container's `RwLock`; alternatively the module can use the
explicitly published `AtomicPtr` pattern already used by the model-cache
guard. Do not call `is_enabled` or acquire the hook container's ownership lock
for every fade node. Ownership inspection belongs to setup or an existing
cold support-report path. Never repatch after another owner changes the site.

Use the stable `[FADE_OWNER]` tag for installation failure and the first
rejection. Do not add per-node admitted-path counters or logging. A single
atomic rejection marker can suppress repeated warnings. This is production
containment reporting, not a separate diagnostic-only executable.

The design introduces no new external API, worker, PE TLS variable, serialized
config layout or helper/core API. It does introduce core hook state, code and
startup preparation. The complete
[startup contract](nvse_startup_phase_safety.md) still applies to the later
compiled candidate: record the existing startup baseline before editing and
compare the relevant import/TLS/startup footprint after the supported release
build. Do not label the resulting artifact startup-accepted from source alone.

### Deterministic cost and qualification

The admitted non-NULL-owner path has three fixed four-byte memory copies,
twelve requested bytes total, two last-error wrapper calls, bounded integer
checks and one original callee invocation. A NULL owner needs one copy. Failed
reads stop at the first failure. There is no scan, loop over foreign data,
page-query cache, allocator query, persistent per-node state, new native lock,
Psycho blocking lock, admitted-path allocation, file I/O or admitted-path log.
These are source-level work bounds, not a latency or FPS measurement. The
additional API cost on a scene with many fade nodes remains unmeasured and
must be reported as such for the candidate.

Qualify the actual production guard and
memory reader with focused offline checks, the affected crate suite,
formatting, the supported 32-bit release build, emitted hook ABI review,
startup-footprint comparison, `git diff --check` and final diff review.
Checks must exercise production code; source assertions, mock native
callbacks, reconstructed rendering and simulated gameplay are not acceptance.
Offline checks support the supplied runtime failure under the exception; they
are not a new game reproduction. No diagnostic game build is required.

The candidate remains allocator-mode and mod agnostic. Normal release and
runtime acceptance remain distinct from permission to begin implementation:
the reporter-only exception requires an observed rejection and continued
gameplay before the candidate can be called runtime-accepted, and the startup
contract retains its release gate. Deployment remains user-only.

## Candidate implementation and qualification

The owner explicitly authorized implementation for this incident on 2026-10-19:
"proceed with implementation. Be carefull - separate agent is in progress on
separate tasks". This authorizes the bounded candidate under the
[reporter-only exception](psycho_engine_fix_exception.md); it does not establish
runtime acceptance or authorize deployment or a commit.

The production
[guard](../psycho-engine-fixes/src/mods/engine_fixes/fade_linked_owner_guard.rs)
implements the admission and predecessor-publication contract above. Its only
shared installer changes are the private module declaration and nonfatal
installation call. Other concurrent workspace changes remain outside this
incident's scope.

Focused offline checks execute the actual production validator, detour and
guarded Win32 reader against owned readable and inaccessible pages under Wine.
They establish neutral-alpha rejection without a helper invocation, preservation
of last-error across repeated rejection, arithmetic-overflow rejection, NULL
owner admission and omission of the unused actor-only slot. The reviewed cases
include four-byte reads straddling an inaccessible page at every pointer-chain
step, overflow of both slot-start and inclusive range-end calculations, and
unchanged node-link and owner words after rejection. They do not mock a native
callback, reproduce the game scene or establish a valid object's lifetime. The
supplied crash remains the real-runtime failure supporting this exception.

The reviewed implementation passes the focused production-boundary checks,
affected crate suite, supported release build, formatting, documentation checks
and final diff checks. These results qualify the offline candidate without
claiming that gameplay or the upstream lifetime defect has been tested.

The initial core release
[disassembly](../analysis/radare2/output/crash_20261019_fade_owner_candidate_abi.txt)
confirms the ECX node input, unchanged predecessor tail call, x87 `1.0` rejection
with ordinary `ret`, preserved nonvolatile registers, and predecessor publication
before activation followed by admission after commit. The subsequent review
changes instruction-context reading during installation and expands tests; it
does not change the detour body or its ABI. That earlier installation capture
predates the complete guarded context copies described above.

The review also checks native continuation after rejection, live callback
registration, NULL-owner delegation, foreign-memory access, all arithmetic,
last-error restoration, process-lifetime predecessor storage, activation order,
failed-activation forwarding and ownership-aware rollback. No node link is
cleared, no type predicate is called an extra time, and no actor-only state is
read unconditionally. The invalidating writer and invalidation after admission
remain outside the established consumer contract. Further probes cannot pin
the object or turn this admission guard into an ownership repair.

## Evidence-gap disposition

| Implementation question | Static result |
|---|---|
| Shared boundary and native coverage | Closed: one helper call, no stored helper address found; direct native callsite selected |
| Input/output ABI and patch bytes | Closed: ECX node, x87 alpha, no helper stack parameters, exact context and five-byte call |
| Every inspected field | Closed: owner `+0xCC`, owner vtable `+0`, one four-byte type slot at `+0x100` |
| Fail-closed result and propagation | Closed for the reported owner-read defect: native `1.0` fallback; continuation does not consume the rejected parent owner |
| Safe new foreign-memory access | Closed by existing guarded reader and its exact-count contract; no direct Rust dereference |
| Valid NULL/static/actor behavior | Closed by forwarding the captured provider, with no extra predicate call or unconditional actor-slot check |
| Chaining, initialization and rollback | Closed by existing direct-call container, transaction and predecessor-publication patterns |
| Threading and ownership policy | Closed for bounded admission: no native mutation or lifetime claim; post-admission invalidation explicitly outside scope |
| Allocator/mod independence | Closed: no allocation classification, form/code allowlist, module discovery or external patch |
| Runtime work bound | Closed at source level: one or three four-byte copies; actual latency remains unmeasured |
| Invalidating writer, freed-slot history and exact race | Not established; not a prerequisite for this defensive candidate under the reporter-only exception |
| Hook ABI | Established by native and emitted detour disassembly; review preserves the detour body/signature |
| Startup and game acceptance | Not established by offline checks; remains the separate release/runtime gate |

The static design gaps for this specific defensive implementation are closed.
This does not turn the unknown invalidating writer into a proven root cause or
establish an ownership repair. The candidate remains unreleased and requires
the exception's observed rejection with continued gameplay, plus the startup
acceptance gate, before any runtime-accepted or release claim.
