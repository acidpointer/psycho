# Source-texture cache publication guard

Status: reporter-validation candidate authorized under the explicit
reporter-only Psycho engine-fix exception. Static qualification does not prove
runtime acceptance.

## Purpose

This engine fix contains one invalid-object crash at FalloutNV's shared
source-texture cache publisher. It validates only the dispatch capabilities that
the publisher immediately consumes. A valid object follows the complete
pre-existing provider unchanged. An invalid object returns without inserting a
cache entry. The native publisher is void, every verified caller continues
without reading a result, and the publisher itself has an established no-op
branch while its cache is unavailable.

The fix does not claim to repair the unknown invalidating owner. It does not
retain, release, free, quarantine, substitute, or rewrite the object; inspect
allocator ownership; identify a DLL or mod; or require callbacks to belong to
FalloutNV.exe.

## Evidence sources

Runtime evidence:

- `.reports/CrashLogger--bstask.log`, captured 2026-08-20;
- `.reports/psycho-engine-fixes-latest--bstask.log`, captured 2026-08-18.

Static research used the radare2 MCP against the supported executable:

| Property | Value |
|---|---|
| File | `fnv_reverse/FalloutNV.exe` |
| Version | Fallout: New Vegas 1.4.0.525 |
| Format | PE32 x86, preferred base `0x00400000` |
| SHA-256 | `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c` |

All absolute addresses below apply only to that executable identity.

## Runtime observation

CrashLogger recorded `EXCEPTION_ACCESS_VIOLATION` on a
`BSTaskManagerThread` after 36 minutes 50 seconds. The instruction pointer was
`0x00009500`. The register and stack state was:

- candidate object in `ESI` and `ECX`: `0xDE24F5E0`;
- value loaded from the object as its vtable: `0x41800000`;
- callback loaded into `EDX`: `0x00009500`;
- return address from that callback: `0x00A61765`;
- return address from the helper to the shared publisher: `0x00A61C72`.

The same report associates the active loading context with a `BSFile`,
`BSStream`, two `QueuedModel` objects, and armor NIF paths. It reports 1.24 GiB
of virtual-address use out of 4 GiB and 1,382 loaded textures. These values are
context, not proof that a named asset or mod invalidated the object.

The Psycho log reports allocator mode 2 for its August 18 session. Its date is
two days earlier than the crash report, so it does not prove that the August 20
crash came from the same process or allocator mode. The fix therefore makes no
allocator attribution and remains active in modes 0, 1, and 2.

## Native contract proof

### Faulting virtual dispatch

`0x00A61C50` calls `0x00A61750` with the candidate. That helper performs:

1. load the candidate vtable from object offset `+0x00`;
2. call vtable slot `+0x98`;
3. call vtable slot `+0x94`;
4. use the larger returned dimension to select a cache bucket.

The callback call at `0x00A61763` returns to `0x00A61765`. The crash state
therefore exactly matches the first required virtual dispatch: vtable value
`0x41800000` supplied callback `0x00009500`, which is not executable user-mode
code.

The publisher then calls `0x00A617C0`. That helper calls candidate vtable slot
`+0x9C`, compares the result with existing cache entries through the same slot,
allocates a cache entry when needed, and increments the candidate's intrusive
reference count. The fallback at `0x00C5D560` also calls candidate slot `+0x9C`.
These three callbacks are therefore the complete immediate virtual capability
set required before publication can proceed.

The candidate reference count is the signed 32-bit word at object offset
`+0x04`. `0x00A617C0` increments that word only when a new cache entry retains
the candidate. Direct constructor evidence at `0x00A5D3A0`, `0x004968B0`, and
`0x00A8F440` initializes valid `NiRefObject` instances with a zero count. The
publisher therefore does not require a positive count on entry, and the guard
must not reject zero or use the count as a lifetime oracle.

### Shared caller coverage and ABI

The supported executable has exactly eight direct references to
`0x00A61C50`:

| Callsite |
|---:|
| `0x0043C596` |
| `0x0043C5BA` |
| `0x004569D8` |
| `0x0061512A` |
| `0x00A1FC2E` |
| `0x00A633B7` |
| `0x00B5594A` |
| `0x00C3B76F` |

Seven callsites push a null second word followed by the candidate. At
`0x0043C596`, the caller first tests and obtains `QueuedTexture+0x2C` through
`0x0055B980` and can pass that opaque pointer-like value as the second word.
The function returns with a plain `ret`; it consumes the candidate at the first
stack position and ignores the second word in this executable. Every caller
removes eight stack bytes and continues without testing a return value. The
hook preserves that cdecl shape and forwards both words unchanged so a chained
provider can still consume the opaque context.

The shared entry begins by checking the native cache pointer at `0x011F4468`.
When the cache is unavailable, it returns without locking, calling a virtual
method, retaining the candidate, or publishing an entry. Together with the
void callsites, this proves a native fail-closed boundary. Skipping while the
cache is active still omits a cache side effect; it is used only when the
dispatch required to perform that side effect cannot be called safely and is
not described as lifecycle-equivalent to successful publication.

### Concurrency and ownership limits

The publisher serializes cache lookup and insertion with the native lock at
`0x011F4480`. The invalid candidate is supplied before that lock can establish
object lifetime. The crash report proves the consumer thread and invalid
dispatch, but it does not identify the producer, invalidator, destructor,
allocation domain, or precise race window.

A guarded memory copy proves that the inspected bytes were readable during
the copy. It does not pin allocation identity or prevent another owner from
retiring or rewriting the object immediately afterward. Consequently this
guard contains candidates already observably invalid at its boundary; it
cannot prove or repair the unknown lifetime defect.

## Intervention and runtime cost

`engine_fixes.source_texture_cache_publication_guard` installs one inline hook
at `0x00A61C50`. The hook chains an executable provider already present at that
entry instead of requiring vanilla bytes or a module identity.

For each candidate it performs:

1. reject null, low, or unaligned object addresses;
2. copy the four-byte vtable pointer and require an aligned, non-low value;
3. copy slots `+0x94`, `+0x98`, and `+0x9C` in one twelve-byte operation;
4. require each distinct callback address to occupy committed executable
   memory;
5. copy the object vtable again immediately before forwarding and reject a
   value that became unreadable or changed during admission.

The admitted path then calls the captured provider with the original arguments.
It performs no Psycho allocation, file IO, log operation, blocking Psycho lock,
or ownership mutation. An invalid candidate increments bounded atomic counters
and logs only the first and power-of-two rejection before returning. Support
reports distinguish completed activation from current direct entry ownership,
expose rejection categories, and publish the last rejected address and reason
as one coherent atomic pair. If another provider displaced the entry, the
report says `displaced`; it does not claim whether that provider still chains
to Psycho.

Executable-page capability checks intentionally accept plugin code and reject
non-code regardless of module ownership. They prove neither a function entry
nor the callback ABI or callback body. This narrow capability boundary keeps
the fix allocator-mode agnostic and mod agnostic without allowlisting modules.

## Configuration and lifecycle

The shipped default is enabled:

```toml
[engine_fixes]
source_texture_cache_publication_guard = true
```

The core owns installation and enforcement. The helper only edits the TOML and
displays the late-bound direct-entry-ownership bit; changing the setting
requires a restart. Failure to resolve the guarded memory reader or install the
shared entry hook leaves native behavior in place and logs that the guard is
unavailable.

The guarded memory wrapper is isolated from the broad shared WinAPI module so
static-library code generation cannot make the helper retain its resolver,
strings, or atomic state. Final-image inspection must continue to confirm that
only the core contains the dynamic `ReadProcessMemory` capability.

This adds a core config field, a dynamically resolved memory-reader symbol, one
hook container, and bounded atomic state before xNVSE DeferredInit. It does not
add a static PE import, TLS value, thread, worker, file scan, or third-party
module lookup. The footprint change still requires the repository startup
safety playtest before release.

## Acceptance

The explicitly authorized static candidate gate is:

- affected core and helper tests pass for `i686-pc-windows-gnu`;
- the supported release target builds;
- formatting and `git diff --check` pass;
- final review confirms one shared hook, capability-based admission, unchanged
  valid forwarding, bounded hot-path work, and no allocator or mod identity.

Runtime acceptance remains unresolved. The reporter must run the representative
Proton/Wine modlist through the affected loading workload with the default guard
enabled. Acceptance requires:

- the log confirms the guard installed and later rejected at least one
  publication;
- the game continues through the same loading activity into normal gameplay;
- no matching `0x00A61765` / callback-address access violation occurs;
- a support report shows activation completed and Psycho directly owns the
  shared publisher entry, or explicitly reports a displaced entry for separate
  chain investigation;
- allocator modes 0, 1, and 2 receive coverage before the fix is described as
  allocator-independent runtime-proven behavior.

Until that evidence exists, this is a defensive reporter-validation candidate,
not proof of the invalidating root cause and not a release-ready fix.
