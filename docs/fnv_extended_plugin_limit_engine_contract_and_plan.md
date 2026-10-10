# FNV extended plugin limit engine contract and implementation plan

Status: research and design proposal. Production implementation is blocked by
the unresolved contracts and behavioral gates below. No expanded plugin limit
is implemented or qualified by this document.

The objective is to load substantially more ordinary ESP/ESM files while
preserving their existing record identities, master relationships, overrides,
scripts, assets, and saved state. A larger selected-file table alone cannot
provide that behavior. Native file ownership, runtime FormIDs, extender-owned
data, and serialization must agree on an identity representation.

The requested policy is the largest evidence-backed capacity, without an
arbitrary configured selected-file ceiling. Use dynamically sized owned
storage; 1,024 is no longer a proposed limit. Selected-file count, record-handle
capacity, save-reference capacity, per-file master selectors, open streams,
and 32-bit address space impose separate bounds. No supported maximum has yet
been established. Unlimited capacity is impossible in this finite process.

The core must work without xNVSE. Engine identity, loading, and persistence
belong to Psycho itself. Optional helper consumers may require xNVSE; that
must never become a dependency of the core. Independent ownership does not
change the private representations of other installed DLLs.

## Evidence and executable scope

The primary binary is `fnv_reverse/FalloutNV.exe`: SHA-256
`42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`,
PE32 x86, preferred image base `0x00400000`, CodeView GUID
`9196089162EE4D29BF48E8D767B32DB91`. Addresses in this document are preferred
virtual addresses in that image. Version labels do not authorize their reuse
in a different executable.

[Raw radare2 evidence](../analysis/radare2/output/fnv_extended_plugin_identity_contract_20261010.txt)
preserves boundary bytes, disassembly, discovered callers, and local extender
source excerpts. The inspected loader boundary bytes agree at all 28 operand
sites and nine function entries listed below. This proves those bytes in this
image; it does not prove that every consumer was found or that a patch is safe.
Level 1 analysis discovers direct references and some data references. It does
not establish complete indirect, vtable, extension, or inlined caller coverage.

The local xNVSE submodule is revision
`694cdde6cbfa5e75afa661df587c73e8f0f6f441`; its version header declares 6.4.4.
`PluginAPI.h` has pre-existing local changes. Local source findings must not be
represented as instruction-level proof for a different deployed extender.
The upstream 6.4.9 sources independently retain the
[byte-valued file APIs and fixed active-file cache](https://raw.githubusercontent.com/xNVSE/NVSE/6.4.9/nvse/nvse/GameData.cpp)
and [high-byte form owner extraction](https://raw.githubusercontent.com/xNVSE/NVSE/6.4.9/nvse/nvse/GameForms.cpp).
The official 6.4.9 source archive was also inspected for mod-local data,
arrays, strings, serialization, lambdas, and caches. These findings agree with
the byte-ownership contracts below; they are source evidence, not complete
instruction-level qualification of the installed DLL. The installed engine
executable matches the researched executable exactly.

The [admission and persistence evidence](../analysis/radare2/output/fnv_extended_plugin_admission_and_persistence_contract_20261010.txt)
records the additional loader, native plugin-list, shared-accessor, generated
cursor, stream-close, and official extender-source findings.

No local game observation establishes expanded loading, save restoration,
thread safety, or startup compatibility. Existing raw Ghidra output remains
unchanged; this contract uses fresh radare2 evidence for address-sensitive
facts. The existing
[startup loading audit](../analysis/ghidra/output/perf/startup_loading_speed_audit.txt)
also identifies the ESP/ESM discovery, per-file loading, and associated archive
paths, but does not prove an expanded identity contract.

## Native storage and identity contracts

| Owner | Offset or address | Proven behavior |
| --- | --- | --- |
| DataHandler singleton | `0x011C3F2C` | Callers load the current handler through this pointer. |
| DataHandler file list | `+0x210` | Inline list head used by existing extender bindings. |
| DataHandler selected count | `+0x218` | Native insertion and iteration use DWORD loads/stores, with byte extraction for file index assignment. |
| DataHandler selected table | `+0x21C` | Native addressing uses four-byte pointer entries. Local `ModList` declares 255 entries. |
| DataHandler generated ID | `+0x208` | Loader sets `0xFF000800`; native allocation at `0x00469800` advances this state. |
| TESFile master count | `+0x3FC` | `0x00471850` reads a DWORD. |
| TESFile master table | `+0x400` | Native master resolution allocates and fills a pointer array. |
| TESFile owner | `+0x40C` | `0x00473210` stores a byte. |
| TESFile header ID state | `+0x3E4` | The same setter combines the byte owner with the retained lower 24 bits. |
| TESFile current record header | `+0x240`, ID at `+0x24C` | Reader consumes a 24-byte header and translates its ID. |
| TESFile endianness | `+0x299` | Predicate `0x00401680` reads this byte before optional header conversion. |
| TESForm runtime ID | `+0x0C` | Native accessors return a DWORD; the local extender extracts its high byte as owner. |
| Global form map | `0x011C54C0` | `0x004839C0` delegates lookup to the map using a full DWORD key. |

The selected table must not be extended in place. Its allocation belongs to
the original DataHandler layout, with subsequent engine fields beyond it.
The DWORD count does not widen the byte owner or the disk record format.

At `0x0046345B..0x004634AF`, the loader stores a file pointer, takes the low
byte of the count, increments the DWORD count, and calls the index setter.
`0x004634BA` compares the count with `0xFF` and emits the native "too many
selected files" diagnostic at or above that value. A second insertion path
repeats this at `0x004635DE..0x00463649`. These instructions establish a
diagnostic and narrowing boundary, not a measured maximum successful modlist.

The setter at `0x00473210` takes `this` in ECX and one stack argument,
zero-extends only the argument byte, shifts it by 24, updates `+0x3E4`, stores
the byte at `+0x40C`, and returns with `ret 4`. Widening a Rust argument type
cannot change this native ABI or object layout.

### Disk references and native translation

Disk FormIDs contain an eight-bit selector and a 24-bit local value. Native
embedded translation at `0x00485D50` increments the selector and calls
`0x00471A10`. That lookup uses one-based master positions, returns the current
file for argument zero, and returns null outside its master table. Translation
falls back to the current file when lookup returns null. It then combines the
selected file's byte owner with the local value.

The native header reader at `0x00472BC0` has its own equivalent translation.
It additionally strips the owner for nonzero local values below `0x800`.
The embedded translator instead tests the complete supplied value with
`0x00484B40`, which recognizes only `1..0x7FF`, before master translation.
These are distinct contracts. Do not impose one blanket low-local-ID rule
without proving the affected record and reference paths, including zero.

Master-selector width remains unchanged by a larger global file registry.
At most 256 selector values exist; the current-file selector must fit alongside
a file's masters. Supporting more total selected files does not permit one
unchanged file to name an arbitrary number of masters.

### Additional translation boundaries

| Boundary | Addresses | Why central translation alone is insufficient |
| --- | --- | --- |
| ONAM references | `0x00468102..0x00468169` | Reconstructs the owner byte inline before the next native call. |
| Group search reference | `0x00461F5F..0x00461FA6` | Reconstructs the owner byte inline before form lookup. |
| Local ID accessor | `0x00485BC0` | Masks the runtime ID with `0x00FFFFFF`. |
| Local ID comparison | `0x00485BE0` | Masks its argument and compares with the local accessor. |
| Voice suffix | ID call at `0x00617460`, mask at `0x00617465` | Formats the masked runtime ID into `%s_%08X_%u`. An opaque handle suffix is not the original asset ID. |
| Weapon initialization | Translation call at `0x0051E4E6`, lookup at `0x0051E4FE` | Receives a value from `0x00525A90` before translation. The exact disk/runtime/pointer alternatives need proof. |
| Dialogue response linking | Calls at `0x006179FE` and `0x00617C3C` | Reads fields, translates them, performs form lookup, and checks type `0x48`. Field lifecycle and already-linked alternatives need proof. |

Do not globally replace the general FormID accessor at `0x0084E3A0` with a
local ID accessor to fix asset naming. It returns the actual `+0x0C` ID and has
many unrelated users. Intervene only at proven asset-identity boundaries.
The weapon field has an observed transition: initialization obtains the value
through `0x00525A90`, translates and looks it up, casts the result, and stores
that result back to `this + 0x118` through `0x0051F4B0`. The getter can return
either that field or the selected ammo's `+0xB4` value through `0x008D80E0`.
The initializer passes zero to the getter, but the fallback ammo component is
still consulted. Local headers type the weapon and ammo fields as projectile
pointers after linking. Complete load, override, copy, and repeated-init
coverage is needed to establish which representation is valid at each call;
the DWORD alone cannot supply that state. A blanket pointer-versus-ID numeric
heuristic is not a correct representation contract.

Pointer readability, a recognized vtable, and a coincidentally matching map
entry cannot substitute for proving the reference field's representation and
lifetime. Other asset naming paths remain unqualified.

## Loader patch surface and caller coverage

The following addresses are an inspected surface, not a complete patch
manifest. Before implementation, classify every other reader/writer of the
selected count, table, list, and owner byte, including accesses inlined into
other functions.

| Operation | Inspected operand sites |
| --- | --- |
| Count reset | `0x004630DF` |
| First insertion count access | `0x0046345B`, `0x0046347A`, `0x0046348C`, `0x0046349B`, `0x004634BA` |
| Second insertion count access | `0x004635DE`, `0x00463603`, `0x00463615`, `0x00463624`, `0x00463649` |
| Insertion table writes | `0x0046346D`, `0x004635F6` |
| Subsequent loader count comparisons | `0x00463693`, `0x00463719`, `0x004638F4` |
| Subsequent loader table access | `0x004636AB`, `0x004636D9`, `0x0046374E`, `0x00463778`, `0x0046392B`, `0x00463947`, `0x00463973` |
| Additional count comparisons | `0x00461D82`, `0x00461E40` |
| Additional table access | `0x00461D90`, `0x00461DA0`, `0x00461E52` |

| Function entry | Native contract and discovered direct caller evidence |
| --- | --- |
| `0x00463070` | Load orchestration, `this` plus boolean argument. Calls at `0x007D6A63` with 1 and `0x0086D2A4` with 0. Both paths need lifecycle qualification. |
| `0x00473210` | File index assignment, `this` plus byte-valued stack argument. Calls at `0x004634AF`, `0x0046363E`, and clone call `0x00473BB0`. |
| `0x00472BC0` | Header read, `this`, boolean result. Calls at `0x00472636` and `0x00472676`. |
| `0x00485D50` | Embedded translation, cdecl pointer-to-ID and file arguments. Many discovered callers are preserved in the raw evidence; callers are not individually qualified here. |
| `0x00485BC0` | Local ID, `this`, DWORD result. Calls at `0x00485B6C` and `0x00485BF4`. |
| `0x00485BE0` | Local comparison, `this` plus ID argument, boolean result. Five direct calls are preserved. |
| `0x00473AE0` | File clone; clone path invokes the setter and master builder. Direct caller at `0x00473A03`. |
| `0x00467780` | Per-file loader. Entry bytes agree; its full ABI, failure propagation, and all call sites still need qualification. |
| `0x00471870` | Master builder, `this`, list and boolean stack arguments. Calls at `0x00462BC8`, `0x00462CDC`, `0x00463181`, `0x004631EF`, `0x00473BC6`. |

Native cloning at `0x00473AE0` reconstructs a TESFile, copies the original byte
index through the setter, and rebuilds masters using the handler's list.
`0x00471870` frees an existing master pointer array through `0x00401030` and
allocates its replacement through `0x00401000`. Psycho must preserve this
engine allocation ownership. A shortened public list requires a separate full
master-resolution view, or clones cannot resolve extended masters.

A file pointer side table also requires a proven retirement and reuse policy.
The follow-up [durability and cost evidence](../analysis/radare2/output/fnv_extended_plugin_durability_and_cost_contract_20261010.txt)
closes part of that lifetime contract. `0x004739B0` follows the original-file
chain through `0x00473C70`, which reads `+0x04`. It calls the real
`GetCurrentThreadId` wrapper at `0x0040FC90` and compares against the DWORD
at singleton `[0x011DEA0C] + 0x10`. A matching thread receives the original;
other threads enter `0x00473AE0` with their thread ID. That function looks up
and inserts clones in the original's map at `+0x08`, keyed by thread ID.
`0x00473CB0` links a clone to the terminal original through `+0x04`.

Destruction is concrete, not process-lifetime retention: scalar deletion
`0x004601A0` calls `0x004709F0` and frees the object when argument bit zero
is set. The destructor frees the master array, clears `+0x400`, and calls
`0x00473A10`. The latter walks the clone map, calls scalar deletion on each
clone, destroys the map, and clears `+0x08`. A pointer-only side table that
never retires entries can consequently associate a reused address with an old
plugin. The exact reader-exclusion interval and map synchronization remain unresolved.
In the researched executable, `0x00483710` is a no-op stub. Its calls establish
neither reference counting nor locking; an installed replacement has not been
qualified.

The second direct loader call also needs a narrower interpretation. Its
caller `0x007D69F0` tests `0x0046FDF0` before the call with argument 1. In this
executable that tested function unconditionally returns zero, bypassing the
reload block. The call with argument 0 at `0x0086D2A4` is in the initialization
path after the native `Loading Files...` diagnostic. This does not prove that
an installed provider cannot change the tested function, or that all indirect
load routes are covered. It does disprove using the mere second direct xref
as evidence that vanilla executes a repeat load.

## Runtime identity design proposal

Maintain a canonical `(plugin identity, original local ID)` independently of
the runtime DWORD. Plugin identity must survive a supported order change;
session ordinal alone is not a durable identity. Resolve selected filenames
case-insensitively, reject ambiguous duplicates, and define how renamed or
replaced files are treated. Persist the canonical identity, not an inferred
owner obtained by shifting an opaque handle.

The proposed core owns three related registries:

1. The complete selected-file sequence and validated master relationships.
2. TESFile and clone associations with canonical plugin owners.
3. Canonical form keys mapped to runtime handles, with a reverse mapping.

One possible encoding retains legacy runtime owners `0x00..0xFC`, allocates
opaque handles from `0xFD000800..0xFEFFFFFF`, and keeps `0xFF` for generated
forms. This is a proposal, not an established safe reservation. The interval
contains 33,552,384 possible handles; that is an arithmetic address-space bound,
not a memory capacity or supported record count. Registry storage, engine
records, and other allocations must fit the actual 32-bit process budget.

The encoding also moves ordinary legacy positions 253 and 254 into an opaque
domain. Existing saves using those positions require explicit migration.
Rejecting them permanently would narrow supported coverage and would not meet
the objective. Disabled mode must retain the existing engine behavior and ABI.

Handle reservation must precede visibility to any producer that can allocate
IDs. A lookup of only already-created engine forms cannot detect handles
reserved for deferred records. The local extender's
`GetNextFreeFormID(UInt32)` advances an ID until engine lookup returns null;
lambda and other generated-object producers require an owner-aware contract.
The native generated-ID allocator uses a separate `0xFF` sequence. Prove both
domains and their reset behavior rather than borrowing plugin handles for
generated objects.

Preserve the engine's own loading, override linking, object allocation, and
record parsing. Redirect only proven identity or storage boundaries. An
external table needs admission before its first write, checked arithmetic,
and a qualified overflow result; a spare slot alone is not an overflow policy.
Stable registry entries must outlive every admitted reader, and stale native
form pointers must never become durable ownership evidence.

### Representation limits and performance direction

For more than 256 owners, retaining every possible 24-bit local value requires
more than 32 bits of canonical identity. A 32-bit runtime field cannot encode that complete
domain injectively. Taking two additional plugin bits from the local ID would
reduce the local domain to 22 bits and lose ordinary record coverage. Retain
full canonical keys and allocate handles for admitted identities, subject to
explicit resource limits. A high file limit never guarantees that every
possible record across those files fits a 32-bit process or a native save.

Global selected-file capacity and per-file master selectors are separate.
`0x00471A10` accepts a DWORD master ordinal, but the translated disk selector
is still only eight bits. The existing selector-plus-one and self-fallback
rules must remain intact; raising the global file limit does not create more
disk selectors in one ESP/ESM. Do not rewrite plugin files or local IDs to make
the runtime encoding fit.

The proposed fast path is setup-bound file bindings, a sparse canonical-to-
handle index, and an indexed reverse table. This is a design direction with
unclosed publication contracts, not a measured choice of the fastest data
structure:

| Operation | Proposed work and evidence constraint |
| --- | --- |
| Master binding | After successful native master construction, bind the file's 256 selector values to immutable canonical owner tokens once. Derive every binding from the actual resolved master pointers and native self/null rules. Preserve the distinct header and embedded fixed-ID predicates. |
| Clone binding | Associate a clone with the original canonical owner and qualified immutable bindings; retain native per-clone stream/header state. Rebuild or share bindings only after proving that the actual master relationships agree. Never rediscover all masters for each reference. |
| Forward translation | Select one owner token and query the full canonical key. Use a reserved, bounded sparse index; compare full keys, including collisions. Preserve the direct legacy path where its contract is unchanged. |
| Reverse identity | Range-check an opaque handle and index its published canonical entry. Do not hash the handle, traverse the native form map, or dereference a form merely to identify its owner/local ID. |
| Native form lookup | Continue through the installed native lookup provider. `0x00853130` dispatches hash and equality through vtable slots `+0x04` and `+0x08`; a private `id % bucket_count` traversal is not a proven replacement. |
| Mutation | Reserve entries at a proven loading/creation boundary before engine or cooperating producer visibility. A read miss may not silently allocate, rehash, or invent an identity. Whether all required identities can be reserved before gameplay is still unproven. |

Flat open-addressing and paged direct indexing remain candidates, not selected
implementations. A fixed probe cutoff cannot treat an existing key as absent;
exhaustion needs the qualified admission failure before publication. A
lock-free label does not prove correctness: readers require stable storage,
initialized payload before publication, explicit memory ordering, and no
retirement until every reader is excluded. Never let a growing vector move
entries that are already visible, or replace a directory while an engine
worker can still read it. Do not introduce a TLS cache without proving both
retirement and the startup footprint.

Budget concrete storage before choosing the representation. These are
arithmetic payload costs, not allocation measurements or promised capacity:

| Proposed payload | Cost |
| --- | --- |
| 256 selector bindings using four-byte owner tokens | 1,024 bytes per original file, excluding metadata and clones. This avoids a 65,536-owner token ceiling; sentinel meanings and admission still require an explicit contract. |
| Fully dense local-ID-to-handle table | Four bytes times 2^24 values is 64 MiB per plugin; 1,024 such tables require 64 GiB before metadata. Reject this representation for the target process. |
| Reverse canonical entries using eight-byte keys | Eight bytes per admitted opaque handle; filling the proposed handle interval alone requires 255.984375 MiB. A paged table can defer unused payload allocation, not eliminate this per-entry cost. |
| Forward index with explicit 16-byte slots and occupancy at most 0.8 | At least 20 bytes per admitted key before control bytes, rounding, and allocation overhead. This is a proposed slot layout, not a verified Rust layout. |

The latter two layouts would require at least 28 bytes per admitted opaque key
before file bindings, manifests, and engine objects. Do not commit that budget
without counting actual identities in the owner's workload and measuring peak
32-bit address-space use. Header record counts alone do not prove the number
of distinct canonical identities: overrides can repeat keys, and embedded
references can mention keys without materialized forms. A reservation census
must account for the actual records and reference producers it admits.

Durability favors separating three lifetimes: selected-file canonical
identities, published runtime-handle entries, and per-save remap state. Loading
a different save must not rewrite the canonical meaning of handles held by
still-live engine objects or extender values. Persist file identity plus the
full local value and remap saved handles to current handles before readers run.
Runtime handles are session addresses, not durable plugin identities. Handle
reuse, registry reset, and plugin-set changes require explicit quiescence and
consumer lifetime proof; a monotonically increasing epoch alone does not
protect native DWORDs that carry no epoch.

## Native save and extender contracts

`0x00846E70` reads a DWORD count and DWORD saved FormIDs, calls
`0x00846D80` at `0x00846ED4`, and inserts the resulting values into its native
reference structures. The remapper extracts the high byte, passes `0xFF`
through, and otherwise obtains a byte mapping through `0x00846DE0` and its
context table at `+0x44`. It returns zero for an unmapped byte.

The follow-up binary evidence closes the central compact encoding:

| Boundary | Binary proof |
| --- | --- |
| `0x00846B60` | Initializes a reversible native map and counter, then inserts zero through `0x00846C90`; zero occupies ordinal zero. |
| `0x00846C90` | Passes generated IDs through; existing keys reuse their ordinal. New non-generated keys receive the DWORD counter at `+0x20`, then increment it and enter both map directions. No ordinal capacity check appears in this function. |
| `0x00853570` | Uses the reference map at save context `+0x08`, converts the runtime ID to an ordinal, marks generated IDs with bit `0x800000`, and writes three bytes in high-to-low order. |
| `0x00853500` | Reads those three bytes. If bit `0x800000` is set, clears it and reconstructs an `0xFF` ID; otherwise resolves the ordinal through the context's `+0x08` map. |
| `0x00846E00` | Writes a DWORD count of nonzero ordinals and then one full DWORD runtime ID per ordinal, using reverse lookup. Together with `0x00846E70`, this establishes the dictionary's full-width payload boundary. |

The three-byte encoding therefore leaves 23 bits for non-generated ordinals:
zero is reserved and the highest representable nonzero ordinal is `0x7FFFFF`.
An ordinal with bit 23 set is decoded as generated, not as a larger reference
table entry. This is an encoding limit, not proof that every native call path
can reach it or that a supplied workload exceeds it. The proposed opaque
handle pool is larger than this saved-reference domain. Do not advertise the
handle count as safe save capacity. Qualify admission before the first
unrepresentable saved reference; the absence of a check in the map routine is
not permission to insert one without proving callers' failure handling.
Generated ID serialization likewise requires proving the native allocator's
range/reset rules; the reader explicitly removes local bit 23.

There is a separate compact domain. `0x0084EB80` obtains the save context's
`+0x0C` map through `0x0084E3A0`, inserts through `0x00846C90`, and stores only
AX at `0x0084EBF6` and `0x0084EC58`. Reader `0x0084E3C0` zero-extends that
word and resolves it through the same `+0x0C` map. Local extender headers name
this map `visitedWorldspaces`. The native proof is the separate map and
16-bit round trip; its complete semantic coverage and overflow admission
remain open. It is not a 65,535-plugin limit or a 16-bit limit on every form
reference. Never widen it based on a mistaken identification of the map.

Retaining the native compact encodings and remapping their full-width
dictionary IDs is the preferred minimum-change direction, subject to complete
save coverage and admission proof. Widening every compact payload would change
its surrounding sizes and every consumer. Central dictionary proof alone does
not establish the paired-save transaction or extender owner provenance.

This proves a useful native table-remapping boundary, but not complete save
coverage. The embedded-reference save branch at `0x00485D72` calls the distinct
routine `0x00857BF0`, which uses its own count at `+0x4C` and byte table at
`+0x50`. Its relationship to every compact reference encoding and writer is
not closed. Keep native compact reference ordinals separate from canonical
plugin IDs; do not widen a three-byte encoding without proving its writers
and readers.

The local extender source has additional independent limitations:

| Path | Source evidence | Required behavior |
| --- | --- | --- |
| File enumeration | `GameData.cpp`, `GameData.h` | Byte count/index APIs and a fixed active-file cache must not enumerate an unbounded list into legacy storage. |
| Core co-save plugin list | `Core_Serialization.cpp:32` | The `MODS` writer narrows the count to a byte and uses the legacy table. A full identity manifest is separately required. |
| Public saved FormID resolution | `Serialization.cpp:640` | Resolves by the high byte. A native engine remap does not change this public API. |
| Arrays | `ArrayVar.cpp`, `ArrayVar.h`, `ScriptUtils.cpp` | Creator ownership and each reference owner's lifetime must retain full identity, including nested arrays, copies, moves, foreach, and releases. |
| Strings | `StringVar.cpp`, `ScriptUtils.cpp` | Creation, assignment, owner changes, ID reuse, and persistence require full owner provenance. |
| Mod-local data | `Commands_Scripting.cpp:629` | Set/get/remove/existence/enumeration pass an 8-bit script owner into the data manager. Shared owner bytes select the same namespace. |
| Lambdas and created forms | `GameAPI.cpp:2944`, `LambdaManager.cpp` | Producers must respect reserved handles and preserve parent/script ownership. |
| Script data cache | `ScriptDataCache.cpp:228`, `ScriptDataCache.cpp:263`, `ScriptDataCache.cpp:361` | Serializes names by byte owner and masked local ID, then reconstructs byte ownership on load. Opaque identities need a complete cache contract. |
| Serialization order | `Serialization.cpp:780` | Callbacks execute as co-save plugin blocks are consumed. A later plugin callback cannot retroactively supply identity to earlier readers. |

Source proof for the local mod-local data path is conclusive: its manager
accepts `UInt8`, and the commands pass `scriptObj->GetModIndex()`. Two scripts
with the same projected byte and key access the same bucket. Whether the
chosen deployed extender retains this exact compiled path is unresolved.

A bounded legacy view prevents a class of cache overflows but cannot express
every extended owner through an eight-bit API. Truncating the list after file
loading also does not protect consumers invoked during loading. Preserve
engine file ownership and every required source/master pointer; do not detach
or leak list tails as a substitute for a proven lifecycle design.

Introduce a minimal versioned, read-only core identity interface for cooperating
consumers: enumerate/find files, resolve a canonical local ID, identify a
runtime handle, and report readiness and unsupported domains. Define calling
convention, size/version negotiation, buffer rules, thread admission, epoch,
and lifetime. Opaque form identity and override provenance are different queries.
The helper may forward exact exports only after the core is already loaded.

Cooperation must be capability-based. Psycho must not identify external mods
by filename/hash, patch their private structures or commands, or install
version-specific bridges. Owners of byte-based private data must adopt the
identity interface themselves. The repository's existing extender bindings
alone cannot guarantee compatibility with arbitrary unmodified DLLs.
Core operation must not require a cooperating extender. Its independent
identity implementation and optional read-only ABI must coexist without
patching external DLLs. Nevertheless, compatibility with extended owners in
unchanged byte-based consumers is not achievable merely by providing that ABI.
The official 6.4.9 active-list cache has 256 entries and indexes it using the
complete native list ordinal without a capacity check. Its mod-local commands
also collapse distinct full owners into the same byte-keyed namespace.
Preserving the full native list while exposing it unchanged to these consumers
is consequently not a safe compatibility design. No tiny independent registry
can recover information discarded before its boundary. External adoption is a
requirement for those consumers' extended-owner support, never a core loading
dependency. A feature claiming all unchanged consumers work remains blocked.

### Additional native admission and persistence boundaries

`0x00465010` returns a selected-file pointer only for indices 0 through 254.
Its callers include `0x00844031`, `0x00847610`, `0x00847779`, and
`0x0085B2A9`. These extend the original operand inventory. The shared accessor
`0x0051F550` reads a DWORD at `this + 0x218`; both DataHandler and weapon
objects call it. Globally changing this accessor would affect unrelated
weapon state. Qualify object ownership at each intervention point.

Native writer `0x00847590` narrows selected count to a byte and writes that
byte followed by plugin names. Native reader `0x00847660` reads the byte and
builds two 255-byte owner maps at context offsets `+0x44` and `+0x143`.
The reader runs at `0x00847F08`, before the extender preload boundary at
`0x00847FD9`. An optional helper preload callback is too late to preflight
this native state. Core admission must precede the actual owner's mutations.
The alternate writer `0x0085B240`, called at `0x00856E0C`, also writes a
byte-sized count; its relationship to every supported save path remains open.
Both formats need actual reader/writer coverage before save migration.

The extender save boundary `0x00847C45` precedes the native owner's result
check at `0x008505C6`. Official 6.4.9 serialization creates the final co-save
with `CREATE_ALWAYS`; its void caller does not propagate failure, and the
write path does not verify complete writes or flush durability. A native-only
FOS rejection cannot guarantee rollback of a previously overwritten co-save.
An engine-owned manifest needs a proven publication protocol; it cannot claim
to make another owner's uncoordinated writes transactional.

Generated-cursor advance `0x004697A0` wraps the masked local value at
`0x007FFFFF` to `0x800`. Starting at `FF000800`, ordinary advancement stays
within `FF000800..FF7FFFFE`. This does not cover all other cursor setters or
external form producers. Native allocation `0x00469800` holds its critical
section while searching and has no observed exhaustion escape.

Native file close `0x00471130` may return success without closing when the
file's `+0x29A` flag is clear and DataHandler's `+0x61D` predicate is false.
The destructor sets the flag before closing. Counting one short-lived stream
per sequentially loaded file is therefore unsupported; quantify actual stream
retention before setting a capacity budget. Loader continuation through
`0x00464D2D` was examined, but clean complete per-file control flow and a
caller-tolerated admission failure remain unresolved. Logging an error is not
proof of a safe failure result.

### Save integrity requirements

Preserve canonical plugin/local identities alongside saved runtime handles in
a versioned manifest. Validate it before any reader consumes opaque IDs,
including extender arrays/strings and native reference tables. Prove preload
ordering against the chosen binary and actual FOS/NVSE file pair.

Every owner-dependent persistent domain needs complete metadata. Runtime
handles do not reveal string or array creators, reference holders, timer
authors, private-variable authors, or linked-reference authors. A companion
record must bind to the exact native payload and preserve native object IDs,
sharing, release behavior, and typed values. Equal byte-owner counts cannot
prove full reference ownership.

Treat missing, stale, malformed, duplicate, or mismatched metadata as an
explicit load-admission failure before state mutation. Falling back to a
legacy byte resolver for opaque IDs can lose or misidentify data. Metadata
write failure must not produce a save reported as safely restorable. Qualify
the engine/extender's actual save cancellation or rollback boundary; logging
an error after partial writes does not prove save integrity.

Define and qualify unchanged order, reordered extended files, movement across
the legacy/opaque boundary, legacy-save import, removal, missing masters, and
paired-save mismatch. The policy for removed content needs an explicit user
decision and native cleanup proof. Missing records must not be silently
treated as accepted migration. Returning to menu and loading a second save
must reset only session save state, without invalidating still-live engine
objects or menu-created referenced arrays/strings.

## Psycho ownership and failure design

All engine loading, canonical registry state, translation, and native save
intervention belong in `psycho-engine-fixes`. The xNVSE helper remains a thin
service/command adapter. Syringe remains a generic loader and has no plugin
identity policy. Do not put this system into OMV, ATOM, or the allocator.

Use the existing core activation boundary outside loader lock. Loader hooks
must be prepared before their first native use; `DeferredInit` is too late
for initial file loading. The current helper forwards no `PostPostLoad`
event, so a design needing that notification requires a narrowly specified
host event or cooperation interface. Choose the boundary only after proving
the real initialization order. Do not start a worker to race file loading.

Follow [startup safety](nvse_startup_phase_safety.md) for every pre-DeferredInit
delta, including configuration layout, imports, statics, allocations, and
callback changes. Keep registry allocation tied to the proven loader lifecycle;
avoid new TLS caches or broad early initialization. Startup qualification uses
the accepted deployed artifact, not the current dirty source tree.

Before activation, validate all engine boundaries, prepare owned state and
relocated bridges, and prove that relevant threads cannot execute modified
bytes during installation. Preserve an installed provider where its chain is
compatible; reject an unqualified collision without overwriting it. Rollback
must restore and verify every mutation before reporting vanilla behavior.
After file identities are published, disabling the feature mid-session is not
a valid recovery strategy.

Contain Rust errors and panics at FFI boundaries. Preserve native ABI, complete
instructions, relative relocations, stack alignment, AL-valued boolean returns,
flags, registers, and floating-point state where callbacks interrupt live
code. Use existing hooking abstractions and safe WinAPI wrappers. Keep logs
under `libpsycho::logger::Logger` and the `log` facade.

Pre-size setup storage from validated input counts where evidence permits.
Measure translation and lookup cost on the same plugin workload. Avoid file
I/O, formatted diagnostics, repeated master reconstruction, routine allocation,
or blocking locks in steady gameplay paths. No record count or FPS claim can
be derived from the handle interval. Read the
[native IO contract](parallel_io_engine_contract.md) before touching worker
topology or file ownership; this feature does not authorize an IO redesign.

## Staged implementation plan

### Stage 1 Close the implementation contracts

Select the supported executable and deployed extender binary. Reverify native
addresses and the byte-based extender paths against those artifacts. Complete
the count/table/list access inventory; classify each access as complete-loader,
legacy-public, serialization, or unrelated. Trace both LoadFiles callers,
every master/clone caller, file destruction/reuse, save writers/readers,
generated-form producers, override provenance, and identity-derived assets.
Establish thread ownership and the interval of exclusion for each mutation.

Prioritize the remaining native proof around publication and persistence:
qualify dictionary remapping before any compact-reference reader; establish
both reference-table overflow failure contracts; prove clone-map reader
exclusion and side-table retirement; then finish inlined owner/count/table
coverage and staged raw-ID-to-pointer fields. The existing inspected operand
list is not exhaustive and cannot yet define a complete patch transaction.

Establish the maximum supported capacity from the native representations and
measured memory and open-stream budgets, with no arbitrary 1,024-file ceiling.
Resolve the authoritative load-order source, legacy-save migration, removed-
content policy, and optional consumers' full-width capabilities. Source observations alone cannot select
these product policies. Preserve ordinary ESP/ESM coverage; do not replace it
with compacted records, dummy files, or a restricted record importer.

Before production edits, execute the acceptance workload against the unchanged
installed path and preserve its observed failure beyond the current limit.
Record plugin selection, canonical records, scripts, assets, paired saves,
and explicit expected results. If that environment is unavailable, production
implementation remains blocked under the repository behavioral gate.

### Stage 2 Implement identity and storage ownership

Proposed cohesive modules under the core's engine-fixes subtree are
`extended_plugins/identity.rs`, `registry.rs`, `engine.rs`, `save.rs`, and
`api.rs`, with `mod.rs` owning installation and lifecycle. Final module
boundaries depend on the closed contracts; avoid a general framework.

Implement typed legacy, opaque, generated, and fixed domains, full canonical
keys, checked reservation, reverse lookup, stable entries, file/clone
association, and staged publication. Add only the needed configuration and
exports, with explicit startup acceptance for their footprint. Exercise actual
production Rust operations offline as supporting regressions; synthetic native
objects cannot establish the engine behavior gate.

### Stage 3 Integrate native loading and references

Install the qualified external count/table access and index-association paths
transactionally. Preserve native discovery, activation, master ordering,
per-file loading, override precedence, archives, and allocations. Keep the
complete native resolution view separate from any legacy ABI view only where
the proven consumers require that distinction.

Integrate header, embedded, ONAM, group, local-ID, and asset-ID boundaries with
representation-specific contracts. Handle clones and repeat load/reset paths
without stale registry entries. Exercise the real record consumers, including
the weapon and dialogue paths; a list of patched addresses is not coverage.

### Stage 4 Integrate persistence and cooperating consumers

Implement manifest publication, validated preload, native save remapping,
legacy import, and admitted migration. Qualify paired-file failure behavior
before enabling save support. Define the minimal core identity ABI and helper
forwarding without relocating engine ownership into the helper.

For optional extender compatibility, cooperating consumer code must cover enumeration, public reference
resolution, arrays, strings, mod-local data, lambdas, cache identities, and
private persistence. Test each advertised capability through its actual shipped
consumer. This stage cannot be replaced by silently skipping unsupported
consumers or disabling their features. Broad arbitrary-DLL compatibility remains
unproven unless those consumers adopt and exercise the contract.

### Stage 5 Qualify the complete feature

| Behavioral boundary | Required result |
| --- | --- |
| Disabled mode and legacy loading | Existing selections, script semantics, assets, and save behavior remain intact. |
| File boundaries | Exercise positions 252, 253, 254, 255, 256, and the proposed final selected-file boundary in the real loader; overflow never writes beyond owned storage. |
| Record identity | Same local IDs in different extended files remain distinct; overrides and master references resolve to the intended canonical record. |
| Native consumers | Real scripts, quests, weapon/projectile references, dialogue/idle links, voice assets, and relevant archives behave correctly. |
| Extender namespaces | Two extended scripts using identical mod-local keys remain isolated; enumeration, local/source queries, and form construction preserve their documented domain. |
| Owned values | Shared/nested arrays, copies, moves, foreach, release, string reassignment, and ID reuse retain full provenance without leaks or premature destruction. |
| Native and co-save persistence | Actual save, process restart, and reload restore gameplay values and native reference tables; all required migration modes preserve identity and ownership. |
| Failure containment | Missing masters, malformed input, bad metadata, paired-file mismatch, capacity exhaustion, and patch conflict select the proven failure result before partial publication. |
| Lifecycle and concurrency | Clones, menu/new-game transitions, a second save, and both supported native load routes preserve valid objects and reset the appropriate state. |
| Startup | Representative Proton load-to-gameplay satisfies the mandatory startup contract for the changed artifacts. |
| Performance | Explicit same-workload load time, translation cost, memory, and file-handle budgets pass; no proxy FPS claim. |

Test expectations must come from actual shipped data, native contracts, and
explicit requirements. Compilation, mocked native objects, reconstructed
reference algorithms, source assertions, logs alone, and relocated synthetic
images do not replace these behavioral observations.

After focused regressions and affected suites, build the affected core/helper
for explicit `i686-pc-windows-gnu`. If shared linkage or startup inputs change,
run the complete supported release build required by the startup contract.
Check formatting, `git diff --check`, and final scope. No packaging, release,
or commit is authorized before the behavioral and startup gates pass; commits
also require the repository's separate exact approval.

## Effects in a 1,024-file scenario

The requested example is 1,024 selected ESP/ESM files, including the base
masters. It is a research scenario, not the final capacity policy or a
qualified configuration. The core remains independent of xNVSE. The
[consumer-effect evidence](../analysis/radare2/output/fnv_extended_plugin_1024_consumer_effects_20261010.txt)
records exact source paths, line ranges, native call rechecks, arithmetic,
and deployment observations. Third-party examples are source findings;
their complete installed binary behavior and current settings are unverified.

### ESP/ESM behavior

Neither file extension grants a different owner width. Native header,
embedded-reference, master, and ONAM paths all need the qualified canonical
translation. The following describes the consequences of each representation,
not observed behavior in an expanded game run.

| Boundary | Effect at 1,024 selected files | Required preservation |
| --- | --- | --- |
| Selection and enumeration | The native 255-pointer inline table cannot contain the selection. A full list exposed to a cold 256-entry extender cache can cause writes beyond that cache. | Core-owned complete storage and qualified access for every consumer; expanding the inline object or truncating discovery is not sufficient. |
| New records | Byte-owner assignment or index masking aliases indices separated by 256. Ordinary files may use the full original 24-bit local domain. | Independent canonical identity and unique admitted runtime handles; do not take plugin bits from original local IDs. |
| Overrides | Overriding an existing record does not require another canonical record identity, but the overriding file still needs discovery, master resolution, source provenance, and load-order precedence. | Preserve the original record identity and actual winning-file behavior. An override-only file is not exempt from file-list compatibility. |
| Cross-file references | Global file count exceeds byte ownership; disk selectors still refer to the individual file's masters. | Translate through actual resolved master pointers. A larger global limit does not increase disk selector width. |
| Scripts and quests | A full handle can identify the script/form, but commands that derive a byte source owner or masked local ID lose canonical meaning. Mod-local data can share namespaces. | Audit actual commands and consumers, not just record deserialization. Standard native execution remains unqualified until runtime testing. |
| Assets | Voice suffix generation uses masked runtime ID, which is not necessarily the original local ID of an opaque handle. | Preserve canonical asset identity at proven naming boundaries. Other asset paths remain open. |
| Native saves | Plugin count and owner maps are byte-based. With an unchanged count-to-byte writer, 1,024 becomes zero. Native compact references also impose separate record-domain bounds. | Full file manifest, dictionary remapping, native admission before mutations, and complete writer/reader coverage. File count alone does not establish save capacity. |
| Existing saves and reordering | A session handle does not preserve identity after reordering or movement across legacy and extended domains. | Canonical saved identities and explicit migration, missing-content, and paired-publication contracts. |
| Resources and performance | Work scales with admitted records, references, assets, clones, and retained streams, not only selected count. | Measure the actual workload and peak 32-bit address space. No FPS or supported-capacity claim follows from pointer-table size. |

For this example, 1,024 file pointers require only 4 KiB, and four-byte
256-selector bindings require 1 MiB for originals before metadata and clones.
These small payloads do not establish feature feasibility: a dense four-byte
handle for every possible local value would require 64 GiB across the 1,024
owners. Preserve the full canonical domain in a sparse registry of admitted
identities. Its workload size, reservation completeness, and performance are
still unmeasured.

### xNVSE DLL behavior

ESP/ESM ownership and xNVSE DLL identity are different domains. Official 6.4.9
[`PluginAPI.h`](https://github.com/xNVSE/NVSE/blob/6.4.9/nvse/nvse/PluginAPI.h)
defines a DWORD DLL handle. `PluginManager` uses a dynamic vector, and the
co-save header counts DLL blocks with a DWORD. Selecting 1,024 ESP/ESM files
does not use up these handles or by itself establish a DLL loading failure.
This is not a claim of unlimited DLL capacity.

Complete DWORD FormIDs can remain opaque runtime handles without widening
the TESForm layout or every DLL argument. The compatibility boundary occurs
when code interprets those handles as byte owner plus original local ID,
indexes legacy file storage, allocates colliding IDs, or persists them using
an incompatible resolver. Full DWORD storage alone is insufficient if the
next operation strips identity or remaps it through a byte table.

| Consumer/path | Proven source contract | Consequence and scope |
| --- | --- | --- |
| xNVSE loaded-file commands | Byte count/index APIs, high-byte source extraction, local-ID mask, and `BuildRef` masking its owner argument with `0xFF`. | With 1,024 loaded entries the count API returns zero. `BuildRef` produces the same value for owner arguments 0, 256, 512, and 768 with equal locals. Source/local queries do not identify arbitrary opaque handles. These are conditional source consequences, not a game-run result. |
| xNVSE name-based loaded check | `IsModLoaded` searches the native list by filename and tests loaded state. | This discovery path does not itself need a wide owner number. Preserving it does not make numerical lookup commands compatible. |
| xNVSE arrays and strings | Array creators/reference holders and string creators are bytes. | Full creator/holder provenance cannot represent 1,024 distinct owners. Array/string IDs themselves do not automatically collide, and no specific destruction failure has been observed. |
| xNVSE mod-local data | Commands pass a byte script owner into the namespace manager. | Distinct owners with the same projected byte and key address the same namespace. Handle uniqueness elsewhere cannot prevent that collision. |
| xNVSE co-save resolver | `MODS` stores a byte count; `ResolveRefID` reconstructs only high-byte ownership. | DLL payloads using this resolver need extended-identity support even if their saved values are DWORDs. Native FOS remapping alone does not fix them. |
| xNVSE lambdas and inherited-owner clones | A private overload increments full IDs until native form lookup is empty and then checks high-byte equality. | An identity reserved only in Psycho's registry is not a materialized form for this collision check. Reserve/producer interoperability remains unresolved. |
| BaseObjectSwapper plugin-qualified configuration | Available source reconstructs an ID using byte filename lookup and a masked local value. | Arbitrary extended targets cannot be resolved this way. Its complete runtime-ID and editor-ID branches are separate paths requiring their own qualification; the DLL is not declared universally broken. |
| Stewie new-file reporting | Optional feature loops over full selected count while indexing native 255-entry file and byte owner arrays. | If enabled with unchanged arrays, index 255 is already outside declared storage. This can affect memory safety even though the feature displays names. Installed enablement is unknown. |
| Stewie saved ammo, weapons, and locations | Available load callbacks call the public xNVSE saved-ID resolver. | Incorrect remapping can affect gameplay state, not just plugin-name reporting. Exact installed binary/source parity remains unverified. |
| Stewie appearance import and source display | Byte filename lookup or byte source owner followed by direct table indexing. | Saved appearance records and source diagnostics need full identity. No observed in-game failure is asserted. |
| Stewie save optimization source | Optional inline reader replaces native call `0x008480C2` and performs its own byte-owner remapping. | Hooking only vanilla `0x00846E70` or `0x00846D80` misses this provider. Admission and dictionary handling must cover the actual shipped path while preserving installed providers. |
| Available TTW/ROOG enumeration source | Uses byte count and legacy active-file cache to build arrays. | Enumeration cannot return the complete selection through that path. This source is not qualification of installed TTW 3.3.3. |
| itr-nvse `NoWeaponSearch` source | This feature stores and compares complete DWORD actor IDs. | No byte-owner decomposition occurs in this selected in-session comparison. It is representation-compatible with unique handles; whole-DLL persistence, lifecycle, and runtime acceptance remain unproven. |
| JIP, JohnnyGuitar, ShowOff, and remaining installed DLLs | The supplied log identifies installed versions but this research does not establish complete relevant consumer contracts. | Compatibility remains unknown. Neither their presence nor a successful legacy startup proves an expanded workload safe. |

The inline save source is gated by its outer inline feature and `bSaveLoad`.
Its configuration supplies default 1 for `bSaveLoad`; current installed
enablement is not established. The reporting hook at `0x00847F08` and the
dictionary replacement at `0x008480C2` overlap the native contracts researched
here. These examples establish the need to qualify the active provider; they
never authorize detecting, rewriting, or bypassing another mod.

### Implementation implications

The example does not show that every extra ESP/ESM or every xNVSE DLL must
fail. It proves that a larger selected table and a unique runtime handle are
insufficient for universal unchanged compatibility. Even a DLL used mainly
with legacy files can enumerate the complete list or save extended records,
so putting scripted files first is not a compatibility solution.

Keep engine loading and canonical persistence in the independent core.
Expose full filename/local-ID resolution, handle identity, and enumeration
through the optional capability-based interface. Preserve complete runtime
IDs in consumers that already treat them as opaque. Owners of byte-based
private namespaces must supply full-width semantics before claiming support
for extended owners; a helper cannot recover discarded identity afterward.
No requirement to load xNVSE may be introduced into the core.

Before implementation, qualify the native and installed-provider admission
path, actual save dictionary construction, and all relevant consumers. A
representative acceptance workload must exercise duplicate local IDs, masters,
overrides, scripts using equal mod-local keys, named DLL configuration targets,
owned arrays/strings, save/restart/reload, reordering, and admitted failures.
Selection of 1,024 files alone is not that behavioral test. The extended
workload and installed DLL behavior have not been run.

## Decisions and evidence still required

Implementation requires the accepted runtime artifacts and unchanged workload,
complete engine consumer/lifetime/concurrency coverage, independent native
persistence and rollback proof, explicit migration policies, measured capacity,
and full-width contracts for every optional consumer claiming extended-owner
support. Dynamic storage and opaque FormIDs are a design direction, but they
do not resolve the proven information loss in unchanged byte-based consumers.
The requested universal compatibility cannot currently be claimed. The next implementation work is Stage 1, not a larger comparison
constant or a port of external private bridges.
