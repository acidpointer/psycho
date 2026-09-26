# Save integrity boundary

## Purpose and user-visible behavior

`psycho-engine-fixes/src/mods/engine_fixes/save_integrity.rs` owns the Fallout:
New Vegas save-integrity boundary. It prevents a temporary `.fos` from
replacing the last usable save unless the engine completed the write, the
physical file is durable, and the serialized envelope is coherent. It also
rejects malformed changed-record reads before they can continue mutating live
forms.

The July 2026 investigation added a PlayerCharacter-specific boundary for a
reported failure in which loading a recent autosave produced a very large
movement-speed increase. A rejected save follows the game's Save Failed path
and leaves the previous final save recoverable. A rejected load returns failure
from the engine load owner; it is not converted back into success.

The feature is controlled by `engine_fixes.save_integrity_fix` in
`psycho_engine_fixes.toml`. The early-loaded core DLL owns all implementation.
The helper DLL does not initialize or load it.

## Proven engine contract

The static contract below was verified against:

- `FalloutNV.exe`
- SHA-256
  `42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c`
- PE i386, 16,084,808 bytes

### Save transaction

The save owner at `0x008503B0` calls, in order:

1. pre-save transition `0x00850BA0`;
2. temporary-file factory `0x00850030`;
3. activation `0x00850EA0`;
4. snapshot traversal `0x00847850`;
5. result predicate at callsite `0x008505C6`;
6. post-save transition `0x00850BF0`;
7. release/promotion `0x00850100`.

Snapshot traversal has no complete change-map lock of its own. The pre-save
transition waits for known engine task state, but the binary evidence does not
prove that every third-party or worker mutation source honors that transition.
The integrity layer therefore treats serialization as a transaction and
verifies a live-state canary at its final boundary.

The write function at `0x00846330`, buffered finalizer at `0x00AA15A0`, CRT
close at `0x00EC9907`, and release/promotion path form the physical commit
chain. Both `0x008463C0` and `0x00AA15A0` return a Boolean in `AL`; their hook
ABIs are byte-returning functions, not 32-bit result functions.

Vanilla release/promotion at `0x00850100` does not use `ReplaceFileA`. After
destroying the save object, it rotates each occupied backup source upward. It
deletes an occupied backup destination with `DeleteFileA`, then calls the CRT
rename at `0x00EC862C`. That CRT function is a thin `MoveFileA` wrapper. The
last two renames are the old final to `.bak` and the temporary file to the now
vacant final name. Vanilla ignores every delete and rename result, so its
sequence is not itself an integrity protocol, but the API family is an
important Proton/MO2 compatibility contract.

The on-disk header begins with `FO3SAVEGAME`, a 32-bit encoded header length,
the current version `0x30`, pipe-delimited metadata, and the screenshot
dimensions. The screenshot consumes `width * height * 3` bytes. The changed
record body follows it. The physical reader performs that multiplication in
32-bit registers at `0x0084DA34-0x0084DA45`.

The physical-file readers at `0x0084D8C0` and `0x0084DAB0` accept two
version-`0x30` header layouts. After the version separator they inspect the byte
following the next four bytes. A pipe means those four bytes are screenshot
width and the 64-byte language block is absent; any other byte means the reader
first consumes the language block and its separator. The absent form defaults
to `ENGLISH`. This is an explicit loader compatibility contract, not a guessed
format extension, and the integrity validator must accept both forms.

Header strings use a second conditional framing rule. The header writer at
`0x0084D4B0` delegates string fields to `0x00865E70`. That helper always emits
the `u16` length as one buffered write, but its zero-length branch at
`0x00865EBD` skips the payload write at `0x00865ECD`. The matching reader
`0x008649A0` always reads the length at `0x008649B8`, then branches at
`0x008649C3` and calls the payload reader at `0x008649F0` only for a nonzero
length. On this ordinary header path, the low-level writer `0x00865CE0`
appends one pipe to every performed write, and the reader `0x00864820`
consumes one pipe after every performed read. Therefore:

- an empty string is encoded as `u16(0), '|'`;
- a nonempty string is encoded as `u16(length), '|', bytes, '|'`.

The omitted payload write means an empty string has no second pipe. This is not
a relaxed corruption policy; it is the exact producer/consumer contract used
by the executable. Nonempty fields still require their payload pipe, and the
encoded header length must still end exactly after the final field.

### Validator reliability policy

The two July corrections had one common engineering cause: the original
validator transcribed an inferred header grammar, and its synthetic test
builder transcribed the same grammar. The builder therefore produced only
files that agreed with the validator. It could not reveal either engine branch
that the transcription omitted: the optional language block or the skipped
empty-string payload operation.

The hardened validator removes that correlated-oracle pattern:

- `HeaderCursor::framed` is the single implementation of the low-level engine
  rule that every performed read consumes one payload followed by one pipe.
  Scalars, fixed blocks, string lengths, and nonempty string payloads cannot
  implement that rule separately.
- `HeaderCursor::string` contains only the proven high-level branch: read the
  framed `u16` length, and perform a framed payload read only when it is
  nonzero.
- Literal byte fixtures test the empty and nonempty branches without calling
  the synthetic header builder. Full-envelope tests exhaust all 16 empty/value
  combinations under both accepted language layouts.
- The temporary file is opened after the engine file object is closed. Its
  validation handle permits readers but denies writer and delete sharing, so
  an existing incompatible handle prevents validation and no new writer or
  path replacement can change the file image while it is parsed and flushed.
- The old final is copied to a recovery path and that copy is independently
  opened and flushed before the final name can change. Promotion first uses
  `MoveFileExA` with replace and write-through flags. If destination
  replacement is unavailable but leaves the final intact, it falls back to
  the engine-compatible sequence: rename the final to `.txn`, then rename the
  temporary file to the vacant final path. Both renames are write-through. It
  does not use the incompatible `ReplaceFileA` metadata transaction.
- Promotion logic is exercised through fault-injected filesystem operations.
  Tests remove the final before returning an injected replacement error and
  prove that recovery republishes the old image. Separate tests prove that a
  recovery-copy failure cannot remove the final and that an interrupted
  transaction restores a missing final before the next temporary file is
  considered. Another test forces destination replacement to fail without
  changing the final and proves the engine-compatible fallback commits. A
  pessimistic post-commit error test proves that a consumed temporary source
  cannot cause the newly published final to be moved back out of place.
- Validation first reads the fixed 15-byte magic/length lead, checks the
  declared length, and then reads exactly that complete header through the
  same handle. Short Win32 reads are retried until the requested envelope is
  complete or physical EOF is reached.

For version `0x30`, the largest possible encoded header body is derived from
the proven schema rather than chosen as a tuning limit:

`5 * (u32 + pipe) + (64-byte language + pipe) + 4 * (u16 + pipe + 65535-byte payload + pipe) = 262246 bytes`.

This admits every value representable by all four on-disk `u16` string lengths
while bounding the cold-path allocation. A larger declared header, a header
that extends past physical EOF, a short second read, or any field that does not
end exactly at the declared boundary fails closed. A future save version must
first have its writer and reader contract proven and must receive an explicit
parser; it is not guessed from version `0x30`.

Screenshot validation follows the same rule. The previous 64 MiB ceiling was a
policy guess and would reject an otherwise coherent high-resolution save; an
8192 by 4096 RGB image is 96 MiB. The hardened validator instead performs the
reader's `u32` RGB-size multiplication with checked arithmetic and proves that
the computed screenshot plus at least one changed-record byte fits inside the
physical file. Thus it rejects consumer-visible integer wrap and truncation
without inventing a resolution limit.

### PlayerCharacter corruption path

PlayerCharacter load is `0x00956F70`. For framed save versions 31 through 89,
it performs this sequence:

1. reads the four-byte `KOLB` marker through `0x008579E0`;
2. logs a bad marker but continues;
3. reads a 16-bit block length;
4. copies actor-value arrays directly into PlayerCharacter;
5. only after those writes, compares the final cursor with the declared block
   boundary and logs under/overrun.

`0x008579E0` is a raw reader: it copies from the cursor at save-manager offset
`+0x14` and advances the cursor without a logical bounds check. The typed
writer is the separate function at `0x008579B0`.

PlayerCharacter is published at singleton slot `0x011DEA3C`. The actor-value
arrays begin at player offsets `+0x244`, `+0x378`, and `+0x4B0`. SpeedMult is
actor value index 21, so its raw modifier slots are `+0x298`, `+0x3CC`, and
`+0x504`. The loader copies these bytes before checking the block boundary.
Consequently a truncated or misframed PlayerCharacter record can write
unrelated serialized bytes into SpeedMult and every other actor value, which
directly explains the reported symptom and permits more serious state damage.

The save/load buffer singleton used by this function is `0x011DE45C`; its
version getter is `0x008DF040`. Versioned minimum block sizes, including the
16-bit size field and the following four-byte field, are:

| Version | Array shape | Minimum block size |
|---|---:|---:|
| 31-48 | 2 x `0x130` | 614 bytes |
| 49-58 | 3 x `0x130` | 918 bytes |
| 59-89 | 3 x `0x134` | 930 bytes |

The general load owner is `0x00847DF0`. The changed-record reader and peek
boundaries are `0x00864820` and `0x00864A60`. The engine load-error bit is
`0x80` at load-owner offset `+0x244`.

## Implementation and ordering

Installation is all-or-nothing. Every inline hook is initialized first. The
audited result call and missing-base-form guard are then installed, and one
`ModificationTransaction` enables all supporting hooks before enabling the
save/load owners. If activation fails, owned inline hooks and fixed patches are
rolled back. The optional Save Failed UI redirection is installed only after
the complete integrity transaction is active.

During a save:

- activation binds the exact temporary file, BSFile, stream, thread, and
  manager;
- short writes, buffering failure, close failure, tracking failure, and
  in-transaction PlayerCharacter SpeedMult mutation latch failure bits;
- the result boundary destroys/closes the engine file without promotion;
- the closed temporary file is reopened with writer and delete sharing denied,
  its 15-byte lead is read, and the declared current-format header is bounded
  by the exact 262,246-byte schema maximum;
- that exact header is read completely through the same stable handle and must
  have either engine-accepted layout, a bounded screenshot, and a nonempty
  changed-record body;
- the file is flushed to stable storage, then the old final is copied to an
  independently flushed recovery image before one write-through replacement,
  with the recoverable two-rename sequence as a compatibility fallback;
- `.txn` is always the transient recovery copy; after success it becomes
  `.bak` when backups are configured and is removed when they are disabled;
- a failed replacement restores the recovery image if the final name is
  unexpectedly absent, and the next transaction reconciles a surviving `.txn`
  before it validates or promotes another temporary file.

The PlayerCharacter canary compares raw float bits rather than an arbitrary
speed range. Finite modded SpeedMult values are permitted. A singleton change,
unreadable slot, non-finite slot, or modifier change between activation and the
result boundary aborts the save.

During a load, the PlayerCharacter hook validates the exact singleton, active
load transaction and changed-record object, `KOLB` marker, declared block
against the record's logical payload end, versioned minimum size, committed
memory range, and finite SpeedMult slots before calling the original loader. A
failed preflight does not call the mutation owner. General changed-record reads
retain their payload/separator checks and local rejected-record bit. Any global
malformed load keeps the engine error bit set and forces the load owner to
return zero. Missing-master records remain a distinct local skip policy and do
not masquerade as malformed data.

## Invariants, costs, and failure behavior

- A tracked `.fos.tmp` is never promoted after any latched integrity failure.
- Hook installation cannot intentionally leave a partial integrity policy.
- Concurrent or reentrant save/load owners are rejected instead of bypassing
  the active transaction.
- Save tracking is restricted to the captured save thread and exact engine
  objects.
- Player actor-value framing is validated before the first actor-value copy.
- A malformed load decision is terminal for that load-owner invocation.
- Existing final saves are not deleted in a preparation failure. Replacement
  recovery uses an independently copied and flushed backup.
- Failure to create or flush the recovery image aborts before the final name
  can change.
- An interrupted replacement cannot make a later malformed temporary file
  block restoration of an available `.txn` recovery image.

Save-time overhead is one 15-byte lead read, one exact header read, an allocation
bounded at 262,261 bytes including the lead, three 32-bit canary reads at each
boundary, one header parse, and one copied-and-flushed old-final image before
the final rename. The copy is cold save-time I/O and is bounded by the previous
save size; it replaces the implicit old-file backup work previously delegated
to `ReplaceFileA`. The canary uses a small cold-path mutex; no lock is added to
ordinary gameplay. Reading the closed file avoids assuming that the hooked
write entry observes the stream from byte zero. Player load preflight performs
one block-range validation and up to three float checks. Valid changed-record
field reads retain their constant-time logical bounds checks and do not
perform per-field allocation or file I/O.

The structural envelope check is not a complete parser for every changed
record. It proves the outer current-format save framing, while the existing
record reader and the new pre-mutation PlayerCharacter check protect the
audited mutation paths. Extending coverage must be based on an exact
serializer/loader contract rather than guessed value limits.

The xNVSE `.nvse` cosave is not atomically paired with `.fos` promotion by this
module. A future paired transaction requires an xNVSE ownership contract and
must not be inferred from the core file path.

## Save guard performance research and proposed changes

Status: unreleased LowProcess optimization candidate. The owner reports
substantially slower saving on weaker machines, cannot reproduce it on the
main PC, and has no
affected-machine log. The available successful-save log has no start or phase
timings. No candidate below is established as the cause, and no elapsed-time
or FPS improvement is claimed. The save-integrity setting has not been
excluded by a supplied controlled comparison.

The owner explicitly authorized skipping the unavailable reproduction/log
step and proceeding with an unreleased implementation. This waives the
baseline requirement for this incident, not the safety-contract requirements
or the distinction between static qualification and runtime performance.

The objective is lower save latency with the same valid serialization,
corruption containment, durable recovery, and promotion behavior. Source-level
work reductions are useful design budgets, not substitutes for measuring that
objective. The radio investigation's 120 FPS target is not a save-duration
budget.

### Evidence and boundaries

The executable identity above was reconfirmed for this research. Focused native
rechecks are in
[`save_guard_optimization_radare2_audit.txt`](../analysis/ghidra/output/perf/save_guard_optimization_radare2_audit.txt).
They confirm the following boundaries:

- Inventory list save at `0x004D4090` calls `0x004BED60` at `0x004D410D`,
  then increments the serialized count. The existing list-level interception
  must remain; bypassing the body alone corrupts the count contract.
- LowProcess serialization uses the embedded head at process `+0x6C`, calls
  data at `0x009105A6`, payload serialization at `0x009105BF`, and next at
  `0x009105D0`. Native dereferences the data accessor result immediately.
  An empty head still reaches the accessor path. Preserve captured providers,
  the permanent readable NULL cell, and native count finalization.
- Ragdoll `0x00C75B40` consumes transform root `+0x58`, hierarchy `+0x2A4`,
  transform buffer `+0x94`, and bone table `+0xA4`, then writes bone transforms.
  Its direct caller at `0x004953B5` was reconfirmed. This proves the consumer,
  not its invocation frequency or contribution during a reported slow save.

Existing ownership and lifetime evidence remains authoritative:

- [`entrydata_save_skip_contract_audit.txt`](../analysis/ghidra/output/crash/entrydata_save_skip_contract_audit.txt)
- [`save_snapshot_lock_ownership_followup.txt`](../analysis/ghidra/output/crash/save_snapshot_lock_ownership_followup.txt)
- [`ragdoll_save_load_contract_deep_audit.txt`](../analysis/ghidra/output/crash/ragdoll_save_load_contract_deep_audit.txt)
- [LowProcess containment contract](crash_20260717_lowprocess_save_structural_containment_plan.md)

The save barrier does not prove universal exclusion of mutations. A readable
mapping does not prove an object's lifetime or generation. In particular,
neither a save-wide validity cache nor cached successful ragdoll readiness has
a proven invalidation contract. These are excluded from the proposed patch.

### Inventory: bound reuse to one validation

`entrydata.rs::is_valid_entry` currently performs exactly three memory queries
for each accepted entry: entry storage, form storage, and vtable storage.
There are no native callbacks between these three checks, but the serializer
calls native code between entries.

Proposed change: evaluate a stack-local cache of at most three queried readable
regions inside one save-side `is_valid_entry` call. Three is derived from the
three existing range checks. Discard it before the native body, logging, or
next-node call; never retain an accepted form or entry result. Preserve the
same pointer reads, range coverage, vtable/text bounds, rejection decisions,
serialized count, flags, and writer state. Keep load-side behavior scoped out
of this optimization.

For stable mappings this changes the query budget from three to the number of
distinct queried regions, between one and three. It cannot promise a reduction
when all ranges occupy different regions, and initialization/comparison costs
must be considered. No allocation, global cache, TLS, or additional lock is
needed. Before implementation, close the within-validation mapping-stability
contract; callback-free source alone does not exclude other threads. If that
contract cannot be established, retain fresh queries rather than weaken the
guard. Reuse across entries is a separate, currently unsupported proposal.

### LowProcess: resolve context once per intercepted call

`lowprocess.rs` caches four readable and four executable regions per
traversal. Before this optimization, on the accepted nonterminal-node path,
context resolution occurred
twice in the data hook, once in the payload hook, and four times in the next
hook. Each resolution fetches the current thread ID and searches up to four
owner slots. `FnPtr::from_raw` only checks NULL; it is not another memory query
and does not justify a function-pointer redesign.

Implemented: resolve the existing owner slot once on entry to each data/next
hook; pass call-local `SaveTraversalAccess` to validation operations instead
of rediscovering it. Payload validation still resolves once, and a NULL
payload still requires no lookup. The normal nonterminal-node budget becomes
three slot resolutions rather than seven. The non-Send, non-Sync handle holds
only a pointer to the existing context storage across a native predecessor
call, never a mutable context reference. Checks reborrow the context after
the call so nested saves can replace and restore it without Rust aliasing
violations. Construction is unsafe and restricted to the intercepted call's
owner lifetime; the handle never claims, releases, or owns a slot.
The existing owner wrapper, four-slot admission, nesting restoration, and
missing-context behavior remain in force.

Retain validation of the predecessor's returned data cell, node alignment,
payload contract, 256-node bound, Brent cycle detection, count behavior, and
sampled anomaly counters. Do not skip native accessors on an empty list or
drop the owner wrapper on that path: an empty payload does not authorize
bypassing an installed provider. Do not increase cache lifetimes or capacities
as part of this change. This is the first implementation candidate because
it removes repeated bookkeeping without extending memory-validation reuse.

### Ragdoll: retain regions within one readiness check

`ragdoll.rs::ragdoll_ready_for_bone_update` currently remembers only the most
recent readable region. It checks up to six ranges: controller, scene root,
transform root, hierarchy, bone group, and bone table. Alternation between
regions can therefore repeat queries within one invocation. The bone loop
checks pointer values; it does not perform a memory query per bone.

Proposed change: allow the existing readiness validator to retain at most six
regions for the writeback hook, with capacity derived from those six checks.
Keep the most recent region as the first lookup to preserve the current cheap
hit. Preserve one-region behavior in the other update wrappers initially, so
the save investigation does not silently change recurring frame costs. Use
stack storage and discard it before native writeback; no controller-address
cache, ready bit, frame cache, or lifecycle hooks.

Retain every existing root, count, capacity, and bone-pointer check, including
the full bone loop and its 512-bone bound. Do not replace it with sampling or
validate only once per controller. Under stable mappings the query count is
at most the existing six, with reductions only when earlier regions recur.
The larger cache adds comparisons and stack initialization, so adopt it only
when the affected path benefits. Mapping stability within the validation
still requires proof; the existing one-region cache is precedent for the
mechanism, not proof that arbitrarily broader caching is safe.

### Durable commit and implementation order

The save write wrapper calls its predecessor and checks the returned byte
count; it does not flush every write. The commit boundary validates only the
bounded envelope, flushes the completed temporary image, independently copies
and flushes the old final, and performs write-through promotion. Preserve all
of these operations, failure propagation, canary checks, and recovery order.
Do not move serialization or promotion to tasklets or workers. A later I/O
optimization needs a separately proven durability and Proton/MO2 contract.

Planned order:

1. The owner waived the unavailable failing actual-save baseline for this
   unreleased candidate. Runtime timing remains unverified.
   If diagnostic instrumentation becomes useful, reuse `hitch_profiling`, the
   existing stopwatch, and logger. Aggregate counts and emit one end-of-save
   summary, not one log or timer per entry. Separate owner duration,
   serialization, and commit costs only at verified boundaries; do not label
   the unaccounted remainder as a particular engine phase.
2. LowProcess slot lookup is refactored with predecessor calls, native ABIs,
   existing static storage, hook installation, and nested-context ownership
   preserved. No imports, TLS, configuration, startup callbacks, or shared
   library APIs are added by this source change.
3. Inventory and ragdoll cache expansion is deferred: the retained barrier
   and lifetime evidence does not establish mapping stability against all
   concurrent mutation sources. Their production code and fresh-query
   behavior remain intact. Skipping runtime logs does not close this gap.
4. Run applicable affected-crate checks, one supported 32-bit release build,
   formatting, and diff review. Do not add mirrored engine models, source
   assertions, or synthetic save workloads as behavioral substitutes.
5. Compare the same real save workload before and after, retaining the same
   mod set, allocator, storage path, save type, and diagnostic settings.
   Measure end-to-end duration and candidate contribution; use repeated
   runs to compare median and tail latency rather than a single sample.
   Vanilla is a contextual baseline, not the correctness oracle for Psycho's
   additional durability work.

Acceptance requires a reproducible reduction in affected save latency,
unchanged valid inventory and gameplay state after reload, the same corrupt
input containment and stream counts, and continued durable-save recovery.
Include manual, quick, and autosave paths, relevant allocator modes, and
existing supported providers. Cache-only changes must not regress ordinary
update timing. Existing LowProcess performance limits remain applicable;
there is no supplied absolute whole-save latency target. Builds and reduced
operation counts alone do not demonstrate the reported slowdown is fixed.
The owner authorized this unreleased candidate without reproduction and
subsequently requested its commit. Runtime performance acceptance and
packaging are not implied.

## Evidence classification

Proven by executable disassembly:

- the save owner/call ordering and intervention points;
- absence of a complete lock inside snapshot traversal;
- raw unchecked PlayerCharacter reads before block-boundary diagnostics;
- actor-array layouts, SpeedMult index/offsets, version gates, marker, and
  minimum block sizes;
- the two version-`0x30` physical-file header layouts and their exact
  separator-based discriminator;
- load error flag, return-byte behavior, and physical commit ABIs;
- vanilla backup rotation and final promotion through `DeleteFileA` and the
  `MoveFileA`-backed CRT rename at `0x00EC862C`.

Reasoned inference:

- an incompletely quiesced mutation or other malformed serialization source can
  make the autosave intermittent;
- the reported speed jump is produced by wrong bytes reaching the proven
  SpeedMult slots through that path.

Runtime observations:

- the reported issue is intermittent and no defective save was available for
  byte comparison;
- available nearby control saves did not reproduce the abnormal SpeedMult
  state;
- the first integrity build rejected every quicksave with failure bits `0x50`
  and `truncated save header`: the completed temporary file was present, but
  the write-entry capture had not observed its initial bytes;
- envelope validation now reads the completed temporary file directly, so it
  does not depend on partial write-hook coverage;
- a later tester build completed each quicksave at the engine boundary but
  rejected promotion with failure bits `0x50` and `save header separator
  mismatch`; Psycho required the optional 64-byte language block even though
  the executable's readers accept a version-`0x30` header without it;
- envelope validation now mirrors the readers and reports the failed metadata
  field, byte offset, expected separator, and observed byte;
- the next tester build produced the same deterministic rejection for quick,
  manual, and automatic saves: `vanilla_failure=false`, failure bits `0x50`,
  and a claimed missing player-name separator at offset 103 where the byte was
  `0x07`;
- with the present 64-byte language block, the first string begins at offset
  100. Its decoded `u16` length was zero, offset 102 was its one valid pipe,
  and offset 103 was the next string's seven-byte length. Psycho's validator
  incorrectly demanded an empty-payload pipe that neither the engine writer
  emits nor its reader consumes. The temporary save was valid under the
  executable's header contract;
- runtime commit `310a920b52ed6e2de5e06871fe8d715e68adc498` accepts the
  corrected envelope but fails all three observed promotions in
  `ReplaceFileA`: two quicksaves and one autosave report Win32 error `0x497`,
  `ERROR_UNABLE_TO_REMOVE_REPLACED`, with failure bits `0x10`. This is a
  promotion/API-compatibility failure, not another serialized-header
  rejection;
- the hardened implementation removes `ReplaceFileA` from the save path. Live
  MO2/Proton acceptance of the new copy, flush, and `MoveFileExA` sequence is
  still required and is not claimed from unit tests;
- runtime playtesting is still required to identify which producer, if any,
  first triggers a rejection under the user's full mod list.

Durable supporting evidence:

- `analysis/ghidra/output/crash/save_snapshot_thread_contract_audit.txt`
- `analysis/ghidra/output/crash/save_snapshot_lock_ownership_followup.txt`
- `analysis/ghidra/output/crash/save_io_commit_error_followup.txt`
- `analysis/ghidra/output/crash/save_format_integrity_contract_audit.txt`
- `analysis/ghidra/output/crash/save_final_intervention_contract_audit.txt`
- `analysis/ghidra/output/crash/save_changed_record_inflate_bounds_followup.txt`
- `.reports/psycho-engine-fixes-latest--save-still-broken.log`
- `.reports/psycho-engine-fixes-latest--saves-again-broken.log`

## Validation and playtest acceptance

Pure regression tests construct both engine-accepted current-format header
layouts and exhaust every empty/nonempty combination across all four string
positions. Independent literal fixtures cover the conditional string-read
branches without using the builder. The suite reproduces the observed
`00 00 7C 07 00 7C` transition at offset 100, accepts metadata beyond the old
2 KiB capture and at the exact schema maximum, and rejects the first byte over
that bound. It also accepts a coherent screenshot above the removed 64 MiB
policy cap while rejecting dimensions that overflow the reader's 32-bit RGB
size. It retains rejection coverage for a nonempty string without its payload
pipe, bad magic, inconsistent header size, a missing changed-record body, and
incorrect versioned PlayerCharacter block layouts.

Required runtime acceptance:

1. Make repeated manual, quick, and autosaves while movement modifiers and
   scripted effects are active.
2. Confirm successful saves log `Durable commit complete`, reload normally,
   and preserve expected movement.
3. On any rejection, preserve the `.fos.tmp`, final `.fos`, adjacent `.nvse`,
   `psycho-engine-fixes-latest.log`, and the immediately preceding good save.
4. Confirm a deliberately truncated/misframed PlayerCharacter block is
   rejected before entering the original PlayerCharacter loader.
5. Confirm the dashboard distinguishes I/O, format, state-mutation, general
   load, PlayerCharacter-preflight, and missing-master events.

Build and test evidence for a change must use the explicit
`i686-pc-windows-gnu` target and be recorded in the change handoff. Static proof
does not replace this runtime playtest.

Validation recorded on 2026-07-23:

- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib`:
  36 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p
  psycho-engine-fixes`: passed;
- the broader unfiltered `cargo test` ran the same unit suite successfully but
  remains nonzero because three pre-existing Havok/navmesh assembly examples
  are marked as Rust doctests.

Validation recorded on 2026-07-27 after adding both accepted header layouts:

- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib`:
  67 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p
  psycho-engine-fixes -p psycho-engine-fixes-helper`: passed;
- successful quick, manual, automatic, and scripted saves with the reporter's
  mod list still require runtime playtesting.

Validation recorded on 2026-07-27 after matching the engine's empty-string
framing:

- the regression test reproduced the runtime failure before the code change:
  offset 103 expected `0x7C`, found `0x07`;
- focused save-envelope tests: 7 passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib`:
  86 passed, 0 failed;
- `cargo build --release --target i686-pc-windows-gnu -p
  psycho-engine-fixes`: passed;
- successful quick, manual, automatic, and scripted saves with the reporter's
  mod list still require runtime playtesting.

Validation recorded on 2026-07-27 after reliability hardening:

- focused save-integrity tests: 13 passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib`:
  90 passed, 0 failed;
- the `libpsycho` unit-test phase: 9 passed, 0 failed; its package-wide command
  remains nonzero because the unrelated existing logger example at
  `libpsycho/src/logger/impl.rs:130` uses the overflowing unsuffixed literal
  `0xDEADBEEF` (the remaining 15 doctests passed);
- `cargo build --release --target i686-pc-windows-gnu -p
  psycho-engine-fixes`: passed;
- runtime save/load acceptance remains required because Wine unit tests cannot
  exercise the live engine hook and filesystem-promotion sequence.

Validation recorded on 2026-07-27 after removing `ReplaceFileA` promotion:

- focused save-integrity tests: 22 passed, 0 failed, including injected
  recovery-copy and replacement failures, interrupted-transaction recovery,
  post-commit error handling, the engine-compatible fallback, first-save
  behavior, and complete configured-backup rotation;
- `cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes --lib`:
  99 passed, 0 failed;
- `cargo test --target i686-pc-windows-gnu -p libpsycho --lib`: 11 passed,
  0 failed; the added Wine filesystem tests executed both the direct
  copy/flush/replacement sequence and the vacant-destination rename fallback,
  then verified the resulting file images;
- `cargo build --release --target i686-pc-windows-gnu -p
  psycho-engine-fixes -p psycho-engine-fixes-helper`: passed;
- successful quick, manual, automatic, and scripted saves through the
  reporter's MO2/Proton virtual save path remain mandatory runtime acceptance.
