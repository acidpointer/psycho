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

The on-disk header begins with `FO3SAVEGAME`, a 32-bit encoded header length,
the current version `0x30`, pipe-delimited metadata, and the screenshot
dimensions. The screenshot consumes `width * height * 3` bytes. The changed
record body follows it.

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
- the first 2 KiB written are captured without extra file I/O;
- short writes, buffering failure, close failure, tracking failure, and
  in-transaction PlayerCharacter SpeedMult mutation latch failure bits;
- the result boundary destroys/closes the engine file without promotion;
- the completed temporary file must have a current coherent header, bounded
  screenshot, and a nonempty changed-record body;
- the file is flushed to stable storage and atomically replaces the final,
  retaining or recovering the old final according to the configured backup
  policy.

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
- Existing final saves are not deleted on failure. Replacement recovery uses
  an owned backup.

Save-time overhead is a 2 KiB capture, three 32-bit canary reads at each
boundary, and one header parse before the already-required durable flush. The
capture and canary use small cold-path mutexes; no lock is added to ordinary
gameplay. Player load preflight performs one block-range validation and up to
three float checks. Valid changed-record field reads retain their constant-time
logical bounds checks and do not perform per-field allocation or file I/O.

The structural envelope check is not a complete parser for every changed
record. It proves the outer current-format save framing, while the existing
record reader and the new pre-mutation PlayerCharacter check protect the
audited mutation paths. Extending coverage must be based on an exact
serializer/loader contract rather than guessed value limits.

The xNVSE `.nvse` cosave is not atomically paired with `.fos` promotion by this
module. A future paired transaction requires an xNVSE ownership contract and
must not be inferred from the core file path.

## Evidence classification

Proven by executable disassembly:

- the save owner/call ordering and intervention points;
- absence of a complete lock inside snapshot traversal;
- raw unchecked PlayerCharacter reads before block-boundary diagnostics;
- actor-array layouts, SpeedMult index/offsets, version gates, marker, and
  minimum block sizes;
- load error flag, return-byte behavior, and physical commit ABIs.

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
- runtime playtesting is still required to identify which producer, if any,
  first triggers a rejection under the user's full mod list.

Durable supporting evidence:

- `analysis/ghidra/output/crash/save_snapshot_thread_contract_audit.txt`
- `analysis/ghidra/output/crash/save_snapshot_lock_ownership_followup.txt`
- `analysis/ghidra/output/crash/save_io_commit_error_followup.txt`
- `analysis/ghidra/output/crash/save_format_integrity_contract_audit.txt`
- `analysis/ghidra/output/crash/save_final_intervention_contract_audit.txt`
- `analysis/ghidra/output/crash/save_changed_record_inflate_bounds_followup.txt`

## Validation and playtest acceptance

Pure regression tests construct current-format headers and reject bad magic,
inconsistent header size, a missing changed-record body, and incorrect
versioned PlayerCharacter block layouts.

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
