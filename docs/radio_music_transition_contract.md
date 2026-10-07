# Fallout New Vegas radio music transition contract

## Status and evidence

This is the static engine contract for the unreleased radio music transition
candidate in `psycho-engine-fixes/src/mods/perf/radio/music.rs`. It concerns
the supported `fnv_reverse/FalloutNV.exe`, inspected with the radare2 MCP.
Addresses below refer to that executable. The owner reported that the same
song restarted immediately after nearly complete plays, later heard
`announcer -> song 1 -> song 2 -> song 2`, and subsequently heard continuing
repeats. These observations rejected the preceding candidate. No capture from
those sessions identifies the exact event order. The earlier
[duration-loop audit](../analysis/ghidra/output/perf/radio_music_duration_loop_radare2_audit.txt)
records the actual original x86 loop bytes and a fail-first execution of them;
the broader scan history is in [radio scan evidence](radio_scan_hitch_evidence.md).
Focused disassembly for the new start, queue, worker, sound, and playlist
findings is preserved in the
[radare2 instruction record](../analysis/radare2/output/fnv_radio_music_transition_contract_20261007.txt).

The native radio player has three separate state machines: the station
playlist and timer, two asynchronous DirectShow slots, and the game sound
handle. The station entry, media generation, and sound activity are different
identities. A terminal event from one path cannot establish that the other
path has stopped. This contract proves the replay routes and safe
intervention boundaries. It does not diagnose the uncaptured playtest's
specific interleaving or claim audible success under Proton.

The decisive defect in the preceding rejected candidate was incomplete start
admission: it guards only the normal argument-0 call while a current-station
sound object can invoke argument 1 for the same selection and bypass the
native active escape. Independent zero/overlong timers and unrecorded media
failures can then prevent the native cursor from advancing. A duration-only
or completion-only patch cannot close these routes.

## Station selection and all music starts

| Boundary | Direct binary evidence | Contract |
|---|---|---|
| Entry identity | `0x00834260` receives the station. Station `+4` owns an outer list; its `+8` is the selected cursor node. That node's first dword is an inner list whose `+8` is the selected music cursor. `0x0083C820` reads the current node. Station `+0xC` is the start tick, `+0x10` the duration/timer. | Compare station, list owner, both nodes, start tick, and a Psycho-owned epoch. Follow pointers only on a live game-side station path. Filename equality alone cannot distinguish entries. |
| Normal start | `0x0083561B..22` calls `0x008331C0(0)` for the current station if this update has not already called it. `0x008334DF..0x00833509` queries `0x00830750(7,1)` and global sound handle `0x011DD5BC`; argument 0 escapes to volume/update at `0x00833A31` when either is active. | A retired slot can appear inactive while the station still selects the same entry. Suppress its resubmission but preserve native volume work. |
| Sound-object start | `0x00835544..71` calls `0x008331C0(1)` for the current station when a station sound object's `+0x1D` is clear and this update has not already called the starter. It checks neither station timer nor media generation. Argument 1 bypasses the active-result escape at `0x00833503..09`. | This was a proved unguarded replay path in the preceding patch. Both station callers need the same entry admission. The per-update byte prevents only a second call in that update. |
| Save restoration | `0x00836E20`, reached from load processing at `0x0084C214`, calls `0x008324E0` and then `0x008331C0(1)` at `0x00836EDD` if a current station exists. These are the only three direct native callers of the starter. | Restoration is a new lifecycle epoch. Do not globally treat argument 1 as a duplicate or block a legitimate restored start. |
| Selected media | `0x0083391E..0x0083398D` resolves the selected inner file, prefixes `data\\sound\\`, and calls `0x008300C0` with priority 7, the station start tick, `arg14=0`, and `arg18=1`. | The policy must work for any station using this native player, including modded selections and extensions. |

The station has two list mutation classes. Native timed progression calls
`0x0083B9F0` at `0x008346CC` to advance the outer node, then
`0x0083C7B0` at `0x00834744` to reset the selected inner cursor and writes
`now+50` and duration 0 at `0x00834755..61`. The current station update can
advance an inner node at `0x00834A82` or `0x0083559F`. `0x00837060`
destroys/rebuilds the outer list at its two direct calls, `0x00834909` and
`0x00835DCA`; `StartRadioConversation` first exhausts the old outer list at
`0x00835CCD`. A rebuilt list may reuse addresses. A monotonic local epoch is
therefore required in addition to node and tick comparison.

`0x0061B440` constructs conversations through `0x0083B850`. Its randomized
selection at `0x0061B707/0x0061B728` uses a local marker array initialized at
`0x0061B67F`, and the array lasts only for that build. Candidate selection
delegates through `0x0061B320 -> 0x0061A790 -> 0x0061A7D0`, which also applies
dialogue and world-state filters. The inspected local marker is therefore
**not** a cross-build, prior-filename guarantee; a universal such guarantee
has not been proved in the nested selector. Treat a changed outer/inner node
as a new native entry even when its file equals the last file. One-track
modded stations necessarily repeat; an optional consecutive-file policy
must act only when a live eligible alternative exists and must not skip
announcer speech or bypass native dialogue filters.

## DirectShow publication and worker outcomes

The shared queue `0x008300C0` returns no success status. It exits before the
current accepted-queue bridge for priority-9 reset (`0x008300F6`), disabled
media (`0x0083010B..1B`), null/empty names (`0x00830120..35`), rejected
priority, and a missing file (`0x008301B8..E0`). Radio's `arg18=1` bypasses
the priority comparison; it does not bypass missing-file or disabled-media
exits. Accepted work publishes one of two generations at
`0x008302A8..0x008302E7` or `0x008303CA..0x00830409` and wakes a worker.
Consequently the existing hook at the two `0x0082F760` calls cannot observe
every failed music attempt. Filename-free priority-7 stop calls from radio
paths call `0x008304A0` first, invoking `0x0082FA30` reset; those null
requests then exit before accepted publication. The reset hook sees them,
not the queue hook.

The worker copies slot and generation at `0x00830B5B..6C` and rejects stale
or canceled work at `0x00830C16..53`. It can fail opening/recognizing the
file at `0x00830E51..0x00830F33`, or fail COM setup at
`0x00830FD5..0x008311B1`, without posting completion. `GetEvent` at
`0x0083196F..0x008319E9` returns code 1 (complete), 2 (user abort), or 3
(error abort). Code 1 with `S_OK` is the only graph-success result currently
recorded. All terminal codes disable the worker run flag at `0x00831A6D`;
other failure exits reach `0x00831A9E`. Before generation cleanup at
`0x00831B01..0x00831C6F`, the worker still holds its copied slot/generation.
This is the outcome boundary for failure without an event, but the station
must distinguish failure from supersession and interruption. The general
pause/disable route `0x00761449 -> 0x008304F0` sets slot flag bit 2 and
cancels work; it is not a bad-track result.

The queue sets native replay bit `0x20` only from `arg14` at
`0x00830245..53` or `0x00830368..76`. Radio passes zero. At
`0x008319EB..0x00831A6D`, terminal media work therefore takes the stop path
instead of worker replay. A repeat of this normal request needs a new
submission or a different logical native entry. Native active query
`0x00830750(7,1)` counts a queued matching generation as active while flag
bit 2 is clear, so a delayed pending worker is not intrinsically invisible.
Once its generation retires, the query can be inactive while the station
still points at the same item.

The queue publishes a new generation before clearing the old slot duration.
The worker first clears that duration at `0x00830C97` or `0x00830D2C`, and
later writes it at `0x0083135D` or `0x008313D7`. Native duration query
`0x008308C0(7)` reads the selected slot. Both station query pairs,
`0x008339CC/DA` and `0x00834634/42`, can race publication or cleanup.
Generation-bound validated duration storage remains necessary. DirectShow
`get_Duration` at `0x008311E9/0x008312ED` and `get_CurrentPosition` at
`0x00831287` share a native output qword; a failed call otherwise leaves a
previous value. The original seek synchronization at `0x00831790` repeatedly
subtracts duration and never terminates when elapsed time is positive and
duration zero. Keep the bounded positive-duration repair and zero-duration
native playback continuation. With positive duration, native resubmission
wraps elapsed time into the file; a duplicate request can audibly restart
near the beginning even with the bounded repair.

## Sound handle and native playlist completion

The starter's media and sound booleans are independent at
`0x0083352B..0x0083368C`. A `.wav` selected file or another native sound
condition can take the sound path at `0x008336A8..0x00833875`; the media path
can still run at `0x00833902`. Thus a modded station entry can have both a
DirectShow request and a game sound handle, potentially for different assets
within the same entry. Sound creation uses flags `0x100101` at
`0x00833722/0x00833791`, registers callback `0x008357E0` on global handle
`0x011DD5BC` at `0x008337D9`, and starts it via `0x00AD8830`. Station sound
objects also register `0x008357E0` at `0x008354A1`.

The callback at `0x008357E0` sets its station argument's `+0x10` timer to 1
when its second argument's low byte is zero. `0x00AD8E60` can invoke that
callback immediately with zero while the sound manager is disabled. The
callback is therefore a timer/cleanup signal, not standalone proof of
natural audible completion. The native handle-active query at `0x00AD8CE0`
and duration query at `0x00AD8B30` are used by the station at
`0x008345F6..0x00834617`. Any graph-completion acceleration must first
check that the current handle is inactive. The internal meaning of every
`0x100101` sound flag is unnecessary for that admission rule; the proof that
radio's DirectShow replay bit is clear says nothing about sound-handle loop
behavior.

At `0x008345E5..0x0083464D`, the current station fills a nonpositive timer
from an active sound handle's duration, otherwise from priority-7 media
duration if a selected inner file exists. Its progression branch requires
`station+0x10 > 0` at `0x00834680..87` and unsigned
`start + duration < now` at `0x0083468D..0x0083469C`. It then calls native
outer-list advancement at `0x008346CC`. A completed graph with zero duration
can therefore leave the entry selected indefinitely; an overlong timer can
leave silence or allow a new same-entry submission after graph retirement.
Conversely, graph completion alone cannot safely force progression while a
game sound handle for that entry is active. The native cursor/timer branch is
the only proven progression point; policy should admit it once, not change
list cursors directly.

The preceding expiry patch's x86 shape is valid: its call at `0x00834680`
replaces seven bytes with a five-byte call and `test eax,eax`, leaving the
native `jle` at `0x00834687` and the native timer comparison. Its admission
policy was incomplete. Its active-query hook covered only normal
starter argument 0 and a positive station timer. It intentionally lets
argument 1 retain the native answer. The current completion hook sees only
successful DirectShow events, and the accepted-queue hook sees only accepted
files. These gaps allow replay or stalls independently of its duration fix.

## Mapped replay and stall routes

| Route | Proved failure mode in the preceding candidate | Required result |
|---|---|---|
| Retired media, timer still positive | Normal starter sees inactive media before native timer expiry and can resubmit the same selected entry. The current bridge covers this case only while its matching positive timer exists. | Hold the entry as already submitted until a verified transition; keep native volume/update work. |
| Forced sound-object start | `0x0083556C` passes argument 1, bypassing native active escape and the current bridge's synthetic active result. | Apply the same entry admission to this callsite. |
| Terminal after expiry check | A worker can publish completion after `0x00834680` but before either starter later in the same `0x00834260` invocation. | Keep the completed entry closed to starts until the next progression opportunity. |
| Zero or overlong timer | Native progression needs a positive expired timer; graph success can precede that timer or have no timer. | Admit current successful graph completion to native progression once, only after sound-handle activity is ruled out. |
| Missing file | Queue returns before the current accepted-request bridge, leaving no attempt state. | Observe the pre-publication rejection boundary; advance an unplayable entry only if no sound path is active. |
| Worker setup failure or graph abort | Graph construction may fail without `EC_COMPLETE`; code 2/3 are not successful completion. | Record generation-bound terminal outcome; distinguish interruption, media error, and supersession. Do not turn pause or seek/Run HRESULT into completion. |
| Reset, tuning, or save load | Old worker callbacks may arrive after native selection or current station changes. | Invalidate old epochs and admit the new station/restored selection without accepting old events. |
| Newly selected same filename | The builder's visible duplicate marker is local to one build; the nested selector does not provide a proven cross-build no-repeat contract. | Treat it as a new entry. If a no-consecutive-file policy is chosen, use only live eligible alternatives and allow a single-track station to repeat. |

The preceding candidate's single `CURRENT_MUSIC_GENERATION` could also discard the older
audible request's completion if an unguarded forced start publishes a newer
generation. That consequence follows directly from the preceding candidate's
generation comparison and the forced starter path; it is another reason to
fix admission at the start boundary instead of only changing completion
handling. These are the identified routes at the **inspected native player
boundaries**. They do not identify the owner's exact route or establish the
behavior of a mod that replaces the player.

## Implementation-ready ownership and ABI

The two station starts are cdecl `push 1/0; call 0x008331C0; add esp,4` at
`0x0083556A..71` and `0x0083561B..22`, inside the live `0x00834260` frame.
The load start has the same ABI at `0x00836EDB..E2` but begins a new epoch.
The expiry bridge at `0x00834680` returns a signed duration to
`test eax,eax`; native instructions then re-read station `+0x10` and own the
cursor changes. Queue publication at `0x008302E7/0x00830409` runs under the
native media lock and calls `0x0082F760` as thiscall with one stack argument
and `ret 4`. Worker outcome must be captured before generation cleanup at
`0x00831B01` using only copied scalar identity. The exact displaced bytes,
registers, flags, and frame offsets for any new bridge still need final
verification at installation; that is a mechanical implementation step, not
an unresolved control-flow contract.

Maintain one current station-entry state on the game side with a monotonic
epoch, both selected nodes, start tick, and attempt status. Worker-visible
two-slot records contain only generation-bound scalar results under
`parking_lot::Mutex`; workers never dereference station, list, or sound
pointers. Only a live game-side station path checks current selection and
`0x00AD8CE0`, outside the Psycho lock. Both native queue publication and
worker retirement take the media lock before any Psycho record lock. Never
call engine code while holding that Psycho lock. Keep the existing
generation-bound duration and bounded seek repair unless replacement code
proves the same invariants.

The station policy needs distinct states for new entry, submitted/pending,
playing, successful completion awaiting native advancement, interrupted
resume, and terminal failure with no audible path. Both station starter
calls consult it. Suppressing a same-entry start cannot simply skip
`0x008331C0`: that would omit its volume/update branch at `0x00833A31`.
Save restoration, station change, list rebuild, and cursor change start a
new epoch. Media success, media failure, and native sound callback/timer are
reconciled only on the game-side station path. An eligible outcome requests
one native next-entry transition; retain duplicate suppression until the
cursor actually changes or the list rebuilds. Disabled media, bit-2 pause,
reset, and station switch are resumable/invalidation paths, not failed songs.
The pre-publication missing-file outcome and post-worker failure outcome need
explicit boundaries because neither reaches the current completion record.

### Offline qualification for the rewrite

The unchanged radio transition runs only in the game; no offline execution of
its station/media boundary is available, so an offline fail-first playback
test cannot be claimed. Once extracted into a focused production Rust policy,
test that actual function with evidence-backed transition inputs. Exercise
delayed accepted work, both station starter calls, terminal publication
between expiry and start,
retirement with positive/zero duration, active sound handle, missing file,
worker setup failure, abort, bit-2 pause, reset, station change, load
restoration, list rebuild, and a one-track station. Test the compiled
production policy, not a mirrored state-machine model or source text. Keep
the existing native x86 instruction test for the zero-duration and inclusive
positive-duration seek boundary. Then run the affected 32-bit crate suite,
the supported `i686-pc-windows-gnu` release build, formatting,
`git diff --check`, and a scoped final diff review. None of these proves
audible playback or Proton startup behavior.

## Implemented candidate and remaining acceptance

The current candidate hooks both station starter calls and gives
save restoration a new entry epoch. An entry is closed to further submissions
only after the native starter reaches its sound start or its media request.
Duplicate starts take the native argument-0 volume/update path; a matching
entry supplies the active result even after a media worker retires. Current
station cursor advances, inner resets, and both list rebuild callers advance
the local epoch. Native reset clears the entry and media records. Selection
identity contains the station, outer list, both cursor nodes, start tick, and
epoch.

The radio queue callsite wrapper observes attempts before native admission.
Its changed return address means the accepted-publication bridge identifies
the synchronous queue call by its thread, filename pointer, and start argument,
then verifies priority 7 and the current station selection. Accepted
publication records the generation before the native lock is released. A
return without an accepted generation is classified from the native
disabled-media byte: disabled work remains resumable; other rejected work can
advance when no sound is active. The worker records generation-bound event outcomes and a
retirement result under the native media lock. A terminal record survives
later reuse of either native slot until the next reset. Pending media holds
the station's native timer so a delayed worker is not cut short by elapsed
queue time. A completed or failed media request can set the timer to one tick
after sound activity and any active priority-7 graph have stopped; the
original branch still chooses and advances the cursor. An interrupted request
without a sound path becomes eligible for a fresh native start.

The station's embedded sound-object list starts at `station+0x1C`. At
`0x00834AEB..0x00834B3D`, native iterates it with `0x008256D0`,
`0x006815C0`, and `0x00726070`; the active object's sound handles are at
`+4` and `+0x10` (the latter is queried at `0x00834D28..0x00834D35`).
The candidate checks these live handles as well as global `0x011DD5BC`
only when a terminal or rejected media result could accelerate progression.
While a handle is active, native timer progression remains available. This
keeps an independent announcer or modded sound path from being cut off solely
because its DirectShow graph ended.

This candidate covers the inspected native same-entry replay and stall routes.
A separate cross-entry no-repeat policy cannot be universal for one-track
stations and needs the live eligibility rules of the nested selector before
it changes native choices. This document
does not establish the exact reported interleaving, whether a particular mod
has alternative tracks, startup compatibility under Proton, or audible
runtime correctness. It does not establish behavior for a mod that replaces
the native radio player. The owner has prohibited agent game runs and owns
gameplay validation. The candidate remains unreleased pending real runtime
acceptance.
