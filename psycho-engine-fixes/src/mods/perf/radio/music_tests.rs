//! Execute the shipped x86 patch and the verified original instructions.
//!
//! The fixture supplies only the audited stack/register inputs and records
//! which native continuation is reached. It does not model a codec, audio
//! graph, worker, or radio station. These tests qualify the repaired machine
//! code boundary, not end-to-end playback in the game.

use core::ffi::c_void;

use libpsycho::os::windows::winapi::{
    FreeType, flush_instructions_cache, virtual_alloc_rwx, virtual_free,
};

use super::{
    EntryKey, EntryState, ExpiryAction, MediaOutcome, MusicRequest, ORIGINAL, REPLACEMENT,
    entry_media_outcome,
};

fn entry(epoch: u64, node: usize) -> EntryKey {
    EntryKey {
        station: 0x1000,
        station_list: 0x2000,
        selected_node: 0x3000,
        selected_music_node: node,
        start: 1000,
        epoch,
    }
}

#[test]
fn admitted_entry_stays_closed_across_retirement_and_forced_starts() {
    let key = entry(1, 0x4000);
    let mut state = EntryState::EMPTY;
    assert!(!state.start_is_duplicate(key));
    // The real queue-attempt bridge closes the selection, independent of a
    // worker generation or a positive native duration.
    state.media_attempted = true;
    state.admitted = true;
    state.accepted_generation = 17;
    assert!(state.start_is_duplicate(key));
    assert_eq!(
        state.expiry(Some(MediaOutcome::Pending), false, 0),
        ExpiryAction::Hold
    );
    assert_eq!(
        state.expiry(Some(MediaOutcome::Pending), false, 190_000),
        ExpiryAction::Hold
    );
    assert_eq!(
        state.expiry(Some(MediaOutcome::Complete), false, 190_000),
        ExpiryAction::Advance
    );
    assert!(state.start_is_duplicate(key));
    assert!(!state.start_is_duplicate(entry(2, 0x4000)));
    assert!(!state.start_is_duplicate(entry(2, 0x5000)));
}

#[test]
fn media_failure_and_dual_sound_reconcile_before_native_advance() {
    let mut state = EntryState::EMPTY;
    state.select(entry(1, 0x4000));
    state.media_attempted = true;
    state.sound_attempted = true;
    state.admitted = true;
    state.accepted_generation = 18;
    assert_eq!(
        state.expiry(Some(MediaOutcome::Failed), true, 0),
        ExpiryAction::Native
    );
    assert_eq!(
        state.expiry(Some(MediaOutcome::Failed), false, 0),
        ExpiryAction::Advance
    );
    assert_eq!(
        state.expiry(Some(MediaOutcome::Complete), true, 1),
        ExpiryAction::Native
    );
    assert_eq!(
        state.expiry(Some(MediaOutcome::Complete), false, 1),
        ExpiryAction::Advance
    );
    assert!(state.start_is_duplicate(entry(1, 0x4000)));
}

#[test]
fn rejected_and_interrupted_entries_take_distinct_paths() {
    let mut state = EntryState::EMPTY;
    state.select(entry(1, 0x4000));
    state.media_attempted = true;
    state.admitted = true;
    state.rejected = true;
    assert_eq!(state.expiry(None, false, 0), ExpiryAction::Advance);

    state.select(entry(2, 0x4000));
    state.media_attempted = true;
    assert_eq!(state.expiry(None, false, 0), ExpiryAction::Hold);
    assert!(!state.start_is_duplicate(entry(2, 0x4000)));

    state.accepted_generation = 19;
    state.admitted = true;
    assert_eq!(
        state.expiry(Some(MediaOutcome::Interrupted), false, 500),
        ExpiryAction::Hold
    );
    assert!(!state.start_is_duplicate(entry(2, 0x4000)));
}

#[test]
fn sound_only_entry_preserves_timer_and_recovers_missing_duration() {
    let mut state = EntryState::EMPTY;
    state.select(entry(1, 0x4000));
    state.sound_attempted = true;
    state.admitted = true;
    assert_eq!(state.expiry(None, true, 0), ExpiryAction::Native);
    assert_eq!(state.expiry(None, false, 2000), ExpiryAction::Native);
    assert_eq!(state.expiry(None, false, 0), ExpiryAction::Advance);
}

#[test]
fn completed_generation_survives_native_slot_reuse() {
    let key = entry(4, 0x7000);
    let finished = MusicRequest {
        generation: 27,
        epoch: key.epoch,
        station: key.station,
        station_list: key.station_list,
        selected_node: key.selected_node,
        selected_music_node: key.selected_music_node,
        start: key.start,
        outcome: MediaOutcome::Complete,
    };
    let slots = [MusicRequest::EMPTY; 2];
    assert_eq!(
        entry_media_outcome(key, 27, 29, &slots, finished),
        Some(MediaOutcome::Complete)
    );
    assert_eq!(
        entry_media_outcome(entry(5, 0x7000), 27, 29, &slots, finished),
        None
    );
    assert_eq!(entry_media_outcome(key, 28, 29, &slots, finished), None);
}

const FUTURE: u32 = 1;
const SEEK: u32 = 2;
const PLAYBACK: u32 = 3;
const CODE_SIZE: usize = 0x138;

struct ExecutableBlock(*mut c_void);

impl ExecutableBlock {
    fn new(bytes: &[u8; 39]) -> Self {
        let code = Self(virtual_alloc_rwx(CODE_SIZE).expect("executable fixture"));
        // SAFETY: this allocation is owned and not executing during writes.
        // All native relative branches stay within it. Continuation stubs
        // return their identity to the caller at the inspected block boundary.
        unsafe {
            core::ptr::write_bytes(code.0.cast::<u8>(), 0xCC, CODE_SIZE);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), code.0.cast(), bytes.len());
            for (offset, outcome) in [(0x27, FUTURE), (0x49, SEEK), (0x132, PLAYBACK)] {
                let target = code.0.cast::<u8>().add(offset);
                target.write(0xB8); // mov eax, outcome
                target.add(1).cast::<u32>().write_unaligned(outcome);
                target.add(5).write(0xC3); // ret
            }
        }
        flush_instructions_cache(code.0, CODE_SIZE).expect("flush fixture instructions");
        code
    }

    fn run(&self, now: u32, start: u32, duration: u32) -> (u32, u32) {
        let mut frame = [0u32; 0x200 / 4];
        frame[(0x200 - 0x14) / 4] = duration;
        frame[(0x200 - 0x40) / 4] = start;
        frame[(0x200 - 0x1F8) / 4] = now;
        frame[(0x200 - 0x1F4) / 4] = now.wrapping_sub(start);
        // SAFETY: execute supplies the audited input registers and preserves
        // the test caller's EBP. The fixture's whole native frame is in bounds
        // and exclusively borrowed; the executable allocation outlives the call.
        let outcome = unsafe { execute(self.0, frame.as_mut_ptr().add(frame.len())) };
        (outcome, frame[(0x200 - 0x1F4) / 4])
    }
}

impl Drop for ExecutableBlock {
    fn drop(&mut self) {
        // SAFETY: every call has returned; no executable/frame pointer escapes.
        unsafe { virtual_free(self.0, FreeType::Release) }.expect("free executable fixture");
    }
}

#[unsafe(naked)]
unsafe extern "C" fn execute(_block: *mut c_void, _frame_end: *mut u32) -> u32 {
    core::arch::naked_asm!(
        "push ebp",
        "mov ecx, [esp + 8]",
        "mov ebp, [esp + 12]",
        "mov eax, [ebp - 0x1F8]",
        "mov edx, [ebp - 0x1F4]",
        "call ecx",
        "pop ebp",
        "ret",
    );
}

#[test]
fn zero_duration_reaches_native_playback_without_unbounded_seek() {
    let patched = ExecutableBlock::new(&REPLACEMENT);
    for (now, start) in [(1000, 900), (900, 900), (899, 900), (u32::MAX, 1)] {
        assert_eq!(
            patched.run(now, start, 0),
            (PLAYBACK, now.wrapping_sub(start))
        );
    }
}

#[test]
fn positive_duration_preserves_native_offset_and_continuation() {
    let native = ExecutableBlock::new(&ORIGINAL);
    let patched = ExecutableBlock::new(&REPLACEMENT);
    for duration in [1, 2, 3, 7, 1000, 180_000, u32::MAX] {
        for elapsed in [0, 1, 2, 3, 7, 15, 999, 1000, 1001, 180_000, 360_000] {
            assert_eq!(
                patched.run(elapsed, 0, duration),
                native.run(elapsed, 0, duration),
                "elapsed={elapsed} duration={duration}"
            );
        }
    }
    // The native comparison is >, not >=: exact multiples retain the endpoint.
    assert_eq!(patched.run(360_000, 0, 180_000), (SEEK, 180_000));
    assert_eq!(patched.run(0, 0, 180_000), (SEEK, 0));
}

#[test]
fn future_start_reaches_native_clamp_without_unsigned_subtraction_loop() {
    let native = ExecutableBlock::new(&ORIGINAL);
    let patched = ExecutableBlock::new(&REPLACEMENT);
    for duration in [180_000, u32::MAX] {
        assert_eq!(native.run(1000, 1050, duration).0, FUTURE);
        assert_eq!(patched.run(1000, 1050, duration).0, FUTURE);
    }
    assert_eq!(patched.run(1000, 1050, 1).0, FUTURE);
}

#[test]
fn full_width_elapsed_finishes_with_native_inclusive_endpoint() {
    let patched = ExecutableBlock::new(&REPLACEMENT);
    assert_eq!(patched.run(u32::MAX, 0, 1), (SEEK, 1));
    assert_eq!(patched.run(u32::MAX, 0, 3), (SEEK, 3));
    assert_eq!(patched.run(u32::MAX, 0, u32::MAX), (SEEK, u32::MAX));
}
