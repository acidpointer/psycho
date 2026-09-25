//! Bounded native music-position synchronization.
//!
//! FalloutAudioMedia's two native workers wrap a radio offset by repeatedly
//! subtracting the reported duration. Zero duration prevents that loop from
//! reaching playback, events, or request cancellation. The in-place repair
//! skips only synchronization while duration is unavailable; native playback
//! and the next iteration's duration query remain responsible for progress.
//!
//! Positive durations retain the native inclusive endpoint, with one division
//! instead of an input-dependent loop. Native future-offset clamping and all
//! graph ownership/cleanup remain intact. There is no retained engine state,
//! allocation, lock, callback, or diagnostic on this worker path. Installation
//! requires the audited instruction contract at the quiescent pre-CRT boundary;
//! a mismatch leaves the existing code untouched.

use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::{CodeSignature, OwnedCodePatch},
};

const WRAP_ADDR: usize = 0x00831790;

// Exact supported-executable instructions, including the timestamp check.
const ORIGINAL: [u8; 39] = [
    0x8B, 0x85, 0x0C, 0xFE, 0xFF, 0xFF, 0x3B, 0x45, 0xEC, 0x76, 0x11, 0x8B, 0x8D, 0x0C, 0xFE, 0xFF,
    0xFF, 0x2B, 0x4D, 0xEC, 0x89, 0x8D, 0x0C, 0xFE, 0xFF, 0xFF, 0xEB, 0xE4, 0x8B, 0x95, 0x08, 0xFE,
    0xFF, 0xFF, 0x3B, 0x55, 0xC0, 0x73, 0x22,
];

// Entry: EAX = current native tick, EDX = wrapping tick - start. EBP belongs
// to 0x00830B30; duration is [EBP-14], start [EBP-40], offset [EBP-1F4].
// All exits reload scratch registers/flags before consuming them. No stack,
// nonvolatile register, x87, or SSE state is changed here.
// For offset > duration > 0, (offset - 1) % duration + 1 is exactly the
// native while(offset > duration) result. Plain modulo would incorrectly
// turn an exact track-end offset into the beginning of the track.
const REPLACEMENT: [u8; 39] = [
    0x8B, 0x4D, 0xEC, // mov ecx, [ebp-14]
    0x85, 0xC9, // test ecx, ecx
    0x0F, 0x84, 0x27, 0x01, 0x00, 0x00, // jz 8318C2: native playback/events
    0x3B, 0x45, 0xC0, // cmp eax, [ebp-40]
    0x72, 0x17, // jb 8317B7: native future clamp
    0x39, 0xCA, // cmp edx, ecx
    0x76, 0x35, // jbe 8317D9: already in range
    0x8D, 0x42, 0xFF, // lea eax, [edx-1]
    0x31, 0xD2, // xor edx, edx
    0xF7, 0xF1, // div ecx (proven nonzero)
    0x42, // inc edx
    0x89, 0x95, 0x0C, 0xFE, 0xFF, 0xFF, // mov [ebp-1F4], edx
    0xEB, 0x25, // jmp 8317D9: native seek policy
    0x90, 0x90, 0x90,
];

static WRAP_PATCH: OwnedCodePatch = OwnedCodePatch::new(
    "radio_music_bounded_position_sync",
    WRAP_ADDR,
    &ORIGINAL,
    &REPLACEMENT,
);

/// Install once before native audio workers exist. No live patching is allowed.
/// An incompatible instruction window returns an error without overwriting it.
pub(super) fn install() -> anyhow::Result<()> {
    // This prefix proves the live register values, not just the frame offsets.
    CodeSignature::new(
        "music sync input",
        0x0083176F,
        &[
            0xE8, 0xFC, 0x22, 0xC2, 0xFF, 0x8B, 0xC8, 0xE8, 0xC5, 0xB8, 0xE0, 0xFF, 0x89, 0x85,
            0x08, 0xFE, 0xFF, 0xFF, 0x8B, 0x95, 0x08, 0xFE, 0xFF, 0xFF, 0x2B, 0x55, 0xC0, 0x89,
            0x95, 0x0C, 0xFE, 0xFF, 0xFF,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "music future-offset clamp",
        0x008317B7,
        &[0xC7, 0x85, 0x0C, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
    )
    .verify()?;
    CodeSignature::new(
        "music seek continuation",
        0x008317D9,
        &[
            0xC7, 0x85, 0x04, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x95, 0x00, 0xFE,
            0xFF, 0xFF,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "music playback continuation",
        0x008318C2,
        &[0x0F, 0xBE, 0x4D, 0xE3, 0x83, 0xE1, 0x02, 0x74, 0x28],
    )
    .verify()?;
    let mut transaction = ModificationTransaction::new();
    transaction.apply_patch(&WRAP_PATCH)?;
    transaction.commit();
    log::info!(
        "[RADIO] Music position synchronization bounded; zero duration retains native playback and cancellation"
    );
    Ok(())
}

#[cfg(test)]
#[path = "music_tests.rs"]
mod tests;
