//! Remove redundant four-vertex setup from native compound/portal construction.
//!
//! Three integer-only loops advance stack-local pointers without touching the
//! vertex buffers. Seven instructions reproduce each loop's final registers,
//! arithmetic flags and two local words, then resume its original continuation.
//! Each reached block loses 32 instructions, nine local reads and nine writes.
//! Native frames, providers, cached-record gates and FP state retain their
//! original contracts. No gameplay-time bridge, guard, allocation or lock is added.
//!
//! Core activation installs this independent group only at the quiescent pre-CRT
//! barrier. All frame/block signatures are checked before writing. One transaction
//! rolls back only acquired writes on failure; equivalent existing replacements
//! acquire no ownership. Successful patches live until exit without event work.
//!
//! Binary contracts, complete native bodies and compiled qualification are retained
//! in `docs/fnv_location_performance_static_audit.md`, compound/portal setup section.

use anyhow::{Context, Result, ensure};
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::{CodeSignature, OwnedCodePatch},
};

// Original entries establish EBP and the local frames before intervention.
// Reject modified frame setup, including entry detours, before touching any site.
static APPEND_FRAME: CodeSignature = CodeSignature::new(
    "Compound append frame",
    0x00C47B50,
    &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x6C, 0x89, 0x4D, 0x98],
);
static PORTAL_FRAME: CodeSignature = CodeSignature::new(
    "Portal compound frame",
    0x00C47D20,
    &[
        0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x74, 0x01, 0x00, 0x00, 0x89, 0x8D, 0x94, 0xFE, 0xFF, 0xFF,
    ],
);
static PLANES_FRAME: CodeSignature = CodeSignature::new(
    "Portal plane frame",
    0x00C33870,
    &[
        0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xBC, 0x01, 0x00, 0x00, 0x56, 0x57, 0x89, 0x8D, 0x48, 0xFE,
        0xFF, 0xFF,
    ],
);

static APPEND_SETUP: OwnedCodePatch = OwnedCodePatch::new(
    "Compound append vertex setup",
    0x00C47BC1,
    &[
        0xC7, 0x45, 0xA8, 0x04, 0x00, 0x00, 0x00, 0x8D, 0x55, 0xC0, 0x89, 0x55, 0xAC, 0x8B, 0x45,
        0xA8, 0x83, 0xE8, 0x01, 0x89, 0x45, 0xA8, 0x78, 0x0B, 0x8B, 0x4D, 0xAC, 0x83, 0xC1, 0x0C,
        0x89, 0x4D, 0xAC, 0xEB, 0xEA,
    ],
    &[
        // EDX=buffer, ECX=buffer+48, EAX=-1. SUB 0,1 retains terminal flags.
        // Preserve the counter/pointer locals; JMP skips all padding to 0xC47BE4.
        0x8D, 0x55, 0xC0, 0x8D, 0x4D, 0xF0, 0x31, 0xC0, 0x83, 0xE8, 0x01, 0x89, 0x45, 0xA8, 0x89,
        0x4D, 0xAC, 0xE9, 0x0D, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90,
    ],
);
static PORTAL_SETUP: OwnedCodePatch = OwnedCodePatch::new(
    "Portal compound vertex setup",
    0x00C47DD6,
    &[
        0xC7, 0x85, 0x14, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x8D, 0x4D, 0xC0, 0x89, 0x8D,
        0x18, 0xFF, 0xFF, 0xFF, 0x8B, 0x95, 0x14, 0xFF, 0xFF, 0xFF, 0x83, 0xEA, 0x01, 0x89, 0x95,
        0x14, 0xFF, 0xFF, 0xFF, 0x78, 0x11, 0x8B, 0x85, 0x18, 0xFF, 0xFF, 0xFF, 0x83, 0xC0, 0x0C,
        0x89, 0x85, 0x18, 0xFF, 0xFF, 0xFF, 0xEB, 0xDE,
    ],
    &[
        // ECX=EBP-0x40, EAX=EBP-0x10, EDX=-1; locals are EBP-0xEC/EBP-0xE8.
        // Final SUB matches the native terminal iteration, not pointer ADD flags.
        // Resume 0xC47E0B without changing the frame or subsequent provider calls.
        0x8D, 0x4D, 0xC0, 0x8D, 0x45, 0xF0, 0x31, 0xD2, 0x83, 0xEA, 0x01, 0x89, 0x95, 0x14, 0xFF,
        0xFF, 0xFF, 0x89, 0x85, 0x18, 0xFF, 0xFF, 0xFF, 0xE9, 0x19, 0x00, 0x00, 0x00, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    ],
);
static PLANES_SETUP: OwnedCodePatch = OwnedCodePatch::new(
    "Portal plane vertex setup",
    0x00C3391F,
    &[
        0xC7, 0x85, 0x10, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x8D, 0x4D, 0xD0, 0x89, 0x8D,
        0x14, 0xFF, 0xFF, 0xFF, 0x8B, 0x95, 0x10, 0xFF, 0xFF, 0xFF, 0x83, 0xEA, 0x01, 0x89, 0x95,
        0x10, 0xFF, 0xFF, 0xFF, 0x78, 0x11, 0x8B, 0x85, 0x14, 0xFF, 0xFF, 0xFF, 0x83, 0xC0, 0x0C,
        0x89, 0x85, 0x14, 0xFF, 0xFF, 0xFF, 0xEB, 0xDE,
    ],
    &[
        // Recompute branch only: the existing cached-record gate stays upstream.
        // ECX=EBP-0x30, EAX=EBP (one past buffer), EDX=-1; no buffer dereference.
        // Preserve locals EBP-0xF0/EBP-0xEC and SUB flags, then resume 0xC33954.
        0x8D, 0x4D, 0xD0, 0x8D, 0x45, 0x00, 0x31, 0xD2, 0x83, 0xEA, 0x01, 0x89, 0x95, 0x10, 0xFF,
        0xFF, 0xFF, 0x89, 0x85, 0x14, 0xFF, 0xFF, 0xFF, 0xE9, 0x19, 0x00, 0x00, 0x00, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    ],
);

/// Install the three independent compound/portal setup patches at core startup.
///
/// Requires the pre-CRT activation barrier before core initialization completes,
/// while native code is quiescent. Checks every frame and block before writing.
/// An exact existing replacement is accepted without acquiring its ownership.
/// Conflicting bytes or memory/protection failures return an error; application
/// failure attempts ownership-aware rollback and reports errors through the
/// shared logger. Foreign writes are never restored over. Successful patches
/// remain until process exit. No native object is read and no unwind or gameplay
/// lifecycle work is introduced.
pub(crate) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "Compound/portal setup installation requires core activation at the pre-CRT barrier"
    );
    for frame in [&APPEND_FRAME, &PORTAL_FRAME, &PLANES_FRAME] {
        frame.verify().with_context(|| frame.name())?;
    }
    for patch in [&APPEND_SETUP, &PORTAL_SETUP, &PLANES_SETUP] {
        patch.verify().with_context(|| patch.name())?;
    }

    let mut transaction = ModificationTransaction::new();
    for patch in [&APPEND_SETUP, &PORTAL_SETUP, &PLANES_SETUP] {
        if let Err(error) = transaction.apply_patch(patch) {
            log::error!(
                "[MULTIBOUND_VERTICES] Setup installation failed; rolling back owned writes: {error}"
            );
            return Err(error).with_context(|| patch.name());
        }
    }
    transaction.commit();
    log::debug!(
        "[MULTIBOUND_VERTICES] Qualified setup sites: append=0x{:08X}, portal=0x{:08X}, planes=0x{:08X}",
        APPEND_SETUP.address(),
        PORTAL_SETUP.address(),
        PLANES_SETUP.address(),
    );
    log::info!(
        "[MULTIBOUND_VERTICES] Redundant compound/portal setup optimized at three native sites"
    );
    Ok(())
}
