//! Remove redundant integer setup from the two native AABB/frustum predicates.
//!
//! Each admitted 35-byte initialization loop advances a local pointer eight
//! times without dereferencing it. Seven instructions reproduce the loop's
//! exact final registers, arithmetic flags and two local words, then resume the
//! original method. Frames, corner generation, plane tests and FP state stay
//! unchanged. This removes 64 executed integer instructions per native call
//! without adding a runtime bridge, admission check, allocation or lock.
//!
//! Installation belongs exclusively to core activation at the quiescent
//! pre-CRT barrier. Exact frame/block signatures reject conflicting code before
//! any write. A shared transaction rolls back only owned writes on failure;
//! identical pre-existing replacements are never claimed. Successful patches
//! live until process exit, with no event work or gameplay-time unpatching.
//!
//! Contract and raw binary evidence:
//! `docs/fnv_location_performance_static_audit.md`, AABB baseline section.

use anyhow::{Context, Result, ensure};
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::{CodeSignature, OwnedCodePatch},
};

// The original 15-byte entries establish EBP, reserve the native frames and
// save ECX before either patch site. Do not admit an altered frame or detour.
static INTERSECTION_FRAME: CodeSignature = CodeSignature::new(
    "AABB intersection frame",
    0x00C387F0,
    &[
        0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xF0, 0x01, 0x00, 0x00, 0x89, 0x8D, 0x14, 0xFE, 0xFF, 0xFF,
    ],
);
static CONTAINMENT_FRAME: CodeSignature = CodeSignature::new(
    "AABB containment frame",
    0x00C38920,
    &[
        0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xE0, 0x01, 0x00, 0x00, 0x89, 0x8D, 0x20, 0xFE, 0xFF, 0xFF,
    ],
);

static INTERSECTION_SETUP: OwnedCodePatch = OwnedCodePatch::new(
    "AABB intersection setup",
    0x00C387FF,
    &[
        0xC7, 0x45, 0x84, 0x08, 0x00, 0x00, 0x00, 0x8D, 0x45, 0x98, 0x89, 0x45, 0x88, 0x8B, 0x4D,
        0x84, 0x83, 0xE9, 0x01, 0x89, 0x4D, 0x84, 0x78, 0x0B, 0x8B, 0x55, 0x88, 0x83, 0xC2, 0x0C,
        0x89, 0x55, 0x88, 0xEB, 0xEA,
    ],
    &[
        // EAX=EBP-0x68, EDX=EBP-0x08; neither LEA dereferences the buffer.
        0x8D, 0x45, 0x98, 0x8D, 0x55, 0xF8,
        // SUB 0,1 reproduces the final counter and CF/PF/AF/ZF/SF/OF.
        0x31, 0xC9, 0x83, 0xE9, 0x01,
        // Preserve even the otherwise dead locals for downstream providers.
        0x89, 0x4D, 0x84, 0x89, 0x55, 0x88,
        // MOV/JMP leave flags unchanged. Resume at 0x00C38822; padding is dead.
        0xE9, 0x0D, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90,
    ],
);
static CONTAINMENT_SETUP: OwnedCodePatch = OwnedCodePatch::new(
    "AABB containment setup",
    0x00C3892F,
    &[
        0xC7, 0x45, 0x90, 0x08, 0x00, 0x00, 0x00, 0x8D, 0x45, 0xA0, 0x89, 0x45, 0x94, 0x8B, 0x4D,
        0x90, 0x83, 0xE9, 0x01, 0x89, 0x4D, 0x90, 0x78, 0x0B, 0x8B, 0x55, 0x94, 0x83, 0xC2, 0x0C,
        0x89, 0x55, 0x94, 0xEB, 0xEA,
    ],
    &[
        // Same final-state reconstruction, with this method's buffer/locals.
        // EAX=EBP-0x60, EDX=EBP, ECX=-1; flags come from SUB 0,1.
        // Resume at 0x00C38952 without moving the frame or original calls.
        0x8D, 0x45, 0xA0, 0x8D, 0x55, 0x00, 0x31, 0xC9, 0x83, 0xE9, 0x01, 0x89, 0x4D, 0x90, 0x89,
        0x55, 0x94, 0xE9, 0x0D, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90,
    ],
);

/// Install both state-preserving AABB setup patches at core startup.
///
/// Requires the pre-CRT barrier, before core initialization finishes, while
/// native methods are quiescent. Verifies both frames and blocks before writes.
/// An exact existing replacement is accepted without acquiring its ownership.
/// A failed write triggers best-effort ownership-aware rollback and an error
/// log; foreign writes are never overwritten. No native object is dereferenced.
/// Successful patches remain for the process lifetime. Returns an error on a
/// wrong lifecycle boundary, signature conflict, or memory/protection failure.
pub(crate) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "AABB setup installation requires core activation at the pre-CRT barrier"
    );
    for frame in [&INTERSECTION_FRAME, &CONTAINMENT_FRAME] {
        frame.verify().with_context(|| frame.name())?;
    }
    for patch in [&INTERSECTION_SETUP, &CONTAINMENT_SETUP] {
        patch.verify().with_context(|| patch.name())?;
    }

    let mut transaction = ModificationTransaction::new();
    for patch in [&INTERSECTION_SETUP, &CONTAINMENT_SETUP] {
        if let Err(error) = transaction.apply_patch(patch) {
            log::error!(
                "[MULTIBOUND] Bounds setup installation failed; rolling back owned writes: {error}"
            );
            return Err(error).with_context(|| patch.name());
        }
    }
    transaction.commit();
    log::debug!(
        "[MULTIBOUND] Qualified setup sites: intersection=0x{:08X}, containment=0x{:08X}",
        INTERSECTION_SETUP.address(),
        CONTAINMENT_SETUP.address(),
    );
    log::info!("[MULTIBOUND] Redundant bounds setup optimized at both native sites");
    Ok(())
}
