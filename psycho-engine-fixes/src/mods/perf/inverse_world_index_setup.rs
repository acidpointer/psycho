//! Fold constant row indices in native unskinned inverse-world expansion.
//!
//! Nine paired initializer/IMUL windows become precomputed byte offsets and
//! neutral LEAs. Native input reads, stack spills, x87 instructions, helpers,
//! output stores and the skinned branch remain at their original addresses.
//! There is no per-call bridge, guard, state, allocation or lock.
//!
//! Core activation verifies the complete supported function around all nine
//! windows before applying one independent transaction at the quiescent pre-CRT
//! barrier. Exact existing replacements acquire no ownership. Failure restores
//! only owned writes; successful patches remain until exit without event work.
//! The owning contract and qualification limits are recorded in
//! `docs/fnv_location_performance_static_audit.md`.

use anyhow::{Context, Result, ensure};
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::{CodeSignature, OwnedCodePatch},
};

const FUNCTION: usize = 0x00C4C2D0;
const NATIVE: &[u8] = include_bytes!("scene_signatures/inverse_world.bin");

// Keep each original window's length beside its patch without a second table
// of offsets. The full-body preflight excludes only these verified windows.
macro_rules! index_patch {
    ($address:expr, $original:expr, $replacement:expr) => {
        (
            OwnedCodePatch::new(
                "Inverse-world constant index",
                $address,
                $original,
                $replacement,
            ),
            $original.len(),
        )
    };
}

static PATCHES: [(OwnedCodePatch, usize); 9] = [
    index_patch!(
        0x00C4C2EF,
        &[0x33, 0xC9, 0x6B, 0xC9, 0x0C],
        &[0x33, 0xC9, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C314,
        &[0xBA, 0x01, 0x00, 0x00, 0x00, 0x6B, 0xD2, 0x0C],
        &[0xBA, 0x0C, 0x00, 0x00, 0x00, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C33D,
        &[0xB8, 0x02, 0x00, 0x00, 0x00, 0x6B, 0xC0, 0x0C],
        &[0xB8, 0x18, 0x00, 0x00, 0x00, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C36E,
        &[0x33, 0xD2, 0x6B, 0xD2, 0x0C],
        &[0x33, 0xD2, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C397,
        &[0xB8, 0x01, 0x00, 0x00, 0x00, 0x6B, 0xC0, 0x0C],
        &[0xB8, 0x0C, 0x00, 0x00, 0x00, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C3C3,
        &[0xB9, 0x02, 0x00, 0x00, 0x00, 0x6B, 0xC9, 0x0C],
        &[0xB9, 0x18, 0x00, 0x00, 0x00, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C3F7,
        &[0x33, 0xC0, 0x6B, 0xC0, 0x0C],
        &[0x33, 0xC0, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C420,
        &[0xB9, 0x01, 0x00, 0x00, 0x00, 0x6B, 0xC9, 0x0C],
        &[0xB9, 0x0C, 0x00, 0x00, 0x00, 0x8D, 0x49, 0x00]
    ),
    index_patch!(
        0x00C4C44C,
        &[0xBA, 0x02, 0x00, 0x00, 0x00, 0x6B, 0xD2, 0x0C],
        &[0xBA, 0x18, 0x00, 0x00, 0x00, 0x8D, 0x49, 0x00]
    ),
];

/// Install the complete nine-window group during core pre-CRT activation.
///
/// Verifies all unmodified function bytes and exact original-or-replacement
/// windows before writing. Requires quiescent native code and an unfinished
/// core initialization. Returns an error for lifecycle, contract or memory
/// failures. Application failure rolls back only still-owned writes through
/// the shared transaction. No native object is accessed and no runtime
/// callback, state publication or teardown work is introduced.
pub(crate) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "Inverse-world index installation requires core activation at the pre-CRT barrier"
    );

    let mut previous = 0;
    for (patch, length) in &PATCHES {
        let offset = patch
            .address()
            .checked_sub(FUNCTION)
            .context("Inverse-world index precedes function")?;
        let expected = NATIVE
            .get(previous..offset)
            .context("Inverse-world contract windows overlap or exceed function")?;
        CodeSignature::new(
            "Inverse-world expansion body",
            FUNCTION + previous,
            expected,
        )
        .verify()?;
        patch.verify().with_context(|| patch.name())?;
        previous = offset
            .checked_add(*length)
            .context("Inverse-world index extent overflow")?;
    }
    let expected = NATIVE
        .get(previous..)
        .context("Inverse-world index exceeds function")?;
    CodeSignature::new(
        "Inverse-world expansion tail",
        FUNCTION + previous,
        expected,
    )
    .verify()?;

    let mut transaction = ModificationTransaction::new();
    for (patch, _) in &PATCHES {
        if let Err(error) = transaction.apply_patch(patch) {
            log::error!(
                "[INVERSE_WORLD_INDEX] Index installation failed; rolling back owned writes: {error}"
            );
            return Err(error).with_context(|| patch.name());
        }
    }
    transaction.commit();
    log::debug!("[INVERSE_WORLD_INDEX] Qualified nine index windows in 0x{FUNCTION:08X}");
    log::info!("[INVERSE_WORLD_INDEX] Redundant object-transform index calculations removed");
    Ok(())
}
