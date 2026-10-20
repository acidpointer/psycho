//! Native menu render resolution, tile targeting, and full-view fade geometry.
//!
//! Six exact patches install together at the core's pre-CRT barrier. Identical
//! existing corrections remain externally owned; unknown code blocks the whole
//! installation. Native rendering, resource lifetime, and x87 height conversion
//! stay engine-owned. No callback intercepts rendering or input. The optional
//! deferred observation reads code once and never repairs a later owner's work.
//! Installation allocates only through the established patch transaction;
//! normal gameplay adds no calls, allocation, locking, or diagnostics.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use anyhow::{Context, ensure};
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::{CodeSignature, OwnedCodePatch},
};

const DISABLED: u8 = 0;
const ACTIVE: u8 = 1;
const CONFLICT: u8 = 2;
const CHANGED: u8 = 3;

static STATUS: AtomicU8 = AtomicU8::new(DISABLED);
static PREEXISTING: AtomicU8 = AtomicU8::new(0);
static OBSERVED_DEFERRED: AtomicBool = AtomicBool::new(false);

const WIDTH_ORIGINAL: &[u8] = &[
    0xC7, 0x45, 0x00, 0x00, 0x05, 0x00, 0x00, 0x8B, 0x17, 0x8B, 0x82, 0xC8, 0x00, 0x00, 0x00, 0x8B,
    0xCF, 0xFF, 0xD0,
];
// Load the native configured-width snapshot, store through EBP, and retain
// the renderer's no-stack-argument virtual +0xC8 call. Native code still
// computes proportional height and restores its x87 control word afterward.
const WIDTH_REPLACEMENT: &[u8] = &[
    0xA1, 0x30, 0x94, 0x1F, 0x01, 0x90, 0x89, 0x45, 0x00, 0x8B, 0x17, 0x8B, 0xCF, 0xFF, 0x92, 0xC8,
    0x00, 0x00, 0x00,
];

struct PatchSite {
    patch: OwnedCodePatch,
    corrected: CodeSignature,
}

impl PatchSite {
    const fn new(
        name: &'static str,
        address: usize,
        original: &'static [u8],
        replacement: &'static [u8],
    ) -> Self {
        Self {
            patch: OwnedCodePatch::new(name, address, original, replacement),
            corrected: CodeSignature::new(name, address, replacement),
        }
    }
}

static SITES: [PatchSite; 6] = [
    // This thiscall predicate has no stack arguments and returns its boolean
    // in AL. Returning before the unchanged prologue suffix makes that suffix
    // unreachable; CONTEXT verifies it through the original RET as well.
    PatchSite::new(
        "menu tile scaling",
        0x00A0_3C60,
        &[0x55, 0x8B, 0xEC, 0x83],
        &[0x32, 0xC0, 0xC3, 0x90],
    ),
    PatchSite::new(
        "screen render width",
        0x00B6_CD2C,
        WIDTH_ORIGINAL,
        WIDTH_REPLACEMENT,
    ),
    PatchSite::new(
        "character creation render width",
        0x00B6_CEC3,
        WIDTH_ORIGINAL,
        WIDTH_REPLACEMENT,
    ),
    // Keep the rel8 destination. CONTEXT checks its displacement and the
    // independent preceding condition, not merely the replaced JE opcode.
    PatchSite::new("menu tile targeting", 0x0071_2BA1, &[0x74], &[0xEB]),
    PatchSite::new(
        "fade width",
        0x0070_0AB2,
        &[0xDC, 0x0D, 0x88, 0x15, 0x01, 0x01],
        &[0x90; 6],
    ),
    PatchSite::new(
        "fade height",
        0x0070_0ACC,
        &[0xDC, 0x0D, 0x88, 0x15, 0x01, 0x01],
        &[0x90; 6],
    ),
];

// Exact surrounding instructions and owner entries from the supported
// executable. Every range excludes all six writable footprints so an
// independently supplied identical correction passes the same preflight.
// Evidence: analysis/radare2/output/fnv_resolution_context_signatures_20261020.txt.
const CONTEXT: &[CodeSignature] = &[
    CodeSignature::new(
        "menu tile scaling suffix",
        0x00A0_3C64,
        &[
            0xEC, 0x0C, 0x89, 0x4D, 0xF4, 0x8B, 0x4D, 0xF4, 0xE8, 0x1F, 0x00, 0x00, 0x00, 0x89,
            0x45, 0xFC, 0x8B, 0x45, 0xFC, 0x8A, 0x48, 0x1C, 0x88, 0x4D, 0xFB, 0x8A, 0x45, 0xFB,
            0x8B, 0xE5, 0x5D, 0xC3,
        ],
    ),
    CodeSignature::new(
        "render dimensions owner",
        0x00B6_C2C0,
        &[
            0x8B, 0x44, 0x24, 0x18, 0x83, 0xEC, 0x08, 0x53, 0x55, 0xC7, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x8B, 0x0D, 0x90, 0x94, 0x1F, 0x01, 0x56,
        ],
    ),
    CodeSignature::new(
        "screen width output",
        0x00B6_CD24,
        &[0x8B, 0x6C, 0x24, 0x24, 0x8B, 0x7C, 0x24, 0x1C],
    ),
    CodeSignature::new(
        "screen aspect source",
        0x00B6_CD3F,
        &[
            0x8B, 0x17, 0x8B, 0xD8, 0x8B, 0x82, 0xC8, 0x00, 0x00, 0x00, 0x8B, 0xCF, 0xFF, 0xD0,
        ],
    ),
    CodeSignature::new(
        "character creation width output",
        0x00B6_CEBB,
        &[0x8B, 0x6C, 0x24, 0x24, 0x8B, 0x7C, 0x24, 0x1C],
    ),
    CodeSignature::new(
        "character creation aspect source",
        0x00B6_CED6,
        &[
            0x8B, 0x17, 0x8B, 0xD8, 0x8B, 0x82, 0xC8, 0x00, 0x00, 0x00, 0x8B, 0xCF, 0xFF, 0xD0,
        ],
    ),
    CodeSignature::new(
        "menu targeting owner",
        0x0071_26C0,
        &[
            0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xA0, 0x80, 0xF0, 0x00, 0x64, 0xA1, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x81, 0xEC, 0xD0, 0x00, 0x00, 0x00,
        ],
    ),
    CodeSignature::new(
        "menu targeting conditions",
        0x0071_2B7D,
        &[
            0xB9, 0xCC, 0xB2, 0x1D, 0x01, 0xE8, 0xD9, 0x61, 0xCF, 0xFF, 0x0F, 0xB6, 0x00, 0x85,
            0xC0, 0x0F, 0x84, 0x89, 0x00, 0x00, 0x00, 0x8B, 0x8D, 0x40, 0xFF, 0xFF, 0xFF, 0x0F,
            0xB6, 0x91, 0x70, 0x01, 0x00, 0x00, 0x85, 0xD2,
        ],
    ),
    CodeSignature::new(
        "menu targeting destination",
        0x0071_2BA2,
        &[0x78, 0xE8, 0x98, 0x42, 0xFF, 0xFF],
    ),
    CodeSignature::new(
        "fade geometry owner",
        0x0070_06C0,
        &[
            0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xE4, 0x77, 0xF0, 0x00, 0x64, 0xA1, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x83, 0xEC, 0x78,
        ],
    ),
    CodeSignature::new(
        "fade width source",
        0x0070_0AA1,
        &[
            0xE8, 0x4A, 0xB7, 0xDD, 0xFF, 0x89, 0x85, 0x14, 0xFF, 0xFF, 0xFF, 0xDB, 0x85, 0x14,
            0xFF, 0xFF, 0xFF,
        ],
    ),
    CodeSignature::new(
        "fade width output and height source",
        0x0070_0AB8,
        &[
            0xD9, 0x5D, 0xF0, 0xE8, 0x40, 0xB7, 0xDD, 0xFF, 0x89, 0x85, 0x10, 0xFF, 0xFF, 0xFF,
            0xDB, 0x85, 0x10, 0xFF, 0xFF, 0xFF,
        ],
    ),
    CodeSignature::new(
        "fade height output",
        0x0070_0AD2,
        &[
            0xD9, 0x5D, 0xB0, 0x51, 0xD9, 0x45, 0xB0, 0xD9, 0x1C, 0x24, 0x51, 0xD9, 0xEE, 0xD9,
            0x1C, 0x24, 0xD9, 0x45, 0xF0,
        ],
    ),
];

/// Install the complete correction once during the admitted core startup.
pub(super) fn install(enabled: bool) {
    if !enabled {
        log::info!("[RESOLUTION] Resolution fixes disabled by config");
        return;
    }

    match apply() {
        Ok(preexisting) => {
            PREEXISTING.store(preexisting, Ordering::Relaxed);
            STATUS.store(ACTIVE, Ordering::Release);
            log::info!(
                "[RESOLUTION] Resolution fixes active: {} sites installed, {preexisting} already corrected",
                SITES.len() - usize::from(preexisting),
            );
        }
        Err(error) => {
            STATUS.store(CONFLICT, Ordering::Release);
            log::warn!(
                "[RESOLUTION] Resolution fixes unavailable; existing external patches retained: {error:#}"
            );
        }
    }
}

fn verify_context() -> anyhow::Result<()> {
    for signature in CONTEXT {
        signature.verify()?;
    }
    Ok(())
}

fn verify_corrected() -> anyhow::Result<()> {
    verify_context()?;
    for site in &SITES {
        site.corrected.verify()?;
    }
    Ok(())
}

fn apply() -> anyhow::Result<u8> {
    // The transaction is not synchronization. Core admission must prove the
    // game's main thread has not entered any of these native instruction paths.
    ensure!(
        crate::entry::has_pre_crt_startup_boundary(),
        "resolution patches require the pre-CRT startup barrier"
    );
    verify_context()?;
    let mut preexisting = 0;
    for site in &SITES {
        site.patch.verify()?;
        if site.corrected.read()? == site.corrected.expected() {
            preexisting += 1;
        }
    }

    let mut transaction = ModificationTransaction::new();
    for site in &SITES {
        transaction
            .apply_patch(&site.patch)
            .with_context(|| format!("install {}", site.patch.name()))?;
    }
    verify_corrected()?;
    transaction.commit();
    Ok(preexisting)
}

/// Observe post-plugin-load ownership once without writing live instructions.
pub(super) fn observe_event(kind: u32) {
    if kind != crate::events::DEFERRED_INIT
        || STATUS.load(Ordering::Acquire) != ACTIVE
        || OBSERVED_DEFERRED.swap(true, Ordering::AcqRel)
    {
        return;
    }
    if let Err(error) = verify_corrected() {
        STATUS.store(CHANGED, Ordering::Release);
        log::warn!(
            "[RESOLUTION] Resolution patch state changed after installation; later code retained: {error:#}"
        );
    }
}

/// Read the published status without inspecting or changing executable memory.
pub(super) fn diagnostic_status() -> (&'static str, u8) {
    let status = match STATUS.load(Ordering::Acquire) {
        ACTIVE => "active",
        CONFLICT => "unavailable",
        CHANGED => "changed after installation",
        _ => "disabled",
    };
    (status, PREEXISTING.load(Ordering::Relaxed))
}
