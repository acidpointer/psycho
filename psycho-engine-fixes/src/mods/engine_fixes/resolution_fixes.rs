//! Native menu render resolution, tile targeting, and full-view fade geometry.
//!
//! Five exact patches install together at the core's pre-CRT barrier. Identical
//! existing corrections remain externally owned; unknown code blocks the whole
//! installation. Native rendering, resource lifetime, and x87 height conversion
//! stay engine-owned. Native clipping and input branches remain intact. Optional
//! deferred observation reads code once and never repairs a later owner's work.
//! Every valid native resolution uses the same patches; no aspect-ratio or
//! resolution threshold controls admission. Allocation and clip/input getters
//! share the default render group's width with the original 1280 minimum.
//! Height retains the native aspect calculation, and fades use both dimensions.
//! Installation allocates only through the established patch transaction;
//! target sizing uses bounded native integer queries; rendering adds no allocation,
//! locking, or diagnostics.

use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

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
const WIDTH_ADDRESSES: [usize; 2] = [0x00B6_CD2C, 0x00B6_CEC3];
const MENU_WIDTH_ADDRESS: usize = 0x0070_6E80;
const MENU_WIDTH_ORIGINAL: &[u8] = &[
    0x55, 0x8B, 0xEC, 0xD9, 0x05, 0x38, 0xEC, 0x06, 0x01, 0x5D, 0xC3,
];

struct ReplacementBytes {
    widths: [[u8; 19]; 2],
    menu_width: [u8; 11],
}

// Replace only the original seven-byte width store with CALL/NOP/NOP.
// The renderer's original virtual +0xC8 call stays byte-for-byte intact.
static REPLACEMENTS: LazyLock<ReplacementBytes> = LazyLock::new(|| {
    let widths = WIDTH_ADDRESSES.map(|address| {
        let mut replacement = [0; 19];
        replacement.copy_from_slice(WIDTH_ORIGINAL);
        replacement[0] = 0xE8;
        replacement[1..5].copy_from_slice(
            &((screen_width_bridge as *const () as usize).wrapping_sub(address + 5) as u32)
                .to_le_bytes(),
        );
        replacement[5..7].fill(0x90);
        replacement
    });
    // Replace the complete getter, including its original prologue and RET.
    // The jump enters a replacement which returns to the original caller.
    let mut menu_width = [0x90; 11];
    menu_width[0] = 0xE9;
    menu_width[1..5].copy_from_slice(
        &((menu_width_getter as *const () as usize).wrapping_sub(MENU_WIDTH_ADDRESS + 5) as u32)
            .to_le_bytes(),
    );
    ReplacementBytes { widths, menu_width }
});

/// Resolve the requested menu width from the native default render group.
///
/// Safety: ECX is a live renderer on the native UI/render path. Its virtual
/// +0xC8 returns the live default group; virtual +0x8C takes color index zero
/// and returns its u32 width in EAX, cleaning that one stack argument. These
/// native integer getters do not touch x87. No pointer escapes the call, and
/// no ownership changes. The thiscall boundary has no stack arguments.
#[unsafe(naked)]
unsafe extern "thiscall" fn screen_render_width(_renderer: *mut core::ffi::c_void) -> u32 {
    core::arch::naked_asm!(
        "mov eax, dword ptr [ecx]",
        "call dword ptr [eax + 0xC8]",
        "mov ecx, eax",
        "mov eax, dword ptr [ecx]",
        "push 0",
        "call dword ptr [eax + 0x8C]",
        "cmp eax, 1280",
        "jae 2f",
        "mov eax, 1280",
        "2:",
        "ret",
    );
}

/// Replace the native width store without reducing its original detail.
///
/// Safety: only the two verified dimension branches may enter this splice.
/// EBP is their live, writable width-output pointer (the displaced instruction
/// already stores there). EDI is the live renderer used by the following native
/// aspect calls. Preserve every register, flags, and the x87 state, and return
/// with the original stack depth.
/// A plain RET consumes only the splice's return address, with no FFI unwind.
#[unsafe(naked)]
unsafe extern "C" fn screen_width_bridge() {
    core::arch::naked_asm!(
        "pushfd",
        "pushad",
        "mov ecx, edi",
        "call {width}",
        "mov dword ptr [ebp], eax",
        "popad",
        "popfd",
        "ret",
        width = sym screen_render_width,
    );
}

/// Return the same requested width to native clipping, height, and input code.
///
/// Safety: only the verified no-argument native getter entry jumps here. The
/// native renderer accessor and integer virtuals preserve x87 stack contents.
/// Preserve registers/flags and add exactly one float result in ST(0), matching
/// the displaced FLD/RET. Zero-extension through an eight-byte stack temporary
/// keeps the u32 width positive before FILD; the store/reload rounds to f32.
#[unsafe(naked)]
unsafe extern "C" fn menu_width_getter() -> f32 {
    core::arch::naked_asm!(
        "pushfd",
        "pushad",
        "mov eax, 0x0043C4B0",
        "call eax",
        "mov ecx, eax",
        "call {width}",
        "push 0",
        "push eax",
        "fild qword ptr [esp]",
        "fstp dword ptr [esp]",
        "fld dword ptr [esp]",
        "add esp, 8",
        "popad",
        "popfd",
        "ret",
        width = sym screen_render_width,
    );
}

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

static SITES: LazyLock<[PatchSite; 5]> = LazyLock::new(|| {
    [
        PatchSite::new(
            "screen render width",
            WIDTH_ADDRESSES[0],
            WIDTH_ORIGINAL,
            &REPLACEMENTS.widths[0],
        ),
        PatchSite::new(
            "character creation render width",
            WIDTH_ADDRESSES[1],
            WIDTH_ORIGINAL,
            &REPLACEMENTS.widths[1],
        ),
        PatchSite::new(
            "menu clip and input width",
            MENU_WIDTH_ADDRESS,
            MENU_WIDTH_ORIGINAL,
            &REPLACEMENTS.menu_width,
        ),
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
    ]
});

// Exact surrounding instructions and owner entries from the supported
// executable. Every range excludes all five writable footprints so an
// independently supplied identical correction passes the same preflight.
// Evidence: analysis/radare2/output/fnv_resolution_context_signatures_20261020.txt.
// Clip/input contracts: fnv_terminal_static_repair_contract_20261020.txt in the
// same evidence directory. These retained native paths are required, not owned.
const CONTEXT: &[CodeSignature] = &[
    CodeSignature::new(
        "native menu clipping predicate",
        0x00A0_3C60,
        &[
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x89, 0x4D, 0xF4, 0x8B, 0x4D, 0xF4, 0xE8, 0x1F,
            0x00, 0x00, 0x00, 0x89, 0x45, 0xFC, 0x8B, 0x45, 0xFC, 0x8A, 0x48, 0x1C, 0x88, 0x4D,
            0xFB, 0x8A, 0x45, 0xFB, 0x8B, 0xE5, 0x5D, 0xC3,
        ],
    ),
    CodeSignature::new(
        "native menu aspect height",
        0x0070_6E90,
        &[
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x30, 0xE8, 0x15, 0x56, 0xD3, 0xFF, 0x89, 0x45, 0xFC,
            0x8B, 0x45, 0xFC, 0x8B, 0x10, 0x8B, 0x4D, 0xFC, 0x8B, 0x82, 0xC8, 0x00, 0x00, 0x00,
            0xFF, 0xD0, 0x89, 0x45, 0xF8, 0x8B, 0x4D, 0xFC, 0x8B, 0x11, 0x8B, 0x4D, 0xFC, 0x8B,
            0x82, 0xC8, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x89, 0x45, 0xF4, 0x6A, 0x00, 0x8B, 0x4D,
            0xF4, 0x8B, 0x11, 0x8B, 0x4D, 0xF4, 0x8B, 0x82, 0x8C, 0x00, 0x00, 0x00, 0xFF, 0xD0,
            0x89, 0x45, 0xEC, 0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00, 0xDF, 0x6D, 0xEC, 0x6A,
            0x00, 0x8B, 0x4D, 0xF8, 0x8B, 0x11, 0x8B, 0x4D, 0xF8, 0x8B, 0x82, 0x90, 0x00, 0x00,
            0x00, 0xDD, 0x5D, 0xE4, 0xFF, 0xD0, 0x89, 0x45, 0xDC, 0xC7, 0x45, 0xE0, 0x00, 0x00,
            0x00, 0x00, 0xDF, 0x6D, 0xDC, 0xDC, 0x75, 0xE4, 0xDD, 0x5D, 0xD4, 0xE8, 0x70, 0xFF,
            0xFF, 0xFF, 0xDC, 0x4D, 0xD4, 0xD9, 0x5D, 0xD0, 0xD9, 0x45, 0xD0, 0x8B, 0xE5, 0x5D,
            0xC3,
        ],
    ),
    CodeSignature::new(
        "native clip dimensions",
        0x00A0_63E2,
        &[
            0xE8, 0x79, 0xD8, 0xFF, 0xFF, 0x0F, 0xB6, 0xD0, 0x85, 0xD2, 0x74, 0x16, 0xE8, 0x8D,
            0x0A, 0xD0, 0xFF, 0xD9, 0x9D, 0xA8, 0xFE, 0xFF, 0xFF, 0xE8, 0x92, 0x0A, 0xD0, 0xFF,
            0xD9, 0x9D, 0xA0, 0xFE, 0xFF, 0xFF,
        ],
    ),
    CodeSignature::new(
        "native sibling clip dimensions",
        0x00A0_65DF,
        &[
            0xE8, 0x7C, 0xD6, 0xFF, 0xFF, 0x0F, 0xB6, 0xC8, 0x85, 0xC9, 0x74, 0x16, 0xE8, 0x90,
            0x08, 0xD0, 0xFF, 0xD9, 0x9D, 0x84, 0xFE, 0xFF, 0xFF, 0xE8, 0x95, 0x08, 0xD0, 0xFF,
            0xD9, 0x9D, 0x78, 0xFE, 0xFF, 0xFF,
        ],
    ),
    CodeSignature::new(
        "native recursive clip dimensions",
        0x00A0_7B3B,
        &[
            0xE8, 0x20, 0xC1, 0xFF, 0xFF, 0x0F, 0xB6, 0xC8, 0x85, 0xC9, 0x74, 0x10, 0xE8, 0x34,
            0xF3, 0xCF, 0xFF, 0xD9, 0x5D, 0xEC, 0xE8, 0x3C, 0xF3, 0xCF, 0xFF, 0xD9, 0x5D, 0xE8,
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
        "native menu targeting conversion",
        0x0071_2BA1,
        &[
            0x74, 0x78, 0xE8, 0x98, 0x42, 0xFF, 0xFF, 0xDD, 0x9D, 0x24, 0xFF, 0xFF, 0xFF, 0xE8,
            0xCD, 0x42, 0xFF, 0xFF, 0xDC, 0xBD, 0x24, 0xFF, 0xFF, 0xFF,
        ],
    ),
    CodeSignature::new(
        "fade geometry owner",
        0x0070_0960,
        &[
            0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xA0, 0x78, 0xF0, 0x00, 0x64, 0xA1, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x81, 0xEC, 0x0C, 0x01, 0x00, 0x00,
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
    for site in SITES.iter() {
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
    for site in SITES.iter() {
        site.patch.verify()?;
        if site.corrected.read()? == site.corrected.expected() {
            preexisting += 1;
        }
    }

    let mut transaction = ModificationTransaction::new();
    for site in SITES.iter() {
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
