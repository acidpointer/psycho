//! FalloutNV 1.4.0.525 allocator patch manifest and compatibility policy.
//!
//! Addresses and instruction boundaries come from
//! `gheap_patch_manifest_audit.txt`. Inline hooks validate and capture the
//! live instructions themselves. Raw patches below accept only the parts of
//! an instruction that matter to the intended replacement.

use core::ffi::c_void;

use libpsycho::os::windows::{
    memory::validate_memory_access,
    patch::{CodeSignature, OwnedCodePatch, module_address},
};

use super::AllocatorMode;

macro_rules! site {
    ($name:literal, $address:literal, [$($byte:literal),+ $(,)?]) => {
        CodeSignature::new($name, $address, &[$($byte),+])
    };
}

macro_rules! patch {
    ($name:literal, $address:literal, [$($expected:literal),+ $(,)?], [$($replacement:literal),+ $(,)?]) => {
        OwnedCodePatch::new($name, $address, &[$($expected),+], &[$($replacement),+])
    };
}

macro_rules! rel_call_patch {
    ($name:literal, $address:literal, [$($byte:literal),+ $(,)?]) => {
        OwnedCodePatch::masked(
            $name,
            $address,
            &[0xE8, $($byte),+],
            &[0xFF, 0x00, 0x00, 0x00, 0x00],
            &[0x90, 0x90, 0x90, 0x90, 0x90],
        )
    };
}

// These callsites exist only to initialize allocator providers that gheap
// replaces. The opcode must still be a near CALL, but its destination may be a
// compatibility wrapper installed by another mod. We disable the callsite's
// role, not one hard-coded callee, and preserve its exact bytes for rollback.

// Full provider boundaries are disabled regardless of an existing entry hook.
// Replacing only the first byte with RET is enough at these no-argument entry
// points and lets rollback restore the exact byte it displaced.
macro_rules! provider_ret_patch {
    ($name:literal, $address:literal) => {
        OwnedCodePatch::masked($name, $address, &[0x55], &[0x00], &[0xC3])
    };
}

const GAME_HEAP_REALLOC_1: CodeSignature = site!(
    "GameHeap realloc 1",
    0x00AA4150,
    [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x89, 0x4D]
);

const REALLOC_1_JUMP_OFFSETS: [usize; 2] = [0, 2];

const SCRAP_TLS_ACCESSOR: CodeSignature = site!(
    "scrap TLS accessor",
    0x00AA42E0,
    [0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x9B, 0xEC]
);

pub const GHEAP_PATCHES: &[OwnedCodePatch] = &[
    provider_ret_patch!("SBM stats reset", 0x00AA6840),
    provider_ret_patch!("SBM config init", 0x00866770),
    provider_ret_patch!("SBM heap construction", 0x00866E00),
    provider_ret_patch!("ScrapHeapManager lazy getter", 0x00866D10),
    provider_ret_patch!("SBM global cleanup", 0x00AA7030),
    provider_ret_patch!("SBM deallocate arenas", 0x00AA5C80),
    provider_ret_patch!("ScrapHeapManager eager constructor", 0x00AA58D0),
    provider_ret_patch!("SBM purge arenas", 0x00AA6F90),
    provider_ret_patch!("SBM decrement arena ref", 0x00AA7290),
    provider_ret_patch!("SBM release arena", 0x00AA7300),
    rel_call_patch!(
        "shared thread setup call A",
        0x0086C56F,
        [0xCC, 0x61, 0x23, 0x00]
    ),
    rel_call_patch!(
        "shared thread setup call B",
        0x00C42EB1,
        [0x8A, 0xF8, 0xE5, 0xFF]
    ),
    rel_call_patch!(
        "shared thread setup call C",
        0x00EC1701,
        [0x3A, 0x10, 0xBE, 0xFF]
    ),
    rel_call_patch!(
        "late singleton allocation",
        0x00AA3060,
        [0xBB, 0xEF, 0xFF, 0xFF]
    ),
    patch!(
        "per-frame SBM management",
        0x0086EED4,
        [0x75, 0x13],
        [0xEB, 0x55]
    ),
];

// There is intentionally no `HeapSingleton + 0x129 = 0` data patch. Ghidra
// shows that the constructor runs after this pre-CRT activation and writes the
// flag back to one. The complete GameHeap allocation-entry hook bypasses that
// branch, so changing the flag would be temporary and misleading.

pub const SHEAP_PATCHES: &[OwnedCodePatch] = &[patch!(
    "embedded scrap-heap constructor",
    0x00AA38CA,
    [
        0x8B, 0x45, 0xA4, 0x05, 0x14, 0x01, 0x00, 0x00, 0x89, 0x45, 0xA8, 0x6A, 0x25, 0x8B, 0x4D,
        0xA8, 0xE8, 0x01, 0x0F, 0x00, 0x00, 0x8B, 0x4D, 0xA8, 0xC7, 0x01, 0xF8, 0x25, 0x0A, 0x01
    ],
    [
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    ]
)];

/// Optional activation choices resolved during allocator preflight.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllocatorPatchPlan {
    /// Hook the first GameHeap realloc entry in addition to the required second
    /// entry. Another allocator may already own the first entry. Ghidra shows
    /// the vanilla body delegates to the required msize, allocate, free, and
    /// CRT realloc hooks, so leaving that body in place is still coherent.
    pub hook_gheap_realloc_1: bool,
}

/// Validate every required runtime modification before reserving allocator VAS.
///
/// Inline targets are decoded later while their trampolines are constructed;
/// this pass owns raw-patch policy and optional-provider detection.
pub fn preflight(mode: AllocatorMode) -> anyhow::Result<AllocatorPatchPlan> {
    if mode == AllocatorMode::Disabled {
        return Ok(AllocatorPatchPlan::default());
    }
    verify_scrap_tls_accessor()?;
    verify_patches(SHEAP_PATCHES)?;

    let mut plan = AllocatorPatchPlan::default();
    if mode == AllocatorMode::GheapAndScrapHeap {
        verify_patches(GHEAP_PATCHES)?;
        plan.hook_gheap_realloc_1 = optional_realloc_1_is_available();
    }
    log::info!(
        "[MEMORY] Allocator patch manifest accepted ({})",
        mode.name()
    );
    Ok(plan)
}

fn optional_realloc_1_is_available() -> bool {
    // Realloc entry 1 has real callers, but does not own allocation policy. Its
    // vanilla body is a composition of the msize/alloc/free/CRT realloc entries
    // that remain mandatory below our activation surface. A pre-existing entry
    // hook can therefore remain in front without forcing all of gheap off.
    match GAME_HEAP_REALLOC_1.verify() {
        Ok(()) => return true,
        Err(error) => {
            let owner = REALLOC_1_JUMP_OFFSETS.into_iter().find_map(|offset| {
                GAME_HEAP_REALLOC_1
                    .direct_jump_target(offset)
                    .ok()
                    .flatten()
                    .and_then(module_address)
            });
            log::warn!(
                "[GHEAP] Optional realloc entry 1 is unavailable: {}. Existing jump owner: {}. Skipping this hook and continuing with realloc entry 2",
                error,
                owner.as_deref().unwrap_or("not detected"),
            );
        }
    }
    false
}

fn verify_scrap_tls_accessor() -> anyhow::Result<()> {
    let site = &SCRAP_TLS_ACCESSOR;
    if site.verify().is_ok() {
        return Ok(());
    }

    let Some(target) = site.direct_jump_target(0)? else {
        return Err(anyhow::anyhow!(
            "{} at 0x{:08X} is neither the vanilla provider nor a direct replacement jump",
            site.name(),
            site.address(),
        ));
    };
    validate_memory_access(target as *mut c_void)?;
    let owner = module_address(target).unwrap_or_else(|| format!("0x{target:08X}"));
    // Chaining through an existing provider is unsafe here. Providers such as
    // Stewie's depend on initialization that gheap deliberately suppresses;
    // calling that trampoline later crashed in its null thread-heap map. A
    // direct entry JMP is a complete, recognizable boundary that Psycho can
    // replace without invoking or depending on the previous implementation.
    log::info!(
        "[MEMORY] {} already has a provider ({owner}); Psycho will replace it without constructing a trampoline",
        site.name(),
    );
    Ok(())
}

fn verify_patches(patches: &[OwnedCodePatch]) -> anyhow::Result<()> {
    for patch in patches {
        patch.verify()?;
    }
    Ok(())
}
