//! Branch-aware retirement cleanup for the cell render-phase list.
//!
//! # Native ownership failure
//!
//! `TESObjectCELL::AddReference` (`0x00548230`) can add a borrowed
//! `TESObjectREFR*` to `CellRenderData + 0x4C`. Final removal in
//! `TESObjectCELL::RemoveReference` (`0x0054CA90`) re-evaluates mutable state and
//! skips `TESObjectCELL::RemoveRenderReference` (`0x00545590`) when that state is
//! false. A reference that changed state after insertion can therefore be
//! destroyed while the live cell list still contains its address.
//!
//! The phase consumer at `0x0054C740` treats every list payload as live. Its
//! `Get3D` call is followed by deeper reference work even when no scene node is
//! returned, so a downstream NULL or readability guard would only propagate
//! the invalid lifetime. The safe intervention point is the owner that must end
//! list membership before reference destruction continues.
//!
//! # Branch-aware intervention
//!
//! The seven-byte predicate-result block at `0x0054CB94` normally branches over
//! a direct removal call when the predicate is false. Psycho replaces that block
//! with a call to [`predicate_result_dispatch`]. The dispatcher reproduces the
//! displaced `movzx` and `test`, then selects one of two native continuations:
//!
//! - true returns through two padding bytes to the existing direct call at
//!   `0x0054CBA2` without changing its target;
//! - false invokes the canonical native remover once and adjusts the dispatch
//!   return address to resume at `0x0054CBA7`, after the existing call.
//!
//! Keeping the existing direct call untouched is the compatibility boundary.
//! A mod that owned that call before Psycho still receives exactly the inputs it
//! received under the original branch. The newly repaired false path enters the
//! executable's ABI-proven canonical helper address, so a normal entry hook on
//! that helper remains part of the engine-wide call chain.
//!
//! # Safety, cost, and diagnostics
//!
//! Installation occurs at Syringe's quiescent pre-CRT boundary. A native branch
//! receives one exact-fingerprint patch; a pre-existing NOP provider is kept
//! intact because it already supplies unconditional cleanup. There is no
//! multi-site transaction or live predecessor state to roll back. Psycho's
//! false path runs at the original native
//! retirement point, on the same thread and outside `CellRefLock`, matching the
//! executable's other render-list mutation callsites. The retiring reference is
//! passed only as an opaque comparison key; Psycho never dereferences or frees
//! it and never manipulates a list node directly.
//!
//! Each formerly skipped retirement adds one native linear list search, which
//! is the minimum work required without maintaining a second membership index.
//! There is no duplicate verification pass, allocation, lock, form lookup, or
//! routine logging. Dashboard sampling re-reads the active provider bytes so a
//! later non-chaining overwrite clears the feature bit and records one
//! ownership-loss event instead of reporting stale installation state.

use std::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};

use anyhow::{Context, ensure};
use libpsycho::{ffi::fnptr::FnPtr, os::windows::winapi::virtual_query};

use super::patching;

const GLOBAL_OVERRIDE_BRANCH_ADDR: usize = 0x0054_CB8A;
const GLOBAL_OVERRIDE_BRANCH: [u8; 2] = [0x75, 0x0F];
const PREDICATE_ARGUMENT_ADDR: usize = 0x0054_CB8C;
const PREDICATE_ARGUMENT: [u8; 3] = [0x8B, 0x4D, 0x08];
const PREDICATE_CALL_ADDR: usize = 0x0054_CB8F;

const PREDICATE_RESULT_BLOCK_ADDR: usize = 0x0054_CB94;
const NATIVE_PREDICATE_RESULT_BLOCK: [u8; 7] = [0x0F, 0xB6, 0xD0, 0x85, 0xD2, 0x74, 0x0C];
const LEGACY_FORCED_RESULT_BLOCK: [u8; 7] = [0x0F, 0xB6, 0xD0, 0x85, 0xD2, 0x90, 0x90];
const DISPATCH_RETURN_ADDR: usize = PREDICATE_RESULT_BLOCK_ADDR + 5;

const EXISTING_OWNER_PATH_ADDR: usize = 0x0054_CB9B;
const EXISTING_OWNER_PREFIX: [u8; 7] = [0x8B, 0x45, 0x08, 0x50, 0x8B, 0x4D, 0xE4];
const EXISTING_OWNER_CALL_ADDR: usize = 0x0054_CBA2;
const SKIPPED_PATH_CONTINUE_ADDR: usize = 0x0054_CBA7;
const SKIPPED_PATH_SUFFIX: [u8; 3] = [0x8B, 0x4D, 0x08];
const SKIPPED_RETURN_DELTA: usize = SKIPPED_PATH_CONTINUE_ADDR - DISPATCH_RETURN_ADDR;

const NATIVE_REMOVE_RENDER_REFERENCE_ADDR: usize = 0x0054_5590;

type RemoveRenderReferenceFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

static ACTIVE_MODE: AtomicU8 = AtomicU8::new(ActiveMode::Inactive as u8);
static FORCED_CLEANUPS: AtomicU64 = AtomicU64::new(0);
static OWNERSHIP_LOSS_RECORDED: AtomicBool = AtomicBool::new(false);

const _: () = assert!(DISPATCH_RETURN_ADDR + 2 == EXISTING_OWNER_PATH_ADDR);
const _: () = assert!(DISPATCH_RETURN_ADDR + SKIPPED_RETURN_DELTA == SKIPPED_PATH_CONTINUE_ADDR);

/// Live capability state and cumulative branch-dispatch diagnostics.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DashboardSnapshot {
    /// Whether Psycho or a pre-existing forced-cleanup provider remains active.
    pub installed: bool,
    /// False-predicate retirements dispatched through the native remover.
    pub forced_cleanups: u64,
    /// Whether a later writer replaced the active provider block after install.
    pub patch_ownership_losses: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PatchState {
    Native,
    LegacyForced,
    Installed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ActiveMode {
    Inactive = 0,
    PsychoDispatch = 1,
    ExternalForced = 2,
}

/// Install branch-aware cell render-list retirement cleanup.
///
/// The caller must run at the pre-CRT startup barrier while the native function
/// body is quiescent. Installation changes only the predicate-result block; it
/// deliberately preserves the current target of the existing direct cleanup
/// call so a compatible mod owner retains its original invocation domain.
pub(super) fn install() -> anyhow::Result<()> {
    let replacement = dispatch_patch();
    let active_mode = active_mode();
    if active_mode != ActiveMode::Inactive {
        ensure!(
            mode_is_active(active_mode, &replacement),
            "cell render retirement dispatch ownership was lost after installation"
        );
        return Ok(());
    }

    unsafe {
        patching::verify_bytes(GLOBAL_OVERRIDE_BRANCH_ADDR, &GLOBAL_OVERRIDE_BRANCH)?;
        patching::verify_bytes(PREDICATE_ARGUMENT_ADDR, &PREDICATE_ARGUMENT)?;
        patching::verify_bytes(EXISTING_OWNER_PATH_ADDR, &EXISTING_OWNER_PREFIX)?;
        patching::verify_bytes(SKIPPED_PATH_CONTINUE_ADDR, &SKIPPED_PATH_SUFFIX)?;
    }
    let predicate_owner = unsafe { patching::relative_call_target(PREDICATE_CALL_ADDR) }
        .context("inspect cell render retirement predicate owner")?;
    let cleanup_owner = unsafe { patching::relative_call_target(EXISTING_OWNER_CALL_ADDR) }
        .context("inspect cell render retirement cleanup owner")?;
    ensure!(
        is_executable(predicate_owner),
        "cell render predicate owner 0x{predicate_owner:08X} is not executable"
    );
    ensure!(
        is_executable(cleanup_owner),
        "cell render cleanup owner 0x{cleanup_owner:08X} is not executable"
    );

    let observed = read_patch_block();
    let state = classify_patch(observed, replacement).with_context(|| {
        format!("unsupported bytes at 0x{PREDICATE_RESULT_BLOCK_ADDR:08X}: {observed:02X?}")
    })?;
    let mode = match state {
        PatchState::Native => {
            let result = unsafe {
                patching::replace_block(PREDICATE_RESULT_BLOCK_ADDR, &observed, &replacement)
            };
            if let Err(error) = result {
                // patch_bytes can report failure while restoring page protection
                // after the complete instruction block is already visible. Because
                // this is a one-site transaction, byte ownership alone determines
                // whether installation completed; no secondary state needs rollback.
                if patch_is_owned(&replacement) {
                    log::warn!(
                        "[CELL_RENDER_RETIREMENT] Dispatch publication completed with a protection warning: {error:#}"
                    );
                } else {
                    return Err(error).context("publish cell render retirement dispatch");
                }
            }

            ActiveMode::PsychoDispatch
        }
        PatchState::Installed => ActiveMode::PsychoDispatch,
        PatchState::LegacyForced => {
            // An existing NOP provider has already made this exact cleanup call
            // unconditional. Replacing its branch would silently narrow any mod
            // call owner that was intentionally installed for both predicate
            // results. Preserve that complete capability instead of assigning
            // plugin-specific meaning or forcing Psycho into its call chain.
            ActiveMode::ExternalForced
        }
    };

    ACTIVE_MODE.store(mode as u8, Ordering::Release);
    log::info!(
        "[CELL_RENDER_RETIREMENT] Cleanup active block=0x{PREDICATE_RESULT_BLOCK_ADDR:08X} predicate=0x{predicate_owner:08X} cleanup_owner=0x{cleanup_owner:08X} previous={state:?} provider={mode:?}"
    );
    Ok(())
}

/// Capture live retirement-patch state and cumulative diagnostics.
///
/// The `installed` field reflects the current Psycho or pre-existing provider
/// bytes, not merely successful startup. A later non-chaining overwrite is
/// recorded once and makes the dashboard feature bit inactive; sampling never
/// attempts to repatch live code.
pub(super) fn dashboard_snapshot() -> DashboardSnapshot {
    let mode = active_mode();
    let installed = mode != ActiveMode::Inactive && mode_is_active(mode, &dispatch_patch());
    if mode != ActiveMode::Inactive
        && !installed
        && !OWNERSHIP_LOSS_RECORDED.swap(true, Ordering::AcqRel)
    {
        log::error!(
            "[CELL_RENDER_RETIREMENT] Dispatch ownership was replaced after installation; protection is no longer active"
        );
    }

    DashboardSnapshot {
        installed,
        forced_cleanups: FORCED_CLEANUPS.load(Ordering::Relaxed),
        patch_ownership_losses: u64::from(OWNERSHIP_LOSS_RECORDED.load(Ordering::Acquire)),
    }
}

// The displaced instructions materialize AL in EDX and branch on its truth
// value. Returning normally lands on two NOPs and then the unchanged existing
// owner path. On false, the dispatcher performs only the missing native cleanup
// and advances its own return address over that owner path. EBP is the proven
// TESObjectCELL::RemoveReference frame: [EBP+8] is the retiring reference and
// [EBP-0x1C] is the cell saved by the native owner.
#[unsafe(naked)]
unsafe extern "C" fn predicate_result_dispatch() {
    core::arch::naked_asm!(
        "movzx edx, al",
        "test edx, edx",
        "jnz 2f",
        "push dword ptr [ebp + 8]",
        "mov ecx, dword ptr [ebp - 0x1c]",
        "call {cleanup}",
        "add dword ptr [esp], {skip_delta}",
        "2:",
        "ret",
        cleanup = sym remove_skipped_render_reference,
        skip_delta = const SKIPPED_RETURN_DELTA,
    );
}

unsafe extern "thiscall" fn remove_skipped_render_reference(
    cell: *mut c_void,
    reference: *mut c_void,
) {
    let remove = unsafe {
        FnPtr::<RemoveRenderReferenceFn>::from_address_unchecked(
            NATIVE_REMOVE_RENDER_REFERENCE_ADDR,
        )
    }
    .as_fn();
    unsafe { remove(cell, reference) };
    FORCED_CLEANUPS.fetch_add(1, Ordering::Relaxed);
}

fn dispatch_patch() -> [u8; 7] {
    let target = predicate_result_dispatch as *const () as usize;
    let displacement = target.wrapping_sub(PREDICATE_RESULT_BLOCK_ADDR + 5) as i32;
    let mut replacement = [0x90; 7];
    replacement[0] = 0xE8;
    replacement[1..5].copy_from_slice(&displacement.to_le_bytes());
    replacement
}

fn read_patch_block() -> [u8; 7] {
    unsafe { ptr::read_unaligned(PREDICATE_RESULT_BLOCK_ADDR as *const [u8; 7]) }
}

fn patch_is_owned(expected: &[u8; 7]) -> bool {
    // Plugin patch writers are outside Rust's synchronization model. Volatile
    // byte reads prevent the compiler from caching executable contents across
    // dashboard samples; startup ordering ensures normal reads see a stable
    // block after all plugin installation has completed.
    expected.iter().enumerate().all(|(offset, expected)| {
        (unsafe { ptr::read_volatile((PREDICATE_RESULT_BLOCK_ADDR + offset) as *const u8) })
            == *expected
    })
}

fn active_mode() -> ActiveMode {
    match ACTIVE_MODE.load(Ordering::Acquire) {
        value if value == ActiveMode::PsychoDispatch as u8 => ActiveMode::PsychoDispatch,
        value if value == ActiveMode::ExternalForced as u8 => ActiveMode::ExternalForced,
        _ => ActiveMode::Inactive,
    }
}

fn mode_is_active(mode: ActiveMode, psycho_patch: &[u8; 7]) -> bool {
    match mode {
        ActiveMode::Inactive => false,
        ActiveMode::PsychoDispatch => patch_is_owned(psycho_patch),
        ActiveMode::ExternalForced => patch_is_owned(&LEGACY_FORCED_RESULT_BLOCK),
    }
}

fn is_executable(address: usize) -> bool {
    address >= 0x10000
        && virtual_query(address as *mut c_void).is_ok_and(|info| info.is_executable())
}

fn classify_patch(observed: [u8; 7], installed: [u8; 7]) -> anyhow::Result<PatchState> {
    match observed {
        NATIVE_PREDICATE_RESULT_BLOCK => Ok(PatchState::Native),
        LEGACY_FORCED_RESULT_BLOCK => Ok(PatchState::LegacyForced),
        _ if observed == installed => Ok(PatchState::Installed),
        _ => anyhow::bail!("unknown predicate-result block"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DISPATCH_RETURN_ADDR, EXISTING_OWNER_PATH_ADDR, LEGACY_FORCED_RESULT_BLOCK,
        NATIVE_PREDICATE_RESULT_BLOCK, PREDICATE_RESULT_BLOCK_ADDR, PatchState,
        SKIPPED_PATH_CONTINUE_ADDR, SKIPPED_RETURN_DELTA, classify_patch,
    };

    #[test]
    fn patch_classifier_accepts_only_supported_instruction_shapes() {
        let installed = direct_call_patch(PREDICATE_RESULT_BLOCK_ADDR, 0x1234_5678);

        assert_eq!(
            classify_patch(NATIVE_PREDICATE_RESULT_BLOCK, installed).unwrap(),
            PatchState::Native
        );
        assert_eq!(
            classify_patch(LEGACY_FORCED_RESULT_BLOCK, installed).unwrap(),
            PatchState::LegacyForced
        );
        assert_eq!(
            classify_patch(installed, installed).unwrap(),
            PatchState::Installed
        );
        assert!(classify_patch([0xCC; 7], installed).is_err());
    }

    #[test]
    fn dispatch_call_and_both_resume_addresses_are_exact() {
        let target = 0x1234_5678usize;
        let patch = direct_call_patch(PREDICATE_RESULT_BLOCK_ADDR, target);
        let displacement = i32::from_le_bytes(patch[1..5].try_into().unwrap());
        let decoded = (PREDICATE_RESULT_BLOCK_ADDR + 5).wrapping_add_signed(displacement as isize);

        assert_eq!(patch[0], 0xE8);
        assert_eq!(&patch[5..], &[0x90, 0x90]);
        assert_eq!(decoded, target);
        assert_eq!(DISPATCH_RETURN_ADDR + 2, EXISTING_OWNER_PATH_ADDR);
        assert_eq!(
            DISPATCH_RETURN_ADDR + SKIPPED_RETURN_DELTA,
            SKIPPED_PATH_CONTINUE_ADDR
        );
    }

    fn direct_call_patch(address: usize, target: usize) -> [u8; 7] {
        let displacement = target.wrapping_sub(address + 5) as i32;
        let mut patch = [0x90; 7];
        patch[0] = 0xE8;
        patch[1..5].copy_from_slice(&displacement.to_le_bytes());
        patch
    }
}
