//! Owned LOD callsite and event-splice patches at the quiescent startup boundary.
//!
//! Each static site keeps its replacement bytes alive for transactional rollback.
//! Calls capture the installed executable provider; splices require exact bytes
//! and replay their displaced instructions in an audited naked bridge. No site
//! allocates or changes ownership after preparation. This is local patch storage,
//! not an engine dispatch or compatibility layer.

use super::super::patching;
use anyhow::{Context, ensure};
use libpsycho::os::windows::{hook::transaction::ModificationTransaction, patch::OwnedCodePatch};
use std::{
    ffi::c_void,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(super) struct Site {
    name: &'static str,
    address: usize,
    original: &'static [u8],
    call: bool,
    replacement: OnceLock<Vec<u8>>,
    patch: OnceLock<OwnedCodePatch>,
    provider: AtomicUsize,
}

impl Site {
    /// Define an exact event splice or a provider-preserving E8 callsite.
    pub(super) const fn new(
        name: &'static str,
        address: usize,
        original: &'static [u8],
        call: bool,
    ) -> Self {
        Self {
            name,
            address,
            original,
            call,
            replacement: OnceLock::new(),
            patch: OnceLock::new(),
            provider: AtomicUsize::new(0),
        }
    }

    /// Prepare and apply this site under the caller's rollback transaction.
    pub(super) fn install(
        &'static self,
        transaction: &mut ModificationTransaction,
        entry: usize,
    ) -> anyhow::Result<()> {
        ensure!(self.original.len() >= 5, "short LOD splice");
        if self.call {
            let target =
                unsafe { patching::relative_call_target(self.address) }.context(self.name)?;
            ensure!(
                target != entry && super::is_executable(target),
                "invalid {} provider",
                self.name
            );
            self.provider.store(target, Ordering::Release);
        }
        let bytes = self.replacement.get_or_init(|| {
            let mut bytes = vec![0x90; self.original.len()];
            bytes[0] = if self.call { 0xE8 } else { 0xE9 };
            bytes[1..5]
                .copy_from_slice(&(entry.wrapping_sub(self.address + 5) as i32).to_le_bytes());
            bytes
        });
        let patch = self.patch.get_or_init(|| {
            if self.call {
                OwnedCodePatch::masked(
                    self.name,
                    self.address,
                    self.original,
                    &[0xFF, 0, 0, 0, 0],
                    bytes,
                )
            } else {
                OwnedCodePatch::new(self.name, self.address, self.original, bytes)
            }
        });
        transaction.apply_patch(patch)?;
        Ok(())
    }

    /// Return the provider captured before activation. Only installed sites call it.
    pub(super) fn provider(&self) -> usize {
        self.provider.load(Ordering::Acquire)
    }
}

/// Read a live native object's unaligned word at a binary-proven offset.
///
/// Safety: the caller proves this range is initialized and live for the read.
pub(super) unsafe fn word(base: usize, offset: isize) -> usize {
    unsafe { (base.wrapping_add_signed(offset) as *const usize).read_unaligned() }
}

/// Forward a captured native thiscall void/no-argument provider once.
///
/// Safety: the site and object must satisfy that exact native ABI/lifetime.
pub(super) unsafe fn call_owner(site: &Site, owner: *mut c_void) {
    let function = unsafe { libpsycho::ffi::fnptr::FnPtr::<unsafe extern "thiscall" fn(*mut c_void)>::from_address_unchecked(site.provider()) }.as_fn();
    unsafe { function(owner) };
}

/// Extract the immutable trampoline from an already activated LOD detour.
///
/// Safety: only that container's enabled detour may call this helper. Init
/// publishes its OnceLock before enable can succeed and never clears it. The
/// static container and trampoline live for the process; no missing-provider
/// recovery is possible or needed on this admitted path.
#[inline]
pub(super) unsafe fn original<F: libpsycho::ffi::fnptr::Function>(
    hook: &libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer<F>,
) -> F {
    // Safety: InlineHookContainer::init publishes original before publishing
    // the hook; enable rejects an uninitialized hook, and OnceLock is immutable.
    unsafe { hook.original().unwrap_unchecked() }
}
