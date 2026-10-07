//! Exact native-code admission shared by the two unreleased lighting candidates.
//!
//! Signatures are bounded extracts of FNV 1.4.0.525 or explicitly verified math
//! leaves with their native tails, never an arbitrary observed provider.
//! Preparation runs only at the pre-CRT barrier;
//! replacement expectations are published before any bridge is enabled and
//! retained for process lifetime. Hot checks use integer volatile reads, with
//! no allocation, locks, WinAPI calls, or logging. A matching signature does
//! not synchronize concurrent code writers or establish engine object lifetime.
//! Those unresolved candidate conditions are recorded in the owning audit.

use std::sync::OnceLock;

use anyhow::{Result, bail, ensure};
use libpsycho::os::windows::patch::CodeSignature;

/// One exact native range with an owned overlay or a verified math alternative.
pub(super) struct NativeRange {
    signature: CodeSignature,
    installed: OnceLock<Box<[u8]>>,
    alternative: Option<&'static [u8]>,
}

impl NativeRange {
    /// Describe immutable native bytes at a verified fixed executable address.
    pub(super) const fn new(name: &'static str, address: usize, bytes: &'static [u8]) -> Self {
        Self {
            signature: CodeSignature::new(name, address, bytes),
            installed: OnceLock::new(),
            alternative: None,
        }
    }

    /// Admit one independently verified, complete math range as well as vanilla.
    /// Preparation rejects a length mismatch or combining it with owned overlays.
    /// Both immutable alternatives remain available after preparation; no live
    /// bytes are learned and the caller's installed arithmetic is never replaced.
    pub(super) const fn with_alternative(mut self, bytes: &'static [u8]) -> Self {
        self.alternative = Some(bytes);
        self
    }

    /// Relocate the same production contract to an owned test code mapping.
    /// Only the address changes; admission still executes the shipped checker.
    #[cfg(test)]
    pub(super) fn relocated(&self, address: usize) -> Self {
        let mut range = Self::new(self.signature.name(), address, self.signature.expected());
        range.alternative = self.alternative;
        range
    }

    /// Validate mapped supported bytes and prepare only explicitly owned overlays.
    /// Failure precedes executable-memory mutation; storage lives until exit.
    pub(super) fn prepare(&self, overlays: &[(usize, &[u8])]) -> Result<()> {
        if let Some(alternative) = self.alternative {
            ensure!(
                alternative.len() == self.signature.expected().len(),
                "math alternative length mismatch"
            );
            ensure!(overlays.is_empty(), "math alternative cannot own overlays");
            self.diagnose()?;
        } else {
            self.signature.verify()?;
        }
        if overlays.is_empty() {
            return Ok(());
        }
        let mut installed = self.signature.expected().to_vec();
        for &(address, bytes) in overlays {
            let offset = address
                .checked_sub(self.signature.address())
                .ok_or_else(|| anyhow::anyhow!("overlay precedes native range"))?;
            let end = offset
                .checked_add(bytes.len())
                .ok_or_else(|| anyhow::anyhow!("overlay size overflow"))?;
            let Some(destination) = installed.get_mut(offset..end) else {
                bail!("overlay exceeds native range");
            };
            destination.copy_from_slice(bytes);
        }
        ensure!(
            self.installed.set(installed.into_boxed_slice()).is_ok(),
            "lighting range already prepared"
        );
        Ok(())
    }

    /// Explain the first mismatch when no complete supported expectation matches.
    /// Only cold preparation or rejection reporting may call this: it validates
    /// and allocates a read buffer. A successful read describes this snapshot, not an earlier
    /// rejection or synchronization with a concurrent executable-code writer.
    pub(super) fn diagnose(&self) -> Result<()> {
        let observed = self.signature.read()?;
        let expected = self
            .installed
            .get()
            .map_or(self.signature.expected(), |bytes| bytes.as_ref());
        if observed == expected || self.alternative.is_some_and(|bytes| observed == bytes) {
            return Ok(());
        }
        // Prefer the alternative for a recognizably inlined but unsupported
        // body so a tail or later instruction mismatch is reported directly.
        // This selection affects diagnostics only; admission compares all bytes.
        let expected = self
            .alternative
            .filter(|bytes| bytes.first() == observed.first())
            .unwrap_or(expected);
        if let Some((offset, (&expected, &observed))) = expected
            .iter()
            .zip(&observed)
            .enumerate()
            .find(|(_, (expected, observed))| expected != observed)
        {
            bail!(
                "{} at 0x{:08X}: expected {:02X}, observed {:02X}",
                self.signature.name(),
                self.signature.address() + offset,
                expected,
                observed
            );
        }
        Ok(())
    }

    /// Compare complete contract bytes without inspecting provider modules.
    ///
    /// # Safety
    /// Preparation must have validated this fixed executable range. FNV's
    /// executable mapping must remain present for process lifetime. Volatile
    /// reads detect replacement but cannot make concurrent code mutation safe.
    #[inline]
    pub(super) unsafe fn matches(&self) -> bool {
        let expected = self
            .installed
            .get()
            .map_or(self.signature.expected(), |b| b.as_ref());
        // A later PostPostLoad math replacement can be supported even when
        // preparation saw vanilla. Never capture the first observed body as
        // the sole expectation or erase a traversal's existing rejection.
        (unsafe { self.matches_expected(expected) })
            || self
                .alternative
                .is_some_and(|bytes| unsafe { self.matches_expected(bytes) })
    }

    // Safety: matches' mapped-lifetime contract applies to the entire expected
    // slice. Preparation proves that an alternative has the same guarded extent.
    #[inline]
    unsafe fn matches_expected(&self, expected: &[u8]) -> bool {
        let address = self.signature.address();
        let mut offset = 0;
        // Align live DWORD reads without assuming the range's starting alignment.
        while offset < expected.len() && (address + offset) & 3 != 0 {
            if unsafe { ((address + offset) as *const u8).read_volatile() } != expected[offset] {
                return false;
            }
            offset += 1;
        }
        while offset + 4 <= expected.len() {
            let value = u32::from_le_bytes([
                expected[offset],
                expected[offset + 1],
                expected[offset + 2],
                expected[offset + 3],
            ]);
            if unsafe { ((address + offset) as *const u32).read_volatile() } != value {
                return false;
            }
            offset += 4;
        }
        while offset < expected.len() {
            if unsafe { ((address + offset) as *const u8).read_volatile() } != expected[offset] {
                return false;
            }
            offset += 1;
        }
        true
    }
}

/// Encode a CALL/JMP in x86's modular 32-bit rel32 address space.
/// Only setup uses this helper; callers provide instruction-aligned windows.
pub(super) fn branch(opcode: u8, site: usize, target: usize) -> [u8; 5] {
    let displacement = (target as u32).wrapping_sub((site as u32).wrapping_add(5));
    let [a, b, c, d] = displacement.to_le_bytes();
    [opcode, a, b, c, d]
}

/// Read an aligned native DWORD without creating a Rust reference to engine data.
///
/// # Safety
/// The native caller must own a mapped, initialized, DWORD-aligned field at
/// `base + offset` for this operation. This does not pin its owner or node.
#[inline]
pub(super) unsafe fn word(base: usize, offset: usize) -> u32 {
    unsafe { (base.wrapping_add(offset) as *const u32).read_volatile() }
}

macro_rules! native_range {
    ($name:ident, $address:expr, $file:literal) => {
        static $name: super::lighting_contract::NativeRange =
            super::lighting_contract::NativeRange::new(
                stringify!($name),
                $address,
                include_bytes!(concat!("lighting_signatures/", $file, ".bin")),
            );
    };
}
pub(super) use native_range;
