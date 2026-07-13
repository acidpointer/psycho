//! Verified modifications of executable process memory.
//!
//! Native extensions often need to replace a small, fixed sequence of code.
//! This module keeps that operation explicit: a signature proves which bytes
//! are present, while an [`OwnedCodePatch`] records the accepted instruction
//! shape and its replacement. Applying a patch returns an [`AppliedCodePatch`]
//! that remembers the exact displaced bytes for ownership-aware restoration.
//!
//! Code writes are not atomic. Callers must patch at a startup boundary or
//! otherwise keep every affected instruction quiescent.

use core::ffi::c_void;

use thiserror::Error;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use super::{
    memory::{MemoryError, read_bytes, validate_memory_range},
    winapi::{
        HModule, WinapiError, flush_instructions_cache, get_module_base_name, virtual_query,
        with_virtual_protect,
    },
};

/// Result type used by verified code-patch operations.
pub type CodePatchResult<T> = Result<T, CodePatchError>;

/// Failure to validate, own, write, or restore a code patch.
#[derive(Debug, Error)]
pub enum CodePatchError {
    #[error(
        "invalid patch '{name}': original is {original_len} bytes, replacement is {replacement_len} bytes"
    )]
    SizeMismatch {
        name: &'static str,
        original_len: usize,
        replacement_len: usize,
    },

    #[error(
        "invalid mask for patch '{name}': pattern is {pattern_len} bytes, mask is {mask_len} bytes"
    )]
    MaskSizeMismatch {
        name: &'static str,
        pattern_len: usize,
        mask_len: usize,
    },

    #[error("{name} at 0x{address:08X}: expected {expected:02X?}, found {observed:02X?}")]
    SignatureMismatch {
        name: &'static str,
        address: usize,
        expected: Vec<u8>,
        observed: Vec<u8>,
    },

    #[error(
        "{name} at 0x{address:08X}: expected pattern {pattern:02X?} with mask {mask:02X?}, found {observed:02X?}"
    )]
    PatternMismatch {
        name: &'static str,
        address: usize,
        pattern: Vec<u8>,
        mask: Vec<u8>,
        observed: Vec<u8>,
    },

    #[error(
        "lost ownership of patch '{name}' at 0x{address:08X}: expected {expected:02X?}, found {observed:02X?}"
    )]
    OwnershipLost {
        name: &'static str,
        address: usize,
        expected: Vec<u8>,
        observed: Vec<u8>,
    },

    #[error("write verification failed for patch '{name}' at 0x{address:08X}")]
    WriteVerificationFailed { name: &'static str, address: usize },

    #[error(transparent)]
    Memory(#[from] MemoryError),

    #[error(transparent)]
    Winapi(#[from] WinapiError),
}

/// A named byte sequence expected at one process address.
///
/// Signatures are intentionally exact. Selecting compatible versions or
/// accepting an existing hook is policy owned by the caller, not this type.
#[derive(Clone, Copy, Debug)]
pub struct CodeSignature {
    name: &'static str,
    address: usize,
    expected: &'static [u8],
}

impl CodeSignature {
    /// Describe one exact byte signature at a process address.
    pub const fn new(name: &'static str, address: usize, expected: &'static [u8]) -> Self {
        Self {
            name,
            address,
            expected,
        }
    }

    /// Human-readable patch-site name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Process address where the signature begins.
    pub const fn address(self) -> usize {
        self.address
    }

    /// Exact bytes expected by this signature.
    pub const fn expected(self) -> &'static [u8] {
        self.expected
    }

    /// Read the signature-sized byte range from the process.
    pub fn read(self) -> CodePatchResult<Vec<u8>> {
        read_bytes(self.address as *const c_void, self.expected.len()).map_err(Into::into)
    }

    /// Require the exact signature bytes to be present.
    pub fn verify(self) -> CodePatchResult<()> {
        let observed = self.read()?;
        if observed == self.expected {
            return Ok(());
        }

        Err(CodePatchError::SignatureMismatch {
            name: self.name,
            address: self.address,
            expected: self.expected.to_vec(),
            observed,
        })
    }

    /// Resolves an `E9 rel32` found at `offset` in the observed bytes.
    ///
    /// This is useful for diagnostics and for caller-defined compatibility
    /// policies. It does not imply that replacing the jump is safe.
    pub fn direct_jump_target(self, offset: usize) -> CodePatchResult<Option<usize>> {
        let observed = self.read()?;
        let Some(bytes) = observed.get(offset..) else {
            return Ok(None);
        };
        let [0xE9, displacement @ ..] = bytes else {
            return Ok(None);
        };
        let Some([byte_0, byte_1, byte_2, byte_3]) = displacement.get(..4) else {
            return Ok(None);
        };
        let displacement = i32::from_le_bytes([*byte_0, *byte_1, *byte_2, *byte_3]);
        let instruction = self.address.wrapping_add(offset);
        Ok(Some(
            instruction
                .wrapping_add(5)
                .wrapping_add_signed(displacement as isize),
        ))
    }
}

/// A size-preserving code patch with ownership-aware restoration.
#[derive(Clone, Copy, Debug)]
pub struct OwnedCodePatch {
    original: CodeSignature,
    mask: &'static [u8],
    replacement: &'static [u8],
}

impl OwnedCodePatch {
    /// Create a size-preserving patch with an exact original signature.
    pub const fn new(
        name: &'static str,
        address: usize,
        original: &'static [u8],
        replacement: &'static [u8],
    ) -> Self {
        Self {
            original: CodeSignature::new(name, address, original),
            mask: &[],
            replacement,
        }
    }

    /// Creates a patch whose original bytes are compared through a bit mask.
    ///
    /// A set mask bit is significant. For example, the mask
    /// `[0xFF, 0, 0, 0, 0]` accepts any five-byte sequence beginning with the
    /// expected opcode. The exact accepted bytes are captured when the patch
    /// is applied and are used for rollback.
    pub const fn masked(
        name: &'static str,
        address: usize,
        original: &'static [u8],
        mask: &'static [u8],
        replacement: &'static [u8],
    ) -> Self {
        Self {
            original: CodeSignature::new(name, address, original),
            mask,
            replacement,
        }
    }

    /// Human-readable patch-site name.
    pub const fn name(self) -> &'static str {
        self.original.name()
    }

    /// Process address where the patch begins.
    pub const fn address(self) -> usize {
        self.original.address()
    }

    /// Accept either the configured original pattern or the replacement.
    ///
    /// Accepting an existing replacement makes preflight idempotent without
    /// claiming rollback ownership of another component's write.
    pub fn verify(self) -> CodePatchResult<()> {
        self.validate_lengths()?;
        let observed = self.original.read()?;
        self.accept_original_or_replacement(&observed)
    }

    /// Applies the replacement and captures the exact displaced bytes.
    ///
    /// If the replacement is already present, no write is performed and
    /// `None` is returned. This prevents one component from claiming rollback
    /// ownership of an equivalent patch installed by another component.
    pub fn apply(self) -> CodePatchResult<Option<AppliedCodePatch>> {
        self.validate_lengths()?;
        let observed = self.original.read()?;
        if observed == self.replacement {
            return Ok(None);
        }
        self.accept_original(&observed)?;

        let applied = AppliedCodePatch {
            name: self.name(),
            address: self.address(),
            original: observed,
            replacement: self.replacement,
        };
        if let Err(error) = write_if_equal(
            applied.name,
            applied.address,
            &applied.original,
            applied.replacement,
        ) {
            if let Err(rollback_error) = applied.restore_if_owned() {
                log::error!(
                    "Code-patch write failed and immediate rollback also failed: {}",
                    rollback_error
                );
            }
            return Err(error);
        }
        Ok(Some(applied))
    }

    fn validate_lengths(self) -> CodePatchResult<()> {
        if self.original.expected().len() == self.replacement.len() {
            if self.mask.is_empty() || self.mask.len() == self.original.expected().len() {
                return Ok(());
            }
            return Err(CodePatchError::MaskSizeMismatch {
                name: self.name(),
                pattern_len: self.original.expected().len(),
                mask_len: self.mask.len(),
            });
        }
        Err(CodePatchError::SizeMismatch {
            name: self.name(),
            original_len: self.original.expected().len(),
            replacement_len: self.replacement.len(),
        })
    }

    fn accept_original_or_replacement(self, observed: &[u8]) -> CodePatchResult<()> {
        if observed == self.replacement {
            return Ok(());
        }
        self.accept_original(observed)
    }

    fn accept_original(self, observed: &[u8]) -> CodePatchResult<()> {
        if self.mask.is_empty() {
            if observed == self.original.expected() {
                return Ok(());
            }
            return Err(CodePatchError::SignatureMismatch {
                name: self.name(),
                address: self.address(),
                expected: self.original.expected().to_vec(),
                observed: observed.to_vec(),
            });
        }

        let matches = observed
            .iter()
            .zip(self.original.expected())
            .zip(self.mask)
            .all(|((&observed, &expected), &mask)| observed & mask == expected & mask);
        if matches {
            Ok(())
        } else {
            Err(CodePatchError::PatternMismatch {
                name: self.name(),
                address: self.address(),
                pattern: self.original.expected().to_vec(),
                mask: self.mask.to_vec(),
                observed: observed.to_vec(),
            })
        }
    }
}

/// A successful code-patch write and the exact bytes it displaced.
pub struct AppliedCodePatch {
    name: &'static str,
    address: usize,
    original: Vec<u8>,
    replacement: &'static [u8],
}

impl AppliedCodePatch {
    /// Restores the displaced bytes if the replacement is still present.
    pub fn restore(self) -> CodePatchResult<()> {
        self.restore_if_owned()
    }

    fn restore_if_owned(&self) -> CodePatchResult<()> {
        let observed = read_bytes(self.address as *const c_void, self.replacement.len())?;
        if observed == self.original {
            return Ok(());
        }
        if observed != self.replacement {
            return Err(CodePatchError::OwnershipLost {
                name: self.name,
                address: self.address,
                expected: self.replacement.to_vec(),
                observed,
            });
        }
        write_if_equal(self.name, self.address, self.replacement, &self.original)
    }
}

fn write_if_equal(
    name: &'static str,
    address: usize,
    expected: &[u8],
    replacement: &[u8],
) -> CodePatchResult<()> {
    let observed = read_bytes(address as *const c_void, expected.len())?;
    if observed != expected {
        return Err(CodePatchError::OwnershipLost {
            name,
            address,
            expected: expected.to_vec(),
            observed,
        });
    }

    validate_memory_range(address as *const c_void, replacement.len())?;
    unsafe {
        with_virtual_protect(
            address as *mut c_void,
            PAGE_EXECUTE_READWRITE,
            replacement.len(),
            || {
                core::ptr::copy_nonoverlapping(
                    replacement.as_ptr(),
                    address as *mut u8,
                    replacement.len(),
                );
            },
        )?;
    }
    flush_instructions_cache(address as *mut c_void, replacement.len())?;

    if read_bytes(address as *const c_void, replacement.len())? != replacement {
        return Err(CodePatchError::WriteVerificationFailed { name, address });
    }
    Ok(())
}

/// Returns a stable module-and-address label for committed module memory.
pub fn module_address(address: usize) -> Option<String> {
    let info = virtual_query(address as *mut c_void).ok()?;
    let module = unsafe { HModule::new(info.allocation_base).ok()? };
    let name = get_module_base_name(module).ok()?;
    Some(format!("{name}!0x{address:08X}"))
}
