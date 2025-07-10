use std::{ffi::c_void, ptr::NonNull};

use parking_lot::Mutex;

use super::*;
use crate::winapi::{read_bytes, validate_memory_range, write_bytes};

/// A patchable memory region that can be enabled/disabled
pub struct MemoryPatch {
    address: NonNull<c_void>,
    original: Vec<u8>,
    patch: Vec<u8>,
    enabled: bool,
    lock: Mutex<()>,
}

impl MemoryPatch {
    /// Creates a new memory patch with custom bytes
    pub fn new(address: NonNull<c_void>, patch_bytes: Vec<u8>) -> Result<Self> {
        if patch_bytes.is_empty() {
            return Err(PatchError::InvalidSize);
        }

        let original = read_bytes(address, patch_bytes.len())?;

        // Ensure patch size matches original memory size
        if original.len() != patch_bytes.len() {
            return Err(PatchError::InvalidSize);
        }

        Ok(Self {
            address,
            original,
            patch: patch_bytes,
            enabled: false,
            lock: Mutex::new(()),
        })
    }

    /// Creates a NOP patch
    pub fn nop(address: NonNull<c_void>, size: usize) -> Result<Self> {
        if size == 0 {
            return Err(PatchError::InvalidSize);
        }

        Self::new(address, vec![0x90; size])
    }

    /// Creates a JMP patch
    pub fn jump(source: NonNull<c_void>, destination: NonNull<c_void>) -> Result<Self> {
        validate_branch_range(source, destination)?;
        let source_addr = source.as_ptr() as usize;
        let dest_addr = destination.as_ptr() as usize;

        // Calculate relative offset (destination - source - 5)
        let relative_offset = dest_addr.wrapping_sub(source_addr + 5) as i32;

        // Create jump instruction (E9 + 4-byte offset)
        let mut jump = [0xE9, 0, 0, 0, 0];
        jump[1..].copy_from_slice(&relative_offset.to_le_bytes());

        Self::new(source, jump.to_vec())
    }

    /// Creates a CALL patch
    pub fn call(source: NonNull<c_void>, destination: NonNull<c_void>) -> Result<Self> {
        validate_branch_range(source, destination)?;
        let source_addr = source.as_ptr() as usize;
        let dest_addr = destination.as_ptr() as usize;

        // Calculate relative offset (destination - source - 5)
        let relative_offset = dest_addr.wrapping_sub(source_addr + 5) as i32;

        // Create call instruction (E8 + 4-byte offset)
        let mut call = [0xE8, 0, 0, 0, 0];
        call[1..].copy_from_slice(&relative_offset.to_le_bytes());

        Self::new(source, call.to_vec())
    }

    /// Enables the patch
    pub fn enable(&mut self) -> Result<()> {
        let _guard = self.lock.lock();

        if self.enabled {
            return Err(PatchError::AlreadyApplied);
        }

        validate_memory_range(self.address, self.patch.len())?;
        write_bytes(self.address, &self.patch)?;

        // We need to be REALLY SURE
        // that patch was applied
        if self.is_patch_applied()? {
            self.enabled = true;

            Ok(())
        } else {
            Err(PatchError::NotApplied)
        }
    }

    /// Disables the patch
    pub fn disable(&mut self) -> Result<()> {
        let _guard = self.lock.lock();

        if !self.enabled {
            return Err(PatchError::NotApplied);
        }

        // We want to be sure that patch TRULLY enabled
        // It means, we want to protect ourself from runtime memory changes
        // For example, if other plugin also do similar patch, we should error here
        // Thus we work only with memory, modified by us
        if self.is_patch_applied()? {
            validate_memory_range(self.address, self.original.len())?;
            write_bytes(self.address, &self.original)?;
            self.enabled = false;
            Ok(())
        } else {
            Err(PatchError::NotApplied)
        }
    }

    pub fn is_patch_applied(&self) -> Result<bool> {
        let current = read_bytes(self.address, self.patch.len())?;
        Ok(current == self.patch)
    }

    /// Checks if the patch is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Gets the patch address
    pub fn address(&self) -> NonNull<c_void> {
        self.address
    }

    /// Gets original bytes
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Gets patch bytes
    pub fn patch_bytes(&self) -> &[u8] {
        &self.patch
    }
}
