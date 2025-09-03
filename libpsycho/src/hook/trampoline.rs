use std::{ffi::c_void, ptr::NonNull};

use crate::winapi::{
    read_bytes, virtual_protect_execute_readwrite, virtual_protect_restore, write_bytes,
};

use super::*;

/// Trampoline: Fixed memory allocation made executable with absolute jumps
pub struct Trampoline {
    /// Fixed allocation, won't move
    buffer: Box<[u8]>,
    /// Old protect for virtual_protect_restore
    old_protect: u32,
}

impl Trampoline {
    pub fn new(original_addr: NonNull<c_void>) -> Result<(Self, usize)> {
        log::debug!(
            "[Trampoline] Creating trampoline for: {:p}",
            original_addr.as_ptr()
        );

        // Calculate safe patch size (minimum 14 bytes for absolute jump)
        let patch_bytes = calculate_safe_patch_size(original_addr, MIN_PATCH_SIZE)?;
        let trampoline_size = patch_bytes + ABS_JMP_SIZE;

        log::debug!(
            "[Trampoline] Size: {trampoline_size} bytes (patch: {patch_bytes}, abs_jmp: {ABS_JMP_SIZE})"
        );

        // Fixed-size allocation that won't move
        let mut buffer = vec![0u8; trampoline_size].into_boxed_slice();

        // Make executable
        let old_protect = virtual_protect_execute_readwrite(
            buffer.as_mut_ptr() as *mut c_void,
            Some(trampoline_size),
        )?;

        log::debug!(
            "[Trampoline] Buffer at {:p} made executable",
            buffer.as_ptr()
        );

        let buffer_ptr = NonNull::new(buffer.as_mut_ptr() as *mut c_void)
            .ok_or_else(|| HookError::NullPointerError("Buffer pointer is null".into()))?;

        // Copy original bytes
        let original_bytes = read_bytes(original_addr, patch_bytes)?;
        write_bytes(buffer_ptr, &original_bytes)?;

        // Create absolute jump back to original function
        let return_addr = original_addr.as_ptr() as usize + patch_bytes;
        let jmp_location = buffer.as_ptr() as usize + patch_bytes;

        log::debug!(
            "[Trampoline] Creating absolute jump from {:p} to {:p}",
            jmp_location as *const c_void,
            return_addr as *const c_void
        );

        let abs_jmp_bytes = create_absolute_jump(return_addr);

        // Write absolute jump at end of trampoline
        let jmp_ptr = NonNull::new((buffer.as_ptr() as usize + patch_bytes) as *mut c_void)
            .ok_or_else(|| HookError::NullPointerError("Jump location is null".into()))?;

        write_bytes(jmp_ptr, &abs_jmp_bytes)?;

        log::debug!("[Trampoline] Successfully created at {:p}", buffer.as_ptr());

        Ok((
            Self {
                buffer,
                old_protect,
            },
            patch_bytes,
        ))
    }

    pub fn get_buffer_ref(&self) -> &[u8] {
        &self.buffer
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.buffer.as_ptr() as *mut c_void
    }
}

impl Drop for Trampoline {
    fn drop(&mut self) {
        let _ = virtual_protect_restore(
            self.buffer.as_mut_ptr() as *mut c_void,
            self.old_protect,
            Some(self.buffer.len()),
        );
    }
}
