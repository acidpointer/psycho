use libc::c_void;

use super::errors::InlineHookError;
use crate::ffi::MAX_JUMP_SIZE;
use crate::os::windows::hook::inline::InlineHookResult;
use crate::os::windows::memory::validate_memory_access;
use crate::os::windows::winapi::{FreeType, flush_instructions_cache, virtual_free};

use super::disasm::*;

/// Guard for safe memory allocation cleanup
struct AllocGuard {
    ptr: *mut c_void,
    should_free: bool,
}

impl AllocGuard {
    fn new(ptr: *mut c_void) -> Self {
        Self {
            ptr,
            should_free: true,
        }
    }

    fn release(mut self) -> *mut c_void {
        self.should_free = false;
        self.ptr
    }
}

impl Drop for AllocGuard {
    fn drop(&mut self) {
        if self.should_free {
            log::debug!("AllocGuard freeing memory at {:p}", self.ptr);

            if let Err(err) = unsafe { virtual_free(self.ptr, FreeType::Release) } {
                log::error!("Failed to free AllocGuard memory: {}", err);
            }
        }
    }
}

pub(super) struct Trampoline {
    ptr: *mut c_void,
    disasm: Disasm,
}

// Safety: Trampoline is Send itself, but pointee funcs may not, be carefull
unsafe impl Send for Trampoline {}

// Safety: Trampoline is Sync itself, but pointee funcs may not, be carefull
unsafe impl Sync for Trampoline {}

impl Trampoline {
    pub(super) fn new(target_ptr: *mut c_void, detour_ptr: *mut c_void) -> InlineHookResult<Self> {
        let (_, region_size) = validate_memory_access(target_ptr)?;

        let disasm = Disasm::from_memory_range(target_ptr, detour_ptr)?;

        let jump_size = disasm.get_jump_size();
        if region_size < jump_size {
            return Err(InlineHookError::FunctionTooSmall { size: region_size });
        }

        log::debug!(
            "Creating trampoline for {} stolen bytes",
            disasm.get_stolen_bytes_len(),
        );

        // Extra space: 16 bytes for alignment and safety padding
        let trampoline_size = disasm.get_stolen_bytes_len() + MAX_JUMP_SIZE + 16;

        // Try to allocate near target for better performance
        let trampoline_ptr = disasm.allocate_near_target(trampoline_size)?;

        // Use guard for automatic cleanup on error
        let alloc_guard = AllocGuard::new(trampoline_ptr);

        log::trace!("Allocated trampoline at {:p}", trampoline_ptr);

        // Relocate instructions for new address
        let relocated_bytes = disasm.relocate_instructions(trampoline_ptr)?;

        if relocated_bytes.is_empty() {
            log::error!("Relocation produced empty bytes");
            return Err(InlineHookError::EncodingError(
                "Empty relocation".to_string(),
            ));
        }

        // Calculate return address after the hook jump
        let return_address = unsafe { target_ptr.add(jump_size) };

        log::trace!("Return address after hook jmp: {:p}", return_address);

        let jump_back_offset = unsafe { trampoline_ptr.add(relocated_bytes.len()) };

        log::trace!("Jump back offset: {:p}", jump_back_offset);
        let jump_back = create_jump_bytes(jump_back_offset, return_address)?;

        // Verify jump back is correct
        // TODO: implement validation for jump

        // Write relocated instructions
        unsafe {
            std::ptr::copy_nonoverlapping(
                relocated_bytes.as_ptr(),
                trampoline_ptr as *mut u8,
                relocated_bytes.len(),
            );

            // Write jump back
            std::ptr::copy_nonoverlapping(
                jump_back.as_ptr(),
                jump_back_offset as *mut u8,
                jump_back.len(),
            );

            // Fill remaining space with INT3 (0xCC) for debugging
            // INT3 causes a breakpoint exception if executed accidentally
            let used_size = relocated_bytes.len() + jump_back.len();
            if used_size < trampoline_size {
                let int3_start = trampoline_ptr.add(used_size) as *mut u8;
                let int3_count = trampoline_size - used_size;
                std::ptr::write_bytes(int3_start, 0xCC, int3_count);
            }
        }

        flush_instructions_cache(trampoline_ptr, trampoline_size)?;

        log::debug!("Trampoline created successfully at {:p}", trampoline_ptr);

        // Release guard and return trampoline
        let final_ptr = alloc_guard.release();

        Ok(Self {
            ptr: final_ptr,
            disasm,
        })
    }

    pub fn get_ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn get_stolen_bytes_ref(&self) -> &Vec<u8> {
        self.disasm.get_stolen_bytes_ref()
    }
}

impl Drop for Trampoline {
    fn drop(&mut self) {
        log::debug!("Freeing trampoline at {:p}", self.ptr);

        if let Err(err) = unsafe { virtual_free(self.ptr, FreeType::Release) } {
            log::error!("Failed to free trampoline memory: {}", err);
        }
    }
}
