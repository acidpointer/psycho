use libc::c_void;
use iced_x86::Instruction;

use super::errors::InlineHookError;
use super::utils::{allocate_near_target, relocate_instructions};
use crate::os::windows::constants::arch::MAX_JUMP_SIZE;
use crate::os::windows::hook::inline::utils::create_jump_bytes;
use crate::os::windows::hook::inline::InlineHookResult;
use crate::os::windows::winapi::{flush_instructions_cache, virtual_free, FreeType};


/// Guard for safe memory allocation cleanup
pub(super) struct AllocGuard {
    ptr: *mut c_void,
    size: usize,
    should_free: bool,
}

impl AllocGuard {
    fn new(ptr: *mut c_void, size: usize) -> Self {
        Self { ptr, size, should_free: true }
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

            if let Err(err) = virtual_free(self.ptr, 0, FreeType::Release) {
                log::error!("Failed to free AllocGuard memory: {}", err);
            }
        }
    }
}

pub(super) struct Trampoline {
    ptr: *mut c_void,
    size: usize,

    stolen_bytes: Vec<u8>,
}

unsafe impl Send for Trampoline {}
unsafe impl Sync for Trampoline {}

impl Trampoline {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub(super) fn new(
        target: *mut c_void,
        stolen_bytes: &[u8],
        stolen_instructions: &[Instruction],
        jump_size: usize,
    ) -> InlineHookResult<Self> {
        log::debug!("Creating trampoline for {} stolen bytes", stolen_bytes.len());
        
        // Extra space: 16 bytes for alignment and safety padding
        let trampoline_size = stolen_bytes.len() + MAX_JUMP_SIZE + 16;
        
        // Try to allocate near target for better performance
        let trampoline_memory = allocate_near_target(target, trampoline_size)?;
        
        // Use guard for automatic cleanup on error
        let alloc_guard = AllocGuard::new(trampoline_memory, trampoline_size);
        
        log::trace!("Allocated trampoline at {:p}", trampoline_memory);
        
        // Relocate instructions for new address
        let relocated_bytes = relocate_instructions(
            stolen_instructions,
            target,
            trampoline_memory
        )?;
        
        if relocated_bytes.is_empty() {
            log::error!("Relocation produced empty bytes");
            return Err(InlineHookError::EncodingError("Empty relocation".to_string()));
        }
        
        // Calculate return address after the hook jump
        let return_address = unsafe { target.add(jump_size) };
        let jump_back_offset = unsafe { trampoline_memory.add(relocated_bytes.len()) };
        
        let jump_back = create_jump_bytes(jump_back_offset, return_address)?;
        
        // Verify jump back is correct
        create_jump_bytes(jump_back.as_ptr() as *mut c_void, jump_back_offset)?;
        
        // Write relocated instructions
        unsafe {
            std::ptr::copy_nonoverlapping(
                relocated_bytes.as_ptr(),
                trampoline_memory as *mut u8,
                relocated_bytes.len()
            );
            
            // Write jump back
            std::ptr::copy_nonoverlapping(
                jump_back.as_ptr(),
                jump_back_offset as *mut u8,
                jump_back.len()
            );
            
            // Fill remaining space with INT3 (0xCC) for debugging
            // INT3 causes a breakpoint exception if executed accidentally
            let used_size = relocated_bytes.len() + jump_back.len();
            if used_size < trampoline_size {
                let int3_start = trampoline_memory.add(used_size) as *mut u8;
                let int3_count = trampoline_size - used_size;
                std::ptr::write_bytes(int3_start, 0xCC, int3_count);
            }
        }
        
        flush_instructions_cache(trampoline_memory, trampoline_size)?;
        
        log::debug!("Trampoline created successfully at {:p}", trampoline_memory);
        
        // Release guard and return trampoline
        let final_ptr = alloc_guard.release();
        
        Ok(Self {
            ptr: final_ptr,
            size: trampoline_size,
            stolen_bytes: stolen_bytes.to_vec(),
        })
    }

    pub fn get_ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn get_stolen_bytes_ref(&self) -> &Vec<u8> {
        &self.stolen_bytes
    }

    pub fn get_size(&self) -> usize {
        self.size
    }
}


impl Drop for Trampoline {
    fn drop(&mut self) {
        log::debug!("Freeing trampoline at {:p}", self.ptr);

        if let Err(err) = virtual_free(self.ptr, 0, FreeType::Release) {
            log::error!("Failed to free trampoline memory: {}", err);
        }
    }
}