//! NULL-safe replacements for the game's two zero-allocation vtable slots.
//!
//! `0x00AA2240` and `0x00AA2370` allocate and immediately zero a buffer
//! without checking the allocation result. Their aligned branches also write
//! an alignment marker before the shared memset tail, so guarding only memset
//! does not cover every OOM fault. Replacing the two consumers keeps the guard
//! out of every unrelated game memset call.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, ensure};
use libc::c_void;
use libpsycho::{ffi::fnptr::FnPtr, os::windows::winapi::safe_write_32};

const GAME_HEAP_ADDR: usize = 0x011F6238;
const GAME_HEAP_ALLOC_ADDR: usize = 0x00AA3E40;

const ZERO_ALLOC_SLOT_1: usize = 0x010A252C;
const ZERO_ALLOC_SLOT_2: usize = 0x010A2538;
const ZERO_ALLOC_ORIGINAL_1: usize = 0x00AA2240;
const ZERO_ALLOC_ORIGINAL_2: usize = 0x00AA2370;

type GameHeapAllocFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> *mut c_void;

static NULL_RETURNS: AtomicU64 = AtomicU64::new(0);

pub fn install_zero_alloc_guards() -> anyhow::Result<()> {
    let replacement_1 = hook_zero_alloc_1 as *const () as usize;
    let replacement_2 = hook_zero_alloc_2 as *const () as usize;
    validate_slot(ZERO_ALLOC_SLOT_1, ZERO_ALLOC_ORIGINAL_1, replacement_1)?;
    validate_slot(ZERO_ALLOC_SLOT_2, ZERO_ALLOC_ORIGINAL_2, replacement_2)?;
    patch_slot(ZERO_ALLOC_SLOT_1, replacement_1)?;
    patch_slot(ZERO_ALLOC_SLOT_2, replacement_2)?;
    Ok(())
}

fn validate_slot(slot: usize, expected: usize, replacement: usize) -> anyhow::Result<()> {
    let current = unsafe { core::ptr::read_unaligned(slot as *const u32) as usize };
    if current == replacement {
        return Ok(());
    }
    ensure!(
        current == expected,
        "zero-allocation slot 0x{slot:08X} target mismatch: expected 0x{expected:08X}, found 0x{current:08X}"
    );
    Ok(())
}

fn patch_slot(slot: usize, replacement: usize) -> anyhow::Result<()> {
    let current = unsafe { core::ptr::read_unaligned(slot as *const u32) as usize };
    if current == replacement {
        return Ok(());
    }
    safe_write_32(slot as *mut c_void, replacement as u32)
        .with_context(|| format!("patch zero-allocation slot 0x{slot:08X}"))?;
    Ok(())
}

unsafe extern "thiscall" fn hook_zero_alloc_1(
    _this: *mut c_void,
    size_ptr: *const u32,
    alignment_ptr: *const u8,
    mode: u32,
    _arg4: u32,
    _arg5: u32,
    _arg6: u32,
    _arg7: u32,
) -> *mut c_void {
    unsafe { zero_alloc(size_ptr, alignment_ptr, mode, 7) }
}

unsafe extern "thiscall" fn hook_zero_alloc_2(
    _this: *mut c_void,
    size_ptr: *const u32,
    alignment_ptr: *const u8,
    mode: u32,
    _arg4: u32,
    _arg5: u32,
    _arg6: u32,
    _arg7: u32,
) -> *mut c_void {
    unsafe { zero_alloc(size_ptr, alignment_ptr, mode, 13) }
}

unsafe fn zero_alloc(
    size_ptr: *const u32,
    alignment_ptr: *const u8,
    mode: u32,
    aligned_mode: u32,
) -> *mut c_void {
    let size = unsafe { core::ptr::read_unaligned(size_ptr) } as usize;
    let allocation = if mode == aligned_mode {
        let alignment = unsafe { core::ptr::read_unaligned(alignment_ptr) };
        let base = unsafe { game_heap_alloc(size.wrapping_add(alignment as usize)) };
        if base.is_null() {
            base
        } else {
            let marker = alignment.wrapping_sub(alignment.wrapping_sub(1) & (base as usize as u8));
            let aligned = unsafe { base.cast::<u8>().add(marker as usize) };
            unsafe { aligned.sub(1).write(marker) };
            aligned.cast()
        }
    } else {
        unsafe { game_heap_alloc(size) }
    };

    if allocation.is_null() {
        log_null_return(size, mode, aligned_mode);
        return allocation;
    }
    if size != 0 {
        unsafe { core::ptr::write_bytes(allocation.cast::<u8>(), 0, size) };
    }
    allocation
}

unsafe fn game_heap_alloc(size: usize) -> *mut c_void {
    let alloc = unsafe { FnPtr::<GameHeapAllocFn>::from_address_unchecked(GAME_HEAP_ALLOC_ADDR) };
    unsafe { alloc.as_fn()(GAME_HEAP_ADDR as *mut c_void, size) }
}

fn log_null_return(size: usize, mode: u32, aligned_mode: u32) {
    let n = NULL_RETURNS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[OOM] zero-allocation consumer returned NULL total={} size={} mode={} aligned_mode={}",
            n,
            size,
            mode,
            aligned_mode,
        );
    }
}
