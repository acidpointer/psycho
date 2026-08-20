//! Guarded current-process memory snapshots for engine containment boundaries.
//!
//! This module is intentionally separate from [`super::winapi`]. Most Psycho
//! DLLs use that broad Win32 boundary, so placing a core-only resolver in the
//! same code-generation unit can make the thin xNVSE helper inherit its code,
//! strings, and static state even when the helper never calls it.
//!
//! `ReadProcessMemory` validates a complete source range without a direct Rust
//! dereference. It does not pin the allocation, prove object identity, or close
//! a lifetime race after the copy. Callers must use snapshots only for
//! defensive admission and preserve a fail-closed result when a copy fails.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, Ordering},
};

use windows::Win32::{
    Foundation::{E_FAIL, HANDLE},
    System::Threading::GetCurrentProcess,
};

use super::winapi::{WinapiError, WinapiResult, get_proc_address_in_dll};

type ReadProcessMemoryFn =
    unsafe extern "system" fn(HANDLE, *const c_void, *mut c_void, usize, *mut usize) -> i32;

static READ_PROCESS_MEMORY_ADDRESS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Copy a complete byte range without directly dereferencing an engine pointer.
///
/// The function is inline so final DLLs which do not use this core-only
/// boundary do not retain its resolver or error strings through static linking.
///
/// # Errors
///
/// Returns an error for a zero address, empty output, unavailable Win32 symbol,
/// inaccessible source range, failed copy, or incomplete transfer.
#[inline]
pub fn read_current_process_memory(address: usize, output: &mut [u8]) -> WinapiResult<()> {
    if address == 0 {
        return Err(WinapiError::InputNullPtr());
    }
    if output.is_empty() {
        return Err(WinapiError::ZeroSize());
    }

    let process = unsafe { GetCurrentProcess() };
    let read_process_memory = resolve_read_process_memory()?;
    let mut bytes_read = 0;
    let succeeded = unsafe {
        read_process_memory(
            process,
            address as *const c_void,
            output.as_mut_ptr().cast(),
            output.len(),
            &mut bytes_read,
        )
    };
    if succeeded == 0 {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }
    if bytes_read != output.len() {
        // BOOL success with a short transfer violates the documented API
        // contract. The caller only needs a deterministic failure and must not
        // consume the partially written snapshot.
        return Err(WinapiError::WindowsCore(
            windows::core::Error::from_hresult(E_FAIL),
        ));
    }
    Ok(())
}

/// Resolve the memory reader before a latency-sensitive path starts.
///
/// Calling this at installation keeps module lookup and symbol resolution out
/// of later engine boundaries. Resolution remains dynamic so final DLLs do not
/// gain a new pre-DeferredInit import solely for defensive pointer snapshots.
///
/// # Errors
///
/// Returns an error when Kernel32 or `ReadProcessMemory` cannot be resolved.
#[inline]
pub fn prepare_current_process_memory_reader() -> WinapiResult<()> {
    resolve_read_process_memory().map(|_| ())
}

#[inline]
fn resolve_read_process_memory() -> WinapiResult<ReadProcessMemoryFn> {
    let mut address = READ_PROCESS_MEMORY_ADDRESS.load(Ordering::Acquire);
    if address.is_null() {
        let resolved = get_proc_address_in_dll("kernel32.dll", "ReadProcessMemory")?;
        address = match READ_PROCESS_MEMORY_ADDRESS.compare_exchange(
            std::ptr::null_mut(),
            resolved,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => resolved,
            Err(existing) => existing,
        };
    }

    // SAFETY: GetProcAddress resolved Kernel32!ReadProcessMemory. Kernel32
    // remains loaded for process lifetime and the Win32 ABI is fixed.
    Ok(unsafe { std::mem::transmute::<*mut c_void, ReadProcessMemoryFn>(address) })
}
