#![allow(dead_code)]
use libc::c_void;

// Gentlemans. Remember!
// Always use correct calling convention in your hooks.
// If Ghidra says that it is "__thiscall", USE "thiscall", thanks!

/// Game heap function signatures (fastcall convention).
pub type GameHeapAllocateFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> *mut c_void;
pub type GameHeapReallocateFn =
    unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapMsizeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> usize;
pub type GameHeapFreeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// Scrap heap function signatures (fastcall convention, except GetThreadLocal).
pub type SheapInitFixFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapInitVarFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize);
pub type SheapAllocFn =
    unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
pub type SheapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
pub type SheapPurgeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapGetThreadLocalFn = unsafe extern "C" fn() -> *mut c_void;
pub type SheapMaintenanceFn = unsafe extern "C" fn(*mut c_void);

//(void *this,undefined4 param_1,undefined4 param_2)
pub type SheapRegisterFn = unsafe extern "thiscall" fn(*mut c_void, u32, *mut c_void);

// RNG
pub type RngFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> u32;

