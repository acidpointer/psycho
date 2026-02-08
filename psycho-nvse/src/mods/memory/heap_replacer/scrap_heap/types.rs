use libc::c_void;

/// Scrap heap function signatures (fastcall convention, except GetThreadLocal).
pub type SheapInitFixFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapInitVarFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize);
pub type SheapAllocFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
pub type SheapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
pub type SheapPurgeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapGetThreadLocalFn = unsafe extern "C" fn() -> *mut c_void;