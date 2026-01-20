use libc::c_void;

/// Game heap function signatures (fastcall convention).
pub type GameHeapAllocateFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapReallocateFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapMsizeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void) -> usize;
pub type GameHeapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);

/// Scrap heap function signatures (fastcall convention, except GetThreadLocal).
pub type SheapInitFixFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapInitVarFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize);
pub type SheapAllocFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
pub type SheapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
pub type SheapPurgeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapGetThreadLocalFn = unsafe extern "C" fn() -> *mut c_void;