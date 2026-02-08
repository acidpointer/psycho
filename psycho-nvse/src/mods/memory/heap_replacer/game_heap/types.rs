use libc::c_void;

/// Game heap function signatures (fastcall convention).
pub type GameHeapAllocateFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapReallocateFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapMsizeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void) -> usize;
pub type GameHeapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);