use libc::c_void;

// Allocator functions
pub type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
pub type MallocAlignFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;
pub type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;
pub type ReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
pub type RecallocFn = unsafe extern "C" fn(*mut c_void, usize, usize) -> *mut c_void;
pub type MsizeFn = unsafe extern "C" fn(*mut c_void) -> usize;
pub type FreeFn = unsafe extern "C" fn(*mut c_void);
pub type FreeAlignFn = unsafe extern "C" fn(*mut c_void, usize);

// Mem ops
pub type MemcmpFn = unsafe extern "C" fn(*const c_void, *const c_void, usize) -> i32;
pub type MemmoveFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void;
pub type MemcpyFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void;
pub type MemsetFn = unsafe extern "C" fn(*mut c_void, i32, usize) -> *mut c_void;

pub type MemmoveSFn = unsafe extern "C" fn(*mut c_void, usize, *const c_void, usize) -> i32;
pub type MemcpySFn = unsafe extern "C" fn(*mut c_void, usize, *const c_void, usize) -> i32;

// Threading
pub type SetThreadPriorityFn = unsafe extern "C" fn(*mut c_void, i32) -> i32;
pub type SetThreadAffinityMaskFn = unsafe extern "C" fn(*mut c_void, usize) -> usize;