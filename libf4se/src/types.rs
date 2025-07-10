use std::ffi::c_void;

pub type BGSMemoryManagerAllocFn =
    unsafe extern "C" fn(*mut c_void, usize, u32, bool) -> *mut c_void;
pub type BGSMemoryManagerDeallocFn = unsafe extern "C" fn(*mut c_void, *mut c_void, bool);
pub type BGSMemoryManagerReallocFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u32, bool) -> *mut c_void;
pub type BGSMemoryManagerMsizeFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize;

pub type BGSScrapHeapAllocFn = unsafe extern "C" fn(*mut c_void, usize, u32) -> *mut c_void;
pub type BGSScrapHeapDeallocFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
