use libc::c_void;

// Game Heap API (Fallout New Vegas/Fallout 3 engine heap functions)
// These use __fastcall convention: self in ECX, edx in EDX
pub type GameHeapAllocateFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapReallocateFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void, usize) -> *mut c_void;
pub type GameHeapMsizeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void) -> usize;
pub type GameHeapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);

// Scrap Heap (sheap) API (Fallout New Vegas/Fallout 3 stack-like heap)
// These use __fastcall convention: heap pointer in ECX, edx in EDX
pub type SheapInitFixFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapInitVarFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize);
pub type SheapAllocFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void;
pub type SheapFreeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
pub type SheapPurgeFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void);
pub type SheapGetThreadLocalFn = unsafe extern "C" fn() -> *mut c_void;