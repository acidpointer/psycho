//! WinAPI wrapper
//!
//! This module contains various wrapper winapi functions and types.

use std::ffi::{CString, NulError, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::NonNull;

use libc::c_void;
use thiserror::Error;
use windows::Win32::Foundation::{GetLastError, HANDLE, HMODULE, HWND, SetLastError, WIN32_ERROR};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleA, GetModuleHandleW, GetProcAddress, LoadLibraryA,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS,
    VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE, VirtualAlloc, VirtualFree, VirtualProtect,
};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::{
    CRITICAL_SECTION, InitializeCriticalSection, SetThreadPriority, THREAD_PRIORITY,
    THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_HIGHEST,
    THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_MIN, THREAD_PRIORITY_NORMAL,
    THREAD_PRIORITY_TIME_CRITICAL,
};
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache, Memory::VirtualQuery, Threading::GetCurrentProcess,
};
use windows::Win32::UI::WindowsAndMessaging::{
    MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxA,
};
use windows::core::{PCSTR, PCWSTR};

#[derive(Debug, Error)]
pub enum WinapiError {
    #[error("Windows core API error: {0}")]
    WindowsCore(#[from] windows::core::Error),

    #[error("Input PTR is NULL")]
    InputNullPtr(),

    #[error("Proc address is NULL for function: {0}")]
    ProcAddressIsNull(String),

    #[error("Size can't be zero")]
    ZeroSize(),

    #[error("VirtualQuery failed with error code: {0}")]
    VirtualQuery(u32),

    #[error("Interior nul bytes found: {0}")]
    NulError(#[from] NulError),
}

pub type WinapiResult<T> = std::result::Result<T, WinapiError>;

/// Wrapped WinAPI type MEMORY_BASIC_INFORMATION
pub struct MemoryBasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    //pub partition_id: u16,
    pub region_size: usize,
    pub state: u32,
    pub protect: PAGE_PROTECTION_FLAGS,
    pub r#type: u32,
}

/// Query memory with VirtualQuery(...)
pub fn virtual_query(ptr: *mut c_void) -> WinapiResult<MemoryBasicInformation> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    let mut info = unsafe { std::mem::zeroed() };
    let info_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    let result = unsafe { VirtualQuery(Some(ptr), &mut info, info_size) };

    if result == 0 {
        let last_error = unsafe { GetLastError().0 };
        return Err(WinapiError::VirtualQuery(last_error));
    }

    let memory_basic_info = MemoryBasicInformation {
        base_address: info.BaseAddress,
        allocation_base: info.AllocationBase,
        allocation_protect: info.AllocationProtect.0,
        //partition_id: info.PartitionId,
        region_size: info.RegionSize,
        state: info.State.0,
        protect: info.Protect,
        r#type: info.Type.0,
    };

    Ok(memory_basic_info)
}

/// WinAPI: FlushInstructionCache(...)
pub fn flush_instructions_cache(base: *mut c_void, size: usize) -> WinapiResult<()> {
    if base.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    let process_handle = get_current_process()?;

    unsafe {
        FlushInstructionCache(process_handle.into(), Some(base), size)?;
    }

    Ok(())
}

/// WinAPI: SetLastError(error_code)
pub fn set_last_error(error_code: u32) {
    unsafe { SetLastError(WIN32_ERROR(error_code)) }
}

/// WinAPI: SetLastError(0)
pub fn reset_last_error() {
    set_last_error(0);
}

/// `InitializeCriticalSection` wrapper from WinAPI
/// 
/// # Safety
/// 
/// - If `ptr` is NULL, error will be returned
pub unsafe fn initialize_critical_section(ptr: *mut CRITICAL_SECTION) -> WinapiResult<()> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    unsafe { InitializeCriticalSection(ptr) };

    Ok(())
}

/// Idiomatic Rust type for storing `THREAD_PRIORITY` values.
/// 
/// Actually, not really better than `THREAD_PRIORITY`, but
/// implements `Debug`, `Display`, `Hash` and easier to use in Rust.
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum ThreadPriority {
    AboveNormal,
    BelowNormal,
    Highest,
    Idle,
    Lowest,
    Min,
    Normal,
    TimeCritical,
    Unknown(i32),
}

impl From<ThreadPriority> for THREAD_PRIORITY {
    fn from(value: ThreadPriority) -> Self {
        match value {
            ThreadPriority::AboveNormal => THREAD_PRIORITY_ABOVE_NORMAL,
            ThreadPriority::BelowNormal => THREAD_PRIORITY_BELOW_NORMAL,
            ThreadPriority::Highest => THREAD_PRIORITY_HIGHEST,
            ThreadPriority::Idle => THREAD_PRIORITY_IDLE,
            ThreadPriority::Lowest => THREAD_PRIORITY_LOWEST,
            ThreadPriority::Min => THREAD_PRIORITY_MIN,
            ThreadPriority::Normal => THREAD_PRIORITY_NORMAL,
            ThreadPriority::TimeCritical => THREAD_PRIORITY_TIME_CRITICAL,
            ThreadPriority::Unknown(priority) => THREAD_PRIORITY(priority),
        }
    }
}

impl From<THREAD_PRIORITY> for ThreadPriority {
    fn from(value: THREAD_PRIORITY) -> Self {
        match value {
            THREAD_PRIORITY_ABOVE_NORMAL => ThreadPriority::AboveNormal,
            THREAD_PRIORITY_BELOW_NORMAL => ThreadPriority::BelowNormal,
            THREAD_PRIORITY_HIGHEST => ThreadPriority::Highest,
            THREAD_PRIORITY_IDLE => ThreadPriority::Idle,
            THREAD_PRIORITY_LOWEST => ThreadPriority::Lowest,
            THREAD_PRIORITY_NORMAL => ThreadPriority::Normal,
            THREAD_PRIORITY_TIME_CRITICAL => ThreadPriority::TimeCritical,
            val => ThreadPriority::Unknown(val.0),
        }
    }
}

/// WinAPI: SetThreadPriority(...)
pub fn set_thread_priority(thread_handle: Handle, priority: ThreadPriority) -> WinapiResult<()> {
    unsafe { SetThreadPriority(thread_handle.into(), priority.into())? };

    Ok(())
}

/// WinAPI: VirtualProtect(...)
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn virtual_protect(
    ptr: *mut c_void,
    protection_flags: PAGE_PROTECTION_FLAGS,
    size: usize,
) -> WinapiResult<PAGE_PROTECTION_FLAGS> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    if size == 0 {
        return Err(WinapiError::ZeroSize());
    }

    let target_protection_flags: PAGE_PROTECTION_FLAGS = protection_flags;
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);

    // Change protection with winapi call
    // We use PageProtectionFlags type instead raw PAGE_PROTECTION_FLAGS
    // Why we need this? Because native idiomatic type works better for
    // devs. You can do way more with custom type and cast to raw when
    // needed.
    unsafe { VirtualProtect(ptr, size, target_protection_flags, &mut old_protect)? }

    Ok(old_protect)
}

/// Wrapper for 'virtual_protect'
///
/// This function takes closure 'func' and execute it after
/// memory protection flag changed to requested: 'protection_flags'.
/// After execution finish, memory protection flags restores to initial
/// value and return result from 'func', if any.
///
/// You really want to use this instead raw 'virtual_protect' because
/// with this safe wrapper, you can freely forget about missing protection
/// flags restoration, and you just write less code!
/// 
/// # Safety
/// - Virtual protect automatically restores after closure evaluation
/// - Same safety rules as for `virtual_protect`
pub unsafe fn with_virtual_protect<T, U: FnOnce() -> T>(
    ptr: *mut c_void,
    protection_flags: PAGE_PROTECTION_FLAGS,
    size: usize,
    func: U,
) -> WinapiResult<T> {
    // Step 1: change protection and save old protection flags to restore it in future
    let old_ptotect = virtual_protect(ptr, protection_flags, size)?;

    // Step 2: Execute callback here, saving it's result
    let callback_result = func();

    // Step 3: Restore protection, using previously stored protection flags
    let _ = virtual_protect(ptr, old_ptotect, size)?;

    Ok(callback_result)
}

/// Very important thing which represents HANDLE from WinAPI.    
/// It tries to be safe using AtomicPtr<c_void>
#[derive(Debug)]
pub struct Handle {
    ptr: NonNull<c_void>,
}

// Safety: Safe, because AtomicPtr is used and pointer is not null
unsafe impl Send for Handle {}

// Safety: Safe, because AtomicPtr is used and pointer is not null
unsafe impl Sync for Handle {}

impl Handle {
    /// Construct new `Handle`
    /// 
    /// # Safety
    /// 
    /// - If `ptr` is NULL, error will be returned
    /// - `ptr` stored in `NonNull<c_void>` container
    pub unsafe fn new(ptr: *mut c_void) -> WinapiResult<Self> {
        if ptr.is_null() {
            return Err(WinapiError::InputNullPtr());
        }

        Ok(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        })
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
}

impl From<Handle> for HANDLE {
    fn from(value: Handle) -> Self {
        HANDLE(value.as_ptr())
    }
}

impl TryFrom<HANDLE> for Handle {
    type Error = WinapiError;

    fn try_from(value: HANDLE) -> Result<Self, Self::Error> {
        unsafe { Handle::new(value.0) }
    }
}

/// WinAPI: GetCurrentProcess()  
/// Return Handle wrapper in Result.
///
/// # Safety:  
/// Handle itself tries to be as safe as possible, using AtomicPtr
/// under the hood.  
pub fn get_current_process() -> WinapiResult<Handle> {
    let handle = unsafe { GetCurrentProcess() };

    handle.try_into()
}

/// Wrapper for WinAPI HMODULE type.
///
/// # Safety
/// HMODULE pointer stored in AtomicPtr and read-only.
#[derive(Debug)]
pub struct HModule {
    ptr: NonNull<c_void>,
}

// Safety: Inner poiter stored in AtomicPtr
unsafe impl Send for HModule {}

// Safety: Inner poiter stored in AtomicPtr
unsafe impl Sync for HModule {}

impl HModule {
    /// Constructs new `HModule`
    /// 
    /// # Safety
    /// - If `ptr` is NULL, error will be returned
    pub unsafe fn new(ptr: *mut c_void) -> WinapiResult<Self> {
        if ptr.is_null() {
            return Err(WinapiError::InputNullPtr());
        }

        Ok(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        })
    }

    /// Returns raw pointer for HMODULE
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
}

impl From<HModule> for HMODULE {
    fn from(value: HModule) -> Self {
        Self(value.as_ptr())
    }
}

impl TryFrom<HMODULE> for HModule {
    type Error = WinapiError;

    fn try_from(value: HMODULE) -> Result<Self, Self::Error> {
        unsafe { HModule::new(value.0) }
    }
}

/// Wrapper for WinAPI MODULEINFO type
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModuleInfo {
    base_of_dll: *mut c_void,
    size_of_image: u32,
    entry_point: *mut c_void,
}

impl From<MODULEINFO> for ModuleInfo {
    fn from(value: MODULEINFO) -> Self {
        Self {
            base_of_dll: value.lpBaseOfDll,
            size_of_image: value.SizeOfImage,
            entry_point: value.EntryPoint,
        }
    }
}

impl From<ModuleInfo> for MODULEINFO {
    fn from(value: ModuleInfo) -> Self {
        Self {
            lpBaseOfDll: value.base_of_dll,
            SizeOfImage: value.size_of_image,
            EntryPoint: value.entry_point,
        }
    }
}

impl Default for ModuleInfo {
    fn default() -> Self {
        MODULEINFO::default().into()
    }
}

/// WinAPI: GetModuleInformation(...)
/// # Safety:
/// Returns error if base is NULL or handle of current process is NULL
pub fn get_module_information(module_handle: HModule) -> WinapiResult<ModuleInfo> {
    let process_handle = get_current_process()?;

    let mut module_info: MODULEINFO = MODULEINFO::default();

    unsafe {
        GetModuleInformation(
            process_handle.into(),
            module_handle.into(),
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )?;
    }

    Ok(module_info.into())
}

/// Universal string conversion
///
/// WinString stores 3 types of string under the hood:
/// - origin string   - default String from Rust std
/// - ANSI string     - CString from Rust std, used in PCSTR conversion
/// - wide bytes vec  - re-encoded bytes from original string to UTF-16 for PCWSTR conversion
///
/// When you call WinString to give any WinAPI string type, it will just get pointer from
/// some of the stored string forms and put this pointer to desired WinAPI string type.
///
/// But the real use case for it - lifetime safety. Let me explain.
///
/// Imagine, you need to call some windows function which require string as argument. And from
/// this point, pain begins. What you need is go through this steps:
/// 1. Create intermediate string representation with CString/CStr/Vec<u16> or whatever
/// 2. Get pointer to just created intermediate string representation
/// 3. Pass pointer to PCSTR or PCWSTR to finally create WinAPI string
/// 4. Pass string to WinAPI function
///
/// You feel it? Pain! And you even not wrote this code yet! But real pain is only starts.
/// As you know, Rust comes with borrow checker which ensures that all type lives within
/// it's scopes. So, Rust will just delete everything which comes outside of initial scope.
///
/// In case of strings, we actually pass raw pointers to WinAPI functions, so it's very important
/// to ensure that original string lives long enougth. Otherwise, we get null pointer and undefined
/// behavior.
///
/// WinString fix all this problems with callback based approach. First, you instantiate WinString,
/// and for each action which require WinAPI string type, you write callbacks.
///
/// I know, it's boring and not very cool, but it really protects from shit, trust me.
/// Better to write not so crazy beatifull code construction instead spend hours on debugging.
#[derive(Debug)]
pub struct WinString {
    origin: String,
    ansi_str: CString,
    wide_vec: Vec<u16>,
}

impl WinString {
    pub fn new(input: &str) -> WinapiResult<Self> {
        let origin = input.to_string();

        let wide_vec: Vec<u16> = OsStr::new(input)
            .encode_wide()
            // Explanation:
            // Our goal is to store wide null-terminated string
            // So what we do here is just create iterator with '0' and chain it to main iterator,
            // thus at the end of vector we will have '0': [1, 2, 3, 0]
            .chain(std::iter::once(0))
            .collect();

        let ansi_str = CString::new(input)?;

        Ok(Self {
            wide_vec,
            ansi_str,
            origin,
        })
    }

    /// Execute closure with PCSTR as input.
    /// Returns result R from closure
    pub fn with_pcstr<F, R>(&self, f: F) -> R
    where
        F: FnOnce(PCSTR) -> R,
    {
        f(self.as_pcstr())
    }

    pub fn try_with_pcstr<F, T>(&self, f: F) -> WinapiResult<T>
    where
        F: FnOnce(PCSTR) -> WinapiResult<T>,
    {
        f(self.as_pcstr())
    }

    pub fn with_pcwstr<F, R>(&self, f: F) -> R
    where
        F: FnOnce(PCWSTR) -> R,
    {
        f(self.as_pcwstr())
    }

    pub fn try_with_pcwstr<F, T>(&self, f: F) -> WinapiResult<T>
    where
        F: FnOnce(PCWSTR) -> WinapiResult<T>,
    {
        f(self.as_pcwstr())
    }

    pub fn as_string(&self) -> String {
        self.origin.clone()
    }

    fn as_pcwstr(&self) -> PCWSTR {
        PCWSTR::from_raw(self.wide_vec.as_ptr())
    }

    fn as_pcstr(&self) -> PCSTR {
        PCSTR::from_raw(self.ansi_str.as_ptr() as *const u8)
    }
}

impl TryFrom<String> for WinString {
    type Error = WinapiError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        WinString::new(value.as_str())
    }
}

impl TryFrom<&String> for WinString {
    type Error = WinapiError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        WinString::new(value.as_str())
    }
}

impl TryFrom<&str> for WinString {
    type Error = WinapiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        WinString::new(value)
    }
}

impl From<WinString> for String {
    fn from(value: WinString) -> Self {
        value.as_string()
    }
}

/// WinAPI: GetModuleHandleA(...)
pub fn get_module_handle_a(module_name: Option<&str>) -> WinapiResult<HModule> {
    let hmodule: HMODULE = match module_name {
        Some(name) => {
            let winstr = WinString::new(name)?;

            winstr.try_with_pcstr(|lpmodulename| Ok(unsafe { GetModuleHandleA(lpmodulename) }?))?
        }

        None => unsafe { GetModuleHandleA(None) }?,
    };

    hmodule.try_into()
}

/// WinAPI: GetProcAddress(...)
pub fn get_proc_address(module: HModule, function_name: &str) -> WinapiResult<*mut c_void> {
    let proc_name = WinString::new(function_name)?;

    let proc =
        proc_name.with_pcstr(|lpprocname| unsafe { GetProcAddress(module.into(), lpprocname) });

    match proc {
        Some(proc_value) => {
            // Safety: We do pointer copy here
            let ptr = proc_value as *mut c_void;

            if ptr.is_null() {
                return Err(WinapiError::ProcAddressIsNull(function_name.to_string()));
            }

            Ok(ptr)
        }

        None => Err(WinapiError::ProcAddressIsNull(function_name.to_string())),
    }
}

/// WinAPI: LoadLibraryA(...)
pub fn load_library_a(dll: &str) -> WinapiResult<HModule> {
    let dll_name = WinString::new(dll)?;

    let hmodule =
        dll_name.try_with_pcstr(|lplibfilename| Ok(unsafe { LoadLibraryA(lplibfilename) }?))?;

    hmodule.try_into()
}

/// If function exist in loaded dll, returns it's address as *mut c_void
/// Otherwise return error
pub fn get_proc_address_in_dll(dll: &str, function_name: &str) -> WinapiResult<*mut c_void> {
    let module_handle = get_module_handle_a(Some(dll))?;
    let proc = get_proc_address(module_handle, function_name)?;

    Ok(proc)
}

/// Memory allocation types for VirtualAlloc
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationType {
    Commit,
    Reserve,
    CommitReserve,
}

impl From<AllocationType> for VIRTUAL_ALLOCATION_TYPE {
    fn from(value: AllocationType) -> Self {
        match value {
            AllocationType::Commit => MEM_COMMIT,
            AllocationType::Reserve => MEM_RESERVE,
            AllocationType::CommitReserve => MEM_COMMIT | MEM_RESERVE,
        }
    }
}

/// Memory free types for VirtualFree
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeType {
    Release,
}

impl From<FreeType> for VIRTUAL_FREE_TYPE {
    fn from(value: FreeType) -> Self {
        match value {
            FreeType::Release => MEM_RELEASE,
        }
    }
}

/// `VirtualAlloc` wrapper from WinAPI
/// 
/// # Safety
/// - If `size == 0`, error will be returned
/// - If result is `NULL`, error will be returned
/// - Other safety rules is same as for `VirtualAlloc`
pub unsafe fn virtual_alloc(
    address: Option<*const c_void>,
    size: usize,
    allocation_type: AllocationType,
    protection: PAGE_PROTECTION_FLAGS,
) -> WinapiResult<*mut c_void> {
    if size == 0 {
        return Err(WinapiError::ZeroSize());
    }

    let result = unsafe { VirtualAlloc(address, size, allocation_type.into(), protection) };

    if result.is_null() {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    Ok(result)
}

/// `VirtualFree` wrapper from WinAPI
/// 
/// # Safety
/// - If `address` is `NULL` error will be returned
/// - Other safety rules is same as for `VirtualFree`
pub unsafe fn virtual_free(address: *mut c_void, free_type: FreeType) -> WinapiResult<()> {
    if address.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    // Per WinAPI docs, 'dwSize' must be 0 if 'dwFreeType' is MEM_RELEASE.
    let size = match free_type {
        FreeType::Release => 0,
    };

    unsafe { VirtualFree(address, size, free_type.into()) }?;

    Ok(())
}

/// WinAPI: GetModuleHandleW(...)
/// Get module handle by name (Unicode version)
/// If input is None, will return handle of current process
pub fn get_module_handle_w(module_name: Option<&str>) -> WinapiResult<HModule> {
    let hmodule = if let Some(name) = module_name {
        let winstr = WinString::new(name)?;
        winstr.try_with_pcwstr(|lpmodulename| Ok(unsafe { GetModuleHandleW(lpmodulename) }?))?
    } else {
        unsafe { GetModuleHandleW(None) }?
    };

    unsafe { HModule::new(hmodule.0) }
}

/// WinAPI: MessageBoxA(...)
/// Display a message box with text and caption
pub fn message_box_a(
    hwnd: Option<HWND>,
    text: &str,
    caption: &str,
    mb_type: Option<MESSAGEBOX_STYLE>,
) -> WinapiResult<MESSAGEBOX_RESULT> {
    // Very easy string conversion using our custom string type.
    // Closures allows us to ensure that lifetimes of strings are
    // okay.

    let text_str = WinString::new(text)?;
    let caption_str = WinString::new(caption)?;
    let style = mb_type.unwrap_or(MB_OK);
    let window = hwnd.unwrap_or(HWND(std::ptr::null_mut()));

    text_str.try_with_pcstr(|text_ptr| {
        caption_str.try_with_pcstr(|caption_ptr| {
            Ok(unsafe { MessageBoxA(Some(window), text_ptr, caption_ptr, style) })
        })
    })
}
