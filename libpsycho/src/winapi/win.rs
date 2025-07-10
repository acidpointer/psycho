//! Safe wrapper for common WinAPI functions
//! Ready for cross-compilation TO windows target!

#![allow(
    dead_code,
    unused_variables,
    unreachable_code,
    unused_imports,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::needless_return
)]

use std::{
    ffi::{CString, c_void},
    fs::File,
    io::Read,
    ptr::NonNull,
};

#[cfg(target_os = "windows")]
use windows::{
    Win32::System::Threading::CRITICAL_SECTION,
    Win32::{
        Foundation::{HANDLE, HMODULE, SetLastError},
        System::{
            Console::AllocConsole,
            Diagnostics::Debug::FlushInstructionCache,
            LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
            Memory::{
                PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualProtect,
            },
            ProcessStatus::{
                GetProcessMemoryInfo, K32GetModuleInformation, MODULEINFO, PROCESS_MEMORY_COUNTERS,
            },
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
            Threading::{
                GetCurrentProcess, InitializeCriticalSection, SetThreadPriority, THREAD_PRIORITY,
            },
        },
    },
    core::PCSTR,
};

use super::errors::WindowsError;
use super::Result;

use goblin::pe::{PE, import::Import};

/// Wrapped MODULEINFO
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleInfo {
    lp_base_of_dll: *mut c_void,
    size_of_image: u32,
    entry_point: *mut c_void,
}

/// PE aka Portable Executable import data
/// This type commonly used for handling executable imported functions
/// or any other symbols
#[derive(Debug, Clone)]
pub struct PEImport {
    pub dll_name: String,
    pub name: String,
    pub ordinal: u16,
    pub rva: usize,
}

impl From<Import<'_>> for PEImport {
    fn from(value: Import) -> Self {
        Self {
            dll_name: value.dll.to_string(),
            name: value.name.to_string(),
            ordinal: value.ordinal,
            rva: value.rva,
        }
    }
}

/// Get all imported functions from a PE file using goblin
///
/// # Arguments
/// * `pe_file_path` - Path to the PE file
///
/// # Returns
/// * `Result<Vec<ImportedFunction>, Box<dyn Error>>` - List of imported functions or error
pub fn get_pe_imports(pe_file_path: &str) -> Result<Vec<PEImport>> {
    // Read file
    let mut buffer = Vec::new();
    let mut file = File::open(pe_file_path)?;
    file.read_to_end(&mut buffer)?;

    let pe = PE::parse(&buffer)?;

    let imports: Vec<PEImport> = pe.imports.into_iter().map(|import| import.into()).collect();

    Ok(imports)
}

/// Attempts to get the actual module size
/// Returns None if the operation is not supported or fails
pub fn get_module_size(base: NonNull<c_void>) -> Option<usize> {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::ProcessStatus::GetModuleInformation;

        let process_handle = GetCurrentProcess();
        let module_handle = HMODULE(base.as_ptr());
        let mut module_info = MODULEINFO::default();

        match GetModuleInformation(
            process_handle,
            module_handle,
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        ) {
            Ok(_) => Some(module_info.SizeOfImage as usize),
            Err(_) => None,
        }
    }

    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
impl From<MODULEINFO> for ModuleInfo {
    fn from(value: MODULEINFO) -> Self {
        Self {
            entry_point: value.EntryPoint,
            lp_base_of_dll: value.lpBaseOfDll,
            size_of_image: value.SizeOfImage,
        }
    }
}

#[cfg(target_os = "windows")]
impl From<ModuleInfo> for MODULEINFO {
    fn from(val: ModuleInfo) -> Self {
        MODULEINFO {
            lpBaseOfDll: val.lp_base_of_dll,
            SizeOfImage: val.size_of_image,
            EntryPoint: val.entry_point,
        }
    }
}

pub fn get_module_information(module_name: Option<&str>) -> Result<ModuleInfo> {
    #[cfg(target_os = "windows")]
    unsafe {
        use std::slice::Windows;

        let process_handle = get_current_process()?;
        let module_handle = get_module_handle_a(module_name)?;

        let mut module_info = MODULEINFO::default();

        let result = K32GetModuleInformation(
            HANDLE(process_handle.as_ptr()),
            HMODULE(module_handle.as_ptr()),
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
        .as_bool();

        if result {
            return Ok(module_info.into());
        }

        return Err(WindowsError::HResultError(
            windows::core::Error::from_win32().into(),
        ));
    };

    #[cfg(not(target_os = "windows"))]
    unimplemented!("get_module_information supported only for Windows target")
}

/// Safe wrapper for GetCurrentProcess() from WinAPI
/// Returns error if underlying pointer is NULL
/// # Returns
/// * `Result<*mut c_void>` - HANDLE pointer or error
pub fn get_current_process() -> Result<NonNull<c_void>> {
    #[cfg(target_os = "windows")]
    {
        let handle = unsafe { GetCurrentProcess() };
        let ptr = handle.0;

        if ptr.is_null() {
            return Err(WindowsError::ProcessHandleNullError);
        }

        return Ok(unsafe { NonNull::new_unchecked(ptr) });
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("get_current_process supported only for Windows target")
}

/// Simple wrapper for GetModuleHandleA
/// This wrapper use Rust native sring slice
pub fn get_module_handle_a(module_name: Option<&str>) -> Result<NonNull<c_void>> {
    #[cfg(target_os = "windows")]
    {
        let module_name_raw = module_name.map(get_pcstr_from_str);

        let handle: HMODULE = match module_name_raw {
            Some(h) => unsafe { GetModuleHandleA(h?) }?,
            None => unsafe { GetModuleHandleA(None) }?,
        };

        let ptr = handle.0;

        if ptr.is_null() {
            return Err(WindowsError::ModuleHandleNullError);
        }

        return Ok(unsafe { NonNull::new_unchecked(ptr) });
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("get_module_handle_a supported only for Windows target")
}

/// Safe wrapper for WinAPI LoadLibraryA
pub fn load_library_a(dll_name: &str) -> Result<NonNull<c_void>> {
    #[cfg(target_os = "windows")]
    {
        let module = unsafe { LoadLibraryA(get_pcstr_from_str(dll_name)?) }
            .map_err(|err| WindowsError::DllLoadError(dll_name.into(), err.to_string()))?;

        // We do copy of internal HMODULE pointer here
        let ptr = module.0;

        if ptr.is_null() {
            return Err(WindowsError::DllLoadNullError(dll_name.into()));
        }

        return Ok(unsafe { NonNull::new_unchecked(ptr) });
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("load_library_a supported only for Windows target")
}

/// Safe wrapper for WinAPI GetProcAddress
pub fn get_proc_address(module: NonNull<c_void>, function_name: &str) -> Result<NonNull<c_void>> {
    #[cfg(target_os = "windows")]
    {
        let proc_name = get_pcstr_from_str(function_name)?;
        let hmodule = HMODULE(module.as_ptr());

        let proc_addr = unsafe { GetProcAddress(hmodule, proc_name) };

        return match proc_addr {
            Some(addr) => {
                // We do COPY here
                let ptr = addr as *mut c_void;

                if ptr.is_null() {
                    return Err(WindowsError::ProcAddressNullError);
                }

                let res = unsafe { NonNull::new_unchecked(ptr) };

                Ok(res)
            }

            None => Err(WindowsError::ProcAddressNullError),
        };
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("get_proc_address supported only for Windows target")
}

/// Safe wrapper for WinAPI AllocConsole
pub fn alloc_console() -> Result<()> {
    #[cfg(target_os = "windows")]
    unsafe {
        return Ok(AllocConsole()?);
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("alloc_console supported only for Windows target")
}

/// Get a function address from a DLL
pub fn get_function_address(dll_name: &str, function_name: &str) -> Result<NonNull<c_void>> {
    // First try to get the module if it's already loaded
    match get_module_handle_a(Some(dll_name)) {
        Ok(module_handle) => {
            log::debug!(
                "[winapi::get_function_address] Module '{}' already loaded, using existing handle",
                dll_name
            );
            get_proc_address(module_handle, function_name)
        }
        Err(_) => {
            // If not loaded, try to load it
            log::debug!(
                "[winapi::get_function_address] Module '{}' not loaded, attempting to load",
                dll_name
            );
            let module_handle = load_library_a(dll_name)?;

            log::debug!("[winapi::get_function_address] Loaded '{}'!", dll_name);
            get_proc_address(module_handle, function_name)
        }
    }
}

pub const THREAD_PRIORITY_NORMAL: i32 = 0;
pub const THREAD_PRIORITY_ABOVE_NORMAL: i32 = 1;
pub const THREAD_PRIORITY_HIGHEST: i32 = 2;
pub const THREAD_PRIORITY_IDLE: i32 = -15;
pub const THREAD_PRIORITY_LOWEST: i32 = -2;
pub const THREAD_PRIORITY_MIN: i32 = -2;
pub const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;

/// WinAPI: SetThreadPriority
pub fn set_thread_priority(hthread: *mut c_void, priority: i32) -> Result<()> {
    #[cfg(target_os = "windows")]
    unsafe {
        SetThreadPriority(HANDLE(hthread), THREAD_PRIORITY(priority))?;

        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("set_thread_priority supported only for Windows target")
}

/// WinAPI: InitializeCriticalSection
#[cfg(target_os = "windows")]
pub fn initialize_critical_section(critsec: *mut CRITICAL_SECTION) {
    #[cfg(target_os = "windows")]
    unsafe {
        InitializeCriticalSection(critsec)
    };

    #[cfg(not(target_os = "windows"))]
    unimplemented!("initialize_critical_section supported only for Windows target")
}

/// Default protection flags for VirtualProtect
pub const VIRTUAL_PROTECT_DEFAULT_FLAGS: u32 = 0x02;

pub fn virtual_protect_execute_readwrite(ptr: *mut c_void, size: Option<usize>) -> Result<u32> {
    #[cfg(target_os = "windows")]
    {
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        let size = match size {
            Some(s) => s,
            None => std::mem::size_of::<*mut c_void>(),
        };

        // Change protection to allow writing
        unsafe {
            VirtualProtect(
                ptr,
                size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )?
        }

        return Ok(old_protect.0);
    }
    #[cfg(not(target_os = "windows"))]
    unimplemented!("virtual_protect_execute_readwrite supported only for Windows target")
}

/// Restores memory protection.
/// `old_protect` - should be None if no spesific flags required
/// `VIRTUAL_PROTECT_DEFAULT_FLAGS` will be used.
///
/// Otherwise, specify packed flags in u32 (pls, use correct for WinAPI)
pub fn virtual_protect_restore(ptr: *mut c_void, old_protect: u32, size: Option<usize>) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let mut op = PAGE_PROTECTION_FLAGS(0);

        let size = match size {
            Some(s) => s,
            None => std::mem::size_of::<*mut c_void>(),
        };

        unsafe {
            VirtualProtect(
                ptr,
                size,
                PAGE_PROTECTION_FLAGS(old_protect),
                &mut op,
            )?
        }

        return Ok(());
    }
    #[cfg(not(target_os = "windows"))]
    unimplemented!("virtual_protect_restore supported only for Windows target")
}

/// WinAPI: SetLastError(0)
pub fn reset_last_error() {
    #[cfg(target_os = "windows")]
    unsafe {
        SetLastError(windows::Win32::Foundation::WIN32_ERROR(0))
    };

    #[cfg(not(target_os = "windows"))]
    unimplemented!("reset_last_error supported only for Windows target")
}

/// WinAPI: FlushInstructionCache(GetCurrentProcess(), Some(target_addr), size)
pub fn flush_instructions_cache(target_addr: *mut c_void, size: usize) -> Result<()> {
    #[cfg(target_os = "windows")]
    unsafe {
        FlushInstructionCache(GetCurrentProcess(), Some(target_addr), size)?;

        return Ok(());
    };

    #[cfg(not(target_os = "windows"))]
    unimplemented!("flush_instructions_cache supported only for Windows target")
}

pub fn get_pcstr_from_str(str: &str) -> Result<PCSTR> {
    #[cfg(target_os = "windows")]
    {
        // Create a static CString that lives for the program duration
        // This is a memory leak, but ensures the pointer stays valid

        use std::ffi::CString;
        let c_string = CString::new(str)?;
        let leaked_str = Box::leak(c_string.into_boxed_c_str());
        return Ok(PCSTR(leaked_str.as_ptr() as *const u8));
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("get_pcstr_from_str supported only for Windows target")
}

/// Wrapped WinAPI type MEMORY_BASIC_INFORMATION
pub struct MemoryBasicInformation {
    pub base_address: *mut core::ffi::c_void,
    pub allocation_base: *mut core::ffi::c_void,
    pub allocation_protect: u32,
    pub partition_id: u16,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub r#type: u32,
}

/// Query memory with VirtualQuery
pub fn query_memory(address: NonNull<c_void>) -> Result<MemoryBasicInformation> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::GetLastError;
        use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
        use windows::Win32::System::Memory::VirtualQuery;

        let mut info = unsafe { std::mem::zeroed() };
        let info_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        let result = unsafe { VirtualQuery(Some(address.as_ptr()), &mut info, info_size) };

        if result == 0 {
            let last_error = unsafe { GetLastError().0 };
            return Err(WindowsError::MemoryQueryFailed(last_error));
        } else {
            let memory_basic_info = MemoryBasicInformation {
                base_address: info.BaseAddress,
                allocation_base: info.AllocationBase,
                allocation_protect: info.AllocationProtect.0,
                partition_id: info.PartitionId,
                region_size: info.RegionSize,
                state: info.State.0,
                protect: info.Protect.0,
                r#type: info.Type.0,
            };

            return Ok(memory_basic_info);
        }
    }

    #[cfg(not(target_os = "windows"))]
    unimplemented!("query_memory supported only for Windows target")
}

