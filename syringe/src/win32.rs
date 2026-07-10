//! Raw Win32 boundary for the early loader.
//!
//! Keep this module boring. The rest of the loader uses these tiny wrappers so
//! unsafe Kernel32 calls and handle ownership rules are not scattered through
//! the startup logic.

use core::cmp::Ordering;
use core::ffi::c_void;
use core::ptr::{null, null_mut};

use crate::wide_path::WidePath;

pub type HInstance = *mut c_void;
pub type HModule = *mut c_void;
type Handle = *mut c_void;

pub const DLL_PROCESS_ATTACH: u32 = 1;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const INVALID_HANDLE_VALUE: Handle = !0usize as Handle;
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_NO_MORE_FILES: u32 = 18;
const MAX_FIND_NAME: usize = 260;

#[repr(C)]
#[derive(Clone, Copy)]
struct FileTime {
    low: u32,
    high: u32,
}

#[repr(C)]
pub struct Win32FindDataW {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    file_size_high: u32,
    file_size_low: u32,
    reserved0: u32,
    reserved1: u32,
    file_name: [u16; MAX_FIND_NAME],
    alternate_file_name: [u16; 14],
    file_type: u32,
    creator_type: u32,
    finder_flags: u16,
}

impl Win32FindDataW {
    pub const fn empty() -> Self {
        Self {
            file_attributes: 0,
            creation_time: FileTime { low: 0, high: 0 },
            last_access_time: FileTime { low: 0, high: 0 },
            last_write_time: FileTime { low: 0, high: 0 },
            file_size_high: 0,
            file_size_low: 0,
            reserved0: 0,
            reserved1: 0,
            file_name: [0; MAX_FIND_NAME],
            alternate_file_name: [0; 14],
            file_type: 0,
            creator_type: 0,
            finder_flags: 0,
        }
    }

    pub fn is_directory(&self) -> bool {
        self.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub fn file_name(&self) -> &[u16] {
        crate::wide_path::nul_trimmed(&self.file_name)
    }
}

pub struct FindHandle(Handle);

impl FindHandle {
    /// Start a `FindFirstFileW` enumeration.
    ///
    /// The returned handle is closed automatically. The first result is written
    /// into `data`, matching the Win32 API contract.
    pub fn first(pattern: &WidePath, data: &mut Win32FindDataW) -> Result<Option<Self>, u32> {
        let Some(path) = pattern
            .with_extended_prefix_if_needed()
            .and_then(|path| path.with_nul())
        else {
            return Err(ERROR_PATH_NOT_FOUND);
        };
        let handle = unsafe { FindFirstFileW(path.as_slice().as_ptr(), data) };
        if handle == INVALID_HANDLE_VALUE {
            match last_error() {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
                error => Err(error),
            }
        } else {
            Ok(Some(Self(handle)))
        }
    }

    pub fn next(&self, data: &mut Win32FindDataW) -> Result<bool, u32> {
        if unsafe { FindNextFileW(self.0, data) != 0 } {
            return Ok(true);
        }
        match last_error() {
            ERROR_NO_MORE_FILES => Ok(false),
            error => Err(error),
        }
    }
}

impl Drop for FindHandle {
    fn drop(&mut self) {
        unsafe {
            FindClose(self.0);
        }
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: Handle) -> i32;
    fn CreateThread(
        attributes: *const c_void,
        stack_size: usize,
        start_address: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
        parameter: *mut c_void,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> Handle;
    fn FindClose(handle: Handle) -> i32;
    fn FindFirstFileW(file_name: *const u16, find_file_data: *mut Win32FindDataW) -> Handle;
    fn FindNextFileW(handle: Handle, find_file_data: *mut Win32FindDataW) -> i32;
    fn GetLastError() -> u32;
    fn GetModuleFileNameW(module: HModule, file_name: *mut u16, size: u32) -> u32;
    fn GetProcAddress(module: HModule, proc_name: *const u8) -> *mut c_void;
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn LoadLibraryExW(file_name: *const u16, file: Handle, flags: u32) -> HModule;
    fn LoadLibraryW(file_name: *const u16) -> HModule;
    fn OutputDebugStringW(output_string: *const u16);
    fn CompareStringOrdinal(
        string1: *const u16,
        count1: i32,
        string2: *const u16,
        count2: i32,
        ignore_case: i32,
    ) -> i32;
}

pub fn close_handle(handle: Handle) {
    if !handle.is_null() {
        unsafe {
            CloseHandle(handle);
        }
    }
}

#[inline]
pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

pub fn get_proc_address(module: HModule, name: &[u8]) -> *mut c_void {
    // Callers pass static NUL-terminated export names. Avoid checking here:
    // this path is used for every proxy export and for every loaded mod.
    unsafe { GetProcAddress(module, name.as_ptr()) }
}

pub fn compare_paths(left: &WidePath, right: &WidePath, ignore_case: bool) -> Ordering {
    let result = unsafe {
        CompareStringOrdinal(
            left.as_slice().as_ptr(),
            left.as_slice().len() as i32,
            right.as_slice().as_ptr(),
            right.as_slice().len() as i32,
            i32::from(ignore_case),
        )
    };
    match result {
        1 => Ordering::Less,
        2 => Ordering::Equal,
        3 => Ordering::Greater,
        _ => left.as_slice().cmp(right.as_slice()),
    }
}

pub fn debug_message(message: &[u8]) {
    let mut wide = [0u16; 256];
    let mut len = 0usize;
    for &byte in message {
        if len + 1 >= wide.len() {
            break;
        }
        wide[len] = u16::from(byte);
        len += 1;
    }
    unsafe { OutputDebugStringW(wide.as_ptr()) };
}

pub fn debug_error(prefix: &[u8], error: u32) {
    let mut wide = [0u16; 256];
    let mut len = 0usize;
    for &byte in prefix {
        if len + 1 >= wide.len() {
            break;
        }
        wide[len] = u16::from(byte);
        len += 1;
    }

    let mut digits = [0u8; 10];
    let mut count = 0usize;
    let mut value = error;
    loop {
        digits[count] = (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    while count > 0 && len + 1 < wide.len() {
        count -= 1;
        wide[len] = u16::from(b'0' + digits[count]);
        len += 1;
    }
    if len + 1 < wide.len() {
        wide[len] = b'\n' as u16;
    }
    unsafe { OutputDebugStringW(wide.as_ptr()) };
}

pub fn load_library(path: &WidePath) -> HModule {
    let Some(nul_path) = path
        .with_extended_prefix_if_needed()
        .and_then(|path| path.with_nul())
    else {
        return null_mut();
    };

    // Module handles returned by LoadLibrary intentionally remain loaded for
    // the process lifetime. The loader never owns or frees them.
    unsafe { LoadLibraryW(nul_path.as_slice().as_ptr()) }
}

pub fn load_library_from_dll_dir(path: &WidePath) -> Result<HModule, u32> {
    let Some(nul_path) = path
        .with_extended_prefix_if_needed()
        .and_then(|path| path.with_nul())
    else {
        return Err(ERROR_PATH_NOT_FOUND);
    };

    let module = unsafe {
        LoadLibraryExW(
            nul_path.as_slice().as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    };
    if module.is_null() {
        Err(last_error())
    } else {
        Ok(module)
    }
}

pub fn process_module_file_name() -> WidePath {
    module_file_name(null_mut())
}

pub fn module_file_name(module: HModule) -> WidePath {
    let mut path = WidePath::new();
    let len = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.capacity() as u32) };
    if !path.set_len_from_win32(len as usize) {
        return WidePath::new();
    }

    path
}

pub fn spawn_thread(start: unsafe extern "system" fn(*mut c_void) -> u32) -> bool {
    let handle = unsafe { CreateThread(null(), 0, Some(start), null_mut(), 0, null_mut()) };
    if handle.is_null() {
        return false;
    }

    close_handle(handle);
    true
}

pub fn system_directory() -> WidePath {
    let mut path = WidePath::new();
    let len = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.capacity() as u32) };
    if !path.set_len_from_win32(len as usize) {
        return WidePath::new();
    }

    path
}
