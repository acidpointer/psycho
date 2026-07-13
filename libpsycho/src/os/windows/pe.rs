//! PE (Portable Executable) parsing utilities for Windows

use goblin::pe::options::ParseOptions;
use libc::c_void;
use thiserror::Error;

use crate::os::windows::winapi::{HModule, get_module_information};

use super::winapi::WinapiError;

#[derive(Debug, Error)]
pub enum PeError {
    #[error("Invalid PE format: {0}")]
    InvalidPe(String),

    #[error("Import not found: library={0}, function={1}")]
    ImportNotFound(String, String),

    #[error("Invalid memory range for PE parsing")]
    InvalidMemoryRange,

    #[error("Failed to read PE data: {0}")]
    ReadError(String),

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),

    #[error("Goblin error: {0}")]
    GoblinError(#[from] goblin::error::Error),
}

pub type PeResult<T> = std::result::Result<T, PeError>;

/// One resolved import slot in a loaded module.
#[derive(Debug, Clone)]
pub struct IatEntry {
    /// Base address of the module that owns the import.
    pub module_base: *mut c_void,
    /// Address of the writable pointer slot.
    pub iat_address: *mut *mut c_void,
    /// Function pointer stored in the slot when it was discovered.
    pub current_function: *mut c_void,
    /// Imported DLL name recorded in the PE image.
    pub library_name: String,
    /// Imported function name recorded in the PE image.
    pub function_name: String,
}

/// Find matching IAT entries in a loaded PE image.
///
/// # Safety
///
/// `module_base` must remain a valid loaded module while its image headers and
/// import table are read. Returned entry pointers are valid only while that
/// module remains loaded.
pub unsafe fn find_iat_entry(
    module_base: *mut c_void,
    library_name: Option<String>,
    function_name: String,
) -> PeResult<Vec<IatEntry>> {
    let mut result = vec![];
    let module_handle = unsafe { HModule::new(module_base) }?;
    {
        let module_info = get_module_information(module_handle)?;

        let pe_start_addr = module_info.base_of_dll as *const u8;
        let pe_len = module_info.size_of_image as usize;

        let pe_bytes = unsafe { std::slice::from_raw_parts(pe_start_addr, pe_len) };

        let module_name = crate::os::windows::winapi::get_module_base_name(module_handle)
            .unwrap_or_else(|_| format!("{:p}", pe_start_addr));

        let mut pe_opts = ParseOptions::default();
        pe_opts.resolve_rva = false;
        pe_opts.parse_mode = goblin::options::ParseMode::Permissive;
        pe_opts.parse_tls_data = false;

        let pe_view = goblin::pe::PE::parse_with_opts(pe_bytes, &pe_opts)?;

        for import in pe_view.imports {
            let dll_name = import.dll;
            let import_name = import.name;
            let import_offset = import.offset;

            let iat_address =
                module_handle.as_ptr().wrapping_add(import_offset) as *mut *mut c_void;

            match &library_name {
                Some(library_name) => {
                    if library_name.eq_ignore_ascii_case(dll_name) && import_name == function_name {
                        log::debug!(
                            "Found import(requested name): '{}::{}' in module '{}' at {:p}",
                            dll_name,
                            import_name,
                            module_name,
                            pe_start_addr
                        );

                        result.push(IatEntry {
                            module_base: module_handle.as_ptr(),
                            iat_address,
                            current_function: unsafe { *iat_address },
                            library_name: dll_name.to_string(),
                            function_name: import_name.to_string(),
                        });
                    }
                }

                None => {
                    if import_name == function_name {
                        log::debug!(
                            "Found import: '{}::{}' in module '{}' at {:p}",
                            dll_name,
                            import_name,
                            module_name,
                            pe_start_addr
                        );

                        result.push(IatEntry {
                            module_base: module_handle.as_ptr(),
                            iat_address,
                            current_function: unsafe { *iat_address },
                            library_name: dll_name.to_string(),
                            function_name: import_name.to_string(),
                        });
                    }
                }
            }
        }
    }

    Ok(result)
}
