//! PE (Portable Executable) parsing utilities for Windows

use std::collections::HashSet;

use goblin::pe::options::ParseOptions;
use libc::c_void;
use thiserror::Error;

use crate::os::windows::winapi::{HModule, enum_process_modules, get_module_information};

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

#[derive(Debug, Clone)]
pub struct IatEntry {
    pub module_base: *mut c_void,
    pub iat_address: *mut *mut c_void,
    pub current_function: *mut c_void,
    pub library_name: String,
    pub function_name: String,
}

/// # Safety
/// UNSAFE!
pub unsafe fn find_iat_entry(
    module_base: *mut c_void,
    library_name: Option<String>,
    function_name: String,
) -> PeResult<Vec<IatEntry>> {
    let mut result = vec![];
    let mut process_modules = enum_process_modules(None)?;

    process_modules.insert(0, unsafe { HModule::new(module_base) }?);

    // Track unique (library_name, function_name) pairs to deduplicate by DLL
    let mut seen_imports: HashSet<(String, String)> = HashSet::new();

    for module_handle in process_modules {
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

        let old_log_level = log::STATIC_MAX_LEVEL;

        log::set_max_level(log::LevelFilter::Error);
        let pe_view = goblin::pe::PE::parse_with_opts(pe_bytes, &pe_opts)?;
        log::set_max_level(old_log_level);

        for import in pe_view.imports {
            let dll_name = import.dll;
            let import_name = import.name;
            let import_offset = import.offset;

            let iat_address =
                module_handle.as_ptr().wrapping_add(import_offset) as *mut *mut c_void;

            match &library_name {
                Some(library_name) => {
                    if library_name.to_lowercase() == dll_name.to_lowercase()
                        && import_name == function_name
                    {
                        // Create key for deduplication using case-insensitive comparison
                        let dll_key = dll_name.to_lowercase();
                        let dedup_key = (dll_key.clone(), import_name.to_string());

                        // Skip if we've already seen this DLL::function combination
                        if !seen_imports.insert(dedup_key) {
                            log::trace!(
                                "Skipping duplicate import: '{}::{}' in module '{}' (already hooked)",
                                dll_name,
                                import_name,
                                module_name
                            );
                            continue;
                        }

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
                        // Create key for deduplication using case-insensitive comparison
                        let dll_key = dll_name.to_lowercase();
                        let dedup_key = (dll_key.clone(), import_name.to_string());

                        // Skip if we've already seen this DLL::function combination
                        if !seen_imports.insert(dedup_key) {
                            log::trace!(
                                "Skipping duplicate import: '{}::{}' in module '{}' (already hooked)",
                                dll_name,
                                import_name,
                                module_name
                            );
                            continue;
                        }

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
