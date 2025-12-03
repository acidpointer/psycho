//! PE (Portable Executable) parsing utilities for Windows

use libc::c_void;
use thiserror::Error;
use goblin::pe::PE;

use crate::os::windows::winapi::virtual_query;

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

    #[error("Goblin parsing error: {0}")]
    GoblinError(#[from] goblin::error::Error),
}

pub type PeResult<T> = std::result::Result<T, PeError>;

#[derive(Debug, Clone)]
pub struct IatEntry {
    pub iat_address: *mut *mut c_void,
    pub current_function: *mut c_void,
    pub library_name: String,
    pub function_name: String,
}

pub struct PeParser {
    module_base: *mut c_void,
    pe_bytes: Vec<u8>,
}

impl PeParser {
    /// # Safety
    /// Module must be a valid PE loaded in memory
    pub unsafe fn new(module_base: *mut c_void) -> PeResult<Self> {
        if module_base.is_null() {
            return Err(PeError::InvalidMemoryRange);
        }

        let memory_basic_info = virtual_query(module_base)?;

        let pe_bytes = unsafe { std::slice::from_raw_parts(
            module_base as *const u8, 
            memory_basic_info.region_size,
        ).to_vec() };

        if pe_bytes.len() < 2 || &pe_bytes[0..2] != b"MZ" {
            return Err(PeError::InvalidPe("Not a PE file".into()));
        }

        Ok(Self { module_base, pe_bytes })
    }

    pub fn find_iat_entry(
        &self,
        library_name: &str,
        function_name: &str,
    ) -> PeResult<IatEntry> {
        let pe = PE::parse(&self.pe_bytes)?;
        
        // Find in the simple imports list first
        let target_import = pe.imports
            .iter()
            .find(|imp| {
                imp.dll.to_lowercase().contains(&library_name.to_lowercase()) &&
                imp.name == function_name
            })
            .ok_or_else(|| PeError::ImportNotFound(
                library_name.into(), 
                function_name.into()
            ))?;

        // Now find the IAT entry
        // goblin's Import struct has an 'offset' field which is the IAT offset
        // But we need the RVA, not file offset
        
        // The simple approach: imports have an rva field for their IAT entry
        let iat_address = unsafe {
            // The import.rva is the RVA of this import's IAT slot
            self.module_base.add(target_import.rva) as *mut *mut c_void
        };
        
        let current_function = unsafe { *iat_address };

        Ok(IatEntry {
            iat_address,
            current_function,
            library_name: target_import.dll.to_string(),
            function_name: target_import.name.to_string(),
        })
    }

    pub fn module_base(&self) -> *mut c_void {
        self.module_base
    }
}

impl std::fmt::Debug for PeParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeParser")
            .field("module_base", &self.module_base)
            .finish()
    }
}


/// Finds IAT entry by module_base, library name and function name.
/// # Safety
/// Module must be valid PE in memory
pub unsafe fn find_iat_entry(
    module_base: *mut c_void,
    library_name: &str,
    function_name: &str,
) -> PeResult<IatEntry> {
    let parser = unsafe { PeParser::new(module_base) }?;
    parser.find_iat_entry(library_name, function_name)
}