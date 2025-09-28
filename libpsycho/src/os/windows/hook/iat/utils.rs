use std::ffi::c_void;

use crate::os::windows::pe::{IatEntry, PeParser};
use super::IatHookResult;

/// Finds IAT entry by module_base, library name and function name.
/// # Safety
/// Module must be valid PE in memory
pub unsafe fn find_iat_entry(
    module_base: *mut c_void,
    library_name: &str,
    function_name: &str,
) -> IatHookResult<IatEntry> {
    let parser = unsafe { PeParser::new(module_base) }?;
    Ok(parser.find_iat_entry(library_name, function_name)?)
}