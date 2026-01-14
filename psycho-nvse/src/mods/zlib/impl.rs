use std::ffi::CStr;

use libc::c_void;
use libnvse::NVSEInterface;
use libpsycho::os::windows::winapi::{patch_memory_nop, replace_call, safe_write_16, safe_write_8};
use libz_rs_sys::{inflate, inflateEnd, inflateInit2_, z_streamp};

/// Zlib version string passed to inflateInit2_
static ZLIB_VERSION: &CStr = c"1.3.1";

/// Increased allocation size for zlib decompression buffers
const ZLIB_ALLOC_SIZE: u16 = 0x1C08;

// ============================================================================
// Fallout: New Vegas Runtime Addresses
// ============================================================================

/// Addresses of inflateInit calls in the game
const GAME_INFLATE_INIT_EX_ADDRS: [usize; 2] = [0x4742AC, 0xAFC537];

/// Addresses of inflate calls in the game
const GAME_INFLATE_ADDRS: [usize; 2] = [0x47434F, 0xAFC1F4];

/// Addresses of inflateEnd calls in the game
const GAME_INFLATE_END_ADDRS: [usize; 7] = [
    0x4742CA, 0x474388, 0x4743D5, 0x474419, 0xAFC00E, 0xAFC21B, 0xAFC552,
];

/// Address where allocation size needs to be patched
const GAME_ALLOC_SIZE_ADDR: usize = 0xAFC4A2;

// ============================================================================
// GECK Editor Addresses
// ============================================================================

/// Addresses of inflateInit calls in the editor
const EDITOR_INFLATE_INIT_EX_ADDRS: [usize; 2] = [0x4E32D8, 0xB552D8];

/// Addresses of inflate calls in the editor
const EDITOR_INFLATE_ADDRS: [usize; 2] = [0x4E3350, 0xB52E98];

/// Addresses of inflateEnd calls in the editor
const EDITOR_INFLATE_END_ADDRS: [usize; 7] = [
    0x4E32E9, 0x4E33DC, 0x4E3387, 0x4E3376, 0xB52D82, 0xB52EF4, 0xB552EB,
];

/// Address where allocation size needs to be patched in editor
const EDITOR_ALLOC_SIZE_ADDR: usize = 0xB55284;

/// Address for TESNPC record compression removal (editor only)
const EDITOR_TESNPC_COMPRESSION_ADDR: usize = 0x57A448;

/// Address for TESObjectLAND compression removal (editor only)
const EDITOR_TESLAND_COMPRESSION_ADDR: usize = 0x61912D;

/// Custom inflateInit wrapper that uses modern zlib with fixed parameters
unsafe extern "C" fn hook_inflate_init_ex(
    strm: z_streamp,
    _version: *const u8,  // Ignored - we use our own version
    stream_size: i32
) -> i32 {
    unsafe { inflateInit2_(strm, 15, ZLIB_VERSION.as_ptr(), stream_size) }
}

/// Passthrough to libz-rs inflate function
unsafe extern "C" fn hook_inflate(strm: z_streamp, flush: i32) -> i32 {
    unsafe { inflate(strm, flush) }
}

/// Passthrough to libz-rs inflateEnd function
unsafe extern "C" fn hook_inflate_end(strm: z_streamp) -> i32 {
    unsafe { inflateEnd(strm) }
}

/// Install zlib patches for Fallout: New Vegas or GECK Editor
///
/// This function patches the game's or editor's zlib calls to use a modern zlib
/// implementation (libz-rs). It replaces CALL instructions at hardcoded addresses
/// to redirect to our hook functions.
///
/// When running in GECK Editor mode, additional patches are applied to disable
/// compression for TESNPC and TESObjectLAND records.
///
/// # Safety
/// This performs direct memory patching of the executable and should only be called
/// during plugin initialization.
pub fn install_zlib_hooks(nvse: &NVSEInterface) -> anyhow::Result<()> {
    let is_editor = nvse.isEditor != 0;

    if is_editor {
        log::info!("[ZLIB] Installing zlib patches for GECK Editor");

        // Patch inflateInit calls
        for addr in EDITOR_INFLATE_INIT_EX_ADDRS {
            unsafe {
                replace_call(addr as *mut c_void, hook_inflate_init_ex as *mut c_void)?;
            }
        }

        // Patch inflate calls
        for addr in EDITOR_INFLATE_ADDRS {
            unsafe {
                replace_call(addr as *mut c_void, hook_inflate as *mut c_void)?;
            }
        }

        // Patch inflateEnd calls
        for addr in EDITOR_INFLATE_END_ADDRS {
            unsafe {
                replace_call(addr as *mut c_void, hook_inflate_end as *mut c_void)?;
            }
        }

        // Update allocation size to accommodate larger zlib structures
        safe_write_16(EDITOR_ALLOC_SIZE_ADDR as *mut c_void, ZLIB_ALLOC_SIZE)?;

        // Disable TESNPC record compression in editor
        unsafe {
            patch_memory_nop(EDITOR_TESNPC_COMPRESSION_ADDR as *mut c_void, 5)?;
            safe_write_8(EDITOR_TESNPC_COMPRESSION_ADDR as *mut c_void, 0x00)?;
        }

        // Disable TESObjectLAND compression in editor
        unsafe {
            patch_memory_nop(EDITOR_TESLAND_COMPRESSION_ADDR as *mut c_void, 5)?;
        }

        log::info!("[ZLIB] Successfully installed all GECK Editor patches");
    } else {
        log::info!("[ZLIB] Installing zlib patches for Fallout: New Vegas");

        // Patch inflateInit calls
        for addr in GAME_INFLATE_INIT_EX_ADDRS {
            unsafe {
                replace_call(addr as *mut c_void, hook_inflate_init_ex as *mut c_void)?;
            }
        }

        // Patch inflate calls
        for addr in GAME_INFLATE_ADDRS {
            unsafe {
                replace_call(addr as *mut c_void, hook_inflate as *mut c_void)?;
            }
        }

        // Patch inflateEnd calls
        for addr in GAME_INFLATE_END_ADDRS {
            unsafe {
                replace_call(addr as *mut c_void, hook_inflate_end as *mut c_void)?;
            }
        }

        // Update allocation size to accommodate larger zlib structures
        safe_write_16(GAME_ALLOC_SIZE_ADDR as *mut c_void, ZLIB_ALLOC_SIZE)?;

        log::info!("[ZLIB] Successfully installed all zlib patches");
    }

    Ok(())
}
