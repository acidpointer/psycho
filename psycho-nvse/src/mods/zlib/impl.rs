use std::ffi::CStr;

use libc::c_void;
use libnvse::NVSEInterface;
use libpsycho::os::windows::winapi::{replace_call, safe_write_16};
use libz_rs_sys::{inflate, inflateEnd, inflateInit2_, z_streamp};

/// Zlib version string passed to inflateInit2_
static ZLIB_VERSION: &CStr = c"1.3.1";

/// Increased allocation size for zlib decompression buffers
const ZLIB_ALLOC_SIZE: u16 = 0x1C08;

// Fallout: New Vegas runtime addresses (NOT GECK editor addresses!)
// These addresses are specific to the game executable and point to CALL instructions
// that need to be redirected to our custom zlib implementation.

/// Addresses of inflateInit calls in the game
const GAME_INFLATE_INIT_EX_ADDRS: [usize; 2] = [0x4742AC, 0xAFC537];

/// Addresses of inflate calls in the game
const GAME_INFLATE_ADDRS: [usize; 2] = [0x47434F, 0xAFC1F4];

/// Addresses of inflateEnd calls in the game
const GAME_INFLATE_END_ADDRS: [usize; 7] = [
    0x4742CA, 0x474388, 0x4743D5, 0x474419,
    0xAFC00E, 0xAFC21B, 0xAFC552
];

/// Address where allocation size needs to be patched
const GAME_ALLOC_SIZE_ADDR: usize = 0xAFC4A2;

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

/// Install zlib patches for Fallout: New Vegas
///
/// This function patches the game's zlib calls to use a modern zlib implementation (libz-rs).
/// It replaces CALL instructions at hardcoded addresses to redirect to our hook functions.
///
/// # Safety
/// This performs direct memory patching of the game executable and should only be called
/// during plugin initialization.
pub fn install_zlib_hooks(nvse: &NVSEInterface) -> anyhow::Result<()> {
    let is_geck_editor = nvse.isEditor != 0;

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
    Ok(())
}
