use libc::c_void;
use std::ptr::null_mut;

/// Game's scrap heap structure.
/// Must match the game's struct layout exactly.
#[repr(C)]
pub struct SheapStruct {
    blocks: *mut *mut c_void, // 0x00
    cur: *mut c_void,         // 0x04
    last: *mut c_void,        // 0x08
}

impl SheapStruct {
    pub const fn new_nulled() -> Self {
        Self {
            blocks: null_mut(),
            cur: null_mut(),
            last: null_mut(),
        }
    }
}
