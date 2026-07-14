//! Remove dying NiSourceTextures from the engine cache at their ownership root.
//!
//! `FUN_00A61F30` is the engine's targeted removal operation. It takes the
//! recursive texture-cache lock, finds the texture across all seven inner
//! tables, removes the outer key mapping, unlinks the inner node, and releases
//! its cache reference. Running it before the destructor prevents stale roots
//! without a lookup-side dead set or per-frame maintenance.

use std::cell::Cell;

use libc::c_void;
use libpsycho::ffi::fnptr::FnPtr;

use super::statics;

const TEXTURE_CACHE_REMOVE_ADDR: usize = 0x00A61F30;

type TextureCacheRemoveFn = unsafe extern "C" fn(*mut c_void) -> u8;

thread_local! {
    static UNLINKING_TEXTURE: Cell<*mut c_void> = const { Cell::new(core::ptr::null_mut()) };
    static ORIGINAL_RAN_DURING_UNLINK: Cell<bool> = const { Cell::new(false) };
}

pub unsafe extern "fastcall" fn hook_nisourcetexture_dtor(this: *mut c_void) {
    let reentered = UNLINKING_TEXTURE.with(|active| active.get() == this && !this.is_null());
    if reentered {
        ORIGINAL_RAN_DURING_UNLINK.with(|ran| ran.set(true));
        call_original(this);
        return;
    }

    let original_ran = if this.is_null() {
        false
    } else {
        UNLINKING_TEXTURE.with(|active| active.set(this));
        ORIGINAL_RAN_DURING_UNLINK.with(|ran| ran.set(false));
        let remove = unsafe {
            FnPtr::<TextureCacheRemoveFn>::from_address_unchecked(TEXTURE_CACHE_REMOVE_ADDR)
        };
        unsafe { remove.as_fn()(this) };
        UNLINKING_TEXTURE.with(|active| active.set(core::ptr::null_mut()));
        ORIGINAL_RAN_DURING_UNLINK.with(Cell::get)
    };

    if !original_ran {
        call_original(this);
    }
}

fn call_original(this: *mut c_void) {
    if let Ok(original) = statics::NISOURCETEXTURE_DTOR_HOOK.original() {
        unsafe { original(this) };
    }
}
