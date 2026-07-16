//! Remove dying NiSourceTextures from the engine cache at their ownership root.
//!
//! `FUN_00A61F30` is the engine's targeted removal operation. It takes the
//! recursive texture-cache lock, finds the texture across all seven inner
//! tables, removes the outer key mapping, unlinks the inner node, and releases
//! its cache reference. Destruction originating outside that lock runs the
//! removal before the destructor, preventing stale roots without lookup-side
//! checks or per-frame maintenance.

use std::cell::Cell;

use libc::c_void;
use libpsycho::ffi::fnptr::FnPtr;
use libpsycho::os::windows::winapi::get_current_thread_id;

use super::statics;

const TEXTURE_CACHE_REMOVE_ADDR: usize = 0x00A61F30;
const TEXTURE_CACHE_KEY_OFFSET: usize = 0x30;
const TEXTURE_CACHE_LOCK_OWNER_ADDR: usize = 0x011F4480;

type TextureCacheRemoveFn = unsafe extern "C" fn(*mut c_void) -> u8;

#[derive(Clone, Copy)]
struct UnlinkState {
    texture: *mut c_void,
    original_ran: bool,
}

const IDLE_UNLINK_STATE: UnlinkState = UnlinkState {
    texture: core::ptr::null_mut(),
    original_ran: false,
};

thread_local! {
    static UNLINK_STATE: Cell<UnlinkState> = const { Cell::new(IDLE_UNLINK_STATE) };
}

pub unsafe extern "fastcall" fn hook_nisourcetexture_dtor(this: *mut c_void) {
    if this.is_null() {
        return;
    }

    // Anonymous textures, including FaceGen render textures, have no cache
    // key and therefore cannot be present in the engine's keyed cache.
    let cache_key = unsafe {
        this.cast::<u8>()
            .add(TEXTURE_CACHE_KEY_OFFSET)
            .cast::<*const u8>()
            .read()
    };
    if cache_key.is_null() {
        call_original(this);
        return;
    }

    // Cache removal and full teardown release their texture references while
    // holding this recursive lock. The surrounding operation already owns the
    // node, so searching for and unlinking it again would duplicate the work.
    let lock_owner = unsafe { (TEXTURE_CACHE_LOCK_OWNER_ADDR as *const u32).read_volatile() };
    if lock_owner != 0 && lock_owner == get_current_thread_id() {
        UNLINK_STATE.with(|state| {
            let mut active = state.get();
            if active.texture == this {
                active.original_ran = true;
                state.set(active);
            }
        });
        call_original(this);
        return;
    }

    UNLINK_STATE.with(|state| {
        state.set(UnlinkState {
            texture: this,
            original_ran: false,
        });
    });
    let remove =
        unsafe { FnPtr::<TextureCacheRemoveFn>::from_address_unchecked(TEXTURE_CACHE_REMOVE_ADDR) };
    unsafe { remove.as_fn()(this) };
    let original_ran = UNLINK_STATE.with(|state| state.replace(IDLE_UNLINK_STATE).original_ran);

    if !original_ran {
        call_original(this);
    }
}

fn call_original(this: *mut c_void) {
    if let Ok(original) = statics::NISOURCETEXTURE_DTOR_HOOK.original() {
        unsafe { original(this) };
    }
}
