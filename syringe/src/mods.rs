//! Root `syringe/*.dll` discovery and initialization.
//!
//! The loader is mod-agnostic: every DLL directly under `<game root>/syringe` is
//! loaded in deterministic case-insensitive filename order. A loaded DLL may
//! export `Syringe_ModInit`; when present, we call it after `LoadLibrary`
//! returns so real initialization runs outside that DLL's loader-lock callback.

use core::ffi::c_void;
use core::mem::transmute;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use syringe_api::{SyringeInfo, SyringeModInitFn};

use crate::wide_path::WidePath;
use crate::win32::{self, FindHandle, HModule, Win32FindDataW};

const MOD_INIT_EXPORT: &[u8] = b"Syringe_ModInit\0";

const MODS_NOT_STARTED: u8 = 0;
const MODS_LOADING: u8 = 1;
const MODS_READY: u8 = 2;
const MODS_FAILED: u8 = 3;

// One-shot guard for the worker launched from DllMain.
static MODS_THREAD_STARTED: AtomicUsize = AtomicUsize::new(0);
// Worker lifecycle is diagnostic only. Proxy exports must not synchronize on it.
static MODS_LOAD_STATE: AtomicU8 = AtomicU8::new(MODS_NOT_STARTED);
// Passed to `Syringe_ModInit` so loaded mods can identify the proxy DLL.
static LOADER_MODULE: AtomicUsize = AtomicUsize::new(0);

pub fn remember_loader_module(module: HModule) {
    LOADER_MODULE.store(module as usize, Ordering::Release);
}

pub fn start_loader_thread() {
    if MODS_THREAD_STARTED
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    MODS_LOAD_STATE.store(MODS_LOADING, Ordering::Release);
    if !win32::spawn_thread(mod_loader_thread) {
        MODS_LOAD_STATE.store(MODS_FAILED, Ordering::Release);
    }
}

unsafe extern "system" fn mod_loader_thread(_parameter: *mut c_void) -> u32 {
    crate::dinput8::preload();
    load_mod_dlls();
    MODS_LOAD_STATE.store(MODS_READY, Ordering::Release);
    0
}

fn load_mod_dlls() -> usize {
    let mut mods = game_root();
    if mods.is_empty() || !mods.append_component_ascii("syringe") {
        return 0;
    }

    let mut pattern = mods;
    if !pattern.append_component_ascii("*.dll") {
        win32::debug_message(b"[Syringe] Mod search path is too long.\n");
        return 0;
    }
    let mut loaded = 0usize;
    let mut previous = None;

    loop {
        let path = match next_mod_path(&mods, &pattern, previous.as_ref()) {
            Ok(Some(path)) => path,
            Ok(None) => break,
            Err(error) => {
                win32::debug_error(b"[Syringe] DLL enumeration failed: ", error);
                break;
            }
        };
        previous = Some(path);

        let module = load_mod_library(&path);
        if !module.is_null() && call_mod_init(module) {
            loaded = loaded.saturating_add(1);
        }
    }

    loaded
}

fn call_mod_init(module: HModule) -> bool {
    let proc = win32::get_proc_address(module, MOD_INIT_EXPORT);
    if proc.is_null() {
        return true;
    }

    let loader_module = LOADER_MODULE.load(Ordering::Acquire);
    let info = SyringeInfo::new(loader_module, module as usize);
    let init: SyringeModInitFn = unsafe { transmute(proc) };
    let initialized = unsafe { init(&info) != 0 };
    if !initialized {
        win32::debug_message(b"[Syringe] Syringe_ModInit returned failure.\n");
    }
    initialized
}

fn load_mod_library(path: &WidePath) -> HModule {
    match win32::load_library_from_dll_dir(path) {
        Ok(module) => module,
        Err(error) => {
            win32::debug_error(b"[Syringe] Secure DLL load failed: ", error);
            core::ptr::null_mut()
        }
    }
}

/// Re-scan the directory to select one next filename without a heap allocation
/// or a fixed mod-count limit. Startup enumeration is intentionally cold.
fn next_mod_path(
    mods: &WidePath,
    pattern: &WidePath,
    previous: Option<&WidePath>,
) -> Result<Option<WidePath>, u32> {
    let mut data = Win32FindDataW::empty();
    let Some(find) = FindHandle::first(pattern, &mut data)? else {
        return Ok(None);
    };

    let mut next = None;

    loop {
        if !data.is_directory() {
            let name = data.file_name();
            if !name.is_empty() {
                let mut path = *mods;
                if path.append_component_wide(name) {
                    let after_previous =
                        previous.is_none_or(|last| compare_paths(&path, last).is_gt());
                    let before_next = next
                        .as_ref()
                        .is_none_or(|candidate| compare_paths(&path, candidate).is_lt());
                    if after_previous && before_next {
                        next = Some(path);
                    }
                } else {
                    win32::debug_message(b"[Syringe] Ignored DLL with an overlong path.\n");
                }
            }
        }

        if !find.next(&mut data)? {
            return Ok(next);
        }
    }
}

fn compare_paths(left: &WidePath, right: &WidePath) -> core::cmp::Ordering {
    let case_folded = win32::compare_paths(left, right, true);
    if case_folded.is_eq() {
        win32::compare_paths(left, right, false)
    } else {
        case_folded
    }
}

fn game_root() -> WidePath {
    win32::process_module_file_name()
        .parent_directory()
        .unwrap_or_else(WidePath::new)
}
