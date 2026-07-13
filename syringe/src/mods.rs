//! Root `syringe/*.dll` discovery and initialization.
//!
//! The loader is mod-agnostic: every DLL directly under `<game root>/syringe` is
//! loaded in deterministic case-insensitive filename order. Initialization is
//! two-phase: every optional `Syringe_ModInit` runs first, then every optional
//! `Syringe_ModActivate`. Both run outside DLL loader-lock callbacks.

use core::ffi::c_void;
use core::mem::transmute;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

use syringe_api::{SyringeInfo, SyringeModActivateFn, SyringeModInitFn};

use crate::wide_path::WidePath;
use crate::win32::{self, FindHandle, HModule, Win32FindDataW};

const MOD_INIT_EXPORT: &[u8] = b"Syringe_ModInit\0";
const MOD_ACTIVATE_EXPORT: &[u8] = b"Syringe_ModActivate\0";

const MODS_NOT_STARTED: u8 = 0;
const MODS_LOADING: u8 = 1;
const MODS_READY: u8 = 2;
const MODS_FAILED: u8 = 3;

// This state owns discovery. The barrier and fallback worker must never run a
// loader pass at the same time.
static MODS_LOAD_STATE: AtomicU8 = AtomicU8::new(MODS_NOT_STARTED);
static LOADER_INFO_FLAGS: AtomicU32 = AtomicU32::new(0);
// Passed to `Syringe_ModInit` so loaded mods can identify the proxy DLL.
static LOADER_MODULE: AtomicUsize = AtomicUsize::new(0);

/// Save the proxy module handle supplied to `DllMain` for callback metadata.
pub fn remember_loader_module(module: HModule) {
    LOADER_MODULE.store(module as usize, Ordering::Release);
}

/// Start the non-blocking compatibility path if no loader pass owns startup.
///
/// This is called from process attach only when the executable barrier could
/// not be installed. The new thread may wait for loader lock, but DllMain never
/// waits for the thread.
pub fn start_loader_thread() {
    if MODS_LOAD_STATE
        .compare_exchange(
            MODS_NOT_STARTED,
            MODS_LOADING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }

    // The worker is not a proven pre-CRT boundary. Store this before spawning
    // so a fast worker cannot publish the wrong capability to loaded mods.
    LOADER_INFO_FLAGS.store(0, Ordering::Release);
    if !win32::spawn_thread(mod_loader_thread) {
        MODS_LOAD_STATE.store(MODS_FAILED, Ordering::Release);
    }
}

/// Complete discovery synchronously at the executable's pre-CRT barrier.
///
/// Only the thread that wins the state transition may publish the pre-CRT
/// flag. If an unusually early proxy call already started the fallback worker,
/// allocator replacement stays disabled rather than claiming false ordering.
pub fn load_mods_at_pre_crt_barrier() {
    if MODS_LOAD_STATE
        .compare_exchange(
            MODS_NOT_STARTED,
            MODS_LOADING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }

    LOADER_INFO_FLAGS.store(syringe_api::SYRINGE_INFO_PRE_CRT_BARRIER, Ordering::Release);
    load_all_mods();
}

unsafe extern "system" fn mod_loader_thread(_parameter: *mut c_void) -> u32 {
    load_all_mods();
    0
}

fn load_all_mods() {
    crate::dinput8::preload();
    load_mod_dlls();
    MODS_LOAD_STATE.store(MODS_READY, Ordering::Release);
}

fn load_mod_dlls() -> usize {
    let loaded = visit_mod_dlls(ModPhase::Load);
    visit_mod_dlls(ModPhase::Initialize);
    visit_mod_dlls(ModPhase::Activate);
    loaded
}

#[derive(Clone, Copy)]
enum ModPhase {
    Load,
    Initialize,
    Activate,
}

fn visit_mod_dlls(phase: ModPhase) -> usize {
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

        let module = match phase {
            ModPhase::Load => load_mod_library(&path),
            ModPhase::Initialize | ModPhase::Activate => {
                let loaded = win32::loaded_module(&path);
                if loaded.is_null() {
                    load_mod_library(&path)
                } else {
                    loaded
                }
            }
        };
        if module.is_null() {
            if !matches!(phase, ModPhase::Load) {
                win32::debug_message(b"[Syringe] Loaded mod disappeared before callback.\n");
            }
            continue;
        }
        match phase {
            ModPhase::Load => loaded = loaded.saturating_add(1),
            ModPhase::Initialize => {
                call_mod_init(module);
            }
            ModPhase::Activate => {
                call_mod_activate(module);
            }
        }
    }

    loaded
}

fn call_mod_activate(module: HModule) -> bool {
    let proc = win32::get_proc_address(module, MOD_ACTIVATE_EXPORT);
    if proc.is_null() {
        return true;
    }

    let loader_module = LOADER_MODULE.load(Ordering::Acquire);
    let info = loader_info(loader_module, module);
    let activate: SyringeModActivateFn = unsafe { transmute(proc) };
    let activated = unsafe { activate(&info) != 0 };
    if !activated {
        win32::debug_message(b"[Syringe] Syringe_ModActivate returned failure.\n");
    }
    activated
}

fn call_mod_init(module: HModule) -> bool {
    let proc = win32::get_proc_address(module, MOD_INIT_EXPORT);
    if proc.is_null() {
        return true;
    }

    let loader_module = LOADER_MODULE.load(Ordering::Acquire);
    let info = loader_info(loader_module, module);
    let init: SyringeModInitFn = unsafe { transmute(proc) };
    let initialized = unsafe { init(&info) != 0 };
    if !initialized {
        win32::debug_message(b"[Syringe] Syringe_ModInit returned failure.\n");
    }
    initialized
}

fn loader_info(loader_module: usize, module: HModule) -> SyringeInfo {
    SyringeInfo::new(loader_module, module as usize)
        .with_flags(LOADER_INFO_FLAGS.load(Ordering::Acquire))
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
