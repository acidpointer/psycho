//! Root `mods/*.dll` discovery and initialization.
//!
//! The loader is mod-agnostic: every DLL directly under `<game root>/mods` is
//! loaded in deterministic case-insensitive filename order. A loaded DLL may
//! export `PsychoLoader_ModInit`; when present, we call it after `LoadLibrary`
//! returns so real initialization runs outside that DLL's loader-lock callback.

use core::cmp::Ordering as CmpOrdering;
use core::ffi::c_void;
use core::mem::transmute;
use core::sync::atomic::{AtomicUsize, Ordering};

use psycho_loader_api::{PsychoLoaderInfo, PsychoLoaderModInitFn};

use crate::wide_path::{WidePath, compare_case_insensitive};
use crate::win32::{self, FindHandle, HModule, Win32FindDataW};

const MAX_MOD_DLLS: usize = 96;
const MODS_LOAD_WAIT_TIMEOUT_MS: u32 = 10_000;
const MOD_INIT_EXPORT: &[u8] = b"PsychoLoader_ModInit\0";

// State encoding is intentionally atomic and allocation-free:
// 0 = not started, usize::MAX = loading, N + 1 = completed with N loaded mods.
const MODS_NOT_STARTED: usize = 0;
const MODS_LOADING: usize = usize::MAX;

// One-shot guard for the best-effort worker thread launched from TLS.
static MODS_THREAD_STARTED: AtomicUsize = AtomicUsize::new(0);
// Public lifecycle state for all callers that need early mods to be ready.
static MODS_LOAD_STATE: AtomicUsize = AtomicUsize::new(MODS_NOT_STARTED);
// Used only to detect same-thread reentry during `LoadLibrary` callbacks.
static MODS_LOADER_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
// Passed to `PsychoLoader_ModInit` so loaded mods can identify the proxy DLL.
static LOADER_MODULE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LoadStatus {
    Loaded(usize),
    Reentrant,
    TimedOut,
}

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

    // Creating a thread from TLS is acceptable here because we never wait for
    // it while the loader lock is held. The exported dinput8 functions provide
    // the synchronous fallback if the worker has not finished yet.
    if !win32::spawn_thread(mod_loader_thread) {
        MODS_THREAD_STARTED.store(0, Ordering::Release);
    }
}

pub fn ensure_loaded() -> LoadStatus {
    let wait_start = win32::tick_count();

    loop {
        match MODS_LOAD_STATE.load(Ordering::Acquire) {
            MODS_NOT_STARTED => {}
            MODS_LOADING => {
                // A reentrant call from the loader thread cannot wait on itself.
                // The proxy layer must not forward to real dinput8 from this
                // path; doing so can start another LoadLibrary chain while a
                // mod callback is already active.
                if MODS_LOADER_THREAD_ID.load(Ordering::Acquire)
                    == win32::current_thread_id() as usize
                {
                    return LoadStatus::Reentrant;
                }

                if win32::tick_count().wrapping_sub(wait_start) >= MODS_LOAD_WAIT_TIMEOUT_MS {
                    return LoadStatus::TimedOut;
                }

                win32::sleep(1);
                continue;
            }
            completed => return LoadStatus::Loaded(completed - 1),
        }

        if MODS_LOAD_STATE
            .compare_exchange(
                MODS_NOT_STARTED,
                MODS_LOADING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            MODS_LOADER_THREAD_ID.store(win32::current_thread_id() as usize, Ordering::Release);
            let loaded = load_mod_dlls();
            MODS_LOADER_THREAD_ID.store(0, Ordering::Release);
            MODS_LOAD_STATE.store(loaded.saturating_add(1), Ordering::Release);
            return LoadStatus::Loaded(loaded);
        }
    }
}

unsafe extern "system" fn mod_loader_thread(_parameter: *mut c_void) -> u32 {
    ensure_loaded();
    0
}

fn load_mod_dlls() -> usize {
    let dlls = mod_dll_paths();
    let mut loaded = 0usize;

    for dll in dlls.iter() {
        let module = load_mod_library(dll);
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
    let info = PsychoLoaderInfo::new(loader_module, module as usize);
    let init: PsychoLoaderModInitFn = unsafe { transmute(proc) };
    unsafe { init(&info) != 0 }
}

fn load_mod_library(path: &WidePath) -> HModule {
    // Prefer a DLL-directory-aware load so a mod can resolve its own sibling
    // DLLs. Fall back to plain LoadLibraryW for older Wine/Windows behavior.
    let module = win32::load_library_from_dll_dir(path);
    if !module.is_null() {
        return module;
    }

    win32::load_library(path)
}

struct ModDllList {
    len: usize,
    dlls: [WidePath; MAX_MOD_DLLS],
}

impl ModDllList {
    fn new() -> Self {
        Self {
            len: 0,
            dlls: [WidePath::new(); MAX_MOD_DLLS],
        }
    }

    fn push(&mut self, dll: WidePath) {
        if self.len >= self.dlls.len() {
            return;
        }

        self.dlls[self.len] = dll;
        self.len += 1;
    }

    fn iter(&self) -> core::slice::Iter<'_, WidePath> {
        self.dlls[..self.len].iter()
    }

    fn sort(&mut self) {
        for index in 1..self.len {
            let item = self.dlls[index];
            let mut cursor = index;

            while cursor > 0
                && compare_case_insensitive(&item, &self.dlls[cursor - 1]) == CmpOrdering::Less
            {
                self.dlls[cursor] = self.dlls[cursor - 1];
                cursor -= 1;
            }

            self.dlls[cursor] = item;
        }
    }
}

fn mod_dll_paths() -> ModDllList {
    let mut dlls = ModDllList::new();
    let mut mods = game_root();
    if mods.is_empty() || !mods.append_component_ascii("mods") {
        return dlls;
    }

    // Only the root `mods` directory is scanned. Subdirectories are ignored on
    // purpose so a mod manager can stage support files without auto-loading.
    let mut pattern = mods;
    if !pattern.append_component_ascii("*.dll") {
        return dlls;
    }

    let Some(pattern) = pattern.with_nul() else {
        return dlls;
    };

    let mut data = Win32FindDataW::empty();
    let Some(find) = FindHandle::first(&pattern, &mut data) else {
        return dlls;
    };

    loop {
        if !data.is_directory() {
            let name = data.file_name();
            if !name.is_empty() {
                let mut path = mods;
                if path.append_component_wide(name) {
                    dlls.push(path);
                }
            }
        }

        if !find.next(&mut data) {
            break;
        }
    }

    dlls.sort();
    dlls
}

fn game_root() -> WidePath {
    win32::process_module_file_name()
        .parent_directory()
        .unwrap_or_else(WidePath::new)
}
