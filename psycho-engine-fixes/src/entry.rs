//! Loader entrypoint for `psycho_engine_fixes.dll`.
//!
//! `Syringe_ModInit` validates and prepares the DLL. `Syringe_ModActivate`
//! performs setup after every Syringe mod has initialized. xNVSE helper
//! callbacks must never initialize this DLL.

use core::{
    ffi::c_void,
    mem::size_of,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
};

use libpsycho::os::windows::winapi::{HModule, disable_thread_library_calls};
use syringe_api::{SYRINGE_API_VERSION, SYRINGE_INFO_PRE_CRT_BARRIER, SYRINGE_MAGIC, SyringeInfo};

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum InitState {
    NotStarted = 0,
    Running = 1,
    Done = 2,
    Failed = 3,
}

impl InitState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Done,
            3 => Self::Failed,
            _ => Self::NotStarted,
        }
    }
}

static INIT_STATE: AtomicU8 = AtomicU8::new(InitState::NotStarted as u8);
static CORE_MODULE: AtomicUsize = AtomicUsize::new(0);
static LOADER_FLAGS: AtomicUsize = AtomicUsize::new(0);

/// `syringe` mod initialization export.
///
/// Returning `0` tells the loader that validation failed. Engine setup is
/// deliberately deferred until every Syringe mod has initialized.
///
/// # Safety
///
/// `info` must point to a readable [`SyringeInfo`] for the duration of this
/// callback, as required by the Syringe ABI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Syringe_ModInit(info: *const SyringeInfo) -> i32 {
    if prepare_from_loader(info) { 1 } else { 0 }
}

/// Final activation callback after every Syringe mod has initialized.
///
/// The core activates only when this callback comes from the proven pre-CRT
/// barrier. The generic worker fallback cannot safely rewrite live game code.
///
/// # Safety
///
/// `info` must point to a readable [`SyringeInfo`] for the duration of this
/// callback, as required by the Syringe ABI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Syringe_ModActivate(info: *const SyringeInfo) -> i32 {
    if activate_from_loader(info) { 1 } else { 0 }
}

pub(crate) fn is_initialized() -> bool {
    current_state() == InitState::Done
}

pub(crate) fn has_pre_crt_startup_boundary() -> bool {
    LOADER_FLAGS.load(Ordering::Acquire) & SYRINGE_INFO_PRE_CRT_BARRIER as usize != 0
}

fn prepare_from_loader(info: *const SyringeInfo) -> bool {
    let Some((module, flags)) = validate_loader_info(info) else {
        return false;
    };

    // The core has no DllMain thread attach work. Disable those callbacks as
    // soon as the loader gives us the actual module handle.
    let _ = disable_thread_library_calls(module);

    let address = module.as_ptr() as usize;
    match CORE_MODULE.compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            LOADER_FLAGS.store(flags as usize, Ordering::Release);
            true
        }
        Err(existing) if existing == address => {
            LOADER_FLAGS.load(Ordering::Acquire) == flags as usize
        }
        Err(_) => false,
    }
}

fn activate_from_loader(info: *const SyringeInfo) -> bool {
    let Some((module, flags)) = validate_loader_info(info) else {
        return false;
    };
    if CORE_MODULE.load(Ordering::Acquire) != module.as_ptr() as usize {
        return false;
    }
    if LOADER_FLAGS.load(Ordering::Acquire) != flags as usize {
        return false;
    }
    // Every core feature patches executable game memory. The worker fallback
    // is useful to generic Syringe mods, but it cannot prove that Fallout's
    // main thread is still quiescent. Refuse the whole core rather than making
    // any code write against a potentially live process.
    if flags & SYRINGE_INFO_PRE_CRT_BARRIER == 0 {
        return false;
    }
    initialize_once()
}

fn validate_loader_info(info: *const SyringeInfo) -> Option<(HModule, u32)> {
    let info = unsafe { info.as_ref() }?;
    if info.magic != SYRINGE_MAGIC
        || info.version != SYRINGE_API_VERSION
        || info.size < size_of::<SyringeInfo>() as u32
        || info.mod_module == 0
    {
        return None;
    }

    let module = unsafe { HModule::new(info.mod_module as *mut c_void) }.ok()?;
    Some((module, info.flags))
}

fn initialize_once() -> bool {
    match current_state() {
        InitState::Done => return true,
        InitState::Failed => return false,
        InitState::Running => return wait_for_initialization(),
        InitState::NotStarted => {}
    }

    if INIT_STATE
        .compare_exchange(
            InitState::NotStarted as u8,
            InitState::Running as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return wait_for_initialization();
    }

    match crate::startup::initialize() {
        Ok(()) => {
            set_state(InitState::Done);
            true
        }
        Err(err) => {
            eprintln!("psycho: Failed to initialize engine fixes: {:?}", err);
            set_state(InitState::Failed);
            false
        }
    }
}

fn wait_for_initialization() -> bool {
    while current_state() == InitState::Running {
        std::thread::yield_now();
    }

    is_initialized()
}

fn current_state() -> InitState {
    InitState::from_u8(INIT_STATE.load(Ordering::Acquire))
}

fn set_state(state: InitState) {
    INIT_STATE.store(state as u8, Ordering::Release);
}
