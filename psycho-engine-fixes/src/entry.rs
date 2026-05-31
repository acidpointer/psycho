//! Loader entrypoint for `psycho_engine_fixes.dll`.
//!
//! The core DLL has one setup path: `PsychoLoader_ModInit`, called by
//! `psycho-loader` after the DLL is mapped and outside the mapped DLL's loader
//! callback. xNVSE helper callbacks must never initialize this DLL.

use core::{
    ffi::c_void,
    mem::size_of,
    sync::atomic::{AtomicU8, Ordering},
};

use libpsycho::os::windows::winapi::{HModule, disable_thread_library_calls};
use psycho_loader_api::{PSYCHO_LOADER_API_VERSION, PSYCHO_LOADER_MAGIC, PsychoLoaderInfo};

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

/// `psycho-loader` mod initialization export.
///
/// Returning `0` tells the loader that core setup failed. The loader still
/// continues with other mods; this DLL just stays unavailable to the helper.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoLoader_ModInit(info: *const PsychoLoaderInfo) -> i32 {
    if initialize_from_loader(info) { 1 } else { 0 }
}

pub(crate) fn is_initialized() -> bool {
    current_state() == InitState::Done
}

fn initialize_from_loader(info: *const PsychoLoaderInfo) -> bool {
    let Some(module) = validate_loader_info(info) else {
        return false;
    };

    // The core has no DllMain thread attach work. Disable those callbacks as
    // soon as the loader gives us the actual module handle.
    let _ = disable_thread_library_calls(module);

    initialize_once()
}

fn validate_loader_info(info: *const PsychoLoaderInfo) -> Option<HModule> {
    let info = unsafe { info.as_ref() }?;
    if info.magic != PSYCHO_LOADER_MAGIC
        || info.version != PSYCHO_LOADER_API_VERSION
        || info.size < size_of::<PsychoLoaderInfo>() as u32
        || info.mod_module == 0
    {
        return None;
    }

    unsafe { HModule::new(info.mod_module as *mut c_void) }.ok()
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
