//! Late-bound ABI calls into `psycho_engine_fixes.dll`.
//!
//! The helper is loaded by xNVSE after the game is already running. It must not
//! load or initialize the core DLL. Every call below is optional and resolves a
//! single named export only when the helper actually needs it.

use core::sync::atomic::{AtomicUsize, Ordering};

use libpsycho::os::windows::winapi::{get_module_handle_w, get_proc_address};

const CORE_DLL: &str = "psycho_engine_fixes.dll";
const RUN_COMMAND_EXPORT: &str = "PsychoEngineFixes_RunCommand";
const NOTIFY_EVENT_EXPORT: &str = "PsychoEngineFixes_NotifyEvent";

// These ids mirror `psycho-engine-fixes/src/events.rs`.
pub(crate) const EVENT_DEFERRED_INIT: u32 = 1;
pub(crate) const EVENT_PRE_LOAD_GAME: u32 = 2;
pub(crate) const EVENT_LOAD_GAME: u32 = 3;
pub(crate) const EVENT_POST_LOAD_GAME: u32 = 4;
pub(crate) const EVENT_MAIN_GAME_LOOP: u32 = 5;
pub(crate) const EVENT_ON_FRAME_PRESENT: u32 = 6;

// These ids mirror `psycho-engine-fixes/src/command_api.rs`.
pub(crate) const COMMAND_INFO: u32 = 1;

type RunCommandFn = unsafe extern "system" fn(command: u32, output: *mut CommandOutput) -> i32;
type NotifyEventFn =
    unsafe extern "system" fn(kind: u32, data: *const u8, data_len: usize, bool_value: i32) -> i32;

static RUN_COMMAND: AtomicUsize = AtomicUsize::new(0);
static NOTIFY_EVENT: AtomicUsize = AtomicUsize::new(0);

/// Output buffer contract for `PsychoEngineFixes_RunCommand`.
///
/// The caller owns `text`; the core copies bytes into it and reports the full
/// wanted length through `written`. No heap object crosses the DLL boundary.
#[repr(C)]
pub(crate) struct CommandOutput {
    pub text: *mut u8,
    pub text_len: usize,
    pub written: usize,
    pub result: f64,
    pub flags: u32,
}

/// Run a command in the core DLL if it is already loaded and initialized.
pub(crate) fn run_command(command: u32, output: &mut CommandOutput) -> bool {
    let Some(function) = resolve_run_command() else {
        return false;
    };

    unsafe { function(command, output) != 0 }
}

/// Forward an xNVSE lifecycle event to the core DLL if it is available.
pub(crate) fn notify_event(kind: u32, data: *const u8, data_len: usize, bool_value: i32) -> bool {
    let Some(function) = resolve_notify_event() else {
        return false;
    };

    unsafe { function(kind, data, data_len, bool_value) != 0 }
}

fn resolve_run_command() -> Option<RunCommandFn> {
    let ptr = resolve_cached(&RUN_COMMAND, RUN_COMMAND_EXPORT)?;

    // SAFETY: The export name is owned by psycho_engine_fixes.dll and the
    // function signature is the ABI contract in psycho_engine_fixes.def.
    Some(unsafe { core::mem::transmute::<usize, RunCommandFn>(ptr) })
}

fn resolve_notify_event() -> Option<NotifyEventFn> {
    let ptr = resolve_cached(&NOTIFY_EVENT, NOTIFY_EVENT_EXPORT)?;

    // SAFETY: The export name is owned by psycho_engine_fixes.dll and the
    // function signature is the ABI contract in psycho_engine_fixes.def.
    Some(unsafe { core::mem::transmute::<usize, NotifyEventFn>(ptr) })
}

fn resolve_cached(cache: &AtomicUsize, export_name: &str) -> Option<usize> {
    let cached = cache.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached);
    }

    // Use GetModuleHandle only. If the core was not loaded by psycho-loader,
    // the helper must stay passive instead of loading it from the xNVSE path.
    let module = get_module_handle_w(Some(CORE_DLL)).ok()?;
    let proc = get_proc_address(module, export_name).ok()? as usize;

    cache.store(proc, Ordering::Release);
    Some(proc)
}
