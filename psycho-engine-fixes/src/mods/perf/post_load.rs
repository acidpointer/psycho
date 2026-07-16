//! Successful-load reconciliation prepass.
//!
//! The normal first rendered frame runs process-manager reconciliation after
//! load completion. Running that same reconciler once before the top-level load
//! owner returns drains the backlog while the loading transition is still active.

use std::sync::{
    LazyLock,
    atomic::{AtomicU64, Ordering},
};

use libc::c_void;

use libpsycho::{ffi::fnptr::FnPtr, os::windows::hook::inline::inlinehook::InlineHookContainer};

use crate::mods::diagnostics;

const TOP_LEVEL_LOAD_ADDR: usize = 0x00850760;
const PROCESS_RECONCILE_ADDR: usize = 0x00455490;
const PROCESS_CONTEXT_ADDR: usize = 0x011DEA10;

type TopLevelLoadFn = unsafe extern "thiscall" fn(*mut c_void, *const c_void, u32, u8, u8) -> u8;
type ProcessReconcileFn = unsafe extern "fastcall" fn(*mut c_void);

static TOP_LEVEL_LOAD_HOOK: LazyLock<InlineHookContainer<TopLevelLoadFn>> =
    LazyLock::new(InlineHookContainer::new);
static PREPASSES: AtomicU64 = AtomicU64::new(0);
static PREPASS_MAX_US: AtomicU64 = AtomicU64::new(0);

pub fn install_post_load_reconciliation_prepass() -> anyhow::Result<()> {
    unsafe {
        TOP_LEVEL_LOAD_HOOK.init(
            "post_load_reconciliation_prepass",
            TOP_LEVEL_LOAD_ADDR as *mut c_void,
            hook_top_level_load,
        )
    }?;
    TOP_LEVEL_LOAD_HOOK.enable()?;
    log::info!(
        "[POST_LOAD] Reconciliation prepass active: load_owner=0x{:08X}",
        TOP_LEVEL_LOAD_ADDR,
    );
    Ok(())
}

unsafe extern "thiscall" fn hook_top_level_load(
    this: *mut c_void,
    path: *const c_void,
    load_context: u32,
    save_history: u8,
    allow_missing: u8,
) -> u8 {
    let Ok(original) = TOP_LEVEL_LOAD_HOOK.original() else {
        return 0;
    };

    let succeeded = unsafe { original(this, path, load_context, save_history, allow_missing) };
    if succeeded == 0 {
        return succeeded;
    }

    let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
    let process_context =
        unsafe { core::ptr::read_volatile(PROCESS_CONTEXT_ADDR as *const *mut c_void) };
    let reconcile =
        unsafe { FnPtr::<ProcessReconcileFn>::from_address_unchecked(PROCESS_RECONCILE_ADDR) }
            .as_fn();
    unsafe { reconcile(process_context) };

    let count = PREPASSES.fetch_add(1, Ordering::Relaxed) + 1;
    if let Some(elapsed_us) = timer.elapsed_us() {
        diagnostics::update_max_u64(&PREPASS_MAX_US, elapsed_us);
        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                "[POST_LOAD] reconciliation_prepass_us={} max_us={} total={}",
                elapsed_us,
                PREPASS_MAX_US.load(Ordering::Relaxed),
                count,
            );
        }
    }

    succeeded
}
