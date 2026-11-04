//! Event ABI for late host adapters.
//!
//! `psycho-engine-fixes-helper` translates xNVSE messages into this small ABI.
//! Keep it independent from xNVSE types so the core DLL remains loader-driven.
//! For presentation only, bool_value is 0 normal, 1 loading, -1 unknown. Other
//! subsystems retain their existing numeric event contract.

use crate::mods::{
    engine_fixes::observe_event as observe_engine_fix_event,
    perf::observe_event as observe_perf_event,
};

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_NotifyEvent(
    kind: u32,
    _data: *const u8,
    _data_len: usize,
    bool_value: i32,
) -> i32 {
    if !crate::entry::is_initialized() {
        return 0;
    }

    observe_engine_fix_event(kind);
    observe_perf_event(kind, bool_value);

    if kind == crate::events::DEFERRED_INIT {
        log::info!("[EVENT] Game engine ready");
    }

    1
}
