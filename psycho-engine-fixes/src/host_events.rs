//! Event ABI for late host adapters.
//!
//! `psycho-engine-fixes-helper` translates xNVSE messages into this small ABI.
//! Keep it independent from xNVSE types so the core DLL remains loader-driven.

use crate::mods::{
    engine_fixes::observe_event as observe_engine_fix_event,
    perf::observe_event as observe_perf_event,
};

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_NotifyEvent(
    kind: u32,
    data: *const u8,
    data_len: usize,
    bool_value: i32,
) -> i32 {
    if !crate::entry::is_initialized() {
        return 0;
    }

    with_event_path(data, data_len, |path| {
        observe_perf_event(kind, path, bool_value);
        observe_engine_fix_event(kind);
    });

    if kind == crate::events::DEFERRED_INIT {
        log::info!("[EVENT] Game engine ready");
    }

    1
}

fn with_event_path(data: *const u8, data_len: usize, f: impl FnOnce(Option<&str>)) {
    if data.is_null() || data_len == 0 {
        f(None);
        return;
    }

    // The helper passes borrowed message bytes only for the duration of this
    // call. Observers must consume the string immediately and never store it.
    let bytes = unsafe { std::slice::from_raw_parts(data, data_len) };
    f(std::str::from_utf8(bytes).ok());
}
