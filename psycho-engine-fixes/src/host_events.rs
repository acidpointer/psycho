//! Event ABI for late host adapters.
//!
//! `psycho-engine-fixes-helper` translates xNVSE messages into this small ABI.
//! Keep it independent from xNVSE types so the core DLL remains loader-driven.

use crate::mods::engine_fixes::observe_event as observe_engine_fix_event;

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_NotifyEvent(
    kind: u32,
    _data: *const u8,
    _data_len: usize,
    _bool_value: i32,
) -> i32 {
    if !crate::entry::is_initialized() {
        return 0;
    }

    observe_engine_fix_event(kind);

    if kind == crate::events::DEFERRED_INIT {
        log::info!("[EVENT] Game engine ready");
    }

    1
}
