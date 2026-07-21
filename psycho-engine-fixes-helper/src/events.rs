//! xNVSE message translation for the core DLL.
//!
//! The core DLL should not depend on xNVSE. This module converts xNVSE message
//! shapes into the tiny numeric event contract accepted by
//! `PsychoEngineFixes_NotifyEvent`.

use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};

use crate::dashboard;
use crate::engine_fixes;

pub(crate) fn forward_to_engine_fixes(msg: &NVSEMessage) {
    if let Some(kind) = event_kind(msg.get_type()) {
        let _ = engine_fixes::notify_event(kind, core::ptr::null(), 0, -1);
    }

    match msg.get_type() {
        NVSEMessageType::DeferredInit => dashboard::deferred_init(),
        NVSEMessageType::OnFramePresent => dashboard::on_frame_present(),
        _ => {}
    }
}

fn event_kind(kind: NVSEMessageType) -> Option<u32> {
    match kind {
        NVSEMessageType::DeferredInit => Some(engine_fixes::EVENT_DEFERRED_INIT),
        NVSEMessageType::OnFramePresent => Some(engine_fixes::EVENT_ON_FRAME_PRESENT),
        _ => None,
    }
}
