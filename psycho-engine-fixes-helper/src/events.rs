//! xNVSE message translation for the core DLL.
//!
//! The core DLL should not depend on xNVSE. This module converts xNVSE message
//! shapes into the tiny numeric event contract accepted by
//! `PsychoEngineFixes_NotifyEvent`.

use core::ptr;

use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};

use crate::engine_fixes;

struct CoreEvent<'a> {
    kind: u32,
    path: Option<&'a str>,
    bool_value: i32,
}

pub(crate) fn forward_to_engine_fixes(msg: &NVSEMessage) {
    let Some(event) = CoreEvent::from_nvse(msg) else {
        return;
    };

    let (data, data_len) = event
        .path
        .map(|path| (path.as_ptr(), path.len()))
        .unwrap_or((ptr::null(), 0));

    let _ = engine_fixes::notify_event(event.kind, data, data_len, event.bool_value);
}

impl<'a> CoreEvent<'a> {
    fn from_nvse(msg: &'a NVSEMessage) -> Option<Self> {
        let kind = event_kind(msg.get_type())?;

        Some(Self {
            kind,
            path: event_path(kind, msg),
            bool_value: event_bool(kind, msg),
        })
    }
}

fn event_kind(kind: NVSEMessageType) -> Option<u32> {
    match kind {
        NVSEMessageType::DeferredInit => Some(engine_fixes::EVENT_DEFERRED_INIT),
        NVSEMessageType::PreLoadGame => Some(engine_fixes::EVENT_PRE_LOAD_GAME),
        NVSEMessageType::LoadGame => Some(engine_fixes::EVENT_LOAD_GAME),
        NVSEMessageType::PostLoadGame => Some(engine_fixes::EVENT_POST_LOAD_GAME),
        NVSEMessageType::MainGameLoop => Some(engine_fixes::EVENT_MAIN_GAME_LOOP),
        NVSEMessageType::OnFramePresent => Some(engine_fixes::EVENT_ON_FRAME_PRESENT),
        _ => None,
    }
}

fn event_path(kind: u32, msg: &NVSEMessage) -> Option<&str> {
    // Only these messages carry C-string save paths. Other xNVSE messages can
    // use the data pointer as an integer payload; decoding them as strings can
    // dereference addresses like 0x1.
    match kind {
        engine_fixes::EVENT_PRE_LOAD_GAME | engine_fixes::EVENT_LOAD_GAME => msg.data_as_path(),
        _ => None,
    }
}

fn event_bool(kind: u32, msg: &NVSEMessage) -> i32 {
    if kind != engine_fixes::EVENT_POST_LOAD_GAME {
        return -1;
    }

    // PostLoadGame stores success as a pointer-sized boolean value, not as a
    // pointer to a bool. Avoid data_as_bool() here because older xNVSE builds
    // may not set a useful data length for this payload.
    let (data, _) = msg.raw_data();
    match data as usize {
        0 => 0,
        1 => 1,
        _ => -1,
    }
}
