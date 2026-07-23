//! xNVSE message translation for the core DLL.
//!
//! The core DLL should not depend on xNVSE. This module converts xNVSE message
//! shapes into the tiny numeric event contract accepted by
//! `PsychoEngineFixes_NotifyEvent`.

use core::sync::atomic::{AtomicBool, Ordering};

use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};

use crate::dashboard;
use crate::engine_fixes;

static DEFERRED_INIT_FORWARDED: AtomicBool = AtomicBool::new(false);

pub(crate) fn forward_to_engine_fixes(msg: &NVSEMessage) {
    let message_type = msg.get_type();
    if should_forward_event(
        message_type,
        DEFERRED_INIT_FORWARDED.load(Ordering::Acquire),
    ) && let Some(kind) = event_kind(message_type)
    {
        let _ = engine_fixes::notify_event(kind, core::ptr::null(), 0, -1);
    }
    if message_type == NVSEMessageType::DeferredInit {
        DEFERRED_INIT_FORWARDED.store(true, Ordering::Release);
    }

    match message_type {
        NVSEMessageType::DeferredInit => dashboard::deferred_init(),
        NVSEMessageType::OnFramePresent => dashboard::on_frame_present(),
        _ => {}
    }
}

fn event_kind(kind: NVSEMessageType) -> Option<u32> {
    match kind {
        NVSEMessageType::DeferredInit => Some(engine_fixes::EVENT_DEFERRED_INIT),
        NVSEMessageType::OnFramePresent => Some(engine_fixes::EVENT_ON_FRAME_PRESENT),
        NVSEMessageType::PreLoadGame => Some(engine_fixes::EVENT_PRE_LOAD_GAME),
        NVSEMessageType::ExitToMainMenu => Some(engine_fixes::EVENT_EXIT_TO_MAIN_MENU),
        NVSEMessageType::NewGame => Some(engine_fixes::EVENT_NEW_GAME),
        _ => None,
    }
}

fn should_forward_event(kind: NVSEMessageType, deferred_ready: bool) -> bool {
    deferred_ready
        || !matches!(
            kind,
            NVSEMessageType::PreLoadGame
                | NVSEMessageType::ExitToMainMenu
                | NVSEMessageType::NewGame
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn world_lifetime_messages_reach_the_core_barrier() {
        assert_eq!(
            event_kind(NVSEMessageType::PreLoadGame),
            Some(engine_fixes::EVENT_PRE_LOAD_GAME)
        );
        assert_eq!(
            event_kind(NVSEMessageType::ExitToMainMenu),
            Some(engine_fixes::EVENT_EXIT_TO_MAIN_MENU)
        );
        assert_eq!(
            event_kind(NVSEMessageType::NewGame),
            Some(engine_fixes::EVENT_NEW_GAME)
        );
    }

    #[test]
    fn world_lifetime_messages_are_dormant_before_deferred_init() {
        assert!(!should_forward_event(NVSEMessageType::PreLoadGame, false));
        assert!(!should_forward_event(NVSEMessageType::NewGame, false));
        assert!(should_forward_event(NVSEMessageType::PreLoadGame, true));
        assert!(should_forward_event(NVSEMessageType::DeferredInit, false));
    }
}
