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
    let deferred_ready = DEFERRED_INIT_FORWARDED.load(Ordering::Acquire);
    if should_forward_event(message_type, deferred_ready)
        && let Some(kind) = event_kind(message_type)
    {
        let phase = frame_phase(msg, deferred_ready);
        let _ = engine_fixes::notify_event(kind, core::ptr::null(), 0, phase);
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

/// Decode xNVSE's synchronous presentation payload into the existing scalar
/// host ABI. It is a pointer to a four-byte integer, unlike PostLoadGame's
/// pointer-valued boolean. Unknown and pre-deferred messages stay unadmitted.
fn frame_phase(msg: &NVSEMessage, deferred_ready: bool) -> i32 {
    let (data, length) = msg.raw_data();
    // SAFETY: the xNVSE callback owns the payload through this synchronous
    // call. Only the documented presentation message dereferences its data.
    unsafe { decode_frame_phase(msg.get_type(), deferred_ready, data.cast(), length) }
}

/// A correctly sized, non-null admitted presentation payload must be live
/// through the call. Other message shapes require no readable pointee.
unsafe fn decode_frame_phase(
    kind: NVSEMessageType,
    deferred_ready: bool,
    data: *const u8,
    length: u32,
) -> i32 {
    if !deferred_ready || kind != NVSEMessageType::OnFramePresent {
        return -1;
    }
    if data.is_null() || length != core::mem::size_of::<i32>() as u32 {
        return -1;
    }
    // SAFETY: xNVSE DisplayFrameHook owns this integer on its stack through
    // synchronous message dispatch. No pointer escapes into the core ABI.
    match unsafe { core::ptr::read_unaligned(data.cast::<i32>()) } {
        0 => 0,
        1 => 1,
        _ => -1,
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
    fn presentation_payload_is_an_integer_pointer_and_requires_deferred_init() {
        let mut phase = 0i32;
        let decode = |phase: &i32, ready, length| {
            // SAFETY: the input is an actual four-byte stack integer, matching
            // DisplayFrameHook's payload. No substitute provider is involved.
            unsafe {
                decode_frame_phase(
                    NVSEMessageType::OnFramePresent,
                    ready,
                    (phase as *const i32).cast(),
                    length,
                )
            }
        };
        assert_eq!(decode(&phase, false, 4), -1);
        assert_eq!(decode(&phase, true, 4), 0);
        phase = 1;
        assert_eq!(decode(&phase, true, 4), 1);
        phase = 2;
        assert_eq!(decode(&phase, true, 4), -1);
        assert_eq!(decode(&phase, true, 1), -1);
        // SAFETY: null is an explicitly rejected payload shape.
        assert_eq!(
            unsafe {
                decode_frame_phase(NVSEMessageType::OnFramePresent, true, core::ptr::null(), 4)
            },
            -1
        );
    }

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
