//! HUD corner notifications (Vault Boy messages).
//!
//! These are the small messages that appear in the top-left corner of the
//! screen with a Vault Boy face. They auto-dismiss after a timeout.
//!
//! # Usage
//!
//! ```no_run
//! use libnvse::api::hud::{hud_message, Emotion};
//!
//! // Simple notification
//! hud_message("Hello from Rust!")?;
//!
//! // With a specific Vault Boy expression
//! hud_message_with("Ouch!", Emotion::Pain, 3.0)?;
//! ```

use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

/// QueueUIMessage function signature from GameAPI.h.
///
/// Displays a corner notification with Vault Boy icon.
type QueueUIMessageFn = unsafe extern "C" fn(
    msg: *const i8,
    emotion: u32,
    dds_path: *const i8,
    sound_name: *const i8,
    msg_time: f32,
    maybe_next_to_display: bool,
) -> bool;

/// QueueUIMessage at 0x007052F0 (Fallout New Vegas).
#[inline]
fn queue_ui_message() -> QueueUIMessageFn {
    unsafe { std::mem::transmute(0x007052F0usize) }
}

/// Vault Boy emotion shown in the notification icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Emotion {
    Happy = 0,
    Sad = 1,
    Neutral = 2,
    Pain = 3,
}

#[derive(Debug, Error)]
pub enum HudError {
    #[error("WinAPI error: {0}")]
    WinApiError(#[from] WinapiError),
}

pub type HudResult<T> = Result<T, HudError>;

/// Show a HUD corner notification with the default Vault Boy face.
///
/// Displays for 2 seconds with a neutral expression.
/// Fire-and-forget -- no ownership concerns.
pub fn hud_message(message: &str) -> HudResult<()> {
    hud_message_with(message, Emotion::Neutral, 2.0)
}

/// Show a HUD corner notification with a specific emotion and duration.
///
/// - `emotion` -- Vault Boy facial expression
/// - `duration` -- display time in seconds
pub fn hud_message_with(message: &str, emotion: Emotion, duration: f32) -> HudResult<()> {
    let win_msg = WinString::new(message)?;
    let queue_fn = queue_ui_message();

    win_msg.with_ansi(|msg_ptr| unsafe {
        queue_fn(
            msg_ptr,
            emotion as u32,
            std::ptr::null(),
            std::ptr::null(),
            duration,
            false,
        );
    });

    Ok(())
}

/// Show a HUD corner notification with a custom icon.
///
/// - `icon_path` -- path to a .dds texture relative to Data/Textures/
/// - `duration` -- display time in seconds
pub fn hud_message_icon(message: &str, icon_path: &str, duration: f32) -> HudResult<()> {
    let win_msg = WinString::new(message)?;
    let win_icon = WinString::new(icon_path)?;
    let queue_fn = queue_ui_message();

    win_msg.with_ansi(|msg_ptr| {
        win_icon.with_ansi(|icon_ptr| unsafe {
            queue_fn(
                msg_ptr,
                0,
                icon_ptr,
                std::ptr::null(),
                duration,
                false,
            );
        });
    });

    Ok(())
}
