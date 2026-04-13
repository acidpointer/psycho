//! Global NVSE services for psycho-nvse subsystems.
//!
//! Stores a pre-queried console function pointer set once during load.
//! Subsystems (heap pressure, etc.) use these to interact with the game
//! without needing a reference to PluginContext.
//!
//! # Safety model
//!
//! All stored pointers are set once via OnceLock (immutable after init).
//! Console and HUD calls only run on the main game thread (same thread
//! as the hooks that call them).

use std::sync::atomic::{AtomicBool, Ordering};

use libnvse::api::hud;

/// Whether the game engine is fully initialized (DeferredInit received).
static GAME_READY: AtomicBool = AtomicBool::new(false);

/// Mark the game as fully initialized.
#[inline]
pub fn set_game_ready() {
    GAME_READY.store(true, Ordering::Release);
}

/// Check if the game is ready for console/UI interaction.
#[inline]
pub fn is_game_ready() -> bool {
    GAME_READY.load(Ordering::Acquire)
}

/// Show a HUD corner notification with Pain Vault Boy.
///
/// Only works on the main thread after DeferredInit.
#[allow(dead_code)]
pub fn show_notification(message: &str) {
    if !is_game_ready() {
        return;
    }
    match hud::hud_message_with(message, hud::Emotion::Pain, 2.0) {
        Ok(_) => {}
        Err(err) => {
            log::error!("[NVSE] Failed to show hud message '{}'; error: {:?}", message, err);
        }
    }
}
