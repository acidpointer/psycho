//! Event ids accepted from late host adapters.
//!
//! Keep these values in sync with `psycho-engine-fixes-helper/src/engine_fixes.rs`.
//! They intentionally stay as plain integers to keep the exported ABI tiny.

pub(crate) const DEFERRED_INIT: u32 = 1;
pub(crate) const ON_FRAME_PRESENT: u32 = 6;
pub(crate) const PRE_LOAD_GAME: u32 = 7;
pub(crate) const EXIT_TO_MAIN_MENU: u32 = 8;
pub(crate) const NEW_GAME: u32 = 9;
