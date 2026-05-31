//! Event ids accepted from late host adapters.
//!
//! Keep these values in sync with `psycho-engine-fixes-helper/src/engine_fixes.rs`.
//! They intentionally stay as plain integers to keep the exported ABI tiny.

pub(crate) const DEFERRED_INIT: u32 = 1;
pub(crate) const PRE_LOAD_GAME: u32 = 2;
pub(crate) const LOAD_GAME: u32 = 3;
pub(crate) const POST_LOAD_GAME: u32 = 4;
pub(crate) const MAIN_GAME_LOOP: u32 = 5;
pub(crate) const ON_FRAME_PRESENT: u32 = 6;
