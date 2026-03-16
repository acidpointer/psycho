//! Combat processing throttles
//!
//! Several per-frame functions in FNV iterate ALL actors/objects with no time
//! budget, causing frame spikes during heavy combat. These hooks throttle
//! the most expensive ones to run every Nth frame.
//!
//! ## FUN_009777a0 - Detection/combat update
//! O(events * actors) per frame. For each detection source, iterates every
//! actor in the cell computing distance, detection formulas, and combat
//! response triggers. With many NPCs this is quadratic.
//!
//! ## FUN_00978550 - Actor data update (ProcessDataUpdate)
//! Iterates ALL actors every frame calling FUN_00565870 per actor.
//! No time budget - linear in actor count but called unconditionally.
//!
//! Both functions store results in per-actor data structures that persist
//! between frames, so skipping a frame means NPCs use slightly stale data -
//! at most 16ms old at 60fps, well within human perception thresholds.
//!
//! IMPORTANT: A warmup period ensures we never skip during game initialization.
//! Other systems (jip_nvse DeferredInit, FUN_00970d50) depend on actor data
//! being initialized by these functions on the first frames.

use std::sync::{
    LazyLock,
    atomic::{AtomicU32, Ordering},
};

use libc::c_void;
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

/// Number of frames to always run before throttling begins.
/// Covers game init, cell loading, plugin deferred init, etc.
/// 120 frames ~= 2 seconds at 60fps - plenty for all init to complete.
const WARMUP_FRAMES: u32 = 120;

// ---------------------------------------------------------------------------
// Detection update throttle (FUN_009777a0)
// ---------------------------------------------------------------------------

/// FUN_009777a0 - per-frame detection/combat update.
/// Calling convention: __fastcall(int param_1)
/// Called from FUN_0086e650 at 0x0086ea3f and 0x0086ea8b.
const DETECTION_UPDATE_ADDR: usize = 0x009777A0;

/// Run detection every 2nd frame (50% cost reduction).
const DETECTION_INTERVAL: u32 = 2;

static DETECTION_FRAME: AtomicU32 = AtomicU32::new(0);

type DetectionUpdateFn = unsafe extern "fastcall" fn(param_1: i32);

static DETECTION_HOOK: LazyLock<InlineHookContainer<DetectionUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);

/// # Safety
/// Called by the game engine via the inline hook trampoline.
unsafe extern "fastcall" fn hook_detection_update(param_1: i32) {
    let frame = DETECTION_FRAME.fetch_add(1, Ordering::Relaxed);

    // Always run during warmup to avoid init-order issues
    if frame >= WARMUP_FRAMES && !frame.is_multiple_of(DETECTION_INTERVAL) {
        return;
    }

    match DETECTION_HOOK.original() {
        Ok(original) => unsafe { original(param_1) },
        Err(err) => {
            log::error!("Detection update: failed to call original: {:?}", err);
        }
    }
}

// ---------------------------------------------------------------------------
// Actor data update throttle (FUN_00978550)
// ---------------------------------------------------------------------------

/// FUN_00978550 - per-frame actor data update (ProcessDataUpdate).
/// Calling convention: __fastcall(int param_1)
/// Called from FUN_0086e650 at 0x0086e9fa.
/// Iterates all actors calling FUN_00565870 per actor, no budget.
const ACTOR_DATA_UPDATE_ADDR: usize = 0x00978550;

/// Run actor data update every 2nd frame (50% cost reduction).
const ACTOR_DATA_INTERVAL: u32 = 2;

static ACTOR_DATA_FRAME: AtomicU32 = AtomicU32::new(0);

type ActorDataUpdateFn = unsafe extern "fastcall" fn(param_1: i32);

static ACTOR_DATA_HOOK: LazyLock<InlineHookContainer<ActorDataUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);

/// # Safety
/// Called by the game engine via the inline hook trampoline.
unsafe extern "fastcall" fn hook_actor_data_update(param_1: i32) {
    let frame = ACTOR_DATA_FRAME.fetch_add(1, Ordering::Relaxed);

    // Always run during warmup - FUN_00970d50 and jip_nvse DeferredInit
    // depend on actor data being initialized by this function.
    if frame >= WARMUP_FRAMES && !frame.is_multiple_of(ACTOR_DATA_INTERVAL) {
        return;
    }

    match ACTOR_DATA_HOOK.original() {
        Ok(original) => unsafe { original(param_1) },
        Err(err) => {
            log::error!("Actor data update: failed to call original: {:?}", err);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install combat processing throttles.
pub fn install_detection_budget() -> anyhow::Result<()> {
    // Hook 1: Detection/combat update
    DETECTION_HOOK.init(
        "detection_update",
        DETECTION_UPDATE_ADDR as *mut c_void,
        hook_detection_update,
    )?;
    DETECTION_HOOK.enable()?;

    log::info!(
        "Detection update: throttled to every {} frames (after {} warmup)",
        DETECTION_INTERVAL,
        WARMUP_FRAMES,
    );

    // Hook 2: Actor data update
    ACTOR_DATA_HOOK.init(
        "actor_data_update",
        ACTOR_DATA_UPDATE_ADDR as *mut c_void,
        hook_actor_data_update,
    )?;
    ACTOR_DATA_HOOK.enable()?;

    log::info!(
        "Actor data update: throttled to every {} frames (after {} warmup)",
        ACTOR_DATA_INTERVAL,
        WARMUP_FRAMES,
    );

    Ok(())
}
