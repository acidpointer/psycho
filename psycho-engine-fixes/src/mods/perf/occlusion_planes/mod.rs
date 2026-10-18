//! Runtime collection and injection of occlusion planes.
//!
//! Fallout: New Vegas has no authored occlusion data for many exterior cells.
//! This module derives one conservative world-space box per opaque, unskinned
//! static geometry of the current cell, or loads an optional per-cell override
//! file, and injects `BSOcclusionPlane` objects into the engine's native
//! occluder list, reusing the engine's own authored `XOCP` creation path.
//! Faces are shrunk to half extent so the occluded cone stays narrow, which
//! limits false culling. Results are cached per cell and reused on a revisit;
//! the cache header is bound to the active plugin list, so a mod install,
//! removal, reorder or update discards it and stale planes are never reused.
//!
//! # Ownership
//!
//! The module owns exactly one native reference per injected plane and removes
//! only the list nodes it created. It never clears the whole list and never
//! reads an existing plane's fields. Authored occluders and rooms are outside
//! its scope.
//!
//! # Lifecycle
//!
//! Configuration is recorded at core startup. The feature verifies its native
//! byte signatures and reads the data file on the `DeferredInit` event. The
//! already-forwarded `OnFramePresent` event drives a cell/scene-graph identity
//! check. On a transition the runtime rebuilds and then retries a bounded
//! settle window, so references whose 3D attaches after the first frame are
//! still collected; a retry whose generated set is unchanged keeps the existing
//! planes. Creation, insertion, removal and release happen only on a rebuild.
//! Load, new-game and exit-to-menu events defer cleanup to the next frame, so
//! the module never scans a list that may be under teardown.
//!
//! # Failure behavior
//!
//! A signature, file or allocation failure leaves the native list untouched.
//! A missing or empty override file is normal; runtime collection still serves
//! every cell that has no override.

mod cache;
mod contract;
mod data;
mod raw;
mod runtime;
mod runtime_generate;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

use crate::config::PerformanceConfig;

/// Record configuration at startup. No file or engine access occurs here;
/// activation waits for the `DeferredInit` event.
pub(crate) fn install(performance: &PerformanceConfig) {
    runtime::configure(
        performance.occlusion_planes,
        performance.occlusion_planes_max_per_cell,
        performance.occlusion_planes_runtime,
        &performance.occlusion_planes_cache_path,
        performance.occlusion_planes_debug,
    );
}

/// Route one core event id to the occlusion-plane lifecycle.
pub(crate) fn observe_event(kind: u32) {
    runtime::observe_event(kind);
}

/// Toggle the occluder debug view from a host command.
pub(crate) fn debug_toggle() -> String {
    runtime::debug_toggle()
}

/// Fill a caller buffer with the current occluder debug frame.
pub(crate) unsafe fn debug_write(out: *mut f32, capacity: usize) -> i32 {
    unsafe { runtime::debug_write(out, capacity) }
}
