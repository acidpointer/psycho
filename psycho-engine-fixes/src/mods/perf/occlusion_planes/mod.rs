//! Runtime collection and injection of occlusion planes.
//!
//! Fallout: New Vegas has no authored occlusion data for many exterior cells.
//! This module derives conservative oriented rectangles per opaque, unskinned
//! static geometry of the current cell and injects `BSOcclusionPlane` objects
//! into the engine's native occluder list, reusing the engine's own authored
//! `XOCP` creation path. Rectangles are fitted to the vertices that support
//! each face and emitted one-sided, so the engine activates a plane only while
//! the camera is on the solid side. Results are cached per cell and reused on a
//! revisit; the cache header is bound to the active plugin list, so a mod
//! install, removal, reorder or update discards it and stale planes are never
//! reused.
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
//! byte signatures and loads its cache on the `DeferredInit` event. The
//! already-forwarded `OnFramePresent` event drives a cell/scene-graph identity
//! check; a new cell must be stable before it replaces the current planes. On a
//! transition the runtime rebuilds and then retries a bounded settle window, so
//! references whose 3D attaches after the first frame are still collected; a
//! retry whose generated set is unchanged keeps the existing planes. A cache
//! entry is reused only after its settle window completed. Creation, insertion,
//! removal and release happen only on a rebuild. Load, new-game and
//! exit-to-menu events defer cleanup to the next frame, so the module never
//! scans a list that may be under teardown.
//!
//! # Failure behavior
//!
//! A signature, cache or allocation failure leaves the native list untouched.

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
