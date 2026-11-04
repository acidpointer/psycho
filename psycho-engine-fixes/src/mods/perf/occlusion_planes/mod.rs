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
//! The module owns one native reference per injected plane and one reference to
//! its containing BSPortalGraph. It unlinks its own nodes before releasing the
//! planes and releases the graph outside the publication lock. It never clears
//! an authored list. Authored occluders and rooms remain engine-owned.
//!
//! # Lifecycle
//!
//! Configuration and two inert publisher bridges are prepared at the pre-CRT
//! barrier. DeferredInit verifies native contracts, publishes synchronization
//! and loads the cache. Only normal main-thread presentation drives cell/graph identity
//! check; a new cell must be stable before it replaces the current planes. On a
//! transition the runtime rebuilds and then retries a bounded settle window, so
//! references whose 3D attaches after the first frame are still collected; a
//! retry whose generated set is unchanged keeps the existing planes. The mesh
//! walk is resumable and advances a fixed work slice per frame, so a dense cell
//! never blocks the frame thread. A cache entry is reused only after its settle
//! window completed. Creation, insertion, removal and release happen only on a
//! rebuild. Loading/unknown phases and world-lifetime events cancel the world
//! epoch without touching engine memory. The next normal presentation cleans
//! the retained graph before looking up a player or cell. Each collection
//! slice receives the current cell afresh under its native reference-list lock.
//!
//! # Failure behavior
//!
//! A signature/publication failure prevents activation. A stale cache is
//! regenerated; failed plane allocations leave the admitted subset owned and
//! schedule a bounded retry. See docs/fnv_runtime_occlusion_plane_implementation_plan.md.

mod cache;
mod contract;
mod data;
mod native_list;
mod raw;
mod runtime;
mod runtime_generate;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

use crate::config::PerformanceConfig;

/// Record configuration and serialize native publication at the pre-CRT
/// barrier. Cache and world access wait for DeferredInit and normal gameplay.
pub(crate) fn install(performance: &PerformanceConfig) {
    let mut enabled = performance.occlusion_planes;
    if enabled && let Err(error) = native_list::install() {
        log::error!("[OCCLUSION_PLANES] Native publication contract unavailable: {error:#}");
        enabled = false;
    }
    runtime::configure(
        enabled,
        performance.occlusion_planes_max_per_cell,
        performance.occlusion_planes_grid_radius,
        &performance.occlusion_planes_cache_path,
        performance.occlusion_planes_debug_log,
    );
}

/// Route one core event id to the occlusion-plane lifecycle.
pub(crate) fn observe_event(kind: u32, frame_phase: i32) {
    runtime::observe_event(kind, frame_phase);
}

/// Read the occlusion-plane runtime counters for the dashboard.
pub(crate) fn dashboard_counters() -> runtime::DashboardCounters {
    runtime::dashboard_counters()
}
