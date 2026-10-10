//! Core-owned performance interventions and lifecycle routing.
//!
//! Each subsystem owns its installation/failure policy. Startup prepares enabled
//! interventions; the two lighting candidates publish admission at
//! DeferredInit without code writes and retain process-lifetime bridge storage.
//! Per-operation ownership and work budgets are documented in their modules.

mod light_property_scores;
mod lighting_contract;
mod multibound_frustum;
mod multibound_loop_bookkeeping;
mod multibound_vertex_setup;
mod post_load;
mod radio;
mod rng;
mod scene_light_scan;

pub(crate) use light_property_scores::install as install_light_property_score_reuse;
pub(crate) use multibound_frustum::install as install_multibound_frustum_tests;
pub(crate) use multibound_loop_bookkeeping::install as install_multibound_loop_bookkeeping;
pub(crate) use multibound_vertex_setup::install as install_multibound_vertex_setup;
pub(crate) use scene_light_scan::install as install_scene_light_sequential_scan;

pub use post_load::install_post_load_reconciliation_prepass;
pub use radio::install_radio_scan_fix;
pub use rng::install_rng_hook;

/// Routes engine lifecycle events to performance subsystems.
///
/// Radio uses DeferredInit for optional native policy optimization. Its queries
/// finish inside each scan; frame and teardown events require no radio work.
/// The lighting candidates publish admission at DeferredInit without code writes.
pub(crate) fn observe_event(kind: u32) {
    radio::observe_event(kind);
    light_property_scores::observe_event(kind);
    scene_light_scan::observe_event(kind);
}
