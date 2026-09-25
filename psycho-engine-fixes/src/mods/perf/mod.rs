mod post_load;
mod radio;
mod rng;

pub use post_load::install_post_load_reconciliation_prepass;
pub use radio::install_radio_scan_fix;
pub use rng::install_rng_hook;

/// Routes engine lifecycle events to performance subsystems.
///
/// Radio uses DeferredInit for optional native policy optimization. Its queries
/// finish inside each scan; frame and teardown events require no radio work.
pub(crate) fn observe_event(kind: u32) {
    radio::observe_event(kind);
}
