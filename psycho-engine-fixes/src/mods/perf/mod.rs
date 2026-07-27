mod post_load;
mod radio;
mod rng;

pub use post_load::install_post_load_reconciliation_prepass;
pub use radio::install_radio_scan_fix;
pub use rng::install_rng_hook;

/// Routes engine lifecycle and frame events to performance subsystems.
///
/// The radio scheduler uses these events to pace query work and to join native
/// tasklets before world-owned forms can be destroyed.
pub(crate) fn observe_event(kind: u32) {
    radio::observe_event(kind);
}
