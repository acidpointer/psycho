mod post_load;
mod radio;
mod rng;

pub use post_load::install_post_load_reconciliation_prepass;
pub use radio::install_radio_scan_fix;
pub use rng::install_rng_hook;

pub(crate) fn observe_event(kind: u32) {
    radio::observe_event(kind);
}
