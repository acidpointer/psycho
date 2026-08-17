//! Draw-scoped object PBR sampler validation.

use super::{engine_contracts::ObjectDrawRejectReason, samplers};

pub(super) fn validate_pixel_samplers(
    pixel_template_id: u16,
    selector: usize,
    diagnostics_enabled: bool,
) -> std::result::Result<(), ObjectDrawRejectReason> {
    samplers::validate_object_layout(pixel_template_id, selector, diagnostics_enabled)
        .map_err(|()| ObjectDrawRejectReason::MissingSampler)
}
