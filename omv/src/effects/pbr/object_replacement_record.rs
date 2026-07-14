//! Draw-scoped object PBR sampler validation.

use libpsycho::os::windows::directx9::Device9Ref;

use super::{engine_contracts::ObjectDrawRejectReason, samplers, shader_record};

pub(super) fn validate_pixel_samplers(
    device: &Device9Ref<'_>,
    record: shader_record::ShaderRecordSnapshot,
    selector: usize,
) -> std::result::Result<(), ObjectDrawRejectReason> {
    samplers::validate_object_layout(device, record.template_id, selector)
        .map_err(|()| ObjectDrawRejectReason::MissingSampler)
}
