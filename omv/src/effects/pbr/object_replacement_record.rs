//! Object replacement-record apply state.
//!
//! NVR stores replacement programs on the native shader object and `SetupShader`
//! calls `SetCT()` when a replacement becomes active. OMV cannot extend native
//! object allocation safely, so this module keeps the same ownership model in a
//! fixed side table keyed by the native wrapper pointer.

use std::{
    array,
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
};

use super::{
    engine_contracts::{self, ObjectDrawRejectReason},
    object_contracts::{self, ObjectContractState},
    samplers, shader_record,
    shader_registry::ShaderStage,
};
use libpsycho::os::windows::directx9::Device9Ref;

const RECORD_COUNT: usize = 512;
const PROBE_COUNT: usize = 8;
const STAGE_NONE: u32 = 0;
const STAGE_VERTEX: u32 = 1;
const STAGE_PIXEL: u32 = 2;
const TEMPLATE_NONE: u32 = u32::MAX;

static TABLE: LazyLock<ObjectReplacementRecordTable> =
    LazyLock::new(ObjectReplacementRecordTable::new);

#[derive(Clone, Copy, Debug)]
pub(super) struct ObjectReplacementApply {
    pub(super) needs_constants: bool,
}

struct ObjectReplacementRecordTable {
    records: [ObjectReplacementRecord; RECORD_COUNT],
}

struct ObjectReplacementRecord {
    shader: AtomicUsize,
    stage: AtomicU32,
    template_id: AtomicU32,
    contract_state: AtomicU32,
    original_handle: AtomicUsize,
    replacement_handle: AtomicUsize,
    last_applied_handle: AtomicUsize,
    constant_version: AtomicU32,
}

impl ObjectReplacementRecordTable {
    fn new() -> Self {
        Self {
            records: array::from_fn(|_| ObjectReplacementRecord::new()),
        }
    }

    fn clear(&self) {
        for record in &self.records {
            record.clear();
        }
    }

    fn active_record_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.shader.load(Ordering::Acquire) != 0)
            .count()
    }

    fn slot_for(&self, shader: usize) -> Option<&ObjectReplacementRecord> {
        if shader == 0 {
            return None;
        }

        let base = hash_slot(shader);
        for offset in 0..PROBE_COUNT {
            let index = (base + offset) % RECORD_COUNT;
            let record = &self.records[index];
            let key = record.shader.load(Ordering::Acquire);
            if key == shader {
                return Some(record);
            }
            if key == 0
                && record
                    .shader
                    .compare_exchange(0, shader, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return Some(record);
            }
        }

        let record = &self.records[base];
        record.clear();
        record.shader.store(shader, Ordering::Release);
        Some(record)
    }

    fn find(&self, shader: usize) -> Option<&ObjectReplacementRecord> {
        if shader == 0 {
            return None;
        }

        let base = hash_slot(shader);
        for offset in 0..PROBE_COUNT {
            let index = (base + offset) % RECORD_COUNT;
            let record = &self.records[index];
            if record.shader.load(Ordering::Acquire) == shader {
                return Some(record);
            }
        }

        None
    }
}

impl ObjectReplacementRecord {
    fn new() -> Self {
        Self {
            shader: AtomicUsize::new(0),
            stage: AtomicU32::new(STAGE_NONE),
            template_id: AtomicU32::new(TEMPLATE_NONE),
            contract_state: AtomicU32::new(0),
            original_handle: AtomicUsize::new(0),
            replacement_handle: AtomicUsize::new(0),
            last_applied_handle: AtomicUsize::new(0),
            constant_version: AtomicU32::new(0),
        }
    }

    fn clear(&self) {
        self.shader.store(0, Ordering::Release);
        self.stage.store(STAGE_NONE, Ordering::Release);
        self.template_id.store(TEMPLATE_NONE, Ordering::Release);
        self.contract_state.store(0, Ordering::Release);
        self.original_handle.store(0, Ordering::Release);
        self.replacement_handle.store(0, Ordering::Release);
        self.last_applied_handle.store(0, Ordering::Release);
        self.constant_version.store(0, Ordering::Release);
    }
}

pub(super) fn apply_shader(
    record: shader_record::ShaderRecordSnapshot,
    replacement: *mut c_void,
    contract_state: ObjectContractState,
    current_d3d_handle: *mut c_void,
    constant_version: u32,
) -> std::result::Result<ObjectReplacementApply, ObjectDrawRejectReason> {
    if replacement.is_null() {
        return Err(ObjectDrawRejectReason::MissingReplacementResource);
    }

    let actual_handle = engine_contracts::shader_handle(record.shader, record.stage)
        .ok_or(ObjectDrawRejectReason::HandleStateMismatch)?;
    if !handle_can_be_replaced(record, actual_handle, replacement) {
        return Err(ObjectDrawRejectReason::HandleStateMismatch);
    }

    let slot = TABLE
        .slot_for(record.shader as usize)
        .ok_or(ObjectDrawRejectReason::MissingShaderRecord)?;
    slot.stage
        .store(stage_to_u32(record.stage), Ordering::Release);
    slot.template_id
        .store(u32::from(record.template_id), Ordering::Release);
    slot.contract_state.store(
        object_contracts::state_code(contract_state),
        Ordering::Release,
    );
    slot.original_handle
        .store(record.original_handle as usize, Ordering::Release);
    slot.replacement_handle
        .store(replacement as usize, Ordering::Release);

    if actual_handle != replacement
        && !engine_contracts::write_shader_handle(record.shader, record.stage, replacement)
    {
        return Err(ObjectDrawRejectReason::HandleStateMismatch);
    }

    shader_record::set_current(record.shader, replacement);
    slot.last_applied_handle
        .store(replacement as usize, Ordering::Release);

    let prior_constant_version = slot.constant_version.load(Ordering::Acquire);
    Ok(ObjectReplacementApply {
        needs_constants: current_d3d_handle != replacement
            || prior_constant_version != constant_version,
    })
}

pub(super) fn validate_pixel_samplers(
    device: &Device9Ref<'_>,
    record: shader_record::ShaderRecordSnapshot,
    selector: usize,
) -> std::result::Result<(), ObjectDrawRejectReason> {
    samplers::validate_object_layout(device, record.template_id, selector)
        .map_err(|()| ObjectDrawRejectReason::MissingSampler)
}

pub(super) fn mark_constants_uploaded(
    vertex_record: shader_record::ShaderRecordSnapshot,
    pixel_record: shader_record::ShaderRecordSnapshot,
    constant_version: u32,
) {
    mark_record_constants_uploaded(vertex_record.shader, constant_version);
    mark_record_constants_uploaded(pixel_record.shader, constant_version);
}

pub(super) fn mark_restored(record: shader_record::ShaderRecordSnapshot) {
    let Some(slot) = TABLE.find(record.shader as usize) else {
        return;
    };
    slot.last_applied_handle
        .store(record.original_handle as usize, Ordering::Release);
}

pub(super) fn active_record_count() -> usize {
    TABLE.active_record_count()
}

pub(super) fn reset() {
    TABLE.clear();
}

fn mark_record_constants_uploaded(shader: *mut c_void, constant_version: u32) {
    let Some(slot) = TABLE.find(shader as usize) else {
        return;
    };
    slot.constant_version
        .store(constant_version, Ordering::Release);
}

fn handle_can_be_replaced(
    record: shader_record::ShaderRecordSnapshot,
    actual_handle: *mut c_void,
    replacement: *mut c_void,
) -> bool {
    if actual_handle == record.original_handle
        || actual_handle == record.current_handle
        || actual_handle == replacement
    {
        return true;
    }

    TABLE.find(record.shader as usize).is_some_and(|slot| {
        actual_handle as usize == slot.last_applied_handle.load(Ordering::Acquire)
    })
}

fn hash_slot(shader: usize) -> usize {
    (shader >> 4) % RECORD_COUNT
}

fn stage_to_u32(stage: ShaderStage) -> u32 {
    match stage {
        ShaderStage::Vertex => STAGE_VERTEX,
        ShaderStage::Pixel => STAGE_PIXEL,
    }
}
