//! Bounded runtime diagnostics for the ImGui dashboard.
//!
//! The primary debugging surface for PBR should be a few counters that answer
//! whether contracts are ready and whether fallback is happening.

use std::{
    array,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use super::{
    engine_contracts::{DrawSnapshot, ObjectDrawRejectReason, ObjectSpecularFadeSnapshot},
    object_contracts::{self, ObjectContractState},
    samplers::ObjectSamplerIdentity,
};

static ENABLED_FRAME_COUNT: AtomicU32 = AtomicU32::new(0);
static DETAILED_ENABLED: AtomicBool = AtomicBool::new(false);
static DIAGNOSTIC_LOG_COUNT: AtomicU32 = AtomicU32::new(0);
static DRAW_TRACE_LOG_COUNT: AtomicU32 = AtomicU32::new(0);
static SPECULAR_FADE_LOG_COUNT: AtomicU32 = AtomicU32::new(0);
static UNRESOLVED_IDENTITY_LOG_COUNT: AtomicU32 = AtomicU32::new(0);
static OBJECT_REPLACEMENTS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_FALLBACKS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_DRAW_GATE_REJECTIONS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_TERRAIN_REJECTIONS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_CONSTANT_UPLOADS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_D3D_TO_REPLACEMENT_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_D3D_TO_OTHER_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_CONTRACT_TRANSITIONS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_REPLACEMENTS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_FALLBACKS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_DRAW_GATE_REJECTIONS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_TERRAIN_REJECTIONS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_CONSTANT_UPLOADS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_D3D_TO_REPLACEMENT_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_D3D_TO_OTHER_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_CONTRACT_TRANSITIONS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static LAND_LOD_REPLACEMENTS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static LAND_LOD_FALLBACKS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static TERRAIN_FADE_REPLACEMENTS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static TERRAIN_FADE_FALLBACKS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static CLOSE_TERRAIN_REPLACEMENTS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static CLOSE_TERRAIN_FALLBACKS_THIS_FRAME: AtomicU32 = AtomicU32::new(0);
static LAND_LOD_REPLACEMENTS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static LAND_LOD_FALLBACKS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static TERRAIN_FADE_REPLACEMENTS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static TERRAIN_FADE_FALLBACKS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static CLOSE_TERRAIN_REPLACEMENTS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static CLOSE_TERRAIN_FALLBACKS_LAST_FRAME: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_VERTEX_SLS: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_PIXEL_SLS: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_VERTEX_TABLE: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_VERTEX_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);
static OBJECT_LAST_NORMALIZED_VERTEX_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);
static OBJECT_LAST_PIXEL_TABLE: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_PIXEL_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);
static OBJECT_LAST_CONTRACT_STATE: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_CONTRACT_TRANSITION_FROM: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_CONTRACT_TRANSITION_TO: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_VERTEX_REPLACEMENT_READY: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_PIXEL_REPLACEMENT_READY: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_VERTEX_WRAPPER: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_PIXEL_WRAPPER: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_VERTEX_REPLACEMENT: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_PIXEL_REPLACEMENT: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_VERTEX_D3D: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_PIXEL_D3D: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_VERTEX_D3D_IS_REPLACEMENT: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_PIXEL_D3D_IS_REPLACEMENT: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_D3D_PAIR_STATE: AtomicU32 = AtomicU32::new(D3D_PAIR_UNKNOWN);
static OBJECT_LAST_SELECTOR: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_SELECTOR_STATE: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_ACTIVE_LAYER_COUNT: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_SCANNED_ENTRIES: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_PASS_ENTRY_LIST: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_REJECT_REASON: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_REJECT_ROW: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_REJECT_SELECTOR: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_FADE_GEOMETRY: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_FADE_PROPERTY: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_FADE_DISTANCE: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_FADE_START: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_FADE_END: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_FADE_EXPECTED: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_FADE_STAGED: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_FADE_C25: AtomicU32 = AtomicU32::new(f32::NAN.to_bits());
static OBJECT_LAST_LIGHT_CAPACITY: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_LIGHT_SIGNATURE: AtomicU32 = AtomicU32::new(0);
static OBJECT_LAST_BASE_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_NORMAL_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_GLOW_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_SHADOW_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static OBJECT_LAST_SHADOW_MASK_TEXTURE: AtomicUsize = AtomicUsize::new(0);

const REJECT_NONE: u32 = 0;
const REJECT_CLOSE_TERRAIN_MATERIAL: u32 = 1;
const REJECT_TERRAIN_ZERO_RESOURCE: u32 = 2;
const REJECT_TERRAIN_LIGHT_RESOURCE: u32 = 3;
const REJECT_TERRAIN_HELPER: u32 = 4;
const REJECT_MISSING_D3D_STATE: u32 = 5;
const REJECT_MISSING_SHADER_RECORD: u32 = 6;
const REJECT_MISSING_TABLE_IDENTITY: u32 = 7;
const REJECT_TABLE_IDENTITY_MISMATCH: u32 = 8;
const REJECT_TERRAIN_TABLE_SLOT: u32 = 9;
const REJECT_ENVMAP_TABLE_SLOT: u32 = 10;
const REJECT_UNSUPPORTED_OBJECT_PAIR: u32 = 11;
const REJECT_MISSING_REPLACEMENT_RESOURCE: u32 = 12;
const REJECT_HANDLE_STATE_MISMATCH: u32 = 13;
const REJECT_MISSING_SAMPLER: u32 = 14;
const REJECT_REASON_COUNT: usize = 15;
const D3D_PAIR_UNKNOWN: u32 = 0;
const D3D_PAIR_OTHER: u32 = 1;
const D3D_PAIR_REPLACEMENT: u32 = 2;
const OBJECT_DRAW_STATE_SLOT_COUNT: usize = 64;
const OBJECT_DRAW_STATE_PROBE_COUNT: usize = 4;
const DRAW_TRACE_LOG_LIMIT: u32 = 96;
const SPECULAR_FADE_LOG_LIMIT: u32 = 128;
const SPECULAR_FADE_BUCKET_UNSET: u32 = u32::MAX;
const UNRESOLVED_IDENTITY_SLOT_COUNT: usize = 128;
const UNRESOLVED_IDENTITY_LOG_LIMIT: u32 = 96;

static OBJECT_DRAW_STATES: LazyLock<[ObjectDrawStateSlot; OBJECT_DRAW_STATE_SLOT_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| ObjectDrawStateSlot::new()));
static REJECTIONS_THIS_FRAME: LazyLock<[AtomicU32; REJECT_REASON_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(0)));
static REJECTIONS_LAST_FRAME: LazyLock<[AtomicU32; REJECT_REASON_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(0)));
static UNRESOLVED_IDENTITY_KEYS: LazyLock<[AtomicU32; UNRESOLVED_IDENTITY_SLOT_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(0)));

struct ObjectDrawStateSlot {
    key: AtomicU32,
    state: AtomicU32,
    specular_fade_bucket: AtomicU32,
}

#[derive(Clone, Copy)]
pub(super) struct ObjectDrawTrace {
    pub(super) key: u32,
    pub(super) geometry: usize,
    pub(super) property: usize,
    pub(super) pass: usize,
    pub(super) pass_index: u32,
    pub(super) selector: usize,
    pub(super) selector_state: u32,
    pub(super) active_layer_count: u32,
    pub(super) scanned_entries: u32,
    pub(super) vertex_index: u32,
    pub(super) pixel_index: u32,
}

#[derive(Clone, Copy)]
pub(super) enum TerrainDrawFamily {
    LandLod,
    TerrainFade,
    CloseTerrain,
}

impl ObjectDrawStateSlot {
    fn new() -> Self {
        Self {
            key: AtomicU32::new(0),
            state: AtomicU32::new(0),
            specular_fade_bucket: AtomicU32::new(SPECULAR_FADE_BUCKET_UNSET),
        }
    }
}

pub(super) fn set_detailed_enabled(enabled: bool) {
    DETAILED_ENABLED.store(enabled, Ordering::Release);
}

pub(super) fn detailed_enabled() -> bool {
    DETAILED_ENABLED.load(Ordering::Relaxed)
}

pub(super) fn service_frame(shader_enabled: bool, debug_log_draws: bool) {
    OBJECT_REPLACEMENTS_LAST_FRAME.store(
        OBJECT_REPLACEMENTS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_FALLBACKS_LAST_FRAME.store(
        OBJECT_FALLBACKS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_DRAW_GATE_REJECTIONS_LAST_FRAME.store(
        OBJECT_DRAW_GATE_REJECTIONS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_TERRAIN_REJECTIONS_LAST_FRAME.store(
        OBJECT_TERRAIN_REJECTIONS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_CONSTANT_UPLOADS_LAST_FRAME.store(
        OBJECT_CONSTANT_UPLOADS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_D3D_TO_REPLACEMENT_LAST_FRAME.store(
        OBJECT_D3D_TO_REPLACEMENT_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_D3D_TO_OTHER_LAST_FRAME.store(
        OBJECT_D3D_TO_OTHER_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    OBJECT_CONTRACT_TRANSITIONS_LAST_FRAME.store(
        OBJECT_CONTRACT_TRANSITIONS_THIS_FRAME.swap(0, Ordering::AcqRel),
        Ordering::Release,
    );
    swap_frame_counter(
        &LAND_LOD_REPLACEMENTS_THIS_FRAME,
        &LAND_LOD_REPLACEMENTS_LAST_FRAME,
    );
    swap_frame_counter(
        &LAND_LOD_FALLBACKS_THIS_FRAME,
        &LAND_LOD_FALLBACKS_LAST_FRAME,
    );
    swap_frame_counter(
        &TERRAIN_FADE_REPLACEMENTS_THIS_FRAME,
        &TERRAIN_FADE_REPLACEMENTS_LAST_FRAME,
    );
    swap_frame_counter(
        &TERRAIN_FADE_FALLBACKS_THIS_FRAME,
        &TERRAIN_FADE_FALLBACKS_LAST_FRAME,
    );
    swap_frame_counter(
        &CLOSE_TERRAIN_REPLACEMENTS_THIS_FRAME,
        &CLOSE_TERRAIN_REPLACEMENTS_LAST_FRAME,
    );
    swap_frame_counter(
        &CLOSE_TERRAIN_FALLBACKS_THIS_FRAME,
        &CLOSE_TERRAIN_FALLBACKS_LAST_FRAME,
    );
    for (current, last) in REJECTIONS_THIS_FRAME
        .iter()
        .zip(REJECTIONS_LAST_FRAME.iter())
    {
        last.store(current.swap(0, Ordering::AcqRel), Ordering::Release);
    }

    if shader_enabled {
        let frame = ENABLED_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);
        let interval = if debug_log_draws { 30 } else { 240 };
        if frame % interval == 0 && DIAGNOSTIC_LOG_COUNT.fetch_add(1, Ordering::Relaxed) < 24 {
            log::info!(
                "[PBR_CONTRACT] draws: replaced={} fallback={} rejected={} constants={} pair=SLS{}/SLS{} class={} selector=0x{:08X} sampler={} sampler_fallback={} selector_cache_mismatch={}",
                OBJECT_REPLACEMENTS_LAST_FRAME.load(Ordering::Acquire),
                OBJECT_FALLBACKS_LAST_FRAME.load(Ordering::Acquire),
                OBJECT_DRAW_GATE_REJECTIONS_LAST_FRAME.load(Ordering::Acquire),
                OBJECT_CONSTANT_UPLOADS_LAST_FRAME.load(Ordering::Acquire),
                OBJECT_LAST_VERTEX_SLS.load(Ordering::Acquire),
                OBJECT_LAST_PIXEL_SLS.load(Ordering::Acquire),
                object_contracts::state_label_from_code(
                    OBJECT_LAST_CONTRACT_STATE.load(Ordering::Acquire)
                ),
                OBJECT_LAST_SELECTOR.load(Ordering::Acquire),
                super::samplers::object_last_sampler_layout_label(),
                super::samplers::object_last_sampler_fallback_label(),
                super::samplers::object_sampler_selector_mismatches_last_frame(),
            );
            log::info!(
                "[PBR_REJECTS] terrain={} d3d={} record={} identity={} identity_mismatch={} terrain_slot={} envmap={} unsupported_pair={} resource={} handle={} sampler={}",
                rejection_count(REJECT_CLOSE_TERRAIN_MATERIAL)
                    + rejection_count(REJECT_TERRAIN_ZERO_RESOURCE)
                    + rejection_count(REJECT_TERRAIN_LIGHT_RESOURCE)
                    + rejection_count(REJECT_TERRAIN_HELPER),
                rejection_count(REJECT_MISSING_D3D_STATE),
                rejection_count(REJECT_MISSING_SHADER_RECORD),
                rejection_count(REJECT_MISSING_TABLE_IDENTITY),
                rejection_count(REJECT_TABLE_IDENTITY_MISMATCH),
                rejection_count(REJECT_TERRAIN_TABLE_SLOT),
                rejection_count(REJECT_ENVMAP_TABLE_SLOT),
                rejection_count(REJECT_UNSUPPORTED_OBJECT_PAIR),
                rejection_count(REJECT_MISSING_REPLACEMENT_RESOURCE),
                rejection_count(REJECT_HANDLE_STATE_MISMATCH),
                rejection_count(REJECT_MISSING_SAMPLER),
            );
        }
    }
}

pub(super) fn record_object_pair(
    vertex_sls: u16,
    pixel_sls: u16,
    vertex_table: u32,
    vertex_index: u32,
    pixel_table: u32,
    pixel_index: u32,
) {
    if !detailed_enabled() {
        return;
    }
    OBJECT_LAST_VERTEX_SLS.store(u32::from(vertex_sls), Ordering::Release);
    OBJECT_LAST_PIXEL_SLS.store(u32::from(pixel_sls), Ordering::Release);
    OBJECT_LAST_VERTEX_TABLE.store(vertex_table, Ordering::Release);
    OBJECT_LAST_VERTEX_INDEX.store(vertex_index, Ordering::Release);
    OBJECT_LAST_PIXEL_TABLE.store(pixel_table, Ordering::Release);
    OBJECT_LAST_PIXEL_INDEX.store(pixel_index, Ordering::Release);
}

pub(super) fn record_object_contract(
    trace: ObjectDrawTrace,
    normalized_vertex_index: u32,
    state: ObjectContractState,
) {
    if !detailed_enabled() {
        return;
    }
    OBJECT_LAST_NORMALIZED_VERTEX_INDEX.store(normalized_vertex_index, Ordering::Release);
    let state_code = object_contracts::state_code(state);
    OBJECT_LAST_CONTRACT_STATE.store(state_code, Ordering::Release);
    record_object_contract_transition(trace, normalized_vertex_index, state_code);
}

pub(super) fn record_object_handles(
    vertex_wrapper: *mut std::ffi::c_void,
    pixel_wrapper: *mut std::ffi::c_void,
    vertex_replacement: Option<*mut std::ffi::c_void>,
    pixel_replacement: Option<*mut std::ffi::c_void>,
) {
    if !detailed_enabled() {
        return;
    }
    OBJECT_LAST_VERTEX_WRAPPER.store(vertex_wrapper as usize, Ordering::Release);
    OBJECT_LAST_PIXEL_WRAPPER.store(pixel_wrapper as usize, Ordering::Release);
    OBJECT_LAST_VERTEX_REPLACEMENT.store(
        vertex_replacement.map_or(0, |handle| handle as usize),
        Ordering::Release,
    );
    OBJECT_LAST_PIXEL_REPLACEMENT.store(
        pixel_replacement.map_or(0, |handle| handle as usize),
        Ordering::Release,
    );
    OBJECT_LAST_VERTEX_REPLACEMENT_READY
        .store(u32::from(vertex_replacement.is_some()), Ordering::Release);
    OBJECT_LAST_PIXEL_REPLACEMENT_READY
        .store(u32::from(pixel_replacement.is_some()), Ordering::Release);
}

pub(super) fn record_object_d3d_state(
    current_vertex: *mut std::ffi::c_void,
    current_pixel: *mut std::ffi::c_void,
    replacement_vertex: *mut std::ffi::c_void,
    replacement_pixel: *mut std::ffi::c_void,
) {
    if !detailed_enabled() {
        return;
    }
    OBJECT_LAST_VERTEX_D3D.store(current_vertex as usize, Ordering::Release);
    OBJECT_LAST_PIXEL_D3D.store(current_pixel as usize, Ordering::Release);
    OBJECT_LAST_VERTEX_D3D_IS_REPLACEMENT.store(
        u32::from(current_vertex == replacement_vertex),
        Ordering::Release,
    );
    OBJECT_LAST_PIXEL_D3D_IS_REPLACEMENT.store(
        u32::from(current_pixel == replacement_pixel),
        Ordering::Release,
    );
    let pair_state = if current_vertex == replacement_vertex && current_pixel == replacement_pixel {
        D3D_PAIR_REPLACEMENT
    } else {
        D3D_PAIR_OTHER
    };
    let previous = OBJECT_LAST_D3D_PAIR_STATE.swap(pair_state, Ordering::AcqRel);
    match (previous, pair_state) {
        (D3D_PAIR_OTHER, D3D_PAIR_REPLACEMENT) => {
            OBJECT_D3D_TO_REPLACEMENT_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
        }
        (D3D_PAIR_REPLACEMENT, D3D_PAIR_OTHER) => {
            OBJECT_D3D_TO_OTHER_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

pub(super) fn record_object_draw_context(snapshot: DrawSnapshot) {
    if !detailed_enabled() {
        return;
    }
    OBJECT_LAST_SELECTOR.store(snapshot.selector, Ordering::Release);
    OBJECT_LAST_SELECTOR_STATE.store(snapshot.selector_state, Ordering::Release);
    OBJECT_LAST_ACTIVE_LAYER_COUNT.store(snapshot.active_layer_count, Ordering::Release);
    OBJECT_LAST_SCANNED_ENTRIES.store(snapshot.scanned_entries, Ordering::Release);
    OBJECT_LAST_PASS_ENTRY_LIST.store(snapshot.pass_entry_list, Ordering::Release);
}

pub(super) fn record_object_specular_fade(
    trace: ObjectDrawTrace,
    fade: ObjectSpecularFadeSnapshot,
    samplers: ObjectSamplerIdentity,
) {
    if !detailed_enabled() || trace.key == 0 {
        return;
    }

    OBJECT_LAST_FADE_GEOMETRY.store(trace.geometry, Ordering::Release);
    OBJECT_LAST_FADE_PROPERTY.store(fade.property, Ordering::Release);
    OBJECT_LAST_FADE_DISTANCE.store(fade.distance.to_bits(), Ordering::Release);
    OBJECT_LAST_FADE_START.store(fade.fade_start.to_bits(), Ordering::Release);
    OBJECT_LAST_FADE_END.store(fade.fade_end.to_bits(), Ordering::Release);
    OBJECT_LAST_FADE_EXPECTED.store(fade.expected_weight.to_bits(), Ordering::Release);
    OBJECT_LAST_FADE_STAGED.store(fade.native_weight.to_bits(), Ordering::Release);
    OBJECT_LAST_FADE_C25.store(
        fade.renderer_constant_weight.unwrap_or(f32::NAN).to_bits(),
        Ordering::Release,
    );
    OBJECT_LAST_LIGHT_CAPACITY.store(fade.light_capacity, Ordering::Release);
    OBJECT_LAST_LIGHT_SIGNATURE.store(fade.light_signature, Ordering::Release);
    OBJECT_LAST_BASE_TEXTURE.store(samplers.base, Ordering::Release);
    OBJECT_LAST_NORMAL_TEXTURE.store(samplers.normal, Ordering::Release);
    OBJECT_LAST_GLOW_TEXTURE.store(samplers.glow, Ordering::Release);
    OBJECT_LAST_SHADOW_TEXTURE.store(samplers.shadow, Ordering::Release);
    OBJECT_LAST_SHADOW_MASK_TEXTURE.store(samplers.shadow_mask, Ordering::Release);

    let bucket = specular_fade_bucket(fade.native_weight);
    let slot = object_draw_state_slot(trace.key);
    let previous = slot.specular_fade_bucket.swap(bucket, Ordering::AcqRel);
    if previous == bucket
        || SPECULAR_FADE_LOG_COUNT.fetch_add(1, Ordering::Relaxed) >= SPECULAR_FADE_LOG_LIMIT
    {
        return;
    }

    let name = super::engine_contracts::geometry_name(trace.geometry)
        .unwrap_or_else(|| "<unnamed>".to_owned());
    log::info!(
        "[PBR_DISTANCE_FADE] shader_applied=true geometry=0x{:08X} name={} property=0x{:08X} flags=0x{:08X}/0x{:08X} pass_index={} pair=VS[{}]/PS[{}] distance={:.3} specular_range={:.3}..{:.3} expected_specular={:.6} staged_specular={:.6} c25_specular={:.6} light_capacity={} light_signature=0x{:08X} textures=base:0x{:08X},normal:0x{:08X},glow:0x{:08X},shadow:0x{:08X},mask:0x{:08X} specular_bucket={}/{}",
        trace.geometry,
        name,
        fade.property,
        fade.property_flags,
        fade.property_flags2,
        trace.pass_index,
        trace.vertex_index,
        trace.pixel_index,
        fade.distance,
        fade.fade_start,
        fade.fade_end,
        fade.expected_weight,
        fade.native_weight,
        fade.renderer_constant_weight.unwrap_or(f32::NAN),
        fade.light_capacity,
        fade.light_signature,
        samplers.base,
        samplers.normal,
        samplers.glow,
        samplers.shadow,
        samplers.shadow_mask,
        specular_fade_bucket_label(bucket),
        specular_fade_bucket_label(previous),
    );
}

pub(super) fn record_object_replacement() {
    OBJECT_REPLACEMENTS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_object_constant_upload() {
    OBJECT_CONSTANT_UPLOADS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_object_fallback() {
    OBJECT_FALLBACKS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_terrain_replacement(family: TerrainDrawFamily) {
    terrain_family_counter(
        family,
        &LAND_LOD_REPLACEMENTS_THIS_FRAME,
        &TERRAIN_FADE_REPLACEMENTS_THIS_FRAME,
        &CLOSE_TERRAIN_REPLACEMENTS_THIS_FRAME,
    )
    .fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_terrain_fallback(family: TerrainDrawFamily) {
    terrain_family_counter(
        family,
        &LAND_LOD_FALLBACKS_THIS_FRAME,
        &TERRAIN_FADE_FALLBACKS_THIS_FRAME,
        &CLOSE_TERRAIN_FALLBACKS_THIS_FRAME,
    )
    .fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_object_draw_gate_rejection(
    reason: ObjectDrawRejectReason,
    row: u16,
    selector: usize,
) {
    let reason_code = reject_reason_code(reason);
    OBJECT_DRAW_GATE_REJECTIONS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
    if let Some(counter) = REJECTIONS_THIS_FRAME.get(reason_code as usize) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    if reject_reason_is_terrain_like(reason) {
        OBJECT_TERRAIN_REJECTIONS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
    }
    if detailed_enabled() {
        OBJECT_LAST_REJECT_REASON.store(reason_code, Ordering::Release);
        OBJECT_LAST_REJECT_ROW.store(u32::from(row), Ordering::Release);
        OBJECT_LAST_REJECT_SELECTOR.store(selector, Ordering::Release);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_unresolved_table_pair(
    snapshot: DrawSnapshot,
    pass_index: u32,
    vertex_shader: *mut std::ffi::c_void,
    pixel_shader: *mut std::ffi::c_void,
    vertex_group: &'static str,
    vertex_index: u32,
    pixel_group: &'static str,
    pixel_index: u32,
    reason: ObjectDrawRejectReason,
) {
    if !detailed_enabled() {
        return;
    }
    let mut key = 0x811C_9DC5u32;
    let identity = if snapshot.geometry != 0 {
        [snapshot.geometry, snapshot.property, snapshot.selector, 0]
    } else {
        [0, 0, vertex_shader as usize, pixel_shader as usize]
    };
    for value in identity {
        key = (key ^ value as u32).wrapping_mul(0x0100_0193);
    }
    if key == 0 {
        key = 1;
    }

    let mut claimed = false;
    for slot in UNRESOLVED_IDENTITY_KEYS.iter() {
        let current = slot.load(Ordering::Acquire);
        if current == key {
            return;
        }
        if current == 0
            && slot
                .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            claimed = true;
            break;
        }
    }
    if !claimed
        || UNRESOLVED_IDENTITY_LOG_COUNT.fetch_add(1, Ordering::Relaxed)
            >= UNRESOLVED_IDENTITY_LOG_LIMIT
    {
        return;
    }

    let geometry_name = super::engine_contracts::geometry_name(snapshot.geometry)
        .unwrap_or_else(|| "<unnamed>".to_owned());
    let vertex_index = table_index_label(vertex_index);
    let pixel_index = table_index_label(pixel_index);
    log::info!(
        "[PBR_UNRESOLVED] geometry=0x{:08X} name={} property=0x{:08X} pass=0x{:08X} pass_index={} selector=0x{:08X} selector_state={} pair=VS:{}[{}]@{:p}/PS:{}[{}]@{:p} reason={}",
        snapshot.geometry,
        geometry_name,
        snapshot.property,
        snapshot.pass,
        pass_index,
        snapshot.selector,
        snapshot.selector_state,
        vertex_group,
        vertex_index,
        vertex_shader,
        pixel_group,
        pixel_index,
        pixel_shader,
        reject_reason_label(reject_reason_code(reason)),
    );
}

fn table_index_label(index: u32) -> String {
    if index == u32::MAX {
        "unknown".to_owned()
    } else {
        index.to_string()
    }
}

fn rejection_count(reason: u32) -> u32 {
    REJECTIONS_LAST_FRAME
        .get(reason as usize)
        .map_or(0, |counter| counter.load(Ordering::Acquire))
}

pub(super) fn object_replacements_last_frame() -> u32 {
    OBJECT_REPLACEMENTS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_fallbacks_last_frame() -> u32 {
    OBJECT_FALLBACKS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_draw_gate_rejections_last_frame() -> u32 {
    OBJECT_DRAW_GATE_REJECTIONS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_terrain_rejections_last_frame() -> u32 {
    OBJECT_TERRAIN_REJECTIONS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_constant_uploads_last_frame() -> u32 {
    OBJECT_CONSTANT_UPLOADS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_d3d_to_replacement_last_frame() -> u32 {
    OBJECT_D3D_TO_REPLACEMENT_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_d3d_to_other_last_frame() -> u32 {
    OBJECT_D3D_TO_OTHER_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_contract_transitions_last_frame() -> u32 {
    OBJECT_CONTRACT_TRANSITIONS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn land_lod_replacements_last_frame() -> u32 {
    LAND_LOD_REPLACEMENTS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn land_lod_fallbacks_last_frame() -> u32 {
    LAND_LOD_FALLBACKS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn terrain_fade_replacements_last_frame() -> u32 {
    TERRAIN_FADE_REPLACEMENTS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn terrain_fade_fallbacks_last_frame() -> u32 {
    TERRAIN_FADE_FALLBACKS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn close_terrain_replacements_last_frame() -> u32 {
    CLOSE_TERRAIN_REPLACEMENTS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn close_terrain_fallbacks_last_frame() -> u32 {
    CLOSE_TERRAIN_FALLBACKS_LAST_FRAME.load(Ordering::Acquire)
}

pub(super) fn object_last_vertex_sls() -> u32 {
    OBJECT_LAST_VERTEX_SLS.load(Ordering::Acquire)
}

pub(super) fn object_last_pixel_sls() -> u32 {
    OBJECT_LAST_PIXEL_SLS.load(Ordering::Acquire)
}

pub(super) fn object_last_vertex_table() -> u32 {
    OBJECT_LAST_VERTEX_TABLE.load(Ordering::Acquire)
}

pub(super) fn object_last_vertex_index() -> u32 {
    OBJECT_LAST_VERTEX_INDEX.load(Ordering::Acquire)
}

pub(super) fn object_last_normalized_vertex_index() -> u32 {
    OBJECT_LAST_NORMALIZED_VERTEX_INDEX.load(Ordering::Acquire)
}

pub(super) fn object_last_pixel_table() -> u32 {
    OBJECT_LAST_PIXEL_TABLE.load(Ordering::Acquire)
}

pub(super) fn object_last_pixel_index() -> u32 {
    OBJECT_LAST_PIXEL_INDEX.load(Ordering::Acquire)
}

pub(super) fn object_last_pair_class_label() -> &'static str {
    object_contracts::state_label_from_code(OBJECT_LAST_CONTRACT_STATE.load(Ordering::Acquire))
}

pub(super) fn object_last_contract_transition_from() -> &'static str {
    object_contracts::state_label_from_code(
        OBJECT_LAST_CONTRACT_TRANSITION_FROM.load(Ordering::Acquire),
    )
}

pub(super) fn object_last_contract_transition_to() -> &'static str {
    object_contracts::state_label_from_code(
        OBJECT_LAST_CONTRACT_TRANSITION_TO.load(Ordering::Acquire),
    )
}

pub(super) fn object_last_vertex_replacement_ready() -> bool {
    OBJECT_LAST_VERTEX_REPLACEMENT_READY.load(Ordering::Acquire) != 0
}

pub(super) fn object_last_pixel_replacement_ready() -> bool {
    OBJECT_LAST_PIXEL_REPLACEMENT_READY.load(Ordering::Acquire) != 0
}

pub(super) fn object_last_vertex_wrapper() -> usize {
    OBJECT_LAST_VERTEX_WRAPPER.load(Ordering::Acquire)
}

pub(super) fn object_last_pixel_wrapper() -> usize {
    OBJECT_LAST_PIXEL_WRAPPER.load(Ordering::Acquire)
}

pub(super) fn object_last_vertex_replacement() -> usize {
    OBJECT_LAST_VERTEX_REPLACEMENT.load(Ordering::Acquire)
}

pub(super) fn object_last_pixel_replacement() -> usize {
    OBJECT_LAST_PIXEL_REPLACEMENT.load(Ordering::Acquire)
}

pub(super) fn object_last_vertex_d3d() -> usize {
    OBJECT_LAST_VERTEX_D3D.load(Ordering::Acquire)
}

pub(super) fn object_last_pixel_d3d() -> usize {
    OBJECT_LAST_PIXEL_D3D.load(Ordering::Acquire)
}

pub(super) fn object_last_vertex_d3d_is_replacement() -> bool {
    OBJECT_LAST_VERTEX_D3D_IS_REPLACEMENT.load(Ordering::Acquire) != 0
}

pub(super) fn object_last_pixel_d3d_is_replacement() -> bool {
    OBJECT_LAST_PIXEL_D3D_IS_REPLACEMENT.load(Ordering::Acquire) != 0
}

pub(super) fn object_last_d3d_pair_state_label() -> &'static str {
    d3d_pair_state_label(OBJECT_LAST_D3D_PAIR_STATE.load(Ordering::Acquire))
}

pub(super) fn object_last_selector() -> usize {
    OBJECT_LAST_SELECTOR.load(Ordering::Acquire)
}

pub(super) fn object_last_selector_state() -> u32 {
    OBJECT_LAST_SELECTOR_STATE.load(Ordering::Acquire)
}

pub(super) fn object_last_active_layer_count() -> u32 {
    OBJECT_LAST_ACTIVE_LAYER_COUNT.load(Ordering::Acquire)
}

pub(super) fn object_last_scanned_entries() -> u32 {
    OBJECT_LAST_SCANNED_ENTRIES.load(Ordering::Acquire)
}

pub(super) fn object_last_pass_entry_list() -> usize {
    OBJECT_LAST_PASS_ENTRY_LIST.load(Ordering::Acquire)
}

pub(super) fn object_last_reject_reason_label() -> &'static str {
    reject_reason_label(OBJECT_LAST_REJECT_REASON.load(Ordering::Acquire))
}

pub(super) fn object_last_reject_row() -> u32 {
    OBJECT_LAST_REJECT_ROW.load(Ordering::Acquire)
}

pub(super) fn object_last_reject_selector() -> usize {
    OBJECT_LAST_REJECT_SELECTOR.load(Ordering::Acquire)
}

pub(super) fn object_last_fade_geometry() -> usize {
    OBJECT_LAST_FADE_GEOMETRY.load(Ordering::Acquire)
}

pub(super) fn object_last_fade_property() -> usize {
    OBJECT_LAST_FADE_PROPERTY.load(Ordering::Acquire)
}

pub(super) fn object_last_fade_distance() -> f32 {
    f32::from_bits(OBJECT_LAST_FADE_DISTANCE.load(Ordering::Acquire))
}

pub(super) fn object_last_fade_start() -> f32 {
    f32::from_bits(OBJECT_LAST_FADE_START.load(Ordering::Acquire))
}

pub(super) fn object_last_fade_end() -> f32 {
    f32::from_bits(OBJECT_LAST_FADE_END.load(Ordering::Acquire))
}

pub(super) fn object_last_fade_expected() -> f32 {
    f32::from_bits(OBJECT_LAST_FADE_EXPECTED.load(Ordering::Acquire))
}

pub(super) fn object_last_fade_staged() -> f32 {
    f32::from_bits(OBJECT_LAST_FADE_STAGED.load(Ordering::Acquire))
}

pub(super) fn object_last_fade_c25() -> f32 {
    f32::from_bits(OBJECT_LAST_FADE_C25.load(Ordering::Acquire))
}

pub(super) fn object_last_light_capacity() -> u32 {
    OBJECT_LAST_LIGHT_CAPACITY.load(Ordering::Acquire)
}

pub(super) fn object_last_light_signature() -> u32 {
    OBJECT_LAST_LIGHT_SIGNATURE.load(Ordering::Acquire)
}

pub(super) fn object_last_base_texture() -> usize {
    OBJECT_LAST_BASE_TEXTURE.load(Ordering::Acquire)
}

pub(super) fn object_last_normal_texture() -> usize {
    OBJECT_LAST_NORMAL_TEXTURE.load(Ordering::Acquire)
}

pub(super) fn reset() {
    DETAILED_ENABLED.store(false, Ordering::Release);
    ENABLED_FRAME_COUNT.store(0, Ordering::Release);
    DIAGNOSTIC_LOG_COUNT.store(0, Ordering::Release);
    DRAW_TRACE_LOG_COUNT.store(0, Ordering::Release);
    SPECULAR_FADE_LOG_COUNT.store(0, Ordering::Release);
    UNRESOLVED_IDENTITY_LOG_COUNT.store(0, Ordering::Release);
    OBJECT_REPLACEMENTS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_FALLBACKS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_DRAW_GATE_REJECTIONS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_TERRAIN_REJECTIONS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_CONSTANT_UPLOADS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_D3D_TO_REPLACEMENT_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_D3D_TO_OTHER_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_CONTRACT_TRANSITIONS_THIS_FRAME.store(0, Ordering::Release);
    OBJECT_REPLACEMENTS_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_FALLBACKS_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_DRAW_GATE_REJECTIONS_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_TERRAIN_REJECTIONS_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_CONSTANT_UPLOADS_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_D3D_TO_REPLACEMENT_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_D3D_TO_OTHER_LAST_FRAME.store(0, Ordering::Release);
    OBJECT_CONTRACT_TRANSITIONS_LAST_FRAME.store(0, Ordering::Release);
    for counter in [
        &LAND_LOD_REPLACEMENTS_THIS_FRAME,
        &LAND_LOD_FALLBACKS_THIS_FRAME,
        &TERRAIN_FADE_REPLACEMENTS_THIS_FRAME,
        &TERRAIN_FADE_FALLBACKS_THIS_FRAME,
        &CLOSE_TERRAIN_REPLACEMENTS_THIS_FRAME,
        &CLOSE_TERRAIN_FALLBACKS_THIS_FRAME,
        &LAND_LOD_REPLACEMENTS_LAST_FRAME,
        &LAND_LOD_FALLBACKS_LAST_FRAME,
        &TERRAIN_FADE_REPLACEMENTS_LAST_FRAME,
        &TERRAIN_FADE_FALLBACKS_LAST_FRAME,
        &CLOSE_TERRAIN_REPLACEMENTS_LAST_FRAME,
        &CLOSE_TERRAIN_FALLBACKS_LAST_FRAME,
    ] {
        counter.store(0, Ordering::Release);
    }
    OBJECT_LAST_VERTEX_SLS.store(0, Ordering::Release);
    OBJECT_LAST_PIXEL_SLS.store(0, Ordering::Release);
    OBJECT_LAST_VERTEX_TABLE.store(0, Ordering::Release);
    OBJECT_LAST_VERTEX_INDEX.store(u32::MAX, Ordering::Release);
    OBJECT_LAST_NORMALIZED_VERTEX_INDEX.store(u32::MAX, Ordering::Release);
    OBJECT_LAST_PIXEL_TABLE.store(0, Ordering::Release);
    OBJECT_LAST_PIXEL_INDEX.store(u32::MAX, Ordering::Release);
    OBJECT_LAST_CONTRACT_STATE.store(0, Ordering::Release);
    OBJECT_LAST_CONTRACT_TRANSITION_FROM.store(0, Ordering::Release);
    OBJECT_LAST_CONTRACT_TRANSITION_TO.store(0, Ordering::Release);
    OBJECT_LAST_VERTEX_REPLACEMENT_READY.store(0, Ordering::Release);
    OBJECT_LAST_PIXEL_REPLACEMENT_READY.store(0, Ordering::Release);
    OBJECT_LAST_VERTEX_WRAPPER.store(0, Ordering::Release);
    OBJECT_LAST_PIXEL_WRAPPER.store(0, Ordering::Release);
    OBJECT_LAST_VERTEX_REPLACEMENT.store(0, Ordering::Release);
    OBJECT_LAST_PIXEL_REPLACEMENT.store(0, Ordering::Release);
    OBJECT_LAST_VERTEX_D3D.store(0, Ordering::Release);
    OBJECT_LAST_PIXEL_D3D.store(0, Ordering::Release);
    OBJECT_LAST_VERTEX_D3D_IS_REPLACEMENT.store(0, Ordering::Release);
    OBJECT_LAST_PIXEL_D3D_IS_REPLACEMENT.store(0, Ordering::Release);
    OBJECT_LAST_D3D_PAIR_STATE.store(D3D_PAIR_UNKNOWN, Ordering::Release);
    OBJECT_LAST_SELECTOR.store(0, Ordering::Release);
    OBJECT_LAST_SELECTOR_STATE.store(0, Ordering::Release);
    OBJECT_LAST_ACTIVE_LAYER_COUNT.store(0, Ordering::Release);
    OBJECT_LAST_SCANNED_ENTRIES.store(0, Ordering::Release);
    OBJECT_LAST_PASS_ENTRY_LIST.store(0, Ordering::Release);
    OBJECT_LAST_REJECT_REASON.store(REJECT_NONE, Ordering::Release);
    OBJECT_LAST_REJECT_ROW.store(0, Ordering::Release);
    OBJECT_LAST_REJECT_SELECTOR.store(0, Ordering::Release);
    OBJECT_LAST_FADE_GEOMETRY.store(0, Ordering::Release);
    OBJECT_LAST_FADE_PROPERTY.store(0, Ordering::Release);
    OBJECT_LAST_FADE_DISTANCE.store(0, Ordering::Release);
    OBJECT_LAST_FADE_START.store(0, Ordering::Release);
    OBJECT_LAST_FADE_END.store(0, Ordering::Release);
    OBJECT_LAST_FADE_EXPECTED.store(0, Ordering::Release);
    OBJECT_LAST_FADE_STAGED.store(0, Ordering::Release);
    OBJECT_LAST_FADE_C25.store(f32::NAN.to_bits(), Ordering::Release);
    OBJECT_LAST_LIGHT_CAPACITY.store(0, Ordering::Release);
    OBJECT_LAST_LIGHT_SIGNATURE.store(0, Ordering::Release);
    OBJECT_LAST_BASE_TEXTURE.store(0, Ordering::Release);
    OBJECT_LAST_NORMAL_TEXTURE.store(0, Ordering::Release);
    OBJECT_LAST_GLOW_TEXTURE.store(0, Ordering::Release);
    OBJECT_LAST_SHADOW_TEXTURE.store(0, Ordering::Release);
    OBJECT_LAST_SHADOW_MASK_TEXTURE.store(0, Ordering::Release);
    for slot in REJECTIONS_THIS_FRAME
        .iter()
        .chain(REJECTIONS_LAST_FRAME.iter())
    {
        slot.store(0, Ordering::Release);
    }
    for slot in OBJECT_DRAW_STATES.iter() {
        slot.key.store(0, Ordering::Release);
        slot.state.store(0, Ordering::Release);
        slot.specular_fade_bucket
            .store(SPECULAR_FADE_BUCKET_UNSET, Ordering::Release);
    }
    for slot in UNRESOLVED_IDENTITY_KEYS.iter() {
        slot.store(0, Ordering::Release);
    }
}

fn reject_reason_code(reason: ObjectDrawRejectReason) -> u32 {
    match reason {
        ObjectDrawRejectReason::CloseTerrainMaterial => REJECT_CLOSE_TERRAIN_MATERIAL,
        ObjectDrawRejectReason::TerrainZeroResource => REJECT_TERRAIN_ZERO_RESOURCE,
        ObjectDrawRejectReason::TerrainLightResource => REJECT_TERRAIN_LIGHT_RESOURCE,
        ObjectDrawRejectReason::TerrainHelper => REJECT_TERRAIN_HELPER,
        ObjectDrawRejectReason::MissingD3DState => REJECT_MISSING_D3D_STATE,
        ObjectDrawRejectReason::MissingShaderRecord => REJECT_MISSING_SHADER_RECORD,
        ObjectDrawRejectReason::MissingTableIdentity => REJECT_MISSING_TABLE_IDENTITY,
        ObjectDrawRejectReason::TableIdentityMismatch => REJECT_TABLE_IDENTITY_MISMATCH,
        ObjectDrawRejectReason::TerrainTableSlot => REJECT_TERRAIN_TABLE_SLOT,
        ObjectDrawRejectReason::EnvMapTableSlot => REJECT_ENVMAP_TABLE_SLOT,
        ObjectDrawRejectReason::UnsupportedObjectPair => REJECT_UNSUPPORTED_OBJECT_PAIR,
        ObjectDrawRejectReason::MissingReplacementResource => REJECT_MISSING_REPLACEMENT_RESOURCE,
        ObjectDrawRejectReason::HandleStateMismatch => REJECT_HANDLE_STATE_MISMATCH,
        ObjectDrawRejectReason::MissingSampler => REJECT_MISSING_SAMPLER,
    }
}

fn reject_reason_is_terrain_like(reason: ObjectDrawRejectReason) -> bool {
    matches!(
        reason,
        ObjectDrawRejectReason::CloseTerrainMaterial
            | ObjectDrawRejectReason::TerrainZeroResource
            | ObjectDrawRejectReason::TerrainLightResource
            | ObjectDrawRejectReason::TerrainHelper
            | ObjectDrawRejectReason::TerrainTableSlot
    )
}

fn reject_reason_label(reason: u32) -> &'static str {
    match reason {
        REJECT_CLOSE_TERRAIN_MATERIAL => "close terrain material row",
        REJECT_TERRAIN_ZERO_RESOURCE => "terrain zero-resource row",
        REJECT_TERRAIN_LIGHT_RESOURCE => "terrain light-resource row",
        REJECT_TERRAIN_HELPER => "terrain helper row",
        REJECT_MISSING_D3D_STATE => "missing current D3D shader state",
        REJECT_MISSING_SHADER_RECORD => "missing shader wrapper record",
        REJECT_MISSING_TABLE_IDENTITY => "missing shader table identity",
        REJECT_TABLE_IDENTITY_MISMATCH => "shader table identity mismatch",
        REJECT_TERRAIN_TABLE_SLOT => "terrain shader table slot",
        REJECT_ENVMAP_TABLE_SLOT => "envmap shader table slot",
        REJECT_UNSUPPORTED_OBJECT_PAIR => "unsupported object table pair",
        REJECT_MISSING_REPLACEMENT_RESOURCE => "missing replacement shader resource",
        REJECT_HANDLE_STATE_MISMATCH => "shader handle state mismatch",
        REJECT_MISSING_SAMPLER => "missing object sampler",
        _ => "none",
    }
}

fn d3d_pair_state_label(state: u32) -> &'static str {
    match state {
        D3D_PAIR_OTHER => "vanilla/other",
        D3D_PAIR_REPLACEMENT => "replacement",
        _ => "unknown",
    }
}

fn specular_fade_bucket(weight: f32) -> u32 {
    if !weight.is_finite() {
        6
    } else if weight <= 0.0 {
        0
    } else if weight < 0.25 {
        1
    } else if weight < 0.5 {
        2
    } else if weight < 0.75 {
        3
    } else if weight < 1.0 {
        4
    } else {
        5
    }
}

fn specular_fade_bucket_label(bucket: u32) -> &'static str {
    match bucket {
        0 => "zero",
        1 => "0..0.25",
        2 => "0.25..0.5",
        3 => "0.5..0.75",
        4 => "0.75..1",
        5 => "one",
        6 => "non-finite",
        _ => "unset",
    }
}

fn record_object_contract_transition(
    trace: ObjectDrawTrace,
    normalized_vertex_index: u32,
    state_code: u32,
) {
    if trace.key == 0 || state_code == 0 {
        return;
    }

    let slot = object_draw_state_slot(trace.key);
    let previous = slot.state.swap(state_code, Ordering::AcqRel);
    if previous != 0 && previous != state_code {
        OBJECT_CONTRACT_TRANSITIONS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
        OBJECT_LAST_CONTRACT_TRANSITION_FROM.store(previous, Ordering::Release);
        OBJECT_LAST_CONTRACT_TRANSITION_TO.store(state_code, Ordering::Release);
    }
    if (previous == 0 || previous != state_code)
        && DRAW_TRACE_LOG_COUNT.fetch_add(1, Ordering::Relaxed) < DRAW_TRACE_LOG_LIMIT
    {
        let name = super::engine_contracts::geometry_name(trace.geometry)
            .unwrap_or_else(|| "<unnamed>".to_owned());
        let constant_flags = super::engine_contracts::pass_constant_flags(trace.pass_index)
            .map_or_else(
                || "unavailable".to_owned(),
                |(vertex, pixel)| format!("VS[0x{vertex:08X}]/PS[0x{pixel:08X}]"),
            );
        log::info!(
            "[PBR_DRAW] geometry=0x{:08X} name={} property=0x{:08X} pass=0x{:08X} pass_index={} constant_flags={} selector=0x{:08X} selector_state={} active_layers={} scanned_entries={} pair=VS[{}]/PS[{}] normalized_vs={} outcome={} previous={}",
            trace.geometry,
            name,
            trace.property,
            trace.pass,
            trace.pass_index,
            constant_flags,
            trace.selector,
            trace.selector_state,
            trace.active_layer_count,
            trace.scanned_entries,
            trace.vertex_index,
            trace.pixel_index,
            normalized_vertex_index,
            object_contracts::state_label_from_code(state_code),
            object_contracts::state_label_from_code(previous),
        );
    }
}

fn object_draw_state_slot(draw_key: u32) -> &'static ObjectDrawStateSlot {
    let base = draw_key as usize % OBJECT_DRAW_STATE_SLOT_COUNT;
    for offset in 0..OBJECT_DRAW_STATE_PROBE_COUNT {
        let index = (base + offset) % OBJECT_DRAW_STATE_SLOT_COUNT;
        let slot = &OBJECT_DRAW_STATES[index];
        let key = slot.key.load(Ordering::Acquire);
        if key == draw_key {
            return slot;
        }
        if key == 0
            && slot
                .key
                .compare_exchange(0, draw_key, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return slot;
        }
    }

    let slot = &OBJECT_DRAW_STATES[base];
    slot.key.store(draw_key, Ordering::Release);
    slot.state.store(0, Ordering::Release);
    slot.specular_fade_bucket
        .store(SPECULAR_FADE_BUCKET_UNSET, Ordering::Release);
    slot
}

fn swap_frame_counter(current: &AtomicU32, last: &AtomicU32) {
    last.store(current.swap(0, Ordering::AcqRel), Ordering::Release);
}

fn terrain_family_counter<'a>(
    family: TerrainDrawFamily,
    land_lod: &'a AtomicU32,
    terrain_fade: &'a AtomicU32,
    close_terrain: &'a AtomicU32,
) -> &'a AtomicU32 {
    match family {
        TerrainDrawFamily::LandLod => land_lod,
        TerrainDrawFamily::TerrainFade => terrain_fade,
        TerrainDrawFamily::CloseTerrain => close_terrain,
    }
}
