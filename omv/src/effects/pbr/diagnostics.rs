//! Bounded runtime diagnostics for the ImGui dashboard.
//!
//! The primary debugging surface for PBR should be a few counters that answer
//! whether contracts are ready and whether fallback is happening.

use std::{
    array,
    sync::{
        LazyLock,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
};

use super::{
    engine_contracts::{DrawSnapshot, ObjectDrawRejectReason},
    object_contracts::{self, ObjectContractState},
};

static ENABLED_FRAME_COUNT: AtomicU32 = AtomicU32::new(0);
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
const D3D_PAIR_UNKNOWN: u32 = 0;
const D3D_PAIR_OTHER: u32 = 1;
const D3D_PAIR_REPLACEMENT: u32 = 2;
const OBJECT_DRAW_STATE_SLOT_COUNT: usize = 64;
const OBJECT_DRAW_STATE_PROBE_COUNT: usize = 4;

static OBJECT_DRAW_STATES: LazyLock<[ObjectDrawStateSlot; OBJECT_DRAW_STATE_SLOT_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| ObjectDrawStateSlot::new()));

struct ObjectDrawStateSlot {
    key: AtomicU32,
    state: AtomicU32,
}

impl ObjectDrawStateSlot {
    fn new() -> Self {
        Self {
            key: AtomicU32::new(0),
            state: AtomicU32::new(0),
        }
    }
}

pub(super) fn service_frame(shader_enabled: bool, _debug_log_draws: bool) {
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

    if shader_enabled {
        ENABLED_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);
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
    OBJECT_LAST_VERTEX_SLS.store(u32::from(vertex_sls), Ordering::Release);
    OBJECT_LAST_PIXEL_SLS.store(u32::from(pixel_sls), Ordering::Release);
    OBJECT_LAST_VERTEX_TABLE.store(vertex_table, Ordering::Release);
    OBJECT_LAST_VERTEX_INDEX.store(vertex_index, Ordering::Release);
    OBJECT_LAST_PIXEL_TABLE.store(pixel_table, Ordering::Release);
    OBJECT_LAST_PIXEL_INDEX.store(pixel_index, Ordering::Release);
}

pub(super) fn record_object_contract(
    draw_key: u32,
    normalized_vertex_index: u32,
    state: ObjectContractState,
) {
    OBJECT_LAST_NORMALIZED_VERTEX_INDEX.store(normalized_vertex_index, Ordering::Release);
    let state_code = object_contracts::state_code(state);
    OBJECT_LAST_CONTRACT_STATE.store(state_code, Ordering::Release);
    record_object_contract_transition(draw_key, state_code);
}

pub(super) fn record_object_handles(
    vertex_wrapper: *mut std::ffi::c_void,
    pixel_wrapper: *mut std::ffi::c_void,
    vertex_replacement: Option<*mut std::ffi::c_void>,
    pixel_replacement: Option<*mut std::ffi::c_void>,
) {
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
    OBJECT_LAST_SELECTOR.store(snapshot.selector, Ordering::Release);
    OBJECT_LAST_SELECTOR_STATE.store(snapshot.selector_state, Ordering::Release);
    OBJECT_LAST_ACTIVE_LAYER_COUNT.store(snapshot.active_layer_count, Ordering::Release);
    OBJECT_LAST_SCANNED_ENTRIES.store(snapshot.scanned_entries, Ordering::Release);
    OBJECT_LAST_PASS_ENTRY_LIST.store(snapshot.pass_entry_list, Ordering::Release);
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

pub(super) fn record_object_draw_gate_rejection(
    reason: ObjectDrawRejectReason,
    row: u16,
    selector: usize,
) {
    let reason_code = reject_reason_code(reason);
    OBJECT_DRAW_GATE_REJECTIONS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
    if reject_reason_is_terrain_like(reason) {
        OBJECT_TERRAIN_REJECTIONS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
    }
    OBJECT_LAST_REJECT_REASON.store(reason_code, Ordering::Release);
    OBJECT_LAST_REJECT_ROW.store(u32::from(row), Ordering::Release);
    OBJECT_LAST_REJECT_SELECTOR.store(selector, Ordering::Release);
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

pub(super) fn reset() {
    ENABLED_FRAME_COUNT.store(0, Ordering::Release);
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
    for slot in OBJECT_DRAW_STATES.iter() {
        slot.key.store(0, Ordering::Release);
        slot.state.store(0, Ordering::Release);
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

fn record_object_contract_transition(draw_key: u32, state_code: u32) {
    if draw_key == 0 || state_code == 0 {
        return;
    }

    let slot = object_draw_state_slot(draw_key);
    let previous = slot.state.swap(state_code, Ordering::AcqRel);
    if previous != 0 && previous != state_code {
        OBJECT_CONTRACT_TRANSITIONS_THIS_FRAME.fetch_add(1, Ordering::Relaxed);
        OBJECT_LAST_CONTRACT_TRANSITION_FROM.store(previous, Ordering::Release);
        OBJECT_LAST_CONTRACT_TRANSITION_TO.store(state_code, Ordering::Release);
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
    slot
}
