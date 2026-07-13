//! Hook installation boundary for the NVR-style object PBR rewrite.
//!
//! This phase installs only shader creation and `SetShaders` ownership hooks.
//! Terrain/material-array hooks stay out until terrain contracts are proven.

use std::{
    ffi::{c_char, c_void},
    mem::size_of,
    ptr::null_mut,
    slice,
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;
use libpsycho::os::windows::{
    directx9::Device9Ref, hook::inline::inlinehook::InlineHookContainer,
    memory::validate_memory_range,
};

use super::{
    constants, device_resources, diagnostics, engine_contracts, object_contracts,
    object_replacement_record, shader_record, shader_registry, shader_registry::ShaderStage,
};
use engine_contracts::ObjectDrawRejectReason;
use object_contracts::{ObjectContractDecision, ObjectContractState};

const BS_SHADER_CREATE_VERTEX_SHADER_ADDR: usize = 0x00BE0FE0;
const BS_SHADER_CREATE_PIXEL_SHADER_ADDR: usize = 0x00BE1750;
const BS_SHADER_SET_SHADERS_ADDR: usize = 0x00BE1F90;
const NIDX9_RENDER_STATE_SET_TEXTURE_ADDR: usize = 0x00E88A20;
const PPLIGHTING_VERTEX_GROUP_C_ADDR: usize = 0x011FDE5C;
const PPLIGHTING_PIXEL_GROUP_B_ADDR: usize = 0x011FDB08;
const PPLIGHTING_VERTEX_GROUP_C_COUNT: usize = 0x67;
const PPLIGHTING_PIXEL_GROUP_B_COUNT: usize = 0xA0;
const TABLE_PPLIGHTING_VERTEX_C: u32 = 1;
const TABLE_PPLIGHTING_PIXEL_B: u32 = 2;
const TABLE_INDEX_UNKNOWN: u32 = u32::MAX;

const SET_SHADERS_PROLOGUE: &[u8] = &[
    0x8B, 0x0D, 0x4C, 0xF7, 0x26, 0x01, 0x56, 0x57, 0xE8, 0x23, 0xD8, 0x29, 0x00, 0x8B, 0xF0, 0xA1,
];
const CREATE_VERTEX_SHADER_PROLOGUE: &[u8] = &[
    0x6A, 0xFF, 0x68, 0x22, 0xD3, 0xF2, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0xB8, 0x98,
];
const CREATE_PIXEL_SHADER_PROLOGUE: &[u8] = &[
    0x6A, 0xFF, 0x68, 0x62, 0xD3, 0xF2, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0xB8, 0x9C,
];
const SET_TEXTURE_PROLOGUE: &[u8] = &[
    0x8B, 0x44, 0x24, 0x04, 0x8B, 0x54, 0x24, 0x08, 0x39, 0x94, 0x81, 0xA0, 0x10, 0x00, 0x00, 0x74,
];

type CreateVertexShaderFn = unsafe extern "thiscall" fn(
    *mut c_void,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
) -> *mut c_void;
type CreatePixelShaderFn = unsafe extern "thiscall" fn(
    *mut c_void,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
) -> *mut c_void;
type SetShadersFn = unsafe extern "thiscall" fn(*mut c_void, u32);
type SetTextureFn = unsafe extern "thiscall" fn(*mut c_void, u32, *mut c_void);

static CREATE_VERTEX_SHADER_HOOK: LazyLock<InlineHookContainer<CreateVertexShaderFn>> =
    LazyLock::new(InlineHookContainer::new);
static CREATE_PIXEL_SHADER_HOOK: LazyLock<InlineHookContainer<CreatePixelShaderFn>> =
    LazyLock::new(InlineHookContainer::new);
static SET_SHADERS_HOOK: LazyLock<InlineHookContainer<SetShadersFn>> =
    LazyLock::new(InlineHookContainer::new);
static SET_TEXTURE_HOOK: LazyLock<InlineHookContainer<SetTextureFn>> =
    LazyLock::new(InlineHookContainer::new);
static HOOKS_READY: AtomicBool = AtomicBool::new(false);
static CREATION_HOOKS_READY: AtomicBool = AtomicBool::new(false);
static SET_SHADERS_READY: AtomicBool = AtomicBool::new(false);
static RESTORE_ALL_PENDING: AtomicBool = AtomicBool::new(false);

pub(super) fn install() -> Result<()> {
    engine_contracts::install_core_contracts();

    let creation_ready = install_shader_creation_hooks();
    let set_shaders_ready = install_set_shaders_hook();
    let texture_tracking_ready = install_set_texture_hook();
    super::samplers::set_texture_tracking_ready(texture_tracking_ready);
    CREATION_HOOKS_READY.store(creation_ready, Ordering::Release);
    SET_SHADERS_READY.store(set_shaders_ready, Ordering::Release);
    HOOKS_READY.store(set_shaders_ready, Ordering::Release);

    let adopted = adopt_existing_object_shaders();
    if adopted != 0 {
        log::info!("[PBR] Object PBR adopted {adopted} existing shader wrapper(s)");
    }

    if set_shaders_ready {
        log::info!("[PBR] Object PBR SetShaders hook installed");
    } else {
        log::warn!(
            "[PBR] Object PBR mandatory SetShaders hook unavailable; creation={creation_ready}"
        );
    }
    if !creation_ready {
        log::info!(
            "[PBR] Object PBR creation hooks unavailable; lazy draw-time wrapper adoption remains enabled"
        );
    }
    if texture_tracking_ready {
        log::info!("[PBR] Object PBR texture-stage tracking installed");
    } else {
        log::warn!(
            "[PBR] Object PBR texture-stage tracking unavailable; sampler checks fall back to D3D GetTexture"
        );
    }

    Ok(())
}

pub(super) fn reset() {
    let _ = SET_SHADERS_HOOK.disable();
    let _ = SET_TEXTURE_HOOK.disable();
    let _ = CREATE_PIXEL_SHADER_HOOK.disable();
    let _ = CREATE_VERTEX_SHADER_HOOK.disable();
    HOOKS_READY.store(false, Ordering::Release);
    CREATION_HOOKS_READY.store(false, Ordering::Release);
    SET_SHADERS_READY.store(false, Ordering::Release);
}

fn install_set_texture_hook() -> bool {
    let Some(target) = resolve_hook_target(
        NIDX9_RENDER_STATE_SET_TEXTURE_ADDR,
        SET_TEXTURE_PROLOGUE,
        "NiDX9RenderState::SetTexture",
    ) else {
        return false;
    };

    match unsafe {
        SET_TEXTURE_HOOK.init("FNV NiDX9RenderState::SetTexture", target, hook_set_texture)
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!("[PBR] SetTexture hook skipped: {err}");
            return false;
        }
    }

    match SET_TEXTURE_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[PBR] SetTexture hook skipped: {err}");
            false
        }
    }
}

pub(super) fn hooks_ready() -> bool {
    HOOKS_READY.load(Ordering::Acquire)
}

pub(super) fn request_restore_all() {
    RESTORE_ALL_PENDING.store(true, Ordering::Release);
}

fn install_shader_creation_hooks() -> bool {
    let Some(vertex_target) = resolve_hook_target(
        BS_SHADER_CREATE_VERTEX_SHADER_ADDR,
        CREATE_VERTEX_SHADER_PROLOGUE,
        "CreateVertexShader",
    ) else {
        return false;
    };
    let Some(pixel_target) = resolve_hook_target(
        BS_SHADER_CREATE_PIXEL_SHADER_ADDR,
        CREATE_PIXEL_SHADER_PROLOGUE,
        "CreatePixelShader",
    ) else {
        return false;
    };

    if !install_create_vertex_shader_hook(vertex_target) {
        return false;
    }
    if !install_create_pixel_shader_hook(pixel_target) {
        let _ = CREATE_VERTEX_SHADER_HOOK.disable();
        return false;
    }

    true
}

fn install_create_vertex_shader_hook(target: *mut c_void) -> bool {
    match unsafe {
        CREATE_VERTEX_SHADER_HOOK.init(
            "FNV BSShader::CreateVertexShader",
            target,
            hook_create_vertex_shader,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!("[PBR] CreateVertexShader hook skipped: {err}");
            return false;
        }
    }

    match CREATE_VERTEX_SHADER_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[PBR] CreateVertexShader hook skipped: {err}");
            false
        }
    }
}

fn install_create_pixel_shader_hook(target: *mut c_void) -> bool {
    match unsafe {
        CREATE_PIXEL_SHADER_HOOK.init(
            "FNV BSShader::CreatePixelShader",
            target,
            hook_create_pixel_shader,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!("[PBR] CreatePixelShader hook skipped: {err}");
            return false;
        }
    }

    match CREATE_PIXEL_SHADER_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[PBR] CreatePixelShader hook skipped: {err}");
            false
        }
    }
}

fn install_set_shaders_hook() -> bool {
    let Some(target) = resolve_hook_target(
        BS_SHADER_SET_SHADERS_ADDR,
        SET_SHADERS_PROLOGUE,
        "SetShaders",
    ) else {
        return false;
    };

    match unsafe { SET_SHADERS_HOOK.init("FNV BSShader::SetShaders", target, hook_set_shaders) } {
        Ok(()) => {}
        Err(err) => {
            log::warn!("[PBR] SetShaders hook skipped: {err}");
            return false;
        }
    }

    match SET_SHADERS_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[PBR] SetShaders hook skipped: {err}");
            false
        }
    }
}

fn resolve_hook_target(
    entry_addr: usize,
    vanilla_prologue: &[u8],
    label: &str,
) -> Option<*mut c_void> {
    let probe_len = vanilla_prologue.len().max(5);
    let ptr = entry_addr as *const c_void;
    if let Err(err) = validate_memory_range(ptr, probe_len) {
        log::warn!("[PBR] Cannot read {label} prologue at 0x{entry_addr:08X}: {err}");
        return None;
    }

    let actual = unsafe { slice::from_raw_parts(entry_addr as *const u8, probe_len) };
    if actual.starts_with(vanilla_prologue) {
        return Some(entry_addr as *mut c_void);
    }

    if actual[0] == 0xE9 {
        let rel = i32::from_le_bytes([actual[1], actual[2], actual[3], actual[4]]);
        let target = (entry_addr as isize)
            .wrapping_add(5)
            .wrapping_add(rel as isize) as usize;
        if validate_memory_range(target as *const c_void, 8).is_ok() {
            log::info!(
                "[PBR] {label} already redirected at 0x{entry_addr:08X}; chaining target 0x{target:08X}"
            );
            return Some(target as *mut c_void);
        }
    }

    log::warn!(
        "[PBR] {label} prologue at 0x{entry_addr:08X} is neither vanilla nor a supported near jump"
    );
    None
}

unsafe extern "thiscall" fn hook_create_vertex_shader(
    shader_owner: *mut c_void,
    file_name: *const c_char,
    arg2: *const c_char,
    shader_type: *const c_char,
    shader_name: *const c_char,
) -> *mut c_void {
    let Ok(original) = CREATE_VERTEX_SHADER_HOOK.original() else {
        return null_mut();
    };

    let shader = unsafe { original(shader_owner, file_name, arg2, shader_type, shader_name) };
    capture_created_shader(shader, ShaderStage::Vertex, shader_name);
    shader
}

unsafe extern "thiscall" fn hook_create_pixel_shader(
    shader_owner: *mut c_void,
    file_name: *const c_char,
    arg2: *const c_char,
    shader_type: *const c_char,
    shader_name: *const c_char,
) -> *mut c_void {
    let Ok(original) = CREATE_PIXEL_SHADER_HOOK.original() else {
        return null_mut();
    };

    let shader = unsafe { original(shader_owner, file_name, arg2, shader_type, shader_name) };
    capture_created_shader(shader, ShaderStage::Pixel, shader_name);
    shader
}

unsafe extern "thiscall" fn hook_set_shaders(shader: *mut c_void, pass_index: u32) {
    let Ok(original) = SET_SHADERS_HOOK.original() else {
        return;
    };

    if !super::shader_enabled() {
        restore_disabled_shader_state();
        unsafe {
            original(shader, pass_index);
        }
        return;
    }

    if super::object_contracts_ready()
        && engine_contracts::eye_position_ready()
        && engine_contracts::shader_package_lifetime_ready()
        && try_apply_object_replacement()
    {
        unsafe {
            original(shader, pass_index);
        }
        return;
    }

    restore_current_pass_to_vanilla();
    diagnostics::record_object_fallback();
    unsafe {
        original(shader, pass_index);
    }
}

unsafe extern "thiscall" fn hook_set_texture(
    render_state: *mut c_void,
    stage: u32,
    texture: *mut c_void,
) {
    let selector = engine_contracts::current_draw_selector_address_fast();
    super::samplers::record_texture_binding(stage, texture, selector);

    let Ok(original) = SET_TEXTURE_HOOK.original() else {
        return;
    };
    unsafe {
        original(render_state, stage, texture);
    }
}

fn capture_created_shader(shader: *mut c_void, stage: ShaderStage, shader_name: *const c_char) {
    if shader.is_null() {
        return;
    }

    let extension = match stage {
        ShaderStage::Vertex => ".vso",
        ShaderStage::Pixel => ".pso",
    };
    let Some(sls_number) = shader_registry::sls_number_from_name(shader_name, extension) else {
        return;
    };
    let Some(template_ref) = shader_registry::object_template_id(stage, sls_number) else {
        return;
    };
    let Some(original_handle) = engine_contracts::shader_handle(shader, stage) else {
        return;
    };
    let (table_id, table_index) = identify_object_table_slot(shader, stage)
        .unwrap_or((shader_record::TABLE_UNKNOWN, TABLE_INDEX_UNKNOWN));

    if shader_record::store_created(
        shader,
        stage,
        original_handle,
        template_ref.id,
        table_id,
        table_index,
    )
    .is_some()
    {
        log::info!(
            "[PBR] Object PBR captured {:?} wrapper={shader:p} shader={} table={table_id}:{} handle={original_handle:p}",
            stage,
            template_ref.template.label,
            table_index_for_log(table_index)
        );
    }
}

fn try_apply_object_replacement() -> bool {
    let Some((vertex_shader, pixel_shader)) = engine_contracts::current_pass_shaders() else {
        return false;
    };
    record_current_table_pair(vertex_shader, pixel_shader);

    let vertex_record = match resolve_current_shader_record(vertex_shader, ShaderStage::Vertex) {
        Ok(record) => record,
        Err(reason) => {
            diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
            return false;
        }
    };
    let pixel_record = match resolve_current_shader_record(pixel_shader, ShaderStage::Pixel) {
        Ok(record) => record,
        Err(reason) => {
            diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
            return false;
        }
    };
    if vertex_record.stage != ShaderStage::Vertex || pixel_record.stage != ShaderStage::Pixel {
        diagnostics::record_object_draw_gate_rejection(
            ObjectDrawRejectReason::TableIdentityMismatch,
            0,
            0,
        );
        return false;
    }
    let vertex_record = ensure_table_identity(vertex_record);
    let pixel_record = ensure_table_identity(pixel_record);

    let draw_snapshot = engine_contracts::current_draw_snapshot();
    diagnostics::record_object_draw_context(draw_snapshot);
    let draw_key = object_draw_key(draw_snapshot, vertex_record, pixel_record);
    if let Some(rejection) = draw_snapshot.rejection {
        diagnostics::record_object_contract(
            draw_key,
            vertex_record.table_index,
            ObjectContractState::BlockedPassEntryTerrain,
        );
        diagnostics::record_object_draw_gate_rejection(
            rejection.reason,
            rejection.row,
            rejection.selector,
        );
        return false;
    }

    diagnostics::record_object_pair(
        template_sls(vertex_record),
        template_sls(pixel_record),
        vertex_record.table_id,
        vertex_record.table_index,
        pixel_record.table_id,
        pixel_record.table_index,
    );
    let contract = match object_contract_decision(vertex_record, pixel_record) {
        Ok(contract) => contract,
        Err(reason) => {
            diagnostics::record_object_contract(
                draw_key,
                vertex_record.table_index,
                contract_state_for_rejection(reason),
            );
            diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
            return false;
        }
    };
    diagnostics::record_object_contract(draw_key, contract.normalized_vertex_index, contract.state);
    if let Some(reason) = object_contract_rejection(contract.state) {
        diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
        return false;
    }

    let replacement_vertex = device_resources::object_shader_handle(vertex_record.template_id);
    let replacement_pixel = device_resources::object_shader_handle(pixel_record.template_id);
    diagnostics::record_object_handles(
        vertex_record.shader,
        pixel_record.shader,
        replacement_vertex,
        replacement_pixel,
    );

    let (Some(replacement_vertex), Some(replacement_pixel)) =
        (replacement_vertex, replacement_pixel)
    else {
        diagnostics::record_object_contract(
            draw_key,
            contract.normalized_vertex_index,
            ObjectContractState::BlockedMissingReplacementResource,
        );
        diagnostics::record_object_draw_gate_rejection(
            ObjectDrawRejectReason::MissingReplacementResource,
            0,
            0,
        );
        return false;
    };

    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        diagnostics::record_object_contract(
            draw_key,
            contract.normalized_vertex_index,
            ObjectContractState::BlockedMissingD3DState,
        );
        diagnostics::record_object_draw_gate_rejection(
            ObjectDrawRejectReason::MissingD3DState,
            0,
            0,
        );
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        diagnostics::record_object_contract(
            draw_key,
            contract.normalized_vertex_index,
            ObjectContractState::BlockedMissingD3DState,
        );
        diagnostics::record_object_draw_gate_rejection(
            ObjectDrawRejectReason::MissingD3DState,
            0,
            0,
        );
        return false;
    };
    let current_vertex_d3d = device.current_vertex_shader_raw().unwrap_or(null_mut());
    let current_pixel_d3d = device.current_pixel_shader_raw().unwrap_or(null_mut());
    diagnostics::record_object_d3d_state(
        current_vertex_d3d,
        current_pixel_d3d,
        replacement_vertex,
        replacement_pixel,
    );
    if let Err(reason) = object_replacement_record::validate_pixel_samplers(
        &device,
        pixel_record,
        draw_snapshot.selector,
    ) {
        diagnostics::record_object_contract(
            draw_key,
            contract.normalized_vertex_index,
            contract_state_for_rejection(reason),
        );
        diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
        return false;
    }

    let constant_version = constants::object_constant_version();
    let Ok(vertex_apply) = object_replacement_record::apply_shader(
        vertex_record,
        replacement_vertex,
        contract.state,
        current_vertex_d3d,
        constant_version,
    ) else {
        diagnostics::record_object_contract(
            draw_key,
            contract.normalized_vertex_index,
            ObjectContractState::BlockedHandleStateMismatch,
        );
        diagnostics::record_object_draw_gate_rejection(
            ObjectDrawRejectReason::HandleStateMismatch,
            0,
            0,
        );
        return false;
    };
    let Ok(pixel_apply) = object_replacement_record::apply_shader(
        pixel_record,
        replacement_pixel,
        contract.state,
        current_pixel_d3d,
        constant_version,
    ) else {
        restore_shader_record(vertex_record);
        diagnostics::record_object_contract(
            draw_key,
            contract.normalized_vertex_index,
            ObjectContractState::BlockedHandleStateMismatch,
        );
        diagnostics::record_object_draw_gate_rejection(
            ObjectDrawRejectReason::HandleStateMismatch,
            0,
            0,
        );
        return false;
    };

    upload_object_constants_if_needed(
        &device,
        vertex_record,
        pixel_record,
        constant_version,
        vertex_apply.needs_constants || pixel_apply.needs_constants,
    );

    diagnostics::record_object_replacement();
    true
}

fn upload_object_constants_if_needed(
    device: &Device9Ref<'_>,
    vertex_record: shader_record::ShaderRecordSnapshot,
    pixel_record: shader_record::ShaderRecordSnapshot,
    constant_version: u32,
    needs_constants: bool,
) {
    if !needs_constants {
        return;
    }

    if constants::upload_object_constants(device) {
        object_replacement_record::mark_constants_uploaded(
            vertex_record,
            pixel_record,
            constant_version,
        );
        diagnostics::record_object_constant_upload();
    }
}

fn record_current_table_pair(vertex_shader: *mut c_void, pixel_shader: *mut c_void) {
    let (vertex_table, vertex_index) =
        identify_object_table_slot(vertex_shader, ShaderStage::Vertex)
            .unwrap_or((shader_record::TABLE_UNKNOWN, TABLE_INDEX_UNKNOWN));
    let (pixel_table, pixel_index) = identify_object_table_slot(pixel_shader, ShaderStage::Pixel)
        .unwrap_or((shader_record::TABLE_UNKNOWN, TABLE_INDEX_UNKNOWN));

    diagnostics::record_object_pair(
        sls_from_table_slot(ShaderStage::Vertex, vertex_table, vertex_index),
        sls_from_table_slot(ShaderStage::Pixel, pixel_table, pixel_index),
        vertex_table,
        vertex_index,
        pixel_table,
        pixel_index,
    );
    diagnostics::record_object_handles(vertex_shader, pixel_shader, None, None);
}

fn sls_from_table_slot(stage: ShaderStage, table_id: u32, table_index: u32) -> u16 {
    if table_id != expected_stage_table_id(stage) || table_index == TABLE_INDEX_UNKNOWN {
        return 0;
    }
    u16::try_from(table_index)
        .ok()
        .and_then(|index| 2000u16.checked_add(index))
        .unwrap_or(0)
}

fn resolve_current_shader_record(
    shader: *mut c_void,
    stage: ShaderStage,
) -> std::result::Result<shader_record::ShaderRecordSnapshot, ObjectDrawRejectReason> {
    if let Some(record) = shader_record::find(shader) {
        return Ok(ensure_table_identity(record));
    }

    let Some((table_id, table_index)) = identify_object_table_slot(shader, stage) else {
        return Err(ObjectDrawRejectReason::MissingTableIdentity);
    };
    if table_id != expected_stage_table_id(stage) {
        return Err(ObjectDrawRejectReason::TableIdentityMismatch);
    }
    if object_contracts::stage_table_slot_is_terrain(stage, table_index) {
        return Err(ObjectDrawRejectReason::TerrainTableSlot);
    }
    if object_contracts::stage_table_slot_is_envmap(stage, table_index) {
        return Err(ObjectDrawRejectReason::EnvMapTableSlot);
    }

    let sls_number = sls_from_table_slot(stage, table_id, table_index);
    let Some(template_ref) = shader_registry::object_template_id(stage, sls_number) else {
        return Err(ObjectDrawRejectReason::MissingShaderRecord);
    };

    shader_record::adopt_existing(shader, stage, template_ref.id, table_id, table_index)
        .or_else(|| shader_record::find(shader))
        .ok_or(ObjectDrawRejectReason::MissingShaderRecord)
}

fn ensure_table_identity(
    record: shader_record::ShaderRecordSnapshot,
) -> shader_record::ShaderRecordSnapshot {
    if record.table_id != shader_record::TABLE_UNKNOWN {
        return record;
    }
    let Some((table_id, table_index)) = identify_object_table_slot(record.shader, record.stage)
    else {
        return record;
    };

    shader_record::set_table_slot(record.shader, table_id, table_index);
    shader_record::ShaderRecordSnapshot {
        table_id,
        table_index,
        ..record
    }
}

fn template_sls(record: shader_record::ShaderRecordSnapshot) -> u16 {
    shader_registry::object_template_at(record.template_id)
        .map_or(0, |template| template.sls_number)
}

fn object_contract_decision(
    vertex_record: shader_record::ShaderRecordSnapshot,
    pixel_record: shader_record::ShaderRecordSnapshot,
) -> std::result::Result<ObjectContractDecision, ObjectDrawRejectReason> {
    if vertex_record.table_id == shader_record::TABLE_UNKNOWN
        || pixel_record.table_id == shader_record::TABLE_UNKNOWN
    {
        return Err(ObjectDrawRejectReason::MissingTableIdentity);
    }
    if vertex_record.table_id != TABLE_PPLIGHTING_VERTEX_C
        || pixel_record.table_id != TABLE_PPLIGHTING_PIXEL_B
    {
        return Err(ObjectDrawRejectReason::TableIdentityMismatch);
    }
    if !record_matches_expected_table_slot(vertex_record)
        || !record_matches_expected_table_slot(pixel_record)
    {
        return Err(ObjectDrawRejectReason::TableIdentityMismatch);
    }

    Ok(object_contracts::classify_pair(
        vertex_record.table_index,
        pixel_record.table_index,
    ))
}

fn record_matches_expected_table_slot(record: shader_record::ShaderRecordSnapshot) -> bool {
    let Some(template) = shader_registry::object_template_at(record.template_id) else {
        return false;
    };
    let expected_table = match template.stage {
        ShaderStage::Vertex => TABLE_PPLIGHTING_VERTEX_C,
        ShaderStage::Pixel => TABLE_PPLIGHTING_PIXEL_B,
    };
    let expected_index = u32::from(template.sls_number.saturating_sub(2000));

    record.stage == template.stage
        && record.table_id == expected_table
        && record.table_index == expected_index
}

fn object_contract_rejection(state: ObjectContractState) -> Option<ObjectDrawRejectReason> {
    if object_contracts::state_is_implemented(state) {
        return None;
    }

    Some(match state {
        ObjectContractState::BlockedTerrain | ObjectContractState::BlockedPassEntryTerrain => {
            ObjectDrawRejectReason::TerrainTableSlot
        }
        ObjectContractState::BlockedEnvMap => ObjectDrawRejectReason::EnvMapTableSlot,
        ObjectContractState::BlockedMissingTemplate
        | ObjectContractState::BlockedMissingShaderRecord => {
            ObjectDrawRejectReason::MissingShaderRecord
        }
        ObjectContractState::BlockedMissingD3DState => ObjectDrawRejectReason::MissingD3DState,
        ObjectContractState::BlockedMissingTableIdentity => {
            ObjectDrawRejectReason::MissingTableIdentity
        }
        ObjectContractState::BlockedTableIdentityMismatch => {
            ObjectDrawRejectReason::TableIdentityMismatch
        }
        ObjectContractState::BlockedMissingReplacementResource => {
            ObjectDrawRejectReason::MissingReplacementResource
        }
        ObjectContractState::BlockedHandleStateMismatch => {
            ObjectDrawRejectReason::HandleStateMismatch
        }
        ObjectContractState::BlockedMissingSampler => ObjectDrawRejectReason::MissingSampler,
        ObjectContractState::BlockedUnknown | ObjectContractState::None => {
            ObjectDrawRejectReason::UnsupportedObjectPair
        }
        _ => ObjectDrawRejectReason::UnsupportedObjectPair,
    })
}

fn contract_state_for_rejection(reason: ObjectDrawRejectReason) -> ObjectContractState {
    match reason {
        ObjectDrawRejectReason::CloseTerrainMaterial
        | ObjectDrawRejectReason::TerrainZeroResource
        | ObjectDrawRejectReason::TerrainLightResource
        | ObjectDrawRejectReason::TerrainHelper
        | ObjectDrawRejectReason::TerrainTableSlot => ObjectContractState::BlockedTerrain,
        ObjectDrawRejectReason::EnvMapTableSlot => ObjectContractState::BlockedEnvMap,
        ObjectDrawRejectReason::MissingD3DState => ObjectContractState::BlockedMissingD3DState,
        ObjectDrawRejectReason::MissingShaderRecord => {
            ObjectContractState::BlockedMissingShaderRecord
        }
        ObjectDrawRejectReason::MissingTableIdentity => {
            ObjectContractState::BlockedMissingTableIdentity
        }
        ObjectDrawRejectReason::TableIdentityMismatch => {
            ObjectContractState::BlockedTableIdentityMismatch
        }
        ObjectDrawRejectReason::UnsupportedObjectPair => ObjectContractState::BlockedUnknown,
        ObjectDrawRejectReason::MissingReplacementResource => {
            ObjectContractState::BlockedMissingReplacementResource
        }
        ObjectDrawRejectReason::HandleStateMismatch => {
            ObjectContractState::BlockedHandleStateMismatch
        }
        ObjectDrawRejectReason::MissingSampler => ObjectContractState::BlockedMissingSampler,
    }
}

fn object_draw_key(
    snapshot: engine_contracts::DrawSnapshot,
    vertex_record: shader_record::ShaderRecordSnapshot,
    pixel_record: shader_record::ShaderRecordSnapshot,
) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    if snapshot.selector != 0 {
        hash = hash_word(hash, snapshot.selector);
        hash = hash_word(hash, snapshot.pass_entry_list);
        hash = hash_word(hash, snapshot.selector_state as usize);
    } else {
        hash = hash_word(hash, vertex_record.shader as usize);
        hash = hash_word(hash, pixel_record.shader as usize);
    }

    if hash == 0 { 1 } else { hash }
}

fn hash_word(hash: u32, value: usize) -> u32 {
    let folded = value as u32;
    hash ^ folded.wrapping_mul(0x0100_0193).rotate_left(5)
}

fn restore_current_pass_to_vanilla() {
    let Some((vertex_shader, pixel_shader)) = engine_contracts::current_pass_shaders() else {
        return;
    };
    if let Some(record) = shader_record::find(vertex_shader) {
        restore_shader_record(record);
    }
    if let Some(record) = shader_record::find(pixel_shader) {
        restore_shader_record(record);
    }
}

fn restore_shader_record(record: shader_record::ShaderRecordSnapshot) {
    if shader_record::restore(record) {
        object_replacement_record::mark_restored(record);
    }
}

fn restore_disabled_shader_state() {
    if RESTORE_ALL_PENDING.swap(false, Ordering::AcqRel) {
        let restored = shader_record::restore_all_mutated();
        object_replacement_record::reset();
        if restored != 0 {
            log::info!("[PBR] Restored {restored} object shader wrapper(s) after disabling PBR");
        }
    }
    restore_current_pass_to_vanilla();
}

fn adopt_existing_object_shaders() -> u32 {
    let mut adopted = 0u32;
    for template_id in 0..shader_registry::object_template_count() {
        let Some(template) = shader_registry::object_template_at(template_id as u16) else {
            continue;
        };
        let local_index = template.sls_number.saturating_sub(2000) as usize;
        let shader = match template.stage {
            ShaderStage::Vertex => read_shader_array_slot(
                PPLIGHTING_VERTEX_GROUP_C_ADDR,
                PPLIGHTING_VERTEX_GROUP_C_COUNT,
                local_index,
            ),
            ShaderStage::Pixel => read_shader_array_slot(
                PPLIGHTING_PIXEL_GROUP_B_ADDR,
                PPLIGHTING_PIXEL_GROUP_B_COUNT,
                local_index,
            ),
        };
        let Some(shader) = shader else {
            continue;
        };
        let Some((table_id, table_index)) = expected_object_table_slot(template) else {
            continue;
        };
        if shader_record::adopt_existing(
            shader,
            template.stage,
            template_id as u16,
            table_id,
            table_index,
        )
        .is_some()
        {
            adopted += 1;
        }
    }
    adopted
}

fn expected_object_table_slot(template: &shader_registry::ShaderTemplate) -> Option<(u32, u32)> {
    let table_id = expected_stage_table_id(template.stage);
    let index = u32::from(template.sls_number.checked_sub(2000)?);
    Some((table_id, index))
}

fn expected_stage_table_id(stage: ShaderStage) -> u32 {
    match stage {
        ShaderStage::Vertex => TABLE_PPLIGHTING_VERTEX_C,
        ShaderStage::Pixel => TABLE_PPLIGHTING_PIXEL_B,
    }
}

fn identify_object_table_slot(shader: *mut c_void, stage: ShaderStage) -> Option<(u32, u32)> {
    match stage {
        ShaderStage::Vertex => find_shader_array_index(
            PPLIGHTING_VERTEX_GROUP_C_ADDR,
            PPLIGHTING_VERTEX_GROUP_C_COUNT,
            shader,
        )
        .map(|index| (TABLE_PPLIGHTING_VERTEX_C, index)),
        ShaderStage::Pixel => find_shader_array_index(
            PPLIGHTING_PIXEL_GROUP_B_ADDR,
            PPLIGHTING_PIXEL_GROUP_B_COUNT,
            shader,
        )
        .map(|index| (TABLE_PPLIGHTING_PIXEL_B, index)),
    }
}

fn find_shader_array_index(base: usize, count: usize, shader: *mut c_void) -> Option<u32> {
    if shader.is_null() {
        return None;
    }
    let byte_len = count * size_of::<*mut c_void>();
    if validate_memory_range(base as *const c_void, byte_len).is_err() {
        return None;
    }

    for index in 0..count {
        let slot = unsafe { (base as *const *mut c_void).add(index) };
        if unsafe { slot.read() } == shader {
            return Some(index as u32);
        }
    }
    None
}

fn table_index_for_log(index: u32) -> String {
    if index == TABLE_INDEX_UNKNOWN {
        "unknown".to_owned()
    } else {
        index.to_string()
    }
}

fn read_shader_array_slot(base: usize, count: usize, index: usize) -> Option<*mut c_void> {
    if index >= count {
        return None;
    }
    let byte_len = count * size_of::<*mut c_void>();
    if validate_memory_range(base as *const c_void, byte_len).is_err() {
        return None;
    }

    let slot = unsafe { (base as *const *mut c_void).add(index) };
    let shader = unsafe { slot.read() };
    (!shader.is_null()).then_some(shader)
}
