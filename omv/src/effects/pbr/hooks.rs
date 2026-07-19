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
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::Result;
use libpsycho::os::windows::{
    directx9::Device9Ref, hook::inline::inlinehook::InlineHookContainer,
    memory::validate_memory_range,
};

use super::{
    constants, device_resources, diagnostics, engine_contracts, object_contracts,
    object_replacement_record, samplers, shader_record, shader_registry,
    shader_registry::ShaderStage,
};
use engine_contracts::ObjectDrawRejectReason;
use object_contracts::{ObjectContractDecision, ObjectContractState};

const BS_SHADER_CREATE_VERTEX_SHADER_ADDR: usize = 0x00BE0FE0;
const BS_SHADER_CREATE_PIXEL_SHADER_ADDR: usize = 0x00BE1750;
const BS_SHADER_SET_SHADERS_ADDR: usize = 0x00BE1F90;
const NIDX9_RENDER_STATE_SET_TEXTURE_ADDR: usize = 0x00E88A20;
const PPLIGHTING_VERTEX_GROUP_A_ADDR: usize = 0x011FDD88;
const PPLIGHTING_VERTEX_GROUP_B_ADDR: usize = 0x011FDE04;
const PPLIGHTING_VERTEX_GROUP_C_ADDR: usize = 0x011FDE5C;
const PPLIGHTING_PIXEL_GROUP_A_ADDR: usize = 0x011FDA48;
const PPLIGHTING_PIXEL_GROUP_B_ADDR: usize = 0x011FDB08;
const PPLIGHTING_VERTEX_GROUP_A_COUNT: usize = 0x1F;
const PPLIGHTING_VERTEX_GROUP_B_COUNT: usize = 0x16;
const PPLIGHTING_VERTEX_GROUP_C_COUNT: usize = 0x67;
const PPLIGHTING_PIXEL_GROUP_A_COUNT: usize = 0x30;
const PPLIGHTING_PIXEL_GROUP_B_COUNT: usize = 0xA0;
const TABLE_PPLIGHTING_VERTEX_C: u32 = 1;
const TABLE_PPLIGHTING_PIXEL_B: u32 = 2;
const TABLE_INDEX_UNKNOWN: u32 = u32::MAX;
const LAND_LOD_PASS_INDEX: u32 = 0xFE;
const LAND_LOD_VERTEX_INDEX: usize = 2;
const LAND_LOD_PIXEL_INDEX: usize = 3;
const LAND_LOD_SAMPLERS: &[u32] = &[0, 1, 4, 6, 7];
const TERRAIN_FADE_PASS_INDEX: u32 = 560;
const TERRAIN_FADE_VERTEX_INDEX: usize = 80;
const TERRAIN_FADE_PIXEL_INDEX: usize = 82;
const TERRAIN_FADE_SAMPLERS: &[u32] = &[0, 1, 2];
const CLOSE_TERRAIN_FIRST_PASS: u32 = 503;
const CLOSE_TERRAIN_LAST_PASS: u32 = 558;
const CLOSE_TERRAIN_VERTEX_INDEX: usize = 100;
const CLOSE_TERRAIN_FIRST_PIXEL_INDEX: usize = 92;
const CLOSE_TERRAIN_LAST_PIXEL_INDEX: usize = 147;
const CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET: u32 = 411;
const PENDING_DRAW_NONE: u32 = 0;
const PENDING_DRAW_OBJECT: u32 = 1;
const PENDING_DRAW_LAND_LOD: u32 = 2;
const PENDING_DRAW_TERRAIN_FADE: u32 = 3;
const PENDING_DRAW_CLOSE_TERRAIN: u32 = 4;
const TABLE_LOOKUP_CACHE_COUNT: usize = 512;

#[derive(Clone, Copy)]
struct PplightingTableSlot {
    label: &'static str,
    index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CloseTerrainVariant {
    pixel_index: usize,
    pixel_sls: u16,
    texture_count: u32,
    point_light_capacity: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CloseTerrainDraw {
    pixel_index: usize,
    replacement: Option<CloseTerrainVariant>,
}

struct TableLookupCacheEntry {
    shader: AtomicUsize,
    base: AtomicUsize,
    index: AtomicU32,
}

impl TableLookupCacheEntry {
    fn new() -> Self {
        Self {
            shader: AtomicUsize::new(0),
            base: AtomicUsize::new(0),
            index: AtomicU32::new(u32::MAX),
        }
    }
}

#[derive(Clone, Copy)]
struct PreparedObjectReplacement {
    vertex_record: shader_record::ShaderRecordSnapshot,
    pixel_record: shader_record::ShaderRecordSnapshot,
    replacement_vertex: *mut c_void,
    replacement_pixel: *mut c_void,
    draw_trace: diagnostics::ObjectDrawTrace,
    normalized_vertex_index: u32,
    contract_state: ObjectContractState,
    uses_native_specular_fade: bool,
    diagnostics_enabled: bool,
}

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
static DIRECT_D3D_ACTIVE: AtomicBool = AtomicBool::new(false);
static DIRECT_NATIVE_VERTEX: AtomicUsize = AtomicUsize::new(0);
static DIRECT_NATIVE_PIXEL: AtomicUsize = AtomicUsize::new(0);
static PENDING_DRAW_KIND: AtomicU32 = AtomicU32::new(PENDING_DRAW_NONE);
static PENDING_DRAW_PASS_INDEX: AtomicU32 = AtomicU32::new(0);
static PENDING_CLOSE_TERRAIN_PIXEL_INDEX: AtomicU32 = AtomicU32::new(0);
static PENDING_DRAW_EVALUATED: AtomicBool = AtomicBool::new(false);
static LAND_LOD_FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static LAND_LOD_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_WARMING_LOGGED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static DIRECT_RESTORE_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static LAND_LOD_LAST_CONSTANT_SIGNATURE: AtomicU32 = AtomicU32::new(0);
static LAND_LOD_CONSTANT_LOG_COUNT: AtomicU32 = AtomicU32::new(0);
static SHADER_TABLES_READABLE: LazyLock<bool> = LazyLock::new(|| {
    [
        (
            PPLIGHTING_VERTEX_GROUP_A_ADDR,
            PPLIGHTING_VERTEX_GROUP_A_COUNT,
        ),
        (
            PPLIGHTING_VERTEX_GROUP_B_ADDR,
            PPLIGHTING_VERTEX_GROUP_B_COUNT,
        ),
        (
            PPLIGHTING_VERTEX_GROUP_C_ADDR,
            PPLIGHTING_VERTEX_GROUP_C_COUNT,
        ),
        (
            PPLIGHTING_PIXEL_GROUP_A_ADDR,
            PPLIGHTING_PIXEL_GROUP_A_COUNT,
        ),
        (
            PPLIGHTING_PIXEL_GROUP_B_ADDR,
            PPLIGHTING_PIXEL_GROUP_B_COUNT,
        ),
    ]
    .into_iter()
    .all(|(base, count)| {
        validate_memory_range(base as *const c_void, count * size_of::<*mut c_void>()).is_ok()
    })
});
static TABLE_LOOKUP_CACHE: LazyLock<[TableLookupCacheEntry; TABLE_LOOKUP_CACHE_COUNT]> =
    LazyLock::new(|| std::array::from_fn(|_| TableLookupCacheEntry::new()));

pub(super) fn install() -> Result<()> {
    if HOOKS_READY.load(Ordering::Acquire) {
        engine_contracts::install_core_contracts();
        super::samplers::set_texture_tracking_ready(SET_TEXTURE_HOOK.is_enabled());
        adopt_existing_object_shaders();
        return Ok(());
    }

    let creation_ready = install_shader_creation_hooks();
    let set_shaders_ready = install_set_shaders_hook();
    let texture_tracking_ready = install_set_texture_hook();
    super::samplers::set_texture_tracking_ready(texture_tracking_ready);
    CREATION_HOOKS_READY.store(creation_ready, Ordering::Release);
    SET_SHADERS_READY.store(set_shaders_ready, Ordering::Release);
    HOOKS_READY.store(set_shaders_ready, Ordering::Release);
    if !set_shaders_ready {
        reset();
        super::samplers::set_texture_tracking_ready(false);
        log::warn!("[PBR] Native PBR blocked: mandatory SetShaders hook unavailable");
        return Ok(());
    }

    engine_contracts::install_core_contracts();

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
    restore_direct_d3d_state();
    let _ = SET_SHADERS_HOOK.disable();
    let _ = SET_TEXTURE_HOOK.disable();
    let _ = CREATE_PIXEL_SHADER_HOOK.disable();
    let _ = CREATE_VERTEX_SHADER_HOOK.disable();
    HOOKS_READY.store(false, Ordering::Release);
    CREATION_HOOKS_READY.store(false, Ordering::Release);
    SET_SHADERS_READY.store(false, Ordering::Release);
    DIRECT_D3D_ACTIVE.store(false, Ordering::Release);
    DIRECT_NATIVE_VERTEX.store(0, Ordering::Release);
    DIRECT_NATIVE_PIXEL.store(0, Ordering::Release);
    PENDING_DRAW_KIND.store(PENDING_DRAW_NONE, Ordering::Release);
    PENDING_DRAW_PASS_INDEX.store(0, Ordering::Release);
    PENDING_CLOSE_TERRAIN_PIXEL_INDEX.store(0, Ordering::Release);
    PENDING_DRAW_EVALUATED.store(false, Ordering::Release);
    LAND_LOD_FIRST_BIND_LOGGED.store(false, Ordering::Release);
    LAND_LOD_FAILURE_LOGGED.store(false, Ordering::Release);
    TERRAIN_FADE_FIRST_BIND_LOGGED.store(false, Ordering::Release);
    TERRAIN_FADE_FAILURE_LOGGED.store(false, Ordering::Release);
    CLOSE_TERRAIN_FIRST_BIND_LOGGED.store(false, Ordering::Release);
    CLOSE_TERRAIN_WARMING_LOGGED.store(false, Ordering::Release);
    CLOSE_TERRAIN_FAILURE_LOGGED.store(false, Ordering::Release);
    DIRECT_RESTORE_FAILURE_LOGGED.store(false, Ordering::Release);
    LAND_LOD_LAST_CONSTANT_SIGNATURE.store(0, Ordering::Release);
    LAND_LOD_CONSTANT_LOG_COUNT.store(0, Ordering::Release);
}

fn install_set_texture_hook() -> bool {
    if SET_TEXTURE_HOOK.is_initialized() {
        return enable_prepared_hook(&SET_TEXTURE_HOOK, "SetTexture");
    }
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

fn install_shader_creation_hooks() -> bool {
    if CREATE_VERTEX_SHADER_HOOK.is_initialized() && CREATE_PIXEL_SHADER_HOOK.is_initialized() {
        return enable_prepared_hook(&CREATE_VERTEX_SHADER_HOOK, "CreateVertexShader")
            && enable_prepared_hook(&CREATE_PIXEL_SHADER_HOOK, "CreatePixelShader");
    }

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
    if CREATE_VERTEX_SHADER_HOOK.is_initialized() {
        return enable_prepared_hook(&CREATE_VERTEX_SHADER_HOOK, "CreateVertexShader");
    }
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
    if CREATE_PIXEL_SHADER_HOOK.is_initialized() {
        return enable_prepared_hook(&CREATE_PIXEL_SHADER_HOOK, "CreatePixelShader");
    }
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
    if SET_SHADERS_HOOK.is_initialized() {
        return enable_prepared_hook(&SET_SHADERS_HOOK, "SetShaders");
    }
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

fn enable_prepared_hook<F>(hook: &InlineHookContainer<F>, label: &'static str) -> bool
where
    F: libpsycho::ffi::fnptr::Function,
{
    if hook.is_enabled() {
        return true;
    }
    match hook.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[PBR] {label} hook could not be re-enabled: {err}");
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

    restore_direct_d3d_state();
    PENDING_DRAW_KIND.store(PENDING_DRAW_NONE, Ordering::Release);

    if !super::shader_enabled() {
        unsafe {
            original(shader, pass_index);
        }
        return;
    }

    if super::terrain_lod_enabled() && current_pass_is_land_lod(pass_index) {
        engine_contracts::enable_fog_for_pass(pass_index);
        unsafe {
            original(shader, pass_index);
        }
        if super::land_lod_contracts_ready() {
            set_pending_draw(PENDING_DRAW_LAND_LOD, pass_index, 0);
        } else {
            diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::LandLod);
        }
        return;
    }

    if super::terrain_fade_enabled() && current_pass_is_terrain_fade(pass_index) {
        engine_contracts::enable_fog_for_pass(pass_index);
        unsafe {
            original(shader, pass_index);
        }
        if super::terrain_fade_contracts_ready() {
            set_pending_draw(PENDING_DRAW_TERRAIN_FADE, pass_index, 0);
        } else {
            diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::TerrainFade);
        }
        return;
    }

    if super::close_terrain_enabled()
        && engine_contracts::terrain_contract_available()
        && let Some(draw) = current_close_terrain_draw(pass_index)
    {
        unsafe {
            original(shader, pass_index);
        }
        if let Some(variant) = draw.replacement {
            if super::close_terrain_contract_available()
                && device_resources::close_terrain_variant_resources_ready(variant.pixel_sls)
            {
                set_pending_draw(
                    PENDING_DRAW_CLOSE_TERRAIN,
                    pass_index,
                    variant.pixel_index as u32,
                );
            } else {
                diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
                if super::close_terrain_contract_available()
                    && !CLOSE_TERRAIN_WARMING_LOGGED.swap(true, Ordering::AcqRel)
                {
                    log::info!(
                        "[PBR] CloseTerrain draw remains vanilla while selected variant SLS{} warms",
                        variant.pixel_sls
                    );
                }
            }
        } else {
            diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
        }
        return;
    }

    unsafe {
        original(shader, pass_index);
    }
    if super::object_contract_available()
        && engine_contracts::eye_position_ready_for_pass(pass_index)
    {
        set_pending_draw(PENDING_DRAW_OBJECT, pass_index, 0);
    }
}

fn set_pending_draw(kind: u32, pass_index: u32, close_terrain_pixel_index: u32) {
    PENDING_DRAW_PASS_INDEX.store(pass_index, Ordering::Release);
    PENDING_CLOSE_TERRAIN_PIXEL_INDEX.store(close_terrain_pixel_index, Ordering::Release);
    PENDING_DRAW_EVALUATED.store(false, Ordering::Release);
    PENDING_DRAW_KIND.store(kind, Ordering::Release);
}

fn current_pass_is_land_lod(pass_index: u32) -> bool {
    if pass_index != LAND_LOD_PASS_INDEX {
        return false;
    }
    let Some((vertex, pixel)) = engine_contracts::current_pass_shaders_fast() else {
        return false;
    };
    let expected_vertex = read_shader_array_slot(
        PPLIGHTING_VERTEX_GROUP_C_ADDR,
        PPLIGHTING_VERTEX_GROUP_C_COUNT,
        LAND_LOD_VERTEX_INDEX,
    );
    let expected_pixel = read_shader_array_slot(
        PPLIGHTING_PIXEL_GROUP_B_ADDR,
        PPLIGHTING_PIXEL_GROUP_B_COUNT,
        LAND_LOD_PIXEL_INDEX,
    );

    expected_vertex == Some(vertex) && expected_pixel == Some(pixel)
}

fn current_pass_is_terrain_fade(pass_index: u32) -> bool {
    if pass_index != TERRAIN_FADE_PASS_INDEX {
        return false;
    }
    let Some((vertex, pixel)) = engine_contracts::current_pass_shaders_fast() else {
        return false;
    };
    read_shader_array_slot(
        PPLIGHTING_VERTEX_GROUP_C_ADDR,
        PPLIGHTING_VERTEX_GROUP_C_COUNT,
        TERRAIN_FADE_VERTEX_INDEX,
    ) == Some(vertex)
        && read_shader_array_slot(
            PPLIGHTING_PIXEL_GROUP_B_ADDR,
            PPLIGHTING_PIXEL_GROUP_B_COUNT,
            TERRAIN_FADE_PIXEL_INDEX,
        ) == Some(pixel)
}

fn current_close_terrain_draw(pass_index: u32) -> Option<CloseTerrainDraw> {
    let (vertex, pixel) = engine_contracts::current_pass_shaders_fast()?;
    if read_shader_array_slot(
        PPLIGHTING_VERTEX_GROUP_C_ADDR,
        PPLIGHTING_VERTEX_GROUP_C_COUNT,
        CLOSE_TERRAIN_VERTEX_INDEX,
    ) != Some(vertex)
    {
        return None;
    }
    let pixel_index = find_shader_array_index(
        PPLIGHTING_PIXEL_GROUP_B_ADDR,
        PPLIGHTING_PIXEL_GROUP_B_COUNT,
        pixel,
    )? as usize;
    close_terrain_draw(pass_index, pixel_index)
}

fn close_terrain_draw(pass_index: u32, pixel_index: usize) -> Option<CloseTerrainDraw> {
    if !(CLOSE_TERRAIN_FIRST_PASS..=CLOSE_TERRAIN_LAST_PASS).contains(&pass_index)
        || !(CLOSE_TERRAIN_FIRST_PIXEL_INDEX..=CLOSE_TERRAIN_LAST_PIXEL_INDEX)
            .contains(&pixel_index)
        || pass_index != pixel_index as u32 + CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET
    {
        return None;
    }

    Some(CloseTerrainDraw {
        pixel_index,
        replacement: close_terrain_variant(pass_index, pixel_index),
    })
}

fn close_terrain_variant(pass_index: u32, pixel_index: usize) -> Option<CloseTerrainVariant> {
    if !(CLOSE_TERRAIN_FIRST_PASS..=CLOSE_TERRAIN_LAST_PASS).contains(&pass_index)
        || !(CLOSE_TERRAIN_FIRST_PIXEL_INDEX..=CLOSE_TERRAIN_LAST_PIXEL_INDEX)
            .contains(&pixel_index)
        || pass_index != pixel_index as u32 + CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET
    {
        return None;
    }

    let family_index = pixel_index - CLOSE_TERRAIN_FIRST_PIXEL_INDEX;
    let point_light_capacity = match family_index % 8 {
        0 => 0,
        2 => 6,
        4 => 12,
        6 => 24,
        _ => return None,
    };

    Some(CloseTerrainVariant {
        pixel_index,
        pixel_sls: 2000u16 + pixel_index as u16,
        texture_count: (family_index / 8 + 1) as u32,
        point_light_capacity,
    })
}

fn bind_land_lod_replacement() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        log_land_lod_failure("D3D device unavailable");
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        log_land_lod_failure("D3D device invalid");
        return;
    };
    let Some(vertex_wrapper) = read_shader_array_slot(
        PPLIGHTING_VERTEX_GROUP_C_ADDR,
        PPLIGHTING_VERTEX_GROUP_C_COUNT,
        LAND_LOD_VERTEX_INDEX,
    ) else {
        log_land_lod_failure("native vertex wrapper unavailable");
        return;
    };
    let Some(pixel_wrapper) = read_shader_array_slot(
        PPLIGHTING_PIXEL_GROUP_B_ADDR,
        PPLIGHTING_PIXEL_GROUP_B_COUNT,
        LAND_LOD_PIXEL_INDEX,
    ) else {
        log_land_lod_failure("native pixel wrapper unavailable");
        return;
    };
    let Some(native_vertex) =
        engine_contracts::shader_handle_fast(vertex_wrapper, ShaderStage::Vertex)
    else {
        log_land_lod_failure("native vertex handle unavailable");
        return;
    };
    let Some(native_pixel) =
        engine_contracts::shader_handle_fast(pixel_wrapper, ShaderStage::Pixel)
    else {
        log_land_lod_failure("native pixel handle unavailable");
        return;
    };
    if device.current_vertex_shader_raw().ok() != Some(native_vertex)
        || device.current_pixel_shader_raw().ok() != Some(native_pixel)
    {
        log_land_lod_failure("engine did not bind the proven native pair");
        return;
    }
    if LAND_LOD_SAMPLERS
        .iter()
        .any(|stage| device.texture_raw(*stage).is_none())
    {
        log_land_lod_failure("required native sampler is unbound");
        return;
    }
    let Some(replacement_vertex) = device_resources::land_lod_shader_handle(ShaderStage::Vertex)
    else {
        diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::LandLod);
        return;
    };
    let Some(replacement_pixel) = device_resources::land_lod_shader_handle(ShaderStage::Pixel)
    else {
        diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::LandLod);
        return;
    };
    let Some(requested_constants) = constants::upload_terrain_constants(&device, None) else {
        log_land_lod_failure("terrain constants could not be uploaded");
        return;
    };
    if diagnostics::detailed_enabled()
        && let Some(observed_constants) = constants::read_terrain_constants(&device)
    {
        log_land_lod_constants(requested_constants, observed_constants);
    }

    if !bind_direct_pair(
        &device,
        native_vertex,
        native_pixel,
        replacement_vertex,
        replacement_pixel,
    ) {
        log_land_lod_failure("replacement pair could not be bound");
        return;
    }

    if !LAND_LOD_FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[PBR] LandLOD PBR active pass=0x{LAND_LOD_PASS_INDEX:03X} vertex=C[{LAND_LOD_VERTEX_INDEX}] pixel=B[{LAND_LOD_PIXEL_INDEX}]"
        );
    }
    diagnostics::record_terrain_replacement(diagnostics::TerrainDrawFamily::LandLod);
}

fn bind_terrain_fade_replacement() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        log_terrain_fade_failure("D3D device unavailable");
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        log_terrain_fade_failure("D3D device invalid");
        return;
    };
    let Some((native_vertex, native_pixel)) =
        native_shader_pair(TERRAIN_FADE_VERTEX_INDEX, TERRAIN_FADE_PIXEL_INDEX, &device)
    else {
        log_terrain_fade_failure("engine did not bind the proven native pair");
        return;
    };
    if TERRAIN_FADE_SAMPLERS
        .iter()
        .any(|stage| device.texture_raw(*stage).is_none())
    {
        log_terrain_fade_failure("required native sampler is unbound");
        return;
    }
    let Some(replacement_vertex) =
        device_resources::terrain_fade_shader_handle(ShaderStage::Vertex)
    else {
        diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::TerrainFade);
        return;
    };
    let Some(replacement_pixel) = device_resources::terrain_fade_shader_handle(ShaderStage::Pixel)
    else {
        diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::TerrainFade);
        return;
    };
    if constants::upload_terrain_constants(&device, None).is_none() {
        log_terrain_fade_failure("terrain constants could not be uploaded");
        return;
    }
    if !bind_direct_pair(
        &device,
        native_vertex,
        native_pixel,
        replacement_vertex,
        replacement_pixel,
    ) {
        log_terrain_fade_failure("replacement pair could not be bound");
        return;
    }

    if !TERRAIN_FADE_FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[PBR] TerrainFade PBR active pass={TERRAIN_FADE_PASS_INDEX} vertex=C[{TERRAIN_FADE_VERTEX_INDEX}] pixel=B[{TERRAIN_FADE_PIXEL_INDEX}]"
        );
    }
    diagnostics::record_terrain_replacement(diagnostics::TerrainDrawFamily::TerrainFade);
}

fn bind_close_terrain_replacement(pass_index: u32, pixel_index: usize) {
    let Some(variant) = close_terrain_variant(pass_index, pixel_index) else {
        log_close_terrain_failure("pass and pixel variant do not match the VPT terrain contract");
        return;
    };
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        log_close_terrain_failure("D3D device unavailable");
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        log_close_terrain_failure("D3D device invalid");
        return;
    };
    let Some((native_vertex, native_pixel)) =
        native_shader_pair(CLOSE_TERRAIN_VERTEX_INDEX, pixel_index, &device)
    else {
        log_close_terrain_failure("engine did not bind the proven VPT pair");
        return;
    };
    let missing_sampler_mask = (0..variant.texture_count)
        .chain(7..7 + variant.texture_count)
        .filter(|stage| device.texture_raw(*stage).is_none())
        .fold(0u16, |mask, stage| mask | (1u16 << stage));
    if missing_sampler_mask != 0 {
        log_close_terrain_missing_samplers(
            pixel_index,
            variant.texture_count,
            missing_sampler_mask,
        );
        return;
    }

    let Some(replacement_vertex) =
        device_resources::close_terrain_shader_handle(ShaderStage::Vertex, 2100)
    else {
        diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
        return;
    };
    let Some(replacement_pixel) =
        device_resources::close_terrain_shader_handle(ShaderStage::Pixel, variant.pixel_sls)
    else {
        diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
        return;
    };
    let supplemental_lights = super::terrain_lights::capture_current();
    if constants::upload_terrain_constants(&device, Some(&supplemental_lights)).is_none() {
        log_close_terrain_failure("terrain constants could not be uploaded");
        return;
    }
    if !bind_direct_pair(
        &device,
        native_vertex,
        native_pixel,
        replacement_vertex,
        replacement_pixel,
    ) {
        log_close_terrain_failure("replacement pair could not be bound");
        return;
    }

    if !CLOSE_TERRAIN_FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[PBR] CloseTerrain PBR active vertex=C[{CLOSE_TERRAIN_VERTEX_INDEX}] pixel=B[{pixel_index}] textures={} point_lights={}",
            variant.texture_count,
            variant.point_light_capacity
        );
    }
    diagnostics::record_terrain_replacement(diagnostics::TerrainDrawFamily::CloseTerrain);
}

fn native_shader_pair(
    vertex_index: usize,
    pixel_index: usize,
    device: &Device9Ref<'_>,
) -> Option<(*mut c_void, *mut c_void)> {
    let vertex_wrapper = read_shader_array_slot(
        PPLIGHTING_VERTEX_GROUP_C_ADDR,
        PPLIGHTING_VERTEX_GROUP_C_COUNT,
        vertex_index,
    )?;
    let pixel_wrapper = read_shader_array_slot(
        PPLIGHTING_PIXEL_GROUP_B_ADDR,
        PPLIGHTING_PIXEL_GROUP_B_COUNT,
        pixel_index,
    )?;
    let native_vertex = engine_contracts::shader_handle_fast(vertex_wrapper, ShaderStage::Vertex)?;
    let native_pixel = engine_contracts::shader_handle_fast(pixel_wrapper, ShaderStage::Pixel)?;
    (device.current_vertex_shader_raw().ok() == Some(native_vertex)
        && device.current_pixel_shader_raw().ok() == Some(native_pixel))
    .then_some((native_vertex, native_pixel))
}

fn restore_direct_d3d_state() {
    if !DIRECT_D3D_ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    let native_vertex = DIRECT_NATIVE_VERTEX.swap(0, Ordering::AcqRel) as *mut c_void;
    let native_pixel = DIRECT_NATIVE_PIXEL.swap(0, Ordering::AcqRel) as *mut c_void;
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };
    let mut restored = unsafe { device.set_raw_vertex_shader(native_vertex) }.is_ok();
    restored &= unsafe { device.set_raw_pixel_shader(native_pixel) }.is_ok();
    if !restored && !DIRECT_RESTORE_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] Native shader pair restore failed; direct replacement ownership cleared");
    }
}

pub(super) fn prepare_direct_draw() {
    if !super::shader_enabled() || PENDING_DRAW_EVALUATED.swap(true, Ordering::AcqRel) {
        return;
    }

    match PENDING_DRAW_KIND.load(Ordering::Acquire) {
        PENDING_DRAW_OBJECT => {
            let pass_index = PENDING_DRAW_PASS_INDEX.load(Ordering::Acquire);
            if let Some(replacement) = try_prepare_object_replacement(pass_index) {
                bind_object_replacement(replacement);
            } else {
                diagnostics::record_object_fallback();
            }
        }
        PENDING_DRAW_LAND_LOD => bind_land_lod_replacement(),
        PENDING_DRAW_TERRAIN_FADE => bind_terrain_fade_replacement(),
        PENDING_DRAW_CLOSE_TERRAIN => {
            let pass_index = PENDING_DRAW_PASS_INDEX.load(Ordering::Acquire);
            let pixel_index = PENDING_CLOSE_TERRAIN_PIXEL_INDEX.load(Ordering::Acquire) as usize;
            bind_close_terrain_replacement(pass_index, pixel_index);
        }
        _ => {}
    }
}

pub(super) fn finish_draw_batches() {
    restore_direct_d3d_state();
    PENDING_DRAW_KIND.store(PENDING_DRAW_NONE, Ordering::Release);
    PENDING_DRAW_EVALUATED.store(true, Ordering::Release);
}

fn bind_direct_pair(
    device: &Device9Ref<'_>,
    native_vertex: *mut c_void,
    native_pixel: *mut c_void,
    replacement_vertex: *mut c_void,
    replacement_pixel: *mut c_void,
) -> bool {
    let vertex_result = unsafe { device.set_raw_vertex_shader(replacement_vertex) };
    let pixel_result = unsafe { device.set_raw_pixel_shader(replacement_pixel) };
    if vertex_result.is_err() || pixel_result.is_err() {
        let _ = unsafe { device.set_raw_vertex_shader(native_vertex) };
        let _ = unsafe { device.set_raw_pixel_shader(native_pixel) };
        return false;
    }

    DIRECT_NATIVE_VERTEX.store(native_vertex as usize, Ordering::Release);
    DIRECT_NATIVE_PIXEL.store(native_pixel as usize, Ordering::Release);
    DIRECT_D3D_ACTIVE.store(true, Ordering::Release);
    true
}

fn log_land_lod_failure(reason: &'static str) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::LandLod);
    if !LAND_LOD_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] LandLOD PBR kept vanilla: {reason}");
    }
}

fn log_terrain_fade_failure(reason: &'static str) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::TerrainFade);
    if !TERRAIN_FADE_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] TerrainFade PBR kept vanilla: {reason}");
    }
}

fn log_close_terrain_failure(reason: &'static str) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
    if !CLOSE_TERRAIN_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] CloseTerrain PBR kept vanilla: {reason}");
    }
}

fn log_close_terrain_missing_samplers(
    pixel_index: usize,
    texture_count: u32,
    missing_sampler_mask: u16,
) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
    if !CLOSE_TERRAIN_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!(
            "[PBR] CloseTerrain PBR kept vanilla: pixel=B[{pixel_index}] textures={texture_count} missing_sampler_mask=0x{missing_sampler_mask:04X}"
        );
    }
}

fn log_land_lod_constants(requested: [[f32; 4]; 2], observed: [[f32; 4]; 2]) {
    let mut signature = 0x811C_9DC5u32;
    for value in requested.into_iter().flatten() {
        let quantized = (value * 1000.0).round() as i32 as u32;
        signature = (signature ^ quantized).wrapping_mul(0x0100_0193);
    }
    if LAND_LOD_LAST_CONSTANT_SIGNATURE.swap(signature, Ordering::AcqRel) == signature
        || LAND_LOD_CONSTANT_LOG_COUNT.fetch_add(1, Ordering::Relaxed) >= 16
    {
        return;
    }

    let matches = requested == observed;
    log::info!(
        "[PBR_LANDLOD_CONSTANTS] requested=c89[{:.3},{:.3},{:.3},{:.3}] c90[{:.3},{:.3},{:.3},{:.3}] observed=c89[{:.3},{:.3},{:.3},{:.3}] c90[{:.3},{:.3},{:.3},{:.3}] match={matches}",
        requested[0][0],
        requested[0][1],
        requested[0][2],
        requested[0][3],
        requested[1][0],
        requested[1][1],
        requested[1][2],
        requested[1][3],
        observed[0][0],
        observed[0][1],
        observed[0][2],
        observed[0][3],
        observed[1][0],
        observed[1][1],
        observed[1][2],
        observed[1][3],
    );
}

unsafe extern "thiscall" fn hook_set_texture(
    render_state: *mut c_void,
    stage: u32,
    texture: *mut c_void,
) {
    let selector = if diagnostics::detailed_enabled() {
        engine_contracts::current_draw_selector_address_fast()
    } else {
        0
    };
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

    if shader_record::store_created(shader, stage, template_ref.id, table_id, table_index).is_some()
    {
        log::info!(
            "[PBR] Object PBR captured {:?} wrapper={shader:p} shader={} table={table_id}:{} handle={original_handle:p}",
            stage,
            template_ref.template.label,
            table_index_for_log(table_index)
        );
    }
}

fn try_prepare_object_replacement(pass_index: u32) -> Option<PreparedObjectReplacement> {
    let Some((vertex_shader, pixel_shader)) = engine_contracts::current_pass_shaders_fast() else {
        return None;
    };
    let diagnostics_enabled = diagnostics::detailed_enabled();
    let draw_snapshot = if diagnostics_enabled {
        engine_contracts::current_draw_snapshot(pass_index)
    } else {
        engine_contracts::DrawSnapshot {
            rejection: engine_contracts::current_object_draw_rejection(pass_index),
            ..engine_contracts::DrawSnapshot::default()
        }
    };
    if diagnostics_enabled {
        diagnostics::record_object_draw_context(draw_snapshot);
        record_current_table_pair(vertex_shader, pixel_shader);
    }

    let vertex_record = match resolve_current_shader_record(vertex_shader, ShaderStage::Vertex) {
        Ok(record) => record,
        Err(reason) => {
            if diagnostics_enabled {
                record_unresolved_table_pair(
                    draw_snapshot,
                    pass_index,
                    vertex_shader,
                    pixel_shader,
                    reason,
                );
                diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
            }
            return None;
        }
    };
    let pixel_record = match resolve_current_shader_record(pixel_shader, ShaderStage::Pixel) {
        Ok(record) => record,
        Err(reason) => {
            if diagnostics_enabled {
                record_unresolved_table_pair(
                    draw_snapshot,
                    pass_index,
                    vertex_shader,
                    pixel_shader,
                    reason,
                );
                diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
            }
            return None;
        }
    };
    if vertex_record.stage != ShaderStage::Vertex || pixel_record.stage != ShaderStage::Pixel {
        if diagnostics_enabled {
            diagnostics::record_object_draw_gate_rejection(
                ObjectDrawRejectReason::TableIdentityMismatch,
                0,
                0,
            );
        }
        return None;
    }
    let vertex_record = ensure_table_identity(vertex_record);
    let pixel_record = ensure_table_identity(pixel_record);

    let draw_trace = if diagnostics_enabled {
        diagnostics::ObjectDrawTrace {
            key: object_draw_key(draw_snapshot, vertex_shader, pixel_shader),
            geometry: draw_snapshot.geometry,
            property: draw_snapshot.property,
            pass: draw_snapshot.pass,
            pass_index,
            selector: draw_snapshot.selector,
            selector_state: draw_snapshot.selector_state,
            active_layer_count: draw_snapshot.active_layer_count,
            scanned_entries: draw_snapshot.scanned_entries,
            vertex_index: vertex_record.table_index,
            pixel_index: pixel_record.table_index,
        }
    } else {
        diagnostics::ObjectDrawTrace::default()
    };
    if let Some(rejection) = draw_snapshot.rejection {
        if diagnostics_enabled {
            diagnostics::record_object_contract(
                draw_trace,
                vertex_record.table_index,
                ObjectContractState::BlockedPassEntryTerrain,
            );
            diagnostics::record_object_draw_gate_rejection(
                rejection.reason,
                rejection.row,
                rejection.selector,
            );
        }
        return None;
    }

    if diagnostics_enabled {
        diagnostics::record_object_pair(
            template_sls(vertex_record),
            template_sls(pixel_record),
            vertex_record.table_id,
            vertex_record.table_index,
            pixel_record.table_id,
            pixel_record.table_index,
        );
    }
    let contract = match object_contract_decision(vertex_record, pixel_record) {
        Ok(contract) => contract,
        Err(reason) => {
            if diagnostics_enabled {
                diagnostics::record_object_contract(
                    draw_trace,
                    vertex_record.table_index,
                    contract_state_for_rejection(reason),
                );
                diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
            }
            return None;
        }
    };
    if let Some(reason) = object_contract_rejection(contract.state) {
        if diagnostics_enabled {
            diagnostics::record_object_contract(
                draw_trace,
                contract.normalized_vertex_index,
                contract.state,
            );
            diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
        }
        return None;
    }

    let replacement_vertex = device_resources::object_shader_handle(vertex_record.template_id);
    let replacement_pixel = device_resources::object_shader_handle(pixel_record.template_id);
    if diagnostics_enabled {
        diagnostics::record_object_handles(
            vertex_record.shader,
            pixel_record.shader,
            replacement_vertex,
            replacement_pixel,
        );
    }

    let (Some(replacement_vertex), Some(replacement_pixel)) =
        (replacement_vertex, replacement_pixel)
    else {
        if diagnostics_enabled {
            diagnostics::record_object_contract(
                draw_trace,
                contract.normalized_vertex_index,
                ObjectContractState::BlockedMissingReplacementResource,
            );
            diagnostics::record_object_draw_gate_rejection(
                ObjectDrawRejectReason::MissingReplacementResource,
                0,
                0,
            );
        }
        return None;
    };

    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        if diagnostics_enabled {
            diagnostics::record_object_contract(
                draw_trace,
                contract.normalized_vertex_index,
                ObjectContractState::BlockedMissingD3DState,
            );
            diagnostics::record_object_draw_gate_rejection(
                ObjectDrawRejectReason::MissingD3DState,
                0,
                0,
            );
        }
        return None;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        if diagnostics_enabled {
            diagnostics::record_object_contract(
                draw_trace,
                contract.normalized_vertex_index,
                ObjectContractState::BlockedMissingD3DState,
            );
            diagnostics::record_object_draw_gate_rejection(
                ObjectDrawRejectReason::MissingD3DState,
                0,
                0,
            );
        }
        return None;
    };
    if let Err(reason) = object_replacement_record::validate_pixel_samplers(
        &device,
        pixel_record,
        draw_snapshot.selector,
        diagnostics_enabled,
    ) {
        if diagnostics_enabled {
            diagnostics::record_object_contract(
                draw_trace,
                contract.normalized_vertex_index,
                contract_state_for_rejection(reason),
            );
            diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
        }
        return None;
    }

    if matches!(
        contract.state,
        ObjectContractState::ImplementedOnlyLight
            | ObjectContractState::ImplementedDiffusePoint
            | ObjectContractState::ImplementedOnlySpecular
    ) {
        engine_contracts::enable_fog_for_pass(pass_index);
    }

    Some(PreparedObjectReplacement {
        vertex_record,
        pixel_record,
        replacement_vertex,
        replacement_pixel,
        draw_trace,
        normalized_vertex_index: contract.normalized_vertex_index,
        contract_state: contract.state,
        uses_native_specular_fade: shader_registry::object_template_uses_native_specular_fade(
            pixel_record.template_id,
        ),
        diagnostics_enabled,
    })
}

fn bind_object_replacement(replacement: PreparedObjectReplacement) {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        record_object_bind_failure(replacement, ObjectDrawRejectReason::MissingD3DState);
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        record_object_bind_failure(replacement, ObjectDrawRejectReason::MissingD3DState);
        return;
    };
    let Some(native_vertex) =
        engine_contracts::shader_handle_fast(replacement.vertex_record.shader, ShaderStage::Vertex)
    else {
        record_object_bind_failure(replacement, ObjectDrawRejectReason::HandleStateMismatch);
        return;
    };
    let Some(native_pixel) =
        engine_contracts::shader_handle_fast(replacement.pixel_record.shader, ShaderStage::Pixel)
    else {
        record_object_bind_failure(replacement, ObjectDrawRejectReason::HandleStateMismatch);
        return;
    };
    let current_vertex = device.current_vertex_shader_raw().unwrap_or(null_mut());
    let current_pixel = device.current_pixel_shader_raw().unwrap_or(null_mut());
    if replacement.diagnostics_enabled {
        diagnostics::record_object_d3d_state(
            current_vertex,
            current_pixel,
            replacement.replacement_vertex,
            replacement.replacement_pixel,
        );
    }
    if current_vertex != native_vertex || current_pixel != native_pixel {
        record_object_bind_failure(replacement, ObjectDrawRejectReason::HandleStateMismatch);
        return;
    }

    if !constants::upload_object_constants(&device) {
        record_object_bind_failure(replacement, ObjectDrawRejectReason::MissingD3DState);
        return;
    }
    if replacement.diagnostics_enabled {
        diagnostics::record_object_constant_upload();
    }
    if !bind_direct_pair(
        &device,
        native_vertex,
        native_pixel,
        replacement.replacement_vertex,
        replacement.replacement_pixel,
    ) {
        record_object_bind_failure(replacement, ObjectDrawRejectReason::HandleStateMismatch);
        return;
    }

    if replacement.diagnostics_enabled && replacement.uses_native_specular_fade {
        let light_capacity =
            shader_registry::object_template_light_count(replacement.pixel_record.template_id);
        let mut light_data = [[0.0; 4]; 10];
        let light_data_ready = device.vertex_shader_constant_f(25, &mut light_data).is_ok();
        let renderer_weight = light_data_ready.then_some(light_data[0][3]);
        let light_signature = light_data_ready
            .then(|| hash_light_data(&light_data, light_capacity))
            .unwrap_or(0);
        if let Some(fade) = engine_contracts::current_object_specular_fade_snapshot(
            renderer_weight,
            light_capacity,
            light_signature,
        ) {
            diagnostics::record_object_specular_fade(
                replacement.draw_trace,
                fade,
                samplers::object_sampler_identity(&device, replacement.pixel_record.template_id),
            );
        }
    }

    if replacement.diagnostics_enabled {
        diagnostics::record_object_contract(
            replacement.draw_trace,
            replacement.normalized_vertex_index,
            replacement.contract_state,
        );
        diagnostics::record_object_replacement();
    }
}

fn record_object_bind_failure(
    replacement: PreparedObjectReplacement,
    reason: ObjectDrawRejectReason,
) {
    if replacement.diagnostics_enabled {
        diagnostics::record_object_contract(
            replacement.draw_trace,
            replacement.normalized_vertex_index,
            contract_state_for_rejection(reason),
        );
        diagnostics::record_object_draw_gate_rejection(reason, 0, 0);
        diagnostics::record_object_fallback();
    }
}

fn record_unresolved_table_pair(
    snapshot: engine_contracts::DrawSnapshot,
    pass_index: u32,
    vertex_shader: *mut c_void,
    pixel_shader: *mut c_void,
    reason: ObjectDrawRejectReason,
) {
    if !diagnostics::detailed_enabled() {
        return;
    }
    let vertex = identify_pplighting_table_slot(vertex_shader, ShaderStage::Vertex);
    let pixel = identify_pplighting_table_slot(pixel_shader, ShaderStage::Pixel);
    let vertex_index = vertex.map_or(TABLE_INDEX_UNKNOWN, |slot| slot.index);
    let pixel_index = pixel.map_or(TABLE_INDEX_UNKNOWN, |slot| slot.index);
    diagnostics::record_object_contract(
        diagnostics::ObjectDrawTrace {
            key: object_draw_key(snapshot, vertex_shader, pixel_shader),
            geometry: snapshot.geometry,
            property: snapshot.property,
            pass: snapshot.pass,
            pass_index,
            selector: snapshot.selector,
            selector_state: snapshot.selector_state,
            active_layer_count: snapshot.active_layer_count,
            scanned_entries: snapshot.scanned_entries,
            vertex_index,
            pixel_index,
        },
        vertex_index,
        contract_state_for_rejection(reason),
    );
    diagnostics::record_unresolved_table_pair(
        snapshot,
        pass_index,
        vertex_shader,
        pixel_shader,
        vertex.map_or("other", |slot| slot.label),
        vertex_index,
        pixel.map_or("other", |slot| slot.label),
        pixel_index,
        reason,
    );
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
    vertex_shader: *mut c_void,
    pixel_shader: *mut c_void,
) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    if snapshot.geometry != 0 {
        hash = hash_word(hash, snapshot.geometry);
        hash = hash_word(hash, snapshot.property);
        hash = hash_word(hash, snapshot.selector);
    } else {
        hash = hash_word(hash, vertex_shader as usize);
        hash = hash_word(hash, pixel_shader as usize);
    }

    if hash == 0 { 1 } else { hash }
}

#[cfg(test)]
mod tests {
    use super::{
        CLOSE_TERRAIN_FIRST_PIXEL_INDEX, CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET, close_terrain_draw,
        close_terrain_variant, hash_light_data, object_draw_key,
    };
    use crate::effects::pbr::engine_contracts::DrawSnapshot;
    use crate::effects::pbr::shader_registry::{self, ShaderStage};

    #[test]
    fn object_draw_key_ignores_pass_identity() {
        let first = DrawSnapshot {
            geometry: 0x1000,
            property: 0x2000,
            pass: 0x3000,
            selector: 0x4000,
            ..DrawSnapshot::default()
        };
        let second = DrawSnapshot {
            pass: 0x5000,
            ..first
        };

        assert_eq!(
            object_draw_key(first, std::ptr::null_mut(), std::ptr::null_mut()),
            object_draw_key(second, std::ptr::null_mut(), std::ptr::null_mut())
        );
    }

    #[test]
    fn light_signature_excludes_native_distance_fade() {
        let mut first = [[0.0; 4]; 10];
        first[0] = [1.0, 2.0, 3.0, 0.25];
        let mut second = first;
        second[0][3] = 0.75;

        assert_eq!(hash_light_data(&first, 1), hash_light_data(&second, 1));

        second[0][0] = 4.0;
        assert_ne!(hash_light_data(&first, 1), hash_light_data(&second, 1));
    }

    #[test]
    fn object_draw_hot_path_uses_fast_reads_and_one_diagnostics_snapshot() {
        let source = include_str!("hooks.rs");
        let prepare = source
            .split_once("fn try_prepare_object_replacement")
            .unwrap()
            .1
            .split_once("fn bind_object_replacement")
            .unwrap()
            .0;
        assert!(prepare.contains("engine_contracts::current_pass_shaders_fast()"));
        assert_eq!(
            prepare.matches("diagnostics::detailed_enabled()").count(),
            1
        );
        assert!(prepare.contains("diagnostics::ObjectDrawTrace::default()"));

        let bind = source
            .split_once("fn bind_object_replacement")
            .unwrap()
            .1
            .split_once("fn record_object_bind_failure")
            .unwrap()
            .0;
        assert_eq!(
            bind.matches("engine_contracts::shader_handle_fast(")
                .count(),
            2
        );
        assert!(!bind.contains("diagnostics::detailed_enabled()"));
        assert!(!bind.contains("engine_contracts::shader_handle("));
    }

    #[test]
    fn close_terrain_mapping_covers_every_supported_variant() {
        for texture_count in 1..=7u32 {
            for (row_offset, point_light_capacity) in [(0usize, 0), (2, 6), (4, 12), (6, 24)] {
                let pixel_index =
                    CLOSE_TERRAIN_FIRST_PIXEL_INDEX + (texture_count as usize - 1) * 8 + row_offset;
                let pass_index = pixel_index as u32 + CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET;
                let variant = close_terrain_variant(pass_index, pixel_index).unwrap();

                assert_eq!(variant.pixel_index, pixel_index);
                assert_eq!(variant.pixel_sls, 2000 + pixel_index as u16);
                assert_eq!(variant.texture_count, texture_count);
                assert_eq!(variant.point_light_capacity, point_light_capacity);
                assert_eq!(
                    close_terrain_draw(pass_index, pixel_index)
                        .unwrap()
                        .replacement,
                    Some(variant)
                );
                assert!(
                    shader_registry::close_terrain_template_id(
                        ShaderStage::Pixel,
                        variant.pixel_sls
                    )
                    .is_some()
                );
            }
        }
    }

    #[test]
    fn close_terrain_canopy_rows_stay_classified_but_use_vanilla_shaders() {
        for texture_count in 1..=7usize {
            for row_offset in [1usize, 3, 5, 7] {
                let pixel_index =
                    CLOSE_TERRAIN_FIRST_PIXEL_INDEX + (texture_count - 1) * 8 + row_offset;
                let pass_index = pixel_index as u32 + CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET;
                let draw = close_terrain_draw(pass_index, pixel_index).unwrap();

                assert_eq!(draw.pixel_index, pixel_index);
                assert_eq!(draw.replacement, None);
                assert_eq!(close_terrain_variant(pass_index, pixel_index), None);
            }
        }
    }

    #[test]
    fn close_terrain_mapping_rejects_mismatched_and_foreign_rows() {
        assert_eq!(close_terrain_draw(503, 93), None);
        assert_eq!(close_terrain_draw(504, 92), None);
        assert_eq!(close_terrain_draw(502, 91), None);
        assert_eq!(close_terrain_draw(559, 148), None);
        assert_eq!(close_terrain_draw(560, 149), None);
    }
}

fn hash_word(hash: u32, value: usize) -> u32 {
    let folded = value as u32;
    hash ^ folded.wrapping_mul(0x0100_0193).rotate_left(5)
}

fn hash_light_data(light_data: &[[f32; 4]; 10], light_capacity: u32) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    for (light_index, light) in light_data
        .iter()
        .take(light_capacity.min(light_data.len() as u32) as usize)
        .enumerate()
    {
        for (component, value) in light.iter().enumerate() {
            // LightData[0].w is the distance fade reported separately.
            if light_index == 0 && component == 3 {
                continue;
            }
            hash = (hash ^ value.to_bits()).wrapping_mul(0x0100_0193);
        }
    }
    hash
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

fn identify_pplighting_table_slot(
    shader: *mut c_void,
    stage: ShaderStage,
) -> Option<PplightingTableSlot> {
    let tables: &[(&'static str, usize, usize)] = match stage {
        ShaderStage::Vertex => &[
            (
                "A",
                PPLIGHTING_VERTEX_GROUP_A_ADDR,
                PPLIGHTING_VERTEX_GROUP_A_COUNT,
            ),
            (
                "B",
                PPLIGHTING_VERTEX_GROUP_B_ADDR,
                PPLIGHTING_VERTEX_GROUP_B_COUNT,
            ),
            (
                "C",
                PPLIGHTING_VERTEX_GROUP_C_ADDR,
                PPLIGHTING_VERTEX_GROUP_C_COUNT,
            ),
        ],
        ShaderStage::Pixel => &[
            (
                "A",
                PPLIGHTING_PIXEL_GROUP_A_ADDR,
                PPLIGHTING_PIXEL_GROUP_A_COUNT,
            ),
            (
                "B",
                PPLIGHTING_PIXEL_GROUP_B_ADDR,
                PPLIGHTING_PIXEL_GROUP_B_COUNT,
            ),
        ],
    };

    for (label, base, count) in tables {
        if let Some(index) = find_shader_array_index(*base, *count, shader) {
            return Some(PplightingTableSlot {
                label: *label,
                index,
            });
        }
    }
    None
}

fn find_shader_array_index(base: usize, count: usize, shader: *mut c_void) -> Option<u32> {
    if shader.is_null() || !*SHADER_TABLES_READABLE {
        return None;
    }

    let cache_index = ((shader as usize >> 4) ^ (base >> 4)) % TABLE_LOOKUP_CACHE_COUNT;
    let cached = &TABLE_LOOKUP_CACHE[cache_index];
    if cached.shader.load(Ordering::Acquire) == shader as usize
        && cached.base.load(Ordering::Relaxed) == base
    {
        let index = cached.index.load(Ordering::Relaxed);
        if index < count as u32 {
            let slot = unsafe { (base as *const *mut c_void).add(index as usize).read() };
            if slot == shader {
                return Some(index);
            }
        }
    }

    for index in 0..count {
        let slot = unsafe { (base as *const *mut c_void).add(index) };
        if unsafe { slot.read() } == shader {
            cached.shader.store(0, Ordering::Release);
            cached.base.store(base, Ordering::Relaxed);
            cached.index.store(index as u32, Ordering::Relaxed);
            cached.shader.store(shader as usize, Ordering::Release);
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
    if index >= count || !*SHADER_TABLES_READABLE {
        return None;
    }

    let slot = unsafe { (base as *const *mut c_void).add(index) };
    let shader = unsafe { slot.read() };
    (!shader.is_null()).then_some(shader)
}
