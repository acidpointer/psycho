//! Native shader interception and draw-scoped PBR ownership.
//!
//! The common selector-setup caller runs every live selector predecessor first,
//! then `SetShaders` exposes replacement handles only for one final native bind.
//! That makes `NiDX9RenderState` the authoritative owner of the bound pair while
//! remaining independent of per-selector cloned vtables. Engine wrappers return
//! immediately to native handles.
//! The direct draw hook still validates samplers and geometry-specific constants
//! immediately before submission. A rejected draw temporarily binds vanilla and
//! then restores the engine-owned replacement. Close terrain normally keeps the
//! engine-owned native-only program; its paired supplemental program changes
//! only when the captured payload mode changes and is restored before the next
//! engine `SetShaders` boundary. Close terrain is re-evaluated at every renderer
//! geometry entry because one engine pass setup can serve several geometries.
//!
//! The mandatory engine `SetTexture` hook maintains the complete texture-stage
//! mirror used by draw admission. Required texture admission never reads D3D
//! state back from the driver: an unknown stage fails closed until the engine
//! binds it, while a known-null stage fails closed until the corresponding
//! engine transition. Supplemental close-terrain lights temporarily borrow
//! sampler s14 around one nonempty draw. That transaction captures only the
//! three sampler fields that physically affect the fixed LOD-zero lookup, and
//! every completion, fallback, and resource-release boundary restores both the
//! engine-owned texture identity and those sampler fields.

use std::{
    ffi::c_void,
    mem::size_of,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::Result;
use libpsycho::os::windows::{
    directx9::{
        D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_SRGBTEXTURE, D3DSAMPLERSTATETYPE,
        D3DTEXF_POINT, Device9Ref,
    },
    hook::{callsite::Rel32CallHookContainer, pointer::PointerSlotHookContainer},
    memory::validate_memory_range,
};

use super::{
    constants, device_resources, diagnostics, engine_contracts, object_contracts,
    object_replacement_record, samplers, samplers::TrackedTextureBinding, shader_record,
    shader_registry, shader_registry::ShaderStage,
};
use engine_contracts::{ObjectDrawAdmission, ObjectDrawRejectReason};
use object_contracts::{ObjectContractDecision, ObjectContractState};

const SELECTOR_SETUP_CALL_ADDR: usize = 0x00B9_9539;
const RENDER_STATE_SET_PIXEL_SHADER_VTABLE_OFFSET: usize = 0x7C;
const RENDER_STATE_SET_VERTEX_SHADER_VTABLE_OFFSET: usize = 0x8C;
const RENDER_STATE_SET_TEXTURE_VTABLE_OFFSET: usize = 0xDC;
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
const NATIVE_DEPTH_VERTEX_FIRST_INDEX: u32 = 92;
const NATIVE_DEPTH_VERTEX_LAST_INDEX: u32 = 95;
const NATIVE_DEPTH_PIXEL_FIRST_INDEX: u32 = 90;
const NATIVE_DEPTH_PIXEL_LAST_INDEX: u32 = 91;
const PENDING_DRAW_NONE: u32 = 0;
const PENDING_DRAW_OBJECT: u32 = 1;
const PENDING_DRAW_LAND_LOD: u32 = 2;
const PENDING_DRAW_TERRAIN_FADE: u32 = 3;
const PENDING_DRAW_CLOSE_TERRAIN: u32 = 4;
const TABLE_LOOKUP_CACHE_COUNT: usize = 512;
const PENDING_OBJECT_TEMPLATE_SHIFT: u32 = 16;
const PENDING_OBJECT_PASS_MASK: u32 = (1 << PENDING_OBJECT_TEMPLATE_SHIFT) - 1;

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
    native_canopy_row: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CloseTerrainDraw {
    pixel_index: usize,
    replacement: Option<CloseTerrainVariant>,
}

/// One proven engine wrapper pair and its native/replacement D3D identities.
///
/// Keeping all six pointers together makes selection, transient wrapper
/// override, draw validation, fallback, and resource release use the same
/// ownership transaction instead of reconstructing state from the device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShaderPairSelection {
    vertex_wrapper: *mut c_void,
    pixel_wrapper: *mut c_void,
    native_vertex: *mut c_void,
    native_pixel: *mut c_void,
    replacement_vertex: *mut c_void,
    replacement_pixel: *mut c_void,
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
    pair: ShaderPairSelection,
    pixel_template_id: u16,
    draw_trace: diagnostics::ObjectDrawTrace,
    normalized_vertex_index: u32,
    contract_state: ObjectContractState,
    uses_native_specular_fade: bool,
    diagnostics_enabled: bool,
}

type SetShadersFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> bool;
type SetRenderStateShaderFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32);
type SelectorSetupFn = unsafe extern "cdecl" fn(u32, *mut c_void);
type SetTextureFn = unsafe extern "thiscall" fn(*mut c_void, u32, *mut c_void);

static SET_SHADERS_HOOK: LazyLock<Rel32CallHookContainer<SelectorSetupFn>> =
    LazyLock::new(Rel32CallHookContainer::new);
static SET_TEXTURE_HOOK: LazyLock<PointerSlotHookContainer<SetTextureFn>> =
    LazyLock::new(PointerSlotHookContainer::new);
static HOOKS_READY: AtomicBool = AtomicBool::new(false);
static ENGINE_SHADER_BINDERS_READY: AtomicBool = AtomicBool::new(false);
static NATIVE_FALLBACK_ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING_VERTEX_WRAPPER: AtomicUsize = AtomicUsize::new(0);
static PENDING_PIXEL_WRAPPER: AtomicUsize = AtomicUsize::new(0);
static PENDING_NATIVE_VERTEX: AtomicUsize = AtomicUsize::new(0);
static PENDING_NATIVE_PIXEL: AtomicUsize = AtomicUsize::new(0);
static PENDING_REPLACEMENT_VERTEX: AtomicUsize = AtomicUsize::new(0);
static PENDING_REPLACEMENT_PIXEL: AtomicUsize = AtomicUsize::new(0);
static PENDING_DRAW_KIND: AtomicU32 = AtomicU32::new(PENDING_DRAW_NONE);
static PENDING_DRAW_PASS_INDEX: AtomicU32 = AtomicU32::new(0);
// Kind-tagged auxiliary value: close-terrain pixel index or object-device
// generation. Keeping it in the existing pending record avoids adding a new
// loader-visible static while making reset ownership explicit.
static PENDING_DRAW_AUXILIARY: AtomicU32 = AtomicU32::new(0);
static PENDING_DRAW_EVALUATED: AtomicBool = AtomicBool::new(false);
static PENDING_REQUIRED_SAMPLER_MASK: AtomicU32 = AtomicU32::new(0);
static PENDING_MISSING_SAMPLER_MASK: AtomicU32 = AtomicU32::new(0);
static PENDING_CLOSE_TERRAIN_PREPARED_GEOMETRY: AtomicUsize = AtomicUsize::new(0);
static PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND: AtomicBool = AtomicBool::new(false);
static PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING_CLOSE_TERRAIN_SAMPLER_STATE_ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING_CLOSE_TERRAIN_SAMPLER_MIN_FILTER: AtomicU32 = AtomicU32::new(0);
static PENDING_CLOSE_TERRAIN_SAMPLER_MAG_FILTER: AtomicU32 = AtomicU32::new(0);
static PENDING_CLOSE_TERRAIN_SAMPLER_SRGB: AtomicU32 = AtomicU32::new(0);
static LAND_LOD_FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static LAND_LOD_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static LAND_LOD_MISSING_SAMPLER_LOGGED: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_MISSING_SAMPLER_LOGGED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_FIRST_CANOPY_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_WARMING_LOGGED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static OBJECT_FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static DIRECT_RESTORE_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static SUPPLEMENTAL_TEXTURE_RESTORE_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
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
        super::samplers::set_texture_tracking_ready(true);
        adopt_existing_object_shaders();
        return Ok(());
    }

    // Resolve both mandatory engine-owned boundaries before publishing either
    // PBR capability. The selector-setup callsite captures the complete live
    // setup predecessor, including an entry detour, and avoids assuming that
    // every selector instance still shares one cached object's vtable.
    // The texture observer is shared with native sky and may remain resident
    // when PBR itself fails closed; SetShaders is never left active without it.
    let set_shaders_prepared = prepare_set_shaders_hook() && prepare_engine_shader_binders();
    let texture_tracking_prepared = prepare_set_texture_hook();
    let texture_tracking_ready =
        texture_tracking_prepared && enable_prepared_pointer(&SET_TEXTURE_HOOK, "SetTexture");
    let set_shaders_ready = texture_tracking_ready
        && set_shaders_prepared
        && enable_prepared_callsite(&SET_SHADERS_HOOK, "selector setup");
    super::samplers::set_texture_tracking_ready(texture_tracking_ready);
    let mandatory_ready = set_shaders_ready && texture_tracking_ready;
    HOOKS_READY.store(mandatory_ready, Ordering::Release);
    if !mandatory_ready {
        // SetShaders without SetTexture would make admission depend on driver
        // readback. Remove only SetShaders: SetTexture is a shared passive
        // observer used by native sky and remains safe without PBR ownership.
        if SET_SHADERS_HOOK.is_enabled() {
            let _ = SET_SHADERS_HOOK.disable();
        }
        release_device_resources();
        log::warn!(
            "[PBR] Native PBR blocked: mandatory SetShaders/SetTexture hook group unavailable"
        );
        return Ok(());
    }

    engine_contracts::install_core_contracts();

    let adopted = adopt_existing_object_shaders();
    if adopted != 0 {
        log::info!("[PBR] Object PBR adopted {adopted} existing shader wrapper(s)");
    }

    log::info!("[PBR] Common selector-setup caller chained for final PBR binding");
    log::info!(
        "[PBR] Shader wrappers use startup and first-use adoption; shared shader-creation entries are not hooked"
    );
    log::info!("[PBR] Object PBR texture-stage vtable slot chained");

    Ok(())
}

fn prepare_set_texture_hook() -> bool {
    if SET_TEXTURE_HOOK.is_initialized() {
        return true;
    }
    let render_state = match crate::backend::render_state_ptr() {
        Ok(render_state) => render_state,
        Err(reason) => {
            log::warn!("[PBR] SetTexture hook skipped: {reason}");
            return false;
        }
    };
    let Some(slot) = resolve_vtable_slot(
        render_state,
        RENDER_STATE_SET_TEXTURE_VTABLE_OFFSET,
        "NiDX9RenderState::SetTexture",
    ) else {
        return false;
    };

    match unsafe {
        SET_TEXTURE_HOOK.init("FNV NiDX9RenderState::SetTexture", slot, hook_set_texture)
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!("[PBR] SetTexture hook skipped: {err}");
            return false;
        }
    }

    true
}

pub(super) fn hooks_ready() -> bool {
    HOOKS_READY.load(Ordering::Acquire)
}

pub(super) fn selection_hook_ready() -> bool {
    SET_SHADERS_HOOK.is_enabled()
}

pub(super) fn texture_hook_ready() -> bool {
    SET_TEXTURE_HOOK.is_enabled()
}

pub(super) fn selection_predecessor() -> Option<usize> {
    SET_SHADERS_HOOK.predecessor_address().ok()
}

pub(super) fn texture_predecessor() -> Option<usize> {
    SET_TEXTURE_HOOK.predecessor_address().ok()
}

/// Probe the live terrain shader family without using provider module names.
///
/// The rows below are the complete native inputs consumed by OMV's LandLOD,
/// terrain-fade, and 56-row close-terrain paths. `read_shader_array_slot`
/// proves table bounds and non-null wrapper identity; `shader_handle` then
/// proves the expected NiD3D stage vtable and a usable native D3D resource.
/// This probe runs only at DeferredInit and native shader-package transitions,
/// never per frame or per draw.
pub(super) fn probe_terrain_shader_contract() -> bool {
    let vertex_rows = [
        LAND_LOD_VERTEX_INDEX,
        TERRAIN_FADE_VERTEX_INDEX,
        CLOSE_TERRAIN_VERTEX_INDEX,
    ];
    if !vertex_rows.into_iter().all(|index| {
        read_shader_array_slot(
            PPLIGHTING_VERTEX_GROUP_C_ADDR,
            PPLIGHTING_VERTEX_GROUP_C_COUNT,
            index,
        )
        .and_then(|shader| engine_contracts::shader_handle(shader, ShaderStage::Vertex))
        .is_some()
    }) {
        return false;
    }

    [LAND_LOD_PIXEL_INDEX, TERRAIN_FADE_PIXEL_INDEX]
        .into_iter()
        .chain(CLOSE_TERRAIN_FIRST_PIXEL_INDEX..=CLOSE_TERRAIN_LAST_PIXEL_INDEX)
        .all(|index| {
            read_shader_array_slot(
                PPLIGHTING_PIXEL_GROUP_B_ADDR,
                PPLIGHTING_PIXEL_GROUP_B_COUNT,
                index,
            )
            .and_then(|shader| engine_contracts::shader_handle(shader, ShaderStage::Pixel))
            .is_some()
        })
}

fn prepare_set_shaders_hook() -> bool {
    if SET_SHADERS_HOOK.is_initialized() {
        return true;
    }
    match unsafe {
        SET_SHADERS_HOOK.init(
            "FNV common selector-setup caller",
            SELECTOR_SETUP_CALL_ADDR as *mut c_void,
            hook_selector_setup,
        )
    } {
        Ok(()) => {}
        Err(err) => {
            log::warn!("[PBR] Selector-setup caller skipped: {err}");
            return false;
        }
    }

    true
}

fn prepare_engine_shader_binders() -> bool {
    if ENGINE_SHADER_BINDERS_READY.load(Ordering::Acquire) {
        return true;
    }
    let render_state = match crate::backend::render_state_ptr() {
        Ok(render_state) => render_state,
        Err(reason) => {
            log::warn!("[PBR] Engine shader binders skipped: {reason}");
            return false;
        }
    };
    let ready = [
        (
            RENDER_STATE_SET_VERTEX_SHADER_VTABLE_OFFSET,
            "NiDX9RenderState::SetVertexShader",
        ),
        (
            RENDER_STATE_SET_PIXEL_SHADER_VTABLE_OFFSET,
            "NiDX9RenderState::SetPixelShader",
        ),
    ]
    .into_iter()
    .all(|(offset, label)| {
        resolve_vtable_slot(render_state, offset, label)
            .and_then(|slot| read_non_null_pointer(slot.cast_const().cast(), label))
            .is_some()
    });
    ENGINE_SHADER_BINDERS_READY.store(ready, Ordering::Release);
    ready
}

fn enable_prepared_callsite<F>(hook: &Rel32CallHookContainer<F>, label: &'static str) -> bool
where
    F: libpsycho::ffi::fnptr::Function,
{
    if hook.is_enabled() {
        return true;
    }
    match hook.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[PBR] {label} caller could not be chained: {err}");
            false
        }
    }
}

/// Enable a prepared engine-owned pointer without treating residency as a
/// runtime feature toggle.
fn enable_prepared_pointer<F>(hook: &PointerSlotHookContainer<F>, label: &'static str) -> bool
where
    F: libpsycho::ffi::fnptr::Function,
{
    if hook.is_enabled() {
        return true;
    }
    match hook.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!("[PBR] {label} slot could not be chained: {err}");
            false
        }
    }
}

/// Resolve one slot from the live engine object's current vtable.
///
/// Looking through the object at DeferredInit is essential for cooperation:
/// another plugin may have installed a cloned vtable. Hard-coding the vanilla
/// table would bypass that owner, while requiring the vanilla function bytes
/// would reject a valid entry-detour chain. `PointerSlotHook` validates and
/// atomically captures the callable value that this exact slot contains.
fn resolve_vtable_slot(owner: *mut c_void, offset: usize, label: &str) -> Option<*mut *mut c_void> {
    let Some(vtable) = read_non_null_pointer(owner.cast_const(), label) else {
        return None;
    };
    let Some(address) = (vtable as usize).checked_add(offset) else {
        log::warn!("[PBR] {label} vtable slot address overflowed");
        return None;
    };
    let slot = address as *mut *mut c_void;
    if let Err(error) = validate_memory_range(slot.cast(), size_of::<*mut c_void>()) {
        log::warn!("[PBR] Cannot read {label} vtable slot at 0x{address:08X}: {error}");
        return None;
    }
    Some(slot)
}

fn read_non_null_pointer(address: *const c_void, label: &str) -> Option<*mut c_void> {
    if let Err(error) = validate_memory_range(address, size_of::<*mut c_void>()) {
        log::warn!("[PBR] Cannot read {label} pointer at {address:p}: {error}");
        return None;
    }
    let value = unsafe { address.cast::<*mut c_void>().read() };
    if value.is_null() {
        log::warn!("[PBR] {label} pointer is null");
        return None;
    }
    Some(value)
}

unsafe extern "cdecl" fn hook_selector_setup(pass_index: u32, selector: *mut c_void) {
    let Ok(original) = SET_SHADERS_HOOK.original() else {
        return;
    };
    reconcile_pending_before_selector_setup();
    unsafe { original(pass_index, selector) };
    let _span =
        crate::graphics_diagnostics::span(crate::graphics_diagnostics::Interval::PbrSelectorSetup);
    unsafe { hook_set_shaders(selector, pass_index) };
}

fn reconcile_pending_before_selector_setup() {
    let _ = restore_close_terrain_fast_shader();
    let previous_kind = PENDING_DRAW_KIND.swap(PENDING_DRAW_NONE, Ordering::AcqRel);
    if previous_kind == PENDING_DRAW_NONE {
        return;
    }
    restore_engine_owned_replacement();
    clear_pending_shader_pair();
    PENDING_REQUIRED_SAMPLER_MASK.store(0, Ordering::Release);
    PENDING_MISSING_SAMPLER_MASK.store(0, Ordering::Release);
}

unsafe extern "thiscall" fn hook_set_shaders(shader: *mut c_void, pass_index: u32) {
    let original = native_set_shaders();
    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::SetShaders, 1);

    // The engine cache owns the native-only replacement selected by the prior
    // SetShaders call. A supplemental program may still be live on the device,
    // so repair that exact delta before the cache compares another pair. The
    // common path is one false atomic load and no D3D call.
    let _ = restore_close_terrain_fast_shader();

    if !super::shader_enabled() {
        return;
    }

    if current_pass_is_native_shadow_depth() {
        // Selector 7's DepthMap pair is executable-proven to be outside every
        // OMV family. Publishing NONE before the native binder prevents stale
        // geometry admission, while leaving the six ignored pointer fields
        // untouched avoids needless atomic traffic at every native shadow
        // pass. The original establishes a different native pair, so any
        // prior raw fallback ceases to own D3D state after it returns.
        PENDING_DRAW_KIND.store(PENDING_DRAW_NONE, Ordering::Release);
        PENDING_REQUIRED_SAMPLER_MASK.store(0, Ordering::Relaxed);
        NATIVE_FALLBACK_ACTIVE.store(false, Ordering::Release);
        return;
    }

    // A prior rejected draw may have temporarily placed vanilla on the device
    // while the engine cache still owns the replacement. Re-align that rare
    // fallback before asking the cache to evaluate another wrapper pair.
    // Most unrelated SetShaders calls have no PBR predecessor and now pay one
    // atomic swap only; the larger selection record is cleared only when it
    // was actually published by an earlier admitted family.
    let previous_kind = PENDING_DRAW_KIND.swap(PENDING_DRAW_NONE, Ordering::AcqRel);
    if previous_kind != PENDING_DRAW_NONE {
        restore_engine_owned_replacement();
        clear_pending_shader_pair();
        PENDING_REQUIRED_SAMPLER_MASK.store(0, Ordering::Release);
        PENDING_MISSING_SAMPLER_MASK.store(0, Ordering::Release);
    }

    if super::terrain_lod_enabled() && current_pass_is_land_lod(pass_index) {
        engine_contracts::enable_fog_for_pass(pass_index);
        let pair = super::land_lod_contracts_ready()
            .then(select_land_lod_pair)
            .flatten();
        if let Some(pair) = pair
            && call_original_with_replacement(original, shader, pass_index, pair)
        {
            set_pending_draw(PENDING_DRAW_LAND_LOD, pass_index, 0, pair);
            return;
        }
        if super::land_lod_contracts_ready() {
            log_land_lod_failure("engine-owned replacement pair could not be selected");
        } else {
            diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::LandLod);
        }
        return;
    }

    if super::terrain_fade_enabled() && current_pass_is_terrain_fade(pass_index) {
        engine_contracts::enable_fog_for_pass(pass_index);
        let pair = super::terrain_fade_contracts_ready()
            .then(select_terrain_fade_pair)
            .flatten();
        if let Some(pair) = pair
            && call_original_with_replacement(original, shader, pass_index, pair)
        {
            set_pending_draw(PENDING_DRAW_TERRAIN_FADE, pass_index, 0, pair);
            return;
        }
        if super::terrain_fade_contracts_ready() {
            log_terrain_fade_failure("engine-owned replacement pair could not be selected");
        } else {
            diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::TerrainFade);
        }
        return;
    }

    if super::close_terrain_enabled()
        && engine_contracts::terrain_contract_available()
        && let Some(draw) = current_close_terrain_draw(pass_index)
    {
        if let Some(variant) = draw.replacement {
            if super::close_terrain_contract_available()
                && device_resources::close_terrain_variant_resources_ready(variant.pixel_sls)
                && let Some(pair) = select_close_terrain_pair(variant)
                && call_original_with_replacement(original, shader, pass_index, pair)
            {
                set_pending_draw(
                    PENDING_DRAW_CLOSE_TERRAIN,
                    pass_index,
                    variant.pixel_index as u32,
                    pair,
                );
                return;
            } else {
                diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
                if super::terrain_engine_contract_ready()
                    && !CLOSE_TERRAIN_WARMING_LOGGED.swap(true, Ordering::AcqRel)
                {
                    log::info!(
                        "[PBR] CloseTerrain remains vanilla until the complete shader family is ready (selected SLS{})",
                        variant.pixel_sls,
                    );
                }
            }
        } else {
            diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::CloseTerrain);
        }
        return;
    }

    if super::object_contract_available()
        && engine_contracts::eye_position_ready_for_pass(pass_index)
        && let Some(replacement) = try_prepare_object_replacement_for_selector(shader, pass_index)
        && call_original_with_replacement(original, shader, pass_index, replacement.pair)
    {
        set_pending_object_draw(pass_index, replacement.pixel_template_id, replacement.pair);
        return;
    }
}

fn native_set_shaders() -> SetShadersFn {
    bind_engine_shader_pair
}

unsafe extern "thiscall" fn bind_engine_shader_pair(
    _selector: *mut c_void,
    _pass_index: u32,
) -> bool {
    if !ENGINE_SHADER_BINDERS_READY.load(Ordering::Acquire) {
        return false;
    }
    let Some((vertex_wrapper, pixel_wrapper)) = engine_contracts::current_pass_shaders_fast()
    else {
        return false;
    };
    let Some(vertex) = engine_contracts::shader_handle_fast(vertex_wrapper, ShaderStage::Vertex)
    else {
        return false;
    };
    let Some(pixel) = engine_contracts::shader_handle_fast(pixel_wrapper, ShaderStage::Pixel)
    else {
        return false;
    };
    let Ok(render_state) = crate::backend::render_state_ptr() else {
        return false;
    };
    let Some(vtable) = live_pointer_fast(render_state) else {
        return false;
    };
    let Some(set_vertex) =
        live_vtable_function_fast(vtable, RENDER_STATE_SET_VERTEX_SHADER_VTABLE_OFFSET)
    else {
        return false;
    };
    let Some(set_pixel) =
        live_vtable_function_fast(vtable, RENDER_STATE_SET_PIXEL_SHADER_VTABLE_OFFSET)
    else {
        return false;
    };

    // This is the exact cache-owning tail of native SetShaders: vertex first,
    // then pixel, with the native save-previous flag clear. Both setters use
    // `ret 8`; omitting that second stack argument corrupts the caller. Re-entering
    // SetShaders itself would run a selector policy detour a second time and
    // could replace OMV's final pair.
    let set_vertex: SetRenderStateShaderFn = unsafe { core::mem::transmute(set_vertex) };
    let set_pixel: SetRenderStateShaderFn = unsafe { core::mem::transmute(set_pixel) };
    unsafe {
        set_vertex(render_state, vertex, 0);
        set_pixel(render_state, pixel, 0);
    }
    true
}

fn live_pointer_fast(owner: *mut c_void) -> Option<*mut c_void> {
    const MIN_ENGINE_PTR: usize = 0x1_0000;

    if (owner as usize) < MIN_ENGINE_PTR {
        return None;
    }
    let value = unsafe { owner.cast::<*mut c_void>().read() };
    (value as usize >= MIN_ENGINE_PTR).then_some(value)
}

fn live_vtable_function_fast(vtable: *mut c_void, offset: usize) -> Option<usize> {
    const MIN_ENGINE_PTR: usize = 0x1_0000;

    let address = (vtable as usize).checked_add(offset)? as *const usize;
    let value = unsafe { address.read() };
    (value >= MIN_ENGINE_PTR).then_some(value)
}

fn call_original_with_replacement(
    original: SetShadersFn,
    shader: *mut c_void,
    pass_index: u32,
    pair: ShaderPairSelection,
) -> bool {
    engine_contracts::with_shader_handle_overrides(
        pair.vertex_wrapper,
        pair.native_vertex,
        pair.replacement_vertex,
        pair.pixel_wrapper,
        pair.native_pixel,
        pair.replacement_pixel,
        || unsafe { original(shader, pass_index) },
    )
    .unwrap_or(false)
}

fn set_pending_draw(
    kind: u32,
    pass_index: u32,
    close_terrain_pixel_index: u32,
    pair: ShaderPairSelection,
) {
    publish_pending_shader_pair(pair);
    PENDING_DRAW_PASS_INDEX.store(pass_index, Ordering::Release);
    PENDING_DRAW_AUXILIARY.store(close_terrain_pixel_index, Ordering::Release);
    PENDING_REQUIRED_SAMPLER_MASK.store(
        u32::from(direct_required_sampler_mask(
            kind,
            pass_index,
            close_terrain_pixel_index,
        )),
        Ordering::Release,
    );
    PENDING_MISSING_SAMPLER_MASK.store(0, Ordering::Release);
    PENDING_CLOSE_TERRAIN_PREPARED_GEOMETRY.store(0, Ordering::Release);
    PENDING_DRAW_EVALUATED.store(false, Ordering::Release);
    PENDING_DRAW_KIND.store(kind, Ordering::Release);
}

fn set_pending_object_draw(pass_index: u32, pixel_template_id: u16, pair: ShaderPairSelection) {
    debug_assert_eq!(pass_index & !PENDING_OBJECT_PASS_MASK, 0);
    let pass_and_template =
        pass_index | (u32::from(pixel_template_id) << PENDING_OBJECT_TEMPLATE_SHIFT);
    publish_pending_shader_pair(pair);
    PENDING_DRAW_PASS_INDEX.store(pass_and_template, Ordering::Release);
    PENDING_DRAW_AUXILIARY.store(crate::backend::d3d_device_generation(), Ordering::Release);
    PENDING_REQUIRED_SAMPLER_MASK.store(0, Ordering::Release);
    PENDING_MISSING_SAMPLER_MASK.store(0, Ordering::Release);
    PENDING_CLOSE_TERRAIN_PREPARED_GEOMETRY.store(0, Ordering::Release);
    PENDING_DRAW_EVALUATED.store(false, Ordering::Release);
    PENDING_DRAW_KIND.store(PENDING_DRAW_OBJECT, Ordering::Release);
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

fn current_pass_is_native_shadow_depth() -> bool {
    let Some((vertex, pixel)) = engine_contracts::current_pass_shaders_fast() else {
        return false;
    };
    let Some(vertex_index) = find_shader_array_index(
        PPLIGHTING_VERTEX_GROUP_C_ADDR,
        PPLIGHTING_VERTEX_GROUP_C_COUNT,
        vertex,
    ) else {
        return false;
    };
    let Some(pixel_index) = find_shader_array_index(
        PPLIGHTING_PIXEL_GROUP_B_ADDR,
        PPLIGHTING_PIXEL_GROUP_B_COUNT,
        pixel,
    ) else {
        return false;
    };
    native_shadow_depth_table_indices(vertex_index, pixel_index)
}

fn native_shadow_depth_table_indices(vertex_index: u32, pixel_index: u32) -> bool {
    (NATIVE_DEPTH_VERTEX_FIRST_INDEX..=NATIVE_DEPTH_VERTEX_LAST_INDEX).contains(&vertex_index)
        && (NATIVE_DEPTH_PIXEL_FIRST_INDEX..=NATIVE_DEPTH_PIXEL_LAST_INDEX).contains(&pixel_index)
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
    let row_kind = family_index % 8;
    let point_light_capacity = match row_kind {
        0 | 1 => 0,
        2 | 3 => 6,
        4 | 5 => 12,
        6 | 7 => 24,
        _ => unreachable!(),
    };

    Some(CloseTerrainVariant {
        pixel_index,
        pixel_sls: 2000u16 + pixel_index as u16,
        texture_count: (family_index / 8 + 1) as u32,
        point_light_capacity,
        native_canopy_row: row_kind % 2 != 0,
    })
}

fn close_terrain_required_sampler_mask(variant: CloseTerrainVariant) -> u16 {
    (0..variant.texture_count)
        .chain(7..7 + variant.texture_count)
        .fold(0u16, |mask, stage| mask | (1u16 << stage))
}

fn select_land_lod_pair() -> Option<ShaderPairSelection> {
    select_terrain_pair(
        LAND_LOD_VERTEX_INDEX,
        LAND_LOD_PIXEL_INDEX,
        device_resources::land_lod_shader_handle(ShaderStage::Vertex)?,
        device_resources::land_lod_shader_handle(ShaderStage::Pixel)?,
    )
}

fn select_terrain_fade_pair() -> Option<ShaderPairSelection> {
    select_terrain_pair(
        TERRAIN_FADE_VERTEX_INDEX,
        TERRAIN_FADE_PIXEL_INDEX,
        device_resources::terrain_fade_shader_handle(ShaderStage::Vertex)?,
        device_resources::terrain_fade_shader_handle(ShaderStage::Pixel)?,
    )
}

fn select_close_terrain_pair(variant: CloseTerrainVariant) -> Option<ShaderPairSelection> {
    select_terrain_pair(
        CLOSE_TERRAIN_VERTEX_INDEX,
        variant.pixel_index,
        device_resources::close_terrain_shader_handle(ShaderStage::Vertex, 2100)?,
        device_resources::close_terrain_fast_pixel_handle(variant.pixel_sls)?,
    )
}

fn select_terrain_pair(
    vertex_index: usize,
    pixel_index: usize,
    replacement_vertex: *mut c_void,
    replacement_pixel: *mut c_void,
) -> Option<ShaderPairSelection> {
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
    Some(ShaderPairSelection {
        vertex_wrapper,
        pixel_wrapper,
        native_vertex: engine_contracts::shader_handle_fast(vertex_wrapper, ShaderStage::Vertex)?,
        native_pixel: engine_contracts::shader_handle_fast(pixel_wrapper, ShaderStage::Pixel)?,
        replacement_vertex,
        replacement_pixel,
    })
}

fn publish_pending_shader_pair(pair: ShaderPairSelection) {
    // `PENDING_DRAW_KIND` is published after this function returns. Its release
    // store is the transaction commit observed by draw hooks, so readers cannot
    // see a kind paired with partially published pointer fields.
    PENDING_VERTEX_WRAPPER.store(pair.vertex_wrapper as usize, Ordering::Release);
    PENDING_PIXEL_WRAPPER.store(pair.pixel_wrapper as usize, Ordering::Release);
    PENDING_NATIVE_VERTEX.store(pair.native_vertex as usize, Ordering::Release);
    PENDING_NATIVE_PIXEL.store(pair.native_pixel as usize, Ordering::Release);
    PENDING_REPLACEMENT_VERTEX.store(pair.replacement_vertex as usize, Ordering::Release);
    PENDING_REPLACEMENT_PIXEL.store(pair.replacement_pixel as usize, Ordering::Release);
}

fn pending_shader_pair() -> Option<ShaderPairSelection> {
    let pair = ShaderPairSelection {
        vertex_wrapper: PENDING_VERTEX_WRAPPER.load(Ordering::Acquire) as *mut c_void,
        pixel_wrapper: PENDING_PIXEL_WRAPPER.load(Ordering::Acquire) as *mut c_void,
        native_vertex: PENDING_NATIVE_VERTEX.load(Ordering::Acquire) as *mut c_void,
        native_pixel: PENDING_NATIVE_PIXEL.load(Ordering::Acquire) as *mut c_void,
        replacement_vertex: PENDING_REPLACEMENT_VERTEX.load(Ordering::Acquire) as *mut c_void,
        replacement_pixel: PENDING_REPLACEMENT_PIXEL.load(Ordering::Acquire) as *mut c_void,
    };
    (!pair.vertex_wrapper.is_null()
        && !pair.pixel_wrapper.is_null()
        && !pair.native_vertex.is_null()
        && !pair.native_pixel.is_null()
        && !pair.replacement_vertex.is_null()
        && !pair.replacement_pixel.is_null())
    .then_some(pair)
}

fn clear_pending_shader_pair() {
    PENDING_VERTEX_WRAPPER.store(0, Ordering::Release);
    PENDING_PIXEL_WRAPPER.store(0, Ordering::Release);
    PENDING_NATIVE_VERTEX.store(0, Ordering::Release);
    PENDING_NATIVE_PIXEL.store(0, Ordering::Release);
    PENDING_REPLACEMENT_VERTEX.store(0, Ordering::Release);
    PENDING_REPLACEMENT_PIXEL.store(0, Ordering::Release);
}

fn bind_land_lod_replacement(pair: ShaderPairSelection) -> bool {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        log_land_lod_failure("D3D device unavailable");
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        log_land_lod_failure("D3D device invalid");
        return false;
    };
    if !pair_still_owns_native_wrappers(pair) {
        log_land_lod_failure("native wrapper ownership changed before draw");
        return false;
    }
    let missing_sampler_mask =
        samplers::missing_required_mask(required_sampler_mask(LAND_LOD_SAMPLERS));
    PENDING_MISSING_SAMPLER_MASK.store(u32::from(missing_sampler_mask), Ordering::Release);
    if missing_sampler_mask != 0 {
        log_land_lod_missing_samplers(missing_sampler_mask);
        return false;
    }
    let Some(requested_constants) = constants::upload_terrain_constants(&device, None) else {
        log_land_lod_failure("terrain constants could not be uploaded");
        return false;
    };
    if diagnostics::detailed_enabled()
        && let Some(observed_constants) = constants::read_terrain_constants(&device)
    {
        log_land_lod_constants(requested_constants, observed_constants);
    }

    if !LAND_LOD_FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[PBR] LandLOD PBR active pass=0x{LAND_LOD_PASS_INDEX:03X} vertex=C[{LAND_LOD_VERTEX_INDEX}] pixel=B[{LAND_LOD_PIXEL_INDEX}]"
        );
    }
    diagnostics::record_terrain_replacement(diagnostics::TerrainDrawFamily::LandLod);
    true
}

fn bind_terrain_fade_replacement(pair: ShaderPairSelection) -> bool {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        log_terrain_fade_failure("D3D device unavailable");
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        log_terrain_fade_failure("D3D device invalid");
        return false;
    };
    if !pair_still_owns_native_wrappers(pair) {
        log_terrain_fade_failure("native wrapper ownership changed before draw");
        return false;
    }
    let missing_sampler_mask =
        samplers::missing_required_mask(required_sampler_mask(TERRAIN_FADE_SAMPLERS));
    PENDING_MISSING_SAMPLER_MASK.store(u32::from(missing_sampler_mask), Ordering::Release);
    if missing_sampler_mask != 0 {
        log_terrain_fade_missing_samplers(missing_sampler_mask);
        return false;
    };
    if constants::upload_terrain_constants(&device, None).is_none() {
        log_terrain_fade_failure("terrain constants could not be uploaded");
        return false;
    }

    if !TERRAIN_FADE_FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[PBR] TerrainFade PBR active pass={TERRAIN_FADE_PASS_INDEX} vertex=C[{TERRAIN_FADE_VERTEX_INDEX}] pixel=B[{TERRAIN_FADE_PIXEL_INDEX}]"
        );
    }
    diagnostics::record_terrain_replacement(diagnostics::TerrainDrawFamily::TerrainFade);
    true
}

fn bind_close_terrain_replacement(
    pass_index: u32,
    pixel_index: usize,
    pair: ShaderPairSelection,
    geometry: *mut c_void,
) -> bool {
    let Some(variant) = close_terrain_variant(pass_index, pixel_index) else {
        log_close_terrain_failure("pass and pixel variant do not match the VPT terrain contract");
        return false;
    };
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        log_close_terrain_failure("D3D device unavailable");
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        log_close_terrain_failure("D3D device invalid");
        return false;
    };
    restore_supplemental_light_texture(&device);
    restore_supplemental_sampler_state(&device);
    if supplemental_sampler_state_is_active() {
        log_close_terrain_failure("previous supplemental sampler state could not be restored");
        return false;
    }
    if !pair_still_owns_native_wrappers(pair) {
        log_close_terrain_failure("native wrapper ownership changed before draw");
        return false;
    }
    if geometry.is_null() {
        log_close_terrain_failure("current geometry is unavailable at the draw boundary");
        return false;
    }
    let geometry_identity = geometry as usize;
    let required_sampler_mask = close_terrain_required_sampler_mask(variant);
    // Texture state belongs to NiDX9RenderState rather than the geometry. The
    // mandatory SetTexture mirror therefore remains authoritative even when a
    // SetShaders batch advances to another geometry without rebinding stages.
    let missing_sampler_mask = samplers::missing_required_mask(required_sampler_mask);
    PENDING_MISSING_SAMPLER_MASK.store(u32::from(missing_sampler_mask), Ordering::Release);
    if missing_sampler_mask != 0 {
        log_close_terrain_missing_samplers(
            pixel_index,
            variant.texture_count,
            missing_sampler_mask,
        );
        return false;
    };
    let supplemental_lights = super::terrain_lights::capture_current_for_draw(geometry_identity);
    if supplemental_lights.is_empty()
        && !set_close_terrain_supplemental_shader(&device, variant, pair, false)
    {
        log_close_terrain_failure("native-only close-terrain shader could not be restored");
        return false;
    }
    if !supplemental_lights.is_empty() {
        // A temporary raw bind is safe only if the engine mirror can restore
        // an exact prior state. Unknown is not equivalent to known-null: the
        // former could hide a live binding installed before the hook existed.
        if matches!(
            samplers::tracked_texture_binding(device_resources::SUPPLEMENTAL_LIGHT_SAMPLER),
            TrackedTextureBinding::Unknown
        ) {
            log_close_terrain_failure("engine ownership of supplemental sampler s14 is unknown");
            return false;
        }
        if !super::device_resources::upload_and_bind_supplemental_light_texture(
            &device,
            &supplemental_lights,
        ) {
            log_close_terrain_failure("supplemental light texture could not be uploaded");
            return false;
        }
        // The tracker intentionally remains engine-owned. This bit records
        // only OMV's temporary raw override so finish/fallback can restore s14
        // from the authoritative SetTexture mirror after the draw.
        PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND.store(true, Ordering::Release);
        if !bind_supplemental_sampler_state(&device) {
            restore_supplemental_sampler_state(&device);
            restore_supplemental_light_texture(&device);
            log_close_terrain_failure("supplemental sampler state could not be owned");
            return false;
        }
    }
    // Native geometry setup may rewrite pixel constants between DIPs even when
    // it reuses the same shader pass. Upload the cheap constant block on every
    // draw; only the expensive engine light scan is cached per geometry.
    if constants::upload_terrain_constants(&device, Some(&supplemental_lights)).is_none() {
        restore_supplemental_sampler_state(&device);
        restore_supplemental_light_texture(&device);
        log_close_terrain_failure("terrain constants could not be uploaded");
        return false;
    }
    if !supplemental_lights.is_empty()
        && !set_close_terrain_supplemental_shader(&device, variant, pair, true)
    {
        restore_supplemental_sampler_state(&device);
        restore_supplemental_light_texture(&device);
        log_close_terrain_failure("supplemental close-terrain shader could not be selected");
        return false;
    }
    PENDING_CLOSE_TERRAIN_PREPARED_GEOMETRY.store(geometry_identity, Ordering::Release);

    if !CLOSE_TERRAIN_FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[PBR] CloseTerrain PBR active vertex=C[{CLOSE_TERRAIN_VERTEX_INDEX}] pixel=B[{pixel_index}] textures={} point_lights={} native_canopy_row={}",
            variant.texture_count,
            variant.point_light_capacity,
            variant.native_canopy_row
        );
    }
    if variant.native_canopy_row
        && !CLOSE_TERRAIN_FIRST_CANOPY_BIND_LOGGED.swap(true, Ordering::AcqRel)
    {
        log::info!(
            "[PBR] CloseTerrain canopy companion active pixel=B[{pixel_index}] object_shadow_sampling=false"
        );
    }
    diagnostics::record_terrain_replacement(diagnostics::TerrainDrawFamily::CloseTerrain);
    true
}

fn pair_still_owns_native_wrappers(pair: ShaderPairSelection) -> bool {
    engine_contracts::shader_handle_fast(pair.vertex_wrapper, ShaderStage::Vertex)
        == Some(pair.native_vertex)
        && engine_contracts::shader_handle_fast(pair.pixel_wrapper, ShaderStage::Pixel)
            == Some(pair.native_pixel)
}

fn set_close_terrain_supplemental_shader(
    device: &Device9Ref<'_>,
    variant: CloseTerrainVariant,
    pair: ShaderPairSelection,
    supplemental: bool,
) -> bool {
    let active = PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.load(Ordering::Acquire);
    if !supplemental_shader_transition_needed(active, supplemental) {
        return true;
    }

    let pixel_shader = if supplemental {
        let Some(shader) =
            device_resources::close_terrain_supplemental_pixel_handle(variant.pixel_sls)
        else {
            return false;
        };
        shader
    } else {
        pair.replacement_pixel
    };
    // The engine cache deliberately continues owning pair.replacement_pixel.
    // Retain the alternate program across compatible geometry draws, then
    // restore the cached identity before SetShaders, fallback completion,
    // frame cleanup, disable, reset, or resource release. This bounds raw
    // transitions by payload-mode changes rather than geometry count.
    if unsafe { device.set_raw_pixel_shader(pixel_shader) }.is_err() {
        return false;
    }
    PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.store(supplemental, Ordering::Release);
    true
}

fn supplemental_shader_transition_needed(active: bool, requested: bool) -> bool {
    active != requested
}

fn restore_close_terrain_fast_shader() -> bool {
    if !PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.load(Ordering::Acquire) {
        return true;
    }
    let Some(pair) = pending_shader_pair() else {
        return false;
    };
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return false;
    };
    if unsafe { device.set_raw_pixel_shader(pair.replacement_pixel) }.is_err() {
        return false;
    }
    PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.store(false, Ordering::Release);
    true
}

fn restore_supplemental_light_texture(device: &Device9Ref<'_>) {
    if !PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND.load(Ordering::Acquire) {
        return;
    }
    let stage = super::device_resources::SUPPLEMENTAL_LIGHT_SAMPLER;
    let restored = match super::samplers::tracked_texture_binding(stage) {
        TrackedTextureBinding::Bound(texture) => unsafe {
            device.set_raw_base_texture(stage, texture as *mut c_void)
        },
        TrackedTextureBinding::Null => device.clear_texture(stage),
        TrackedTextureBinding::Unknown => return,
    }
    .is_ok();
    if restored {
        PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND.store(false, Ordering::Release);
    } else if !SUPPLEMENTAL_TEXTURE_RESTORE_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] Engine-owned sampler s14 could not be restored after terrain draw");
    }
}

fn bind_supplemental_sampler_state(device: &Device9Ref<'_>) -> bool {
    let _span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::PbrSupplementalSampler,
    );
    crate::graphics_diagnostics::add(
        crate::graphics_diagnostics::Counter::SupplementalSamplerGet,
        1,
    );
    let Ok(min_filter) = device.sampler_state(
        device_resources::SUPPLEMENTAL_LIGHT_SAMPLER,
        D3DSAMP_MINFILTER,
    ) else {
        return false;
    };
    crate::graphics_diagnostics::add(
        crate::graphics_diagnostics::Counter::SupplementalSamplerGet,
        1,
    );
    let Ok(mag_filter) = device.sampler_state(
        device_resources::SUPPLEMENTAL_LIGHT_SAMPLER,
        D3DSAMP_MAGFILTER,
    ) else {
        return false;
    };
    crate::graphics_diagnostics::add(
        crate::graphics_diagnostics::Counter::SupplementalSamplerGet,
        1,
    );
    let Ok(srgb) = device.sampler_state(
        device_resources::SUPPLEMENTAL_LIGHT_SAMPLER,
        D3DSAMP_SRGBTEXTURE,
    ) else {
        return false;
    };

    let point = D3DTEXF_POINT.0 as u32;
    // tex2Dlod fixes mip level zero, and both 64-wide coordinates are exact
    // interior texel centers, so mip and address modes cannot influence this
    // lookup. Min/mag filtering and sRGB decode remain physical fetch/color
    // inputs and are therefore owned explicitly for the draw.
    if min_filter == point && mag_filter == point && srgb == 0 {
        return true;
    }

    // Publish the complete rollback record before the first mutating D3D call.
    // A setter and its immediate rollback can both fail during device loss; in
    // that case the active marker must survive so every later boundary retries
    // restoration instead of silently treating partially changed state as the
    // engine's state. This ordering is off the empty-payload fast path.
    PENDING_CLOSE_TERRAIN_SAMPLER_MIN_FILTER.store(min_filter, Ordering::Relaxed);
    PENDING_CLOSE_TERRAIN_SAMPLER_MAG_FILTER.store(mag_filter, Ordering::Relaxed);
    PENDING_CLOSE_TERRAIN_SAMPLER_SRGB.store(srgb, Ordering::Relaxed);
    PENDING_CLOSE_TERRAIN_SAMPLER_STATE_ACTIVE.store(true, Ordering::Release);

    if (min_filter != point && !set_supplemental_sampler_state(device, D3DSAMP_MINFILTER, point))
        || (mag_filter != point
            && !set_supplemental_sampler_state(device, D3DSAMP_MAGFILTER, point))
        || (srgb != 0 && !set_supplemental_sampler_state(device, D3DSAMP_SRGBTEXTURE, 0))
    {
        restore_supplemental_sampler_state(device);
        return false;
    }
    true
}

fn restore_supplemental_sampler_state(device: &Device9Ref<'_>) {
    if !PENDING_CLOSE_TERRAIN_SAMPLER_STATE_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let _span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::PbrSupplementalSampler,
    );
    let mut restored = set_supplemental_sampler_state(
        device,
        D3DSAMP_MINFILTER,
        PENDING_CLOSE_TERRAIN_SAMPLER_MIN_FILTER.load(Ordering::Relaxed),
    );
    restored &= set_supplemental_sampler_state(
        device,
        D3DSAMP_MAGFILTER,
        PENDING_CLOSE_TERRAIN_SAMPLER_MAG_FILTER.load(Ordering::Relaxed),
    );
    restored &= set_supplemental_sampler_state(
        device,
        D3DSAMP_SRGBTEXTURE,
        PENDING_CLOSE_TERRAIN_SAMPLER_SRGB.load(Ordering::Relaxed),
    );
    if restored {
        PENDING_CLOSE_TERRAIN_SAMPLER_STATE_ACTIVE.store(false, Ordering::Release);
    } else if !SUPPLEMENTAL_TEXTURE_RESTORE_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] Engine-owned sampler s14 state could not be restored after terrain draw");
    }
}

fn set_supplemental_sampler_state(
    device: &Device9Ref<'_>,
    state: D3DSAMPLERSTATETYPE,
    value: u32,
) -> bool {
    crate::graphics_diagnostics::add(
        crate::graphics_diagnostics::Counter::SupplementalSamplerSet,
        1,
    );
    device
        .set_sampler_state(device_resources::SUPPLEMENTAL_LIGHT_SAMPLER, state, value)
        .is_ok()
}

fn supplemental_sampler_state_is_active() -> bool {
    PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND.load(Ordering::Acquire)
        || PENDING_CLOSE_TERRAIN_SAMPLER_STATE_ACTIVE.load(Ordering::Acquire)
}

/// Forget a temporary s14 override after a proven D3D generation transition.
///
/// A failed restore retains its marker while the device remains live. Once the
/// lifecycle generation changes, D3D9 has invalidated that old binding and the
/// marker must not poison admission on the replacement device.
pub(super) fn forget_supplemental_light_texture_binding_after_device_change() {
    PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND.store(false, Ordering::Release);
    PENDING_CLOSE_TERRAIN_SAMPLER_STATE_ACTIVE.store(false, Ordering::Release);
    PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.store(false, Ordering::Release);
}

fn restore_engine_owned_replacement() {
    if !NATIVE_FALLBACK_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let Some(pair) = pending_shader_pair() else {
        NATIVE_FALLBACK_ACTIVE.store(false, Ordering::Release);
        return;
    };
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };
    let mut restored = unsafe { device.set_raw_vertex_shader(pair.replacement_vertex) }.is_ok();
    restored &= unsafe { device.set_raw_pixel_shader(pair.replacement_pixel) }.is_ok();
    if restored {
        NATIVE_FALLBACK_ACTIVE.store(false, Ordering::Release);
        PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.store(false, Ordering::Release);
    } else {
        // A partial replacement bind is not drawable. Put both vanilla stages
        // back and retain fallback ownership so a later boundary can retry.
        let _ = unsafe { device.set_raw_vertex_shader(pair.native_vertex) };
        let _ = unsafe { device.set_raw_pixel_shader(pair.native_pixel) };
        if !DIRECT_RESTORE_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
            log::warn!(
                "[PBR] Engine-owned replacement pair could not be restored after vanilla fallback"
            );
        }
    }
}

/// Returns the current PBR-owned device state to vanilla before resources drop.
///
/// The engine render-state cache still contains the replacement identity. That
/// is intentional: on its next ordinary `SetShaders` call it observes a native
/// wrapper handle different from the cached replacement and repairs the cache
/// through the normal engine path. No replacement handle remains in a wrapper.
pub(super) fn release_device_resources() {
    let device = crate::backend::d3d_device_ptr()
        .and_then(|device_ptr| unsafe { Device9Ref::from_raw_void(device_ptr) });
    if let Some(device) = device.as_ref() {
        restore_supplemental_sampler_state(device);
        restore_supplemental_light_texture(device);
        let _ = restore_close_terrain_fast_shader();
        if let Some(pair) = pending_shader_pair()
            && !NATIVE_FALLBACK_ACTIVE.load(Ordering::Acquire)
        {
            let _ = unsafe { device.set_raw_vertex_shader(pair.native_vertex) };
            let _ = unsafe { device.set_raw_pixel_shader(pair.native_pixel) };
        }
    }
    NATIVE_FALLBACK_ACTIVE.store(false, Ordering::Release);
    PENDING_DRAW_KIND.store(PENDING_DRAW_NONE, Ordering::Release);
    PENDING_DRAW_EVALUATED.store(true, Ordering::Release);
    clear_pending_shader_pair();
}

/// Evaluates pending native PBR ownership before one D3D draw.
///
/// Returns `true` only for a close-terrain draw boundary that must be passed to
/// [`finish_direct_draw`] after the native draw, including when replacement
/// admission fell back.
#[must_use]
pub(super) fn prepare_direct_draw(geometry: *mut c_void) -> bool {
    let kind = PENDING_DRAW_KIND.load(Ordering::Acquire);
    if kind == PENDING_DRAW_NONE {
        crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::PbrPendingNone, 1);
        return false;
    }
    if !super::shader_enabled() {
        return false;
    }
    if !draw_needs_evaluation(PENDING_DRAW_EVALUATED.load(Ordering::Acquire)) {
        return false;
    }

    PENDING_DRAW_EVALUATED.store(true, Ordering::Release);

    let Some(pair) = pending_shader_pair() else {
        PENDING_DRAW_KIND.store(PENDING_DRAW_NONE, Ordering::Release);
        return false;
    };
    let _span =
        crate::graphics_diagnostics::span(crate::graphics_diagnostics::Interval::PbrAdmission);
    // Repair a prior vanilla fallback before this geometry chooses any
    // draw-specific state. Restoring afterward would overwrite a supplemental
    // close-terrain pixel program selected by the binding transaction below.
    // A failed repair remains vanilla and rejects this draw rather than
    // reporting admission against a device state OMV does not own.
    restore_engine_owned_replacement();
    let replacement_ready = !NATIVE_FALLBACK_ACTIVE.load(Ordering::Acquire);
    let admitted = replacement_ready
        && match kind {
            PENDING_DRAW_OBJECT => {
                let pass_and_template = PENDING_DRAW_PASS_INDEX.load(Ordering::Acquire);
                let pass_index = pass_and_template & PENDING_OBJECT_PASS_MASK;
                let pixel_template_id = (pass_and_template >> PENDING_OBJECT_TEMPLATE_SHIFT) as u16;
                let device_generation = PENDING_DRAW_AUXILIARY.load(Ordering::Acquire);
                bind_object_replacement(pass_index, pixel_template_id, device_generation, pair)
            }
            PENDING_DRAW_LAND_LOD => bind_land_lod_replacement(pair),
            PENDING_DRAW_TERRAIN_FADE => bind_terrain_fade_replacement(pair),
            PENDING_DRAW_CLOSE_TERRAIN => {
                let pass_index = PENDING_DRAW_PASS_INDEX.load(Ordering::Acquire);
                let pixel_index = PENDING_DRAW_AUXILIARY.load(Ordering::Acquire) as usize;
                bind_close_terrain_replacement(pass_index, pixel_index, pair, geometry)
            }
            _ => false,
        };
    if admitted {
        crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::PbrAdmission, 1);
    } else {
        crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::PbrFallback, 1);
        bind_native_fallback(pair);
    }

    // Re-arm close-terrain admission after this geometry even when binding fell
    // back. A later geometry can be valid without another SetShaders call, so
    // a failed first draw cannot close the batch.
    direct_draw_requires_finish(kind)
}

/// Restores and re-arms state acquired by [`prepare_direct_draw`].
pub(super) fn finish_direct_draw(restore_after_draw: bool) {
    if !restore_after_draw {
        return;
    }

    if let Some(device_ptr) = crate::backend::d3d_device_ptr()
        && let Some(device) = unsafe { Device9Ref::from_raw_void(device_ptr) }
    {
        restore_supplemental_sampler_state(&device);
        restore_supplemental_light_texture(&device);
    }

    // Close terrain is admitted per renderer geometry, not per SetShaders
    // batch. A rejected geometry used vanilla for this submission; restore the cache-owned replacement
    // before re-arming so a later valid geometry keeps full PBR coverage.
    restore_engine_owned_replacement();
    PENDING_DRAW_EVALUATED.store(false, Ordering::Release);
}

/// Clears pending validation state at the frame boundary.
pub(super) fn finish_draw_batches() {
    if let Some(device_ptr) = crate::backend::d3d_device_ptr()
        && let Some(device) = unsafe { Device9Ref::from_raw_void(device_ptr) }
    {
        restore_supplemental_sampler_state(&device);
        restore_supplemental_light_texture(&device);
    }
    let _ = restore_close_terrain_fast_shader();
    restore_engine_owned_replacement();
    PENDING_DRAW_KIND.store(PENDING_DRAW_NONE, Ordering::Release);
    PENDING_DRAW_EVALUATED.store(true, Ordering::Release);
    PENDING_REQUIRED_SAMPLER_MASK.store(0, Ordering::Release);
    PENDING_MISSING_SAMPLER_MASK.store(0, Ordering::Release);
    PENDING_CLOSE_TERRAIN_PREPARED_GEOMETRY.store(0, Ordering::Release);
    super::terrain_lights::invalidate_draw_cache();
}

fn draw_needs_evaluation(evaluated: bool) -> bool {
    !evaluated
}

fn direct_draw_requires_finish(kind: u32) -> bool {
    kind == PENDING_DRAW_CLOSE_TERRAIN
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectSamplerChange {
    Ignore,
    Keep,
    Missing(u16),
    Recovered(u16),
}

fn direct_required_sampler_mask(kind: u32, pass_index: u32, close_terrain_pixel_index: u32) -> u16 {
    match kind {
        PENDING_DRAW_LAND_LOD => required_sampler_mask(LAND_LOD_SAMPLERS),
        PENDING_DRAW_TERRAIN_FADE => required_sampler_mask(TERRAIN_FADE_SAMPLERS),
        PENDING_DRAW_CLOSE_TERRAIN => {
            close_terrain_variant(pass_index, close_terrain_pixel_index as usize)
                .map(close_terrain_required_sampler_mask)
                .unwrap_or(0)
        }
        _ => 0,
    }
}

fn direct_sampler_change(
    required_sampler_mask: u16,
    missing_sampler_mask: u16,
    stage: u32,
    texture_bound: bool,
) -> DirectSamplerChange {
    if stage >= 16 {
        return DirectSamplerChange::Ignore;
    }
    let stage_mask = 1u16 << stage;
    if required_sampler_mask & stage_mask == 0 {
        return DirectSamplerChange::Ignore;
    }
    if !texture_bound && missing_sampler_mask & stage_mask == 0 {
        return DirectSamplerChange::Missing(missing_sampler_mask | stage_mask);
    }
    if !texture_bound {
        return DirectSamplerChange::Keep;
    }
    if missing_sampler_mask & stage_mask != 0 {
        return DirectSamplerChange::Recovered(missing_sampler_mask & !stage_mask);
    }
    DirectSamplerChange::Keep
}

fn required_sampler_mask(stages: &[u32]) -> u16 {
    stages
        .iter()
        .copied()
        .filter(|stage| *stage < 16)
        .fold(0u16, |mask, stage| mask | (1u16 << stage))
}

fn bind_native_fallback(pair: ShaderPairSelection) -> bool {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return false;
    };
    restore_supplemental_sampler_state(&device);
    restore_supplemental_light_texture(&device);
    // A failed restore means OMV still owns s14. Reporting a successful
    // fallback in that state would submit vanilla with OMV's data texture.
    if supplemental_sampler_state_is_active() {
        return false;
    }
    if NATIVE_FALLBACK_ACTIVE.load(Ordering::Acquire) {
        return true;
    }
    let vertex_result = unsafe { device.set_raw_vertex_shader(pair.native_vertex) };
    let pixel_result = unsafe { device.set_raw_pixel_shader(pair.native_pixel) };
    if vertex_result.is_err() || pixel_result.is_err() {
        let _ = unsafe { device.set_raw_vertex_shader(pair.replacement_vertex) };
        if unsafe { device.set_raw_pixel_shader(pair.replacement_pixel) }.is_ok() {
            PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.store(false, Ordering::Release);
        }
        return false;
    }

    // The native pixel bind supersedes either member of the close-terrain pair.
    // Keeping the supplemental marker set would cause a later boundary to make
    // an unnecessary raw transition based on stale device-state ownership.
    PENDING_CLOSE_TERRAIN_SUPPLEMENTAL_SHADER_ACTIVE.store(false, Ordering::Release);
    NATIVE_FALLBACK_ACTIVE.store(true, Ordering::Release);
    true
}

fn log_land_lod_failure(reason: &'static str) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::LandLod);
    if !LAND_LOD_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] LandLOD PBR kept vanilla: {reason}");
    }
}

fn log_land_lod_missing_samplers(missing_sampler_mask: u16) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::LandLod);
    if !LAND_LOD_MISSING_SAMPLER_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!(
            "[PBR] LandLOD PBR kept vanilla: missing_sampler_mask=0x{missing_sampler_mask:04X} required_sampler_mask=0x{:04X}",
            required_sampler_mask(LAND_LOD_SAMPLERS),
        );
    }
}

fn log_terrain_fade_failure(reason: &'static str) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::TerrainFade);
    if !TERRAIN_FADE_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[PBR] TerrainFade PBR kept vanilla: {reason}");
    }
}

fn log_terrain_fade_missing_samplers(missing_sampler_mask: u16) {
    diagnostics::record_terrain_fallback(diagnostics::TerrainDrawFamily::TerrainFade);
    if !TERRAIN_FADE_MISSING_SAMPLER_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!(
            "[PBR] TerrainFade PBR kept vanilla: missing_sampler_mask=0x{missing_sampler_mask:04X} required_sampler_mask=0x{:04X}",
            required_sampler_mask(TERRAIN_FADE_SAMPLERS),
        );
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
    let Ok(original) = SET_TEXTURE_HOOK.original() else {
        return;
    };
    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::SetTexture, 1);
    // This fixed atomic mirror is shared with native sky. It must remain
    // authoritative while PBR is disabled; otherwise enabling sky alone would
    // have to query texture state back from the driver at geometry frequency.
    let selector = if diagnostics::detailed_enabled() {
        engine_contracts::current_draw_selector_address_fast()
    } else {
        0
    };
    super::samplers::record_texture_binding(stage, texture, selector);
    unsafe {
        original(render_state, stage, texture);
    }

    if !super::replacement_configured() {
        return;
    }

    let required_sampler_mask = PENDING_REQUIRED_SAMPLER_MASK.load(Ordering::Relaxed) as u16;
    if required_sampler_mask == 0 {
        return;
    }
    let missing_sampler_mask = PENDING_MISSING_SAMPLER_MASK.load(Ordering::Relaxed) as u16;
    match direct_sampler_change(
        required_sampler_mask,
        missing_sampler_mask,
        stage,
        !texture.is_null(),
    ) {
        DirectSamplerChange::Ignore | DirectSamplerChange::Keep => {}
        DirectSamplerChange::Missing(mask) => {
            PENDING_MISSING_SAMPLER_MASK.store(u32::from(mask), Ordering::Relaxed);
            if let Some(pair) = pending_shader_pair() {
                bind_native_fallback(pair);
            }
            PENDING_DRAW_EVALUATED.store(false, Ordering::Release);
        }
        DirectSamplerChange::Recovered(mask) => {
            PENDING_MISSING_SAMPLER_MASK.store(u32::from(mask), Ordering::Relaxed);
            PENDING_DRAW_EVALUATED.store(false, Ordering::Release);
        }
    }
}

fn try_prepare_object_replacement(pass_index: u32) -> Option<PreparedObjectReplacement> {
    let selector = engine_contracts::current_draw_selector_address_fast() as *mut c_void;
    try_prepare_object_replacement_for_selector(selector, pass_index)
}

fn try_prepare_object_replacement_for_selector(
    selector: *mut c_void,
    pass_index: u32,
) -> Option<PreparedObjectReplacement> {
    let _span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::PbrObjectPreparation,
    );
    let Some((vertex_shader, pixel_shader)) = engine_contracts::current_pass_shaders_fast() else {
        return None;
    };
    let diagnostics_enabled = diagnostics::detailed_enabled();

    let vertex_record = match resolve_current_shader_record(vertex_shader, ShaderStage::Vertex) {
        Ok(record) => record,
        Err(reason) => {
            if diagnostics_enabled {
                record_unresolved_table_pair(
                    engine_contracts::DrawSnapshot::default(),
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
                    engine_contracts::DrawSnapshot::default(),
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
    let mut draw_snapshot = if diagnostics_enabled {
        engine_contracts::current_draw_snapshot(selector, pass_index)
    } else {
        engine_contracts::DrawSnapshot::default()
    };

    // Only a proven PPLighting wrapper pair authorizes interpreting the
    // callback-owned selector layout. Missing or malformed selector state is
    // fail-closed and preserves the native pair.
    let admission = engine_contracts::object_draw_admission(selector, pass_index);
    if matches!(admission, ObjectDrawAdmission::Unavailable) {
        if diagnostics_enabled {
            diagnostics::record_object_draw_gate_rejection(
                ObjectDrawRejectReason::MissingD3DState,
                0,
                selector as usize,
            );
        }
        return None;
    }
    if let ObjectDrawAdmission::Reject(rejection) = admission {
        draw_snapshot.rejection = Some(rejection);
    }
    if diagnostics_enabled {
        diagnostics::record_object_draw_context(draw_snapshot);
        record_current_table_pair(vertex_shader, pixel_shader);
    }

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
    let Some(native_vertex) =
        engine_contracts::shader_handle_fast(vertex_record.shader, ShaderStage::Vertex)
    else {
        return None;
    };
    let Some(native_pixel) =
        engine_contracts::shader_handle_fast(pixel_record.shader, ShaderStage::Pixel)
    else {
        return None;
    };

    if matches!(
        contract.state,
        ObjectContractState::ImplementedOnlyLight
            | ObjectContractState::ImplementedDiffusePoint
            | ObjectContractState::ImplementedOnlySpecular
    ) {
        engine_contracts::enable_fog_for_pass(pass_index);
    }

    Some(PreparedObjectReplacement {
        pair: ShaderPairSelection {
            vertex_wrapper: vertex_record.shader,
            pixel_wrapper: pixel_record.shader,
            native_vertex,
            native_pixel,
            replacement_vertex,
            replacement_pixel,
        },
        pixel_template_id: pixel_record.template_id,
        draw_trace,
        normalized_vertex_index: contract.normalized_vertex_index,
        contract_state: contract.state,
        uses_native_specular_fade: shader_registry::object_template_uses_native_specular_fade(
            pixel_record.template_id,
        ),
        diagnostics_enabled,
    })
}

fn bind_object_replacement(
    pass_index: u32,
    pixel_template_id: u16,
    device_generation: u32,
    pending_pair: ShaderPairSelection,
) -> bool {
    if crate::backend::d3d_device_generation() != device_generation {
        record_optional_object_bind_failure(None, ObjectDrawRejectReason::HandleStateMismatch);
        return false;
    }
    let detailed = diagnostics::detailed_enabled();
    let replacement = detailed
        .then(|| try_prepare_object_replacement(pass_index))
        .flatten();
    if detailed && replacement.is_none() {
        diagnostics::record_object_fallback();
        return false;
    }
    if replacement.is_some_and(|replacement| {
        replacement.pair != pending_pair || replacement.pixel_template_id != pixel_template_id
    }) || !pair_still_owns_native_wrappers(pending_pair)
    {
        record_optional_object_bind_failure(
            replacement,
            ObjectDrawRejectReason::HandleStateMismatch,
        );
        return false;
    }
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        record_optional_object_bind_failure(replacement, ObjectDrawRejectReason::MissingD3DState);
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        record_optional_object_bind_failure(replacement, ObjectDrawRejectReason::MissingD3DState);
        return false;
    };
    // SetShaders selected this exact pair through the engine wrapper/cache
    // boundary. Reading both shaders back from D3D here would synchronize the
    // driver for diagnostic confirmation of state OMV just established.
    if detailed {
        diagnostics::record_object_d3d_state(
            pending_pair.replacement_vertex,
            pending_pair.replacement_pixel,
            pending_pair.replacement_vertex,
            pending_pair.replacement_pixel,
        );
    }
    if let Err(reason) = object_replacement_record::validate_pixel_samplers(
        pixel_template_id,
        replacement.map_or(0, |replacement| replacement.draw_trace.selector),
        detailed,
    ) {
        record_optional_object_bind_failure(replacement, reason);
        return false;
    }

    if !constants::upload_object_constants(&device) {
        record_optional_object_bind_failure(replacement, ObjectDrawRejectReason::MissingD3DState);
        return false;
    }
    if detailed {
        diagnostics::record_object_constant_upload();
    }
    if let Some(replacement) = replacement {
        if replacement.uses_native_specular_fade {
            let light_capacity = shader_registry::object_template_light_count(pixel_template_id);
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
                    samplers::object_sampler_identity(pixel_template_id),
                );
            }
        }
        diagnostics::record_object_contract(
            replacement.draw_trace,
            replacement.normalized_vertex_index,
            replacement.contract_state,
        );
        diagnostics::record_object_replacement();
    }
    if !OBJECT_FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!("[PBR] Object PBR active pass={pass_index}");
    }
    true
}

fn record_optional_object_bind_failure(
    replacement: Option<PreparedObjectReplacement>,
    reason: ObjectDrawRejectReason,
) {
    if let Some(replacement) = replacement {
        record_object_bind_failure(replacement, reason);
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
        CLOSE_TERRAIN_FIRST_PIXEL_INDEX, CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET, DirectSamplerChange,
        LAND_LOD_SAMPLERS, PENDING_DRAW_CLOSE_TERRAIN, PENDING_DRAW_LAND_LOD, PENDING_DRAW_OBJECT,
        PENDING_DRAW_TERRAIN_FADE, TERRAIN_FADE_SAMPLERS, close_terrain_draw,
        close_terrain_required_sampler_mask, close_terrain_variant, direct_draw_requires_finish,
        direct_required_sampler_mask, direct_sampler_change, draw_needs_evaluation,
        hash_light_data, native_shadow_depth_table_indices, object_draw_key, required_sampler_mask,
        supplemental_shader_transition_needed,
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
    fn terrain_sampler_masks_match_the_native_shader_abi() {
        assert_eq!(required_sampler_mask(LAND_LOD_SAMPLERS), 0x00D3);
        assert_eq!(required_sampler_mask(TERRAIN_FADE_SAMPLERS), 0x0007);
    }

    #[test]
    fn native_shadow_depth_rows_are_never_pbr_candidates() {
        for vertex in 92..=95 {
            for pixel in 90..=91 {
                assert!(native_shadow_depth_table_indices(vertex, pixel));
            }
        }
        assert!(!native_shadow_depth_table_indices(100, 92));
        assert!(!native_shadow_depth_table_indices(49, 56));
    }

    #[test]
    fn direct_draw_rechecks_only_when_tracking_cannot_prove_ownership() {
        assert!(draw_needs_evaluation(false));
        assert!(!draw_needs_evaluation(true));
    }

    #[test]
    fn only_close_terrain_requires_per_geometry_cleanup() {
        assert!(!direct_draw_requires_finish(PENDING_DRAW_OBJECT));
        assert!(!direct_draw_requires_finish(PENDING_DRAW_LAND_LOD));
        assert!(!direct_draw_requires_finish(PENDING_DRAW_TERRAIN_FADE));
        assert!(direct_draw_requires_finish(PENDING_DRAW_CLOSE_TERRAIN));
    }

    #[test]
    fn disabled_set_shaders_skips_pending_draw_reconciliation() {
        let source = include_str!("hooks.rs");
        let set_shaders = source
            .split_once("unsafe extern \"thiscall\" fn hook_set_shaders")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("fn set_pending_draw"))
            .map(|(body, _)| body)
            .expect("SetShaders hook");
        let disabled_gate = set_shaders.find("if !super::shader_enabled()").unwrap();
        let supplemental_restore = set_shaders
            .find("restore_close_terrain_fast_shader()")
            .unwrap();
        let restore = set_shaders
            .find("restore_engine_owned_replacement()")
            .unwrap();
        assert!(supplemental_restore < disabled_gate);
        assert!(disabled_gate < restore);
    }

    #[test]
    fn set_shaders_uses_engine_cache_before_publishing_draw_ownership() {
        let source = include_str!("hooks.rs");
        let call = source
            .split_once("fn call_original_with_replacement")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("fn set_pending_draw"))
            .map(|(body, _)| body)
            .expect("engine-owned SetShaders call");
        let override_pair = call
            .find("engine_contracts::with_shader_handle_overrides")
            .unwrap();
        let native_call = call.find("original(shader, pass_index)").unwrap();
        assert!(override_pair < native_call);

        let set_shaders = source
            .split_once("unsafe extern \"thiscall\" fn hook_set_shaders")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("fn call_original_with_replacement"))
            .map(|(body, _)| body)
            .expect("SetShaders hook");
        assert!(!set_shaders.contains("set_raw_vertex_shader"));
        assert!(!set_shaders.contains("set_raw_pixel_shader"));
    }

    #[test]
    fn shared_set_texture_tracking_precedes_native_and_pbr_specific_work() {
        let source = include_str!("hooks.rs");
        let hook = source
            .split_once("unsafe extern \"thiscall\" fn hook_set_texture")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("fn try_prepare_object_replacement"))
            .map(|(body, _)| body)
            .expect("SetTexture hook");
        let tracking = hook
            .find("super::samplers::record_texture_binding")
            .expect("sampler tracking");
        let native = hook
            .find("original(render_state, stage, texture)")
            .expect("native SetTexture");
        let gate = hook
            .find("if !super::replacement_configured()")
            .expect("configured-state gate");

        assert!(tracking < native);
        assert!(native < gate);
    }

    #[test]
    fn shader_creation_entries_are_not_hooked_and_first_use_adopts_wrappers() {
        let source = include_str!("hooks.rs");
        for removed_entry in [["0x00BE", "0FE0"], ["0x00BE", "1750"]] {
            assert!(!source.contains(&removed_entry.concat()));
        }
        for removed_wrapper in [
            ["hook_create_", "vertex_shader"],
            ["hook_create_", "pixel_shader"],
        ] {
            assert!(!source.contains(&removed_wrapper.concat()));
        }

        let adoption = source
            .split_once("fn resolve_current_shader_record")
            .and_then(|(_, tail)| tail.split_once("fn ensure_table_identity"))
            .map(|(body, _)| body)
            .expect("draw-time wrapper adoption");
        assert!(adoption.contains("shader_record::adopt_existing"));

        let install = source
            .split_once("pub(super) fn install()")
            .and_then(|(_, tail)| tail.split_once("fn prepare_set_texture_hook"))
            .map(|(body, _)| body)
            .expect("PBR install");
        assert!(install.contains("adopt_existing_object_shaders()"));
    }

    #[test]
    fn direct_sampler_tracking_uses_exact_family_masks() {
        let required = required_sampler_mask(LAND_LOD_SAMPLERS);

        assert_eq!(direct_required_sampler_mask(PENDING_DRAW_OBJECT, 0, 0), 0);
        assert_eq!(
            direct_required_sampler_mask(
                PENDING_DRAW_CLOSE_TERRAIN,
                503,
                CLOSE_TERRAIN_FIRST_PIXEL_INDEX as u32,
            ),
            0x0081
        );
        assert_eq!(
            direct_required_sampler_mask(
                PENDING_DRAW_CLOSE_TERRAIN,
                558,
                (CLOSE_TERRAIN_FIRST_PIXEL_INDEX + 55) as u32,
            ),
            0x3FFF
        );
        assert_eq!(
            direct_required_sampler_mask(PENDING_DRAW_LAND_LOD, 0, 0),
            required
        );
        assert_eq!(
            direct_required_sampler_mask(PENDING_DRAW_TERRAIN_FADE, 0, 0),
            required_sampler_mask(TERRAIN_FADE_SAMPLERS)
        );
        assert_eq!(
            direct_sampler_change(required, 0, 0, true),
            DirectSamplerChange::Keep
        );
        assert_eq!(
            direct_sampler_change(required, 0, 3, true),
            DirectSamplerChange::Ignore
        );
        assert_eq!(
            direct_sampler_change(required, 0, 4, false),
            DirectSamplerChange::Missing(1 << 4)
        );
        assert_eq!(
            direct_sampler_change(required, 1 << 4, 4, false),
            DirectSamplerChange::Keep
        );
        assert_eq!(
            direct_sampler_change(required, 1 << 4, 4, true),
            DirectSamplerChange::Recovered(0)
        );
        assert_eq!(
            direct_sampler_change(required, (1 << 4) | (1 << 6), 4, true),
            DirectSamplerChange::Recovered(1 << 6)
        );

        let source = include_str!("hooks.rs");
        let hook = source
            .split("unsafe extern \"thiscall\" fn hook_set_texture")
            .nth(1)
            .and_then(|tail| tail.split("fn try_prepare_object_replacement").next())
            .expect("SetTexture hook source");
        assert!(!hook.contains("fetch_add"));
        assert!(!hook.contains("TEXTURE_BIND_GENERATION"));
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
        assert!(bind.contains("pair_still_owns_native_wrappers"));
        assert_eq!(bind.matches("diagnostics::detailed_enabled()").count(), 1);
        assert!(bind.contains(".then(|| try_prepare_object_replacement(pass_index))"));
        assert!(!bind.contains("engine_contracts::shader_handle("));
    }

    #[test]
    fn non_terrain_admitted_draw_paths_do_not_mutate_raw_shader_state() {
        let source = include_str!("hooks.rs");
        for (start, end) in [
            (
                "fn bind_land_lod_replacement",
                "fn bind_terrain_fade_replacement",
            ),
            (
                "fn bind_terrain_fade_replacement",
                "fn bind_close_terrain_replacement",
            ),
            (
                "fn bind_object_replacement",
                "fn record_object_bind_failure",
            ),
        ] {
            let body = source
                .split_once(start)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once(end))
                .map(|(body, _)| body)
                .expect("admitted draw path");
            assert!(!body.contains("set_raw_vertex_shader"), "{start}");
            assert!(!body.contains("set_raw_pixel_shader"), "{start}");
        }
    }

    #[test]
    fn supplemental_shader_changes_only_when_payload_mode_changes() {
        let mut active = false;
        let mut transitions = 0;
        for requested in [false, true, true, false, false] {
            if supplemental_shader_transition_needed(active, requested) {
                transitions += 1;
                active = requested;
            }
        }
        assert_eq!(transitions, 2);

        let source = include_str!("hooks.rs");
        let select = source
            .split_once("fn set_close_terrain_supplemental_shader")
            .and_then(|(_, tail)| tail.split_once("fn supplemental_shader_transition_needed"))
            .map(|(body, _)| body)
            .expect("supplemental shader selector");
        assert_eq!(select.matches("set_raw_pixel_shader").count(), 1);
        assert!(select.contains("supplemental_shader_transition_needed"));

        let prepare = source
            .split_once("pub(super) fn prepare_direct_draw")
            .and_then(|(_, tail)| tail.split_once("pub(super) fn finish_direct_draw"))
            .map(|(body, _)| body)
            .expect("direct draw preparation");
        assert!(
            prepare.find("restore_engine_owned_replacement").unwrap()
                < prepare.find("bind_close_terrain_replacement").unwrap(),
            "a prior vanilla fallback must be repaired before supplemental selection"
        );
    }

    #[test]
    fn supplemental_light_texture_is_transactional_at_the_draw_boundary() {
        let source = include_str!("hooks.rs");
        let bind = source
            .split_once("fn bind_close_terrain_replacement")
            .and_then(|(_, tail)| tail.split_once("fn pair_still_owns_native_wrappers"))
            .map(|(body, _)| body)
            .expect("close-terrain bind body");
        let upload = bind
            .find("upload_and_bind_supplemental_light_texture")
            .expect("supplemental texture upload");
        let publish = bind
            .find("PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND.store(true")
            .expect("temporary binding publication");
        let constants = bind
            .find("constants::upload_terrain_constants")
            .expect("terrain constant upload");
        assert!(upload < publish && publish < constants);
        assert!(!bind.contains("record_texture_binding"));
        assert!(!bind.contains("set_sampler_state"));
        assert!(!bind.contains("let mut texels"));

        let restore = source
            .split_once("fn restore_supplemental_light_texture")
            .and_then(|(_, tail)| tail.split_once("fn bind_supplemental_sampler_state"))
            .map(|(body, _)| body)
            .expect("supplemental texture restore");
        assert!(restore.contains("super::samplers::tracked_texture_binding(stage)"));
        assert!(restore.contains("set_raw_base_texture"));
        assert!(restore.contains("clear_texture"));

        assert!(bind.contains("TrackedTextureBinding::Unknown"));

        let sampler = source
            .split_once("fn bind_supplemental_sampler_state")
            .and_then(|(_, tail)| tail.split_once("fn supplemental_sampler_state_is_active"))
            .map(|(body, _)| body)
            .expect("supplemental sampler transaction");
        assert_eq!(sampler.matches("device.sampler_state").count(), 3);
        assert!(sampler.contains("D3DTEXF_POINT"));
        assert!(sampler.contains("D3DSAMP_SRGBTEXTURE"));
        assert!(sampler.contains("fn restore_supplemental_sampler_state"));
        assert!(
            sampler
                .find("PENDING_CLOSE_TERRAIN_SAMPLER_STATE_ACTIVE.store(true")
                .unwrap()
                < sampler.find(".set_sampler_state").unwrap(),
            "sampler rollback ownership must be published before the first D3D mutation"
        );

        let finish = source
            .split_once("pub(super) fn finish_direct_draw")
            .and_then(|(_, tail)| tail.split_once("pub(super) fn finish_draw_batches"))
            .map(|(body, _)| body)
            .expect("direct draw finish");
        assert!(finish.contains("restore_supplemental_light_texture"));

        let release = source
            .split_once("pub(super) fn release_device_resources")
            .and_then(|(_, tail)| tail.split_once("pub(super) fn prepare_direct_draw"))
            .map(|(body, _)| body)
            .expect("resource release body");
        assert!(release.contains("restore_supplemental_light_texture"));
        assert!(!release.contains("PENDING_CLOSE_TERRAIN_LIGHT_TEXTURE_BOUND.store(false"));

        let fallback = source
            .split_once("fn bind_native_fallback")
            .and_then(|(_, tail)| tail.split_once("fn log_land_lod_failure"))
            .map(|(body, _)| body)
            .expect("native fallback body");
        assert!(
            fallback.find("restore_supplemental_light_texture").unwrap()
                < fallback.find("set_raw_vertex_shader").unwrap()
        );
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
                assert!(!variant.native_canopy_row);
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
    fn canopy_companions_cover_every_texture_and_point_light_bucket() {
        for texture_count in 1..=7u32 {
            for (row_offset, point_light_capacity) in [(1usize, 0), (3, 6), (5, 12), (7, 24)] {
                let pixel_index =
                    CLOSE_TERRAIN_FIRST_PIXEL_INDEX + (texture_count as usize - 1) * 8 + row_offset;
                let pass_index = pixel_index as u32 + CLOSE_TERRAIN_PASS_TO_PIXEL_OFFSET;
                let variant = close_terrain_variant(pass_index, pixel_index).unwrap();

                assert_eq!(variant.pixel_index, pixel_index);
                assert_eq!(variant.pixel_sls, 2000 + pixel_index as u16);
                assert_eq!(variant.texture_count, texture_count);
                assert_eq!(variant.point_light_capacity, point_light_capacity);
                assert!(variant.native_canopy_row);
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
    fn canopy_companions_ignore_camera_projected_shadow_samplers() {
        let base = close_terrain_variant(503, CLOSE_TERRAIN_FIRST_PIXEL_INDEX).unwrap();
        let canopy = close_terrain_variant(504, CLOSE_TERRAIN_FIRST_PIXEL_INDEX + 1).unwrap();
        let seven_layer_canopy =
            close_terrain_variant(558, CLOSE_TERRAIN_FIRST_PIXEL_INDEX + 55).unwrap();

        assert_eq!(close_terrain_required_sampler_mask(base), 0x0081);
        assert_eq!(close_terrain_required_sampler_mask(canopy), 0x0081);
        assert_eq!(
            close_terrain_required_sampler_mask(seven_layer_canopy),
            0x3FFF
        );
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
                crate::graphics_diagnostics::add(
                    crate::graphics_diagnostics::Counter::ShaderTablePositiveHit,
                    1,
                );
                return Some(index);
            }
        }
    }

    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::ShaderTableMiss, 1);
    for index in 0..count {
        crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::ShaderTableEntry, 1);
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

fn read_shader_array_slot(base: usize, count: usize, index: usize) -> Option<*mut c_void> {
    if index >= count || !*SHADER_TABLES_READABLE {
        return None;
    }

    let slot = unsafe { (base as *const *mut c_void).add(index) };
    let shader = unsafe { slot.read() };
    (!shader.is_null()).then_some(shader)
}
