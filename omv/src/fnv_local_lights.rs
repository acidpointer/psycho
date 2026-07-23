//! Coherent capture of Fallout New Vegas scene-wide local lights.

use core::{
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::NonNull,
};
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering},
};

use libpsycho::os::windows::{
    directx9::{
        D3DFMT_A8R8G8B8, D3DFMT_R32F, D3DFORMAT, D3DPOOL_DEFAULT, D3DRTYPE_TEXTURE,
        USAGE_RENDER_TARGET, raw_texture_2d_description,
    },
    hook::inline::inlinehook::InlineHookContainer,
    memory::validate_memory_range,
};
use parking_lot::Mutex;

const WORLD_LIGHT_EPOCH_ADDR: usize = 0x0087_1290;
const SHADOW_SCENE_MANAGER_GETTER_ADDR: usize = 0x0045_0B80;
const RENDER_LOCAL_SHADOW_ADDR: usize = 0x00B9_F780;
const LOCAL_LIGHT_CAPACITY: usize = 16;
const TERRAIN_LIGHT_CAPACITY: usize = 64;
const NATIVE_SHADOW_CAPACITY: usize = 4;
const MAX_SCENE_LIGHT_SCAN: usize = 512;

const SHADOW_SCENE_MANAGER_SIZE: usize = 0xC0;
const SCENE_LIGHT_LIST_OFFSET: usize = 0xB4;
const SCENE_LIGHT_COUNT_OFFSET: usize = 0xBC;
const LIST_NODE_NEXT_OFFSET: usize = 0x00;
const LIST_NODE_VALUE_OFFSET: usize = 0x08;

const SHADOW_SCENE_LIGHT_SIZE: usize = 0x112;
const SHADOW_MATRIX_OFFSET: usize = 0x10;
const SHADOW_VIEW_MATRIX_OFFSET: usize = 0x50;
const SHADOW_PROJECTION_MATRIX_OFFSET: usize = 0x90;
const SHADOW_TRANSITION_OFFSET: usize = 0xD0;
const SHADOW_FADE_OFFSET: usize = 0xD4;
const SHADOW_POSITIONAL_OFFSET: usize = 0xF4;
const SHADOW_AMBIENT_OFFSET: usize = 0xF5;
const SHADOW_NATIVE_LIGHT_OFFSET: usize = 0xF8;
const SHADOW_RENDERED_TEXTURE_OFFSET: usize = 0x10C;
const SHADOW_ACTIVE_STATE_OFFSET: usize = 0x110;
const SHADOW_INACTIVE_STATE: u16 = 0x00FF;

const NATIVE_LIGHT_SIZE: usize = 0xE4;
const NATIVE_LIGHT_DISABLED_FLAGS_OFFSET: usize = 0x30;
const NATIVE_LIGHT_POSITION_OFFSET: usize = 0x8C;
const NATIVE_LIGHT_DIMMER_OFFSET: usize = 0xC4;
const NATIVE_LIGHT_COLOR_OFFSET: usize = 0xD4;
const NATIVE_LIGHT_RADIUS_OFFSET: usize = 0xE0;
const LIGHT_COMPONENT_MIN: f32 = 1.0 / 255.0;

const RENDERED_TEXTURE_SIZE: usize = 0x34;
const RENDERED_TEXTURE_TEXTURE_ZERO_OFFSET: usize = 0x30;
const NI_TEXTURE_SIZE: usize = 0x28;
const NI_TEXTURE_RENDERER_DATA_OFFSET: usize = 0x24;
const DX9_TEXTURE_DATA_SIZE: usize = 0x68;
const DX9_TEXTURE_DATA_BASE_TEXTURE_OFFSET: usize = 0x64;
const NI_REF_COUNT_OFFSET: usize = 0x04;
const NI_VTABLE_DELETE_OFFSET: usize = 0x04;
const COM_TEXTURE_VTABLE_BYTES: usize = 0x50;

const MAX_CAPTURE_LOGS: u32 = 16;

type WorldLightEpochFn = unsafe extern "cdecl" fn();
type ShadowSceneManagerGetterFn = unsafe extern "cdecl" fn(i32) -> *mut u8;
type RenderLocalShadowFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, i32);
type DeleteRenderedTextureFn = unsafe extern "thiscall" fn(*mut c_void);

static WORLD_LIGHT_EPOCH_HOOK: LazyLock<InlineHookContainer<WorldLightEpochFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_LOCAL_SHADOW_HOOK: LazyLock<InlineHookContainer<RenderLocalShadowFn>> =
    LazyLock::new(InlineHookContainer::new);

static STAGING: LazyLock<Mutex<StagingEpoch>> =
    LazyLock::new(|| Mutex::new(StagingEpoch::default()));
static PUBLISHED: LazyLock<Mutex<Option<LocalLightEpoch>>> = LazyLock::new(|| Mutex::new(None));
static PUBLISHED_TERRAIN: LazyLock<Mutex<Option<TerrainLightEpoch>>> =
    LazyLock::new(|| Mutex::new(None));

static HOOKS_READY: AtomicBool = AtomicBool::new(false);
static SHADOW_HOOK_READY: AtomicBool = AtomicBool::new(false);
static ATMOSPHERE_CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);
static TERRAIN_CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);
static CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
static DIAGNOSTICS_ACTIVE: AtomicBool = AtomicBool::new(false);

static CAPTURED_LIGHTS: AtomicU32 = AtomicU32::new(0);
static ACCEPTED_LIGHTS: AtomicU32 = AtomicU32::new(0);
static REJECTED_LIGHTS: AtomicU32 = AtomicU32::new(0);
static R32F_LIGHTS: AtomicU32 = AtomicU32::new(0);
static A8_LIGHTS: AtomicU32 = AtomicU32::new(0);
static REJECTED_FORMATS: AtomicU32 = AtomicU32::new(0);
static RENDERED_LIGHTS: AtomicU32 = AtomicU32::new(0);
static STAGING_BUSY: AtomicU32 = AtomicU32::new(0);
static PUBLISH_BUSY: AtomicU32 = AtomicU32::new(0);
static CONSUME_BUSY: AtomicU32 = AtomicU32::new(0);
static RESET_BUSY: AtomicU32 = AtomicU32::new(0);
static CAPTURE_LOGS: AtomicU32 = AtomicU32::new(0);
static CAPTURE_TRAVERSALS: AtomicU32 = AtomicU32::new(0);
static OVERFLOW_LIGHTS: AtomicU32 = AtomicU32::new(0);
static SCENE_LIGHTS: AtomicU32 = AtomicU32::new(0);
static SHADOWED_LIGHTS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShadowTextureFormat {
    R32F,
    A8R8G8B8,
}

impl ShadowTextureFormat {
    pub(crate) fn bias(self) -> f32 {
        match self {
            Self::R32F => 0.001_171_875,
            Self::A8R8G8B8 => 1.0 / 255.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalLightValues {
    pub(crate) position: [f32; 3],
    pub(crate) color: [f32; 3],
    pub(crate) radius: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct TerrainSceneLight {
    pub(crate) native_light_identity: usize,
    pub(crate) point: bool,
    pub(crate) ambient: bool,
    pub(crate) relative_position: [f32; 3],
    pub(crate) radius: f32,
    pub(crate) diffuse: [f32; 3],
    pub(crate) dimmer: f32,
    pub(crate) lod_dimmer: f32,
    pub(crate) fade: f32,
}

#[derive(Clone, Copy)]
struct TerrainLightEpoch {
    render_epoch: u32,
    device_identity: usize,
    lights: [TerrainSceneLight; TERRAIN_LIGHT_CAPACITY],
    count: usize,
}

impl Default for TerrainLightEpoch {
    fn default() -> Self {
        Self {
            render_epoch: 0,
            device_identity: 0,
            lights: [TerrainSceneLight::default(); TERRAIN_LIGHT_CAPACITY],
            count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalShadowValues {
    pub(crate) shadow_matrix: [[f32; 4]; 4],
    #[allow(dead_code)]
    pub(crate) shadow_view_matrix: [[f32; 4]; 4],
    #[allow(dead_code)]
    pub(crate) shadow_projection_matrix: [[f32; 4]; 4],
    pub(crate) format: ShadowTextureFormat,
}

pub(crate) struct LocalVolumetricLight {
    pub(crate) values: LocalLightValues,
    shadow: Option<LocalShadow>,
}

impl LocalVolumetricLight {
    pub(crate) fn shadow_binding(&self, device_identity: usize) -> Option<LocalShadowBinding> {
        let shadow = self.shadow.as_ref()?;
        let texture = unsafe { shadow.texture.resolve_shadow_texture(device_identity)? };
        Some(LocalShadowBinding {
            texture,
            values: shadow.values,
        })
    }

    #[cfg(test)]
    fn has_shadow(&self) -> bool {
        self.shadow.is_some()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LocalShadowBinding {
    pub(crate) texture: *mut c_void,
    pub(crate) values: LocalShadowValues,
}

struct LocalShadow {
    values: LocalShadowValues,
    texture: RetainedRenderedTexture,
}

pub(crate) struct LocalLightEpoch {
    pub(crate) render_epoch: u32,
    pub(crate) device_identity: usize,
    slots: [Option<LocalVolumetricLight>; LOCAL_LIGHT_CAPACITY],
}

impl LocalLightEpoch {
    pub(crate) fn lights(&self) -> impl Iterator<Item = &LocalVolumetricLight> {
        self.slots.iter().filter_map(Option::as_ref)
    }

    pub(crate) fn light_count(&self) -> usize {
        self.lights().count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublishedEpochAccess {
    Busy,
    Empty,
    Ready,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LocalLightTelemetry {
    pub(crate) hooks_ready: bool,
    pub(crate) shadow_hook_ready: bool,
    pub(crate) capture_enabled: bool,
    pub(crate) traversals: u32,
    pub(crate) captured: u32,
    pub(crate) accepted: u32,
    pub(crate) rejected: u32,
    pub(crate) overflow: u32,
    pub(crate) r32f: u32,
    pub(crate) a8r8g8b8: u32,
    pub(crate) rejected_formats: u32,
    pub(crate) rendered: u32,
    pub(crate) staging_busy: u32,
    pub(crate) publish_busy: u32,
    pub(crate) consume_busy: u32,
    pub(crate) reset_busy: u32,
    pub(crate) scene_lights: u32,
    pub(crate) shadowed_lights: u32,
}

#[derive(Default)]
struct StagingEpoch {
    render_epoch: u32,
    device_identity: usize,
    seen_slots: u8,
    shadows: [Option<CapturedShadow>; NATIVE_SHADOW_CAPACITY],
}

struct CapturedShadow {
    native_light_identity: usize,
    shadow: LocalShadow,
}

#[derive(Clone, Copy, Debug)]
struct RankedSceneLight {
    native_light_identity: usize,
    values: LocalLightValues,
    score: f32,
}

#[derive(Clone, Copy, Debug)]
struct RankedTerrainSceneLight {
    light: TerrainSceneLight,
    normalized_distance_squared: Option<f32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureSlot {
    Retained(usize),
    Overflow,
    Invalid,
}

impl StagingEpoch {
    fn begin(&mut self, render_epoch: u32, device_identity: usize) {
        self.shadows = std::array::from_fn(|_| None);
        self.render_epoch = render_epoch;
        self.device_identity = device_identity;
        self.seen_slots = 0;
    }

    fn take_shadows(&mut self) -> [Option<CapturedShadow>; NATIVE_SHADOW_CAPACITY] {
        std::array::from_fn(|index| self.shadows[index].take())
    }

    fn clear(&mut self) {
        self.shadows = std::array::from_fn(|_| None);
        self.render_epoch = 0;
        self.device_identity = 0;
        self.seen_slots = 0;
    }
}

struct RetainedRenderedTexture {
    rendered_texture: NonNull<u8>,
    shadow_texture_identity: usize,
    format: ShadowTextureFormat,
}

// The engine uses interlocked intrusive references. The owner moves only
// between private render mailboxes; texture lookup and final release stay on
// the render/reset path.
unsafe impl Send for RetainedRenderedTexture {}

impl RetainedRenderedTexture {
    unsafe fn retain(
        rendered_texture: *mut u8,
        shadow_texture_identity: usize,
        format: ShadowTextureFormat,
    ) -> Option<Self> {
        validate_memory_range(rendered_texture.cast(), RENDERED_TEXTURE_SIZE).ok()?;
        let rendered_texture = NonNull::new(rendered_texture)?;
        let count = unsafe {
            &*rendered_texture
                .as_ptr()
                .add(NI_REF_COUNT_OFFSET)
                .cast::<AtomicI32>()
        };
        let mut current = count.load(Ordering::Acquire);
        loop {
            if current <= 0 || current == i32::MAX {
                return None;
            }
            match count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        Some(Self {
            rendered_texture,
            shadow_texture_identity,
            format,
        })
    }

    unsafe fn resolve_shadow_texture(&self, device_identity: usize) -> Option<*mut c_void> {
        let resolved = unsafe { resolve_texture_chain(self.rendered_texture.as_ptr())? };
        if resolved.raw_texture as usize != self.shadow_texture_identity
            || resolved.device_identity != device_identity
            || resolved.format != self.format
        {
            return None;
        }
        Some(resolved.raw_texture)
    }
}

impl Drop for RetainedRenderedTexture {
    fn drop(&mut self) {
        unsafe {
            let object = self.rendered_texture.as_ptr();
            let count = &*object.add(NI_REF_COUNT_OFFSET).cast::<AtomicI32>();
            let previous = count.fetch_sub(1, Ordering::SeqCst);
            if previous != 1 {
                debug_assert!(previous > 1, "invalid BSRenderedTexture reference count");
                return;
            }
            let Some(delete_address) = read_virtual(object, NI_VTABLE_DELETE_OFFSET) else {
                return;
            };
            let delete: DeleteRenderedTextureFn = transmute(delete_address);
            delete(object.cast());
        }
    }
}

#[derive(Clone, Copy)]
struct ResolvedTexture {
    raw_texture: *mut c_void,
    device_identity: usize,
    format: ShadowTextureFormat,
}

pub(crate) fn install_hooks() {
    HOOKS_READY.store(false, Ordering::Release);
    SHADOW_HOOK_READY.store(false, Ordering::Release);
    LazyLock::force(&STAGING);
    LazyLock::force(&PUBLISHED);
    LazyLock::force(&PUBLISHED_TERRAIN);

    if let Err(err) = unsafe {
        WORLD_LIGHT_EPOCH_HOOK.init(
            "FNV scene-wide local-light epoch",
            WORLD_LIGHT_EPOCH_ADDR as *mut c_void,
            hook_world_light_epoch,
        )
    } {
        log::warn!(
            "[ATMOSPHERE LOCAL] Scene epoch hook unavailable at 0x{WORLD_LIGHT_EPOCH_ADDR:08X}: {err}"
        );
        return;
    }
    if let Err(err) = WORLD_LIGHT_EPOCH_HOOK.enable() {
        log::warn!("[ATMOSPHERE LOCAL] Scene epoch hook enable failed: {err}");
        return;
    }
    HOOKS_READY.store(true, Ordering::Release);

    if let Err(err) = unsafe {
        RENDER_LOCAL_SHADOW_HOOK.init(
            "FNV completed local shadow slot",
            RENDER_LOCAL_SHADOW_ADDR as *mut c_void,
            hook_render_local_shadow,
        )
    } {
        log::warn!(
            "[ATMOSPHERE LOCAL] Optional shadow-slot hook unavailable at 0x{RENDER_LOCAL_SHADOW_ADDR:08X}; shadowless local volumes remain active: {err}"
        );
        log::info!(
            "[ATMOSPHERE LOCAL] Scene-wide shadowless capture installed at 0x{WORLD_LIGHT_EPOCH_ADDR:08X}"
        );
        return;
    }
    if let Err(err) = RENDER_LOCAL_SHADOW_HOOK.enable() {
        log::warn!(
            "[ATMOSPHERE LOCAL] Optional shadow-slot hook enable failed; shadowless local volumes remain active: {err}"
        );
        return;
    }

    SHADOW_HOOK_READY.store(true, Ordering::Release);
    log::info!(
        "[ATMOSPHERE LOCAL] Scene-wide local-light capture with optional native-shadow enrichment installed at 0x{WORLD_LIGHT_EPOCH_ADDR:08X}/0x{RENDER_LOCAL_SHADOW_ADDR:08X}"
    );
}

pub(crate) fn configure_atmosphere(enabled: bool) {
    let previous = ATMOSPHERE_CAPTURE_ENABLED.swap(enabled, Ordering::AcqRel);
    if previous != enabled {
        log::info!(
            "[ATMOSPHERE LOCAL] Volumetric capture {} by the world-effects contract",
            if enabled { "enabled" } else { "disabled" },
        );
    }
}

pub(crate) fn configure_terrain(enabled: bool) {
    let previous = TERRAIN_CAPTURE_ENABLED.swap(enabled, Ordering::AcqRel);
    if previous != enabled {
        log::info!(
            "[PBR TERRAIN LIGHT] Scene-light capture {} by the native-PBR contract",
            if enabled { "enabled" } else { "disabled" },
        );
    }
}

pub(crate) fn capture_enabled() -> bool {
    capture_requested(
        ATMOSPHERE_CAPTURE_ENABLED.load(Ordering::Acquire),
        TERRAIN_CAPTURE_ENABLED.load(Ordering::Acquire),
    )
}

pub(crate) fn atmosphere_capture_enabled() -> bool {
    ATMOSPHERE_CAPTURE_ENABLED.load(Ordering::Acquire)
}

pub(crate) fn set_diagnostics_active(active: bool) {
    if DIAGNOSTICS_ACTIVE.swap(active, Ordering::AcqRel) == active || !active {
        return;
    }
    for counter in [
        &CAPTURED_LIGHTS,
        &ACCEPTED_LIGHTS,
        &R32F_LIGHTS,
        &A8_LIGHTS,
        &RENDERED_LIGHTS,
        &CAPTURE_TRAVERSALS,
        &SCENE_LIGHTS,
        &SHADOWED_LIGHTS,
    ] {
        counter.store(0, Ordering::Release);
    }
}

pub(crate) fn telemetry() -> LocalLightTelemetry {
    LocalLightTelemetry {
        hooks_ready: HOOKS_READY.load(Ordering::Acquire),
        shadow_hook_ready: SHADOW_HOOK_READY.load(Ordering::Acquire),
        // This telemetry is rendered inside the volumetric-lighting menu.
        // Terrain's scalar-only consumer must not impersonate atmosphere
        // capture or make a disabled volumetric toggle report active.
        capture_enabled: atmosphere_capture_enabled(),
        traversals: CAPTURE_TRAVERSALS.load(Ordering::Relaxed),
        captured: CAPTURED_LIGHTS.load(Ordering::Relaxed),
        accepted: ACCEPTED_LIGHTS.load(Ordering::Relaxed),
        rejected: REJECTED_LIGHTS.load(Ordering::Relaxed),
        overflow: OVERFLOW_LIGHTS.load(Ordering::Relaxed),
        r32f: R32F_LIGHTS.load(Ordering::Relaxed),
        a8r8g8b8: A8_LIGHTS.load(Ordering::Relaxed),
        rejected_formats: REJECTED_FORMATS.load(Ordering::Relaxed),
        rendered: RENDERED_LIGHTS.load(Ordering::Relaxed),
        staging_busy: STAGING_BUSY.load(Ordering::Relaxed),
        publish_busy: PUBLISH_BUSY.load(Ordering::Relaxed),
        consume_busy: CONSUME_BUSY.load(Ordering::Relaxed),
        reset_busy: RESET_BUSY.load(Ordering::Relaxed),
        scene_lights: SCENE_LIGHTS.load(Ordering::Relaxed),
        shadowed_lights: SHADOWED_LIGHTS.load(Ordering::Relaxed),
    }
}

pub(crate) fn try_with_current_terrain_lights<T>(
    callback: impl FnOnce(&[TerrainSceneLight]) -> T,
) -> Option<T> {
    let published = PUBLISHED_TERRAIN.try_lock()?;
    let epoch = published.as_ref()?;
    let device_identity = crate::backend::d3d_device_ptr()? as usize;
    if !terrain_epoch_is_current(
        epoch.render_epoch,
        epoch.device_identity,
        crate::hooks::render_epoch(),
        device_identity,
    ) {
        return None;
    }
    Some(callback(&epoch.lights[..epoch.count]))
}

pub(crate) fn record_rendered_lights(count: u32) {
    record_diagnostic(&RENDERED_LIGHTS, count, diagnostics_active());
}

pub(crate) fn try_take_published(
    destination: &mut Option<LocalLightEpoch>,
    device_identity: usize,
) -> PublishedEpochAccess {
    let Some(mut published) = PUBLISHED.try_lock() else {
        CONSUME_BUSY.fetch_add(1, Ordering::Relaxed);
        return PublishedEpochAccess::Busy;
    };
    let Some(epoch) = published.take() else {
        return PublishedEpochAccess::Empty;
    };
    if epoch.device_identity == device_identity {
        *destination = Some(epoch);
        PublishedEpochAccess::Ready
    } else {
        *destination = None;
        PublishedEpochAccess::Empty
    }
}

pub(crate) fn try_release_device_resources_after<F>(device_identity: usize, after: F) -> bool
where
    F: FnOnce() -> bool,
{
    let Some(mut staging) = STAGING.try_lock() else {
        RESET_BUSY.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let Some(mut published) = PUBLISHED.try_lock() else {
        RESET_BUSY.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    if !after() {
        return false;
    }
    if staging.device_identity == 0 || staging.device_identity == device_identity {
        staging.clear();
    }
    if published
        .as_ref()
        .is_some_and(|epoch| epoch.device_identity == device_identity)
    {
        *published = None;
    }
    if let Some(mut terrain) = PUBLISHED_TERRAIN.try_lock() {
        if terrain
            .as_ref()
            .is_some_and(|epoch| epoch.device_identity == device_identity)
        {
            *terrain = None;
        }
    }
    true
}

unsafe extern "cdecl" fn hook_world_light_epoch() {
    let Ok(original) = WORLD_LIGHT_EPOCH_HOOK.original() else {
        log_capture_error("missing original world local-light transaction");
        return;
    };
    if !capture_ready() {
        unsafe { original() };
        try_drain_disabled_publication();
        return;
    }
    let render_epoch = crate::hooks::render_epoch();
    let device_identity = crate::backend::d3d_device_ptr().map_or(0, |device| device as usize);
    if device_identity == 0 {
        unsafe { original() };
        return;
    }
    let atmosphere_capture = ATMOSPHERE_CAPTURE_ENABLED.load(Ordering::Acquire);
    let terrain_capture = TERRAIN_CAPTURE_ENABLED.load(Ordering::Acquire);
    let diagnostics_active = diagnostics_active();
    if atmosphere_capture {
        record_diagnostic(&CAPTURE_TRAVERSALS, 1, diagnostics_active);
    }
    let shadow_capture_started = if shadow_capture_requested(
        atmosphere_capture,
        SHADOW_HOOK_READY.load(Ordering::Acquire),
    ) {
        if let Some(mut staging) = STAGING.try_lock() {
            staging.begin(render_epoch, device_identity);
            CAPTURE_ACTIVE.store(true, Ordering::Release);
            true
        } else {
            STAGING_BUSY.fetch_add(1, Ordering::Relaxed);
            CAPTURE_ACTIVE.store(false, Ordering::Release);
            false
        }
    } else {
        CAPTURE_ACTIVE.store(false, Ordering::Release);
        false
    };

    unsafe { original() };
    CAPTURE_ACTIVE.store(false, Ordering::Release);

    if !capture_ready()
        || crate::backend::d3d_device_ptr().map_or(0, |device| device as usize) != device_identity
    {
        return;
    }
    let shadows = if atmosphere_capture && shadow_capture_started {
        if let Some(mut staging) = STAGING.try_lock() {
            if staging.render_epoch == render_epoch && staging.device_identity == device_identity {
                staging.take_shadows()
            } else {
                std::array::from_fn(|_| None)
            }
        } else {
            STAGING_BUSY.fetch_add(1, Ordering::Relaxed);
            std::array::from_fn(|_| None)
        }
    } else {
        std::array::from_fn(|_| None)
    };
    let camera = capture_requested(atmosphere_capture, terrain_capture)
        .then(|| crate::backend::fnv_world_camera_frame(1, 1))
        .flatten();
    let captured = unsafe {
        capture_scene_lights(
            camera,
            atmosphere_capture,
            terrain_capture,
            diagnostics_active,
        )
    };
    if atmosphere_capture {
        let epoch = build_epoch(
            render_epoch,
            device_identity,
            captured.ranked,
            shadows,
            diagnostics_active,
        );
        if let Some(mut published) = PUBLISHED.try_lock() {
            *published = Some(epoch);
        } else {
            PUBLISH_BUSY.fetch_add(1, Ordering::Relaxed);
        }
    }
    if terrain_capture {
        let terrain_count = captured.terrain_lights.iter().flatten().count();
        let epoch = TerrainLightEpoch {
            render_epoch,
            device_identity,
            lights: std::array::from_fn(|index| {
                captured.terrain_lights[index]
                    .map_or_else(TerrainSceneLight::default, |ranked| ranked.light)
            }),
            count: terrain_count,
        };
        if let Some(mut published) = PUBLISHED_TERRAIN.try_lock() {
            *published = Some(epoch);
        }
    }
}

unsafe extern "thiscall" fn hook_render_local_shadow(
    shadow_scene_light: *mut c_void,
    accumulator: *mut c_void,
    slot: i32,
) {
    let Ok(original) = RENDER_LOCAL_SHADOW_HOOK.original() else {
        log_capture_error("missing original completed shadow-slot function");
        return;
    };
    unsafe { original(shadow_scene_light, accumulator, slot) };
    if !CAPTURE_ACTIVE.load(Ordering::Acquire) || !capture_ready() {
        return;
    }
    let diagnostics_active = diagnostics_active();
    record_diagnostic(&CAPTURED_LIGHTS, 1, diagnostics_active);
    let slot_index = match classify_capture_slot(slot) {
        CaptureSlot::Retained(index) => index,
        CaptureSlot::Overflow => {
            OVERFLOW_LIGHTS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        CaptureSlot::Invalid => {
            return;
        }
    };
    let device_identity = crate::backend::d3d_device_ptr().map_or(0, |device| device as usize);
    let record = unsafe { capture_shadow(shadow_scene_light.cast(), device_identity) };
    let Some(mut staging) = STAGING.try_lock() else {
        STAGING_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let slot_bit = 1u8 << slot_index;
    if staging.seen_slots & slot_bit != 0 || staging.device_identity != device_identity {
        return;
    }
    staging.seen_slots |= slot_bit;
    match record {
        Some(record) => {
            match record.shadow.values.format {
                ShadowTextureFormat::R32F => record_diagnostic(&R32F_LIGHTS, 1, diagnostics_active),
                ShadowTextureFormat::A8R8G8B8 => {
                    record_diagnostic(&A8_LIGHTS, 1, diagnostics_active)
                }
            };
            record_diagnostic(&ACCEPTED_LIGHTS, 1, diagnostics_active);
            staging.shadows[slot_index] = Some(record);
        }
        None => {
            REJECTED_LIGHTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn classify_capture_slot(slot: i32) -> CaptureSlot {
    if slot < 0 {
        CaptureSlot::Invalid
    } else if slot as usize >= NATIVE_SHADOW_CAPACITY {
        CaptureSlot::Overflow
    } else {
        CaptureSlot::Retained(slot as usize)
    }
}

fn capture_ready() -> bool {
    capture_enabled() && HOOKS_READY.load(Ordering::Acquire)
}

fn try_drain_disabled_publication() {
    if capture_enabled() {
        return;
    }
    if let Some(mut staging) = STAGING.try_lock() {
        staging.clear();
    } else {
        STAGING_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Some(mut published) = PUBLISHED.try_lock() {
        *published = None;
    } else {
        PUBLISH_BUSY.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(mut published) = PUBLISHED_TERRAIN.try_lock() {
        *published = None;
    }
}

unsafe fn capture_shadow(
    shadow_scene_light: *mut u8,
    device_identity: usize,
) -> Option<CapturedShadow> {
    if device_identity == 0 {
        return None;
    }
    validate_memory_range(shadow_scene_light.cast(), SHADOW_SCENE_LIGHT_SIZE).ok()?;
    if unsafe { read_at::<u8>(shadow_scene_light, SHADOW_POSITIONAL_OFFSET)? } == 0 {
        return None;
    }
    let native_light =
        unsafe { read_at::<*mut u8>(shadow_scene_light, SHADOW_NATIVE_LIGHT_OFFSET)? };
    validate_memory_range(native_light.cast(), NATIVE_LIGHT_SIZE).ok()?;
    let rendered_texture =
        unsafe { read_at::<*mut u8>(shadow_scene_light, SHADOW_RENDERED_TEXTURE_OFFSET)? };

    let shadow_matrix = unsafe { read_matrix4(shadow_scene_light, SHADOW_MATRIX_OFFSET)? };
    let shadow_view_matrix =
        unsafe { read_matrix4(shadow_scene_light, SHADOW_VIEW_MATRIX_OFFSET)? };
    let shadow_projection_matrix =
        unsafe { read_matrix4(shadow_scene_light, SHADOW_PROJECTION_MATRIX_OFFSET)? };
    let resolved = unsafe { resolve_texture_chain(rendered_texture)? };
    if resolved.device_identity != device_identity {
        return None;
    }
    let texture = unsafe {
        RetainedRenderedTexture::retain(
            rendered_texture,
            resolved.raw_texture as usize,
            resolved.format,
        )?
    };
    Some(CapturedShadow {
        native_light_identity: native_light as usize,
        shadow: LocalShadow {
            values: LocalShadowValues {
                shadow_matrix,
                shadow_view_matrix,
                shadow_projection_matrix,
                format: resolved.format,
            },
            texture,
        },
    })
}

struct SceneLightCapture {
    ranked: [Option<RankedSceneLight>; LOCAL_LIGHT_CAPACITY],
    terrain_lights: [Option<RankedTerrainSceneLight>; TERRAIN_LIGHT_CAPACITY],
}

impl Default for SceneLightCapture {
    fn default() -> Self {
        Self {
            ranked: [None; LOCAL_LIGHT_CAPACITY],
            terrain_lights: [None; TERRAIN_LIGHT_CAPACITY],
        }
    }
}

unsafe fn capture_scene_lights(
    camera: Option<crate::backend::CameraFrame>,
    capture_atmosphere: bool,
    capture_terrain: bool,
    diagnostics_active: bool,
) -> SceneLightCapture {
    let mut capture = SceneLightCapture::default();
    let camera = camera.filter(|camera| camera.world_transform.available);
    let getter: ShadowSceneManagerGetterFn = unsafe { transmute(SHADOW_SCENE_MANAGER_GETTER_ADDR) };
    let manager = unsafe { getter(0) };
    if validate_memory_range(manager.cast(), SHADOW_SCENE_MANAGER_SIZE).is_err() {
        return capture;
    }
    // The engine owns and mutates this chain on the same world-render thread.
    // Validate its manager once; VirtualQuery for every scalar is too costly here.
    let scene_count = unsafe { read_at_unchecked::<u32>(manager, SCENE_LIGHT_COUNT_OFFSET) };
    let scan_capacity = scene_scan_capacity(capture_atmosphere, capture_terrain);
    let scan_count = (scene_count as usize).min(scan_capacity);
    if capture_atmosphere && scene_count as usize > scan_count {
        OVERFLOW_LIGHTS.fetch_add(
            (scene_count as usize - scan_count) as u32,
            Ordering::Relaxed,
        );
    }
    let mut node = unsafe { read_at_unchecked::<*mut u8>(manager, SCENE_LIGHT_LIST_OFFSET) };
    let mut scanned = 0usize;
    while !node.is_null() && scanned < scan_count {
        let next = unsafe { read_at_unchecked::<*mut u8>(node, LIST_NODE_NEXT_OFFSET) };
        let shadow_scene_light =
            unsafe { read_at_unchecked::<*mut u8>(node, LIST_NODE_VALUE_OFFSET) };
        if !shadow_scene_light.is_null() {
            if capture_atmosphere
                && let Some(camera) = camera
                && let Some(light) = unsafe { capture_scene_light(shadow_scene_light, camera) }
            {
                record_diagnostic(&SCENE_LIGHTS, 1, diagnostics_active);
                insert_ranked_light(&mut capture.ranked, light);
            }
            if capture_terrain
                && let Some(light) = unsafe { capture_terrain_scene_light(shadow_scene_light) }
            {
                insert_ranked_terrain_light(&mut capture.terrain_lights, light, camera);
            }
        }
        node = next;
        scanned += 1;
    }
    capture
}

unsafe fn capture_terrain_scene_light(shadow_scene_light: *mut u8) -> Option<TerrainSceneLight> {
    if unsafe { read_at_unchecked::<u16>(shadow_scene_light, SHADOW_ACTIVE_STATE_OFFSET) }
        == SHADOW_INACTIVE_STATE
    {
        return None;
    }
    let native_light =
        unsafe { read_at_unchecked::<*mut u8>(shadow_scene_light, SHADOW_NATIVE_LIGHT_OFFSET) };
    if native_light.is_null()
        || unsafe { read_at_unchecked::<u8>(native_light, NATIVE_LIGHT_DISABLED_FLAGS_OFFSET) } & 1
            != 0
    {
        return None;
    }
    let light = TerrainSceneLight {
        native_light_identity: native_light as usize,
        point: unsafe { read_at_unchecked::<u8>(shadow_scene_light, SHADOW_POSITIONAL_OFFSET) }
            != 0,
        ambient: unsafe { read_at_unchecked::<u8>(shadow_scene_light, SHADOW_AMBIENT_OFFSET) } != 0,
        relative_position: unsafe {
            read_vec3_unchecked(native_light, NATIVE_LIGHT_POSITION_OFFSET)
        },
        radius: unsafe { read_at_unchecked(native_light, NATIVE_LIGHT_RADIUS_OFFSET) },
        diffuse: unsafe { read_vec3_unchecked(native_light, NATIVE_LIGHT_COLOR_OFFSET) },
        dimmer: unsafe { read_at_unchecked(native_light, NATIVE_LIGHT_DIMMER_OFFSET) },
        lod_dimmer: unsafe { read_at_unchecked(shadow_scene_light, SHADOW_TRANSITION_OFFSET) },
        fade: unsafe { read_at_unchecked(shadow_scene_light, SHADOW_FADE_OFFSET) },
    };
    terrain_light_is_eligible(light).then_some(light)
}

fn terrain_light_is_eligible(light: TerrainSceneLight) -> bool {
    light.native_light_identity != 0
        && light.point
        && !light.ambient
        && valid_light_scalars(
            light.relative_position,
            light.diffuse,
            light.dimmer,
            light.lod_dimmer,
            light.radius,
        )
        && light
            .diffuse
            .into_iter()
            .any(|component| component * light.dimmer > LIGHT_COMPONENT_MIN)
}

fn terrain_light_normalized_distance_squared(
    light: TerrainSceneLight,
    camera: Option<crate::backend::CameraFrame>,
) -> Option<f32> {
    // Close terrain is camera-local. Rank by normalized light-sphere distance
    // so a nearby portable light cannot be displaced by manager list order.
    let camera = camera?;
    if !camera.available || !camera.world_transform.available {
        return None;
    }
    let delta = [
        light.relative_position[0] - camera.world_transform.translation[0],
        light.relative_position[1] - camera.world_transform.translation[1],
        light.relative_position[2] - camera.world_transform.translation[2],
    ];
    let distance_squared = dot3(delta, delta);
    let radius_squared = light.radius * light.radius;
    let score = distance_squared / radius_squared;
    score.is_finite().then_some(score)
}

fn insert_ranked_terrain_light(
    ranked: &mut [Option<RankedTerrainSceneLight>; TERRAIN_LIGHT_CAPACITY],
    light: TerrainSceneLight,
    camera: Option<crate::backend::CameraFrame>,
) {
    if ranked
        .iter()
        .flatten()
        .any(|current| current.light.native_light_identity == light.native_light_identity)
    {
        return;
    }
    let candidate = RankedTerrainSceneLight {
        light,
        normalized_distance_squared: terrain_light_normalized_distance_squared(light, camera),
    };
    let insert_at = ranked.iter().position(|current| {
        current.is_none_or(|current| terrain_light_precedes(candidate, current))
    });
    let Some(insert_at) = insert_at else {
        return;
    };
    for index in (insert_at + 1..TERRAIN_LIGHT_CAPACITY).rev() {
        ranked[index] = ranked[index - 1];
    }
    ranked[insert_at] = Some(candidate);
}

fn terrain_light_precedes(
    candidate: RankedTerrainSceneLight,
    current: RankedTerrainSceneLight,
) -> bool {
    match (
        candidate.normalized_distance_squared,
        current.normalized_distance_squared,
    ) {
        (Some(candidate_score), Some(current_score)) => {
            candidate_score < current_score
                || (candidate_score == current_score
                    && candidate.light.native_light_identity < current.light.native_light_identity)
        }
        (Some(_), None) => true,
        (None, Some(_)) | (None, None) => false,
    }
}

unsafe fn capture_scene_light(
    shadow_scene_light: *mut u8,
    camera: crate::backend::CameraFrame,
) -> Option<RankedSceneLight> {
    if unsafe { read_at_unchecked::<u8>(shadow_scene_light, SHADOW_POSITIONAL_OFFSET) } == 0 {
        return None;
    }
    let native_light =
        unsafe { read_at_unchecked::<*mut u8>(shadow_scene_light, SHADOW_NATIVE_LIGHT_OFFSET) };
    if native_light.is_null() {
        return None;
    }
    let position = unsafe { read_vec3_unchecked(native_light, NATIVE_LIGHT_POSITION_OFFSET) };
    let native_color = unsafe { read_vec3_unchecked(native_light, NATIVE_LIGHT_COLOR_OFFSET) };
    let dimmer = unsafe { read_at_unchecked::<f32>(native_light, NATIVE_LIGHT_DIMMER_OFFSET) };
    let transition =
        unsafe { read_at_unchecked::<f32>(shadow_scene_light, SHADOW_TRANSITION_OFFSET) };
    let radius = unsafe { read_at_unchecked::<f32>(native_light, NATIVE_LIGHT_RADIUS_OFFSET) };
    if !valid_light_scalars(position, native_color, dimmer, transition, radius) {
        return None;
    }
    let color = native_color.map(|component| component * dimmer * transition);
    if !color.into_iter().all(f32::is_finite) || color.iter().all(|component| *component <= 0.0) {
        return None;
    }
    let values = LocalLightValues {
        position,
        color,
        radius,
    };
    let score = scene_light_score(values, camera)?;
    Some(RankedSceneLight {
        native_light_identity: native_light as usize,
        values,
        score,
    })
}

fn scene_light_score(values: LocalLightValues, camera: crate::backend::CameraFrame) -> Option<f32> {
    let transform = camera.world_transform;
    if !camera.available || !transform.available {
        return None;
    }
    let delta = [
        values.position[0] - transform.translation[0],
        values.position[1] - transform.translation[1],
        values.position[2] - transform.translation[2],
    ];
    let forward = [
        transform.rotation[0][0],
        transform.rotation[1][0],
        transform.rotation[2][0],
    ];
    let distance_squared = dot3(delta, delta);
    let forward_distance = dot3(delta, forward);
    if !distance_squared.is_finite()
        || !forward_distance.is_finite()
        || forward_distance + values.radius <= 0.0
    {
        return None;
    }
    let luminance = values.color[0] * 0.2126 + values.color[1] * 0.7152 + values.color[2] * 0.0722;
    let radius_squared = values.radius * values.radius;
    let score = luminance * radius_squared / distance_squared.max(radius_squared * 0.0625);
    (score.is_finite() && score > 0.0).then_some(score)
}

fn insert_ranked_light(
    ranked: &mut [Option<RankedSceneLight>; LOCAL_LIGHT_CAPACITY],
    candidate: RankedSceneLight,
) {
    if ranked
        .iter()
        .flatten()
        .any(|light| light.native_light_identity == candidate.native_light_identity)
    {
        return;
    }
    let insert_at = ranked.iter().position(|current| {
        current.is_none_or(|current| {
            candidate.score > current.score
                || (candidate.score == current.score
                    && candidate.native_light_identity < current.native_light_identity)
        })
    });
    let Some(insert_at) = insert_at else {
        return;
    };
    for index in (insert_at + 1..LOCAL_LIGHT_CAPACITY).rev() {
        ranked[index] = ranked[index - 1];
    }
    ranked[insert_at] = Some(candidate);
}

fn build_epoch(
    render_epoch: u32,
    device_identity: usize,
    ranked: [Option<RankedSceneLight>; LOCAL_LIGHT_CAPACITY],
    mut shadows: [Option<CapturedShadow>; NATIVE_SHADOW_CAPACITY],
    diagnostics_active: bool,
) -> LocalLightEpoch {
    let slots = std::array::from_fn(|index| {
        let light = ranked[index]?;
        let matching_shadow = shadows.iter().position(|shadow| {
            shadow
                .as_ref()
                .is_some_and(|shadow| shadow.native_light_identity == light.native_light_identity)
        });
        let shadow =
            matching_shadow.and_then(|index| shadows[index].take().map(|entry| entry.shadow));
        if shadow.is_some() {
            record_diagnostic(&SHADOWED_LIGHTS, 1, diagnostics_active);
        }
        Some(LocalVolumetricLight {
            values: light.values,
            shadow,
        })
    });
    LocalLightEpoch {
        render_epoch,
        device_identity,
        slots,
    }
}

fn capture_requested(atmosphere: bool, terrain: bool) -> bool {
    atmosphere || terrain
}

#[inline]
fn diagnostics_active() -> bool {
    DIAGNOSTICS_ACTIVE.load(Ordering::Relaxed)
}

#[inline]
fn record_diagnostic(counter: &AtomicU32, value: u32, active: bool) {
    if active {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}

fn scene_scan_capacity(atmosphere: bool, terrain: bool) -> usize {
    if atmosphere || terrain {
        MAX_SCENE_LIGHT_SCAN
    } else {
        0
    }
}

fn shadow_capture_requested(atmosphere: bool, shadow_hook_ready: bool) -> bool {
    atmosphere && shadow_hook_ready
}

fn terrain_epoch_is_current(
    published_render_epoch: u32,
    published_device_identity: usize,
    current_render_epoch: u32,
    current_device_identity: usize,
) -> bool {
    published_render_epoch == current_render_epoch
        && published_device_identity != 0
        && published_device_identity == current_device_identity
}

fn dot3(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

unsafe fn read_at_unchecked<T: Copy>(base: *mut u8, offset: usize) -> T {
    unsafe { base.add(offset).cast::<T>().read_unaligned() }
}

unsafe fn read_vec3_unchecked(base: *mut u8, offset: usize) -> [f32; 3] {
    [
        unsafe { read_at_unchecked(base, offset) },
        unsafe { read_at_unchecked(base, offset + 4) },
        unsafe { read_at_unchecked(base, offset + 8) },
    ]
}

unsafe fn resolve_texture_chain(rendered_texture: *mut u8) -> Option<ResolvedTexture> {
    validate_memory_range(rendered_texture.cast(), RENDERED_TEXTURE_SIZE).ok()?;
    let texture =
        unsafe { read_at::<*mut u8>(rendered_texture, RENDERED_TEXTURE_TEXTURE_ZERO_OFFSET)? };
    validate_memory_range(texture.cast(), NI_TEXTURE_SIZE).ok()?;
    let renderer_data = unsafe { read_at::<*mut u8>(texture, NI_TEXTURE_RENDERER_DATA_OFFSET)? };
    validate_memory_range(renderer_data.cast(), DX9_TEXTURE_DATA_SIZE).ok()?;
    let raw_texture =
        unsafe { read_at::<*mut c_void>(renderer_data, DX9_TEXTURE_DATA_BASE_TEXTURE_OFFSET)? };
    validate_com_texture(raw_texture)?;
    let description = unsafe { raw_texture_2d_description(raw_texture).ok()? };
    let desc = description.level_zero;
    if description.level_count != 1
        || desc.Type != D3DRTYPE_TEXTURE
        || desc.Width != 1024
        || desc.Height != 1024
        || desc.Pool != D3DPOOL_DEFAULT
        || desc.Usage & USAGE_RENDER_TARGET == 0
    {
        return None;
    }
    let format = texture_format(desc.Format)?;
    Some(ResolvedTexture {
        raw_texture,
        device_identity: description.device_identity,
        format,
    })
}

fn texture_format(format: D3DFORMAT) -> Option<ShadowTextureFormat> {
    if format == D3DFMT_R32F {
        Some(ShadowTextureFormat::R32F)
    } else if format == D3DFMT_A8R8G8B8 {
        Some(ShadowTextureFormat::A8R8G8B8)
    } else {
        REJECTED_FORMATS.fetch_add(1, Ordering::Relaxed);
        None
    }
}

fn validate_com_texture(texture: *mut c_void) -> Option<()> {
    validate_memory_range(texture.cast_const(), size_of::<usize>()).ok()?;
    let vtable = unsafe { texture.cast::<*const c_void>().read_unaligned() };
    validate_memory_range(vtable, COM_TEXTURE_VTABLE_BYTES).ok()?;
    Some(())
}

unsafe fn read_virtual(object: *mut u8, offset: usize) -> Option<usize> {
    validate_memory_range(object.cast(), size_of::<usize>()).ok()?;
    let vtable = unsafe { object.cast::<*const u8>().read_unaligned() };
    validate_memory_range(unsafe { vtable.add(offset) }.cast(), size_of::<usize>()).ok()?;
    let address = unsafe { vtable.add(offset).cast::<usize>().read_unaligned() };
    (address != 0).then_some(address)
}

unsafe fn read_at<T: Copy>(base: *mut u8, offset: usize) -> Option<T> {
    let address = unsafe { base.add(offset) };
    validate_memory_range(address.cast(), size_of::<T>()).ok()?;
    Some(unsafe { address.cast::<T>().read_unaligned() })
}

unsafe fn read_matrix4(base: *mut u8, offset: usize) -> Option<[[f32; 4]; 4]> {
    let mut matrix = [[0.0f32; 4]; 4];
    for (row_index, row) in matrix.iter_mut().enumerate() {
        for (column_index, value) in row.iter_mut().enumerate() {
            *value = unsafe { read_at(base, offset + (row_index * 4 + column_index) * 4)? };
        }
    }
    matrix
        .iter()
        .flatten()
        .all(|value| value.is_finite())
        .then_some(matrix)
}

fn valid_light_scalars(
    position: [f32; 3],
    color: [f32; 3],
    dimmer: f32,
    transition: f32,
    radius: f32,
) -> bool {
    position.into_iter().all(f32::is_finite)
        && color
            .into_iter()
            .all(|value| value.is_finite() && value >= 0.0)
        && dimmer.is_finite()
        && dimmer >= 0.0
        && transition.is_finite()
        && transition >= 0.0
        && radius.is_finite()
        && radius > 0.0
}

fn log_capture_error(message: &'static str) {
    if CAPTURE_LOGS.fetch_add(1, Ordering::Relaxed) < MAX_CAPTURE_LOGS {
        log::warn!("[ATMOSPHERE LOCAL] {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaptureSlot, LOCAL_LIGHT_CAPACITY, LocalLightEpoch, LocalLightValues,
        NATIVE_LIGHT_COLOR_OFFSET, NATIVE_LIGHT_DIMMER_OFFSET, NATIVE_LIGHT_DISABLED_FLAGS_OFFSET,
        NATIVE_LIGHT_POSITION_OFFSET, NATIVE_LIGHT_RADIUS_OFFSET, NATIVE_LIGHT_SIZE, PUBLISHED,
        PublishedEpochAccess, RankedSceneLight, SHADOW_ACTIVE_STATE_OFFSET, SHADOW_AMBIENT_OFFSET,
        SHADOW_FADE_OFFSET, SHADOW_INACTIVE_STATE, SHADOW_NATIVE_LIGHT_OFFSET,
        SHADOW_POSITIONAL_OFFSET, SHADOW_SCENE_LIGHT_SIZE, SHADOW_TRANSITION_OFFSET,
        ShadowTextureFormat, StagingEpoch, TERRAIN_LIGHT_CAPACITY, TerrainSceneLight, build_epoch,
        capture_requested, capture_terrain_scene_light, classify_capture_slot, insert_ranked_light,
        insert_ranked_terrain_light, record_diagnostic, scene_light_score, scene_scan_capacity,
        shadow_capture_requested, terrain_epoch_is_current, terrain_light_is_eligible,
        try_take_published, valid_light_scalars,
    };
    use crate::backend::{CameraFrame, CameraTransformFrame};
    use parking_lot::Mutex;
    use std::{
        mem::size_of,
        sync::{
            LazyLock,
            atomic::{AtomicU32, Ordering},
        },
    };

    static MAILBOX_TEST: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    unsafe fn write_at<T: Copy>(buffer: &mut [u8], offset: usize, value: T) {
        assert!(offset + size_of::<T>() <= buffer.len());
        unsafe {
            buffer
                .as_mut_ptr()
                .add(offset)
                .cast::<T>()
                .write_unaligned(value)
        };
    }

    fn empty_epoch(render_epoch: u32, device_identity: usize) -> LocalLightEpoch {
        LocalLightEpoch {
            render_epoch,
            device_identity,
            slots: std::array::from_fn(|_| None),
        }
    }

    fn camera() -> CameraFrame {
        CameraFrame {
            near_z: 1.0,
            far_z: 100_000.0,
            aspect_ratio: 16.0 / 9.0,
            frustum_left: -1.0,
            frustum_right: 1.0,
            frustum_bottom: -1.0,
            frustum_top: 1.0,
            world_transform: CameraTransformFrame {
                rotation: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                translation: [0.0; 3],
                scale: 1.0,
                available: true,
            },
            available: true,
        }
    }

    fn ranked(identity: usize, x: f32, intensity: f32) -> RankedSceneLight {
        let values = LocalLightValues {
            position: [x, 0.0, 0.0],
            color: [intensity; 3],
            radius: 128.0,
        };
        RankedSceneLight {
            native_light_identity: identity,
            values,
            score: scene_light_score(values, camera()).expect("visible local light"),
        }
    }

    fn terrain_light(identity: usize, x: f32, radius: f32) -> TerrainSceneLight {
        TerrainSceneLight {
            native_light_identity: identity,
            point: true,
            ambient: false,
            relative_position: [x, 0.0, 0.0],
            radius,
            diffuse: [1.0; 3],
            dimmer: 1.0,
            lod_dimmer: 1.0,
            fade: 1.0,
        }
    }

    #[test]
    fn light_scalar_validation_rejects_every_nonfinite_or_nonphysical_boundary() {
        assert!(valid_light_scalars(
            [1.0, 2.0, 3.0],
            [2.0, 1.0, 0.0],
            1.0,
            0.5,
            256.0,
        ));
        assert!(!valid_light_scalars(
            [f32::NAN, 2.0, 3.0],
            [1.0; 3],
            1.0,
            1.0,
            1.0,
        ));
        assert!(!valid_light_scalars(
            [1.0; 3],
            [-1.0, 1.0, 1.0],
            1.0,
            1.0,
            1.0,
        ));
        assert!(!valid_light_scalars([1.0; 3], [1.0; 3], -1.0, 1.0, 1.0,));
        assert!(!valid_light_scalars([1.0; 3], [1.0; 3], 1.0, -1.0, 1.0,));
        assert!(!valid_light_scalars([1.0; 3], [1.0; 3], 1.0, 1.0, 0.0,));
    }

    #[test]
    fn terrain_consumer_keeps_scene_capture_active_without_volumetric_lighting() {
        assert!(!capture_requested(false, false));
        assert!(capture_requested(true, false));
        assert!(capture_requested(false, true));
        assert!(capture_requested(true, true));

        assert!(!shadow_capture_requested(false, true));
        assert!(!shadow_capture_requested(true, false));
        assert!(shadow_capture_requested(true, true));

        assert_eq!(scene_scan_capacity(false, false), 0);
        assert_eq!(scene_scan_capacity(false, true), 512);
        assert_eq!(scene_scan_capacity(true, false), 512);
        assert_eq!(scene_scan_capacity(true, true), 512);

        let source = include_str!("fnv_local_lights.rs");
        let telemetry = source
            .split("pub(crate) fn telemetry()")
            .nth(1)
            .and_then(|source| {
                source
                    .split("pub(crate) fn try_with_current_terrain_lights")
                    .next()
            })
            .expect("telemetry implementation");
        assert!(telemetry.contains("capture_enabled: atmosphere_capture_enabled()"));
    }

    #[test]
    fn terrain_mailbox_filters_unusable_lights_before_ranking() {
        let valid = terrain_light(0x20000, 1.0, 128.0);
        assert!(terrain_light_is_eligible(valid));

        let mut directional = valid;
        directional.point = false;
        assert!(!terrain_light_is_eligible(directional));

        let mut ambient = valid;
        ambient.ambient = true;
        assert!(!terrain_light_is_eligible(ambient));

        let mut dark = valid;
        dark.diffuse = [0.0; 3];
        assert!(!terrain_light_is_eligible(dark));
    }

    #[test]
    fn terrain_epoch_rejects_stale_frames_and_foreign_devices() {
        assert!(terrain_epoch_is_current(7, 0x1234, 7, 0x1234));
        assert!(!terrain_epoch_is_current(6, 0x1234, 7, 0x1234));
        assert!(!terrain_epoch_is_current(7, 0x5678, 7, 0x1234));
        assert!(!terrain_epoch_is_current(7, 0, 7, 0));
    }

    #[test]
    fn terrain_snapshot_copies_only_active_enabled_scene_light_values() {
        let mut scene_light = [0u8; SHADOW_SCENE_LIGHT_SIZE];
        let mut native_light = [0u8; NATIVE_LIGHT_SIZE];
        unsafe {
            write_at(&mut scene_light, SHADOW_ACTIVE_STATE_OFFSET, 0u16);
            write_at(&mut scene_light, SHADOW_POSITIONAL_OFFSET, 1u8);
            write_at(&mut scene_light, SHADOW_AMBIENT_OFFSET, 0u8);
            write_at(
                &mut scene_light,
                SHADOW_NATIVE_LIGHT_OFFSET,
                native_light.as_mut_ptr(),
            );
            write_at(&mut scene_light, SHADOW_TRANSITION_OFFSET, 0.5f32);
            write_at(&mut scene_light, SHADOW_FADE_OFFSET, 0.75f32);
            write_at(&mut native_light, NATIVE_LIGHT_DISABLED_FLAGS_OFFSET, 0u8);
            write_at(&mut native_light, NATIVE_LIGHT_POSITION_OFFSET, 1.0f32);
            write_at(&mut native_light, NATIVE_LIGHT_POSITION_OFFSET + 4, 2.0f32);
            write_at(&mut native_light, NATIVE_LIGHT_POSITION_OFFSET + 8, 3.0f32);
            write_at(&mut native_light, NATIVE_LIGHT_COLOR_OFFSET, 0.25f32);
            write_at(&mut native_light, NATIVE_LIGHT_COLOR_OFFSET + 4, 0.5f32);
            write_at(&mut native_light, NATIVE_LIGHT_COLOR_OFFSET + 8, 1.0f32);
            write_at(&mut native_light, NATIVE_LIGHT_DIMMER_OFFSET, 2.0f32);
            write_at(&mut native_light, NATIVE_LIGHT_RADIUS_OFFSET, 128.0f32);
        }

        let captured = unsafe { capture_terrain_scene_light(scene_light.as_mut_ptr()) }
            .expect("active point light snapshot");
        assert_eq!(
            captured.native_light_identity,
            native_light.as_ptr() as usize
        );
        assert!(captured.point);
        assert!(!captured.ambient);
        assert_eq!(captured.relative_position, [1.0, 2.0, 3.0]);
        assert_eq!(captured.diffuse, [0.25, 0.5, 1.0]);
        assert_eq!(captured.dimmer, 2.0);
        assert_eq!(captured.lod_dimmer, 0.5);
        assert_eq!(captured.fade, 0.75);
        assert_eq!(captured.radius, 128.0);

        unsafe {
            write_at(
                &mut scene_light,
                SHADOW_ACTIVE_STATE_OFFSET,
                SHADOW_INACTIVE_STATE,
            )
        };
        assert!(unsafe { capture_terrain_scene_light(scene_light.as_mut_ptr()) }.is_none());
        unsafe {
            write_at(&mut scene_light, SHADOW_ACTIVE_STATE_OFFSET, 0u16);
            write_at(&mut native_light, NATIVE_LIGHT_DISABLED_FLAGS_OFFSET, 1u8);
        }
        assert!(unsafe { capture_terrain_scene_light(scene_light.as_mut_ptr()) }.is_none());
    }

    #[test]
    fn ati_shadow_bias_covers_one_red_channel_quantization_step() {
        assert_eq!(ShadowTextureFormat::R32F.bias(), 0.001_171_875);
        assert_eq!(ShadowTextureFormat::A8R8G8B8.bias(), 1.0 / 255.0);
        assert!(ShadowTextureFormat::A8R8G8B8.bias() > ShadowTextureFormat::R32F.bias());
    }

    #[test]
    fn a_new_staging_epoch_clears_slot_identity_without_allocation() {
        let mut staging = StagingEpoch {
            render_epoch: u32::MAX,
            device_identity: 0x1234,
            seen_slots: 0x0f,
            ..StagingEpoch::default()
        };
        staging.begin(0, 0x5678);
        assert_eq!(staging.render_epoch, 0);
        assert_eq!(staging.device_identity, 0x5678);
        assert_eq!(staging.seen_slots, 0);
        assert!(staging.shadows.iter().all(Option::is_none));
    }

    #[test]
    fn native_slots_beyond_the_fixed_budget_are_overflow_not_epoch_corruption() {
        assert_eq!(classify_capture_slot(-1), CaptureSlot::Invalid);
        for slot in 0..4 {
            assert_eq!(
                classify_capture_slot(slot),
                CaptureSlot::Retained(slot as usize)
            );
        }
        assert_eq!(classify_capture_slot(4), CaptureSlot::Overflow);
        assert_eq!(classify_capture_slot(5), CaptureSlot::Overflow);
        assert_eq!(classify_capture_slot(i32::MAX), CaptureSlot::Overflow);
    }

    #[test]
    fn scene_ranking_is_bounded_deterministic_and_rejects_fully_behind_lights() {
        let mut lights = [None; LOCAL_LIGHT_CAPACITY];
        insert_ranked_light(&mut lights, ranked(3, 400.0, 1.0));
        insert_ranked_light(&mut lights, ranked(2, 100.0, 1.0));
        insert_ranked_light(&mut lights, ranked(1, 100.0, 1.0));
        insert_ranked_light(&mut lights, ranked(1, 50.0, 8.0));

        let identities: Vec<_> = lights
            .iter()
            .flatten()
            .map(|light| light.native_light_identity)
            .collect();
        assert_eq!(identities, [1, 2, 3]);
        let behind = LocalLightValues {
            position: [-512.0, 0.0, 0.0],
            color: [1.0; 3],
            radius: 64.0,
        };
        assert!(scene_light_score(behind, camera()).is_none());
    }

    #[test]
    fn terrain_ranking_keeps_a_relevant_light_after_raw_node_sixty_four() {
        let mut lights = [None; TERRAIN_LIGHT_CAPACITY];
        for index in 0..TERRAIN_LIGHT_CAPACITY {
            insert_ranked_terrain_light(
                &mut lights,
                terrain_light(0x20000 + index * 4, 10_000.0 + index as f32, 32.0),
                Some(camera()),
            );
        }
        let omitted_without_full_scan = 0x50000;
        insert_ranked_terrain_light(
            &mut lights,
            terrain_light(omitted_without_full_scan, 1.0, 256.0),
            Some(camera()),
        );

        let identities: Vec<_> = lights
            .iter()
            .flatten()
            .map(|ranked| ranked.light.native_light_identity)
            .collect();
        assert_eq!(identities.len(), TERRAIN_LIGHT_CAPACITY);
        assert_eq!(identities[0], omitted_without_full_scan);
        assert!(!identities.contains(&(0x20000 + (TERRAIN_LIGHT_CAPACITY - 1) * 4)));
    }

    #[test]
    fn zero_native_shadow_slots_still_build_a_complete_visible_light_epoch() {
        let mut lights = [None; LOCAL_LIGHT_CAPACITY];
        insert_ranked_light(&mut lights, ranked(7, 100.0, 2.0));
        let epoch = build_epoch(42, 0x1234, lights, std::array::from_fn(|_| None), false);

        assert_eq!(epoch.render_epoch, 42);
        assert_eq!(epoch.device_identity, 0x1234);
        assert_eq!(epoch.light_count(), 1);
        assert!(!epoch.lights().next().expect("light").has_shadow());
    }

    #[test]
    fn closed_menu_skips_optional_light_telemetry() {
        let counter = AtomicU32::new(0);
        record_diagnostic(&counter, 3, false);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        record_diagnostic(&counter, 3, true);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn busy_consumer_preserves_the_last_complete_epoch_and_empty_publication_replaces_it() {
        let _test = MAILBOX_TEST.lock();
        *PUBLISHED.lock() = None;
        let mut cached = Some(empty_epoch(u32::MAX, 0x1234));
        let published_guard = PUBLISHED.lock();
        assert_eq!(
            try_take_published(&mut cached, 0x1234),
            PublishedEpochAccess::Busy,
        );
        assert_eq!(
            cached.as_ref().map(|epoch| epoch.render_epoch),
            Some(u32::MAX)
        );
        drop(published_guard);

        *PUBLISHED.lock() = Some(empty_epoch(0, 0x1234));
        assert_eq!(
            try_take_published(&mut cached, 0x1234),
            PublishedEpochAccess::Ready,
        );
        let cached = cached.expect("explicit empty epoch remains a complete publication");
        assert_eq!(cached.render_epoch, 0);
        assert_eq!(cached.light_count(), 0);
    }

    #[test]
    fn foreign_device_publication_cannot_leave_a_stale_cached_epoch() {
        let _test = MAILBOX_TEST.lock();
        *PUBLISHED.lock() = Some(empty_epoch(8, 0x5678));
        let mut cached = Some(empty_epoch(7, 0x1234));
        assert_eq!(
            try_take_published(&mut cached, 0x1234),
            PublishedEpochAccess::Empty,
        );
        assert!(cached.is_none());
    }
}
