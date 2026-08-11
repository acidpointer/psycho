//! Coherent capture of Fallout New Vegas scene-wide local lights.
//!
//! The engine's native shadow prefix at `0x00871290` is a receiver-bearing
//! thiscall selected by three mutually exclusive dispatcher branches. A small
//! x86 ABI bridge preserves the incoming `ECX`, records the branch return and
//! caller frame, and invokes one Rust transaction body without changing the
//! native stack contract. Only main-render callers may publish scalar lights;
//! special and screenshot calls execute natively but cannot replace gameplay
//! data in the same presentation epoch.
//!
//! Completed native shadow textures are inspected and retained once through
//! COM. Published consumers borrow that retained identity directly. No later
//! sampler bind walks `BSRenderedTexture -> NiTexture -> NiDX9TextureData`,
//! performs `VirtualQuery`, or asks D3D9 for the resource description again.
//!
//! Terrain consumes scalar data through a post-Deferred render snapshot. The
//! first geometry for a publication version copies the coherent atomic epoch;
//! later geometries borrow ordinary POD from a nonblocking fixed-capacity
//! owner. This prevents up to 64 records from being reconstructed atomically
//! for every terrain draw while preserving the producer's lock-free mailbox.

use core::{
    ffi::c_void,
    mem::{size_of, transmute},
};
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::os::windows::{
    directx9::{
        D3DFMT_A8R8G8B8, D3DFMT_R32F, D3DFORMAT, D3DPOOL_DEFAULT, D3DRTYPE_TEXTURE, Texture9,
        USAGE_RENDER_TARGET, raw_texture_2d_description,
    },
    hook::inline::inlinehook::InlineHookContainer,
    memory::validate_memory_range,
};
use parking_lot::Mutex;

const WORLD_LIGHT_EPOCH_ADDR: usize = 0x0087_1290;
const SHADOW_SCENE_MANAGER_GETTER_ADDR: usize = 0x0045_0B80;
const RENDER_LOCAL_SHADOW_ADDR: usize = 0x00B9_F780;
const WORLD_LIGHT_EPOCH_PROLOGUE: &[u8] = &[0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x9C, 0x00, 0x00, 0x00];
const RENDER_LOCAL_SHADOW_PROLOGUE: &[u8] = &[0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0];
const LOCAL_LIGHT_CAPACITY: usize = 16;
const TERRAIN_LIGHT_CAPACITY: usize = 64;
const NATIVE_SHADOW_CAPACITY: usize = 4;
const MAX_SCENE_LIGHT_SCAN: usize = 512;
const TERRAIN_LIGHT_COMPONENTS_PER_ENTRY: usize = 10;
const TERRAIN_LIGHT_COMPONENT_COUNT: usize =
    TERRAIN_LIGHT_CAPACITY * TERRAIN_LIGHT_COMPONENTS_PER_ENTRY;

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
const COM_TEXTURE_VTABLE_BYTES: usize = 0x50;

const SHADOW_VARIANT_A_RETURN: usize = 0x0087_0856;
const SHADOW_VARIANT_B_RETURN: usize = 0x0087_0A79;
const SHADOW_VARIANT_C_RETURN: usize = 0x0087_0C41;
const MAIN_RENDER_FIRST_RETURN: usize = 0x0087_0249;
const MAIN_RENDER_SECOND_RETURN: usize = 0x0087_02AE;
const SPECIAL_RENDER_RETURN: usize = 0x0087_21A9;
const SCREENSHOT_RENDER_RETURN: usize = 0x0087_9179;

const MAX_CAPTURE_LOGS: u32 = 16;

type WorldLightEpochFn = unsafe extern "thiscall" fn(*mut c_void);
type ShadowSceneManagerGetterFn = unsafe extern "cdecl" fn(i32) -> *mut u8;
type RenderLocalShadowFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, i32);

static WORLD_LIGHT_EPOCH_HOOK: LazyLock<InlineHookContainer<WorldLightEpochFn>> =
    LazyLock::new(InlineHookContainer::new);
static RENDER_LOCAL_SHADOW_HOOK: LazyLock<InlineHookContainer<RenderLocalShadowFn>> =
    LazyLock::new(InlineHookContainer::new);

static STAGING: LazyLock<Mutex<StagingEpoch>> =
    LazyLock::new(|| Mutex::new(StagingEpoch::default()));
static PUBLISHED: LazyLock<Mutex<Option<LocalLightEpoch>>> = LazyLock::new(|| Mutex::new(None));
// Terrain consumers need scalar POD only. An even/odd atomic publication lets
// every geometry copy a stable current epoch without taking the atmosphere
// resource mailbox lock. Odd means a writer owns the payload; an unchanged
// even version before and after copying proves a coherent snapshot.
static TERRAIN_PUBLICATION_VERSION: AtomicU32 = AtomicU32::new(0);
static TERRAIN_PUBLICATION_RENDER_EPOCH: AtomicU32 = AtomicU32::new(0);
static TERRAIN_PUBLICATION_DEVICE: AtomicUsize = AtomicUsize::new(0);
static TERRAIN_PUBLICATION_DEVICE_GENERATION: AtomicU32 = AtomicU32::new(0);
static TERRAIN_PUBLICATION_COUNT: AtomicU32 = AtomicU32::new(0);
static TERRAIN_PUBLICATION_IDENTITIES: [AtomicUsize; TERRAIN_LIGHT_CAPACITY] =
    [const { AtomicUsize::new(0) }; TERRAIN_LIGHT_CAPACITY];
static TERRAIN_PUBLICATION_FLAGS: [AtomicU32; TERRAIN_LIGHT_CAPACITY] =
    [const { AtomicU32::new(0) }; TERRAIN_LIGHT_CAPACITY];
static TERRAIN_PUBLICATION_COMPONENTS: [AtomicU32; TERRAIN_LIGHT_COMPONENT_COUNT] =
    [const { AtomicU32::new(0) }; TERRAIN_LIGHT_COMPONENT_COUNT];
static TERRAIN_RENDER_SNAPSHOT: LazyLock<Mutex<TerrainRenderSnapshot>> =
    LazyLock::new(|| Mutex::new(TerrainRenderSnapshot::default()));

static HOOKS_READY: AtomicBool = AtomicBool::new(false);
static SHADOW_HOOK_READY: AtomicBool = AtomicBool::new(false);
static ATMOSPHERE_CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);
static TERRAIN_CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);
static CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
static PUBLICATION_DRAIN_PENDING: AtomicBool = AtomicBool::new(true);
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
static LAST_AUTHORITATIVE_RENDER_EPOCH: AtomicU32 = AtomicU32::new(0);
static LAST_AUTHORITATIVE_DEVICE_GENERATION: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShadowDispatcherVariant {
    A,
    B,
    C,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShadowRenderContext {
    Main,
    Special,
    Screenshot,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShadowInvocation {
    variant: ShadowDispatcherVariant,
    context: ShadowRenderContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Native local-shadow texture encoding accepted by atmosphere sampling.
pub(crate) enum ShadowTextureFormat {
    /// Single-channel floating-point native shadow target.
    R32F,
    /// Four-channel quantized native shadow target used by the ATI path.
    A8R8G8B8,
}

impl ShadowTextureFormat {
    /// Return the receiver bias required by the native texture encoding.
    pub(crate) fn bias(self) -> f32 {
        match self {
            Self::R32F => 0.001_171_875,
            Self::A8R8G8B8 => 1.0 / 255.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Immutable scalar values for one atmosphere local light.
pub(crate) struct LocalLightValues {
    /// World-space light position.
    pub(crate) position: [f32; 3],
    /// Native diffuse color after dimmer and transition weighting.
    pub(crate) color: [f32; 3],
    /// Native world-space light radius.
    pub(crate) radius: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
/// Scalar manager-light snapshot consumed by close-terrain PBR.
pub(crate) struct TerrainSceneLight {
    /// Stable native-light pointer used only as an identity and deduplication key.
    pub(crate) native_light_identity: usize,
    /// Whether the native shadow-scene entry represents a point light.
    pub(crate) point: bool,
    /// Whether the native entry is ambient and therefore ineligible.
    pub(crate) ambient: bool,
    /// Engine-relative light position copied during the producer epoch.
    pub(crate) relative_position: [f32; 3],
    /// Native light radius.
    pub(crate) radius: f32,
    /// Unscaled native diffuse color.
    pub(crate) diffuse: [f32; 3],
    /// Native light dimmer.
    pub(crate) dimmer: f32,
    /// Shadow-scene LOD transition dimmer.
    pub(crate) lod_dimmer: f32,
    /// Native shadow fade, retained for diagnostics and future consumers.
    pub(crate) fade: f32,
}

/// Fixed render-thread copy of one coherent atomic terrain publication.
///
/// This owner is separate from the atmosphere mailbox because terrain needs
/// scalar POD only and must never retain an engine or COM pointer.
struct TerrainRenderSnapshot {
    valid: bool,
    version: u32,
    render_epoch: u32,
    device_identity: usize,
    device_generation: u32,
    count: usize,
    lights: [TerrainSceneLight; TERRAIN_LIGHT_CAPACITY],
}

impl Default for TerrainRenderSnapshot {
    fn default() -> Self {
        Self {
            valid: false,
            version: 0,
            render_epoch: 0,
            device_identity: 0,
            device_generation: 0,
            count: 0,
            lights: [TerrainSceneLight::default(); TERRAIN_LIGHT_CAPACITY],
        }
    }
}

impl TerrainRenderSnapshot {
    /// Test whether all owners of the copied payload are still exact.
    fn matches(
        &self,
        version: u32,
        render_epoch: u32,
        device_identity: usize,
        device_generation: u32,
    ) -> bool {
        self.valid
            && self.version == version
            && self.render_epoch == render_epoch
            && self.device_identity == device_identity
            && self.device_generation == device_generation
    }
}

#[derive(Clone, Copy, Debug)]
/// Copied matrices and format for one retained completed native shadow.
pub(crate) struct LocalShadowValues {
    /// Combined matrix consumed by the current atmosphere shader.
    pub(crate) shadow_matrix: [[f32; 4]; 4],
    #[allow(dead_code)]
    /// Native shadow view matrix retained as part of the complete contract.
    pub(crate) shadow_view_matrix: [[f32; 4]; 4],
    #[allow(dead_code)]
    /// Native shadow projection matrix retained as part of the complete contract.
    pub(crate) shadow_projection_matrix: [[f32; 4]; 4],
    /// Encoding of the retained native texture.
    pub(crate) format: ShadowTextureFormat,
}

/// One published atmosphere light with optional owned shadow enrichment.
pub(crate) struct LocalVolumetricLight {
    /// Scalar light values copied from engine state.
    pub(crate) values: LocalLightValues,
    shadow: Option<LocalShadow>,
}

impl LocalVolumetricLight {
    /// Borrow the retained native shadow texture for the current D3D device.
    ///
    /// A device mismatch rejects stale reset-era resources without consulting
    /// engine objects or issuing a D3D getter.
    pub(crate) fn shadow_binding(&self, device_identity: usize) -> Option<LocalShadowBinding> {
        let shadow = self.shadow.as_ref()?;
        if shadow.device_identity != device_identity {
            return None;
        }
        Some(LocalShadowBinding {
            texture: shadow.texture.as_raw_base_texture(),
            values: shadow.values,
        })
    }

    #[cfg(test)]
    fn has_shadow(&self) -> bool {
        self.shadow.is_some()
    }
}

#[derive(Clone, Copy)]
/// Borrowed shadow binding valid for one matching device generation.
pub(crate) struct LocalShadowBinding {
    /// Borrowed `IDirect3DBaseTexture9*` kept live by the owning epoch.
    pub(crate) texture: *mut c_void,
    /// Copied native shadow matrices and texture encoding.
    pub(crate) values: LocalShadowValues,
}

struct LocalShadow {
    values: LocalShadowValues,
    texture: Texture9,
    device_identity: usize,
}

/// Immutable gameplay light publication for one render/device epoch.
pub(crate) struct LocalLightEpoch {
    /// Presentation render epoch that produced the publication.
    pub(crate) render_epoch: u32,
    /// Raw device identity whose resources are retained by the publication.
    pub(crate) device_identity: usize,
    /// Device lifecycle generation that owns every retained shadow resource.
    pub(crate) device_generation: u32,
    slots: [Option<LocalVolumetricLight>; LOCAL_LIGHT_CAPACITY],
}

impl LocalLightEpoch {
    /// Iterate the bounded published light set in deterministic rank order.
    pub(crate) fn lights(&self) -> impl Iterator<Item = &LocalVolumetricLight> {
        self.slots.iter().filter_map(Option::as_ref)
    }

    /// Return the number of published atmosphere lights.
    pub(crate) fn light_count(&self) -> usize {
        self.lights().count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Nonblocking atmosphere-mailbox access result.
pub(crate) enum PublishedEpochAccess {
    /// The producer or reset path currently owns the mailbox.
    Busy,
    /// No publication for the requested device was available.
    Empty,
    /// A matching complete publication was moved into the consumer.
    Ready,
}

#[derive(Clone, Copy, Debug, Default)]
/// Bounded local-light counters displayed by OMV diagnostics.
pub(crate) struct LocalLightTelemetry {
    /// Whether the authoritative world transaction hook is resident.
    pub(crate) hooks_ready: bool,
    /// Whether optional completed-shadow enrichment is resident.
    pub(crate) shadow_hook_ready: bool,
    /// Whether atmosphere, rather than scalar-only terrain, requests capture.
    pub(crate) capture_enabled: bool,
    /// Authoritative atmosphere manager traversals.
    pub(crate) traversals: u32,
    /// Native completed-shadow callbacks observed.
    pub(crate) captured: u32,
    /// Native completed shadows accepted and retained.
    pub(crate) accepted: u32,
    /// Native completed shadows rejected by the resource contract.
    pub(crate) rejected: u32,
    /// Completed-shadow slots beyond OMV's fixed retention budget.
    pub(crate) overflow: u32,
    /// Accepted R32F native shadows.
    pub(crate) r32f: u32,
    /// Accepted A8R8G8B8 native shadows.
    pub(crate) a8r8g8b8: u32,
    /// Native shadow resources rejected for unsupported formats.
    pub(crate) rejected_formats: u32,
    /// Local volumes rendered by the atmosphere consumer.
    pub(crate) rendered: u32,
    /// Nonblocking staging-mailbox misses.
    pub(crate) staging_busy: u32,
    /// Nonblocking publication-mailbox misses.
    pub(crate) publish_busy: u32,
    /// Nonblocking consumer-mailbox misses.
    pub(crate) consume_busy: u32,
    /// Reset attempts deferred by a busy light owner.
    pub(crate) reset_busy: u32,
    /// Eligible scalar scene lights observed.
    pub(crate) scene_lights: u32,
    /// Published atmosphere lights matched with retained shadows.
    pub(crate) shadowed_lights: u32,
}

#[derive(Default)]
struct StagingEpoch {
    render_epoch: u32,
    device_identity: usize,
    device_generation: u32,
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
    fn begin(&mut self, render_epoch: u32, device_identity: usize, device_generation: u32) {
        self.shadows = std::array::from_fn(|_| None);
        self.render_epoch = render_epoch;
        self.device_identity = device_identity;
        self.device_generation = device_generation;
        self.seen_slots = 0;
    }

    fn take_shadows(&mut self) -> [Option<CapturedShadow>; NATIVE_SHADOW_CAPACITY] {
        std::array::from_fn(|index| self.shadows[index].take())
    }

    fn clear(&mut self) {
        self.shadows = std::array::from_fn(|_| None);
        self.render_epoch = 0;
        self.device_identity = 0;
        self.device_generation = 0;
        self.seen_slots = 0;
    }
}

#[derive(Clone, Copy)]
struct ResolvedTexture {
    raw_texture: *mut c_void,
    device_identity: usize,
    format: ShadowTextureFormat,
}

/// Install the authoritative scalar-light hook and optional shadow enrichment.
pub(crate) fn install_hooks() {
    HOOKS_READY.store(false, Ordering::Release);
    SHADOW_HOOK_READY.store(false, Ordering::Release);
    LazyLock::force(&STAGING);
    LazyLock::force(&PUBLISHED);
    // Pay the fixed POD snapshot initialization at the established
    // DeferredInit hook-install boundary. First terrain submission must not
    // absorb LazyLock initialization while the player is already rendering.
    LazyLock::force(&TERRAIN_RENDER_SNAPSHOT);

    if !WORLD_LIGHT_EPOCH_HOOK.is_initialized() {
        if !validate_exact_hook_entry(
            WORLD_LIGHT_EPOCH_ADDR,
            WORLD_LIGHT_EPOCH_PROLOGUE,
            "scene-wide local-light epoch",
        ) {
            return;
        }
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
    }
    if !WORLD_LIGHT_EPOCH_HOOK.is_enabled()
        && let Err(err) = WORLD_LIGHT_EPOCH_HOOK.enable()
    {
        log::warn!("[ATMOSPHERE LOCAL] Scene epoch hook enable failed: {err}");
        return;
    }
    HOOKS_READY.store(true, Ordering::Release);

    if !RENDER_LOCAL_SHADOW_HOOK.is_initialized() {
        if !validate_exact_hook_entry(
            RENDER_LOCAL_SHADOW_ADDR,
            RENDER_LOCAL_SHADOW_PROLOGUE,
            "completed local-shadow slot",
        ) {
            log::warn!(
                "[ATMOSPHERE LOCAL] Optional shadow-slot enrichment unavailable; shadowless local volumes remain active"
            );
            return;
        }
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
    }
    if !RENDER_LOCAL_SHADOW_HOOK.is_enabled()
        && let Err(err) = RENDER_LOCAL_SHADOW_HOOK.enable()
    {
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

/// Apply the atmosphere consumer's passive capture demand.
pub(crate) fn configure_atmosphere(enabled: bool) {
    let previous = ATMOSPHERE_CAPTURE_ENABLED.swap(enabled, Ordering::AcqRel);
    if previous != enabled {
        log::info!(
            "[ATMOSPHERE LOCAL] Volumetric capture {} by the world-effects contract",
            if enabled { "enabled" } else { "disabled" },
        );
    }
    if !capture_enabled() {
        PUBLICATION_DRAIN_PENDING.store(true, Ordering::Release);
    }
}

/// Apply close-terrain's passive scalar-light capture demand.
pub(crate) fn configure_terrain(enabled: bool) {
    let previous = TERRAIN_CAPTURE_ENABLED.swap(enabled, Ordering::AcqRel);
    if previous != enabled {
        log::info!(
            "[PBR TERRAIN LIGHT] Scene-light capture {} by the native-PBR contract",
            if enabled { "enabled" } else { "disabled" },
        );
    }
    if !capture_enabled() {
        PUBLICATION_DRAIN_PENDING.store(true, Ordering::Release);
    }
}

/// Return whether any ready consumer requests a scalar manager epoch.
pub(crate) fn capture_enabled() -> bool {
    capture_requested(
        ATMOSPHERE_CAPTURE_ENABLED.load(Ordering::Acquire),
        TERRAIN_CAPTURE_ENABLED.load(Ordering::Acquire),
    )
}

/// Return whether atmosphere requests shadow-enriched light capture.
pub(crate) fn atmosphere_capture_enabled() -> bool {
    ATMOSPHERE_CAPTURE_ENABLED.load(Ordering::Acquire)
}

/// Enable or disable optional menu-facing cumulative telemetry.
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

/// Read the current bounded local-light telemetry snapshot.
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

/// Invoke `callback` with a coherent current scalar-light snapshot.
///
/// Returns `None` rather than blocking when publication is changing or when
/// the render/device generation is stale.
pub(crate) fn try_with_current_terrain_lights<T>(
    callback: impl FnOnce(&[TerrainSceneLight]) -> T,
) -> Option<T> {
    let version = TERRAIN_PUBLICATION_VERSION.load(Ordering::Acquire);
    if version & 1 != 0 {
        return None;
    }
    let device_identity = crate::backend::d3d_device_ptr()? as usize;
    let render_epoch = crate::hooks::render_epoch();
    let device_generation = crate::backend::d3d_device_generation();
    if !terrain_epoch_is_current(
        TERRAIN_PUBLICATION_RENDER_EPOCH.load(Ordering::Relaxed),
        TERRAIN_PUBLICATION_DEVICE.load(Ordering::Relaxed),
        TERRAIN_PUBLICATION_DEVICE_GENERATION.load(Ordering::Relaxed),
        render_epoch,
        device_identity,
        device_generation,
    ) {
        return None;
    }

    let Some(mut snapshot) = TERRAIN_RENDER_SNAPSHOT.try_lock() else {
        return None;
    };
    if snapshot.matches(version, render_epoch, device_identity, device_generation) {
        return Some(callback(&snapshot.lights[..snapshot.count]));
    }

    // Mark the prior snapshot unusable before copying. If the producer changes
    // version during the copy, this draw fails closed and a later draw retries;
    // partially refreshed POD is never exposed to a callback.
    snapshot.valid = false;
    let count =
        (TERRAIN_PUBLICATION_COUNT.load(Ordering::Relaxed) as usize).min(TERRAIN_LIGHT_CAPACITY);
    for (index, light) in snapshot.lights[..count].iter_mut().enumerate() {
        *light = load_terrain_publication_light(index);
    }
    if TERRAIN_PUBLICATION_VERSION.load(Ordering::Acquire) != version {
        return None;
    }
    snapshot.version = version;
    snapshot.render_epoch = render_epoch;
    snapshot.device_identity = device_identity;
    snapshot.device_generation = device_generation;
    snapshot.count = count;
    snapshot.valid = true;
    Some(callback(&snapshot.lights[..count]))
}

/// Return the immutable scalar-light publication generation.
///
/// The value changes only when a complete world-light epoch is published or
/// cleared. It is a cache key, not an invocation counter.
pub(crate) fn terrain_light_generation() -> u32 {
    TERRAIN_PUBLICATION_VERSION.load(Ordering::Acquire)
}

/// Record atmosphere volumes rendered while optional telemetry is active.
pub(crate) fn record_rendered_lights(count: u32) {
    record_diagnostic(&RENDERED_LIGHTS, count, diagnostics_active());
}

/// Move a complete matching atmosphere epoch into `destination` without waiting.
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

/// Release device-owned light resources after an adjacent owner succeeds.
///
/// The callback runs while both nonblocking light mailboxes are exclusively
/// held, making device reset an all-or-nothing resource transition.
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
    clear_terrain_publication();
    true
}

// The target has no stack arguments: ECX is the native receiver and [ESP] is
// the direct branch continuation. EBP still belongs to the branch function at
// entry. Push the three observations as ordinary cdecl arguments, call the
// Rust body, then return with the original stack exactly intact.
#[unsafe(naked)]
unsafe extern "thiscall" fn hook_world_light_epoch(_receiver: *mut c_void) {
    core::arch::naked_asm!(
        "push ebp",
        "mov eax, dword ptr [esp + 4]",
        "push eax",
        "push ecx",
        "call {}",
        "add esp, 12",
        "ret",
        sym hook_world_light_epoch_body,
    );
}

unsafe extern "C" fn hook_world_light_epoch_body(
    receiver: *mut c_void,
    return_address: usize,
    caller_ebp: usize,
) {
    let Ok(original) = WORLD_LIGHT_EPOCH_HOOK.original() else {
        log_capture_error("missing original world local-light transaction");
        return;
    };
    let pre_span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::NativeShadowPreWork,
    );
    let invocation = unsafe { classify_shadow_invocation(return_address, caller_ebp) };
    record_shadow_invocation(invocation);
    if !capture_ready() {
        drop(pre_span);
        unsafe { call_native_shadow_prefix(original, receiver) };
        try_drain_disabled_publication();
        return;
    }
    let render_epoch = crate::hooks::render_epoch();
    let device_generation = crate::backend::d3d_device_generation();
    if !authoritative_shadow_invocation(invocation)
        || (LAST_AUTHORITATIVE_RENDER_EPOCH.load(Ordering::Acquire) == render_epoch
            && LAST_AUTHORITATIVE_DEVICE_GENERATION.load(Ordering::Acquire) == device_generation)
    {
        if invocation.context == ShadowRenderContext::Main {
            crate::graphics_diagnostics::add(
                crate::graphics_diagnostics::Counter::RepeatedLightPublication,
                1,
            );
        }
        drop(pre_span);
        unsafe { call_native_shadow_prefix(original, receiver) };
        return;
    }
    let device_identity = crate::backend::d3d_device_ptr().map_or(0, |device| device as usize);
    if device_identity == 0 {
        drop(pre_span);
        unsafe { call_native_shadow_prefix(original, receiver) };
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
            staging.begin(render_epoch, device_identity, device_generation);
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

    drop(pre_span);
    unsafe { call_native_shadow_prefix(original, receiver) };
    CAPTURE_ACTIVE.store(false, Ordering::Release);

    if !capture_ready()
        || crate::backend::d3d_device_ptr().map_or(0, |device| device as usize) != device_identity
    {
        return;
    }
    let _post_span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::NativeShadowPostWork,
    );
    let shadows = if atmosphere_capture && shadow_capture_started {
        if let Some(mut staging) = STAGING.try_lock() {
            if staging.render_epoch == render_epoch
                && staging.device_identity == device_identity
                && staging.device_generation == device_generation
            {
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
        .then(|| unsafe { crate::backend::fnv_world_camera_frame_fast(1, 1) })
        .flatten();
    let traversal_span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::SceneLightTraversal,
    );
    let captured = unsafe {
        capture_scene_lights(
            camera,
            atmosphere_capture,
            terrain_capture,
            diagnostics_active,
        )
    };
    drop(traversal_span);
    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::SceneLightTraversal, 1);
    let mut publication_complete = true;
    if atmosphere_capture {
        let epoch = build_epoch(
            render_epoch,
            device_identity,
            device_generation,
            captured.ranked,
            shadows,
            diagnostics_active,
        );
        if let Some(mut published) = PUBLISHED.try_lock() {
            *published = Some(epoch);
        } else {
            PUBLISH_BUSY.fetch_add(1, Ordering::Relaxed);
            publication_complete = false;
        }
    }
    if terrain_capture {
        let terrain_count = captured.terrain_lights.iter().flatten().count();
        let lights: [TerrainSceneLight; TERRAIN_LIGHT_CAPACITY] = std::array::from_fn(|index| {
            captured.terrain_lights[index]
                .map_or_else(TerrainSceneLight::default, |ranked| ranked.light)
        });
        if !publish_terrain_lights(
            render_epoch,
            device_identity,
            device_generation,
            &lights[..terrain_count],
        ) {
            publication_complete = false;
        }
    }
    if publication_complete {
        LAST_AUTHORITATIVE_DEVICE_GENERATION.store(device_generation, Ordering::Release);
        LAST_AUTHORITATIVE_RENDER_EPOCH.store(render_epoch, Ordering::Release);
    }
}

unsafe fn call_native_shadow_prefix(original: WorldLightEpochFn, receiver: *mut c_void) {
    let _span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::NativeShadowPrefix,
    );
    unsafe { original(receiver) };
}

unsafe fn classify_shadow_invocation(return_address: usize, caller_ebp: usize) -> ShadowInvocation {
    const MIN_LIVE_POINTER: usize = 0x1_0000;

    let variant = match return_address {
        SHADOW_VARIANT_A_RETURN => ShadowDispatcherVariant::A,
        SHADOW_VARIANT_B_RETURN => ShadowDispatcherVariant::B,
        SHADOW_VARIANT_C_RETURN => ShadowDispatcherVariant::C,
        _ => ShadowDispatcherVariant::Unknown,
    };
    // At the common entry EBP is the selected branch frame. Its saved EBP is
    // the dispatcher frame, whose saved return identifies main, special, or
    // screenshot ownership. Both functions have proven frame-pointer
    // prologues in FalloutNV.exe 1.4.0.525.
    let context = if variant == ShadowDispatcherVariant::Unknown
        || caller_ebp < MIN_LIVE_POINTER
        || caller_ebp & 3 != 0
    {
        // An unknown direct caller has not established the proven EBP chain.
        // Fail closed before dereferencing it instead of trading one avoided
        // VirtualQuery for an unchecked read through an unproven frame.
        ShadowRenderContext::Unknown
    } else {
        let dispatcher_ebp = unsafe { (caller_ebp as *const usize).read() };
        if dispatcher_ebp < MIN_LIVE_POINTER || dispatcher_ebp & 3 != 0 {
            ShadowRenderContext::Unknown
        } else {
            let dispatcher_return =
                unsafe { ((dispatcher_ebp + size_of::<usize>()) as *const usize).read() };
            match dispatcher_return {
                MAIN_RENDER_FIRST_RETURN | MAIN_RENDER_SECOND_RETURN => ShadowRenderContext::Main,
                SPECIAL_RENDER_RETURN => ShadowRenderContext::Special,
                SCREENSHOT_RENDER_RETURN => ShadowRenderContext::Screenshot,
                _ => ShadowRenderContext::Unknown,
            }
        }
    };
    ShadowInvocation { variant, context }
}

fn authoritative_shadow_invocation(invocation: ShadowInvocation) -> bool {
    invocation.context == ShadowRenderContext::Main
        && invocation.variant != ShadowDispatcherVariant::Unknown
}

fn validate_exact_hook_entry(address: usize, expected: &[u8], label: &'static str) -> bool {
    if validate_memory_range(address as *const c_void, expected.len()).is_err() {
        log::warn!("[ATMOSPHERE LOCAL] Cannot read {label} entry at 0x{address:08X}");
        return false;
    }
    let observed = unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) };
    if observed != expected {
        log::warn!(
            "[ATMOSPHERE LOCAL] {label} entry at 0x{address:08X} has unsupported ownership or executable bytes"
        );
        return false;
    }
    true
}

fn record_shadow_invocation(invocation: ShadowInvocation) {
    use crate::graphics_diagnostics::Counter;

    crate::graphics_diagnostics::add(Counter::NativeShadowEntry, 1);
    let variant = match invocation.variant {
        ShadowDispatcherVariant::A => Some(Counter::NativeShadowVariantA),
        ShadowDispatcherVariant::B => Some(Counter::NativeShadowVariantB),
        ShadowDispatcherVariant::C => Some(Counter::NativeShadowVariantC),
        ShadowDispatcherVariant::Unknown => None,
    };
    if let Some(variant) = variant {
        crate::graphics_diagnostics::add(variant, 1);
    }
    let context = match invocation.context {
        ShadowRenderContext::Main => Counter::NativeShadowMain,
        ShadowRenderContext::Special => Counter::NativeShadowSpecial,
        ShadowRenderContext::Screenshot => Counter::NativeShadowScreenshot,
        ShadowRenderContext::Unknown => Counter::NativeShadowUnknownContext,
    };
    crate::graphics_diagnostics::add(context, 1);
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
    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::NativeShadowSlot, 1);
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
            crate::graphics_diagnostics::add(
                crate::graphics_diagnostics::Counter::RetainedNativeShadow,
                1,
            );
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
    if capture_enabled() || !PUBLICATION_DRAIN_PENDING.load(Ordering::Acquire) {
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
        return;
    }
    clear_terrain_publication();
    PUBLICATION_DRAIN_PENDING.store(false, Ordering::Release);
}

unsafe fn capture_shadow(
    shadow_scene_light: *mut u8,
    device_identity: usize,
) -> Option<CapturedShadow> {
    if device_identity == 0 {
        return None;
    }
    validate_memory_range(shadow_scene_light.cast(), SHADOW_SCENE_LIGHT_SIZE).ok()?;
    if unsafe { read_at_unchecked::<u8>(shadow_scene_light, SHADOW_POSITIONAL_OFFSET) } == 0 {
        return None;
    }
    let native_light =
        unsafe { read_at_unchecked::<*mut u8>(shadow_scene_light, SHADOW_NATIVE_LIGHT_OFFSET) };
    validate_memory_range(native_light.cast(), NATIVE_LIGHT_SIZE).ok()?;
    let rendered_texture =
        unsafe { read_at_unchecked::<*mut u8>(shadow_scene_light, SHADOW_RENDERED_TEXTURE_OFFSET) };

    // One whole-record validation above proves all three contiguous matrices.
    // Copy each with one unaligned aggregate load and validate finiteness;
    // the former implementation issued 48 VirtualQuery calls per shadow.
    let shadow_matrix =
        unsafe { read_matrix4_unchecked(shadow_scene_light, SHADOW_MATRIX_OFFSET)? };
    let shadow_view_matrix =
        unsafe { read_matrix4_unchecked(shadow_scene_light, SHADOW_VIEW_MATRIX_OFFSET)? };
    let shadow_projection_matrix =
        unsafe { read_matrix4_unchecked(shadow_scene_light, SHADOW_PROJECTION_MATRIX_OFFSET)? };
    let retention_span = crate::graphics_diagnostics::span(
        crate::graphics_diagnostics::Interval::NativeShadowRetention,
    );
    let resolved = unsafe { resolve_texture_chain(rendered_texture)? };
    if resolved.device_identity != device_identity {
        return None;
    }
    let texture = unsafe { Texture9::retain_raw(resolved.raw_texture).ok()? };
    drop(retention_span);
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
            device_identity,
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
    if (manager as usize) < 0x1_0000 {
        return capture;
    }
    // The engine owns and mutates this chain on the same world-render thread.
    // The exact common-shadow callback proves the manager/list lifetime. Keep
    // the scan equivalent to the engine's own unchecked traversal: querying
    // every manager, node, record, or scalar would reintroduce the hot-path
    // Windows memory traffic this producer exists to remove.
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
    device_generation: u32,
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
        device_generation,
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
    published_device_generation: u32,
    current_render_epoch: u32,
    current_device_identity: usize,
    current_device_generation: u32,
) -> bool {
    published_render_epoch == current_render_epoch
        && published_device_identity != 0
        && published_device_identity == current_device_identity
        && published_device_generation != 0
        && published_device_generation == current_device_generation
}

fn publish_terrain_lights(
    render_epoch: u32,
    device_identity: usize,
    device_generation: u32,
    lights: &[TerrainSceneLight],
) -> bool {
    let version = TERRAIN_PUBLICATION_VERSION.load(Ordering::Acquire);
    if version & 1 != 0
        || TERRAIN_PUBLICATION_VERSION
            .compare_exchange(
                version,
                version.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        return false;
    }

    for (index, light) in lights.iter().take(TERRAIN_LIGHT_CAPACITY).enumerate() {
        TERRAIN_PUBLICATION_IDENTITIES[index].store(light.native_light_identity, Ordering::Relaxed);
        let flags = u32::from(light.point) | (u32::from(light.ambient) << 1);
        TERRAIN_PUBLICATION_FLAGS[index].store(flags, Ordering::Relaxed);
        let components = [
            light.relative_position[0],
            light.relative_position[1],
            light.relative_position[2],
            light.radius,
            light.diffuse[0],
            light.diffuse[1],
            light.diffuse[2],
            light.dimmer,
            light.lod_dimmer,
            light.fade,
        ];
        let base = index * TERRAIN_LIGHT_COMPONENTS_PER_ENTRY;
        for (component, value) in components.into_iter().enumerate() {
            TERRAIN_PUBLICATION_COMPONENTS[base + component]
                .store(value.to_bits(), Ordering::Relaxed);
        }
    }
    TERRAIN_PUBLICATION_COUNT.store(
        lights.len().min(TERRAIN_LIGHT_CAPACITY) as u32,
        Ordering::Relaxed,
    );
    TERRAIN_PUBLICATION_RENDER_EPOCH.store(render_epoch, Ordering::Relaxed);
    TERRAIN_PUBLICATION_DEVICE.store(device_identity, Ordering::Relaxed);
    TERRAIN_PUBLICATION_DEVICE_GENERATION.store(device_generation, Ordering::Relaxed);
    let next = version.wrapping_add(2).max(2);
    TERRAIN_PUBLICATION_VERSION.store(next, Ordering::Release);
    true
}

fn clear_terrain_publication() {
    let _ = publish_terrain_lights(0, 0, 0, &[]);
}

fn load_terrain_publication_light(index: usize) -> TerrainSceneLight {
    let base = index * TERRAIN_LIGHT_COMPONENTS_PER_ENTRY;
    let component = |offset: usize| {
        f32::from_bits(TERRAIN_PUBLICATION_COMPONENTS[base + offset].load(Ordering::Relaxed))
    };
    let flags = TERRAIN_PUBLICATION_FLAGS[index].load(Ordering::Relaxed);
    TerrainSceneLight {
        native_light_identity: TERRAIN_PUBLICATION_IDENTITIES[index].load(Ordering::Relaxed),
        point: flags & 1 != 0,
        ambient: flags & 2 != 0,
        relative_position: [component(0), component(1), component(2)],
        radius: component(3),
        diffuse: [component(4), component(5), component(6)],
        dimmer: component(7),
        lod_dimmer: component(8),
        fade: component(9),
    }
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
    let texture = unsafe {
        read_at_unchecked::<*mut u8>(rendered_texture, RENDERED_TEXTURE_TEXTURE_ZERO_OFFSET)
    };
    validate_memory_range(texture.cast(), NI_TEXTURE_SIZE).ok()?;
    let renderer_data =
        unsafe { read_at_unchecked::<*mut u8>(texture, NI_TEXTURE_RENDERER_DATA_OFFSET) };
    validate_memory_range(renderer_data.cast(), DX9_TEXTURE_DATA_SIZE).ok()?;
    let raw_texture = unsafe {
        read_at_unchecked::<*mut c_void>(renderer_data, DX9_TEXTURE_DATA_BASE_TEXTURE_OFFSET)
    };
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

unsafe fn read_matrix4_unchecked(base: *mut u8, offset: usize) -> Option<[[f32; 4]; 4]> {
    let matrix = unsafe { base.add(offset).cast::<[[f32; 4]; 4]>().read_unaligned() };
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
        MAIN_RENDER_FIRST_RETURN, NATIVE_LIGHT_COLOR_OFFSET, NATIVE_LIGHT_DIMMER_OFFSET,
        NATIVE_LIGHT_DISABLED_FLAGS_OFFSET, NATIVE_LIGHT_POSITION_OFFSET,
        NATIVE_LIGHT_RADIUS_OFFSET, NATIVE_LIGHT_SIZE, PUBLISHED, PublishedEpochAccess,
        RankedSceneLight, RenderLocalShadowFn, SCREENSHOT_RENDER_RETURN,
        SHADOW_ACTIVE_STATE_OFFSET, SHADOW_AMBIENT_OFFSET, SHADOW_FADE_OFFSET,
        SHADOW_INACTIVE_STATE, SHADOW_MATRIX_OFFSET, SHADOW_NATIVE_LIGHT_OFFSET,
        SHADOW_POSITIONAL_OFFSET, SHADOW_SCENE_LIGHT_SIZE, SHADOW_TRANSITION_OFFSET,
        SHADOW_VARIANT_A_RETURN, SPECIAL_RENDER_RETURN, ShadowDispatcherVariant, ShadowInvocation,
        ShadowRenderContext, ShadowTextureFormat, StagingEpoch, TERRAIN_LIGHT_CAPACITY,
        TerrainRenderSnapshot, TerrainSceneLight, WorldLightEpochFn,
        authoritative_shadow_invocation, build_epoch, capture_requested,
        capture_terrain_scene_light, classify_capture_slot, classify_shadow_invocation,
        hook_render_local_shadow, hook_world_light_epoch, insert_ranked_light,
        insert_ranked_terrain_light, read_matrix4_unchecked, record_diagnostic, scene_light_score,
        scene_scan_capacity, shadow_capture_requested, terrain_epoch_is_current,
        terrain_light_is_eligible, try_take_published, valid_light_scalars,
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

    #[test]
    fn shadow_detours_use_the_executable_proven_x86_abis() {
        let _: WorldLightEpochFn = hook_world_light_epoch;
        let _: RenderLocalShadowFn = hook_render_local_shadow;
    }

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
            device_generation: 0,
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

    fn classified_invocation(branch_return: usize, dispatcher_return: usize) -> ShadowInvocation {
        let dispatcher_frame = [0usize, dispatcher_return];
        let branch_frame = [dispatcher_frame.as_ptr() as usize, 0usize];
        unsafe { classify_shadow_invocation(branch_return, branch_frame.as_ptr() as usize) }
    }

    #[test]
    fn shadow_publication_accepts_main_and_rejects_special_and_screenshot_callers() {
        let main = classified_invocation(SHADOW_VARIANT_A_RETURN, MAIN_RENDER_FIRST_RETURN);
        assert_eq!(main.variant, ShadowDispatcherVariant::A);
        assert_eq!(main.context, ShadowRenderContext::Main);
        assert!(authoritative_shadow_invocation(main));

        let special = classified_invocation(SHADOW_VARIANT_A_RETURN, SPECIAL_RENDER_RETURN);
        assert_eq!(special.context, ShadowRenderContext::Special);
        assert!(!authoritative_shadow_invocation(special));

        let screenshot = classified_invocation(SHADOW_VARIANT_A_RETURN, SCREENSHOT_RENDER_RETURN);
        assert_eq!(screenshot.context, ShadowRenderContext::Screenshot);
        assert!(!authoritative_shadow_invocation(screenshot));
        assert!(!authoritative_shadow_invocation(ShadowInvocation {
            variant: ShadowDispatcherVariant::Unknown,
            context: ShadowRenderContext::Main,
        }));
    }

    #[test]
    fn bulk_shadow_matrix_copy_preserves_all_values_and_rejects_nonfinite_data() {
        let mut record = [0u8; SHADOW_SCENE_LIGHT_SIZE];
        for index in 0..16 {
            unsafe {
                write_at(
                    &mut record,
                    SHADOW_MATRIX_OFFSET + index * size_of::<f32>(),
                    index as f32 + 0.25,
                );
            }
        }
        let matrix = unsafe { read_matrix4_unchecked(record.as_mut_ptr(), SHADOW_MATRIX_OFFSET) }
            .expect("finite bulk matrix");
        assert_eq!(matrix[0][0], 0.25);
        assert_eq!(matrix[3][3], 15.25);

        unsafe {
            write_at(
                &mut record,
                SHADOW_MATRIX_OFFSET + 7 * size_of::<f32>(),
                f32::NAN,
            );
        }
        assert!(
            unsafe { read_matrix4_unchecked(record.as_mut_ptr(), SHADOW_MATRIX_OFFSET) }.is_none()
        );
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
        assert!(terrain_epoch_is_current(7, 0x1234, 2, 7, 0x1234, 2));
        assert!(!terrain_epoch_is_current(6, 0x1234, 2, 7, 0x1234, 2));
        assert!(!terrain_epoch_is_current(7, 0x5678, 2, 7, 0x1234, 2));
        assert!(!terrain_epoch_is_current(7, 0x1234, 1, 7, 0x1234, 2));
        assert!(!terrain_epoch_is_current(7, 0, 0, 7, 0, 0));
    }

    #[test]
    fn terrain_render_snapshot_reuses_only_an_exact_publication_epoch() {
        let mut snapshot = TerrainRenderSnapshot::default();
        assert!(!snapshot.matches(8, 11, 0x1234, 2));

        snapshot.valid = true;
        snapshot.version = 8;
        snapshot.render_epoch = 11;
        snapshot.device_identity = 0x1234;
        snapshot.device_generation = 2;
        assert!(snapshot.matches(8, 11, 0x1234, 2));
        assert!(!snapshot.matches(10, 11, 0x1234, 2));
        assert!(!snapshot.matches(8, 12, 0x1234, 2));
        assert!(!snapshot.matches(8, 11, 0x5678, 2));
        assert!(!snapshot.matches(8, 11, 0x1234, 3));

        let source = include_str!("fnv_local_lights.rs");
        let consumer = source
            .split_once("pub(crate) fn try_with_current_terrain_lights")
            .and_then(|(_, tail)| tail.split_once("pub(crate) fn terrain_light_generation"))
            .map(|(body, _)| body)
            .expect("terrain publication consumer");
        assert!(consumer.contains("TERRAIN_RENDER_SNAPSHOT.try_lock()"));
        assert!(
            consumer.find("snapshot.matches").unwrap()
                < consumer.find("load_terrain_publication_light").unwrap(),
            "a cache hit must return before reconstructing atomic light records"
        );
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
        staging.begin(0, 0x5678, 3);
        assert_eq!(staging.render_epoch, 0);
        assert_eq!(staging.device_identity, 0x5678);
        assert_eq!(staging.device_generation, 3);
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
        let epoch = build_epoch(42, 0x1234, 3, lights, std::array::from_fn(|_| None), false);

        assert_eq!(epoch.render_epoch, 42);
        assert_eq!(epoch.device_identity, 0x1234);
        assert_eq!(epoch.device_generation, 3);
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
