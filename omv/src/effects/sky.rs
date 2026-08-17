//! Draw-scoped replacement for the native Fallout NV sky shader family.
//!
//! The engine constants hook identifies a pending sky draw and the resident
//! `NiDX9Renderer::RenderTriShape`/`RenderTriStrips` hooks bind the replacement
//! across the geometry submission that consumes it. Texture admission reads
//! the process-static mirror maintained by the shared engine `SetTexture`
//! observer; it never asks the D3D driver to report current sampler state.
//! Disabling native sky makes both resident engine hooks passive through their
//! atomic gate and releases its D3D shader objects; compiled bytecode remains
//! process-owned for a cheap later rebuild.
//! Resource creation and reset use nonblocking owners at
//! `OnFramePresent`/Recreate; a busy compiler or resource publication is
//! deferred rather than stalling the renderer thread.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    thread,
};

use anyhow::Result;
use libpsycho::os::windows::{
    directx9::{Device9Ref, PixelShader9, VertexShader9},
    hook::pointer::PointerSlotHookContainer,
    memory::validate_memory_range,
};
use parking_lot::Mutex;

const SKY_SELECTOR_CACHE_ADDR: usize = 0x011F9570;
const SKY_UPDATE_CONSTANTS_VTABLE_OFFSET: usize = 0x7C;
const SKY_SHADER_PROPERTY_VTABLE: usize = 0x010B8CE0;
const CURRENT_DRAW_ENTRY_ADDR: usize = 0x011F91E0;
const CURRENT_PASS_ADDR: usize = 0x0126F74C;
const PASS_PIXEL_SHADER_OFFSET: usize = 0x44;
const PASS_VERTEX_SHADER_OFFSET: usize = 0x5C;
const SKY_VERTEX_ARRAY_OFFSET: usize = 0x98;
const SKY_PIXEL_ARRAY_OFFSET: usize = 0xC4;
const SKY_VERTEX_COUNT: usize = 11;
const SKY_PIXEL_COUNT: usize = 8;
const PROPERTY_STATE_SHADE_PROPERTY_OFFSET: usize = 0x0C;
const SKY_PROPERTY_OBJECT_TYPE_OFFSET: usize = 0x8C;
const NID3D_PIXEL_SHADER_VTABLE: usize = 0x010EF7D4;
const NID3D_VERTEX_SHADER_VTABLE: usize = 0x010EF87C;
const PIXEL_SHADER_HANDLE_OFFSET: usize = 0x2C;
const VERTEX_SHADER_HANDLE_OFFSET: usize = 0x34;
const SHADER_BACKUP_HANDLE_OFFSET: usize = 0x1C;
const CONSTANT_FIRST_REGISTER: u32 = 21;
const CREATE_BUDGET_PER_FRAME: usize = 3;
const NO_INDEX: u32 = u32::MAX;

const ATMOSPHERE_VS: &[u8] = include_bytes!("../../shaders/embedded/native_sky_atmosphere.vs.hlsl");
const TEXTURED_VS: &[u8] = include_bytes!("../../shaders/embedded/native_sky_textured.vs.hlsl");
const STARS_VS: &[u8] = include_bytes!("../../shaders/embedded/native_sky_stars.vs.hlsl");
const ATMOSPHERE_PS: &[u8] = include_bytes!("../../shaders/embedded/native_sky_atmosphere.hlsl");
const TEXTURED_PS: &[u8] = include_bytes!("../../shaders/embedded/native_sky_textured.hlsl");
const STARS_PS: &[u8] = include_bytes!("../../shaders/embedded/native_sky_stars.hlsl");

const VS_ATMOSPHERE: usize = 0;
const VS_CELESTIAL: usize = 1;
const VS_MOON_MASK: usize = 2;
const VS_STARS: usize = 3;
const VS_CLOUDS: usize = 4;
const VS_FORWARD_OFFSET: usize = 5;
const PS_ATMOSPHERE: usize = 10;
const PS_CELESTIAL_OTHER: usize = 11;
const PS_CELESTIAL_SUN: usize = 12;
const PS_CELESTIAL_MOON: usize = 13;
const PS_CLOUDS: usize = 14;
const PS_CLOUD_NORMALS: usize = 15;
const PS_STARS: usize = 16;
const SHADER_COUNT: usize = 17;

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSkySettings {
    enabled: bool,
    atmosphere_thickness: f32,
    sun_influence: f32,
    sun_strength: f32,
    glare_strength: f32,
    star_strength: f32,
    star_twinkle: f32,
    cloud_transparency: f32,
    cloud_brightness: f32,
    cloud_normals: bool,
    use_sun_disk_color: bool,
    sunset: [f32; 3],
    sky_multiplier: f32,
}

impl From<crate::config::NativeSkyConfig> for NativeSkySettings {
    fn from(value: crate::config::NativeSkyConfig) -> Self {
        Self {
            enabled: value.enabled,
            atmosphere_thickness: sanitize(value.atmosphere_thickness, 0.7068965, 0.0, 8.0),
            sun_influence: sanitize(value.sun_influence, 1.291271, 0.05, 8.0),
            sun_strength: sanitize(value.sun_strength, 1.517241, 0.0, 8.0),
            glare_strength: sanitize(value.glare_strength, 0.8965517, 0.0, 8.0),
            star_strength: sanitize(value.star_strength, 1.0, 0.0, 8.0),
            star_twinkle: sanitize(value.star_twinkle, 1.0, 0.0, 8.0),
            cloud_transparency: sanitize(value.cloud_transparency, 0.3610992, 0.05, 1.0),
            cloud_brightness: sanitize(value.cloud_brightness, 1.305171, 0.0, 4.0),
            cloud_normals: value.cloud_normals,
            use_sun_disk_color: value.use_sun_disk_color,
            sunset: [
                sanitize(value.sunset_red, 0.5, 0.0, 4.0),
                sanitize(value.sunset_green, 0.0, 0.0, 4.0),
                sanitize(value.sunset_blue, 0.03, 0.0, 4.0),
            ],
            sky_multiplier: sanitize(value.sky_multiplier, 2.043103, 0.0, 4.0),
        }
    }
}

impl NativeSkySettings {
    pub(crate) const fn with_master_enabled(mut self, master_enabled: bool) -> Self {
        self.enabled = self.enabled && master_enabled;
        self
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSkyStatus {
    pub(crate) installed: bool,
    pub(crate) enabled: bool,
    pub(crate) compiled: usize,
    pub(crate) created: usize,
    pub(crate) total: usize,
    pub(crate) failed: bool,
}

/// Engine-slot ownership evidence kept separate from user enablement and GPU
/// resource preparation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSkyInteropStatus {
    pub(crate) constants_ready: bool,
    pub(crate) constants_predecessor: Option<usize>,
}

#[derive(Clone, Copy)]
enum Stage {
    Vertex,
    Pixel,
}

#[derive(Clone, Copy)]
struct ShaderTemplate {
    label: &'static str,
    stage: Stage,
    source: &'static [u8],
    prefix: &'static [u8],
}

const TEMPLATES: [ShaderTemplate; SHADER_COUNT] = [
    ShaderTemplate {
        label: "sky_atmosphere_vs",
        stage: Stage::Vertex,
        source: ATMOSPHERE_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 1\n",
    },
    ShaderTemplate {
        label: "sky_celestial_vs",
        stage: Stage::Vertex,
        source: TEXTURED_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 1\n",
    },
    ShaderTemplate {
        label: "sky_moon_mask_vs",
        stage: Stage::Vertex,
        source: TEXTURED_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 1\n#define OMV_MOON_MASK_VERTEX 1\n",
    },
    ShaderTemplate {
        label: "sky_stars_vs",
        stage: Stage::Vertex,
        source: STARS_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 1\n",
    },
    ShaderTemplate {
        label: "sky_clouds_vs",
        stage: Stage::Vertex,
        source: TEXTURED_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 1\n#define OMV_CLOUD_VERTEX 1\n",
    },
    ShaderTemplate {
        label: "sky_atmosphere_forward_vs",
        stage: Stage::Vertex,
        source: ATMOSPHERE_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 0\n",
    },
    ShaderTemplate {
        label: "sky_celestial_forward_vs",
        stage: Stage::Vertex,
        source: TEXTURED_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 0\n",
    },
    ShaderTemplate {
        label: "sky_moon_mask_forward_vs",
        stage: Stage::Vertex,
        source: TEXTURED_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 0\n#define OMV_MOON_MASK_VERTEX 1\n",
    },
    ShaderTemplate {
        label: "sky_stars_forward_vs",
        stage: Stage::Vertex,
        source: STARS_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 0\n",
    },
    ShaderTemplate {
        label: "sky_clouds_forward_vs",
        stage: Stage::Vertex,
        source: TEXTURED_VS,
        prefix: b"#define OMV_REVERSED_DEPTH 0\n#define OMV_CLOUD_VERTEX 1\n",
    },
    ShaderTemplate {
        label: "sky_atmosphere_ps",
        stage: Stage::Pixel,
        source: ATMOSPHERE_PS,
        prefix: b"",
    },
    ShaderTemplate {
        label: "sky_celestial_other_ps",
        stage: Stage::Pixel,
        source: TEXTURED_PS,
        prefix: b"#define OMV_CELESTIAL 1\n",
    },
    ShaderTemplate {
        label: "sky_celestial_sun_ps",
        stage: Stage::Pixel,
        source: TEXTURED_PS,
        prefix: b"#define OMV_CELESTIAL 1\n#define OMV_CELESTIAL_SUN 1\n",
    },
    ShaderTemplate {
        label: "sky_celestial_moon_ps",
        stage: Stage::Pixel,
        source: TEXTURED_PS,
        prefix: b"#define OMV_CELESTIAL 1\n#define OMV_CELESTIAL_MOON 1\n",
    },
    ShaderTemplate {
        label: "sky_clouds_ps",
        stage: Stage::Pixel,
        source: TEXTURED_PS,
        prefix: b"#define OMV_CELESTIAL 0\n#define OMV_CLOUD_NORMALS 0\n",
    },
    ShaderTemplate {
        label: "sky_cloud_normals_ps",
        stage: Stage::Pixel,
        source: TEXTURED_PS,
        prefix: b"#define OMV_CELESTIAL 0\n#define OMV_CLOUD_NORMALS 1\n",
    },
    ShaderTemplate {
        label: "sky_stars_ps",
        stage: Stage::Pixel,
        source: STARS_PS,
        prefix: b"",
    },
];

type SkyUpdateFn = unsafe extern "thiscall" fn(*mut c_void, *const c_void);

static SETTINGS: LazyLock<Mutex<NativeSkySettings>> =
    LazyLock::new(|| Mutex::new(crate::config::NativeSkyConfig::default().into()));
static UPDATE_HOOK: LazyLock<PointerSlotHookContainer<SkyUpdateFn>> =
    LazyLock::new(PointerSlotHookContainer::new);
static INSTALLED: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
static DRAW_BOUNDARY_READY: AtomicBool = AtomicBool::new(false);
static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FINISHED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static FRAME_EPOCH: AtomicU32 = AtomicU32::new(1);
static BYTECODE: LazyLock<Mutex<Vec<Option<Vec<u32>>>>> =
    LazyLock::new(|| Mutex::new((0..SHADER_COUNT).map(|_| None).collect()));
static RESOURCES: LazyLock<Mutex<ResourceState>> =
    LazyLock::new(|| Mutex::new(ResourceState::new()));
static FRAME_STATE: LazyLock<Mutex<FrameState>> =
    LazyLock::new(|| Mutex::new(FrameState::default()));
static HANDLES: LazyLock<Vec<AtomicUsize>> =
    LazyLock::new(|| (0..SHADER_COUNT).map(|_| AtomicUsize::new(0)).collect());

static PENDING: AtomicBool = AtomicBool::new(false);
static PENDING_EVALUATED: AtomicBool = AtomicBool::new(true);
static PENDING_VERTEX_INDEX: AtomicU32 = AtomicU32::new(NO_INDEX);
static PENDING_PIXEL_INDEX: AtomicU32 = AtomicU32::new(NO_INDEX);
static PENDING_OBJECT_TYPE: AtomicU32 = AtomicU32::new(8);
static PENDING_GEOMETRY: AtomicUsize = AtomicUsize::new(0);
static PENDING_NATIVE_VERTEX: AtomicUsize = AtomicUsize::new(0);
static PENDING_NATIVE_PIXEL: AtomicUsize = AtomicUsize::new(0);
static DIRECT_ACTIVE: AtomicBool = AtomicBool::new(false);
static DIRECT_NATIVE_VERTEX: AtomicUsize = AtomicUsize::new(0);
static DIRECT_NATIVE_PIXEL: AtomicUsize = AtomicUsize::new(0);
static FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

struct ResourceState {
    device: usize,
    device_generation: u32,
    slots: Vec<ResourceSlot>,
}

#[derive(Default)]
struct FrameState {
    epoch: u32,
    resolved: bool,
    prepared: Option<PreparedSkyFrame>,
}

impl FrameState {
    fn clear(&mut self) {
        self.epoch = 0;
        self.resolved = false;
        self.prepared = None;
    }

    fn prepared(&mut self, epoch: u32, settings: NativeSkySettings) -> Option<PreparedSkyFrame> {
        if self.epoch != epoch {
            self.epoch = epoch;
            self.resolved = false;
            self.prepared = None;
        }
        if !self.resolved {
            self.prepared =
                crate::backend::native_sky_frame().map(|frame| prepare_sky_frame(frame, settings));
            self.resolved = true;
        }
        self.prepared
    }
}

#[derive(Clone, Copy)]
struct PreparedSkyFrame {
    reversed_depth: bool,
    constants: [[f32; 4]; 11],
}

impl ResourceState {
    fn new() -> Self {
        Self {
            device: 0,
            device_generation: 0,
            slots: (0..SHADER_COUNT).map(|_| ResourceSlot::default()).collect(),
        }
    }

    fn clear_for_device(&mut self, device: usize, device_generation: u32) {
        self.device = device;
        self.device_generation = device_generation;
        for slot in &mut self.slots {
            *slot = ResourceSlot::default();
        }
    }
}

#[derive(Default)]
struct ResourceSlot {
    vertex: Option<VertexShader9>,
    pixel: Option<PixelShader9>,
    failed: bool,
}

impl ResourceSlot {
    fn ready(&self) -> bool {
        self.vertex.is_some() || self.pixel.is_some()
    }
}

/// Stage native-sky settings and install the resident constants observer.
///
/// The renderer geometry hooks are owned by `crate::hooks`; replacement stays
/// fail-closed until that owner publishes [`set_draw_boundary_ready`].
pub(crate) fn install(settings: NativeSkySettings) -> Result<()> {
    configure_runtime_options(settings);
    if UPDATE_HOOK.is_initialized() {
        ensure_engine_hook_resident();
        return Ok(());
    }

    let slot = match resolve_update_slot() {
        Ok(slot) => slot,
        Err(err) => {
            log::warn!("[SKY] Native sky disabled: {err:#}");
            return Ok(());
        }
    };
    if let Err(err) = unsafe {
        UPDATE_HOOK.init(
            "FNV SkyShader::UpdateConstants",
            slot,
            hook_update_constants,
        )
    } {
        log::warn!("[SKY] Native sky hook initialization failed: {err}");
        return Ok(());
    }
    ensure_engine_hook_resident();
    if settings.enabled {
        start_compile_worker();
    }
    log::info!("[SKY] Native NVR-style sky hook prepared");
    Ok(())
}

/// Apply live native-sky settings at the serialized configuration boundary.
pub(crate) fn configure_runtime_options(settings: NativeSkySettings) {
    let was_enabled = ENABLED.swap(settings.enabled, Ordering::AcqRel);
    *SETTINGS.lock() = settings;
    FRAME_EPOCH.fetch_add(1, Ordering::AcqRel);
    if settings.enabled {
        start_compile_worker();
    } else if was_enabled {
        // Restore any replacement pair before the resident hook becomes
        // passive. Device resources are recreated lazily when the user
        // enables the feature again.
        let _ = reset_runtime_state();
    }
}

fn ensure_engine_hook_resident() {
    if !UPDATE_HOOK.is_initialized() {
        INSTALLED.store(false, Ordering::Release);
        return;
    }
    if UPDATE_HOOK.is_enabled() {
        INSTALLED.store(true, Ordering::Release);
        return;
    }
    match UPDATE_HOOK.enable() {
        Ok(()) => {
            INSTALLED.store(true, Ordering::Release);
            log::info!("[SKY] Resident engine interposition attached");
        }
        Err(err) => {
            INSTALLED.store(UPDATE_HOOK.is_enabled(), Ordering::Release);
            log::warn!("[SKY] Could not attach resident engine interposition: {err}");
        }
    }
}

/// Publish whether both executable-proven renderer geometry hooks are active.
pub(crate) fn set_draw_boundary_ready(ready: bool) {
    DRAW_BOUNDARY_READY.store(ready, Ordering::Release);
}

/// Snapshot native-sky installation, compilation, and device-resource state.
pub(crate) fn runtime_status() -> NativeSkyStatus {
    NativeSkyStatus {
        installed: INSTALLED.load(Ordering::Acquire),
        enabled: ENABLED.load(Ordering::Acquire),
        compiled: BYTECODE
            .try_lock()
            .as_deref()
            .map(|bytecode| bytecode.iter().filter(|entry| entry.is_some()).count())
            .unwrap_or(0),
        created: HANDLES
            .iter()
            .filter(|handle| handle.load(Ordering::Acquire) != 0)
            .count(),
        total: SHADER_COUNT,
        failed: COMPILE_FAILED.load(Ordering::Acquire)
            || RESOURCES
                .try_lock()
                .as_deref()
                .is_some_and(|resources| resources.slots.iter().any(|slot| slot.failed)),
    }
}

pub(crate) fn interoperability_status() -> NativeSkyInteropStatus {
    NativeSkyInteropStatus {
        constants_ready: UPDATE_HOOK.is_enabled(),
        constants_predecessor: UPDATE_HOOK.predecessor_address().ok(),
    }
}

/// Advance sky resource preparation at the serialized presentation boundary.
pub(crate) fn service_present_frame() {
    FRAME_EPOCH.fetch_add(1, Ordering::AcqRel);
    if ENABLED.load(Ordering::Acquire) {
        start_compile_worker();
        create_ready_resources();
    }
}

/// Admit and bind one pending sky replacement before its exact geometry work.
///
/// `UpdateConstants` publishes the consuming geometry from the engine's
/// current pass entry. A different geometry leaves this transaction pending
/// and remains available to PBR. A `true` result owns a draw-local restoration
/// and must be paired with [`finish_direct_draw`] after native submission.
#[must_use]
pub(crate) fn prepare_direct_draw(geometry: *mut c_void) -> bool {
    if !PENDING.load(Ordering::Acquire) {
        return false;
    }
    if geometry.is_null() || PENDING_GEOMETRY.load(Ordering::Acquire) != geometry as usize {
        return false;
    }
    if !ENABLED.load(Ordering::Acquire)
        || !DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        || PENDING_EVALUATED.swap(true, Ordering::AcqRel)
    {
        return false;
    }

    if !try_bind_pending_draw() {
        crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::SkyFallback, 1);
        if !FALLBACK_LOGGED.swap(true, Ordering::AcqRel) {
            log::warn!(
                "[SKY] Sky draw kept vanilla because a replacement contract was unavailable"
            );
        }
    }
    true
}

/// Restore native sky shader ownership after an admitted geometry submission.
pub(crate) fn finish_direct_draw() {
    restore_direct_pair();
    PENDING.store(false, Ordering::Release);
}

/// Release current-device sky resources and clear pending draw ownership.
///
/// A `false` result leaves all publication unchanged so Recreate can abort and
/// retry without waiting or carrying a still-owned shader across native reset.
#[must_use]
pub(crate) fn reset_runtime_state() -> bool {
    let Some(mut resources) = RESOURCES.try_lock() else {
        return false;
    };
    let Some(mut frame_state) = FRAME_STATE.try_lock() else {
        return false;
    };
    restore_direct_pair();
    clear_handles();
    resources.clear_for_device(0, 0);
    frame_state.clear();
    FRAME_EPOCH.fetch_add(1, Ordering::AcqRel);
    clear_pending();
    FIRST_BIND_LOGGED.store(false, Ordering::Release);
    FALLBACK_LOGGED.store(false, Ordering::Release);
    true
}

fn start_compile_worker() {
    if COMPILE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    COMPILE_FINISHED.store(false, Ordering::Release);
    if let Err(err) = thread::Builder::new()
        .name("omv-sky-compile".to_owned())
        .spawn(compile_worker)
    {
        COMPILE_FAILED.store(true, Ordering::Release);
        COMPILE_FINISHED.store(true, Ordering::Release);
        log::warn!("[SKY] Could not start sky compile worker: {err}");
    }
}

fn compile_worker() {
    for (index, template) in TEMPLATES.iter().enumerate() {
        let source = template_source(template);
        let profile = template_profile(template);
        match load_or_compile(template.label, &source, profile) {
            Ok((bytecode, origin)) => {
                BYTECODE.lock()[index] = Some(bytecode);
                log::info!("[SKY] Prepared {} from {origin}", template.label);
            }
            Err(err) => {
                COMPILE_FAILED.store(true, Ordering::Release);
                log::warn!("[SKY] Failed to compile {}: {err:#}", template.label);
            }
        }
    }
    COMPILE_FINISHED.store(true, Ordering::Release);
}

fn template_source(template: &ShaderTemplate) -> Vec<u8> {
    let mut source = Vec::with_capacity(template.prefix.len() + template.source.len());
    source.extend_from_slice(template.prefix);
    source.extend_from_slice(template.source);
    source
}

fn template_profile(template: &ShaderTemplate) -> &'static str {
    match template.stage {
        Stage::Vertex => "vs_3_0",
        Stage::Pixel => "ps_3_0",
    }
}

#[cfg(test)]
mod shader_compile_tests {
    use super::{
        NativeSkySettings, PS_CELESTIAL_MOON, PS_CELESTIAL_OTHER, PS_CELESTIAL_SUN, STARS_PS,
        TEMPLATES, TEXTURED_PS, VS_CELESTIAL, draw_constants, prepare_sky_frame,
        replacement_templates, template_profile, template_source,
    };

    fn compiled_instruction_opcodes(bytecode: &[u32]) -> Vec<u16> {
        const COMMENT: u16 = 0xfffe;
        const END: u16 = 0xffff;

        let mut opcodes = Vec::new();
        let mut offset = 1usize;
        while offset < bytecode.len() {
            let token = bytecode[offset];
            let opcode = token as u16;
            if opcode == END {
                break;
            }
            if opcode == COMMENT {
                offset += 1 + ((token >> 16) & 0x7fff) as usize;
                continue;
            }
            opcodes.push(opcode);
            offset += 1 + ((token >> 24) & 0x0f) as usize;
        }
        assert!(offset < bytecode.len(), "shader bytecode has no END token");
        opcodes
    }

    #[test]
    fn all_native_sky_shader_variants_compile() {
        for template in &TEMPLATES {
            let source = template_source(template);
            crate::shaders::assert_hlsl_compiles(
                template.label,
                &source,
                template_profile(template),
            );
        }
    }

    #[test]
    fn native_sky_shaders_stay_within_static_gpu_budget() {
        for template in &TEMPLATES {
            let source = template_source(template);
            let bytecode = crate::shaders::compile_hlsl_source_target(
                template.label,
                &source,
                template_profile(template),
            )
            .unwrap();
            let opcodes = compiled_instruction_opcodes(&bytecode);
            let texture_count = opcodes.iter().filter(|opcode| **opcode == 66).count();
            let (instruction_limit, texture_limit, byte_limit) = match template.label {
                "sky_atmosphere_vs" | "sky_atmosphere_forward_vs" => (51, 0, 944),
                "sky_celestial_vs"
                | "sky_moon_mask_vs"
                | "sky_celestial_forward_vs"
                | "sky_moon_mask_forward_vs" => (59, 0, 1_052),
                "sky_stars_vs" => (58, 0, 1_128),
                "sky_stars_forward_vs" => (56, 0, 1_104),
                "sky_clouds_vs" | "sky_clouds_forward_vs" => (64, 0, 1_172),
                "sky_atmosphere_ps" => (81, 0, 1_660),
                "sky_celestial_other_ps" => (66, 1, 1_288),
                "sky_celestial_sun_ps" => (65, 1, 1_276),
                "sky_celestial_moon_ps" => (65, 1, 1_228),
                "sky_clouds_ps" => (193, 2, 3_484),
                "sky_cloud_normals_ps" => (254, 2, 4_524),
                "sky_stars_ps" => (188, 1, 3_204),
                label => panic!("missing native-sky GPU budget for {label}"),
            };
            assert!(
                opcodes.len() <= instruction_limit,
                "{} grew to {} instructions (limit {})",
                template.label,
                opcodes.len(),
                instruction_limit
            );
            assert_eq!(
                texture_count, texture_limit,
                "{} texture sample count",
                template.label
            );
            assert!(
                bytecode.len() * 4 <= byte_limit,
                "{} grew to {} bytes (limit {})",
                template.label,
                bytecode.len() * 4,
                byte_limit
            );
        }
    }

    #[test]
    fn star_twinkle_uses_one_temporally_smooth_noise_field() {
        let source = std::str::from_utf8(STARS_PS).unwrap();
        assert_eq!(source.matches("ValueNoise(").count(), 2);
        assert!(source.contains("twinkle *= twinkle * 1.5"));

        let samples = 65_536u32;
        let mut old_mean = 0.0f64;
        let mut new_mean = 0.0f64;
        for index in 0..samples {
            let value = (f64::from(index) + 0.5) / f64::from(samples);
            old_mean += 2.0 * value * 0.5;
            new_mean += 1.5 * value * value;
        }
        old_mean /= f64::from(samples);
        new_mean /= f64::from(samples);
        assert!((new_mean - old_mean).abs() <= 0.000_001);
        assert!(1.5 < 2.0, "the new field must cap pathological star spikes");
    }

    #[test]
    fn celestial_object_kinds_are_compile_time_specialized() {
        let labels = TEMPLATES
            .iter()
            .map(|template| template.label)
            .collect::<Vec<_>>();
        assert!(labels.contains(&"sky_celestial_sun_ps"));
        assert!(labels.contains(&"sky_celestial_moon_ps"));
        assert!(labels.contains(&"sky_celestial_other_ps"));

        let source = std::str::from_utf8(TEXTURED_PS).unwrap();
        assert!(source.contains("OMV_CELESTIAL_SUN"));
        assert!(source.contains("OMV_CELESTIAL_MOON"));
        assert!(!source.contains("float isSun"));
        assert!(!source.contains("float isMoon"));

        let texture = [0.7f32, 0.5, 0.25, 0.8];
        let vertex = [0.6f32, 0.8, 1.0, 0.75];
        let sun_color = [1.0f32, 0.7, 0.4];
        let params_y = 1.2f32;
        let sun_data_y = 0.35f32;
        let sunset_weight = 0.4f32;
        let daylight_gate = 0.9f32;
        for object_type in [0u32, 6, 4] {
            let is_sun = if object_type == 0 { 1.0 } else { 0.0 };
            let is_moon = if object_type == 6 { 1.0 } else { 0.0 };
            let non_sun = std::array::from_fn::<_, 3, _>(|index| {
                texture[index]
                    * vertex[index]
                    * params_y
                    * (sun_data_y + (1.0 - sun_data_y) * is_moon)
            });
            let sun = std::array::from_fn::<_, 3, _>(|index| {
                texture[index] + sun_color[index] * (sunset_weight + sun_data_y)
            });
            let old_rgb = std::array::from_fn::<_, 3, _>(|index| {
                non_sun[index] + (sun[index] - non_sun[index]) * is_sun
            });
            let old_alpha = texture[3] * vertex[3]
                + (texture[3] * daylight_gate - texture[3] * vertex[3]) * is_sun;

            let (specialized_rgb, specialized_alpha) = match object_type {
                0 => (sun, texture[3] * daylight_gate),
                6 => (
                    std::array::from_fn(|index| texture[index] * vertex[index] * params_y),
                    texture[3] * vertex[3],
                ),
                _ => (
                    std::array::from_fn(|index| {
                        texture[index] * vertex[index] * params_y * sun_data_y
                    }),
                    texture[3] * vertex[3],
                ),
            };
            assert_eq!(specialized_rgb, old_rgb);
            assert_eq!(specialized_alpha, old_alpha);
        }

        assert_eq!(
            replacement_templates(1, 1, 0, false, true),
            Some((VS_CELESTIAL, PS_CELESTIAL_SUN))
        );
        assert_eq!(
            replacement_templates(1, 1, 6, false, true),
            Some((VS_CELESTIAL, PS_CELESTIAL_MOON))
        );
        assert_eq!(
            replacement_templates(1, 1, 4, false, true),
            Some((VS_CELESTIAL, PS_CELESTIAL_OTHER))
        );
    }

    #[test]
    fn native_sky_frame_math_is_prepared_once_for_every_object_kind() {
        let settings = NativeSkySettings::from(crate::config::NativeSkyConfig::default());
        let frame = crate::backend::NativeSkyFrame {
            sky_upper: [0.25, 0.5, 0.75],
            sky_lower: [0.1, 0.2, 0.3],
            horizon: [0.4, 0.3, 0.2],
            sun_light: [1.0, 0.8, 0.6],
            sun_disk: [1.0, 0.9, 0.7],
            sun_direction: [0.0, 0.6, 0.8],
            daylight: 0.9,
            game_hour: 17.5,
            is_exterior: true,
            reversed_depth: true,
        };
        let prepared = prepare_sky_frame(frame, settings);
        let atmosphere = draw_constants(prepared.constants, 2);
        let clouds = draw_constants(prepared.constants, 3);

        assert!(prepared.reversed_depth);
        assert_eq!(atmosphere[..10], clouds[..10]);
        assert_eq!(atmosphere[10][1..], clouds[10][1..]);
        assert_eq!(atmosphere[10][0], 2.0);
        assert_eq!(clouds[10][0], 3.0);
    }

    #[test]
    fn master_switch_is_a_runtime_override_not_a_config_mutation() {
        let configured = NativeSkySettings::from(crate::config::NativeSkyConfig::default());
        assert!(configured.enabled);
        assert!(!configured.with_master_enabled(false).enabled);
        assert!(configured.with_master_enabled(true).enabled);
    }

    #[test]
    fn runtime_toggle_never_mutates_the_resident_engine_slot() {
        let source = include_str!("sky.rs");
        let configure = source
            .split_once("pub(crate) fn configure_runtime_options")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("fn ensure_engine_hook_resident"))
            .map(|(body, _)| body)
            .expect("native sky runtime configuration");
        assert!(!configure.contains("ensure_engine_hook_resident()"));
        assert!(!configure.contains("UPDATE_HOOK.enable()"));
        assert!(!configure.contains("UPDATE_HOOK.disable()"));

        let residency = source
            .split_once("fn ensure_engine_hook_resident")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("pub(crate) fn set_draw_boundary_ready"))
            .map(|(body, _)| body)
            .expect("native sky resident hook transition");
        assert!(residency.contains("UPDATE_HOOK.enable()"));
        assert!(!residency.contains("UPDATE_HOOK.disable()"));
    }

    #[test]
    fn native_sky_uses_the_live_selector_slot_not_the_shared_entry() {
        let source = include_str!("sky.rs");
        assert!(source.contains("SKY_SELECTOR_CACHE_ADDR"));
        assert!(source.contains("SKY_UPDATE_CONSTANTS_VTABLE_OFFSET"));
        assert!(source.contains("PointerSlotHookContainer<SkyUpdateFn>"));
        assert!(!source.contains(&["0x00B8", "9D80"].concat()));
        assert!(!source.contains(&["SKY_UPDATE_", "PROLOGUE"].concat()));
    }

    #[test]
    fn native_sky_render_resource_paths_defer_instead_of_waiting() {
        let source = include_str!("sky.rs");
        let create = source
            .split_once("fn create_ready_resources()")
            .and_then(|(_, tail)| {
                tail.split_once("unsafe extern \"thiscall\" fn hook_update_constants")
            })
            .map(|(body, _)| body)
            .expect("native sky resource creation body");
        assert!(create.contains("BYTECODE.try_lock()"));
        assert!(create.contains("RESOURCES.try_lock()"));

        let reset = source
            .split_once("pub(crate) fn reset_runtime_state()")
            .and_then(|(_, tail)| tail.split_once("fn start_compile_worker()"))
            .map(|(body, _)| body)
            .expect("native sky resource reset body");
        assert!(reset.contains("RESOURCES.try_lock()"));
        assert!(reset.contains("FRAME_STATE.try_lock()"));
        assert!(reset.contains("resources.clear_for_device(0, 0)"));
        assert!(!reset.contains("ResourceState::new()"));
    }
}

fn load_or_compile(label: &str, source: &[u8], profile: &str) -> Result<(Vec<u32>, &'static str)> {
    let cached = crate::shaders::load_or_compile_hlsl_cached(
        crate::shaders::HlslCacheSpec {
            namespace: "native_sky",
            family: None,
            cache_label: label,
            source_name: label,
            target: profile,
            cache_tag: profile,
            contract_revision: b"native-sky-v1",
        },
        source,
    )?;
    Ok((cached.bytecode, cached.origin.label()))
}

fn create_ready_resources() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };
    let Some(bytecode) = BYTECODE.try_lock() else {
        return;
    };
    let Some(mut resources) = RESOURCES.try_lock() else {
        return;
    };
    let device_generation = crate::backend::d3d_device_generation();
    if resources.device != device_ptr as usize || resources.device_generation != device_generation {
        clear_handles();
        resources.clear_for_device(device_ptr as usize, device_generation);
    }

    let mut created = 0usize;
    for index in 0..SHADER_COUNT {
        if created >= CREATE_BUDGET_PER_FRAME {
            break;
        }
        if resources.slots[index].ready() || resources.slots[index].failed {
            continue;
        }
        let Some(code) = bytecode[index].as_deref() else {
            continue;
        };
        let result = match TEMPLATES[index].stage {
            Stage::Vertex => device.create_vertex_shader(code).map(|shader| {
                let handle = shader.as_raw();
                resources.slots[index].vertex = Some(shader);
                handle
            }),
            Stage::Pixel => device.create_pixel_shader(code).map(|shader| {
                let handle = shader.as_raw();
                resources.slots[index].pixel = Some(shader);
                handle
            }),
        };
        match result {
            Ok(handle) => {
                HANDLES[index].store(handle as usize, Ordering::Release);
                created += 1;
            }
            Err(_) => {
                resources.slots[index].failed = true;
            }
        }
    }
}

unsafe extern "thiscall" fn hook_update_constants(
    sky_shader: *mut c_void,
    property_state: *const c_void,
) {
    let Ok(original) = UPDATE_HOOK.original() else {
        return;
    };
    unsafe { original(sky_shader, property_state) };

    if !ENABLED.load(Ordering::Acquire) || sky_shader.is_null() || property_state.is_null() {
        return;
    }
    clear_pending();
    let Some(property) = read_ptr_offset(property_state, PROPERTY_STATE_SHADE_PROPERTY_OFFSET)
    else {
        return;
    };
    if read_usize(property).is_none_or(|vtable| vtable != SKY_SHADER_PROPERTY_VTABLE) {
        return;
    }
    let Some(object_type) = read_u32_offset(property, SKY_PROPERTY_OBJECT_TYPE_OFFSET) else {
        return;
    };
    if object_type > 8 {
        return;
    }

    let Some(pass) = read_ptr(CURRENT_PASS_ADDR as *const c_void) else {
        return;
    };
    let Some(vertex_wrapper) = read_ptr_offset(pass, PASS_VERTEX_SHADER_OFFSET) else {
        return;
    };
    let Some(pixel_wrapper) = read_ptr_offset(pass, PASS_PIXEL_SHADER_OFFSET) else {
        return;
    };
    let Some(vertex_index) = find_array_index(
        sky_shader,
        SKY_VERTEX_ARRAY_OFFSET,
        SKY_VERTEX_COUNT,
        vertex_wrapper,
    ) else {
        return;
    };
    let Some(pixel_index) = find_array_index(
        sky_shader,
        SKY_PIXEL_ARRAY_OFFSET,
        SKY_PIXEL_COUNT,
        pixel_wrapper,
    ) else {
        return;
    };
    if !pair_supported_for_object(object_type, vertex_index, pixel_index) {
        return;
    }
    let Some(native_vertex) = shader_handle(vertex_wrapper, Stage::Vertex) else {
        return;
    };
    let Some(native_pixel) = shader_handle(pixel_wrapper, Stage::Pixel) else {
        return;
    };
    let Some(draw_entry) = read_ptr(CURRENT_DRAW_ENTRY_ADDR as *const c_void) else {
        return;
    };
    let Some(geometry) = read_ptr(draw_entry.cast_const()) else {
        return;
    };

    PENDING_VERTEX_INDEX.store(vertex_index as u32, Ordering::Release);
    PENDING_PIXEL_INDEX.store(pixel_index as u32, Ordering::Release);
    PENDING_OBJECT_TYPE.store(object_type, Ordering::Release);
    PENDING_GEOMETRY.store(geometry as usize, Ordering::Release);
    PENDING_NATIVE_VERTEX.store(native_vertex as usize, Ordering::Release);
    PENDING_NATIVE_PIXEL.store(native_pixel as usize, Ordering::Release);
    PENDING_EVALUATED.store(false, Ordering::Release);
    PENDING.store(true, Ordering::Release);
}

fn try_bind_pending_draw() -> bool {
    let _span =
        crate::graphics_diagnostics::span(crate::graphics_diagnostics::Interval::SkyAdmission);
    let vertex_index = PENDING_VERTEX_INDEX.load(Ordering::Acquire) as usize;
    let pixel_index = PENDING_PIXEL_INDEX.load(Ordering::Acquire) as usize;
    let object_type = PENDING_OBJECT_TYPE.load(Ordering::Acquire);
    let Some(settings) = SETTINGS.try_lock().map(|settings| *settings) else {
        return false;
    };
    let Some(mut frame_state) = FRAME_STATE.try_lock() else {
        return false;
    };
    let frame_epoch = FRAME_EPOCH.load(Ordering::Acquire);
    let Some(frame) = frame_state.prepared(frame_epoch, settings) else {
        return false;
    };
    drop(frame_state);
    let Some((vertex_template, pixel_template)) = replacement_templates(
        vertex_index,
        pixel_index,
        object_type,
        settings.cloud_normals,
        frame.reversed_depth,
    ) else {
        return false;
    };
    let Some(replacement_vertex) = shader_resource_handle(vertex_template) else {
        return false;
    };
    let Some(replacement_pixel) = shader_resource_handle(pixel_template) else {
        return false;
    };
    let native_vertex = PENDING_NATIVE_VERTEX.load(Ordering::Acquire) as *mut c_void;
    let native_pixel = PENDING_NATIVE_PIXEL.load(Ordering::Acquire) as *mut c_void;
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return false;
    };
    // UpdateConstants publishes the native wrapper pair, and the renderer
    // geometry hook invokes this function after native SetShaders and
    // SetupGeometry but before submission. Reading both shaders back here was
    // redundant synchronization with the driver on every admitted geometry.
    if pixel_index == 1 {
        if super::pbr::tracked_texture(0).is_none()
            || (vertex_index == 6 && super::pbr::tracked_texture(1).is_none())
        {
            return false;
        }
    } else if pixel_index == 4 && super::pbr::tracked_texture(0).is_none() {
        return false;
    }

    if upload_constants(&device, frame.constants, object_type).is_none() {
        return false;
    }
    if unsafe { device.set_raw_vertex_shader(replacement_vertex) }.is_err()
        || unsafe { device.set_raw_pixel_shader(replacement_pixel) }.is_err()
    {
        let _ = unsafe { device.set_raw_vertex_shader(native_vertex) };
        let _ = unsafe { device.set_raw_pixel_shader(native_pixel) };
        return false;
    }
    DIRECT_NATIVE_VERTEX.store(native_vertex as usize, Ordering::Release);
    DIRECT_NATIVE_PIXEL.store(native_pixel as usize, Ordering::Release);
    DIRECT_ACTIVE.store(true, Ordering::Release);
    if !FIRST_BIND_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[SKY] Native sky replacement active vertex={} pixel={} object={}",
            vertex_index,
            pixel_index,
            object_type
        );
    }
    crate::graphics_diagnostics::add(crate::graphics_diagnostics::Counter::SkyAdmission, 1);
    true
}

fn replacement_templates(
    vertex_index: usize,
    pixel_index: usize,
    object_type: u32,
    cloud_normals: bool,
    reversed_depth: bool,
) -> Option<(usize, usize)> {
    let celestial_pixel = match object_type {
        0 => PS_CELESTIAL_SUN,
        6 => PS_CELESTIAL_MOON,
        _ => PS_CELESTIAL_OTHER,
    };
    let (vertex, pixel) = match (vertex_index, pixel_index) {
        (0, 0) => Some((VS_ATMOSPHERE, PS_ATMOSPHERE)),
        (1, 1) => Some((VS_CELESTIAL, celestial_pixel)),
        (2, 1) => Some((VS_MOON_MASK, celestial_pixel)),
        (4, 4) => Some((VS_STARS, PS_STARS)),
        (6, 1) => Some((
            VS_CLOUDS,
            if cloud_normals {
                PS_CLOUD_NORMALS
            } else {
                PS_CLOUDS
            },
        )),
        _ => None,
    }?;
    Some((
        if reversed_depth {
            vertex
        } else {
            vertex + VS_FORWARD_OFFSET
        },
        pixel,
    ))
}

fn pair_supported_for_object(object_type: u32, vertex_index: usize, pixel_index: usize) -> bool {
    let pair_supported = matches!(
        (vertex_index, pixel_index),
        (0, 0) | (1, 1) | (2, 1) | (4, 4) | (6, 1)
    );
    pair_supported
        && match object_type {
            2 => (vertex_index, pixel_index) == (0, 0),
            3 => (vertex_index, pixel_index) == (6, 1),
            5 => (vertex_index, pixel_index) == (4, 4),
            _ => true,
        }
}

fn prepare_sky_frame(
    frame: crate::backend::NativeSkyFrame,
    settings: NativeSkySettings,
) -> PreparedSkyFrame {
    let sun_disk_source = if settings.use_sun_disk_color {
        frame.sun_disk
    } else {
        frame.sun_light
    };
    let sunset = if frame.is_exterior {
        settings.sunset
    } else {
        [0.0; 3]
    };
    let mut sky_sun_direction = frame.sun_direction;
    if !frame.is_exterior || frame.daylight <= 0.5 {
        sky_sun_direction[2] = -sky_sun_direction[2];
    }
    let sun_height = sky_sun_direction[2].max(0.0);
    let linear_sunset = linearize_color(sunset);
    let linear_sun_light = evaluate_sun(
        linearize_color(frame.sun_light),
        linear_sunset,
        sun_height,
        frame.daylight,
        settings.atmosphere_thickness,
    );
    let linear_sun_disk = evaluate_sun(
        linearize_color(sun_disk_source),
        linear_sunset,
        sun_height,
        frame.daylight,
        settings.atmosphere_thickness,
    );
    PreparedSkyFrame {
        reversed_depth: frame.reversed_depth,
        constants: [
            color4(linearize_color(frame.sky_upper)),
            color4(linearize_color(frame.sky_lower)),
            color4(linearize_color(frame.horizon)),
            color4(linear_sun_light),
            [
                sky_sun_direction[0],
                sky_sun_direction[1],
                sky_sun_direction[2],
                settings.sun_influence.recip(),
            ],
            [
                settings.atmosphere_thickness,
                settings.sun_influence,
                settings.sun_strength,
                settings.star_strength,
            ],
            [
                if settings.cloud_normals { 1.0 } else { 0.0 },
                settings.star_twinkle,
                settings.cloud_transparency,
                settings.cloud_brightness,
            ],
            [
                frame.daylight,
                settings.glare_strength,
                frame.game_hour * 3600.0,
                sun_height,
            ],
            [
                linear_sunset[0],
                linear_sunset[1],
                linear_sunset[2],
                settings.sky_multiplier,
            ],
            color4(linear_sun_disk),
            [
                0.0,
                frame.horizon[0].max(0.0).powf(2.2),
                frame.horizon[1].max(0.0).powf(2.2),
                frame.horizon[2].max(0.0).powf(2.2),
            ],
        ],
    }
}

fn draw_constants(mut constants: [[f32; 4]; 11], object_type: u32) -> [[f32; 4]; 11] {
    constants[10][0] = object_type as f32;
    constants
}

fn upload_constants(
    device: &Device9Ref<'_>,
    constants: [[f32; 4]; 11],
    object_type: u32,
) -> Option<()> {
    let constants = draw_constants(constants, object_type);
    device
        .set_pixel_shader_constant_f(CONSTANT_FIRST_REGISTER, &constants)
        .ok()
}

fn linearize_color(color: [f32; 3]) -> [f32; 3] {
    color.map(|component| {
        if component <= 0.04045 {
            component / 12.92
        } else {
            ((component + 0.055) / 1.055).powf(2.4)
        }
    })
}

fn evaluate_sun(
    sun: [f32; 3],
    sunset: [f32; 3],
    sun_height: f32,
    daylight: f32,
    atmosphere_thickness: f32,
) -> [f32; 3] {
    let sunset_base = 1.0 - sun_height;
    let sunset_base2 = sunset_base * sunset_base;
    let sunset_base4 = sunset_base2 * sunset_base2;
    let sunset_weight = (sunset_base4 * sunset_base4).clamp(0.0, 1.0) * daylight;
    std::array::from_fn(|index| {
        (1.0 + sun_height) * sun[index] + sunset[index] * sunset_weight * atmosphere_thickness
    })
}

fn color4(color: [f32; 3]) -> [f32; 4] {
    [color[0], color[1], color[2], 1.0]
}

fn restore_direct_pair() {
    if !DIRECT_ACTIVE.swap(false, Ordering::AcqRel) {
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
    let _ = unsafe { device.set_raw_vertex_shader(native_vertex) };
    let _ = unsafe { device.set_raw_pixel_shader(native_pixel) };
}

fn resolve_update_slot() -> Result<*mut *mut c_void> {
    let Some(selector) = read_ptr(SKY_SELECTOR_CACHE_ADDR as *const c_void) else {
        anyhow::bail!("SkyShader selector cache is unavailable")
    };
    let Some(vtable) = read_ptr(selector.cast_const()) else {
        anyhow::bail!("SkyShader selector vtable is unavailable")
    };
    let address = (vtable as usize)
        .checked_add(SKY_UPDATE_CONSTANTS_VTABLE_OFFSET)
        .ok_or_else(|| anyhow::anyhow!("SkyShader::UpdateConstants slot address overflowed"))?;
    let slot = address as *mut *mut c_void;
    validate_memory_range(slot.cast(), size_of::<*mut c_void>())?;

    // Resolve the current live vtable rather than the vanilla table. This
    // preserves a predecessor installed by a mod through either a cloned
    // selector vtable or an entry detour, while PointerSlotHook's CAS prevents
    // OMV from overwriting an owner that changes the slot after this preflight.
    Ok(slot)
}

fn find_array_index(
    owner: *mut c_void,
    offset: usize,
    count: usize,
    target: *mut c_void,
) -> Option<usize> {
    let start = (owner as usize).checked_add(offset)? as *const c_void;
    validate_memory_range(start, count.checked_mul(size_of::<usize>())?).ok()?;
    (0..count).find(|index| {
        let slot = (start as usize + index * size_of::<usize>()) as *const usize;
        unsafe { slot.read() == target as usize }
    })
}

fn shader_handle(shader: *mut c_void, stage: Stage) -> Option<*mut c_void> {
    let (vtable, offset) = match stage {
        Stage::Vertex => (NID3D_VERTEX_SHADER_VTABLE, VERTEX_SHADER_HANDLE_OFFSET),
        Stage::Pixel => (NID3D_PIXEL_SHADER_VTABLE, PIXEL_SHADER_HANDLE_OFFSET),
    };
    if read_usize(shader)? != vtable {
        return None;
    }
    read_ptr_offset(shader, offset).or_else(|| read_ptr_offset(shader, SHADER_BACKUP_HANDLE_OFFSET))
}

fn shader_resource_handle(index: usize) -> Option<*mut c_void> {
    let handle = HANDLES.get(index)?.load(Ordering::Acquire) as *mut c_void;
    (!handle.is_null()).then_some(handle)
}

fn clear_handles() {
    for handle in HANDLES.iter() {
        handle.store(0, Ordering::Release);
    }
}

fn clear_pending() {
    PENDING.store(false, Ordering::Release);
    PENDING_EVALUATED.store(true, Ordering::Release);
    PENDING_VERTEX_INDEX.store(NO_INDEX, Ordering::Release);
    PENDING_PIXEL_INDEX.store(NO_INDEX, Ordering::Release);
    PENDING_GEOMETRY.store(0, Ordering::Release);
    PENDING_NATIVE_VERTEX.store(0, Ordering::Release);
    PENDING_NATIVE_PIXEL.store(0, Ordering::Release);
}

fn read_ptr(address: *const c_void) -> Option<*mut c_void> {
    validate_memory_range(address, size_of::<usize>()).ok()?;
    let value = unsafe { (address as *const usize).read() } as *mut c_void;
    (!value.is_null()).then_some(value)
}

fn read_ptr_offset(base: *const c_void, offset: usize) -> Option<*mut c_void> {
    read_ptr((base as usize).checked_add(offset)? as *const c_void)
}

fn read_usize(address: *const c_void) -> Option<usize> {
    validate_memory_range(address, size_of::<usize>()).ok()?;
    Some(unsafe { (address as *const usize).read() })
}

fn read_u32_offset(base: *const c_void, offset: usize) -> Option<u32> {
    let address = (base as usize).checked_add(offset)? as *const c_void;
    validate_memory_range(address, size_of::<u32>()).ok()?;
    Some(unsafe { (address as *const u32).read() })
}

fn sanitize(value: f32, fallback: f32, minimum: f32, maximum: f32) -> f32 {
    if value.is_finite() {
        value.clamp(minimum, maximum)
    } else {
        fallback
    }
}
