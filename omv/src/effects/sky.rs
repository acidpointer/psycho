//! Draw-scoped replacement for the native Fallout NV sky shader family.

use std::{
    ffi::c_void,
    fs,
    mem::size_of,
    path::PathBuf,
    slice,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    thread,
};

use anyhow::Result;
use libpsycho::os::windows::{
    directx9::{Device9Ref, PixelShader9, VertexShader9},
    hook::inline::inlinehook::InlineHookContainer,
    memory::validate_memory_range,
};
use parking_lot::Mutex;

const SKY_UPDATE_CONSTANTS_ADDR: usize = 0x00B89D80;
const SKY_SHADER_PROPERTY_VTABLE: usize = 0x010B8CE0;
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

const SKY_UPDATE_PROLOGUE: &[u8] = &[
    0x83, 0xEC, 0x68, 0xA1, 0xE4, 0x91, 0x1F, 0x01, 0x53, 0x89, 0x4C, 0x24, 0x04, 0x8B, 0x0D, 0xE0,
];

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
const PS_CELESTIAL: usize = 11;
const PS_CLOUDS: usize = 12;
const PS_CLOUD_NORMALS: usize = 13;
const PS_STARS: usize = 14;
const SHADER_COUNT: usize = 15;

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
            atmosphere_thickness: sanitize(value.atmosphere_thickness, 2.0, 0.0, 8.0),
            sun_influence: sanitize(value.sun_influence, 1.0, 0.05, 8.0),
            sun_strength: sanitize(value.sun_strength, 1.0, 0.0, 8.0),
            glare_strength: sanitize(value.glare_strength, 1.0, 0.0, 8.0),
            star_strength: sanitize(value.star_strength, 1.0, 0.0, 8.0),
            star_twinkle: sanitize(value.star_twinkle, 1.0, 0.0, 8.0),
            cloud_transparency: sanitize(value.cloud_transparency, 0.4, 0.05, 1.0),
            cloud_brightness: sanitize(value.cloud_brightness, 0.9, 0.0, 4.0),
            cloud_normals: value.cloud_normals,
            use_sun_disk_color: value.use_sun_disk_color,
            sunset: [
                sanitize(value.sunset_red, 0.5, 0.0, 4.0),
                sanitize(value.sunset_green, 0.0, 0.0, 4.0),
                sanitize(value.sunset_blue, 0.03, 0.0, 4.0),
            ],
            sky_multiplier: sanitize(value.sky_multiplier, 1.0, 0.0, 4.0),
        }
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
        label: "sky_celestial_ps",
        stage: Stage::Pixel,
        source: TEXTURED_PS,
        prefix: b"#define OMV_CELESTIAL 1\n",
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
static UPDATE_HOOK: LazyLock<InlineHookContainer<SkyUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
static INSTALLED: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
static DRAW_BOUNDARY_READY: AtomicBool = AtomicBool::new(false);
static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FINISHED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Vec<Option<Vec<u32>>>>> =
    LazyLock::new(|| Mutex::new((0..SHADER_COUNT).map(|_| None).collect()));
static RESOURCES: LazyLock<Mutex<ResourceState>> =
    LazyLock::new(|| Mutex::new(ResourceState::new()));
static HANDLES: LazyLock<Vec<AtomicUsize>> =
    LazyLock::new(|| (0..SHADER_COUNT).map(|_| AtomicUsize::new(0)).collect());

static PENDING: AtomicBool = AtomicBool::new(false);
static PENDING_EVALUATED: AtomicBool = AtomicBool::new(true);
static PENDING_VERTEX_INDEX: AtomicU32 = AtomicU32::new(NO_INDEX);
static PENDING_PIXEL_INDEX: AtomicU32 = AtomicU32::new(NO_INDEX);
static PENDING_OBJECT_TYPE: AtomicU32 = AtomicU32::new(8);
static PENDING_NATIVE_VERTEX: AtomicUsize = AtomicUsize::new(0);
static PENDING_NATIVE_PIXEL: AtomicUsize = AtomicUsize::new(0);
static DIRECT_ACTIVE: AtomicBool = AtomicBool::new(false);
static DIRECT_NATIVE_VERTEX: AtomicUsize = AtomicUsize::new(0);
static DIRECT_NATIVE_PIXEL: AtomicUsize = AtomicUsize::new(0);
static FIRST_BIND_LOGGED: AtomicBool = AtomicBool::new(false);
static FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

struct ResourceState {
    device: usize,
    slots: Vec<ResourceSlot>,
}

impl ResourceState {
    fn new() -> Self {
        Self {
            device: 0,
            slots: (0..SHADER_COUNT).map(|_| ResourceSlot::default()).collect(),
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

pub(crate) fn install(settings: NativeSkySettings) -> Result<()> {
    configure_runtime_options(settings);
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    let target = match resolve_hook_target() {
        Ok(target) => target,
        Err(err) => {
            log::warn!("[SKY] Native sky disabled: {err:#}");
            return Ok(());
        }
    };
    if let Err(err) = unsafe {
        UPDATE_HOOK.init(
            "FNV SkyShader::UpdateConstants",
            target,
            hook_update_constants,
        )
    } {
        log::warn!("[SKY] Native sky hook initialization failed: {err}");
        return Ok(());
    }
    if let Err(err) = UPDATE_HOOK.enable() {
        log::warn!("[SKY] Native sky hook enable failed: {err}");
        return Ok(());
    }
    INSTALLED.store(true, Ordering::Release);
    if settings.enabled {
        start_compile_worker();
    }
    log::info!("[SKY] Native NVR-style sky hook installed");
    Ok(())
}

pub(crate) fn configure_runtime_options(settings: NativeSkySettings) {
    *SETTINGS.lock() = settings;
    ENABLED.store(settings.enabled, Ordering::Release);
    if settings.enabled && INSTALLED.load(Ordering::Acquire) {
        start_compile_worker();
    }
}

pub(crate) fn set_draw_boundary_ready(ready: bool) {
    DRAW_BOUNDARY_READY.store(ready, Ordering::Release);
}

pub(crate) fn runtime_status() -> NativeSkyStatus {
    NativeSkyStatus {
        installed: INSTALLED.load(Ordering::Acquire),
        enabled: ENABLED.load(Ordering::Acquire),
        compiled: BYTECODE
            .lock()
            .iter()
            .filter(|entry| entry.is_some())
            .count(),
        created: HANDLES
            .iter()
            .filter(|handle| handle.load(Ordering::Acquire) != 0)
            .count(),
        total: SHADER_COUNT,
        failed: COMPILE_FAILED.load(Ordering::Acquire)
            || RESOURCES.lock().slots.iter().any(|slot| slot.failed),
    }
}

pub(crate) fn service_present_frame() {
    if ENABLED.load(Ordering::Acquire) {
        start_compile_worker();
        create_ready_resources();
    }
}

pub(crate) fn prepare_direct_draw() {
    if !ENABLED.load(Ordering::Acquire)
        || !DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        || !PENDING.load(Ordering::Acquire)
        || PENDING_EVALUATED.swap(true, Ordering::AcqRel)
    {
        return;
    }

    if !try_bind_pending_draw() && !FALLBACK_LOGGED.swap(true, Ordering::AcqRel) {
        log::warn!("[SKY] Sky draw kept vanilla because a replacement contract was unavailable");
    }
}

pub(crate) fn finish_direct_draw() {
    restore_direct_pair();
    PENDING.store(false, Ordering::Release);
}

pub(crate) fn reset_runtime_state() {
    restore_direct_pair();
    clear_handles();
    *RESOURCES.lock() = ResourceState::new();
    clear_pending();
    FIRST_BIND_LOGGED.store(false, Ordering::Release);
    FALLBACK_LOGGED.store(false, Ordering::Release);
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
        let mut source = Vec::with_capacity(template.prefix.len() + template.source.len());
        source.extend_from_slice(template.prefix);
        source.extend_from_slice(template.source);
        let profile = match template.stage {
            Stage::Vertex => "vs_3_0",
            Stage::Pixel => "ps_3_0",
        };
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

fn load_or_compile(label: &str, source: &[u8], profile: &str) -> Result<(Vec<u32>, &'static str)> {
    let hash = shader_source_hash(label, profile, source);
    let path = shader_cache_path(label, profile, hash);
    if let Ok(bytes) = fs::read(&path)
        && let Some(bytecode) = decode_cached_shader(&bytes, profile)
    {
        return Ok((bytecode, "cache"));
    }

    let bytecode = crate::shaders::compile_hlsl_source_target(label, source, profile)?;
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_ok()
    {
        let bytes = unsafe {
            slice::from_raw_parts(
                bytecode.as_ptr().cast::<u8>(),
                bytecode.len() * size_of::<u32>(),
            )
        };
        let _ = fs::write(path, bytes);
    }
    Ok((bytecode, "compiler"))
}

fn shader_source_hash(label: &str, profile: &str, source: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in label
        .as_bytes()
        .iter()
        .chain(profile.as_bytes())
        .chain(source)
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn shader_cache_path(label: &str, profile: &str, hash: u64) -> PathBuf {
    let mut path = PathBuf::from(crate::config::CONFIG_PATH);
    let _ = path.pop();
    path.push("cache");
    path.push("native_sky");
    path.push(format!("{label}_{profile}_{hash:016x}.cso"));
    path
}

fn decode_cached_shader(bytes: &[u8], profile: &str) -> Option<Vec<u32>> {
    if bytes.len() < size_of::<u32>() || !bytes.len().is_multiple_of(size_of::<u32>()) {
        return None;
    }
    let expected_version = if profile.starts_with("vs_") {
        0xFFFE_0300
    } else {
        0xFFFF_0300
    };
    let version = u32::from_le_bytes(bytes[..4].try_into().ok()?);
    if version != expected_version {
        return None;
    }
    Some(
        bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("four-byte shader word")))
            .collect(),
    )
}

fn create_ready_resources() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };
    let bytecode = BYTECODE.lock();
    let mut resources = RESOURCES.lock();
    if resources.device != device_ptr as usize {
        clear_handles();
        resources.device = device_ptr as usize;
        resources.slots = (0..SHADER_COUNT).map(|_| ResourceSlot::default()).collect();
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
            Err(err) => {
                resources.slots[index].failed = true;
                log::warn!("[SKY] Failed to create {}: {err}", TEMPLATES[index].label);
            }
        }
    }
}

unsafe extern "thiscall" fn hook_update_constants(
    sky_shader: *mut c_void,
    property_state: *const c_void,
) {
    clear_pending();
    let Ok(original) = UPDATE_HOOK.original() else {
        return;
    };
    unsafe { original(sky_shader, property_state) };

    if !ENABLED.load(Ordering::Acquire) || sky_shader.is_null() || property_state.is_null() {
        return;
    }
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

    PENDING_VERTEX_INDEX.store(vertex_index as u32, Ordering::Release);
    PENDING_PIXEL_INDEX.store(pixel_index as u32, Ordering::Release);
    PENDING_OBJECT_TYPE.store(object_type, Ordering::Release);
    PENDING_NATIVE_VERTEX.store(native_vertex as usize, Ordering::Release);
    PENDING_NATIVE_PIXEL.store(native_pixel as usize, Ordering::Release);
    PENDING_EVALUATED.store(false, Ordering::Release);
    PENDING.store(true, Ordering::Release);
}

fn try_bind_pending_draw() -> bool {
    let vertex_index = PENDING_VERTEX_INDEX.load(Ordering::Acquire) as usize;
    let pixel_index = PENDING_PIXEL_INDEX.load(Ordering::Acquire) as usize;
    let object_type = PENDING_OBJECT_TYPE.load(Ordering::Acquire);
    let settings = *SETTINGS.lock();
    let Some(frame) = crate::backend::native_sky_frame() else {
        return false;
    };
    let Some((vertex_template, pixel_template)) = replacement_templates(
        vertex_index,
        pixel_index,
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
    if device.current_vertex_shader_raw().ok() != Some(native_vertex)
        || device.current_pixel_shader_raw().ok() != Some(native_pixel)
    {
        return false;
    }
    if pixel_index == 1 {
        if device.texture_raw(0).is_none() || (vertex_index == 6 && device.texture_raw(1).is_none())
        {
            return false;
        }
    } else if pixel_index == 4 && device.texture_raw(0).is_none() {
        return false;
    }

    if upload_constants(&device, frame, settings, object_type).is_none() {
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
    true
}

fn replacement_templates(
    vertex_index: usize,
    pixel_index: usize,
    cloud_normals: bool,
    reversed_depth: bool,
) -> Option<(usize, usize)> {
    let (vertex, pixel) = match (vertex_index, pixel_index) {
        (0, 0) => Some((VS_ATMOSPHERE, PS_ATMOSPHERE)),
        (1, 1) => Some((VS_CELESTIAL, PS_CELESTIAL)),
        (2, 1) => Some((VS_MOON_MASK, PS_CELESTIAL)),
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

fn upload_constants(
    device: &Device9Ref<'_>,
    frame: crate::backend::NativeSkyFrame,
    settings: NativeSkySettings,
    object_type: u32,
) -> Option<()> {
    let sun_disk = if settings.use_sun_disk_color {
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
    let constants = [
        color4(frame.sky_upper),
        color4(frame.sky_lower),
        color4(frame.horizon),
        color4(frame.sun_light),
        [
            sky_sun_direction[0],
            sky_sun_direction[1],
            sky_sun_direction[2],
            1.0,
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
            0.0,
        ],
        [sunset[0], sunset[1], sunset[2], settings.sky_multiplier],
        color4(sun_disk),
        [object_type as f32, 0.0, 0.0, 0.0],
    ];
    device
        .set_pixel_shader_constant_f(CONSTANT_FIRST_REGISTER, &constants)
        .ok()
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

fn resolve_hook_target() -> Result<*mut c_void> {
    validate_memory_range(
        SKY_UPDATE_CONSTANTS_ADDR as *const c_void,
        SKY_UPDATE_PROLOGUE.len(),
    )?;
    let actual = unsafe {
        slice::from_raw_parts(
            SKY_UPDATE_CONSTANTS_ADDR as *const u8,
            SKY_UPDATE_PROLOGUE.len(),
        )
    };
    if actual.starts_with(SKY_UPDATE_PROLOGUE) {
        return Ok(SKY_UPDATE_CONSTANTS_ADDR as *mut c_void);
    }
    if actual[0] == 0xE9 {
        let relative = i32::from_le_bytes([actual[1], actual[2], actual[3], actual[4]]);
        let target = (SKY_UPDATE_CONSTANTS_ADDR as isize)
            .wrapping_add(5)
            .wrapping_add(relative as isize) as usize;
        validate_memory_range(target as *const c_void, 8)?;
        log::info!("[SKY] Chaining existing SkyShader redirect at 0x{target:08X}");
        return Ok(target as *mut c_void);
    }
    anyhow::bail!("SkyShader::UpdateConstants prologue is unsupported")
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
