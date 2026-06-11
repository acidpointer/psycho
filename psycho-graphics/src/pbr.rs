//! Native PBR draw-contract layer for FalloutNV.
//!
//! This module owns the proven engine-side contract for material PBR:
//! draw-scoped current pass capture, final vanilla texture-stage capture, and
//! an opt-in NVR-style pixel shader handle substitution for one proven
//! PPLighting family.

use std::{
    array,
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::null_mut,
    slice,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::Result;
use libpsycho::os::windows::{
    directx9::{
        D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER,
        D3DSAMP_MIPFILTER, D3DTEXF_LINEAR, D3DTEXF_NONE, Device9Ref, PixelShader9, VertexShader9,
    },
    hook::inline::inlinehook::InlineHookContainer,
    memory::validate_memory_range,
    winapi::virtual_query,
};
use parking_lot::Mutex;
use windows::Win32::System::Memory::{
    MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY,
};

const BS_SHADER_SET_SHADERS_ADDR: usize = 0x00BE1F90;
const CURRENT_PASS_SHADER_APPLY_ADDR: usize = 0x00BD4BA0;
const NIDX9_RENDER_STATE_SET_TEXTURE_ADDR: usize = 0x00E88A20;
const PPLIGHTING_SELECTOR_SETUP_VARIANT_ADDR: usize = 0x00BDB4A0;
const PPLIGHTING_SELECTOR_SETUP_MAIN_ADDR: usize = 0x00BDF790;
const CURRENT_GEOMETRY_SLOT_ADDR: usize = 0x011F91E0;
const CURRENT_PASS_GLOBAL_ADDR: usize = 0x0126F74C;
const RENDERER_GLOBAL_ADDR: usize = 0x0126F6C4;
const SHADER_INTERFACE_SELECTOR_ARRAY_ADDR: usize = 0x011F9548;
const PPLIGHTING_SHADER_SELECTOR_INDEX: usize = 1;
const PASS_PIXEL_SHADER_OFFSET: usize = 0x44;
const PASS_VERTEX_SHADER_OFFSET: usize = 0x5C;
const NID3D_PIXEL_SHADER_VTABLE_ADDR: usize = 0x010EF7D4;
const NID3D_VERTEX_SHADER_VTABLE_ADDR: usize = 0x010EF87C;
const PIXEL_SHADER_NATIVE_HANDLE_OFFSET: usize = 0x2C;
const VERTEX_SHADER_SET_SHADERS_HANDLE_OFFSET: usize = 0x34;
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
const PPLIGHTING_GROUP_NONE: u32 = 0;
const PPLIGHTING_VERTEX_GROUP_A: u32 = 1;
const PPLIGHTING_VERTEX_GROUP_B: u32 = 2;
const PPLIGHTING_VERTEX_GROUP_C: u32 = 3;
const PPLIGHTING_PIXEL_GROUP_A: u32 = 1;
const PPLIGHTING_PIXEL_GROUP_B: u32 = 2;
const PPLIGHTING_FAMILY_NONE: u32 = 0;
const PPLIGHTING_FAMILY_VERTEX_A_PIXEL_A: u32 = 1;
const PPLIGHTING_FAMILY_VERTEX_B_PIXEL_A: u32 = 2;
const PPLIGHTING_FAMILY_VERTEX_C_PIXEL_B: u32 = 3;
const PPLIGHTING_FAMILY_UNKNOWN_PAIR: u32 = u32::MAX;
const PPLIGHTING_VERTEX_SLS2_ADTS_BASE_INDEX: u32 = 0;
const PPLIGHTING_PIXEL_SLS2_ADTS_OPT_INDEX: u32 = 1;
const PPLIGHTING_VERTEX_SLS2_ADTS_LOD_INDEX: u32 = 1;
const PPLIGHTING_PIXEL_SLS2_ADTS_OPT_LOD_INDEX: u32 = 2;
const PPLIGHTING_VERTEX_SLS2_LANDLOD_INDEX: u32 = 2;
const PPLIGHTING_PIXEL_SLS2_LANDLOD_INDEX: u32 = 3;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_INDEX: u32 = 12;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_SKIN_INDEX: u32 = 13;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_INDEX: u32 = 17;
const PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_INDEX: u32 = 22;
const PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_INDEX: u32 = 31;
const APPLY_PARAM_RESOURCE_OFFSET: usize = 0x08;
const SHADER_INTERFACE_PIXEL_OFFSET: usize = 0x30;
const SHADER_INTERFACE_VERTEX_OFFSET: usize = 0x34;
const SHADER_INTERFACE_PIXEL_ALT_OFFSET: usize = 0x7C;
const SHADER_INTERFACE_VERTEX_ALT_OFFSET: usize = 0x80;
const SHADER_INTERFACE_PIXEL_ACTIVE_COPY_OFFSET: usize = 0x84;
const SHADER_INTERFACE_VERTEX_ACTIVE_COPY_OFFSET: usize = 0x88;
const SHADER_INTERFACE_APPLY_SLOT_OFFSET: usize = 0x78;
const SHADER_INTERFACE_FIELD_VTABLE_ADDR: usize = 0x010EF544;
const SHADER_INTERFACE_FIELD_APPLY_ADDR: usize = 0x00E826D0;
const TEXTURE_RESOLVER_OFFSET: usize = 0x8C4;
const TEXTURE_RESOLVER_VTABLE_ADDR: usize = 0x010F086C;
const TEXTURE_RESOLVER_RESOLVE_SLOT_OFFSET: usize = 0x0C;
const TEXTURE_RESOLVER_RESOLVE_ADDR: usize = 0x00E90B10;
const CURRENT_DRAW_SELECTOR_OFFSET: usize = 0xC0;
const SELECTOR_FLAGS_OFFSET: usize = 0x20;
const SELECTOR_PASS_ENTRY_LIST_OFFSET: usize = 0x3C;
const SELECTOR_MATERIAL_ARRAY_OFFSETS: [usize; SELECTOR_MATERIAL_ARRAY_COUNT] =
    [0xAC, 0xB0, 0xB4, 0xB8, 0xBC, 0xC0];
const SELECTOR_MATERIAL_ARRAY_COUNT: usize = 6;
const SELECTOR_CAPTURE_SLOTS: usize = 4096;
const TEXTURE_RESOLVE_CACHE_SLOTS: usize = 128;
const SELECTOR_SETUP_VARIANT_KIND: u32 = 1;
const SELECTOR_SETUP_MAIN_KIND: u32 = 2;
const GEOMETRY_FLAGS_OFFSET: usize = 0x20;
const GEOMETRY_SHADER_ARGS_OFFSET: usize = 0x68;
const GEOMETRY_STATE_OFFSET: usize = 0xB8;
const GEOMETRY_CONTEXT_OFFSET: usize = 0xBC;
const GEOMETRY_STATE_VALUE_OFFSET: usize = 0x34;
const MAX_TEXTURE_STAGES: usize = 16;
const MAX_LOGS: u32 = 16;
const MIN_READABLE_ADDRESS: usize = 0x10000;
const PBR_MATERIAL_FLAGS_REGISTER: u32 = 31;
const PBR_NVR_DATA_REGISTER: u32 = 32;
const PBR_NVR_EXTRA_DATA_REGISTER: u32 = 33;
const PBR_MATERIAL_SLOT_NORMAL: usize = 1;
const PBR_MATERIAL_SLOT_GLOW: usize = 2;
const PBR_MATERIAL_SLOT_HEIGHT: usize = 3;
const PBR_MATERIAL_SLOT_ENVIRONMENT: usize = 4;
const PBR_MATERIAL_SLOT_ENVIRONMENT_MASK: usize = 5;
const PBR_NORMAL_STAGE: u32 = 1;
const PBR_GLOW_STAGE: u32 = 2;
const PBR_HEIGHT_STAGE: u32 = 3;
const PBR_ENVIRONMENT_STAGE: u32 = 4;
const PBR_ENVIRONMENT_MASK_STAGE: u32 = 5;

const SET_SHADERS_PROLOGUE: &[u8] = &[
    0x8B, 0x0D, 0x4C, 0xF7, 0x26, 0x01, 0x56, 0x57, 0xE8, 0x23, 0xD8, 0x29, 0x00, 0x8B, 0xF0, 0xA1,
];
const SET_TEXTURE_PROLOGUE: &[u8] = &[
    0x8B, 0x44, 0x24, 0x04, 0x8B, 0x54, 0x24, 0x08, 0x39, 0x94, 0x81, 0xA0, 0x10, 0x00, 0x00, 0x74,
];
const PASS_SHADER_APPLY_PROLOGUE: &[u8] = &[
    0x83, 0xEC, 0x0C, 0xA1, 0xE0, 0x91, 0x1F, 0x01, 0x53, 0x55, 0x56, 0x8B, 0x30, 0x8B, 0x46, 0x20,
];
const SELECTOR_SETUP_VARIANT_PROLOGUE: &[u8] = &[
    0x83, 0xEC, 0x38, 0x53, 0x55, 0x56, 0x8B, 0xF1, 0x8B, 0x46, 0x20, 0xA8, 0x01, 0x0F, 0x97, 0xC1,
];
const SELECTOR_SETUP_MAIN_PROLOGUE: &[u8] = &[
    0x83, 0xEC, 0x7C, 0x53, 0x55, 0x56, 0x8B, 0xF1, 0x8B, 0x46, 0x20, 0xA8, 0x01, 0x0F, 0x97, 0x44,
];

const PPLIGHTING_VERTEX_GROUPS: [ShaderArrayGroup; 3] = [
    ShaderArrayGroup {
        id: PPLIGHTING_VERTEX_GROUP_A,
        base: PPLIGHTING_VERTEX_GROUP_A_ADDR,
        count: PPLIGHTING_VERTEX_GROUP_A_COUNT,
    },
    ShaderArrayGroup {
        id: PPLIGHTING_VERTEX_GROUP_B,
        base: PPLIGHTING_VERTEX_GROUP_B_ADDR,
        count: PPLIGHTING_VERTEX_GROUP_B_COUNT,
    },
    ShaderArrayGroup {
        id: PPLIGHTING_VERTEX_GROUP_C,
        base: PPLIGHTING_VERTEX_GROUP_C_ADDR,
        count: PPLIGHTING_VERTEX_GROUP_C_COUNT,
    },
];

const PPLIGHTING_PIXEL_GROUPS: [ShaderArrayGroup; 2] = [
    ShaderArrayGroup {
        id: PPLIGHTING_PIXEL_GROUP_A,
        base: PPLIGHTING_PIXEL_GROUP_A_ADDR,
        count: PPLIGHTING_PIXEL_GROUP_A_COUNT,
    },
    ShaderArrayGroup {
        id: PPLIGHTING_PIXEL_GROUP_B,
        base: PPLIGHTING_PIXEL_GROUP_B_ADDR,
        count: PPLIGHTING_PIXEL_GROUP_B_COUNT,
    },
];

type SetShadersFn = unsafe extern "thiscall" fn(*mut c_void, u32);
type SetTextureFn = unsafe extern "thiscall" fn(*mut c_void, u32, *mut c_void);
type PassShaderApplyFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
type SelectorSetupFn =
    unsafe extern "thiscall" fn(*mut c_void, usize, usize, usize, usize, usize, usize);
type TextureResolverResolveFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut u8, *mut u8, *mut u8) -> *mut c_void;

static SET_SHADERS_HOOK: LazyLock<InlineHookContainer<SetShadersFn>> =
    LazyLock::new(InlineHookContainer::new);
static SET_TEXTURE_HOOK: LazyLock<InlineHookContainer<SetTextureFn>> =
    LazyLock::new(InlineHookContainer::new);
static PASS_SHADER_APPLY_HOOK: LazyLock<InlineHookContainer<PassShaderApplyFn>> =
    LazyLock::new(InlineHookContainer::new);
static SELECTOR_SETUP_VARIANT_HOOK: LazyLock<InlineHookContainer<SelectorSetupFn>> =
    LazyLock::new(InlineHookContainer::new);
static SELECTOR_SETUP_MAIN_HOOK: LazyLock<InlineHookContainer<SelectorSetupFn>> =
    LazyLock::new(InlineHookContainer::new);

static INSTALLED: AtomicBool = AtomicBool::new(false);
static HOOKS_ACTIVE: AtomicBool = AtomicBool::new(false);
static DEBUG_LOG_DRAWS: AtomicBool = AtomicBool::new(false);
static MATERIAL_SHADER_ENABLED: AtomicBool = AtomicBool::new(false);
static DRAW_LOGS: AtomicU32 = AtomicU32::new(0);
static TEXTURE_LOGS: AtomicU32 = AtomicU32::new(0);
static INTERFACE_LOGS: AtomicU32 = AtomicU32::new(0);
static SELECTOR_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_APPLY_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_APPLIED_COUNT: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_RESOURCE_LOGS: AtomicU32 = AtomicU32::new(0);
static MATERIAL_BIND_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_SUMMARY_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_UNSUPPORTED_PAIR_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_CHECKS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_DIFFUSE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_DRAW_CONTEXT: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_UNSUPPORTED_FAMILY: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_SELECTOR_RECORD: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_NORMAL_SOURCE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_REPLACEMENT_SHADER: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_BIND_FAILED: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_VANILLA_HANDLE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_HANDLE_WRITE_FAILED: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_LAST_FAMILY: AtomicU32 = AtomicU32::new(PPLIGHTING_FAMILY_NONE);
static REPLACEMENT_LAST_VERTEX_GROUP: AtomicU32 = AtomicU32::new(PPLIGHTING_GROUP_NONE);
static REPLACEMENT_LAST_VERTEX_INDEX: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_LAST_PIXEL_GROUP: AtomicU32 = AtomicU32::new(PPLIGHTING_GROUP_NONE);
static REPLACEMENT_LAST_PIXEL_INDEX: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_ADTS_LOD_PIXEL_SHADER_HANDLE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_ADTS_LOD_PIXEL_SHADER_DEVICE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_ADTS_SPECULAR_PIXEL_SHADER_HANDLE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_ADTS_SPECULAR_PIXEL_SHADER_DEVICE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_ADTS10_LIGHTS4_PIXEL_SHADER_HANDLE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_ADTS10_LIGHTS4_PIXEL_SHADER_DEVICE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_LANDLOD_PIXEL_SHADER_HANDLE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_LANDLOD_PIXEL_SHADER_DEVICE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_LANDLOD_VERTEX_SHADER_HANDLE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_LANDLOD_VERTEX_SHADER_DEVICE: AtomicUsize = AtomicUsize::new(0);
static PBR_ROUGHNESS_SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static PBR_LIGHT_SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static PBR_AMBIENT_SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static PBR_ALBEDO_SATURATION_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());

static TEXTURE_CAPTURE: LazyLock<TextureCapture> = LazyLock::new(TextureCapture::new);
static DRAW_CAPTURE: LazyLock<DrawCapture> = LazyLock::new(DrawCapture::new);
static INTERFACE_CAPTURE: LazyLock<ShaderInterfaceCapture> =
    LazyLock::new(ShaderInterfaceCapture::new);
static SELECTOR_CAPTURE: LazyLock<SelectorCaptureTable> = LazyLock::new(SelectorCaptureTable::new);
static TEXTURE_RESOLVE_CACHE: LazyLock<TextureResolveCache> =
    LazyLock::new(TextureResolveCache::new);
static VERTEX_SHADER_MEMBERSHIP_CACHE: LazyLock<ShaderMembershipCache> =
    LazyLock::new(ShaderMembershipCache::new);
static PIXEL_SHADER_MEMBERSHIP_CACHE: LazyLock<ShaderMembershipCache> =
    LazyLock::new(ShaderMembershipCache::new);
static PBR_REPLACEMENT: LazyLock<Mutex<PbrReplacementState>> =
    LazyLock::new(|| Mutex::new(PbrReplacementState::new()));

const PBR_REPLACEMENT_PIXEL_SHADER: &[u8] = include_bytes!("native_pbr_pplighting.hlsl");
const PBR_REPLACEMENT_ADTS_LOD_PIXEL_SHADER: &[u8] =
    include_bytes!("native_pbr_pplighting_adts_lod.hlsl");
const PBR_REPLACEMENT_ADTS10_PIXEL_SHADER: &[u8] =
    include_bytes!("native_pbr_pplighting_adts10.hlsl");
const PBR_REPLACEMENT_LANDLOD_PIXEL_SHADER: &[u8] =
    include_bytes!("native_pbr_pplighting_landlod.hlsl");
const PBR_REPLACEMENT_LANDLOD_VERTEX_SHADER: &[u8] =
    include_bytes!("native_pbr_pplighting_landlod.vs.hlsl");
const REQUIRE_VANILLA_PROLOGUES: bool = true;

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePbrSettings {
    pub(crate) enabled: bool,
    pub(crate) debug_log_draws: bool,
    pub(crate) roughness_scale: f32,
    pub(crate) light_scale: f32,
    pub(crate) ambient_scale: f32,
    pub(crate) albedo_saturation: f32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePbrRuntimeStatus {
    pub(crate) installed: bool,
    pub(crate) shader_enabled: bool,
}

#[derive(Clone, Copy)]
struct ShaderArrayGroup {
    id: u32,
    base: usize,
    count: usize,
}

#[derive(Clone, Copy)]
struct ShaderArrayMembership {
    group: u32,
    index: u32,
}

impl ShaderArrayMembership {
    const NONE: Self = Self {
        group: PPLIGHTING_GROUP_NONE,
        index: 0,
    };
}

struct ShaderMembershipCache {
    records: [ShaderMembershipCacheRecord; 64],
}

impl ShaderMembershipCache {
    fn new() -> Self {
        Self {
            records: array::from_fn(|_| ShaderMembershipCacheRecord::new()),
        }
    }

    fn get(&self, shader: *mut c_void) -> Option<ShaderArrayMembership> {
        let key = shader as usize;
        if key == 0 {
            return Some(ShaderArrayMembership::NONE);
        }

        let record = &self.records[shader_membership_cache_slot(key)];
        if record.key.load(Ordering::Acquire) != key {
            return None;
        }

        Some(ShaderArrayMembership {
            group: record.group.load(Ordering::Acquire),
            index: record.index.load(Ordering::Acquire),
        })
    }

    fn store(&self, shader: *mut c_void, membership: ShaderArrayMembership) {
        let key = shader as usize;
        if key == 0 {
            return;
        }

        let record = &self.records[shader_membership_cache_slot(key)];
        record.key.store(0, Ordering::Release);
        record.group.store(membership.group, Ordering::Release);
        record.index.store(membership.index, Ordering::Release);
        record.key.store(key, Ordering::Release);
    }
}

struct ShaderMembershipCacheRecord {
    key: AtomicUsize,
    group: AtomicU32,
    index: AtomicU32,
}

impl ShaderMembershipCacheRecord {
    fn new() -> Self {
        Self {
            key: AtomicUsize::new(0),
            group: AtomicU32::new(PPLIGHTING_GROUP_NONE),
            index: AtomicU32::new(0),
        }
    }
}

fn shader_membership_cache_slot(shader: usize) -> usize {
    (shader >> 4) % 64
}

impl Default for NativePbrSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            debug_log_draws: false,
            roughness_scale: 1.0,
            light_scale: 1.0,
            ambient_scale: 1.0,
            albedo_saturation: 1.0,
        }
    }
}

impl From<crate::config::NativePbrConfig> for NativePbrSettings {
    fn from(value: crate::config::NativePbrConfig) -> Self {
        Self {
            enabled: value.enabled,
            debug_log_draws: value.debug_log_draws,
            roughness_scale: value.roughness_scale,
            light_scale: value.light_scale,
            ambient_scale: value.ambient_scale,
            albedo_saturation: value.albedo_saturation,
        }
    }
}

struct TextureCapture {
    render_state: AtomicUsize,
    selector_object: AtomicUsize,
    selector_generation: AtomicU32,
    stages: [AtomicUsize; MAX_TEXTURE_STAGES],
    set_calls: AtomicU32,
}

impl TextureCapture {
    fn new() -> Self {
        Self {
            render_state: AtomicUsize::new(0),
            selector_object: AtomicUsize::new(0),
            selector_generation: AtomicU32::new(0),
            stages: array::from_fn(|_| AtomicUsize::new(0)),
            set_calls: AtomicU32::new(0),
        }
    }

    fn clear(&self) {
        self.render_state.store(0, Ordering::Release);
        self.selector_object.store(0, Ordering::Release);
        self.selector_generation.store(0, Ordering::Release);
        for stage in &self.stages {
            stage.store(0, Ordering::Release);
        }
        self.set_calls.store(0, Ordering::Release);
    }
}

struct DrawCapture {
    pass_index: AtomicU32,
    pass: AtomicUsize,
    vertex_shader: AtomicUsize,
    pixel_shader: AtomicUsize,
    vertex_shader_handle: AtomicUsize,
    pixel_shader_handle: AtomicUsize,
    pplighting_family: AtomicU32,
    pplighting_vertex_group: AtomicU32,
    pplighting_vertex_index: AtomicU32,
    pplighting_pixel_group: AtomicU32,
    pplighting_pixel_index: AtomicU32,
    render_state: AtomicUsize,
    set_shader_calls: AtomicU32,
}

impl DrawCapture {
    fn new() -> Self {
        Self {
            pass_index: AtomicU32::new(0),
            pass: AtomicUsize::new(0),
            vertex_shader: AtomicUsize::new(0),
            pixel_shader: AtomicUsize::new(0),
            vertex_shader_handle: AtomicUsize::new(0),
            pixel_shader_handle: AtomicUsize::new(0),
            pplighting_family: AtomicU32::new(PPLIGHTING_FAMILY_NONE),
            pplighting_vertex_group: AtomicU32::new(PPLIGHTING_GROUP_NONE),
            pplighting_vertex_index: AtomicU32::new(0),
            pplighting_pixel_group: AtomicU32::new(PPLIGHTING_GROUP_NONE),
            pplighting_pixel_index: AtomicU32::new(0),
            render_state: AtomicUsize::new(0),
            set_shader_calls: AtomicU32::new(0),
        }
    }

    fn clear(&self) {
        self.pass_index.store(0, Ordering::Release);
        self.pass.store(0, Ordering::Release);
        self.vertex_shader.store(0, Ordering::Release);
        self.pixel_shader.store(0, Ordering::Release);
        self.vertex_shader_handle.store(0, Ordering::Release);
        self.pixel_shader_handle.store(0, Ordering::Release);
        self.pplighting_family
            .store(PPLIGHTING_FAMILY_NONE, Ordering::Release);
        self.pplighting_vertex_group
            .store(PPLIGHTING_GROUP_NONE, Ordering::Release);
        self.pplighting_vertex_index.store(0, Ordering::Release);
        self.pplighting_pixel_group
            .store(PPLIGHTING_GROUP_NONE, Ordering::Release);
        self.pplighting_pixel_index.store(0, Ordering::Release);
        self.render_state.store(0, Ordering::Release);
        self.set_shader_calls.store(0, Ordering::Release);
    }
}

struct ShaderInterfaceCapture {
    apply_this: AtomicUsize,
    apply_param: AtomicUsize,
    apply_param_resource: AtomicUsize,
    current_geometry_slot: AtomicUsize,
    current_geometry: AtomicUsize,
    geometry_flags: AtomicU32,
    geometry_shader_args: AtomicUsize,
    geometry_state: AtomicUsize,
    geometry_state_value: AtomicUsize,
    geometry_context: AtomicU32,
    pass: AtomicUsize,
    vertex_shader: AtomicUsize,
    pixel_shader: AtomicUsize,
    selector_object: AtomicUsize,
    selector_pixel_interface: AtomicUsize,
    selector_vertex_interface: AtomicUsize,
    selector_pixel_apply: AtomicUsize,
    selector_vertex_apply: AtomicUsize,
    selector_pixel_alt_interface: AtomicUsize,
    selector_vertex_alt_interface: AtomicUsize,
    selector_pixel_alt_apply: AtomicUsize,
    selector_vertex_alt_apply: AtomicUsize,
    selector_pixel_active_copy_interface: AtomicUsize,
    selector_vertex_active_copy_interface: AtomicUsize,
    selector_pixel_active_copy_apply: AtomicUsize,
    selector_vertex_active_copy_apply: AtomicUsize,
    selector_material_generation: AtomicU32,
    selector_material_setup_kind: AtomicU32,
    selector_pass_entry_list: AtomicUsize,
    selector_material_arrays: [AtomicUsize; SELECTOR_MATERIAL_ARRAY_COUNT],
    param_pixel_interface: AtomicUsize,
    param_vertex_interface: AtomicUsize,
    param_pixel_apply: AtomicUsize,
    param_vertex_apply: AtomicUsize,
    apply_calls: AtomicU32,
}

impl ShaderInterfaceCapture {
    fn new() -> Self {
        Self {
            apply_this: AtomicUsize::new(0),
            apply_param: AtomicUsize::new(0),
            apply_param_resource: AtomicUsize::new(0),
            current_geometry_slot: AtomicUsize::new(0),
            current_geometry: AtomicUsize::new(0),
            geometry_flags: AtomicU32::new(0),
            geometry_shader_args: AtomicUsize::new(0),
            geometry_state: AtomicUsize::new(0),
            geometry_state_value: AtomicUsize::new(0),
            geometry_context: AtomicU32::new(0),
            pass: AtomicUsize::new(0),
            vertex_shader: AtomicUsize::new(0),
            pixel_shader: AtomicUsize::new(0),
            selector_object: AtomicUsize::new(0),
            selector_pixel_interface: AtomicUsize::new(0),
            selector_vertex_interface: AtomicUsize::new(0),
            selector_pixel_apply: AtomicUsize::new(0),
            selector_vertex_apply: AtomicUsize::new(0),
            selector_pixel_alt_interface: AtomicUsize::new(0),
            selector_vertex_alt_interface: AtomicUsize::new(0),
            selector_pixel_alt_apply: AtomicUsize::new(0),
            selector_vertex_alt_apply: AtomicUsize::new(0),
            selector_pixel_active_copy_interface: AtomicUsize::new(0),
            selector_vertex_active_copy_interface: AtomicUsize::new(0),
            selector_pixel_active_copy_apply: AtomicUsize::new(0),
            selector_vertex_active_copy_apply: AtomicUsize::new(0),
            selector_material_generation: AtomicU32::new(0),
            selector_material_setup_kind: AtomicU32::new(0),
            selector_pass_entry_list: AtomicUsize::new(0),
            selector_material_arrays: array::from_fn(|_| AtomicUsize::new(0)),
            param_pixel_interface: AtomicUsize::new(0),
            param_vertex_interface: AtomicUsize::new(0),
            param_pixel_apply: AtomicUsize::new(0),
            param_vertex_apply: AtomicUsize::new(0),
            apply_calls: AtomicU32::new(0),
        }
    }

    fn clear(&self) {
        self.apply_this.store(0, Ordering::Release);
        self.apply_param.store(0, Ordering::Release);
        self.apply_param_resource.store(0, Ordering::Release);
        self.current_geometry_slot.store(0, Ordering::Release);
        self.current_geometry.store(0, Ordering::Release);
        self.geometry_flags.store(0, Ordering::Release);
        self.geometry_shader_args.store(0, Ordering::Release);
        self.geometry_state.store(0, Ordering::Release);
        self.geometry_state_value.store(0, Ordering::Release);
        self.geometry_context.store(0, Ordering::Release);
        self.pass.store(0, Ordering::Release);
        self.vertex_shader.store(0, Ordering::Release);
        self.pixel_shader.store(0, Ordering::Release);
        self.selector_object.store(0, Ordering::Release);
        self.selector_pixel_interface.store(0, Ordering::Release);
        self.selector_vertex_interface.store(0, Ordering::Release);
        self.selector_pixel_apply.store(0, Ordering::Release);
        self.selector_vertex_apply.store(0, Ordering::Release);
        self.selector_pixel_alt_interface
            .store(0, Ordering::Release);
        self.selector_vertex_alt_interface
            .store(0, Ordering::Release);
        self.selector_pixel_alt_apply.store(0, Ordering::Release);
        self.selector_vertex_alt_apply.store(0, Ordering::Release);
        self.selector_pixel_active_copy_interface
            .store(0, Ordering::Release);
        self.selector_vertex_active_copy_interface
            .store(0, Ordering::Release);
        self.selector_pixel_active_copy_apply
            .store(0, Ordering::Release);
        self.selector_vertex_active_copy_apply
            .store(0, Ordering::Release);
        self.selector_material_generation
            .store(0, Ordering::Release);
        self.selector_material_setup_kind
            .store(0, Ordering::Release);
        self.selector_pass_entry_list.store(0, Ordering::Release);
        for material_array in &self.selector_material_arrays {
            material_array.store(0, Ordering::Release);
        }
        self.param_pixel_interface.store(0, Ordering::Release);
        self.param_vertex_interface.store(0, Ordering::Release);
        self.param_pixel_apply.store(0, Ordering::Release);
        self.param_vertex_apply.store(0, Ordering::Release);
        self.apply_calls.store(0, Ordering::Release);
    }
}

struct SelectorCaptureTable {
    generation: AtomicU32,
    records: [SelectorCaptureRecord; SELECTOR_CAPTURE_SLOTS],
}

impl SelectorCaptureTable {
    fn new() -> Self {
        Self {
            generation: AtomicU32::new(1),
            records: array::from_fn(|_| SelectorCaptureRecord::new()),
        }
    }

    fn clear(&self) {
        self.generation.store(1, Ordering::Release);
        for record in &self.records {
            record.clear();
        }
    }

    fn store(&self, snapshot: SelectorCaptureSnapshot) {
        if snapshot.selector == 0 {
            return;
        }

        let index = self.find_or_replace_slot(snapshot.selector);
        self.records[index].store(snapshot);
    }

    fn find(&self, selector: usize) -> Option<SelectorCaptureSnapshot> {
        if selector == 0 {
            return None;
        }

        let start = selector_hash_slot(selector);
        for probe in 0..SELECTOR_CAPTURE_SLOTS {
            let index = (start + probe) % SELECTOR_CAPTURE_SLOTS;
            let record = &self.records[index];
            let key = record.selector.load(Ordering::Acquire);
            if key == selector {
                return record.snapshot();
            }
        }

        None
    }

    fn next_generation(&self) -> u32 {
        self.generation.fetch_add(1, Ordering::AcqRel)
    }

    fn find_or_replace_slot(&self, selector: usize) -> usize {
        let start = selector_hash_slot(selector);
        for probe in 0..SELECTOR_CAPTURE_SLOTS {
            let index = (start + probe) % SELECTOR_CAPTURE_SLOTS;
            let key = self.records[index].selector.load(Ordering::Acquire);
            if key == 0 || key == selector {
                return index;
            }
        }

        start
    }
}

struct SelectorCaptureRecord {
    selector: AtomicUsize,
    setup_kind: AtomicU32,
    generation: AtomicU32,
    flags: AtomicU32,
    pass_entry_list: AtomicUsize,
    material_arrays: [AtomicUsize; SELECTOR_MATERIAL_ARRAY_COUNT],
    setup_calls: AtomicU32,
}

impl SelectorCaptureRecord {
    fn new() -> Self {
        Self {
            selector: AtomicUsize::new(0),
            setup_kind: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            pass_entry_list: AtomicUsize::new(0),
            material_arrays: array::from_fn(|_| AtomicUsize::new(0)),
            setup_calls: AtomicU32::new(0),
        }
    }

    fn clear(&self) {
        self.selector.store(0, Ordering::Release);
        self.setup_kind.store(0, Ordering::Release);
        self.generation.store(0, Ordering::Release);
        self.flags.store(0, Ordering::Release);
        self.pass_entry_list.store(0, Ordering::Release);
        for material_array in &self.material_arrays {
            material_array.store(0, Ordering::Release);
        }
        self.setup_calls.store(0, Ordering::Release);
    }

    fn store(&self, snapshot: SelectorCaptureSnapshot) {
        self.selector.store(0, Ordering::Release);
        self.setup_kind
            .store(snapshot.setup_kind, Ordering::Release);
        self.generation
            .store(snapshot.generation, Ordering::Release);
        self.flags.store(snapshot.flags, Ordering::Release);
        self.pass_entry_list
            .store(snapshot.pass_entry_list, Ordering::Release);
        for (slot, value) in self
            .material_arrays
            .iter()
            .zip(snapshot.material_arrays.iter().copied())
        {
            slot.store(value, Ordering::Release);
        }
        self.setup_calls.fetch_add(1, Ordering::Relaxed);
        self.selector.store(snapshot.selector, Ordering::Release);
    }

    fn snapshot(&self) -> Option<SelectorCaptureSnapshot> {
        let selector = self.selector.load(Ordering::Acquire);
        if selector == 0 {
            return None;
        }

        Some(SelectorCaptureSnapshot {
            selector,
            setup_kind: self.setup_kind.load(Ordering::Acquire),
            generation: self.generation.load(Ordering::Acquire),
            flags: self.flags.load(Ordering::Acquire),
            pass_entry_list: self.pass_entry_list.load(Ordering::Acquire),
            material_arrays: array::from_fn(|index| {
                self.material_arrays[index].load(Ordering::Acquire)
            }),
        })
    }
}

#[derive(Clone, Copy)]
struct SelectorCaptureSnapshot {
    selector: usize,
    setup_kind: u32,
    generation: u32,
    flags: u32,
    pass_entry_list: usize,
    material_arrays: [usize; SELECTOR_MATERIAL_ARRAY_COUNT],
}

struct TextureResolveCache {
    resolver: AtomicUsize,
    records: [TextureResolveCacheRecord; TEXTURE_RESOLVE_CACHE_SLOTS],
}

impl TextureResolveCache {
    fn new() -> Self {
        Self {
            resolver: AtomicUsize::new(0),
            records: array::from_fn(|_| TextureResolveCacheRecord::new()),
        }
    }

    fn clear(&self) {
        self.resolver.store(0, Ordering::Release);
        for record in &self.records {
            record.clear();
        }
    }

    fn get(&self, resolver: *mut c_void, resource: *mut c_void) -> Option<*mut c_void> {
        let resolver_key = resolver as usize;
        let resource_key = resource as usize;
        if resolver_key == 0 || resource_key == 0 {
            return None;
        }

        if self.resolver.load(Ordering::Acquire) != resolver_key {
            return None;
        }

        let record = &self.records[texture_resolve_cache_slot(resource_key)];
        if record.resource.load(Ordering::Acquire) != resource_key {
            return None;
        }

        let resolved = record.resolved.load(Ordering::Acquire);
        if resolved == 0 {
            return None;
        }

        Some(resolved as *mut c_void)
    }

    fn store(&self, resolver: *mut c_void, resource: *mut c_void, resolved: *mut c_void) {
        let resolver_key = resolver as usize;
        let resource_key = resource as usize;
        let resolved_key = resolved as usize;
        if resolver_key == 0 || resource_key == 0 || resolved_key == 0 {
            return;
        }

        if self.resolver.load(Ordering::Acquire) != resolver_key {
            self.clear();
            self.resolver.store(resolver_key, Ordering::Release);
        }

        let record = &self.records[texture_resolve_cache_slot(resource_key)];
        record.resource.store(0, Ordering::Release);
        record.resolved.store(resolved_key, Ordering::Release);
        record.resource.store(resource_key, Ordering::Release);
    }
}

struct TextureResolveCacheRecord {
    resource: AtomicUsize,
    resolved: AtomicUsize,
}

impl TextureResolveCacheRecord {
    fn new() -> Self {
        Self {
            resource: AtomicUsize::new(0),
            resolved: AtomicUsize::new(0),
        }
    }

    fn clear(&self) {
        self.resource.store(0, Ordering::Release);
        self.resolved.store(0, Ordering::Release);
    }
}

fn texture_resolve_cache_slot(resource: usize) -> usize {
    (resource >> 4) % TEXTURE_RESOLVE_CACHE_SLOTS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementShaderKind {
    AdtsOptLod,
    AdtsSpecular,
    Adts10Lights4,
    LandLod,
}

impl ReplacementShaderKind {
    fn source_name(self) -> &'static str {
        match self {
            Self::AdtsOptLod => "native_pbr_pplighting_adts_lod.hlsl",
            Self::AdtsSpecular => "native_pbr_pplighting.hlsl",
            Self::Adts10Lights4 => "native_pbr_pplighting_adts10.hlsl",
            Self::LandLod => "native_pbr_pplighting_landlod.hlsl",
        }
    }

    fn source(self) -> &'static [u8] {
        match self {
            Self::AdtsOptLod => PBR_REPLACEMENT_ADTS_LOD_PIXEL_SHADER,
            Self::AdtsSpecular => PBR_REPLACEMENT_PIXEL_SHADER,
            Self::Adts10Lights4 => PBR_REPLACEMENT_ADTS10_PIXEL_SHADER,
            Self::LandLod => PBR_REPLACEMENT_LANDLOD_PIXEL_SHADER,
        }
    }

    fn vertex_source_name(self) -> Option<&'static str> {
        match self {
            Self::AdtsOptLod | Self::AdtsSpecular | Self::Adts10Lights4 => None,
            Self::LandLod => Some("native_pbr_pplighting_landlod.vs.hlsl"),
        }
    }

    fn vertex_source(self) -> Option<&'static [u8]> {
        match self {
            Self::AdtsOptLod | Self::AdtsSpecular | Self::Adts10Lights4 => None,
            Self::LandLod => Some(PBR_REPLACEMENT_LANDLOD_VERTEX_SHADER),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::AdtsOptLod => "adts_opt_lod",
            Self::AdtsSpecular => "adts_specular",
            Self::Adts10Lights4 => "adts10_lights4",
            Self::LandLod => "landlod",
        }
    }

    fn cached_device(self) -> &'static AtomicUsize {
        match self {
            Self::AdtsOptLod => &REPLACEMENT_ADTS_LOD_PIXEL_SHADER_DEVICE,
            Self::AdtsSpecular => &REPLACEMENT_ADTS_SPECULAR_PIXEL_SHADER_DEVICE,
            Self::Adts10Lights4 => &REPLACEMENT_ADTS10_LIGHTS4_PIXEL_SHADER_DEVICE,
            Self::LandLod => &REPLACEMENT_LANDLOD_PIXEL_SHADER_DEVICE,
        }
    }

    fn cached_handle(self) -> &'static AtomicUsize {
        match self {
            Self::AdtsOptLod => &REPLACEMENT_ADTS_LOD_PIXEL_SHADER_HANDLE,
            Self::AdtsSpecular => &REPLACEMENT_ADTS_SPECULAR_PIXEL_SHADER_HANDLE,
            Self::Adts10Lights4 => &REPLACEMENT_ADTS10_LIGHTS4_PIXEL_SHADER_HANDLE,
            Self::LandLod => &REPLACEMENT_LANDLOD_PIXEL_SHADER_HANDLE,
        }
    }

    fn cached_vertex_device(self) -> Option<&'static AtomicUsize> {
        match self {
            Self::AdtsOptLod | Self::AdtsSpecular | Self::Adts10Lights4 => None,
            Self::LandLod => Some(&REPLACEMENT_LANDLOD_VERTEX_SHADER_DEVICE),
        }
    }

    fn cached_vertex_handle(self) -> Option<&'static AtomicUsize> {
        match self {
            Self::AdtsOptLod | Self::AdtsSpecular | Self::Adts10Lights4 => None,
            Self::LandLod => Some(&REPLACEMENT_LANDLOD_VERTEX_SHADER_HANDLE),
        }
    }

    fn replaces_vertex_shader(self) -> bool {
        self.vertex_source().is_some()
    }

    fn uses_extra_material_stages(self) -> bool {
        match self {
            Self::AdtsOptLod | Self::AdtsSpecular | Self::Adts10Lights4 | Self::LandLod => false,
        }
    }

    fn writes_material_flags(self) -> bool {
        match self {
            Self::AdtsOptLod => false,
            Self::AdtsSpecular | Self::Adts10Lights4 => true,
            Self::LandLod => false,
        }
    }
}

struct PbrReplacementState {
    device: usize,
    adts_lod: PbrShaderSlot,
    adts_specular: PbrShaderSlot,
    adts10_lights4: PbrShaderSlot,
    landlod: PbrShaderSlot,
    landlod_vertex: PbrVertexShaderSlot,
}

impl PbrReplacementState {
    fn new() -> Self {
        Self {
            device: 0,
            adts_lod: PbrShaderSlot::new(),
            adts_specular: PbrShaderSlot::new(),
            adts10_lights4: PbrShaderSlot::new(),
            landlod: PbrShaderSlot::new(),
            landlod_vertex: PbrVertexShaderSlot::new(),
        }
    }

    fn release(&mut self) {
        self.device = 0;
        self.adts_lod.release();
        self.adts_specular.release();
        self.adts10_lights4.release();
        self.landlod.release();
        self.landlod_vertex.release();
        REPLACEMENT_ADTS_LOD_PIXEL_SHADER_DEVICE.store(0, Ordering::Release);
        REPLACEMENT_ADTS_LOD_PIXEL_SHADER_HANDLE.store(0, Ordering::Release);
        REPLACEMENT_ADTS_SPECULAR_PIXEL_SHADER_DEVICE.store(0, Ordering::Release);
        REPLACEMENT_ADTS_SPECULAR_PIXEL_SHADER_HANDLE.store(0, Ordering::Release);
        REPLACEMENT_ADTS10_LIGHTS4_PIXEL_SHADER_DEVICE.store(0, Ordering::Release);
        REPLACEMENT_ADTS10_LIGHTS4_PIXEL_SHADER_HANDLE.store(0, Ordering::Release);
        REPLACEMENT_LANDLOD_PIXEL_SHADER_DEVICE.store(0, Ordering::Release);
        REPLACEMENT_LANDLOD_PIXEL_SHADER_HANDLE.store(0, Ordering::Release);
        REPLACEMENT_LANDLOD_VERTEX_SHADER_DEVICE.store(0, Ordering::Release);
        REPLACEMENT_LANDLOD_VERTEX_SHADER_HANDLE.store(0, Ordering::Release);
    }

    fn pixel_shader_handle(
        &mut self,
        kind: ReplacementShaderKind,
        device: &Device9Ref<'_>,
        device_ptr: usize,
    ) -> Option<*mut c_void> {
        if self.device != device_ptr {
            self.release();
            self.device = device_ptr;
        }

        self.slot_mut(kind)
            .pixel_shader_handle(kind, device, device_ptr)
    }

    fn vertex_shader_handle(
        &mut self,
        kind: ReplacementShaderKind,
        device: &Device9Ref<'_>,
        device_ptr: usize,
    ) -> Option<*mut c_void> {
        if self.device != device_ptr {
            self.release();
            self.device = device_ptr;
        }

        match kind {
            ReplacementShaderKind::AdtsOptLod
            | ReplacementShaderKind::AdtsSpecular
            | ReplacementShaderKind::Adts10Lights4 => None,
            ReplacementShaderKind::LandLod => self
                .landlod_vertex
                .vertex_shader_handle(kind, device, device_ptr),
        }
    }

    fn slot_mut(&mut self, kind: ReplacementShaderKind) -> &mut PbrShaderSlot {
        match kind {
            ReplacementShaderKind::AdtsOptLod => &mut self.adts_lod,
            ReplacementShaderKind::AdtsSpecular => &mut self.adts_specular,
            ReplacementShaderKind::Adts10Lights4 => &mut self.adts10_lights4,
            ReplacementShaderKind::LandLod => &mut self.landlod,
        }
    }
}

struct PbrShaderSlot {
    bytecode: Option<Vec<u32>>,
    pixel_shader: Option<PixelShader9>,
    compile_failed: bool,
}

impl PbrShaderSlot {
    fn new() -> Self {
        Self {
            bytecode: None,
            pixel_shader: None,
            compile_failed: false,
        }
    }

    fn release(&mut self) {
        self.pixel_shader = None;
    }

    fn pixel_shader_handle(
        &mut self,
        kind: ReplacementShaderKind,
        device: &Device9Ref<'_>,
        device_ptr: usize,
    ) -> Option<*mut c_void> {
        if let Some(pixel_shader) = &self.pixel_shader {
            return Some(pixel_shader.as_raw());
        }

        if self.compile_failed {
            return None;
        }

        if self.bytecode.is_none() {
            match crate::shaders::compile_hlsl_source(kind.source_name(), kind.source()) {
                Ok(bytecode) => {
                    self.bytecode = Some(bytecode);
                }
                Err(err) => {
                    self.compile_failed = true;
                    log_limited(
                        &REPLACEMENT_RESOURCE_LOGS,
                        &format!(
                            "[PBR] Embedded native PBR {} pixel shader compile failed: {err:#}",
                            kind.label()
                        ),
                    );
                    return None;
                }
            }
        }

        let Some(bytecode) = self.bytecode.as_deref() else {
            return None;
        };

        match device.create_pixel_shader(bytecode) {
            Ok(pixel_shader) => {
                let handle = pixel_shader.as_raw();
                self.pixel_shader = Some(pixel_shader);
                kind.cached_device().store(device_ptr, Ordering::Release);
                kind.cached_handle()
                    .store(handle as usize, Ordering::Release);
                log::info!(
                    "[PBR] Embedded native PBR {} pixel shader created",
                    kind.label()
                );
                Some(handle)
            }
            Err(err) => {
                log_limited(
                    &REPLACEMENT_RESOURCE_LOGS,
                    &format!(
                        "[PBR] Embedded native PBR {} pixel shader creation failed: {err:?}",
                        kind.label()
                    ),
                );
                None
            }
        }
    }
}

struct PbrVertexShaderSlot {
    bytecode: Option<Vec<u32>>,
    vertex_shader: Option<VertexShader9>,
    compile_failed: bool,
}

impl PbrVertexShaderSlot {
    fn new() -> Self {
        Self {
            bytecode: None,
            vertex_shader: None,
            compile_failed: false,
        }
    }

    fn release(&mut self) {
        self.vertex_shader = None;
    }

    fn vertex_shader_handle(
        &mut self,
        kind: ReplacementShaderKind,
        device: &Device9Ref<'_>,
        device_ptr: usize,
    ) -> Option<*mut c_void> {
        if let Some(vertex_shader) = &self.vertex_shader {
            return Some(vertex_shader.as_raw());
        }

        if self.compile_failed {
            return None;
        }

        if self.bytecode.is_none() {
            let source_name = kind.vertex_source_name()?;
            let source = kind.vertex_source()?;
            match crate::shaders::compile_hlsl_source_target(source_name, source, "vs_3_0") {
                Ok(bytecode) => {
                    self.bytecode = Some(bytecode);
                }
                Err(err) => {
                    self.compile_failed = true;
                    log_limited(
                        &REPLACEMENT_RESOURCE_LOGS,
                        &format!(
                            "[PBR] Embedded native PBR {} vertex shader compile failed: {err:#}",
                            kind.label()
                        ),
                    );
                    return None;
                }
            }
        }

        let Some(bytecode) = self.bytecode.as_deref() else {
            return None;
        };

        match device.create_vertex_shader(bytecode) {
            Ok(vertex_shader) => {
                let handle = vertex_shader.as_raw();
                self.vertex_shader = Some(vertex_shader);
                if let Some(cached_device) = kind.cached_vertex_device() {
                    cached_device.store(device_ptr, Ordering::Release);
                }
                if let Some(cached_handle) = kind.cached_vertex_handle() {
                    cached_handle.store(handle as usize, Ordering::Release);
                }
                log::info!(
                    "[PBR] Embedded native PBR {} vertex shader created",
                    kind.label()
                );
                Some(handle)
            }
            Err(err) => {
                log_limited(
                    &REPLACEMENT_RESOURCE_LOGS,
                    &format!(
                        "[PBR] Embedded native PBR {} vertex shader creation failed: {err:?}",
                        kind.label()
                    ),
                );
                None
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ReplacementDrawContext {
    pass: *mut c_void,
    vertex_shader: *mut c_void,
    pixel_shader: *mut c_void,
    vertex_membership: ShaderArrayMembership,
    pixel_membership: ShaderArrayMembership,
    family: u32,
}

#[derive(Clone, Copy)]
struct ReplacementMaterialResources {
    selector: usize,
    generation: u32,
    normal: *mut c_void,
    glow: *mut c_void,
    height: *mut c_void,
    environment: *mut c_void,
    environment_mask: *mut c_void,
}

#[derive(Clone, Copy)]
struct ReplacementMaterialBindings {
    selector: usize,
    generation: u32,
    has_normal: bool,
    has_glow: bool,
    has_height: bool,
    has_environment: bool,
    has_environment_mask: bool,
}

#[derive(Clone, Copy)]
enum ReplacementSkipReason {
    NoDiffuse,
    NoDrawContext,
    UnsupportedFamily,
    UnsupportedVertexAbi,
    NoSelectorRecord,
    NoNormalSource,
    NoReplacementShader,
    BindFailed,
    NoVanillaHandle,
    HandleWriteFailed,
}

impl ReplacementSkipReason {
    fn label(self) -> &'static str {
        match self {
            Self::NoDiffuse => "no_diffuse",
            Self::NoDrawContext => "no_draw_context",
            Self::UnsupportedFamily => "unsupported_family",
            Self::UnsupportedVertexAbi => "unsupported_vertex_abi",
            Self::NoSelectorRecord => "no_selector_record",
            Self::NoNormalSource => "no_normal_source",
            Self::NoReplacementShader => "no_replacement_shader",
            Self::BindFailed => "bind_failed",
            Self::NoVanillaHandle => "no_vanilla_handle",
            Self::HandleWriteFailed => "handle_write_failed",
        }
    }
}

enum ReplacementMaterialResourceError {
    NoSelectorRecord,
    NoNormalSource,
}

fn selector_hash_slot(selector: usize) -> usize {
    (selector >> 4) % SELECTOR_CAPTURE_SLOTS
}

pub(crate) fn install(settings: NativePbrSettings) -> Result<()> {
    configure_runtime_options(settings);

    if REQUIRE_VANILLA_PROLOGUES && !verify_hook_prologues() {
        HOOKS_ACTIVE.store(false, Ordering::Release);
        log::warn!("[PBR] Native PBR hooks skipped because a target prologue is not vanilla");
        return Ok(());
    }

    if INSTALLED.swap(true, Ordering::AcqRel) {
        HOOKS_ACTIVE.store(true, Ordering::Release);
        log::info!("[PBR] Native PBR hooks already installed");
        return Ok(());
    }

    if !install_selector_setup_hooks() {
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        return Ok(());
    }

    if !install_set_texture_hook() {
        disable_all_hooks();
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        return Ok(());
    }

    if !install_set_shaders_hook() {
        disable_all_hooks();
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        return Ok(());
    }

    if !install_pass_shader_apply_hook() {
        disable_all_hooks();
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        return Ok(());
    }

    HOOKS_ACTIVE.store(true, Ordering::Release);
    log::info!("[PBR] Native PBR selector, draw, texture, and shader-interface hooks installed");

    if settings.enabled {
        log::info!(
            "[PBR] Native PBR material shader enabled for proven PPLighting material and land LOD variants"
        );
    }

    Ok(())
}

pub(crate) fn configure_runtime_options(settings: NativePbrSettings) {
    let installed = INSTALLED.load(Ordering::Acquire);
    HOOKS_ACTIVE.store(installed, Ordering::Release);
    PBR_ROUGHNESS_SCALE_BITS.store(
        sanitize_pbr_scale(settings.roughness_scale, 1.0, 0.05, 4.0).to_bits(),
        Ordering::Release,
    );
    PBR_LIGHT_SCALE_BITS.store(
        sanitize_pbr_scale(settings.light_scale, 1.0, 0.0, 4.0).to_bits(),
        Ordering::Release,
    );
    PBR_AMBIENT_SCALE_BITS.store(
        sanitize_pbr_scale(settings.ambient_scale, 1.0, 0.0, 4.0).to_bits(),
        Ordering::Release,
    );
    PBR_ALBEDO_SATURATION_BITS.store(
        sanitize_pbr_scale(settings.albedo_saturation, 1.0, 0.0, 2.0).to_bits(),
        Ordering::Release,
    );

    let debug_was_enabled = DEBUG_LOG_DRAWS.swap(settings.debug_log_draws, Ordering::AcqRel);
    let material_was_enabled = MATERIAL_SHADER_ENABLED.swap(settings.enabled, Ordering::AcqRel);

    if settings.debug_log_draws && !debug_was_enabled {
        reset_debug_capture_budget();
    }
    if settings.enabled && !material_was_enabled {
        reset_replacement_skip_budget();
    }
}

pub(crate) fn runtime_status() -> NativePbrRuntimeStatus {
    NativePbrRuntimeStatus {
        installed: INSTALLED.load(Ordering::Acquire),
        shader_enabled: MATERIAL_SHADER_ENABLED.load(Ordering::Acquire),
    }
}

pub(crate) fn reset_runtime_state() {
    TEXTURE_CAPTURE.clear();
    DRAW_CAPTURE.clear();
    INTERFACE_CAPTURE.clear();
    SELECTOR_CAPTURE.clear();
    TEXTURE_RESOLVE_CACHE.clear();
    reset_replacement_skip_budget();
    PBR_REPLACEMENT.lock().release();
}

fn disable_all_hooks() {
    let _ = PASS_SHADER_APPLY_HOOK.disable();
    let _ = SET_SHADERS_HOOK.disable();
    let _ = SET_TEXTURE_HOOK.disable();
    let _ = SELECTOR_SETUP_MAIN_HOOK.disable();
    let _ = SELECTOR_SETUP_VARIANT_HOOK.disable();
}

fn install_selector_setup_hooks() -> bool {
    if !install_selector_setup_variant_hook() {
        return false;
    }

    if !install_selector_setup_main_hook() {
        let _ = SELECTOR_SETUP_VARIANT_HOOK.disable();
        return false;
    }

    true
}

fn install_selector_setup_variant_hook() -> bool {
    match SELECTOR_SETUP_VARIANT_HOOK.init(
        "FNV PPLighting selector setup +0xF0",
        PPLIGHTING_SELECTOR_SETUP_VARIANT_ADDR as *mut c_void,
        hook_selector_setup_variant,
    ) {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[PBR] PPLighting selector setup +0xF0 hook skipped at 0x{PPLIGHTING_SELECTOR_SETUP_VARIANT_ADDR:08X}: {err}"
            );
            return false;
        }
    }

    match SELECTOR_SETUP_VARIANT_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!(
                "[PBR] PPLighting selector setup +0xF0 hook skipped at 0x{PPLIGHTING_SELECTOR_SETUP_VARIANT_ADDR:08X}: {err}"
            );
            false
        }
    }
}

fn install_selector_setup_main_hook() -> bool {
    match SELECTOR_SETUP_MAIN_HOOK.init(
        "FNV PPLighting selector setup +0xF4",
        PPLIGHTING_SELECTOR_SETUP_MAIN_ADDR as *mut c_void,
        hook_selector_setup_main,
    ) {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[PBR] PPLighting selector setup +0xF4 hook skipped at 0x{PPLIGHTING_SELECTOR_SETUP_MAIN_ADDR:08X}: {err}"
            );
            return false;
        }
    }

    match SELECTOR_SETUP_MAIN_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!(
                "[PBR] PPLighting selector setup +0xF4 hook skipped at 0x{PPLIGHTING_SELECTOR_SETUP_MAIN_ADDR:08X}: {err}"
            );
            false
        }
    }
}

fn install_set_texture_hook() -> bool {
    match SET_TEXTURE_HOOK.init(
        "FNV NiDX9RenderState::SetTexture",
        NIDX9_RENDER_STATE_SET_TEXTURE_ADDR as *mut c_void,
        hook_set_texture,
    ) {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[PBR] SetTexture hook skipped at 0x{NIDX9_RENDER_STATE_SET_TEXTURE_ADDR:08X}: {err}"
            );
            return false;
        }
    }

    match SET_TEXTURE_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!(
                "[PBR] SetTexture hook skipped at 0x{NIDX9_RENDER_STATE_SET_TEXTURE_ADDR:08X}: {err}"
            );
            false
        }
    }
}

fn install_set_shaders_hook() -> bool {
    match SET_SHADERS_HOOK.init(
        "FNV BSShader::SetShaders",
        BS_SHADER_SET_SHADERS_ADDR as *mut c_void,
        hook_set_shaders,
    ) {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[PBR] SetShaders hook skipped at 0x{BS_SHADER_SET_SHADERS_ADDR:08X}: {err}"
            );
            return false;
        }
    }

    match SET_SHADERS_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!(
                "[PBR] SetShaders hook skipped at 0x{BS_SHADER_SET_SHADERS_ADDR:08X}: {err}"
            );
            false
        }
    }
}

fn install_pass_shader_apply_hook() -> bool {
    match PASS_SHADER_APPLY_HOOK.init(
        "FNV current pass shader-interface apply",
        CURRENT_PASS_SHADER_APPLY_ADDR as *mut c_void,
        hook_pass_shader_apply,
    ) {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[PBR] Pass shader-interface hook skipped at 0x{CURRENT_PASS_SHADER_APPLY_ADDR:08X}: {err}"
            );
            return false;
        }
    }

    match PASS_SHADER_APPLY_HOOK.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!(
                "[PBR] Pass shader-interface hook skipped at 0x{CURRENT_PASS_SHADER_APPLY_ADDR:08X}: {err}"
            );
            false
        }
    }
}

fn verify_hook_prologues() -> bool {
    let set_shaders_ok = target_bytes_match(
        BS_SHADER_SET_SHADERS_ADDR,
        SET_SHADERS_PROLOGUE,
        "SetShaders",
    );
    let set_texture_ok = target_bytes_match(
        NIDX9_RENDER_STATE_SET_TEXTURE_ADDR,
        SET_TEXTURE_PROLOGUE,
        "SetTexture",
    );
    let pass_shader_apply_ok = target_bytes_match(
        CURRENT_PASS_SHADER_APPLY_ADDR,
        PASS_SHADER_APPLY_PROLOGUE,
        "PassShaderApply",
    );
    let selector_setup_variant_ok = target_bytes_match(
        PPLIGHTING_SELECTOR_SETUP_VARIANT_ADDR,
        SELECTOR_SETUP_VARIANT_PROLOGUE,
        "PPLightingSelectorSetupF0",
    );
    let selector_setup_main_ok = target_bytes_match(
        PPLIGHTING_SELECTOR_SETUP_MAIN_ADDR,
        SELECTOR_SETUP_MAIN_PROLOGUE,
        "PPLightingSelectorSetupF4",
    );

    set_shaders_ok
        && set_texture_ok
        && pass_shader_apply_ok
        && selector_setup_variant_ok
        && selector_setup_main_ok
}

fn target_bytes_match(addr: usize, expected: &[u8], label: &str) -> bool {
    let ptr = addr as *const c_void;
    if let Err(err) = validate_memory_range(ptr, expected.len()) {
        log::warn!("[PBR] Cannot read {label} prologue at 0x{addr:08X}: {err}");
        return false;
    }

    let actual = unsafe { slice::from_raw_parts(addr as *const u8, expected.len()) };
    if actual == expected {
        return true;
    }

    log::warn!(
        "[PBR] {label} prologue mismatch at 0x{addr:08X}; another graphics mod may already own this hook"
    );
    false
}

unsafe extern "thiscall" fn hook_set_texture(
    render_state: *mut c_void,
    stage: u32,
    texture: *mut c_void,
) {
    let Ok(original) = SET_TEXTURE_HOOK.original() else {
        log_limited(&TEXTURE_LOGS, "[PBR] Missing original SetTexture function");
        return;
    };

    unsafe {
        original(render_state, stage, texture);
    }

    record_texture_binding(render_state, stage, texture);
}

unsafe extern "thiscall" fn hook_selector_setup_variant(
    selector: *mut c_void,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    arg7: usize,
) {
    let Ok(original) = SELECTOR_SETUP_VARIANT_HOOK.original() else {
        log_limited(
            &SELECTOR_LOGS,
            "[PBR] Missing original PPLighting selector setup +0xF0 function",
        );
        return;
    };

    let capture = HOOKS_ACTIVE.load(Ordering::Acquire) && should_capture_selector_context();
    if capture {
        unsafe {
            record_selector_material_context(selector, SELECTOR_SETUP_VARIANT_KIND);
        }
    }

    unsafe {
        original(selector, arg2, arg3, arg4, arg5, arg6, arg7);
    }

    if capture {
        unsafe {
            record_selector_material_context(selector, SELECTOR_SETUP_VARIANT_KIND);
        }
    }
}

unsafe extern "thiscall" fn hook_selector_setup_main(
    selector: *mut c_void,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    arg7: usize,
) {
    let Ok(original) = SELECTOR_SETUP_MAIN_HOOK.original() else {
        log_limited(
            &SELECTOR_LOGS,
            "[PBR] Missing original PPLighting selector setup +0xF4 function",
        );
        return;
    };

    let capture = HOOKS_ACTIVE.load(Ordering::Acquire) && should_capture_selector_context();
    if capture {
        unsafe {
            record_selector_material_context(selector, SELECTOR_SETUP_MAIN_KIND);
        }
    }

    unsafe {
        original(selector, arg2, arg3, arg4, arg5, arg6, arg7);
    }

    if capture {
        unsafe {
            record_selector_material_context(selector, SELECTOR_SETUP_MAIN_KIND);
        }
    }
}

unsafe extern "thiscall" fn hook_set_shaders(shader: *mut c_void, pass_index: u32) {
    let hooks_active = HOOKS_ACTIVE.load(Ordering::Acquire);
    if hooks_active {
        if should_capture_draw_context() {
            unsafe {
                record_draw_context(pass_index);
            }
        }
    }

    let Ok(original) = SET_SHADERS_HOOK.original() else {
        log_limited(&DRAW_LOGS, "[PBR] Missing original SetShaders function");
        return;
    };

    if hooks_active
        && MATERIAL_SHADER_ENABLED.load(Ordering::Acquire)
        && unsafe { call_set_shaders_with_replacement(original, shader, pass_index) }
    {
        return;
    }

    unsafe {
        original(shader, pass_index);
    }
}

unsafe extern "thiscall" fn hook_pass_shader_apply(
    apply_this: *mut c_void,
    apply_param: *mut c_void,
) {
    if HOOKS_ACTIVE.load(Ordering::Acquire) && should_capture_shader_interface_context() {
        unsafe {
            record_shader_interface_context(apply_this, apply_param);
        }
    }

    let Ok(original) = PASS_SHADER_APPLY_HOOK.original() else {
        log_limited(
            &INTERFACE_LOGS,
            "[PBR] Missing original pass shader-interface apply function",
        );
        return;
    };

    unsafe {
        original(apply_this, apply_param);
    }
}

unsafe fn call_set_shaders_with_replacement(
    original: SetShadersFn,
    shader: *mut c_void,
    pass_index: u32,
) -> bool {
    if !required_diffuse_stage_bound() {
        record_replacement_skip(ReplacementSkipReason::NoDiffuse, None);
        return false;
    }

    let Some(draw_context) = (unsafe { replacement_draw_context() }) else {
        record_replacement_skip(ReplacementSkipReason::NoDrawContext, None);
        return false;
    };

    let shader_kind = match replacement_shader_kind(draw_context) {
        Ok(shader_kind) => shader_kind,
        Err(reason) => {
            record_replacement_skip(reason, Some(draw_context));
            return false;
        }
    };

    let material_resources = match unsafe { replacement_material_resources(shader_kind) } {
        Ok(material_resources) => material_resources,
        Err(ReplacementMaterialResourceError::NoSelectorRecord) => {
            record_replacement_skip(ReplacementSkipReason::NoSelectorRecord, Some(draw_context));
            return false;
        }
        Err(ReplacementMaterialResourceError::NoNormalSource) => {
            record_replacement_skip(ReplacementSkipReason::NoNormalSource, Some(draw_context));
            return false;
        }
    };

    let Some(replacement_pixel_handle) = replacement_pixel_shader_handle(shader_kind) else {
        record_replacement_skip(
            ReplacementSkipReason::NoReplacementShader,
            Some(draw_context),
        );
        return false;
    };
    if replacement_pixel_handle.is_null() {
        record_replacement_skip(
            ReplacementSkipReason::NoReplacementShader,
            Some(draw_context),
        );
        return false;
    }

    let replacement_vertex_handle = if shader_kind.replaces_vertex_shader() {
        let Some(handle) = replacement_vertex_shader_handle(shader_kind) else {
            record_replacement_skip(
                ReplacementSkipReason::NoReplacementShader,
                Some(draw_context),
            );
            return false;
        };
        if handle.is_null() {
            record_replacement_skip(
                ReplacementSkipReason::NoReplacementShader,
                Some(draw_context),
            );
            return false;
        }
        handle
    } else {
        null_mut()
    };

    let Some(material_bindings) =
        (unsafe { bind_replacement_material_textures(material_resources, shader_kind) })
    else {
        record_replacement_skip(ReplacementSkipReason::BindFailed, Some(draw_context));
        return false;
    };

    let original_pixel_handle = unsafe {
        read_shader_native_handle(
            draw_context.pixel_shader,
            NID3D_PIXEL_SHADER_VTABLE_ADDR,
            PIXEL_SHADER_NATIVE_HANDLE_OFFSET,
        )
    };
    if original_pixel_handle.is_null() || original_pixel_handle == replacement_pixel_handle {
        record_replacement_skip(ReplacementSkipReason::NoVanillaHandle, Some(draw_context));
        return false;
    }

    let original_vertex_handle = if shader_kind.replaces_vertex_shader() {
        let handle = unsafe {
            read_shader_native_handle(
                draw_context.vertex_shader,
                NID3D_VERTEX_SHADER_VTABLE_ADDR,
                VERTEX_SHADER_SET_SHADERS_HANDLE_OFFSET,
            )
        };
        if handle.is_null() || handle == replacement_vertex_handle {
            record_replacement_skip(ReplacementSkipReason::NoVanillaHandle, Some(draw_context));
            return false;
        }
        handle
    } else {
        null_mut()
    };

    if !unsafe {
        write_shader_native_handle(
            draw_context.pixel_shader,
            PIXEL_SHADER_NATIVE_HANDLE_OFFSET,
            replacement_pixel_handle,
        )
    } {
        log_limited(
            &REPLACEMENT_LOGS,
            "[PBR] Native PBR replacement skipped because the pixel shader handle slot is not writable",
        );
        record_replacement_skip(ReplacementSkipReason::HandleWriteFailed, Some(draw_context));
        return false;
    }

    if shader_kind.replaces_vertex_shader()
        && !unsafe {
            write_shader_native_handle(
                draw_context.vertex_shader,
                VERTEX_SHADER_SET_SHADERS_HANDLE_OFFSET,
                replacement_vertex_handle,
            )
        }
    {
        let _ = unsafe {
            write_shader_native_handle(
                draw_context.pixel_shader,
                PIXEL_SHADER_NATIVE_HANDLE_OFFSET,
                original_pixel_handle,
            )
        };
        log_limited(
            &REPLACEMENT_LOGS,
            "[PBR] Native PBR replacement skipped because the vertex shader handle slot is not writable",
        );
        record_replacement_skip(ReplacementSkipReason::HandleWriteFailed, Some(draw_context));
        return false;
    }

    log_replacement_apply(
        shader_kind,
        draw_context,
        pass_index,
        original_pixel_handle,
        replacement_pixel_handle,
        original_vertex_handle,
        replacement_vertex_handle,
        material_bindings,
    );

    unsafe {
        original(shader, pass_index);
    }

    if !force_replacement_pixel_shader(replacement_pixel_handle) {
        log_limited(
            &REPLACEMENT_LOGS,
            "[PBR] Native PBR replacement could not force the final D3D pixel shader state",
        );
    }
    if shader_kind.replaces_vertex_shader()
        && !force_replacement_vertex_shader(replacement_vertex_handle)
    {
        log_limited(
            &REPLACEMENT_LOGS,
            "[PBR] Native PBR replacement could not force the final D3D vertex shader state",
        );
    }
    upload_replacement_material_constants(shader_kind, material_bindings);

    if !unsafe {
        write_shader_native_handle(
            draw_context.pixel_shader,
            PIXEL_SHADER_NATIVE_HANDLE_OFFSET,
            original_pixel_handle,
        )
    } {
        log_limited(
            &REPLACEMENT_LOGS,
            "[PBR] Native PBR replacement could not restore the vanilla pixel shader handle",
        );
    }
    if shader_kind.replaces_vertex_shader()
        && !unsafe {
            write_shader_native_handle(
                draw_context.vertex_shader,
                VERTEX_SHADER_SET_SHADERS_HANDLE_OFFSET,
                original_vertex_handle,
            )
        }
    {
        log_limited(
            &REPLACEMENT_LOGS,
            "[PBR] Native PBR replacement could not restore the vanilla vertex shader handle",
        );
    }

    true
}

fn force_replacement_pixel_shader(replacement_handle: *mut c_void) -> bool {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return false;
    };

    unsafe { device.set_raw_pixel_shader(replacement_handle) }.is_ok()
}

fn force_replacement_vertex_shader(replacement_handle: *mut c_void) -> bool {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return false;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return false;
    };

    unsafe { device.set_raw_vertex_shader(replacement_handle) }.is_ok()
}

unsafe fn replacement_draw_context() -> Option<ReplacementDrawContext> {
    let pass = unsafe { read_ptr(CURRENT_PASS_GLOBAL_ADDR) };
    if pass.is_null() {
        return None;
    }

    let vertex_shader = unsafe { read_ptr_offset(pass, PASS_VERTEX_SHADER_OFFSET) };
    let pixel_shader = unsafe { read_ptr_offset(pass, PASS_PIXEL_SHADER_OFFSET) };
    if vertex_shader.is_null() || pixel_shader.is_null() {
        return None;
    }

    let vertex_membership = unsafe {
        cached_shader_array_membership(
            vertex_shader,
            &PPLIGHTING_VERTEX_GROUPS,
            &VERTEX_SHADER_MEMBERSHIP_CACHE,
        )
    };
    let pixel_membership = unsafe {
        cached_shader_array_membership(
            pixel_shader,
            &PPLIGHTING_PIXEL_GROUPS,
            &PIXEL_SHADER_MEMBERSHIP_CACHE,
        )
    };
    let family = classify_pplighting_family(vertex_membership, pixel_membership);

    Some(ReplacementDrawContext {
        pass,
        vertex_shader,
        pixel_shader,
        vertex_membership,
        pixel_membership,
        family,
    })
}

fn replacement_shader_kind(
    draw_context: ReplacementDrawContext,
) -> std::result::Result<ReplacementShaderKind, ReplacementSkipReason> {
    if draw_context.family != PPLIGHTING_FAMILY_VERTEX_C_PIXEL_B {
        return Err(ReplacementSkipReason::UnsupportedFamily);
    }

    if pplighting_pair_uses_sls2_adts_opt_or_lod(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        return Ok(ReplacementShaderKind::AdtsOptLod);
    }

    if pplighting_pair_uses_sls2_landlod(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        return Ok(ReplacementShaderKind::LandLod);
    }

    if pplighting_pair_uses_sls2_adts_specular(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        return Ok(ReplacementShaderKind::AdtsSpecular);
    }

    if pplighting_pair_uses_sls2_adts10_lights4(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        return Ok(ReplacementShaderKind::Adts10Lights4);
    }

    Err(ReplacementSkipReason::UnsupportedVertexAbi)
}

fn pplighting_pair_uses_sls2_adts_opt_or_lod(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> bool {
    if vertex.group != PPLIGHTING_VERTEX_GROUP_C || pixel.group != PPLIGHTING_PIXEL_GROUP_B {
        return false;
    }

    (vertex.index == PPLIGHTING_VERTEX_SLS2_ADTS_BASE_INDEX
        && pixel.index == PPLIGHTING_PIXEL_SLS2_ADTS_OPT_INDEX)
        || (vertex.index == PPLIGHTING_VERTEX_SLS2_ADTS_LOD_INDEX
            && pixel.index == PPLIGHTING_PIXEL_SLS2_ADTS_OPT_LOD_INDEX)
}

fn pplighting_pair_uses_sls2_landlod(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> bool {
    vertex.group == PPLIGHTING_VERTEX_GROUP_C
        && vertex.index == PPLIGHTING_VERTEX_SLS2_LANDLOD_INDEX
        && pixel.group == PPLIGHTING_PIXEL_GROUP_B
        && pixel.index == PPLIGHTING_PIXEL_SLS2_LANDLOD_INDEX
}

fn pplighting_pair_uses_sls2_adts_specular(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> bool {
    vertex.group == PPLIGHTING_VERTEX_GROUP_C
        && (vertex.index == PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_INDEX
            || vertex.index == PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_SKIN_INDEX)
        && pixel.group == PPLIGHTING_PIXEL_GROUP_B
        && pixel.index == PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_INDEX
}

fn pplighting_pair_uses_sls2_adts10_lights4(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> bool {
    vertex.group == PPLIGHTING_VERTEX_GROUP_C
        && vertex.index == PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_INDEX
        && pixel.group == PPLIGHTING_PIXEL_GROUP_B
        && pixel.index == PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_INDEX
}

fn required_diffuse_stage_bound() -> bool {
    let diffuse = TEXTURE_CAPTURE.stages[0].load(Ordering::Acquire);
    diffuse != 0
}

fn replacement_pixel_shader_handle(kind: ReplacementShaderKind) -> Option<*mut c_void> {
    let device_ptr = crate::backend::d3d_device_ptr()?;
    let device_key = device_ptr as usize;
    let cached_device = kind.cached_device().load(Ordering::Acquire);
    let cached_handle = kind.cached_handle().load(Ordering::Acquire);
    if cached_device == device_key && cached_handle != 0 {
        return Some(cached_handle as *mut c_void);
    }

    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return None;
    };

    PBR_REPLACEMENT
        .lock()
        .pixel_shader_handle(kind, &device, device_key)
}

fn replacement_vertex_shader_handle(kind: ReplacementShaderKind) -> Option<*mut c_void> {
    if !kind.replaces_vertex_shader() {
        return None;
    }

    let device_ptr = crate::backend::d3d_device_ptr()?;
    let device_key = device_ptr as usize;
    if let (Some(cached_device), Some(cached_handle)) =
        (kind.cached_vertex_device(), kind.cached_vertex_handle())
    {
        let cached_device = cached_device.load(Ordering::Acquire);
        let cached_handle = cached_handle.load(Ordering::Acquire);
        if cached_device == device_key && cached_handle != 0 {
            return Some(cached_handle as *mut c_void);
        }
    }

    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return None;
    };

    PBR_REPLACEMENT
        .lock()
        .vertex_shader_handle(kind, &device, device_key)
}

fn record_texture_binding(render_state: *mut c_void, stage: u32, texture: *mut c_void) {
    if !HOOKS_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    if stage as usize >= MAX_TEXTURE_STAGES {
        log_limited(
            &TEXTURE_LOGS,
            "[PBR] Ignoring SetTexture call with stage outside the 16-slot native cache",
        );
        return;
    }

    let replacement_capture = MATERIAL_SHADER_ENABLED.load(Ordering::Acquire);
    let debug_capture = should_capture_texture_context();
    if !replacement_capture && !debug_capture {
        return;
    }
    if replacement_capture && !debug_capture && stage > 1 {
        return;
    }

    TEXTURE_CAPTURE
        .render_state
        .store(render_state as usize, Ordering::Release);
    TEXTURE_CAPTURE.stages[stage as usize].store(texture as usize, Ordering::Release);

    if !debug_capture {
        return;
    }

    let selector = unsafe { current_draw_selector() } as usize;
    let selector_generation = SELECTOR_CAPTURE
        .find(selector)
        .map_or(0, |snapshot| snapshot.generation);
    TEXTURE_CAPTURE
        .selector_object
        .store(selector, Ordering::Release);
    TEXTURE_CAPTURE
        .selector_generation
        .store(selector_generation, Ordering::Release);
    TEXTURE_CAPTURE.set_calls.fetch_add(1, Ordering::Relaxed);
}

fn should_capture_draw_context() -> bool {
    should_capture_debug_context(&DRAW_LOGS)
}

fn should_capture_shader_interface_context() -> bool {
    should_capture_debug_context(&INTERFACE_LOGS)
}

fn should_capture_selector_context() -> bool {
    MATERIAL_SHADER_ENABLED.load(Ordering::Acquire) || should_capture_debug_context(&SELECTOR_LOGS)
}

fn should_capture_texture_context() -> bool {
    DEBUG_LOG_DRAWS.load(Ordering::Acquire)
        && TEXTURE_CAPTURE.set_calls.load(Ordering::Acquire) < MAX_LOGS
}

fn should_capture_debug_context(counter: &AtomicU32) -> bool {
    DEBUG_LOG_DRAWS.load(Ordering::Acquire) && counter.load(Ordering::Acquire) < MAX_LOGS
}

fn reset_debug_capture_budget() {
    DRAW_LOGS.store(0, Ordering::Release);
    INTERFACE_LOGS.store(0, Ordering::Release);
    SELECTOR_LOGS.store(0, Ordering::Release);
    REPLACEMENT_UNSUPPORTED_PAIR_LOGS.store(0, Ordering::Release);
    TEXTURE_CAPTURE.set_calls.store(0, Ordering::Release);
}

fn reset_replacement_skip_budget() {
    REPLACEMENT_APPLIED_COUNT.store(0, Ordering::Release);
    REPLACEMENT_APPLY_LOGS.store(0, Ordering::Release);
    REPLACEMENT_SKIP_SUMMARY_LOGS.store(0, Ordering::Release);
    REPLACEMENT_SKIP_CHECKS.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_DIFFUSE.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_DRAW_CONTEXT.store(0, Ordering::Release);
    REPLACEMENT_SKIP_UNSUPPORTED_FAMILY.store(0, Ordering::Release);
    REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_SELECTOR_RECORD.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_NORMAL_SOURCE.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_REPLACEMENT_SHADER.store(0, Ordering::Release);
    REPLACEMENT_SKIP_BIND_FAILED.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_VANILLA_HANDLE.store(0, Ordering::Release);
    REPLACEMENT_SKIP_HANDLE_WRITE_FAILED.store(0, Ordering::Release);
    REPLACEMENT_LAST_FAMILY.store(PPLIGHTING_FAMILY_NONE, Ordering::Release);
    REPLACEMENT_LAST_VERTEX_GROUP.store(PPLIGHTING_GROUP_NONE, Ordering::Release);
    REPLACEMENT_LAST_VERTEX_INDEX.store(0, Ordering::Release);
    REPLACEMENT_LAST_PIXEL_GROUP.store(PPLIGHTING_GROUP_NONE, Ordering::Release);
    REPLACEMENT_LAST_PIXEL_INDEX.store(0, Ordering::Release);
}

unsafe fn record_selector_material_context(selector: *mut c_void, setup_kind: u32) {
    let Some(snapshot) = (unsafe {
        selector_material_snapshot(selector, setup_kind, SELECTOR_CAPTURE.next_generation())
    }) else {
        return;
    };

    SELECTOR_CAPTURE.store(snapshot);

    if DEBUG_LOG_DRAWS.load(Ordering::Acquire) {
        log_selector_material_context(snapshot);
    }
}

unsafe fn selector_material_snapshot(
    selector: *mut c_void,
    setup_kind: u32,
    generation: u32,
) -> Option<SelectorCaptureSnapshot> {
    if selector.is_null() {
        return None;
    }

    let selector_ptr = selector as *const c_void;
    if !silent_readable_range(
        selector_ptr,
        SELECTOR_MATERIAL_ARRAY_OFFSETS[5] + size_of::<usize>(),
    ) {
        return None;
    }

    let flags = unsafe { read_u32_offset(selector, SELECTOR_FLAGS_OFFSET) };
    let pass_entry_list =
        unsafe { read_ptr_offset(selector, SELECTOR_PASS_ENTRY_LIST_OFFSET) } as usize;
    let material_arrays = array::from_fn(|index| unsafe {
        read_ptr_offset(selector, SELECTOR_MATERIAL_ARRAY_OFFSETS[index]) as usize
    });

    Some(SelectorCaptureSnapshot {
        selector: selector as usize,
        setup_kind,
        generation,
        flags,
        pass_entry_list,
        material_arrays,
    })
}

unsafe fn replacement_material_resources(
    shader_kind: ReplacementShaderKind,
) -> Result<ReplacementMaterialResources, ReplacementMaterialResourceError> {
    let selector = unsafe { current_draw_selector() } as usize;
    let vanilla_normal = TEXTURE_CAPTURE.stages[PBR_NORMAL_STAGE as usize].load(Ordering::Acquire);
    let snapshot = match SELECTOR_CAPTURE.find(selector) {
        Some(snapshot) => Some(snapshot),
        None if selector != 0 => unsafe {
            selector_material_snapshot(selector as *mut c_void, 0, 0)
        },
        None => None,
    };

    let Some(snapshot) = snapshot else {
        if !shader_kind.uses_extra_material_stages() && vanilla_normal != 0 {
            log_limited(
                &REPLACEMENT_RESOURCE_LOGS,
                "[PBR] Native PBR using vanilla bound normal because selector material record is missing",
            );
            return Ok(ReplacementMaterialResources {
                selector,
                generation: 0,
                normal: null_mut(),
                glow: null_mut(),
                height: null_mut(),
                environment: null_mut(),
                environment_mask: null_mut(),
            });
        }

        return Err(ReplacementMaterialResourceError::NoSelectorRecord);
    };

    let normal = unsafe {
        read_material_array_resource(snapshot.material_arrays[PBR_MATERIAL_SLOT_NORMAL], 0)
    };
    let glow = unsafe {
        read_material_array_resource(snapshot.material_arrays[PBR_MATERIAL_SLOT_GLOW], 0)
    };
    let height = unsafe {
        read_material_array_resource(snapshot.material_arrays[PBR_MATERIAL_SLOT_HEIGHT], 0)
    };
    let environment = unsafe {
        read_material_array_resource(snapshot.material_arrays[PBR_MATERIAL_SLOT_ENVIRONMENT], 0)
    };
    let environment_mask = unsafe {
        read_material_array_resource(
            snapshot.material_arrays[PBR_MATERIAL_SLOT_ENVIRONMENT_MASK],
            0,
        )
    };

    if normal.is_null() && vanilla_normal == 0 {
        return Err(ReplacementMaterialResourceError::NoNormalSource);
    }

    Ok(ReplacementMaterialResources {
        selector,
        generation: snapshot.generation,
        normal,
        glow,
        height,
        environment,
        environment_mask,
    })
}

unsafe fn read_material_array_resource(array_ptr: usize, index: usize) -> *mut c_void {
    if array_ptr == 0 {
        return null_mut();
    }

    let byte_offset = match index.checked_mul(size_of::<*mut c_void>()) {
        Some(value) => value,
        None => return null_mut(),
    };
    let slot = (array_ptr + byte_offset) as *const c_void;
    if !silent_readable_range(slot, size_of::<*mut c_void>()) {
        return null_mut();
    }

    unsafe { (slot as *const *mut c_void).read() }
}

unsafe fn bind_replacement_material_textures(
    resources: ReplacementMaterialResources,
    shader_kind: ReplacementShaderKind,
) -> Option<ReplacementMaterialBindings> {
    let render_state = TEXTURE_CAPTURE.render_state.load(Ordering::Acquire) as *mut c_void;
    if render_state.is_null() {
        return Some(ReplacementMaterialBindings {
            selector: resources.selector,
            generation: resources.generation,
            has_normal: TEXTURE_CAPTURE.stages[PBR_NORMAL_STAGE as usize].load(Ordering::Acquire)
                != 0,
            has_glow: false,
            has_height: false,
            has_environment: false,
            has_environment_mask: false,
        });
    }

    let Ok(set_texture) = SET_TEXTURE_HOOK.original() else {
        log_limited(
            &MATERIAL_BIND_LOGS,
            "[PBR] Native PBR material binding skipped because original SetTexture is unavailable",
        );
        return None;
    };

    let mut has_normal =
        TEXTURE_CAPTURE.stages[PBR_NORMAL_STAGE as usize].load(Ordering::Acquire) != 0;
    if unsafe {
        bind_material_texture_resource(
            set_texture,
            render_state,
            PBR_NORMAL_STAGE,
            resources.normal,
        )
    } {
        has_normal = true;
    }

    if !has_normal {
        return None;
    }

    if !shader_kind.uses_extra_material_stages() {
        return Some(ReplacementMaterialBindings {
            selector: resources.selector,
            generation: resources.generation,
            has_normal,
            has_glow: false,
            has_height: false,
            has_environment: false,
            has_environment_mask: false,
        });
    }

    configure_pbr_sampler_states();

    let has_glow = unsafe {
        bind_material_texture_or_clear(set_texture, render_state, PBR_GLOW_STAGE, resources.glow)
    };
    let has_height = unsafe {
        bind_material_texture_or_clear(
            set_texture,
            render_state,
            PBR_HEIGHT_STAGE,
            resources.height,
        )
    };
    let has_environment = unsafe {
        bind_material_texture_or_clear(
            set_texture,
            render_state,
            PBR_ENVIRONMENT_STAGE,
            resources.environment,
        )
    };
    let has_environment_mask = unsafe {
        bind_material_texture_or_clear(
            set_texture,
            render_state,
            PBR_ENVIRONMENT_MASK_STAGE,
            resources.environment_mask,
        )
    };

    Some(ReplacementMaterialBindings {
        selector: resources.selector,
        generation: resources.generation,
        has_normal,
        has_glow,
        has_height,
        has_environment,
        has_environment_mask,
    })
}

fn configure_pbr_sampler_states() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };

    for sampler in [
        PBR_GLOW_STAGE,
        PBR_HEIGHT_STAGE,
        PBR_ENVIRONMENT_STAGE,
        PBR_ENVIRONMENT_MASK_STAGE,
    ] {
        let _ = device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, 1);
        let _ = device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, 1);
        let _ = device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32);
        let _ = device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32);
        let _ = device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32);
    }
}

unsafe fn bind_material_texture_or_clear(
    set_texture: SetTextureFn,
    render_state: *mut c_void,
    stage: u32,
    resource: *mut c_void,
) -> bool {
    if unsafe { bind_material_texture_resource(set_texture, render_state, stage, resource) } {
        return true;
    }

    unsafe {
        set_texture(render_state, stage, null_mut());
    }
    TEXTURE_CAPTURE.stages[stage as usize].store(0, Ordering::Release);
    false
}

unsafe fn bind_material_texture_resource(
    set_texture: SetTextureFn,
    render_state: *mut c_void,
    stage: u32,
    resource: *mut c_void,
) -> bool {
    if resource.is_null() {
        return false;
    }

    let resolved = unsafe { resolve_material_texture(resource) };
    if resolved.is_null() {
        return false;
    }

    if TEXTURE_CAPTURE.stages[stage as usize].load(Ordering::Acquire) == resolved as usize {
        return true;
    }

    unsafe {
        set_texture(render_state, stage, resolved);
    }
    TEXTURE_CAPTURE.stages[stage as usize].store(resolved as usize, Ordering::Release);
    true
}

unsafe fn resolve_material_texture(resource: *mut c_void) -> *mut c_void {
    if resource.is_null() {
        return null_mut();
    }

    let renderer = unsafe { read_ptr(RENDERER_GLOBAL_ADDR) };
    let resolver = unsafe { read_ptr_offset(renderer, TEXTURE_RESOLVER_OFFSET) };
    if resolver.is_null() {
        return null_mut();
    }

    if let Some(resolved) = TEXTURE_RESOLVE_CACHE.get(resolver, resource) {
        return resolved;
    }

    let resolver_vtable = unsafe { read_ptr_from(resolver) };
    if resolver_vtable as usize != TEXTURE_RESOLVER_VTABLE_ADDR {
        log_limited(
            &MATERIAL_BIND_LOGS,
            "[PBR] Native PBR material binding skipped because texture resolver vtable is not vanilla",
        );
        return null_mut();
    }

    let resolve_slot =
        unsafe { read_ptr_offset(resolver_vtable, TEXTURE_RESOLVER_RESOLVE_SLOT_OFFSET) };
    if resolve_slot as usize != TEXTURE_RESOLVER_RESOLVE_ADDR {
        log_limited(
            &MATERIAL_BIND_LOGS,
            "[PBR] Native PBR material binding skipped because texture resolver slot is not vanilla",
        );
        return null_mut();
    }

    let resolve: TextureResolverResolveFn = unsafe { transmute(resolve_slot) };
    let mut created = 0u8;
    let mut multi_texture = 0u8;
    let mut non_power_of_two = 0u8;
    let resolved = unsafe {
        resolve(
            resolver,
            resource,
            &mut created,
            &mut multi_texture,
            &mut non_power_of_two,
        )
    };
    if !resolved.is_null() {
        TEXTURE_RESOLVE_CACHE.store(resolver, resource, resolved);
    }
    resolved
}

fn upload_replacement_material_constants(
    shader_kind: ReplacementShaderKind,
    bindings: ReplacementMaterialBindings,
) {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };

    if shader_kind.writes_material_flags() {
        let flags = [[
            bindings.has_glow as u8 as f32,
            bindings.has_height as u8 as f32,
            bindings.has_environment as u8 as f32,
            bindings.has_environment_mask as u8 as f32,
        ]];
        let _ = device.set_pixel_shader_constant_f(PBR_MATERIAL_FLAGS_REGISTER, &flags);
    }

    let pbr_data = [[
        0.0,
        atomic_pbr_f32(&PBR_ROUGHNESS_SCALE_BITS),
        atomic_pbr_f32(&PBR_LIGHT_SCALE_BITS),
        atomic_pbr_f32(&PBR_AMBIENT_SCALE_BITS),
    ]];
    let pbr_extra_data = [[atomic_pbr_f32(&PBR_ALBEDO_SATURATION_BITS), 0.0, 0.0, 0.0]];
    let _ = device.set_pixel_shader_constant_f(PBR_NVR_DATA_REGISTER, &pbr_data);
    let _ = device.set_pixel_shader_constant_f(PBR_NVR_EXTRA_DATA_REGISTER, &pbr_extra_data);
}

fn atomic_pbr_f32(value: &AtomicU32) -> f32 {
    f32::from_bits(value.load(Ordering::Acquire))
}

fn sanitize_pbr_scale(value: f32, fallback: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        fallback
    }
}

unsafe fn record_draw_context(pass_index: u32) {
    let pass = unsafe { read_ptr(CURRENT_PASS_GLOBAL_ADDR) };
    let vertex_shader = unsafe { read_ptr_offset(pass, PASS_VERTEX_SHADER_OFFSET) };
    let pixel_shader = unsafe { read_ptr_offset(pass, PASS_PIXEL_SHADER_OFFSET) };
    let vertex_shader_handle = unsafe {
        read_shader_native_handle(
            vertex_shader,
            NID3D_VERTEX_SHADER_VTABLE_ADDR,
            VERTEX_SHADER_SET_SHADERS_HANDLE_OFFSET,
        )
    };
    let pixel_shader_handle = unsafe {
        read_shader_native_handle(
            pixel_shader,
            NID3D_PIXEL_SHADER_VTABLE_ADDR,
            PIXEL_SHADER_NATIVE_HANDLE_OFFSET,
        )
    };
    let vertex_membership =
        unsafe { find_shader_array_membership(vertex_shader, &PPLIGHTING_VERTEX_GROUPS) };
    let pixel_membership =
        unsafe { find_shader_array_membership(pixel_shader, &PPLIGHTING_PIXEL_GROUPS) };
    let pplighting_family = classify_pplighting_family(vertex_membership, pixel_membership);
    let render_state = TEXTURE_CAPTURE.render_state.load(Ordering::Acquire);
    let selector = unsafe { current_draw_selector() };
    let selector_generation = SELECTOR_CAPTURE
        .find(selector as usize)
        .map_or(0, |snapshot| snapshot.generation);

    DRAW_CAPTURE.pass_index.store(pass_index, Ordering::Release);
    DRAW_CAPTURE.pass.store(pass as usize, Ordering::Release);
    DRAW_CAPTURE
        .vertex_shader
        .store(vertex_shader as usize, Ordering::Release);
    DRAW_CAPTURE
        .pixel_shader
        .store(pixel_shader as usize, Ordering::Release);
    DRAW_CAPTURE
        .vertex_shader_handle
        .store(vertex_shader_handle as usize, Ordering::Release);
    DRAW_CAPTURE
        .pixel_shader_handle
        .store(pixel_shader_handle as usize, Ordering::Release);
    DRAW_CAPTURE
        .pplighting_family
        .store(pplighting_family, Ordering::Release);
    DRAW_CAPTURE
        .pplighting_vertex_group
        .store(vertex_membership.group, Ordering::Release);
    DRAW_CAPTURE
        .pplighting_vertex_index
        .store(vertex_membership.index, Ordering::Release);
    DRAW_CAPTURE
        .pplighting_pixel_group
        .store(pixel_membership.group, Ordering::Release);
    DRAW_CAPTURE
        .pplighting_pixel_index
        .store(pixel_membership.index, Ordering::Release);
    DRAW_CAPTURE
        .render_state
        .store(render_state, Ordering::Release);
    DRAW_CAPTURE
        .set_shader_calls
        .fetch_add(1, Ordering::Relaxed);

    if DEBUG_LOG_DRAWS.load(Ordering::Acquire) {
        log_draw_context(
            pass_index,
            pass,
            vertex_shader,
            pixel_shader,
            vertex_shader_handle,
            pixel_shader_handle,
            pplighting_family,
            vertex_membership,
            pixel_membership,
            render_state,
            selector,
            selector_generation,
        );
    }
}

unsafe fn record_shader_interface_context(apply_this: *mut c_void, apply_param: *mut c_void) {
    let pass = unsafe { read_ptr(CURRENT_PASS_GLOBAL_ADDR) };
    let vertex_shader = unsafe { read_ptr_offset(pass, PASS_VERTEX_SHADER_OFFSET) };
    let pixel_shader = unsafe { read_ptr_offset(pass, PASS_PIXEL_SHADER_OFFSET) };
    let selector_cache_object = unsafe {
        read_ptr(
            SHADER_INTERFACE_SELECTOR_ARRAY_ADDR
                + PPLIGHTING_SHADER_SELECTOR_INDEX * size_of::<*mut c_void>(),
        )
    };
    let geometry_slot = unsafe { read_ptr(CURRENT_GEOMETRY_SLOT_ADDR) };
    let geometry = unsafe { read_ptr_from(geometry_slot) };
    let current_selector_object =
        unsafe { read_ptr_offset(geometry, CURRENT_DRAW_SELECTOR_OFFSET) };
    let selector_object = if current_selector_object.is_null() {
        selector_cache_object
    } else {
        current_selector_object
    };
    let selector_material = SELECTOR_CAPTURE.find(selector_object as usize);
    let selector_material_generation = selector_material.map_or(0, |snapshot| snapshot.generation);
    let selector_material_setup_kind = selector_material.map_or(0, |snapshot| snapshot.setup_kind);
    let selector_pass_entry_list = selector_material.map_or(0, |snapshot| snapshot.pass_entry_list);
    let selector_material_arrays = selector_material
        .map_or([0usize; SELECTOR_MATERIAL_ARRAY_COUNT], |snapshot| {
            snapshot.material_arrays
        });
    let selector_pixel_interface =
        unsafe { read_ptr_offset(selector_object, SHADER_INTERFACE_PIXEL_OFFSET) };
    let selector_vertex_interface =
        unsafe { read_ptr_offset(selector_object, SHADER_INTERFACE_VERTEX_OFFSET) };
    let selector_pixel_apply =
        unsafe { read_vtable_slot(selector_pixel_interface, SHADER_INTERFACE_APPLY_SLOT_OFFSET) };
    let selector_vertex_apply = unsafe {
        read_vtable_slot(
            selector_vertex_interface,
            SHADER_INTERFACE_APPLY_SLOT_OFFSET,
        )
    };
    let selector_pixel_alt_interface =
        unsafe { read_ptr_offset(selector_object, SHADER_INTERFACE_PIXEL_ALT_OFFSET) };
    let selector_vertex_alt_interface =
        unsafe { read_ptr_offset(selector_object, SHADER_INTERFACE_VERTEX_ALT_OFFSET) };
    let selector_pixel_active_copy_interface =
        unsafe { read_ptr_offset(selector_object, SHADER_INTERFACE_PIXEL_ACTIVE_COPY_OFFSET) };
    let selector_vertex_active_copy_interface =
        unsafe { read_ptr_offset(selector_object, SHADER_INTERFACE_VERTEX_ACTIVE_COPY_OFFSET) };
    let selector_pixel_alt_apply = unsafe {
        read_vtable_slot(
            selector_pixel_alt_interface,
            SHADER_INTERFACE_APPLY_SLOT_OFFSET,
        )
    };
    let selector_vertex_alt_apply = unsafe {
        read_vtable_slot(
            selector_vertex_alt_interface,
            SHADER_INTERFACE_APPLY_SLOT_OFFSET,
        )
    };
    let selector_pixel_active_copy_apply = unsafe {
        read_vtable_slot(
            selector_pixel_active_copy_interface,
            SHADER_INTERFACE_APPLY_SLOT_OFFSET,
        )
    };
    let selector_vertex_active_copy_apply = unsafe {
        read_vtable_slot(
            selector_vertex_active_copy_interface,
            SHADER_INTERFACE_APPLY_SLOT_OFFSET,
        )
    };
    let param_pixel_interface =
        unsafe { read_ptr_offset(apply_param, SHADER_INTERFACE_PIXEL_OFFSET) };
    let param_vertex_interface =
        unsafe { read_ptr_offset(apply_param, SHADER_INTERFACE_VERTEX_OFFSET) };
    let param_pixel_apply =
        unsafe { read_vtable_slot(param_pixel_interface, SHADER_INTERFACE_APPLY_SLOT_OFFSET) };
    let param_vertex_apply =
        unsafe { read_vtable_slot(param_vertex_interface, SHADER_INTERFACE_APPLY_SLOT_OFFSET) };
    let selector_pixel_vtable = unsafe { read_ptr_from(selector_pixel_interface) };
    let selector_vertex_vtable = unsafe { read_ptr_from(selector_vertex_interface) };
    let selector_pixel_alt_vtable = unsafe { read_ptr_from(selector_pixel_alt_interface) };
    let selector_vertex_alt_vtable = unsafe { read_ptr_from(selector_vertex_alt_interface) };
    let selector_pixel_active_copy_vtable =
        unsafe { read_ptr_from(selector_pixel_active_copy_interface) };
    let selector_vertex_active_copy_vtable =
        unsafe { read_ptr_from(selector_vertex_active_copy_interface) };
    let param_pixel_vtable = unsafe { read_ptr_from(param_pixel_interface) };
    let param_vertex_vtable = unsafe { read_ptr_from(param_vertex_interface) };
    let geometry_state = unsafe { read_ptr_offset(geometry, GEOMETRY_STATE_OFFSET) };

    let apply_param_resource = unsafe { read_ptr_offset(apply_param, APPLY_PARAM_RESOURCE_OFFSET) };
    let geometry_flags = unsafe { read_u32_offset(geometry, GEOMETRY_FLAGS_OFFSET) };
    let geometry_shader_args = unsafe { offset_ptr(geometry, GEOMETRY_SHADER_ARGS_OFFSET) };
    let geometry_state_value =
        unsafe { read_ptr_offset(geometry_state, GEOMETRY_STATE_VALUE_OFFSET) };
    let geometry_context = unsafe { read_u32_offset(geometry, GEOMETRY_CONTEXT_OFFSET) };

    INTERFACE_CAPTURE
        .apply_this
        .store(apply_this as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .apply_param
        .store(apply_param as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .apply_param_resource
        .store(apply_param_resource as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .current_geometry_slot
        .store(geometry_slot as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .current_geometry
        .store(geometry as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .geometry_flags
        .store(geometry_flags, Ordering::Release);
    INTERFACE_CAPTURE
        .geometry_shader_args
        .store(geometry_shader_args as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .geometry_state
        .store(geometry_state as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .geometry_state_value
        .store(geometry_state_value as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .geometry_context
        .store(geometry_context, Ordering::Release);
    INTERFACE_CAPTURE
        .pass
        .store(pass as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .vertex_shader
        .store(vertex_shader as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .pixel_shader
        .store(pixel_shader as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_object
        .store(selector_object as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_pixel_interface
        .store(selector_pixel_interface as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_vertex_interface
        .store(selector_vertex_interface as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_pixel_apply
        .store(selector_pixel_apply as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_vertex_apply
        .store(selector_vertex_apply as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_pixel_alt_interface
        .store(selector_pixel_alt_interface as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_vertex_alt_interface
        .store(selector_vertex_alt_interface as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_pixel_alt_apply
        .store(selector_pixel_alt_apply as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_vertex_alt_apply
        .store(selector_vertex_alt_apply as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_pixel_active_copy_interface
        .store(
            selector_pixel_active_copy_interface as usize,
            Ordering::Release,
        );
    INTERFACE_CAPTURE
        .selector_vertex_active_copy_interface
        .store(
            selector_vertex_active_copy_interface as usize,
            Ordering::Release,
        );
    INTERFACE_CAPTURE
        .selector_pixel_active_copy_apply
        .store(selector_pixel_active_copy_apply as usize, Ordering::Release);
    INTERFACE_CAPTURE.selector_vertex_active_copy_apply.store(
        selector_vertex_active_copy_apply as usize,
        Ordering::Release,
    );
    INTERFACE_CAPTURE
        .selector_material_generation
        .store(selector_material_generation, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_material_setup_kind
        .store(selector_material_setup_kind, Ordering::Release);
    INTERFACE_CAPTURE
        .selector_pass_entry_list
        .store(selector_pass_entry_list, Ordering::Release);
    for (slot, value) in INTERFACE_CAPTURE
        .selector_material_arrays
        .iter()
        .zip(selector_material_arrays.iter().copied())
    {
        slot.store(value, Ordering::Release);
    }
    INTERFACE_CAPTURE
        .param_pixel_interface
        .store(param_pixel_interface as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .param_vertex_interface
        .store(param_vertex_interface as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .param_pixel_apply
        .store(param_pixel_apply as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .param_vertex_apply
        .store(param_vertex_apply as usize, Ordering::Release);
    INTERFACE_CAPTURE
        .apply_calls
        .fetch_add(1, Ordering::Relaxed);

    if DEBUG_LOG_DRAWS.load(Ordering::Acquire) {
        log_shader_interface_context(
            apply_this,
            apply_param,
            apply_param_resource,
            pass,
            vertex_shader,
            pixel_shader,
            selector_object,
            selector_pixel_interface,
            selector_vertex_interface,
            selector_pixel_apply,
            selector_vertex_apply,
            selector_pixel_alt_interface,
            selector_vertex_alt_interface,
            selector_pixel_alt_apply,
            selector_vertex_alt_apply,
            selector_pixel_active_copy_interface,
            selector_vertex_active_copy_interface,
            selector_pixel_active_copy_apply,
            selector_vertex_active_copy_apply,
            param_pixel_interface,
            param_vertex_interface,
            param_pixel_apply,
            param_vertex_apply,
            selector_pixel_vtable,
            selector_vertex_vtable,
            selector_pixel_alt_vtable,
            selector_vertex_alt_vtable,
            selector_pixel_active_copy_vtable,
            selector_vertex_active_copy_vtable,
            param_pixel_vtable,
            param_vertex_vtable,
            selector_material_generation,
            selector_material_setup_kind,
            selector_pass_entry_list,
            selector_material_arrays,
            geometry_slot,
            geometry,
            geometry_flags,
            geometry_state,
            geometry_state_value,
            geometry_context,
        );
    }
}

unsafe fn current_draw_selector() -> *mut c_void {
    let current_draw = unsafe { read_ptr(CURRENT_GEOMETRY_SLOT_ADDR) };
    let geometry = unsafe { read_ptr_from(current_draw) };
    unsafe { read_ptr_offset(geometry, CURRENT_DRAW_SELECTOR_OFFSET) }
}

unsafe fn read_ptr(address: usize) -> *mut c_void {
    let slot = address as *const c_void;
    if !silent_readable_range(slot, size_of::<*mut c_void>()) {
        return null_mut();
    }

    unsafe { (address as *const *mut c_void).read() }
}

unsafe fn read_ptr_from(ptr: *mut c_void) -> *mut c_void {
    if ptr.is_null() {
        return null_mut();
    }

    if !silent_readable_range(ptr, size_of::<*mut c_void>()) {
        return null_mut();
    }

    unsafe { (ptr as *const *mut c_void).read() }
}

unsafe fn read_ptr_offset(base: *mut c_void, offset: usize) -> *mut c_void {
    let slot = unsafe { offset_ptr(base, offset) };
    if slot.is_null() {
        return null_mut();
    }

    if !silent_readable_range(slot, size_of::<*mut c_void>()) {
        return null_mut();
    }

    unsafe { (slot as *const *mut c_void).read() }
}

unsafe fn write_ptr_offset(base: *mut c_void, offset: usize, value: *mut c_void) -> bool {
    let slot = unsafe { offset_ptr(base, offset) };
    if slot.is_null() {
        return false;
    }

    if !silent_writable_range(slot, size_of::<*mut c_void>()) {
        return false;
    }

    unsafe {
        (slot as *mut *mut c_void).write(value);
    }
    true
}

unsafe fn read_u32_offset(base: *mut c_void, offset: usize) -> u32 {
    let slot = unsafe { offset_ptr(base, offset) };
    if slot.is_null() {
        return 0;
    }

    if !silent_readable_range(slot, size_of::<u32>()) {
        return 0;
    }

    unsafe { (slot as *const u32).read() }
}

unsafe fn read_vtable_slot(object: *mut c_void, slot_offset: usize) -> *mut c_void {
    let vtable = unsafe { read_ptr_from(object) };
    unsafe { read_ptr_offset(vtable, slot_offset) }
}

unsafe fn find_shader_array_membership(
    shader: *mut c_void,
    groups: &[ShaderArrayGroup],
) -> ShaderArrayMembership {
    if shader.is_null() {
        return ShaderArrayMembership::NONE;
    }

    for group in groups {
        let byte_len = group.count * size_of::<*mut c_void>();
        let base = group.base as *const c_void;
        if !silent_readable_range(base, byte_len) {
            continue;
        }

        for index in 0..group.count {
            let slot = unsafe { (group.base as *const *mut c_void).add(index) };
            let candidate = unsafe { slot.read() };
            if candidate == shader {
                return ShaderArrayMembership {
                    group: group.id,
                    index: index as u32,
                };
            }
        }
    }

    ShaderArrayMembership::NONE
}

unsafe fn cached_shader_array_membership(
    shader: *mut c_void,
    groups: &[ShaderArrayGroup],
    cache: &ShaderMembershipCache,
) -> ShaderArrayMembership {
    if let Some(membership) = cache.get(shader) {
        return membership;
    }

    let membership = unsafe { find_shader_array_membership(shader, groups) };
    cache.store(shader, membership);
    membership
}

fn silent_readable_range(address: *const c_void, size: usize) -> bool {
    if address.is_null() || size == 0 {
        return false;
    }

    let start = address as usize;
    if start < MIN_READABLE_ADDRESS {
        return false;
    }

    let Some(end) = start.checked_add(size) else {
        return false;
    };

    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };

    if info.state != MEM_COMMIT.0 {
        return false;
    }

    let protect = info.protect.0;
    if protect & PAGE_GUARD.0 != 0 || protect & PAGE_NOACCESS.0 != 0 {
        return false;
    }

    let region_start = info.base_address as usize;
    let Some(region_end) = region_start.checked_add(info.region_size) else {
        return false;
    };

    start >= region_start && end <= region_end
}

fn silent_writable_range(address: *mut c_void, size: usize) -> bool {
    if !silent_readable_range(address.cast_const(), size) {
        return false;
    }

    let Ok(info) = virtual_query(address) else {
        return false;
    };

    let protect = info.protect.0 & 0xff;
    protect != PAGE_READONLY.0 && protect != PAGE_EXECUTE.0 && protect != PAGE_EXECUTE_READ.0
}

fn classify_pplighting_family(vertex: ShaderArrayMembership, pixel: ShaderArrayMembership) -> u32 {
    match (vertex.group, pixel.group) {
        (PPLIGHTING_GROUP_NONE, PPLIGHTING_GROUP_NONE) => PPLIGHTING_FAMILY_NONE,
        (PPLIGHTING_VERTEX_GROUP_A, PPLIGHTING_PIXEL_GROUP_A) => PPLIGHTING_FAMILY_VERTEX_A_PIXEL_A,
        (PPLIGHTING_VERTEX_GROUP_B, PPLIGHTING_PIXEL_GROUP_A) => PPLIGHTING_FAMILY_VERTEX_B_PIXEL_A,
        (PPLIGHTING_VERTEX_GROUP_C, PPLIGHTING_PIXEL_GROUP_B) => PPLIGHTING_FAMILY_VERTEX_C_PIXEL_B,
        _ => PPLIGHTING_FAMILY_UNKNOWN_PAIR,
    }
}

unsafe fn read_shader_native_handle(
    shader: *mut c_void,
    expected_vtable: usize,
    handle_offset: usize,
) -> *mut c_void {
    let vtable = unsafe { read_ptr_from(shader) };
    if vtable as usize != expected_vtable {
        return null_mut();
    }

    unsafe { read_ptr_offset(shader, handle_offset) }
}

unsafe fn write_shader_native_handle(
    shader: *mut c_void,
    handle_offset: usize,
    handle: *mut c_void,
) -> bool {
    unsafe { write_ptr_offset(shader, handle_offset, handle) }
}

unsafe fn offset_ptr(base: *mut c_void, offset: usize) -> *mut c_void {
    if base.is_null() {
        return null_mut();
    }

    (base as *mut u8).wrapping_add(offset).cast::<c_void>()
}

fn log_draw_context(
    pass_index: u32,
    pass: *mut c_void,
    vertex_shader: *mut c_void,
    pixel_shader: *mut c_void,
    vertex_shader_handle: *mut c_void,
    pixel_shader_handle: *mut c_void,
    pplighting_family: u32,
    vertex_membership: ShaderArrayMembership,
    pixel_membership: ShaderArrayMembership,
    render_state: usize,
    selector: *mut c_void,
    selector_generation: u32,
) {
    let count = DRAW_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_LOGS {
        return;
    }

    let stages = &TEXTURE_CAPTURE.stages;
    log::debug!(
        "[PBR] Draw pass={} pass={:p} vs={:p} ps={:p} vs_handle={:p} ps_handle={:p} family={} vgrp={} vidx={} pgrp={} pidx={} render_state=0x{:08X} selector={:p} selector_gen={} s0=0x{:08X} s1=0x{:08X} s2=0x{:08X} s3=0x{:08X}",
        pass_index,
        pass,
        vertex_shader,
        pixel_shader,
        vertex_shader_handle,
        pixel_shader_handle,
        pplighting_family,
        vertex_membership.group,
        vertex_membership.index,
        pixel_membership.group,
        pixel_membership.index,
        render_state,
        selector,
        selector_generation,
        stages[0].load(Ordering::Acquire),
        stages[1].load(Ordering::Acquire),
        stages[2].load(Ordering::Acquire),
        stages[3].load(Ordering::Acquire),
    );
}

#[allow(clippy::too_many_arguments)]
fn log_shader_interface_context(
    apply_this: *mut c_void,
    apply_param: *mut c_void,
    apply_param_resource: *mut c_void,
    pass: *mut c_void,
    vertex_shader: *mut c_void,
    pixel_shader: *mut c_void,
    selector_object: *mut c_void,
    selector_pixel_interface: *mut c_void,
    selector_vertex_interface: *mut c_void,
    selector_pixel_apply: *mut c_void,
    selector_vertex_apply: *mut c_void,
    selector_pixel_alt_interface: *mut c_void,
    selector_vertex_alt_interface: *mut c_void,
    selector_pixel_alt_apply: *mut c_void,
    selector_vertex_alt_apply: *mut c_void,
    selector_pixel_active_copy_interface: *mut c_void,
    selector_vertex_active_copy_interface: *mut c_void,
    selector_pixel_active_copy_apply: *mut c_void,
    selector_vertex_active_copy_apply: *mut c_void,
    param_pixel_interface: *mut c_void,
    param_vertex_interface: *mut c_void,
    param_pixel_apply: *mut c_void,
    param_vertex_apply: *mut c_void,
    selector_pixel_vtable: *mut c_void,
    selector_vertex_vtable: *mut c_void,
    selector_pixel_alt_vtable: *mut c_void,
    selector_vertex_alt_vtable: *mut c_void,
    selector_pixel_active_copy_vtable: *mut c_void,
    selector_vertex_active_copy_vtable: *mut c_void,
    param_pixel_vtable: *mut c_void,
    param_vertex_vtable: *mut c_void,
    selector_material_generation: u32,
    selector_material_setup_kind: u32,
    selector_pass_entry_list: usize,
    selector_material_arrays: [usize; SELECTOR_MATERIAL_ARRAY_COUNT],
    geometry_slot: *mut c_void,
    geometry: *mut c_void,
    geometry_flags: u32,
    geometry_state: *mut c_void,
    geometry_state_value: *mut c_void,
    geometry_context: u32,
) {
    let count = INTERFACE_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_LOGS {
        return;
    }

    let selector_pixel_known =
        shader_interface_dispatcher_matches(selector_pixel_vtable, selector_pixel_apply);
    let selector_vertex_known =
        shader_interface_dispatcher_matches(selector_vertex_vtable, selector_vertex_apply);
    let param_pixel_known =
        shader_interface_dispatcher_matches(param_pixel_vtable, param_pixel_apply);
    let param_vertex_known =
        shader_interface_dispatcher_matches(param_vertex_vtable, param_vertex_apply);
    let selector_pixel_alt_known =
        shader_interface_dispatcher_matches(selector_pixel_alt_vtable, selector_pixel_alt_apply);
    let selector_vertex_alt_known =
        shader_interface_dispatcher_matches(selector_vertex_alt_vtable, selector_vertex_alt_apply);
    let selector_pixel_active_copy_known = shader_interface_dispatcher_matches(
        selector_pixel_active_copy_vtable,
        selector_pixel_active_copy_apply,
    );
    let selector_vertex_active_copy_known = shader_interface_dispatcher_matches(
        selector_vertex_active_copy_vtable,
        selector_vertex_active_copy_apply,
    );

    log::debug!(
        "[PBR] ShaderInterface this={:p} param={:p} resource={:p} pass={:p} vs={:p} ps={:p} selector={:p} sel_gen={} sel_setup={} sel_entries=0x{:08X} sel_pi={:p} sel_vi={:p} sel_p78={:p} sel_v78={:p} param_pi={:p} param_vi={:p} param_p78={:p} param_v78={:p} sel_known=({},{}) param_known=({},{}) geom_slot={:p} geom={:p} flags=0x{:08X} geom_state={:p} state_value={:p} geom_ctx=0x{:08X}",
        apply_this,
        apply_param,
        apply_param_resource,
        pass,
        vertex_shader,
        pixel_shader,
        selector_object,
        selector_material_generation,
        selector_material_setup_kind,
        selector_pass_entry_list,
        selector_pixel_interface,
        selector_vertex_interface,
        selector_pixel_apply,
        selector_vertex_apply,
        param_pixel_interface,
        param_vertex_interface,
        param_pixel_apply,
        param_vertex_apply,
        selector_pixel_known,
        selector_vertex_known,
        param_pixel_known,
        param_vertex_known,
        geometry_slot,
        geometry,
        geometry_flags,
        geometry_state,
        geometry_state_value,
        geometry_context,
    );

    log::debug!(
        "[PBR] ShaderInterface selector_extra selector={:p} mat_ac=0x{:08X} mat_b0=0x{:08X} mat_b4=0x{:08X} mat_b8=0x{:08X} mat_bc=0x{:08X} mat_c0=0x{:08X} alt_pi={:p} alt_vi={:p} alt_p78={:p} alt_v78={:p} copy_pi={:p} copy_vi={:p} copy_p78={:p} copy_v78={:p} alt_known=({},{}) copy_known=({},{})",
        selector_object,
        selector_material_arrays[0],
        selector_material_arrays[1],
        selector_material_arrays[2],
        selector_material_arrays[3],
        selector_material_arrays[4],
        selector_material_arrays[5],
        selector_pixel_alt_interface,
        selector_vertex_alt_interface,
        selector_pixel_alt_apply,
        selector_vertex_alt_apply,
        selector_pixel_active_copy_interface,
        selector_vertex_active_copy_interface,
        selector_pixel_active_copy_apply,
        selector_vertex_active_copy_apply,
        selector_pixel_alt_known,
        selector_vertex_alt_known,
        selector_pixel_active_copy_known,
        selector_vertex_active_copy_known,
    );
}

fn shader_interface_dispatcher_matches(vtable: *mut c_void, apply: *mut c_void) -> bool {
    vtable as usize == SHADER_INTERFACE_FIELD_VTABLE_ADDR
        && apply as usize == SHADER_INTERFACE_FIELD_APPLY_ADDR
}

fn log_selector_material_context(snapshot: SelectorCaptureSnapshot) {
    let count = SELECTOR_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_LOGS {
        return;
    }

    log::debug!(
        "[PBR] Selector setup selector=0x{:08X} gen={} kind={} flags=0x{:08X} entries=0x{:08X} mat_ac=0x{:08X} mat_b0=0x{:08X} mat_b4=0x{:08X} mat_b8=0x{:08X} mat_bc=0x{:08X} mat_c0=0x{:08X}",
        snapshot.selector,
        snapshot.generation,
        snapshot.setup_kind,
        snapshot.flags,
        snapshot.pass_entry_list,
        snapshot.material_arrays[0],
        snapshot.material_arrays[1],
        snapshot.material_arrays[2],
        snapshot.material_arrays[3],
        snapshot.material_arrays[4],
        snapshot.material_arrays[5],
    );
}

fn log_replacement_apply(
    shader_kind: ReplacementShaderKind,
    draw_context: ReplacementDrawContext,
    pass_index: u32,
    original_pixel_handle: *mut c_void,
    replacement_pixel_handle: *mut c_void,
    original_vertex_handle: *mut c_void,
    replacement_vertex_handle: *mut c_void,
    material_bindings: ReplacementMaterialBindings,
) {
    REPLACEMENT_APPLIED_COUNT.fetch_add(1, Ordering::Relaxed);

    let count = REPLACEMENT_APPLY_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= 8 {
        return;
    }

    log::info!(
        "[PBR] Native PBR replacement kind={} pass_index={} pass={:p} vs={:p} ps={:p} family={} vgrp={} vidx={} pgrp={} pidx={} vanilla_vs={:p} replacement_vs={:p} vanilla_ps={:p} replacement_ps={:p} selector=0x{:08X} sel_gen={} maps=n{} g{} h{} e{} m{} s0=0x{:08X} s1=0x{:08X} s2=0x{:08X} s3=0x{:08X} s4=0x{:08X} s5=0x{:08X}",
        shader_kind.label(),
        pass_index,
        draw_context.pass,
        draw_context.vertex_shader,
        draw_context.pixel_shader,
        draw_context.family,
        draw_context.vertex_membership.group,
        draw_context.vertex_membership.index,
        draw_context.pixel_membership.group,
        draw_context.pixel_membership.index,
        original_vertex_handle,
        replacement_vertex_handle,
        original_pixel_handle,
        replacement_pixel_handle,
        material_bindings.selector,
        material_bindings.generation,
        material_bindings.has_normal as u8,
        material_bindings.has_glow as u8,
        material_bindings.has_height as u8,
        material_bindings.has_environment as u8,
        material_bindings.has_environment_mask as u8,
        TEXTURE_CAPTURE.stages[0].load(Ordering::Acquire),
        TEXTURE_CAPTURE.stages[1].load(Ordering::Acquire),
        TEXTURE_CAPTURE.stages[2].load(Ordering::Acquire),
        TEXTURE_CAPTURE.stages[3].load(Ordering::Acquire),
        TEXTURE_CAPTURE.stages[4].load(Ordering::Acquire),
        TEXTURE_CAPTURE.stages[5].load(Ordering::Acquire),
    );
}

fn record_replacement_skip(
    reason: ReplacementSkipReason,
    draw_context: Option<ReplacementDrawContext>,
) {
    let checks = REPLACEMENT_SKIP_CHECKS.fetch_add(1, Ordering::Relaxed) + 1;

    match reason {
        ReplacementSkipReason::NoDiffuse => {
            REPLACEMENT_SKIP_NO_DIFFUSE.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoDrawContext => {
            REPLACEMENT_SKIP_NO_DRAW_CONTEXT.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::UnsupportedFamily => {
            REPLACEMENT_SKIP_UNSUPPORTED_FAMILY.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::UnsupportedVertexAbi => {
            REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoSelectorRecord => {
            REPLACEMENT_SKIP_NO_SELECTOR_RECORD.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoNormalSource => {
            REPLACEMENT_SKIP_NO_NORMAL_SOURCE.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoReplacementShader => {
            REPLACEMENT_SKIP_NO_REPLACEMENT_SHADER.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::BindFailed => {
            REPLACEMENT_SKIP_BIND_FAILED.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoVanillaHandle => {
            REPLACEMENT_SKIP_NO_VANILLA_HANDLE.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::HandleWriteFailed => {
            REPLACEMENT_SKIP_HANDLE_WRITE_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    if let Some(draw_context) = draw_context {
        REPLACEMENT_LAST_FAMILY.store(draw_context.family, Ordering::Release);
        REPLACEMENT_LAST_VERTEX_GROUP
            .store(draw_context.vertex_membership.group, Ordering::Release);
        REPLACEMENT_LAST_VERTEX_INDEX
            .store(draw_context.vertex_membership.index, Ordering::Release);
        REPLACEMENT_LAST_PIXEL_GROUP.store(draw_context.pixel_membership.group, Ordering::Release);
        REPLACEMENT_LAST_PIXEL_INDEX.store(draw_context.pixel_membership.index, Ordering::Release);
        maybe_log_unsupported_replacement_pair(reason, draw_context);
    }

    maybe_log_replacement_skip_summary(checks);
}

fn maybe_log_unsupported_replacement_pair(
    reason: ReplacementSkipReason,
    draw_context: ReplacementDrawContext,
) {
    if !DEBUG_LOG_DRAWS.load(Ordering::Acquire) {
        return;
    }
    if !matches!(
        reason,
        ReplacementSkipReason::UnsupportedFamily | ReplacementSkipReason::UnsupportedVertexAbi
    ) {
        return;
    }

    let count = REPLACEMENT_UNSUPPORTED_PAIR_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_LOGS {
        return;
    }

    log::info!(
        "[PBR] Unsupported replacement pair: reason={} family={} vgrp={} vidx={} pgrp={} pidx={} pass={:p} vs={:p} ps={:p}",
        reason.label(),
        draw_context.family,
        draw_context.vertex_membership.group,
        draw_context.vertex_membership.index,
        draw_context.pixel_membership.group,
        draw_context.pixel_membership.index,
        draw_context.pass,
        draw_context.vertex_shader,
        draw_context.pixel_shader,
    );
}

fn maybe_log_replacement_skip_summary(checks: u32) {
    if checks < 1024 || !checks.is_power_of_two() {
        return;
    }
    if REPLACEMENT_APPLIED_COUNT.load(Ordering::Acquire) != 0 {
        return;
    }

    let count = REPLACEMENT_SKIP_SUMMARY_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= 4 {
        return;
    }

    log::info!(
        "[PBR] Native PBR replacement has not applied yet: checks={} no_diffuse={} no_context={} unsupported_family={} unsupported_vertex_abi={} no_selector={} no_normal={} no_shader={} bind_failed={} no_vanilla_handle={} handle_write_failed={} last_family={} last_vgrp={} last_vidx={} last_pgrp={} last_pidx={}",
        checks,
        REPLACEMENT_SKIP_NO_DIFFUSE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_DRAW_CONTEXT.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNSUPPORTED_FAMILY.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_SELECTOR_RECORD.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_NORMAL_SOURCE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_REPLACEMENT_SHADER.load(Ordering::Acquire),
        REPLACEMENT_SKIP_BIND_FAILED.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_VANILLA_HANDLE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_HANDLE_WRITE_FAILED.load(Ordering::Acquire),
        REPLACEMENT_LAST_FAMILY.load(Ordering::Acquire),
        REPLACEMENT_LAST_VERTEX_GROUP.load(Ordering::Acquire),
        REPLACEMENT_LAST_VERTEX_INDEX.load(Ordering::Acquire),
        REPLACEMENT_LAST_PIXEL_GROUP.load(Ordering::Acquire),
        REPLACEMENT_LAST_PIXEL_INDEX.load(Ordering::Acquire),
    );
}

fn log_limited(counter: &AtomicU32, message: &str) {
    let count = counter.fetch_add(1, Ordering::Relaxed);
    if count < MAX_LOGS {
        log::warn!("{message}");
    }
}
