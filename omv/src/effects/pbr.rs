//! Native PBR draw-contract layer for FalloutNV.
//!
//! This module owns the proven engine-side contract for material PBR:
//! draw-scoped current pass capture, final vanilla texture-stage capture, and
//! an opt-in pixel shader handle substitution for one proven PPLighting family.

use std::{
    array,
    borrow::Cow,
    collections::VecDeque,
    ffi::c_void,
    fs,
    mem::{size_of, transmute},
    path::{Path, PathBuf},
    ptr::null_mut,
    slice,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    thread,
    time::Instant,
};

use anyhow::Result;
use libpsycho::os::windows::{
    directx9::{
        D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER,
        D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DTEXF_LINEAR, D3DTEXF_NONE, Device9Ref,
        PixelShader9, Texture9, VertexShader9,
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
const PPLIGHTING_PIXEL_SLS2_ADTS_DEFAULT_INDEX: u32 = 0;
const PPLIGHTING_PIXEL_SLS2_ADTS_OPT_INDEX: u32 = 1;
const PPLIGHTING_VERTEX_SLS2_ADTS_LOD_INDEX: u32 = 1;
const PPLIGHTING_PIXEL_SLS2_ADTS_OPT_LOD_INDEX: u32 = 2;
const PPLIGHTING_VERTEX_SLS2_LANDLOD_INDEX: u32 = 2;
const PPLIGHTING_PIXEL_SLS2_LANDLOD_INDEX: u32 = 3;
const PPLIGHTING_VERTEX_SLS2_ADTS_SKIN_INDEX: u32 = 3;
const PPLIGHTING_VERTEX_SLS2_ADTS_PROJECTED_SHADOW_INDEX: u32 = 4;
const PPLIGHTING_VERTEX_SLS2_LANDLOD_PROJECTED_SHADOW_INDEX: u32 = 5;
const PPLIGHTING_PIXEL_SLS2_LANDLOD_PROJECTED_SHADOW_INDEX: u32 = 6;
const PPLIGHTING_VERTEX_SLS2_ADTS_PROJECTED_SHADOW_SKIN_INDEX: u32 = 6;
const PPLIGHTING_VERTEX_SLS2_ADTS_STBB_INDEX: u32 = 7;
const PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_INDEX: u32 = 8;
const PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_SKIN_INDEX: u32 = 9;
const PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_INDEX: u32 = 10;
const PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_SKIN_INDEX: u32 = 11;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_INDEX: u32 = 12;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_SKIN_INDEX: u32 = 13;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_INDEX: u32 = 14;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_SKIN_INDEX: u32 = 15;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_INDEX: u32 = 16;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_SKIN_INDEX: u32 = 17;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_INDEX: u32 = 18;
const PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_SKIN_INDEX: u32 = 19;
const PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS9_INDEX: u32 = 20;
const PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS9_SKIN_INDEX: u32 = 21;
const PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_INDEX: u32 = 22;
const PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_OPT_INDEX: u32 = 23;
const PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_SKIN_INDEX: u32 = 24;
const PPLIGHTING_VERTEX_SLS2_ADTS10_SPECULAR_LIGHTS4_INDEX: u32 = 25;
const PPLIGHTING_VERTEX_SLS2_ADTS10_SPECULAR_LIGHTS4_OPT_INDEX: u32 = 26;
const PPLIGHTING_VERTEX_SLS2_ADTS10_SPECULAR_LIGHTS4_SKIN_INDEX: u32 = 27;
const PPLIGHTING_PIXEL_SLS2_ADTS_SI_INDEX: u32 = 4;
const PPLIGHTING_PIXEL_SLS2_ADTS_PROJECTED_SHADOW_INDEX: u32 = 5;
const PPLIGHTING_PIXEL_SLS2_ADTS_SI_PROJECTED_SHADOW_INDEX: u32 = 7;
const PPLIGHTING_PIXEL_SLS2_ADTS_STBB_INDEX: u32 = 8;
const PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_INDEX: u32 = 11;
const PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_SI_INDEX: u32 = 12;
const PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_INDEX: u32 = 14;
const PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_SI_PROJECTED_SHADOW_INDEX: u32 = 15;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_INDEX: u32 = 17;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_SI_INDEX: u32 = 18;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_INDEX: u32 = 20;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_SI_PROJECTED_SHADOW_INDEX: u32 = 21;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_INDEX: u32 = 23;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_SI_INDEX: u32 = 24;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_INDEX: u32 = 26;
const PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_SI_PROJECTED_SHADOW_INDEX: u32 = 27;
const PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS9_INDEX: u32 = 29;
const PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS9_SI_INDEX: u32 = 30;
const PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_INDEX: u32 = 31;
const PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_OPT_INDEX: u32 = 32;
const PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_SI_INDEX: u32 = 33;
const PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_INDEX: u32 = 34;
const PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_OPT_INDEX: u32 = 35;
const PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_SI_INDEX: u32 = 36;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_INDEX: u32 = 28;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_SKIN_INDEX: u32 = 29;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_PROJECTED_SHADOW_INDEX: u32 = 30;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_PROJECTED_SHADOW_SKIN_INDEX: u32 = 31;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_INDEX: u32 = 32;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_SKIN_INDEX: u32 = 33;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_PROJECTED_SHADOW_INDEX: u32 = 34;
const PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_PROJECTED_SHADOW_SKIN_INDEX: u32 = 35;
const PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS2_INDEX: u32 = 36;
const PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS2_SKIN_INDEX: u32 = 37;
const PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS3_INDEX: u32 = 38;
const PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS3_SKIN_INDEX: u32 = 39;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_INDEX: u32 = 40;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_SKIN_INDEX: u32 = 41;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_PROJECTED_SHADOW_INDEX: u32 = 42;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_PROJECTED_SHADOW_SKIN_INDEX: u32 = 43;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_INDEX: u32 = 44;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_SKIN_INDEX: u32 = 45;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS2_INDEX: u32 = 46;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS2_SKIN_INDEX: u32 = 47;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS3_INDEX: u32 = 48;
const PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS3_SKIN_INDEX: u32 = 49;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_INDEX: u32 = 37;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_SI_INDEX: u32 = 38;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_PROJECTED_SHADOW_INDEX: u32 = 39;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_SI_PROJECTED_SHADOW_INDEX: u32 = 40;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_INDEX: u32 = 41;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_SI_INDEX: u32 = 42;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_PROJECTED_SHADOW_INDEX: u32 = 43;
const PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_SI_PROJECTED_SHADOW_INDEX: u32 = 44;
const PPLIGHTING_PIXEL_SLS2_DIFFUSE_LIGHTS2_INDEX: u32 = 45;
const PPLIGHTING_PIXEL_SLS2_DIFFUSE_LIGHTS3_INDEX: u32 = 46;
const PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_INDEX: u32 = 47;
const PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_PROJECTED_SHADOW_INDEX: u32 = 49;
const PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_POINT_INDEX: u32 = 51;
const PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_POINT_LIGHTS2_INDEX: u32 = 53;
const PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_POINT_LIGHTS3_INDEX: u32 = 55;
const PPLIGHTING_VERTEX_SLS2_VPT_CLOSE_TERRAIN_A_INDEX: u32 = 100;
const PPLIGHTING_VERTEX_SLS2_VPT_CLOSE_TERRAIN_B_INDEX: u32 = 101;
const PPLIGHTING_PIXEL_SLS2_VPT_CLOSE_TERRAIN_FIRST_INDEX: u32 = 92;
const PPLIGHTING_PIXEL_SLS2_VPT_CLOSE_TERRAIN_LAST_INDEX: u32 = 147;
const APPLY_PARAM_RESOURCE_OFFSET: usize = 0x08;
const RENDER_PASS_ENUM_OFFSET: usize = 0x04;
const RENDER_PASS_NUM_LIGHTS_OFFSET: usize = 0x09;
const RENDER_PASS_CURRENT_LAND_TEXTURE_OFFSET: usize = 0x0B;
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
const PBR_DATA_REGISTER: u32 = 32;
const PBR_EXTRA_DATA_REGISTER: u32 = 33;
const TERRAIN_DATA_REGISTER: u32 = 89;
const TERRAIN_EXTRA_DATA_REGISTER: u32 = 90;
const TERRAIN_PARALLAX_DATA_REGISTER: u32 = 91;
const TERRAIN_PARALLAX_EXTRA_DATA_REGISTER: u32 = 92;
const PBR_MATERIAL_SLOT_NORMAL: usize = 1;
const PBR_MATERIAL_SLOT_GLOW: usize = 2;
const PBR_MATERIAL_SLOT_HEIGHT: usize = 3;
const PBR_MATERIAL_SLOT_ENVIRONMENT: usize = 4;
const PBR_MATERIAL_SLOT_ENVIRONMENT_MASK: usize = 5;
const PBR_NORMAL_STAGE: u32 = 1;
const PBR_TERRAIN_NORMAL_STAGE: u32 = 7;
const PBR_ONLY_LIGHT_SI_GLOW_STAGE: u32 = 3;
const PBR_SI_GLOW_STAGE: u32 = 4;
const PBR_GLOW_STAGE: u32 = 2;
const PBR_HEIGHT_STAGE: u32 = 3;
const PBR_ENVIRONMENT_STAGE: u32 = 4;
const PBR_ENVIRONMENT_MASK_STAGE: u32 = 5;
const REPLACEMENT_SHADER_KIND_COUNT: usize = 70;

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
static REPLACEMENT_TERRAIN_CANDIDATE_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_SUMMARY_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_UNSUPPORTED_PAIR_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_CHECKS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_DIFFUSE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_DRAW_CONTEXT: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_UNSUPPORTED_FAMILY: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_MISSING_OBJECT_ROW_CONTRACT: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_SKIN_VERTEX_ABI: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_MISSING_TERRAIN_CONTRACT: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_INTERIOR_TERRAIN_DISABLED: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_INTERIOR_OBJECT_LIGHT_PASS_DISABLED: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_UNPROVEN_LANDLOD_SHADOW: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_SELECTOR_RECORD: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_NORMAL_SOURCE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_GLOW_SOURCE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_SHADOW_SOURCE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_REPLACEMENT_SHADER: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_BIND_FAILED: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_NO_VANILLA_HANDLE: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_SKIP_HANDLE_WRITE_FAILED: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_LAST_FAMILY: AtomicU32 = AtomicU32::new(PPLIGHTING_FAMILY_NONE);
static REPLACEMENT_LAST_VERTEX_GROUP: AtomicU32 = AtomicU32::new(PPLIGHTING_GROUP_NONE);
static REPLACEMENT_LAST_VERTEX_INDEX: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_LAST_PIXEL_GROUP: AtomicU32 = AtomicU32::new(PPLIGHTING_GROUP_NONE);
static REPLACEMENT_LAST_PIXEL_INDEX: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_PIXEL_SHADER_HANDLES: LazyLock<[AtomicUsize; REPLACEMENT_SHADER_KIND_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicUsize::new(0)));
static REPLACEMENT_PIXEL_SHADER_DEVICES: LazyLock<[AtomicUsize; REPLACEMENT_SHADER_KIND_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicUsize::new(0)));
static REPLACEMENT_VERTEX_SHADER_HANDLES: LazyLock<[AtomicUsize; REPLACEMENT_SHADER_KIND_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicUsize::new(0)));
static REPLACEMENT_VERTEX_SHADER_DEVICES: LazyLock<[AtomicUsize; REPLACEMENT_SHADER_KIND_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicUsize::new(0)));
static REPLACEMENT_LANDLOD_VERTEX_SHADER_HANDLE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_LANDLOD_VERTEX_SHADER_DEVICE: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_APPLY_SUMMARY_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_APPLY_KIND_COUNTS: LazyLock<[AtomicU32; REPLACEMENT_SHADER_KIND_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(0)));
static REPLACEMENT_PREWARM_INDEX: AtomicUsize = AtomicUsize::new(0);
static REPLACEMENT_PREWARM_TICK: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_PREWARM_DONE: AtomicBool = AtomicBool::new(false);
static PBR_OBJECT_PROFILE_BITS: LazyLock<
    [[AtomicU32; PBR_PROFILE_VALUE_COUNT]; PBR_PROFILE_COUNT],
> = LazyLock::new(|| array::from_fn(|_| array::from_fn(|_| AtomicU32::new(0))));
static PBR_TERRAIN_PROFILE_BITS: LazyLock<
    [[AtomicU32; PBR_PROFILE_VALUE_COUNT]; PBR_PROFILE_COUNT],
> = LazyLock::new(|| array::from_fn(|_| array::from_fn(|_| AtomicU32::new(0))));
static PBR_TERRAIN_LOD_NOISE_SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static PBR_TERRAIN_LOD_NOISE_TILE_BITS: AtomicU32 = AtomicU32::new(1.75f32.to_bits());
static PBR_STATE_TRANSITION_CURVE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static PBR_STATE_EXTERIOR_KNOWN: AtomicBool = AtomicBool::new(false);
static PBR_STATE_IS_EXTERIOR: AtomicBool = AtomicBool::new(true);
static TERRAIN_CONTRACT_AVAILABLE: AtomicBool = AtomicBool::new(false);

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
static INSTALL_BLOCK_REASON: LazyLock<Mutex<Option<&'static str>>> =
    LazyLock::new(|| Mutex::new(None));
static REPLACEMENT_PIXEL_BYTECODE_STATES: LazyLock<[AtomicU32; REPLACEMENT_SHADER_KIND_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(REPLACEMENT_BYTECODE_MISSING)));
static REPLACEMENT_VERTEX_BYTECODE_STATES: LazyLock<[AtomicU32; REPLACEMENT_SHADER_KIND_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(REPLACEMENT_BYTECODE_MISSING)));
static REPLACEMENT_LANDLOD_VERTEX_BYTECODE_STATE: AtomicU32 =
    AtomicU32::new(REPLACEMENT_BYTECODE_MISSING);
static REPLACEMENT_COMPILE_WORKERS_STARTED: AtomicBool = AtomicBool::new(false);
static REPLACEMENT_COMPILED_BYTECODE: LazyLock<Mutex<Vec<CompiledReplacementShader>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

const PBR_REPLACEMENT_OBJECT_PIXEL_SHADER: &str =
    include_str!("../../shaders/embedded/native_pbr_pplighting_object.hlsl");
const PBR_REPLACEMENT_OBJECT_VERTEX_SHADER: &str =
    include_str!("../../shaders/embedded/native_pbr_pplighting_object.vs.hlsl");
const PBR_REPLACEMENT_CLOSE_TERRAIN_PIXEL_SHADER: &str =
    include_str!("../../shaders/embedded/native_pbr_pplighting_close_terrain.hlsl");
const PBR_REPLACEMENT_LANDLOD_PIXEL_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/native_pbr_pplighting_landlod.hlsl");
const PBR_REPLACEMENT_LANDLOD_VERTEX_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/native_pbr_pplighting_landlod.vs.hlsl");
const REQUIRE_VANILLA_PROLOGUES: bool = true;
const PBR_PROFILE_DEFAULT: usize = 0;
const PBR_PROFILE_RAIN: usize = 1;
const PBR_PROFILE_NIGHT: usize = 2;
const PBR_PROFILE_NIGHT_RAIN: usize = 3;
const PBR_PROFILE_INTERIOR: usize = 4;
const PBR_PROFILE_COUNT: usize = 5;
const PBR_PROFILE_METALLICNESS: usize = 0;
const PBR_PROFILE_ROUGHNESS_SCALE: usize = 1;
const PBR_PROFILE_LIGHT_SCALE: usize = 2;
const PBR_PROFILE_AMBIENT_SCALE: usize = 3;
const PBR_PROFILE_ALBEDO_SATURATION: usize = 4;
const PBR_PROFILE_VALUE_COUNT: usize = 5;
const REPLACEMENT_SHADER_PREWARM_INTERVAL: u32 = 1;
const REPLACEMENT_SHADER_CREATE_BUDGET: usize = 2;
const REPLACEMENT_COMPILE_WORKER_COUNT: usize = 2;
const REPLACEMENT_BYTECODE_MISSING: u32 = 0;
const REPLACEMENT_BYTECODE_QUEUED: u32 = 1;
const REPLACEMENT_BYTECODE_READY: u32 = 2;
const REPLACEMENT_BYTECODE_FAILED: u32 = 3;
const NEUTRAL_NORMAL_ARGB: u32 = 0x0080_80FF;

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePbrSettings {
    enabled: bool,
    debug_log_draws: bool,
    object: NativePbrObjectProfiles,
    terrain: NativePbrTerrainProfiles,
    terrain_lod_noise_scale: f32,
    terrain_lod_noise_tile: f32,
}

#[derive(Clone, Copy, Debug)]
struct NativePbrObjectProfiles {
    default: PbrProfileSettings,
    rain: PbrProfileSettings,
    night: PbrProfileSettings,
    night_rain: PbrProfileSettings,
    interior: PbrProfileSettings,
}

#[derive(Clone, Copy, Debug)]
struct NativePbrTerrainProfiles {
    default: PbrProfileSettings,
    rain: PbrProfileSettings,
    night: PbrProfileSettings,
    night_rain: PbrProfileSettings,
}

#[derive(Clone, Copy, Debug)]
struct PbrProfileSettings {
    metallicness: f32,
    roughness_scale: f32,
    light_scale: f32,
    ambient_scale: f32,
    albedo_saturation: f32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePbrRuntimeStatus {
    pub(crate) installed: bool,
    pub(crate) shader_enabled: bool,
    pub(crate) terrain_contract_available: bool,
    pub(crate) block_reason: Option<&'static str>,
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
            object: NativePbrObjectProfiles::default(),
            terrain: NativePbrTerrainProfiles::default(),
            terrain_lod_noise_scale: 1.0,
            terrain_lod_noise_tile: 1.75,
        }
    }
}

impl Default for NativePbrObjectProfiles {
    fn default() -> Self {
        let default = PbrProfileSettings::default();
        Self {
            default,
            rain: default,
            night: default,
            night_rain: default,
            interior: default,
        }
    }
}

impl Default for NativePbrTerrainProfiles {
    fn default() -> Self {
        let default = PbrProfileSettings::default();
        Self {
            default,
            rain: default,
            night: default,
            night_rain: default,
        }
    }
}

impl Default for PbrProfileSettings {
    fn default() -> Self {
        Self {
            metallicness: 0.0,
            roughness_scale: 1.0,
            light_scale: 1.0,
            ambient_scale: 1.0,
            albedo_saturation: 1.0,
        }
    }
}

impl From<crate::config::NativePbrConfig> for NativePbrSettings {
    fn from(value: crate::config::NativePbrConfig) -> Self {
        let legacy = PbrProfileSettings {
            metallicness: value.metallicness,
            roughness_scale: value.roughness_scale,
            light_scale: value.light_scale,
            ambient_scale: value.ambient_scale,
            albedo_saturation: value.albedo_saturation,
        };
        Self {
            enabled: value.enabled,
            debug_log_draws: value.debug_log_draws,
            object: NativePbrObjectProfiles {
                default: PbrProfileSettings::from_config(value.object_default, legacy),
                rain: PbrProfileSettings::from_config(value.object_rain, legacy),
                night: PbrProfileSettings::from_config(value.object_night, legacy),
                night_rain: PbrProfileSettings::from_config(value.object_night_rain, legacy),
                interior: PbrProfileSettings::from_config(value.object_interior, legacy),
            },
            terrain: NativePbrTerrainProfiles {
                default: PbrProfileSettings::from_config(value.terrain_default, legacy),
                rain: PbrProfileSettings::from_config(value.terrain_rain, legacy),
                night: PbrProfileSettings::from_config(value.terrain_night, legacy),
                night_rain: PbrProfileSettings::from_config(value.terrain_night_rain, legacy),
            },
            terrain_lod_noise_scale: value.terrain_lod_noise_scale,
            terrain_lod_noise_tile: value.terrain_lod_noise_tile,
        }
    }
}

impl PbrProfileSettings {
    fn from_config(
        value: crate::config::NativePbrProfileConfig,
        fallback: PbrProfileSettings,
    ) -> Self {
        if native_pbr_profile_is_neutral_block(value) {
            return fallback;
        }

        Self {
            metallicness: value.metallicness.unwrap_or(fallback.metallicness),
            roughness_scale: value.roughness_scale.unwrap_or(fallback.roughness_scale),
            light_scale: value.light_scale.unwrap_or(fallback.light_scale),
            ambient_scale: value.ambient_scale.unwrap_or(fallback.ambient_scale),
            albedo_saturation: value
                .albedo_saturation
                .unwrap_or(fallback.albedo_saturation),
        }
    }

    fn neutral_terrain() -> Self {
        Self {
            metallicness: 0.0,
            roughness_scale: 1.0,
            light_scale: 1.0,
            ambient_scale: 1.0,
            albedo_saturation: 1.0,
        }
    }

    fn sanitized_values(self) -> [f32; PBR_PROFILE_VALUE_COUNT] {
        [
            sanitize_pbr_scale(self.metallicness, 0.0, 0.0, 1.0),
            sanitize_pbr_scale(self.roughness_scale, 1.0, 0.05, 4.0),
            sanitize_pbr_scale(self.light_scale, 1.0, 0.0, 4.0),
            sanitize_pbr_scale(self.ambient_scale, 1.0, 0.0, 4.0),
            sanitize_pbr_scale(self.albedo_saturation, 1.0, 0.0, 2.0),
        ]
    }
}

fn native_pbr_profile_is_neutral_block(value: crate::config::NativePbrProfileConfig) -> bool {
    value.metallicness == Some(0.0)
        && value.roughness_scale == Some(1.0)
        && value.light_scale == Some(1.0)
        && value.ambient_scale == Some(1.0)
        && value.albedo_saturation == Some(1.0)
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
    ObjectLowOpt,
    ObjectLow,
    ObjectLowSi,
    ObjectLowShadow,
    ObjectLowSiShadow,
    ObjectLowLights2,
    ObjectLowLights2Si,
    ObjectLowLights2Shadow,
    ObjectLowLights2SiShadow,
    ObjectLowSpecular,
    ObjectLowSpecularSi,
    ObjectLowSpecularShadow,
    ObjectLowSpecularSiShadow,
    ObjectLowSpecularLights2,
    ObjectLowSpecularLights2Si,
    ObjectLowSpecularLights2Shadow,
    ObjectLowSpecularLights2SiShadow,
    ObjectLowStbb,
    ObjectHigh6,
    ObjectHigh6Si,
    ObjectHigh4,
    ObjectHigh4Si,
    ObjectHigh4Opt,
    ObjectHigh3Specular,
    ObjectHigh3SpecularSi,
    ObjectHigh3SpecularOpt,
    LandLod,
    CloseTerrain {
        tex_count: u8,
        point_light_count: u8,
    },
    ObjectOnlyLightLights2,
    ObjectOnlyLightLights2Si,
    ObjectOnlyLightLights2Shadow,
    ObjectOnlyLightLights2SiShadow,
    ObjectOnlyLightLights3,
    ObjectOnlyLightLights3Si,
    ObjectOnlyLightLights3Shadow,
    ObjectOnlyLightLights3SiShadow,
    ObjectDiffuseLights2,
    ObjectDiffuseLights3,
    ObjectOnlySpecular,
    ObjectOnlySpecularShadow,
    ObjectOnlySpecularPoint,
    ObjectOnlySpecularPointLights2,
    ObjectOnlySpecularPointLights3,
}

const REPLACEMENT_SHADER_KINDS: [ReplacementShaderKind; REPLACEMENT_SHADER_KIND_COUNT] = [
    ReplacementShaderKind::ObjectLowOpt,
    ReplacementShaderKind::ObjectLow,
    ReplacementShaderKind::ObjectLowSi,
    ReplacementShaderKind::ObjectLowShadow,
    ReplacementShaderKind::ObjectLowSiShadow,
    ReplacementShaderKind::ObjectLowLights2,
    ReplacementShaderKind::ObjectLowLights2Si,
    ReplacementShaderKind::ObjectLowLights2Shadow,
    ReplacementShaderKind::ObjectLowLights2SiShadow,
    ReplacementShaderKind::ObjectLowSpecular,
    ReplacementShaderKind::ObjectLowSpecularSi,
    ReplacementShaderKind::ObjectLowSpecularShadow,
    ReplacementShaderKind::ObjectLowSpecularSiShadow,
    ReplacementShaderKind::ObjectLowSpecularLights2,
    ReplacementShaderKind::ObjectLowSpecularLights2Si,
    ReplacementShaderKind::ObjectLowSpecularLights2Shadow,
    ReplacementShaderKind::ObjectLowSpecularLights2SiShadow,
    ReplacementShaderKind::ObjectLowStbb,
    ReplacementShaderKind::ObjectHigh6,
    ReplacementShaderKind::ObjectHigh6Si,
    ReplacementShaderKind::ObjectHigh4,
    ReplacementShaderKind::ObjectHigh4Si,
    ReplacementShaderKind::ObjectHigh4Opt,
    ReplacementShaderKind::ObjectHigh3Specular,
    ReplacementShaderKind::ObjectHigh3SpecularSi,
    ReplacementShaderKind::ObjectHigh3SpecularOpt,
    ReplacementShaderKind::LandLod,
    ReplacementShaderKind::CloseTerrain {
        tex_count: 1,
        point_light_count: 0,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 1,
        point_light_count: 6,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 1,
        point_light_count: 12,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 1,
        point_light_count: 24,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 2,
        point_light_count: 0,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 2,
        point_light_count: 6,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 2,
        point_light_count: 12,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 2,
        point_light_count: 24,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 3,
        point_light_count: 0,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 3,
        point_light_count: 6,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 3,
        point_light_count: 12,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 3,
        point_light_count: 24,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 4,
        point_light_count: 0,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 4,
        point_light_count: 6,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 4,
        point_light_count: 12,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 4,
        point_light_count: 24,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 5,
        point_light_count: 0,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 5,
        point_light_count: 6,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 5,
        point_light_count: 12,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 5,
        point_light_count: 24,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 6,
        point_light_count: 0,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 6,
        point_light_count: 6,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 6,
        point_light_count: 12,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 6,
        point_light_count: 24,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 7,
        point_light_count: 0,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 7,
        point_light_count: 6,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 7,
        point_light_count: 12,
    },
    ReplacementShaderKind::CloseTerrain {
        tex_count: 7,
        point_light_count: 24,
    },
    ReplacementShaderKind::ObjectOnlyLightLights2,
    ReplacementShaderKind::ObjectOnlyLightLights2Si,
    ReplacementShaderKind::ObjectOnlyLightLights2Shadow,
    ReplacementShaderKind::ObjectOnlyLightLights2SiShadow,
    ReplacementShaderKind::ObjectOnlyLightLights3,
    ReplacementShaderKind::ObjectOnlyLightLights3Si,
    ReplacementShaderKind::ObjectOnlyLightLights3Shadow,
    ReplacementShaderKind::ObjectOnlyLightLights3SiShadow,
    ReplacementShaderKind::ObjectDiffuseLights2,
    ReplacementShaderKind::ObjectDiffuseLights3,
    ReplacementShaderKind::ObjectOnlySpecular,
    ReplacementShaderKind::ObjectOnlySpecularShadow,
    ReplacementShaderKind::ObjectOnlySpecularPoint,
    ReplacementShaderKind::ObjectOnlySpecularPointLights2,
    ReplacementShaderKind::ObjectOnlySpecularPointLights3,
];

const PREWARM_SHADER_KINDS: [ReplacementShaderKind; REPLACEMENT_SHADER_KIND_COUNT] =
    REPLACEMENT_SHADER_KINDS;

#[derive(Clone, Copy)]
struct ObjectRowContract {
    vertex_index: u32,
    pixel_index: u32,
    kind: ReplacementShaderKind,
}

const fn object_row(
    vertex_index: u32,
    pixel_index: u32,
    kind: ReplacementShaderKind,
) -> ObjectRowContract {
    ObjectRowContract {
        vertex_index,
        pixel_index,
        kind,
    }
}

// Source-derived from NVR PBRShaders::Templates(). This is the current
// implemented subset only; missing skin, hair, and hair helper rows remain
// deliberate vanilla fallbacks until their vertex/resource contracts are closed.
const OBJECT_ROW_CONTRACTS: &[ObjectRowContract] = &[
    // ADTS base/object rows.
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_BASE_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_DEFAULT_INDEX,
        ReplacementShaderKind::ObjectLow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_BASE_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_OPT_INDEX,
        ReplacementShaderKind::ObjectLowOpt,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_BASE_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SI_INDEX,
        ReplacementShaderKind::ObjectLowSi,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_LOD_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_OPT_LOD_INDEX,
        ReplacementShaderKind::ObjectLowOpt,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SI_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowSiShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_INDEX,
        ReplacementShaderKind::ObjectLowLights2,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_SI_INDEX,
        ReplacementShaderKind::ObjectLowLights2Si,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowLights2Shadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_SI_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowLights2SiShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_INDEX,
        ReplacementShaderKind::ObjectLowSpecular,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_SI_INDEX,
        ReplacementShaderKind::ObjectLowSpecularSi,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowSpecularShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_SI_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowSpecularSiShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_INDEX,
        ReplacementShaderKind::ObjectLowSpecularLights2,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_SI_INDEX,
        ReplacementShaderKind::ObjectLowSpecularLights2Si,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowSpecularLights2Shadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_SI_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectLowSpecularLights2SiShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS_STBB_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS_STBB_INDEX,
        ReplacementShaderKind::ObjectLowStbb,
    ),
    // ADTS10 high-light rows.
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS9_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS9_INDEX,
        ReplacementShaderKind::ObjectHigh6,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS9_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS9_SI_INDEX,
        ReplacementShaderKind::ObjectHigh6Si,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_INDEX,
        ReplacementShaderKind::ObjectHigh4,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_SI_INDEX,
        ReplacementShaderKind::ObjectHigh4Si,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_OPT_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_OPT_INDEX,
        ReplacementShaderKind::ObjectHigh4Opt,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_SPECULAR_LIGHTS4_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_INDEX,
        ReplacementShaderKind::ObjectHigh3Specular,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_SPECULAR_LIGHTS4_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_SI_INDEX,
        ReplacementShaderKind::ObjectHigh3SpecularSi,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ADTS10_SPECULAR_LIGHTS4_OPT_INDEX,
        PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_OPT_INDEX,
        ReplacementShaderKind::ObjectHigh3SpecularOpt,
    ),
    // Helper rows.
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights2,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_SI_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights2Si,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights2Shadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS2_SI_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights2SiShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights3,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_SI_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights3Si,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights3Shadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_LIGHT_LIGHTS3_SI_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectOnlyLightLights3SiShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_DIFFUSE_LIGHTS2_INDEX,
        ReplacementShaderKind::ObjectDiffuseLights2,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS3_INDEX,
        PPLIGHTING_PIXEL_SLS2_DIFFUSE_LIGHTS3_INDEX,
        ReplacementShaderKind::ObjectDiffuseLights3,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_INDEX,
        ReplacementShaderKind::ObjectOnlySpecular,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_PROJECTED_SHADOW_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_PROJECTED_SHADOW_INDEX,
        ReplacementShaderKind::ObjectOnlySpecularShadow,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_POINT_INDEX,
        ReplacementShaderKind::ObjectOnlySpecularPoint,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS2_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_POINT_LIGHTS2_INDEX,
        ReplacementShaderKind::ObjectOnlySpecularPointLights2,
    ),
    object_row(
        PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS3_INDEX,
        PPLIGHTING_PIXEL_SLS2_ONLY_SPECULAR_POINT_LIGHTS3_INDEX,
        ReplacementShaderKind::ObjectOnlySpecularPointLights3,
    ),
];

fn object_replacement_contract(
    vertex_index: u32,
    pixel_index: u32,
) -> Option<&'static ObjectRowContract> {
    OBJECT_ROW_CONTRACTS.iter().find(|contract| {
        contract.vertex_index == vertex_index && contract.pixel_index == pixel_index
    })
}

impl ReplacementShaderKind {
    fn index(self) -> usize {
        match self {
            Self::ObjectLowOpt => 0,
            Self::ObjectLow => 1,
            Self::ObjectLowSi => 2,
            Self::ObjectLowShadow => 3,
            Self::ObjectLowSiShadow => 4,
            Self::ObjectLowLights2 => 5,
            Self::ObjectLowLights2Si => 6,
            Self::ObjectLowLights2Shadow => 7,
            Self::ObjectLowLights2SiShadow => 8,
            Self::ObjectLowSpecular => 9,
            Self::ObjectLowSpecularSi => 10,
            Self::ObjectLowSpecularShadow => 11,
            Self::ObjectLowSpecularSiShadow => 12,
            Self::ObjectLowSpecularLights2 => 13,
            Self::ObjectLowSpecularLights2Si => 14,
            Self::ObjectLowSpecularLights2Shadow => 15,
            Self::ObjectLowSpecularLights2SiShadow => 16,
            Self::ObjectLowStbb => 17,
            Self::ObjectHigh6 => 18,
            Self::ObjectHigh6Si => 19,
            Self::ObjectHigh4 => 20,
            Self::ObjectHigh4Si => 21,
            Self::ObjectHigh4Opt => 22,
            Self::ObjectHigh3Specular => 23,
            Self::ObjectHigh3SpecularSi => 24,
            Self::ObjectHigh3SpecularOpt => 25,
            Self::LandLod => 26,
            Self::CloseTerrain {
                tex_count,
                point_light_count,
            } => 27 + close_terrain_variant_offset(tex_count, point_light_count),
            Self::ObjectOnlyLightLights2 => 55,
            Self::ObjectOnlyLightLights2Si => 56,
            Self::ObjectOnlyLightLights2Shadow => 57,
            Self::ObjectOnlyLightLights2SiShadow => 58,
            Self::ObjectOnlyLightLights3 => 59,
            Self::ObjectOnlyLightLights3Si => 60,
            Self::ObjectOnlyLightLights3Shadow => 61,
            Self::ObjectOnlyLightLights3SiShadow => 62,
            Self::ObjectDiffuseLights2 => 63,
            Self::ObjectDiffuseLights3 => 64,
            Self::ObjectOnlySpecular => 65,
            Self::ObjectOnlySpecularShadow => 66,
            Self::ObjectOnlySpecularPoint => 67,
            Self::ObjectOnlySpecularPointLights2 => 68,
            Self::ObjectOnlySpecularPointLights3 => 69,
        }
    }

    fn source_name(self) -> &'static str {
        match self {
            Self::ObjectLowOpt => "native_pbr_pplighting_object_low_opt.hlsl",
            Self::ObjectLow => "native_pbr_pplighting_object_low.hlsl",
            Self::ObjectLowSi => "native_pbr_pplighting_object_low_si.hlsl",
            Self::ObjectLowShadow => "native_pbr_pplighting_object_low_shadow.hlsl",
            Self::ObjectLowSiShadow => "native_pbr_pplighting_object_low_si_shadow.hlsl",
            Self::ObjectLowLights2 => "native_pbr_pplighting_object_low_lights2.hlsl",
            Self::ObjectLowLights2Si => "native_pbr_pplighting_object_low_lights2_si.hlsl",
            Self::ObjectLowLights2Shadow => "native_pbr_pplighting_object_low_lights2_shadow.hlsl",
            Self::ObjectLowLights2SiShadow => {
                "native_pbr_pplighting_object_low_lights2_si_shadow.hlsl"
            }
            Self::ObjectLowSpecular => "native_pbr_pplighting_object_low_specular.hlsl",
            Self::ObjectLowSpecularSi => "native_pbr_pplighting_object_low_specular_si.hlsl",
            Self::ObjectLowSpecularShadow => {
                "native_pbr_pplighting_object_low_specular_shadow.hlsl"
            }
            Self::ObjectLowSpecularSiShadow => {
                "native_pbr_pplighting_object_low_specular_si_shadow.hlsl"
            }
            Self::ObjectLowSpecularLights2 => {
                "native_pbr_pplighting_object_low_specular_lights2.hlsl"
            }
            Self::ObjectLowSpecularLights2Si => {
                "native_pbr_pplighting_object_low_specular_lights2_si.hlsl"
            }
            Self::ObjectLowSpecularLights2Shadow => {
                "native_pbr_pplighting_object_low_specular_lights2_shadow.hlsl"
            }
            Self::ObjectLowSpecularLights2SiShadow => {
                "native_pbr_pplighting_object_low_specular_lights2_si_shadow.hlsl"
            }
            Self::ObjectLowStbb => "native_pbr_pplighting_object_low_stbb.hlsl",
            Self::ObjectHigh6 => "native_pbr_pplighting_object_high6.hlsl",
            Self::ObjectHigh6Si => "native_pbr_pplighting_object_high6_si.hlsl",
            Self::ObjectHigh4 => "native_pbr_pplighting_object_high4.hlsl",
            Self::ObjectHigh4Si => "native_pbr_pplighting_object_high4_si.hlsl",
            Self::ObjectHigh4Opt => "native_pbr_pplighting_object_high4_opt.hlsl",
            Self::ObjectHigh3Specular => "native_pbr_pplighting_object_high3_specular.hlsl",
            Self::ObjectHigh3SpecularSi => "native_pbr_pplighting_object_high3_specular_si.hlsl",
            Self::ObjectHigh3SpecularOpt => "native_pbr_pplighting_object_high3_specular_opt.hlsl",
            Self::LandLod => "native_pbr_pplighting_landlod.hlsl",
            Self::CloseTerrain { .. } => "native_pbr_pplighting_close_terrain.hlsl",
            Self::ObjectOnlyLightLights2 => "native_pbr_pplighting_object_only_light_lights2.hlsl",
            Self::ObjectOnlyLightLights2Si => {
                "native_pbr_pplighting_object_only_light_lights2_si.hlsl"
            }
            Self::ObjectOnlyLightLights2Shadow => {
                "native_pbr_pplighting_object_only_light_lights2_shadow.hlsl"
            }
            Self::ObjectOnlyLightLights2SiShadow => {
                "native_pbr_pplighting_object_only_light_lights2_si_shadow.hlsl"
            }
            Self::ObjectOnlyLightLights3 => "native_pbr_pplighting_object_only_light_lights3.hlsl",
            Self::ObjectOnlyLightLights3Si => {
                "native_pbr_pplighting_object_only_light_lights3_si.hlsl"
            }
            Self::ObjectOnlyLightLights3Shadow => {
                "native_pbr_pplighting_object_only_light_lights3_shadow.hlsl"
            }
            Self::ObjectOnlyLightLights3SiShadow => {
                "native_pbr_pplighting_object_only_light_lights3_si_shadow.hlsl"
            }
            Self::ObjectDiffuseLights2 => "native_pbr_pplighting_object_diffuse_lights2.hlsl",
            Self::ObjectDiffuseLights3 => "native_pbr_pplighting_object_diffuse_lights3.hlsl",
            Self::ObjectOnlySpecular => "native_pbr_pplighting_object_only_specular.hlsl",
            Self::ObjectOnlySpecularShadow => {
                "native_pbr_pplighting_object_only_specular_shadow.hlsl"
            }
            Self::ObjectOnlySpecularPoint => {
                "native_pbr_pplighting_object_only_specular_point.hlsl"
            }
            Self::ObjectOnlySpecularPointLights2 => {
                "native_pbr_pplighting_object_only_specular_point_lights2.hlsl"
            }
            Self::ObjectOnlySpecularPointLights3 => {
                "native_pbr_pplighting_object_only_specular_point_lights3.hlsl"
            }
        }
    }

    fn source(self) -> Cow<'static, [u8]> {
        if let Some(defines) = self.object_shader_defines() {
            return Cow::Owned(
                format!("{defines}\n{PBR_REPLACEMENT_OBJECT_PIXEL_SHADER}").into_bytes(),
            );
        }

        if let Self::CloseTerrain {
            tex_count,
            point_light_count,
        } = self
        {
            return Cow::Owned(
                format!(
                    "#define PBR_TERRAIN_TEX_COUNT {tex_count}\n#define PBR_TERRAIN_POINT_LIGHTS {point_light_count}\n{PBR_REPLACEMENT_CLOSE_TERRAIN_PIXEL_SHADER}"
                )
                .into_bytes(),
            );
        }

        Cow::Borrowed(PBR_REPLACEMENT_LANDLOD_PIXEL_SHADER)
    }

    fn is_object_kind(self) -> bool {
        !matches!(self, Self::LandLod | Self::CloseTerrain { .. })
    }

    fn object_shader_defines(self) -> Option<&'static str> {
        match self {
            Self::ObjectLowOpt => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 1",
            ),
            Self::ObjectLow => Some("#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1"),
            Self::ObjectLowSi => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectLowShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectLowSiShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectLowLights2 => Some("#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2"),
            Self::ObjectLowLights2Si => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectLowLights2Shadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectLowLights2SiShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectLowSpecular => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1",
            ),
            Self::ObjectLowSpecularSi => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectLowSpecularShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectLowSpecularSiShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectLowSpecularLights2 => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1",
            ),
            Self::ObjectLowSpecularLights2Si => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectLowSpecularLights2Shadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectLowSpecularLights2SiShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectHigh6 => Some("#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 6"),
            Self::ObjectHigh6Si => Some(
                "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 6\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectHigh4 => Some("#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4"),
            Self::ObjectHigh4Si => Some(
                "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectHigh4Opt => Some(
                "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 4",
            ),
            Self::ObjectHigh3Specular => Some(
                "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SPECULAR 1",
            ),
            Self::ObjectHigh3SpecularSi => Some(
                "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectHigh3SpecularOpt => Some(
                "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SPECULAR 1",
            ),
            Self::ObjectLowStbb => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_STBB 1",
            ),
            Self::ObjectOnlyLightLights2 => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2",
            ),
            Self::ObjectOnlyLightLights2Si => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectOnlyLightLights2Shadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectOnlyLightLights2SiShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectOnlyLightLights3 => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3",
            ),
            Self::ObjectOnlyLightLights3Si => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SI 1",
            ),
            Self::ObjectOnlyLightLights3Shadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectOnlyLightLights3SiShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
            ),
            Self::ObjectDiffuseLights2 => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2",
            ),
            Self::ObjectDiffuseLights3 => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3",
            ),
            Self::ObjectOnlySpecular => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1",
            ),
            Self::ObjectOnlySpecularShadow => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_LIGHTS 1",
            ),
            Self::ObjectOnlySpecularPoint => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 1",
            ),
            Self::ObjectOnlySpecularPointLights2 => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2",
            ),
            Self::ObjectOnlySpecularPointLights3 => Some(
                "#define PBR_OBJECT_LOW 1\n#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3",
            ),
            Self::LandLod | Self::CloseTerrain { .. } => None,
        }
    }

    fn vertex_source_name(self) -> Option<&'static str> {
        match self {
            Self::LandLod => Some("native_pbr_pplighting_landlod.vs.hlsl"),
            _ if self.is_object_kind() => Some("native_pbr_pplighting_object.vs.hlsl"),
            _ => None,
        }
    }

    fn vertex_source(self) -> Option<Cow<'static, [u8]>> {
        if let Some(defines) = self.object_shader_defines() {
            return Some(Cow::Owned(
                format!("{defines}\n{PBR_REPLACEMENT_OBJECT_VERTEX_SHADER}").into_bytes(),
            ));
        }

        match self {
            Self::LandLod => Some(Cow::Borrowed(PBR_REPLACEMENT_LANDLOD_VERTEX_SHADER)),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ObjectLowOpt => "object_low_opt",
            Self::ObjectLow => "object_low",
            Self::ObjectLowSi => "object_low_si",
            Self::ObjectLowShadow => "object_low_shadow",
            Self::ObjectLowSiShadow => "object_low_si_shadow",
            Self::ObjectLowLights2 => "object_low_lights2",
            Self::ObjectLowLights2Si => "object_low_lights2_si",
            Self::ObjectLowLights2Shadow => "object_low_lights2_shadow",
            Self::ObjectLowLights2SiShadow => "object_low_lights2_si_shadow",
            Self::ObjectLowSpecular => "object_low_specular",
            Self::ObjectLowSpecularSi => "object_low_specular_si",
            Self::ObjectLowSpecularShadow => "object_low_specular_shadow",
            Self::ObjectLowSpecularSiShadow => "object_low_specular_si_shadow",
            Self::ObjectLowSpecularLights2 => "object_low_specular_lights2",
            Self::ObjectLowSpecularLights2Si => "object_low_specular_lights2_si",
            Self::ObjectLowSpecularLights2Shadow => "object_low_specular_lights2_shadow",
            Self::ObjectLowSpecularLights2SiShadow => "object_low_specular_lights2_si_shadow",
            Self::ObjectLowStbb => "object_low_stbb",
            Self::ObjectHigh6 => "object_high6",
            Self::ObjectHigh6Si => "object_high6_si",
            Self::ObjectHigh4 => "object_high4",
            Self::ObjectHigh4Si => "object_high4_si",
            Self::ObjectHigh4Opt => "object_high4_opt",
            Self::ObjectHigh3Specular => "object_high3_specular",
            Self::ObjectHigh3SpecularSi => "object_high3_specular_si",
            Self::ObjectHigh3SpecularOpt => "object_high3_specular_opt",
            Self::LandLod => "landlod",
            Self::CloseTerrain {
                tex_count: 1,
                point_light_count: 0,
            } => "close_terrain_tex1_lights0",
            Self::CloseTerrain {
                tex_count: 1,
                point_light_count: 6,
            } => "close_terrain_tex1_lights6",
            Self::CloseTerrain {
                tex_count: 1,
                point_light_count: 12,
            } => "close_terrain_tex1_lights12",
            Self::CloseTerrain {
                tex_count: 1,
                point_light_count: 24,
            } => "close_terrain_tex1_lights24",
            Self::CloseTerrain {
                tex_count: 2,
                point_light_count: 0,
            } => "close_terrain_tex2_lights0",
            Self::CloseTerrain {
                tex_count: 2,
                point_light_count: 6,
            } => "close_terrain_tex2_lights6",
            Self::CloseTerrain {
                tex_count: 2,
                point_light_count: 12,
            } => "close_terrain_tex2_lights12",
            Self::CloseTerrain {
                tex_count: 2,
                point_light_count: 24,
            } => "close_terrain_tex2_lights24",
            Self::CloseTerrain {
                tex_count: 3,
                point_light_count: 0,
            } => "close_terrain_tex3_lights0",
            Self::CloseTerrain {
                tex_count: 3,
                point_light_count: 6,
            } => "close_terrain_tex3_lights6",
            Self::CloseTerrain {
                tex_count: 3,
                point_light_count: 12,
            } => "close_terrain_tex3_lights12",
            Self::CloseTerrain {
                tex_count: 3,
                point_light_count: 24,
            } => "close_terrain_tex3_lights24",
            Self::CloseTerrain {
                tex_count: 4,
                point_light_count: 0,
            } => "close_terrain_tex4_lights0",
            Self::CloseTerrain {
                tex_count: 4,
                point_light_count: 6,
            } => "close_terrain_tex4_lights6",
            Self::CloseTerrain {
                tex_count: 4,
                point_light_count: 12,
            } => "close_terrain_tex4_lights12",
            Self::CloseTerrain {
                tex_count: 4,
                point_light_count: 24,
            } => "close_terrain_tex4_lights24",
            Self::CloseTerrain {
                tex_count: 5,
                point_light_count: 0,
            } => "close_terrain_tex5_lights0",
            Self::CloseTerrain {
                tex_count: 5,
                point_light_count: 6,
            } => "close_terrain_tex5_lights6",
            Self::CloseTerrain {
                tex_count: 5,
                point_light_count: 12,
            } => "close_terrain_tex5_lights12",
            Self::CloseTerrain {
                tex_count: 5,
                point_light_count: 24,
            } => "close_terrain_tex5_lights24",
            Self::CloseTerrain {
                tex_count: 6,
                point_light_count: 0,
            } => "close_terrain_tex6_lights0",
            Self::CloseTerrain {
                tex_count: 6,
                point_light_count: 6,
            } => "close_terrain_tex6_lights6",
            Self::CloseTerrain {
                tex_count: 6,
                point_light_count: 12,
            } => "close_terrain_tex6_lights12",
            Self::CloseTerrain {
                tex_count: 6,
                point_light_count: 24,
            } => "close_terrain_tex6_lights24",
            Self::CloseTerrain {
                tex_count: 7,
                point_light_count: 0,
            } => "close_terrain_tex7_lights0",
            Self::CloseTerrain {
                tex_count: 7,
                point_light_count: 6,
            } => "close_terrain_tex7_lights6",
            Self::CloseTerrain {
                tex_count: 7,
                point_light_count: 12,
            } => "close_terrain_tex7_lights12",
            Self::CloseTerrain {
                tex_count: 7,
                point_light_count: 24,
            } => "close_terrain_tex7_lights24",
            Self::ObjectOnlyLightLights2 => "object_only_light_lights2",
            Self::ObjectOnlyLightLights2Si => "object_only_light_lights2_si",
            Self::ObjectOnlyLightLights2Shadow => "object_only_light_lights2_shadow",
            Self::ObjectOnlyLightLights2SiShadow => "object_only_light_lights2_si_shadow",
            Self::ObjectOnlyLightLights3 => "object_only_light_lights3",
            Self::ObjectOnlyLightLights3Si => "object_only_light_lights3_si",
            Self::ObjectOnlyLightLights3Shadow => "object_only_light_lights3_shadow",
            Self::ObjectOnlyLightLights3SiShadow => "object_only_light_lights3_si_shadow",
            Self::ObjectDiffuseLights2 => "object_diffuse_lights2",
            Self::ObjectDiffuseLights3 => "object_diffuse_lights3",
            Self::ObjectOnlySpecular => "object_only_specular",
            Self::ObjectOnlySpecularShadow => "object_only_specular_shadow",
            Self::ObjectOnlySpecularPoint => "object_only_specular_point",
            Self::ObjectOnlySpecularPointLights2 => "object_only_specular_point_lights2",
            Self::ObjectOnlySpecularPointLights3 => "object_only_specular_point_lights3",
            Self::CloseTerrain { .. } => "close_terrain_invalid",
        }
    }

    fn cached_device(self) -> &'static AtomicUsize {
        &REPLACEMENT_PIXEL_SHADER_DEVICES[self.index()]
    }

    fn cached_handle(self) -> &'static AtomicUsize {
        &REPLACEMENT_PIXEL_SHADER_HANDLES[self.index()]
    }

    fn cached_vertex_device(self) -> Option<&'static AtomicUsize> {
        match self {
            Self::LandLod => Some(&REPLACEMENT_LANDLOD_VERTEX_SHADER_DEVICE),
            _ if self.is_object_kind() => Some(&REPLACEMENT_VERTEX_SHADER_DEVICES[self.index()]),
            _ => None,
        }
    }

    fn cached_vertex_handle(self) -> Option<&'static AtomicUsize> {
        match self {
            Self::LandLod => Some(&REPLACEMENT_LANDLOD_VERTEX_SHADER_HANDLE),
            _ if self.is_object_kind() => Some(&REPLACEMENT_VERTEX_SHADER_HANDLES[self.index()]),
            _ => None,
        }
    }

    fn replaces_vertex_shader(self) -> bool {
        matches!(self, Self::LandLod) || self.is_object_kind()
    }

    fn runtime_enabled(self) -> bool {
        !matches!(
            self,
            Self::CloseTerrain {
                point_light_count: 6 | 12 | 24,
                ..
            }
        )
    }

    fn uses_terrain_constants(self) -> bool {
        matches!(self, Self::LandLod | Self::CloseTerrain { .. })
    }

    fn close_terrain_variant(self) -> Option<(u8, u8)> {
        match self {
            Self::CloseTerrain {
                tex_count,
                point_light_count,
            } => Some((tex_count, point_light_count)),
            _ => None,
        }
    }

    fn uses_extra_material_stages(self) -> bool {
        false
    }

    fn uses_selector_material_resources(self) -> bool {
        false
    }

    fn writes_material_flags(self) -> bool {
        false
    }

    fn normal_stage(self) -> Option<u32> {
        match self {
            Self::CloseTerrain { .. } => Some(PBR_TERRAIN_NORMAL_STAGE),
            Self::ObjectDiffuseLights2
            | Self::ObjectDiffuseLights3
            | Self::ObjectOnlySpecular
            | Self::ObjectOnlySpecularShadow
            | Self::ObjectOnlySpecularPoint
            | Self::ObjectOnlySpecularPointLights2
            | Self::ObjectOnlySpecularPointLights3 => Some(0),
            _ => Some(PBR_NORMAL_STAGE),
        }
    }

    fn allows_neutral_normal_fallback(self) -> bool {
        self.is_object_kind()
    }

    fn glow_stage(self) -> Option<u32> {
        match self {
            Self::ObjectOnlyLightLights2Si
            | Self::ObjectOnlyLightLights2SiShadow
            | Self::ObjectOnlyLightLights3Si
            | Self::ObjectOnlyLightLights3SiShadow => Some(PBR_ONLY_LIGHT_SI_GLOW_STAGE),
            Self::ObjectLowSi
            | Self::ObjectLowSiShadow
            | Self::ObjectLowLights2Si
            | Self::ObjectLowLights2SiShadow
            | Self::ObjectLowSpecularSi
            | Self::ObjectLowSpecularSiShadow
            | Self::ObjectLowSpecularLights2Si
            | Self::ObjectLowSpecularLights2SiShadow
            | Self::ObjectHigh6Si
            | Self::ObjectHigh4Si
            | Self::ObjectHigh3SpecularSi => Some(PBR_SI_GLOW_STAGE),
            _ => None,
        }
    }

    fn samples_object_diffuse(self) -> bool {
        !matches!(
            self,
            Self::LandLod
                | Self::CloseTerrain { .. }
                | Self::ObjectDiffuseLights2
                | Self::ObjectDiffuseLights3
                | Self::ObjectOnlySpecular
                | Self::ObjectOnlySpecularShadow
                | Self::ObjectOnlySpecularPoint
                | Self::ObjectOnlySpecularPointLights2
                | Self::ObjectOnlySpecularPointLights3
        )
    }

    fn shadow_stages(self) -> Option<(u32, u32)> {
        match self {
            Self::ObjectOnlySpecularShadow => Some((4, 5)),
            Self::ObjectOnlyLightLights2Shadow
            | Self::ObjectOnlyLightLights2SiShadow
            | Self::ObjectOnlyLightLights3Shadow
            | Self::ObjectOnlyLightLights3SiShadow => Some((5, 6)),
            Self::ObjectLowShadow
            | Self::ObjectLowSiShadow
            | Self::ObjectLowLights2Shadow
            | Self::ObjectLowLights2SiShadow
            | Self::ObjectLowSpecularShadow
            | Self::ObjectLowSpecularSiShadow
            | Self::ObjectLowSpecularLights2Shadow
            | Self::ObjectLowSpecularLights2SiShadow => Some((6, 7)),
            _ => None,
        }
    }
}

fn close_terrain_variant_offset(tex_count: u8, point_light_count: u8) -> usize {
    let tex_index = tex_count.saturating_sub(1).min(6) as usize;
    (tex_index * 4) + close_terrain_point_light_tier(point_light_count)
}

fn close_terrain_point_light_tier(point_light_count: u8) -> usize {
    match point_light_count {
        0 => 0,
        6 => 1,
        12 => 2,
        24 => 3,
        _ => 0,
    }
}

fn vpt_close_terrain_kind_from_pixel_index(pixel_index: u32) -> Option<ReplacementShaderKind> {
    if !(PPLIGHTING_PIXEL_SLS2_VPT_CLOSE_TERRAIN_FIRST_INDEX
        ..=PPLIGHTING_PIXEL_SLS2_VPT_CLOSE_TERRAIN_LAST_INDEX)
        .contains(&pixel_index)
    {
        return None;
    }

    let local_index = pixel_index - PPLIGHTING_PIXEL_SLS2_VPT_CLOSE_TERRAIN_FIRST_INDEX;
    if local_index % 2 != 0 {
        return None;
    }
    let tex_count = ((local_index / 8) + 1) as u8;
    let point_light_count = match (local_index % 8) / 2 {
        0 => 0,
        1 => 6,
        2 => 12,
        _ => 24,
    };
    if point_light_count != 0 {
        return None;
    }

    Some(ReplacementShaderKind::CloseTerrain {
        tex_count,
        point_light_count,
    })
}

struct PbrReplacementState {
    device: usize,
    pixel_slots: [PbrShaderSlot; REPLACEMENT_SHADER_KIND_COUNT],
    vertex_slots: [PbrVertexShaderSlot; REPLACEMENT_SHADER_KIND_COUNT],
    landlod: PbrShaderSlot,
    landlod_vertex: PbrVertexShaderSlot,
    neutral_normal: Option<Texture9>,
}

impl PbrReplacementState {
    fn new() -> Self {
        Self {
            device: 0,
            pixel_slots: array::from_fn(|_| PbrShaderSlot::new()),
            vertex_slots: array::from_fn(|_| PbrVertexShaderSlot::new()),
            landlod: PbrShaderSlot::new(),
            landlod_vertex: PbrVertexShaderSlot::new(),
            neutral_normal: None,
        }
    }

    fn release(&mut self) {
        self.device = 0;
        for slot in &mut self.pixel_slots {
            slot.release();
        }
        for slot in &mut self.vertex_slots {
            slot.release();
        }
        self.landlod.release();
        self.landlod_vertex.release();
        self.neutral_normal = None;
        for device in REPLACEMENT_PIXEL_SHADER_DEVICES.iter() {
            device.store(0, Ordering::Release);
        }
        for handle in REPLACEMENT_PIXEL_SHADER_HANDLES.iter() {
            handle.store(0, Ordering::Release);
        }
        for device in REPLACEMENT_VERTEX_SHADER_DEVICES.iter() {
            device.store(0, Ordering::Release);
        }
        for handle in REPLACEMENT_VERTEX_SHADER_HANDLES.iter() {
            handle.store(0, Ordering::Release);
        }
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
            ReplacementShaderKind::LandLod => self
                .landlod_vertex
                .vertex_shader_handle(kind, device, device_ptr),
            _ if kind.replaces_vertex_shader() => {
                self.vertex_slots[kind.index()].vertex_shader_handle(kind, device, device_ptr)
            }
            _ => None,
        }
    }

    fn neutral_normal_handle(
        &mut self,
        device: &Device9Ref<'_>,
        device_ptr: usize,
    ) -> Option<*mut c_void> {
        if self.device != device_ptr {
            self.release();
            self.device = device_ptr;
        }

        if self.neutral_normal.is_none() {
            let texture = match device.create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
            {
                Ok(texture) => texture,
                Err(err) => {
                    log_limited(
                        &REPLACEMENT_RESOURCE_LOGS,
                        &format!(
                            "[PBR] Native PBR neutral normal texture creation failed: {err:?}"
                        ),
                    );
                    return None;
                }
            };

            if let Err(err) = texture.write_level0_argb_pixel(NEUTRAL_NORMAL_ARGB) {
                log_limited(
                    &REPLACEMENT_RESOURCE_LOGS,
                    &format!("[PBR] Native PBR neutral normal texture upload failed: {err:?}"),
                );
                return None;
            }

            log::info!("[PBR] Native PBR neutral normal texture created");
            self.neutral_normal = Some(texture);
        }

        self.neutral_normal
            .as_ref()
            .map(Texture9::as_raw_base_texture)
    }

    fn slot_mut(&mut self, kind: ReplacementShaderKind) -> &mut PbrShaderSlot {
        if kind == ReplacementShaderKind::LandLod {
            &mut self.landlod
        } else {
            &mut self.pixel_slots[kind.index()]
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementShaderTarget {
    Pixel,
    Vertex,
}

impl ReplacementShaderTarget {
    fn profile(self) -> &'static str {
        match self {
            Self::Pixel => "ps_3_0",
            Self::Vertex => "vs_3_0",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Pixel => "pso",
            Self::Vertex => "vso",
        }
    }
}

#[derive(Clone, Copy)]
struct ReplacementCompileJob {
    kind: ReplacementShaderKind,
    target: ReplacementShaderTarget,
}

struct CompiledReplacementShader {
    kind: ReplacementShaderKind,
    target: ReplacementShaderTarget,
    bytecode: Vec<u32>,
}

fn start_replacement_shader_compiler() {
    if REPLACEMENT_COMPILE_WORKERS_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }

    let jobs = replacement_compile_jobs();
    if jobs.is_empty() {
        log::info!("[PBR] Native PBR async compile skipped because no shaders are eligible");
        return;
    }

    let job_count = jobs.len();
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let worker_count = REPLACEMENT_COMPILE_WORKER_COUNT.min(job_count).max(1);
    log::info!(
        "[PBR] Native PBR async compile queued {} shader(s) on {} worker(s)",
        job_count,
        worker_count
    );

    for worker_index in 0..worker_count {
        let queue = Arc::clone(&queue);
        if let Err(err) = thread::Builder::new()
            .name(format!("omv-pbr-compile-{worker_index}"))
            .spawn(move || replacement_shader_compile_worker(worker_index, queue))
        {
            log::warn!(
                "[PBR] Native PBR async compile worker {worker_index} failed to start: {err}"
            );
        }
    }
}

fn replacement_compile_jobs() -> Vec<ReplacementCompileJob> {
    let mut jobs = Vec::with_capacity(PREWARM_SHADER_KINDS.len() + 1);
    let terrain_contract_available = TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire);

    for kind in PREWARM_SHADER_KINDS {
        if !kind.runtime_enabled() {
            continue;
        }
        if kind.uses_terrain_constants() && !terrain_contract_available {
            continue;
        }

        if queue_replacement_compile_job(kind, ReplacementShaderTarget::Pixel) {
            jobs.push(ReplacementCompileJob {
                kind,
                target: ReplacementShaderTarget::Pixel,
            });
        }

        if kind.replaces_vertex_shader()
            && queue_replacement_compile_job(kind, ReplacementShaderTarget::Vertex)
        {
            jobs.push(ReplacementCompileJob {
                kind,
                target: ReplacementShaderTarget::Vertex,
            });
        }
    }

    jobs
}

fn queue_replacement_compile_job(
    kind: ReplacementShaderKind,
    target: ReplacementShaderTarget,
) -> bool {
    let Some(state) = replacement_shader_bytecode_state(kind, target) else {
        return false;
    };

    state
        .compare_exchange(
            REPLACEMENT_BYTECODE_MISSING,
            REPLACEMENT_BYTECODE_QUEUED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

fn replacement_shader_compile_worker(
    worker_index: usize,
    queue: Arc<Mutex<VecDeque<ReplacementCompileJob>>>,
) {
    loop {
        let Some(job) = queue.lock().pop_front() else {
            log::info!("[PBR] Native PBR async compile worker {worker_index} finished");
            return;
        };

        compile_replacement_shader_job(worker_index, job);
    }
}

fn compile_replacement_shader_job(worker_index: usize, job: ReplacementCompileJob) {
    let started = Instant::now();
    match load_or_compile_replacement_shader(job) {
        Ok((bytecode, source)) => {
            let elapsed = started.elapsed().as_millis();
            REPLACEMENT_COMPILED_BYTECODE
                .lock()
                .push(CompiledReplacementShader {
                    kind: job.kind,
                    target: job.target,
                    bytecode,
                });
            if let Some(state) = replacement_shader_bytecode_state(job.kind, job.target) {
                state.store(REPLACEMENT_BYTECODE_READY, Ordering::Release);
            }
            log::info!(
                "[PBR] Native PBR async compile worker={} kind={} target={} source={} ms={}",
                worker_index,
                job.kind.label(),
                job.target.profile(),
                source,
                elapsed
            );
        }
        Err(err) => {
            if let Some(state) = replacement_shader_bytecode_state(job.kind, job.target) {
                state.store(REPLACEMENT_BYTECODE_FAILED, Ordering::Release);
            }
            log::warn!(
                "[PBR] Native PBR async compile failed worker={} kind={} target={}: {err:#}",
                worker_index,
                job.kind.label(),
                job.target.profile()
            );
        }
    }
}

fn load_or_compile_replacement_shader(
    job: ReplacementCompileJob,
) -> Result<(Vec<u32>, &'static str)> {
    let (source_name, source) = replacement_shader_source(job)?;
    let source_hash = replacement_shader_source_hash(job, source.as_ref());
    let cache_path = replacement_shader_cache_path(job, source_hash);

    if let Some(bytecode) = read_replacement_shader_cache(&cache_path) {
        return Ok((bytecode, "cache"));
    }

    let compile_name = format!("{}:{}", source_name, job.kind.label());
    let bytecode = crate::shaders::compile_hlsl_source_target(
        &compile_name,
        source.as_ref(),
        job.target.profile(),
    )?;
    write_replacement_shader_cache(&cache_path, &bytecode);
    Ok((bytecode, "compiler"))
}

fn replacement_shader_source(
    job: ReplacementCompileJob,
) -> Result<(&'static str, Cow<'static, [u8]>)> {
    match job.target {
        ReplacementShaderTarget::Pixel => Ok((job.kind.source_name(), job.kind.source())),
        ReplacementShaderTarget::Vertex => {
            let Some(source_name) = job.kind.vertex_source_name() else {
                anyhow::bail!("replacement shader has no vertex source");
            };
            let Some(source) = job.kind.vertex_source() else {
                anyhow::bail!("replacement shader has no vertex source bytes");
            };
            Ok((source_name, source))
        }
    }
}

fn replacement_shader_source_hash(job: ReplacementCompileJob, source: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    hash = fnv1a_hash_bytes(hash, job.kind.label().as_bytes());
    hash = fnv1a_hash_bytes(hash, job.target.profile().as_bytes());
    fnv1a_hash_bytes(hash, source)
}

fn fnv1a_hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn replacement_shader_cache_path(job: ReplacementCompileJob, source_hash: u64) -> PathBuf {
    let mut path = PathBuf::from(crate::config::CONFIG_PATH);
    let _ = path.pop();
    path.push("cache");
    path.push("native_pbr");
    path.push(format!(
        "{}_{}_{source_hash:016x}.cso",
        job.kind.label(),
        job.target.suffix()
    ));
    path
}

fn read_replacement_shader_cache(path: &Path) -> Option<Vec<u32>> {
    let bytes = fs::read(path).ok()?;
    match dword_aligned_replacement_bytecode(&bytes) {
        Ok(bytecode) => Some(bytecode),
        Err(err) => {
            log::warn!(
                "[PBR] Ignoring invalid native PBR shader cache '{}': {err:#}",
                path.display()
            );
            None
        }
    }
}

fn write_replacement_shader_cache(path: &Path, bytecode: &[u32]) {
    if let Some(parent) = path.parent()
        && let Err(err) = fs::create_dir_all(parent)
    {
        log::warn!(
            "[PBR] Native PBR shader cache directory '{}' could not be created: {err}",
            parent.display()
        );
        return;
    }

    let mut bytes = Vec::with_capacity(std::mem::size_of_val(bytecode));
    for word in bytecode {
        bytes.extend_from_slice(&word.to_le_bytes());
    }

    if let Err(err) = fs::write(path, bytes) {
        log::warn!(
            "[PBR] Native PBR shader cache '{}' could not be written: {err}",
            path.display()
        );
    }
}

fn dword_aligned_replacement_bytecode(bytes: &[u8]) -> Result<Vec<u32>> {
    if bytes.is_empty() {
        anyhow::bail!("shader bytecode is empty");
    }
    if bytes.len() % size_of::<u32>() != 0 {
        anyhow::bail!("shader bytecode length is not DWORD aligned");
    }

    Ok(bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn take_compiled_replacement_bytecode(
    kind: ReplacementShaderKind,
    target: ReplacementShaderTarget,
) -> Option<Vec<u32>> {
    let mut bytecode = REPLACEMENT_COMPILED_BYTECODE.lock();
    let index = bytecode
        .iter()
        .position(|entry| entry.kind == kind && entry.target == target)?;
    Some(bytecode.swap_remove(index).bytecode)
}

fn replacement_shader_bytecode_failed(
    kind: ReplacementShaderKind,
    target: ReplacementShaderTarget,
) -> bool {
    replacement_shader_bytecode_state(kind, target)
        .map(|state| state.load(Ordering::Acquire) == REPLACEMENT_BYTECODE_FAILED)
        .unwrap_or(true)
}

fn replacement_shader_bytecode_pending(
    kind: ReplacementShaderKind,
    target: ReplacementShaderTarget,
) -> bool {
    replacement_shader_bytecode_state(kind, target)
        .map(|state| {
            matches!(
                state.load(Ordering::Acquire),
                REPLACEMENT_BYTECODE_MISSING | REPLACEMENT_BYTECODE_QUEUED
            )
        })
        .unwrap_or(false)
}

fn replacement_shader_bytecode_state(
    kind: ReplacementShaderKind,
    target: ReplacementShaderTarget,
) -> Option<&'static AtomicU32> {
    match target {
        ReplacementShaderTarget::Pixel => Some(&REPLACEMENT_PIXEL_BYTECODE_STATES[kind.index()]),
        ReplacementShaderTarget::Vertex => match kind {
            ReplacementShaderKind::LandLod => Some(&REPLACEMENT_LANDLOD_VERTEX_BYTECODE_STATE),
            _ if kind.replaces_vertex_shader() => {
                Some(&REPLACEMENT_VERTEX_BYTECODE_STATES[kind.index()])
            }
            _ => None,
        },
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

    fn load_ready_bytecode(&mut self, kind: ReplacementShaderKind) -> Option<&[u32]> {
        if self.bytecode.is_none() {
            if replacement_shader_bytecode_failed(kind, ReplacementShaderTarget::Pixel) {
                self.compile_failed = true;
                return None;
            }
            if let Some(bytecode) =
                take_compiled_replacement_bytecode(kind, ReplacementShaderTarget::Pixel)
            {
                self.bytecode = Some(bytecode);
            }
        }

        self.bytecode.as_deref()
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

        let create_result = {
            let bytecode = self.load_ready_bytecode(kind)?;
            device.create_pixel_shader(bytecode)
        };

        match create_result {
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

    fn load_ready_bytecode(&mut self, kind: ReplacementShaderKind) -> Option<&[u32]> {
        if self.bytecode.is_none() {
            if replacement_shader_bytecode_failed(kind, ReplacementShaderTarget::Vertex) {
                self.compile_failed = true;
                return None;
            }
            if let Some(bytecode) =
                take_compiled_replacement_bytecode(kind, ReplacementShaderTarget::Vertex)
            {
                self.bytecode = Some(bytecode);
            }
        }

        self.bytecode.as_deref()
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

        let create_result = {
            let bytecode = self.load_ready_bytecode(kind)?;
            device.create_vertex_shader(bytecode)
        };

        match create_result {
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
    render_pass_enum: u16,
    render_pass_num_lights: u8,
    render_pass_current_land_texture: u8,
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
struct ReplacementRecord {
    kind: ReplacementShaderKind,
    constants: ReplacementConstantContract,
    samplers: ReplacementSamplerContract,
    material_source: ReplacementMaterialSource,
    sampler_clear: ReplacementSamplerClearPolicy,
}

impl ReplacementRecord {
    fn for_kind(kind: ReplacementShaderKind) -> Self {
        Self {
            kind,
            constants: ReplacementConstantContract::for_kind(kind),
            samplers: ReplacementSamplerContract::for_kind(kind),
            material_source: ReplacementMaterialSource::for_kind(kind),
            sampler_clear: ReplacementSamplerClearPolicy::for_kind(kind),
        }
    }

    fn validate_textures(self) -> std::result::Result<(), ReplacementSkipReason> {
        self.samplers.validate(self.kind)
    }

    unsafe fn material_bindings(
        self,
    ) -> std::result::Result<ReplacementMaterialBindings, ReplacementSkipReason> {
        match self.material_source {
            ReplacementMaterialSource::VanillaBound => unsafe {
                bind_vanilla_or_neutral_material_textures(self.kind)
            },
            ReplacementMaterialSource::SelectorMaterialArrays => {
                let material_resources = match unsafe { replacement_material_resources(self.kind) }
                {
                    Ok(material_resources) => material_resources,
                    Err(ReplacementMaterialResourceError::NoSelectorRecord) => {
                        return Err(ReplacementSkipReason::NoSelectorRecord);
                    }
                    Err(ReplacementMaterialResourceError::NoNormalSource) => {
                        return Err(ReplacementSkipReason::NoNormalSource);
                    }
                };

                unsafe { bind_replacement_material_textures(material_resources, self.kind) }
                    .ok_or(ReplacementSkipReason::BindFailed)
            }
        }
    }

    fn apply_constants(self, bindings: ReplacementMaterialBindings) {
        upload_replacement_record_constants(self.constants, self.kind, bindings);
    }

    fn apply_sampler_policy(self) {
        match self.sampler_clear {
            ReplacementSamplerClearPolicy::PreserveVanilla => {}
            ReplacementSamplerClearPolicy::ClearExtraMaterialStages => {
                configure_pbr_sampler_states()
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ReplacementConstantContract {
    ObjectPbr,
    TerrainPbr,
}

impl ReplacementConstantContract {
    fn for_kind(kind: ReplacementShaderKind) -> Self {
        if kind.uses_terrain_constants() {
            Self::TerrainPbr
        } else {
            Self::ObjectPbr
        }
    }
}

#[derive(Clone, Copy)]
struct ReplacementSamplerContract {
    diffuse: RequiredSamplerSet,
    normal: RequiredSamplerSet,
    glow_stage: Option<u32>,
    shadow_stages: Option<(u32, u32)>,
    extra: ReplacementExtraSamplerContract,
}

impl ReplacementSamplerContract {
    fn for_kind(kind: ReplacementShaderKind) -> Self {
        if let Some((tex_count, _)) = kind.close_terrain_variant() {
            return Self {
                diffuse: RequiredSamplerSet::Range {
                    first_stage: 0,
                    count: tex_count.clamp(1, 7),
                    reason: ReplacementSkipReason::NoDiffuse,
                },
                normal: RequiredSamplerSet::Range {
                    first_stage: PBR_TERRAIN_NORMAL_STAGE,
                    count: tex_count.clamp(1, 7),
                    reason: ReplacementSkipReason::NoNormalSource,
                },
                glow_stage: None,
                shadow_stages: None,
                extra: ReplacementExtraSamplerContract::None,
            };
        }

        if kind == ReplacementShaderKind::LandLod {
            return Self {
                diffuse: RequiredSamplerSet::Single {
                    stage: 0,
                    reason: ReplacementSkipReason::NoDiffuse,
                },
                normal: RequiredSamplerSet::Single {
                    stage: 1,
                    reason: ReplacementSkipReason::NoNormalSource,
                },
                glow_stage: None,
                shadow_stages: None,
                extra: ReplacementExtraSamplerContract::LandLod,
            };
        }

        Self {
            diffuse: if kind.samples_object_diffuse() {
                RequiredSamplerSet::Single {
                    stage: 0,
                    reason: ReplacementSkipReason::NoDiffuse,
                }
            } else {
                RequiredSamplerSet::None
            },
            normal: match kind.normal_stage() {
                Some(stage) => RequiredSamplerSet::Single {
                    stage,
                    reason: ReplacementSkipReason::NoNormalSource,
                },
                None => RequiredSamplerSet::None,
            },
            glow_stage: kind.glow_stage(),
            shadow_stages: kind.shadow_stages(),
            extra: ReplacementExtraSamplerContract::None,
        }
    }

    fn validate(
        self,
        kind: ReplacementShaderKind,
    ) -> std::result::Result<(), ReplacementSkipReason> {
        self.diffuse.validate(kind)?;
        self.normal.validate(kind)?;

        if let Some(stage) = self.glow_stage {
            validate_sampler_stage(stage, ReplacementSkipReason::NoGlowSource)?;
        }

        if let Some((shadow_map_stage, shadow_mask_stage)) = self.shadow_stages {
            validate_sampler_stage(shadow_map_stage, ReplacementSkipReason::NoShadowSource)?;
            validate_sampler_stage(shadow_mask_stage, ReplacementSkipReason::NoShadowSource)?;
        }

        self.extra.validate(kind)
    }
}

#[derive(Clone, Copy)]
enum RequiredSamplerSet {
    None,
    Single {
        stage: u32,
        reason: ReplacementSkipReason,
    },
    Range {
        first_stage: u32,
        count: u8,
        reason: ReplacementSkipReason,
    },
}

impl RequiredSamplerSet {
    fn validate(
        self,
        kind: ReplacementShaderKind,
    ) -> std::result::Result<(), ReplacementSkipReason> {
        match self {
            Self::None => Ok(()),
            Self::Single { stage, reason } => match validate_sampler_stage(stage, reason) {
                Ok(()) => Ok(()),
                Err(ReplacementSkipReason::NoNormalSource)
                    if kind.allows_neutral_normal_fallback() =>
                {
                    Ok(())
                }
                Err(reason) => Err(reason),
            },
            Self::Range {
                first_stage,
                count,
                reason,
            } => {
                for offset in 0..count {
                    validate_sampler_stage(first_stage + offset as u32, reason)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ReplacementExtraSamplerContract {
    None,
    LandLod,
}

impl ReplacementExtraSamplerContract {
    fn validate(
        self,
        _kind: ReplacementShaderKind,
    ) -> std::result::Result<(), ReplacementSkipReason> {
        match self {
            Self::None => Ok(()),
            Self::LandLod => {
                validate_sampler_stage(4, ReplacementSkipReason::NoDiffuse)?;
                validate_sampler_stage(6, ReplacementSkipReason::NoNormalSource)?;
                validate_sampler_stage(7, ReplacementSkipReason::NoDiffuse)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ReplacementMaterialSource {
    VanillaBound,
    SelectorMaterialArrays,
}

impl ReplacementMaterialSource {
    fn for_kind(kind: ReplacementShaderKind) -> Self {
        if kind.uses_selector_material_resources() {
            Self::SelectorMaterialArrays
        } else {
            Self::VanillaBound
        }
    }
}

#[derive(Clone, Copy)]
enum ReplacementSamplerClearPolicy {
    PreserveVanilla,
    ClearExtraMaterialStages,
}

impl ReplacementSamplerClearPolicy {
    fn for_kind(kind: ReplacementShaderKind) -> Self {
        if kind.uses_extra_material_stages() {
            Self::ClearExtraMaterialStages
        } else {
            Self::PreserveVanilla
        }
    }
}

fn validate_sampler_stage(
    stage: u32,
    reason: ReplacementSkipReason,
) -> std::result::Result<(), ReplacementSkipReason> {
    if stage as usize >= MAX_TEXTURE_STAGES {
        return Err(reason);
    }
    if TEXTURE_CAPTURE.stages[stage as usize].load(Ordering::Acquire) == 0 {
        return Err(reason);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ReplacementSkipReason {
    NoDiffuse,
    NoDrawContext,
    UnsupportedFamily,
    UnsupportedVertexAbi,
    MissingObjectRowContract,
    SkinVertexAbi,
    MissingTerrainContract,
    InteriorTerrainDisabled,
    UnprovenLandLodProjectedShadow,
    NoSelectorRecord,
    NoNormalSource,
    NoGlowSource,
    NoShadowSource,
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
            Self::MissingObjectRowContract => "missing_object_row_contract",
            Self::SkinVertexAbi => "skin_vertex_abi",
            Self::MissingTerrainContract => "missing_terrain_contract",
            Self::InteriorTerrainDisabled => "interior_terrain_disabled",
            Self::UnprovenLandLodProjectedShadow => "unproven_landlod_projected_shadow",
            Self::NoSelectorRecord => "no_selector_record",
            Self::NoNormalSource => "no_normal_source",
            Self::NoGlowSource => "no_glow_source",
            Self::NoShadowSource => "no_shadow_source",
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
        set_block_reason(Some("target prologue is not vanilla"));
        log::warn!("[PBR] Native PBR hooks skipped because a target prologue is not vanilla");
        return Ok(());
    }

    if INSTALLED.swap(true, Ordering::AcqRel) {
        HOOKS_ACTIVE.store(true, Ordering::Release);
        set_block_reason(None);
        log::info!("[PBR] Native PBR hooks already installed");
        return Ok(());
    }

    if !install_selector_setup_hooks() {
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        set_block_reason(Some("selector setup hook install failed"));
        return Ok(());
    }

    if !install_set_texture_hook() {
        disable_all_hooks();
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        set_block_reason(Some("SetTexture hook install failed"));
        return Ok(());
    }

    if !install_set_shaders_hook() {
        disable_all_hooks();
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        set_block_reason(Some("SetShaders hook install failed"));
        return Ok(());
    }

    if !install_pass_shader_apply_hook() {
        disable_all_hooks();
        INSTALLED.store(false, Ordering::Release);
        HOOKS_ACTIVE.store(false, Ordering::Release);
        set_block_reason(Some("pass shader-interface hook install failed"));
        return Ok(());
    }

    HOOKS_ACTIVE.store(true, Ordering::Release);
    set_block_reason(None);
    log::info!("[PBR] Native PBR selector, draw, texture, and shader-interface hooks installed");

    if settings.enabled {
        log::info!("[PBR] Native PBR material shader enabled for object material variants");
        if TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire) {
            log::info!("[PBR] VPT terrain contract available; terrain PBR may run");
        } else {
            log::info!(
                "[PBR] VPT terrain contract missing; LandLOD and close terrain PBR stay disabled"
            );
        }
        start_replacement_shader_compiler();
        log::info!("[PBR] Native PBR shader prewarm scheduled with async bytecode compile");
        reset_replacement_prewarm();
    }

    Ok(())
}

pub(crate) fn configure_terrain_contract(available: bool) {
    let was_available = TERRAIN_CONTRACT_AVAILABLE.swap(available, Ordering::AcqRel);
    if available != was_available {
        reset_replacement_skip_budget();
    }
}

pub(crate) fn configure_runtime_options(settings: NativePbrSettings) {
    let installed = INSTALLED.load(Ordering::Acquire);
    HOOKS_ACTIVE.store(installed, Ordering::Release);
    store_object_pbr_profiles(settings.object);
    store_terrain_pbr_profiles(settings.terrain);
    PBR_TERRAIN_LOD_NOISE_SCALE_BITS.store(
        sanitize_pbr_scale(settings.terrain_lod_noise_scale, 1.0, 0.0, 4.0).to_bits(),
        Ordering::Release,
    );
    PBR_TERRAIN_LOD_NOISE_TILE_BITS.store(
        sanitize_pbr_scale(settings.terrain_lod_noise_tile, 1.75, 0.05, 16.0).to_bits(),
        Ordering::Release,
    );
    refresh_material_state_frame();

    let debug_was_enabled = DEBUG_LOG_DRAWS.swap(settings.debug_log_draws, Ordering::AcqRel);
    let material_was_enabled = MATERIAL_SHADER_ENABLED.swap(settings.enabled, Ordering::AcqRel);

    if settings.debug_log_draws && !debug_was_enabled {
        reset_debug_capture_budget();
    }
    if settings.enabled && !material_was_enabled {
        reset_replacement_skip_budget();
        reset_replacement_prewarm();
        if installed {
            start_replacement_shader_compiler();
        }
    }
}

fn store_object_pbr_profiles(profiles: NativePbrObjectProfiles) {
    store_object_pbr_profile(PBR_PROFILE_DEFAULT, profiles.default);
    store_object_pbr_profile(PBR_PROFILE_RAIN, profiles.rain);
    store_object_pbr_profile(PBR_PROFILE_NIGHT, profiles.night);
    store_object_pbr_profile(PBR_PROFILE_NIGHT_RAIN, profiles.night_rain);
    store_object_pbr_profile(PBR_PROFILE_INTERIOR, profiles.interior);
}

fn store_object_pbr_profile(index: usize, profile: PbrProfileSettings) {
    store_pbr_profile(&PBR_OBJECT_PROFILE_BITS, index, profile);
}

fn store_terrain_pbr_profiles(profiles: NativePbrTerrainProfiles) {
    store_terrain_pbr_profile(PBR_PROFILE_DEFAULT, profiles.default);
    store_terrain_pbr_profile(PBR_PROFILE_RAIN, profiles.rain);
    store_terrain_pbr_profile(PBR_PROFILE_NIGHT, profiles.night);
    store_terrain_pbr_profile(PBR_PROFILE_NIGHT_RAIN, profiles.night_rain);
    store_terrain_pbr_profile(PBR_PROFILE_INTERIOR, PbrProfileSettings::neutral_terrain());
}

fn store_terrain_pbr_profile(index: usize, profile: PbrProfileSettings) {
    store_pbr_profile(&PBR_TERRAIN_PROFILE_BITS, index, profile);
}

fn store_pbr_profile(
    storage: &[[AtomicU32; PBR_PROFILE_VALUE_COUNT]; PBR_PROFILE_COUNT],
    index: usize,
    profile: PbrProfileSettings,
) {
    let values = profile.sanitized_values();
    for (slot, value) in storage[index].iter().zip(values) {
        slot.store(value.to_bits(), Ordering::Release);
    }
}

pub(crate) fn runtime_status() -> NativePbrRuntimeStatus {
    NativePbrRuntimeStatus {
        installed: INSTALLED.load(Ordering::Acquire),
        shader_enabled: MATERIAL_SHADER_ENABLED.load(Ordering::Acquire),
        terrain_contract_available: TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire),
        block_reason: *INSTALL_BLOCK_REASON.lock(),
    }
}

fn set_block_reason(reason: Option<&'static str>) {
    *INSTALL_BLOCK_REASON.lock() = reason;
}

pub(crate) fn service_present_frame() {
    refresh_material_state_frame();

    if !HOOKS_ACTIVE.load(Ordering::Acquire) || !MATERIAL_SHADER_ENABLED.load(Ordering::Acquire) {
        return;
    }

    maybe_prewarm_replacement_shader();
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
    let replacement_record = ReplacementRecord::for_kind(shader_kind);

    if let Err(reason) = replacement_record.validate_textures() {
        record_replacement_skip(reason, Some(draw_context));
        return false;
    }

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

    let material_bindings = match unsafe { replacement_record.material_bindings() } {
        Ok(material_bindings) => material_bindings,
        Err(reason) => {
            record_replacement_skip(reason, Some(draw_context));
            return false;
        }
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
    replacement_record.apply_sampler_policy();
    replacement_record.apply_constants(material_bindings);

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
    let render_pass_enum = unsafe { read_u16_offset(pass, RENDER_PASS_ENUM_OFFSET) };
    let render_pass_num_lights = unsafe { read_u8_offset(pass, RENDER_PASS_NUM_LIGHTS_OFFSET) };
    let render_pass_current_land_texture =
        unsafe { read_u8_offset(pass, RENDER_PASS_CURRENT_LAND_TEXTURE_OFFSET) };

    Some(ReplacementDrawContext {
        pass,
        vertex_shader,
        pixel_shader,
        render_pass_enum,
        render_pass_num_lights,
        render_pass_current_land_texture,
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

    if pplighting_pair_uses_sls2_landlod(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        if !TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire) {
            return Err(ReplacementSkipReason::MissingTerrainContract);
        }
        if !current_material_state_is_known_exterior() {
            return Err(ReplacementSkipReason::InteriorTerrainDisabled);
        }
        return Ok(ReplacementShaderKind::LandLod);
    }
    if pplighting_pair_uses_sls2_landlod_projected_shadow(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        return Err(ReplacementSkipReason::UnprovenLandLodProjectedShadow);
    }

    if let Some(shader_kind) = pplighting_pair_uses_vpt_close_terrain(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        if !TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire) {
            return Err(ReplacementSkipReason::MissingTerrainContract);
        }
        if !current_material_state_is_known_exterior() {
            return Err(ReplacementSkipReason::InteriorTerrainDisabled);
        }
        return exact_close_terrain_replacement_kind(shader_kind);
    }

    if is_sls2_skin_vertex_index(draw_context.vertex_membership.index) {
        return Err(ReplacementSkipReason::SkinVertexAbi);
    }

    if let Some(shader_kind) = pplighting_sls2_object_replacement_kind(
        draw_context.vertex_membership,
        draw_context.pixel_membership,
    ) {
        return Ok(shader_kind);
    }

    if draw_context.family == PPLIGHTING_FAMILY_VERTEX_C_PIXEL_B
        && draw_context.vertex_membership.group == PPLIGHTING_VERTEX_GROUP_C
        && draw_context.pixel_membership.group == PPLIGHTING_PIXEL_GROUP_B
        && is_sls2_object_candidate_pixel_index(draw_context.pixel_membership.index)
    {
        return Err(ReplacementSkipReason::MissingObjectRowContract);
    }

    Err(ReplacementSkipReason::UnsupportedVertexAbi)
}

fn exact_close_terrain_replacement_kind(
    shader_kind: ReplacementShaderKind,
) -> std::result::Result<ReplacementShaderKind, ReplacementSkipReason> {
    let Some((_tex_count, point_light_count)) = shader_kind.close_terrain_variant() else {
        return Ok(shader_kind);
    };

    if close_terrain_tier_created(point_light_count) {
        return Ok(shader_kind);
    }

    Err(ReplacementSkipReason::NoReplacementShader)
}

fn close_terrain_tier_created(point_light_count: u8) -> bool {
    (1..=7).all(|tex_count| {
        replacement_shader_created(ReplacementShaderKind::CloseTerrain {
            tex_count,
            point_light_count,
        })
    })
}

fn pplighting_sls2_object_replacement_kind(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> Option<ReplacementShaderKind> {
    if vertex.group != PPLIGHTING_VERTEX_GROUP_C || pixel.group != PPLIGHTING_PIXEL_GROUP_B {
        return None;
    }

    object_replacement_contract(vertex.index, pixel.index).map(|contract| contract.kind)
}

fn pplighting_pair_uses_sls2_landlod(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> bool {
    if vertex.group != PPLIGHTING_VERTEX_GROUP_C || pixel.group != PPLIGHTING_PIXEL_GROUP_B {
        return false;
    }

    vertex.index == PPLIGHTING_VERTEX_SLS2_LANDLOD_INDEX
        && pixel.index == PPLIGHTING_PIXEL_SLS2_LANDLOD_INDEX
}

fn pplighting_pair_uses_sls2_landlod_projected_shadow(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> bool {
    if vertex.group != PPLIGHTING_VERTEX_GROUP_C || pixel.group != PPLIGHTING_PIXEL_GROUP_B {
        return false;
    }

    vertex.index == PPLIGHTING_VERTEX_SLS2_LANDLOD_PROJECTED_SHADOW_INDEX
        && pixel.index == PPLIGHTING_PIXEL_SLS2_LANDLOD_PROJECTED_SHADOW_INDEX
}

fn pplighting_pair_uses_vpt_close_terrain(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> Option<ReplacementShaderKind> {
    if vertex.group != PPLIGHTING_VERTEX_GROUP_C || pixel.group != PPLIGHTING_PIXEL_GROUP_B {
        return None;
    }
    if !matches!(
        vertex.index,
        PPLIGHTING_VERTEX_SLS2_VPT_CLOSE_TERRAIN_A_INDEX
            | PPLIGHTING_VERTEX_SLS2_VPT_CLOSE_TERRAIN_B_INDEX
    ) {
        return None;
    }

    vpt_close_terrain_kind_from_pixel_index(pixel.index)
}

fn is_sls2_skin_vertex_index(index: u32) -> bool {
    matches!(
        index,
        PPLIGHTING_VERTEX_SLS2_ADTS_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS_PROJECTED_SHADOW_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS9_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS10_LIGHTS4_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ADTS10_SPECULAR_LIGHTS4_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS2_PROJECTED_SHADOW_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_LIGHT_LIGHTS3_PROJECTED_SHADOW_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS2_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_DIFFUSE_LIGHTS3_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_PROJECTED_SHADOW_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS2_SKIN_INDEX
            | PPLIGHTING_VERTEX_SLS2_ONLY_SPECULAR_POINT_LIGHTS3_SKIN_INDEX
    )
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

fn reset_replacement_prewarm() {
    REPLACEMENT_PREWARM_INDEX.store(0, Ordering::Release);
    REPLACEMENT_PREWARM_TICK.store(0, Ordering::Release);
    REPLACEMENT_PREWARM_DONE.store(false, Ordering::Release);
}

fn maybe_prewarm_replacement_shader() {
    if REPLACEMENT_PREWARM_DONE.load(Ordering::Acquire) {
        return;
    }

    let tick = REPLACEMENT_PREWARM_TICK.fetch_add(1, Ordering::Relaxed);
    if tick % REPLACEMENT_SHADER_PREWARM_INTERVAL != 0 {
        return;
    }

    if crate::backend::d3d_device_ptr().is_none() {
        return;
    }

    if all_replacement_prewarms_complete() {
        REPLACEMENT_PREWARM_DONE.store(true, Ordering::Release);
        log::info!("[PBR] Native PBR shader prewarm finished");
        return;
    }

    let mut index = REPLACEMENT_PREWARM_INDEX.load(Ordering::Acquire) % PREWARM_SHADER_KINDS.len();
    let mut visited = 0usize;
    let mut created = 0usize;

    while visited < PREWARM_SHADER_KINDS.len() && created < REPLACEMENT_SHADER_CREATE_BUDGET {
        let shader_kind = PREWARM_SHADER_KINDS[index];
        index = (index + 1) % PREWARM_SHADER_KINDS.len();
        REPLACEMENT_PREWARM_INDEX.store(index, Ordering::Release);
        visited += 1;

        if shader_kind.uses_terrain_constants()
            && !TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire)
        {
            continue;
        }
        if !shader_kind.runtime_enabled() {
            continue;
        }
        if replacement_shader_created(shader_kind) {
            continue;
        }
        if replacement_shader_preload_failed(shader_kind) {
            log_limited(
                &REPLACEMENT_RESOURCE_LOGS,
                &format!(
                    "[PBR] Native PBR prewarm skipped {} after async compile/create failure",
                    shader_kind.label()
                ),
            );
            continue;
        }
        if replacement_shader_bytecode_pending(shader_kind, ReplacementShaderTarget::Pixel) {
            continue;
        }
        if shader_kind.replaces_vertex_shader()
            && replacement_shader_bytecode_pending(shader_kind, ReplacementShaderTarget::Vertex)
        {
            continue;
        }

        let warmed = replacement_pixel_shader_handle(shader_kind).is_some()
            && (!shader_kind.replaces_vertex_shader()
                || replacement_vertex_shader_handle(shader_kind).is_some());
        if warmed {
            created += 1;
        }
    }
}

fn replacement_shader_created(kind: ReplacementShaderKind) -> bool {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return false;
    };
    let device_key = device_ptr as usize;
    let pixel_created = kind.cached_device().load(Ordering::Acquire) == device_key
        && kind.cached_handle().load(Ordering::Acquire) != 0;
    if !pixel_created {
        return false;
    }

    if !kind.replaces_vertex_shader() {
        return true;
    }

    let Some(vertex_device) = kind.cached_vertex_device() else {
        return false;
    };
    let Some(vertex_handle) = kind.cached_vertex_handle() else {
        return false;
    };
    vertex_device.load(Ordering::Acquire) == device_key
        && vertex_handle.load(Ordering::Acquire) != 0
}

fn replacement_shader_preload_failed(kind: ReplacementShaderKind) -> bool {
    if replacement_shader_bytecode_failed(kind, ReplacementShaderTarget::Pixel) {
        return true;
    }
    kind.replaces_vertex_shader()
        && replacement_shader_bytecode_failed(kind, ReplacementShaderTarget::Vertex)
}

fn all_replacement_prewarms_complete() -> bool {
    PREWARM_SHADER_KINDS.iter().all(|kind| {
        if !kind.runtime_enabled() {
            return true;
        }
        if kind.uses_terrain_constants() && !TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire) {
            return true;
        }
        replacement_shader_created(*kind) || replacement_shader_preload_failed(*kind)
    })
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
    REPLACEMENT_APPLY_SUMMARY_LOGS.store(0, Ordering::Release);
    for count in REPLACEMENT_APPLY_KIND_COUNTS.iter() {
        count.store(0, Ordering::Release);
    }
    REPLACEMENT_SKIP_SUMMARY_LOGS.store(0, Ordering::Release);
    REPLACEMENT_SKIP_CHECKS.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_DIFFUSE.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_DRAW_CONTEXT.store(0, Ordering::Release);
    REPLACEMENT_SKIP_UNSUPPORTED_FAMILY.store(0, Ordering::Release);
    REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI.store(0, Ordering::Release);
    REPLACEMENT_SKIP_SKIN_VERTEX_ABI.store(0, Ordering::Release);
    REPLACEMENT_SKIP_MISSING_TERRAIN_CONTRACT.store(0, Ordering::Release);
    REPLACEMENT_SKIP_INTERIOR_TERRAIN_DISABLED.store(0, Ordering::Release);
    REPLACEMENT_SKIP_INTERIOR_OBJECT_LIGHT_PASS_DISABLED.store(0, Ordering::Release);
    REPLACEMENT_SKIP_UNPROVEN_LANDLOD_SHADOW.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_SELECTOR_RECORD.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_NORMAL_SOURCE.store(0, Ordering::Release);
    REPLACEMENT_SKIP_NO_GLOW_SOURCE.store(0, Ordering::Release);
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

unsafe fn bind_vanilla_or_neutral_material_textures(
    shader_kind: ReplacementShaderKind,
) -> std::result::Result<ReplacementMaterialBindings, ReplacementSkipReason> {
    let normal_stage = shader_kind.normal_stage().unwrap_or(PBR_NORMAL_STAGE);
    let mut has_normal = TEXTURE_CAPTURE.stages[normal_stage as usize].load(Ordering::Acquire) != 0;

    if !has_normal && shader_kind.allows_neutral_normal_fallback() {
        has_normal = unsafe { bind_neutral_normal_texture(normal_stage) };
    }

    if !has_normal && shader_kind.normal_stage().is_some() {
        return Err(ReplacementSkipReason::NoNormalSource);
    }

    Ok(ReplacementMaterialBindings {
        selector: 0,
        generation: 0,
        has_normal,
        has_glow: shader_kind.glow_stage().is_some_and(|stage| {
            TEXTURE_CAPTURE.stages[stage as usize].load(Ordering::Acquire) != 0
        }),
        has_height: false,
        has_environment: false,
        has_environment_mask: false,
    })
}

unsafe fn bind_neutral_normal_texture(stage: u32) -> bool {
    if stage as usize >= MAX_TEXTURE_STAGES {
        return false;
    }

    let render_state = TEXTURE_CAPTURE.render_state.load(Ordering::Acquire) as *mut c_void;
    if render_state.is_null() {
        return false;
    }

    let Ok(set_texture) = SET_TEXTURE_HOOK.original() else {
        log_limited(
            &MATERIAL_BIND_LOGS,
            "[PBR] Native PBR neutral normal binding skipped because original SetTexture is unavailable",
        );
        return false;
    };

    let Some(texture) = neutral_normal_texture_handle() else {
        return false;
    };

    unsafe {
        set_texture(render_state, stage, texture);
    }
    TEXTURE_CAPTURE.stages[stage as usize].store(texture as usize, Ordering::Release);
    true
}

fn neutral_normal_texture_handle() -> Option<*mut c_void> {
    let device_ptr = crate::backend::d3d_device_ptr()?;
    let device_key = device_ptr as usize;
    let device = unsafe { Device9Ref::from_raw_void(device_ptr) }?;
    PBR_REPLACEMENT
        .lock()
        .neutral_normal_handle(&device, device_key)
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

fn upload_replacement_record_constants(
    constants: ReplacementConstantContract,
    shader_kind: ReplacementShaderKind,
    bindings: ReplacementMaterialBindings,
) {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };

    if matches!(constants, ReplacementConstantContract::TerrainPbr) {
        let profile = current_terrain_pbr_profile();
        let terrain_data = [[
            profile.metallicness,
            profile.roughness_scale,
            profile.light_scale,
            profile.ambient_scale,
        ]];
        let terrain_extra_data = [[
            1.0,
            profile.albedo_saturation,
            atomic_pbr_f32(&PBR_TERRAIN_LOD_NOISE_SCALE_BITS),
            atomic_pbr_f32(&PBR_TERRAIN_LOD_NOISE_TILE_BITS),
        ]];
        let terrain_parallax_data = [[0.0, 0.0, 0.0, 0.0]];
        let terrain_parallax_extra_data = [[2048.0, 0.0, 0.0, 0.0]];
        let _ = device.set_pixel_shader_constant_f(TERRAIN_DATA_REGISTER, &terrain_data);
        let _ =
            device.set_pixel_shader_constant_f(TERRAIN_EXTRA_DATA_REGISTER, &terrain_extra_data);
        let _ = device
            .set_pixel_shader_constant_f(TERRAIN_PARALLAX_DATA_REGISTER, &terrain_parallax_data);
        let _ = device.set_pixel_shader_constant_f(
            TERRAIN_PARALLAX_EXTRA_DATA_REGISTER,
            &terrain_parallax_extra_data,
        );
        return;
    }

    if shader_kind.writes_material_flags() {
        let flags = [[
            bindings.has_glow as u8 as f32,
            bindings.has_height as u8 as f32,
            bindings.has_environment as u8 as f32,
            bindings.has_environment_mask as u8 as f32,
        ]];
        let _ = device.set_pixel_shader_constant_f(PBR_MATERIAL_FLAGS_REGISTER, &flags);
    }

    let profile = current_object_pbr_profile();
    let pbr_data = [[
        profile.metallicness,
        profile.roughness_scale,
        profile.light_scale,
        profile.ambient_scale,
    ]];
    let pbr_extra_data = [[profile.albedo_saturation, 0.0, 0.0, 0.0]];
    let _ = device.set_pixel_shader_constant_f(PBR_DATA_REGISTER, &pbr_data);
    let _ = device.set_pixel_shader_constant_f(PBR_EXTRA_DATA_REGISTER, &pbr_extra_data);
}

fn current_object_pbr_profile() -> PbrProfileSettings {
    let state = cached_material_state_frame();
    if state.exterior_known && !state.is_exterior {
        return load_object_pbr_profile(PBR_PROFILE_INTERIOR);
    }

    let transition = state.transition_curve.clamp(0.0, 1.0);
    let dry = lerp_pbr_profile(
        load_object_pbr_profile(PBR_PROFILE_NIGHT),
        load_object_pbr_profile(PBR_PROFILE_DEFAULT),
        transition,
    );
    let wet = lerp_pbr_profile(
        load_object_pbr_profile(PBR_PROFILE_NIGHT_RAIN),
        load_object_pbr_profile(PBR_PROFILE_RAIN),
        transition,
    );

    // Rain/wet profiles are part of the NVR object PBR contract, but OMV does
    // not yet own a proven WetWorld-equivalent runtime signal.
    let rain_factor = 0.0;
    lerp_pbr_profile(dry, wet, rain_factor)
}

fn current_terrain_pbr_profile() -> PbrProfileSettings {
    let state = cached_material_state_frame();
    if state.exterior_known && !state.is_exterior {
        return load_terrain_pbr_profile(PBR_PROFILE_INTERIOR);
    }

    let transition = state.transition_curve.clamp(0.0, 1.0);
    let dry = lerp_pbr_profile(
        load_terrain_pbr_profile(PBR_PROFILE_NIGHT),
        load_terrain_pbr_profile(PBR_PROFILE_DEFAULT),
        transition,
    );
    let wet = lerp_pbr_profile(
        load_terrain_pbr_profile(PBR_PROFILE_NIGHT_RAIN),
        load_terrain_pbr_profile(PBR_PROFILE_RAIN),
        transition,
    );

    // NVR terrain blends rain through WetWorld. OMV does not yet own that
    // signal, so rain terrain profiles remain parsed but inactive.
    let rain_factor = 0.0;
    lerp_pbr_profile(dry, wet, rain_factor)
}

fn current_material_state_is_known_exterior() -> bool {
    let state = cached_material_state_frame();
    state.exterior_known && state.is_exterior
}

fn cached_material_state_frame() -> crate::backend::MaterialStateFrame {
    crate::backend::MaterialStateFrame {
        transition_curve: f32::from_bits(PBR_STATE_TRANSITION_CURVE_BITS.load(Ordering::Acquire)),
        exterior_known: PBR_STATE_EXTERIOR_KNOWN.load(Ordering::Acquire),
        is_exterior: PBR_STATE_IS_EXTERIOR.load(Ordering::Acquire),
    }
}

fn refresh_material_state_frame() -> crate::backend::MaterialStateFrame {
    let state = crate::backend::material_state_frame();
    PBR_STATE_TRANSITION_CURVE_BITS.store(state.transition_curve.to_bits(), Ordering::Release);
    PBR_STATE_EXTERIOR_KNOWN.store(state.exterior_known, Ordering::Release);
    PBR_STATE_IS_EXTERIOR.store(state.is_exterior, Ordering::Release);
    state
}

fn load_object_pbr_profile(index: usize) -> PbrProfileSettings {
    load_pbr_profile(&PBR_OBJECT_PROFILE_BITS, index)
}

fn load_terrain_pbr_profile(index: usize) -> PbrProfileSettings {
    load_pbr_profile(&PBR_TERRAIN_PROFILE_BITS, index)
}

fn load_pbr_profile(
    storage: &[[AtomicU32; PBR_PROFILE_VALUE_COUNT]; PBR_PROFILE_COUNT],
    index: usize,
) -> PbrProfileSettings {
    let profile = &storage[index];
    PbrProfileSettings {
        metallicness: f32::from_bits(profile[PBR_PROFILE_METALLICNESS].load(Ordering::Acquire)),
        roughness_scale: f32::from_bits(
            profile[PBR_PROFILE_ROUGHNESS_SCALE].load(Ordering::Acquire),
        ),
        light_scale: f32::from_bits(profile[PBR_PROFILE_LIGHT_SCALE].load(Ordering::Acquire)),
        ambient_scale: f32::from_bits(profile[PBR_PROFILE_AMBIENT_SCALE].load(Ordering::Acquire)),
        albedo_saturation: f32::from_bits(
            profile[PBR_PROFILE_ALBEDO_SATURATION].load(Ordering::Acquire),
        ),
    }
}

fn lerp_pbr_profile(a: PbrProfileSettings, b: PbrProfileSettings, t: f32) -> PbrProfileSettings {
    PbrProfileSettings {
        metallicness: lerp_f32(a.metallicness, b.metallicness, t),
        roughness_scale: lerp_f32(a.roughness_scale, b.roughness_scale, t),
        light_scale: lerp_f32(a.light_scale, b.light_scale, t),
        ambient_scale: lerp_f32(a.ambient_scale, b.ambient_scale, t),
        albedo_saturation: lerp_f32(a.albedo_saturation, b.albedo_saturation, t),
    }
}

fn lerp_f32(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
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
    let render_pass_enum = unsafe { read_u16_offset(pass, RENDER_PASS_ENUM_OFFSET) };
    let render_pass_num_lights = unsafe { read_u8_offset(pass, RENDER_PASS_NUM_LIGHTS_OFFSET) };
    let render_pass_current_land_texture =
        unsafe { read_u8_offset(pass, RENDER_PASS_CURRENT_LAND_TEXTURE_OFFSET) };
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
            render_pass_enum,
            render_pass_num_lights,
            render_pass_current_land_texture,
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

unsafe fn read_u16_offset(base: *mut c_void, offset: usize) -> u16 {
    let slot = unsafe { offset_ptr(base, offset) };
    if slot.is_null() {
        return 0;
    }

    if !silent_readable_range(slot, size_of::<u16>()) {
        return 0;
    }

    unsafe { (slot as *const u16).read() }
}

unsafe fn read_u8_offset(base: *mut c_void, offset: usize) -> u8 {
    let slot = unsafe { offset_ptr(base, offset) };
    if slot.is_null() {
        return 0;
    }

    if !silent_readable_range(slot, size_of::<u8>()) {
        return 0;
    }

    unsafe { (slot as *const u8).read() }
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
    render_pass_enum: u16,
    render_pass_num_lights: u8,
    render_pass_current_land_texture: u8,
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
        "[PBR] Draw pass={} pass={:p} pass_enum={} pass_lights={} pass_land_tex={} vs={:p} ps={:p} vs_handle={:p} ps_handle={:p} family={} vgrp={} vidx={} pgrp={} pidx={} render_state=0x{:08X} selector={:p} selector_gen={} s0=0x{:08X} s1=0x{:08X} s2=0x{:08X} s3=0x{:08X}",
        pass_index,
        pass,
        render_pass_enum,
        render_pass_num_lights,
        render_pass_current_land_texture,
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
    let applied = REPLACEMENT_APPLIED_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    REPLACEMENT_APPLY_KIND_COUNTS[shader_kind.index()].fetch_add(1, Ordering::Relaxed);
    maybe_log_replacement_apply_summary(applied);
    if !DEBUG_LOG_DRAWS.load(Ordering::Acquire) {
        return;
    }

    let count = REPLACEMENT_APPLY_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= 8 {
        return;
    }

    let (terrain_tex_count, terrain_point_light_count) =
        shader_kind.close_terrain_variant().unwrap_or((0, 0));
    let stages = &TEXTURE_CAPTURE.stages;
    log::info!(
        "[PBR] Native PBR replacement kind={} pass_index={} pass={:p} pass_enum={} pass_lights={} pass_land_tex={} terrain_tex={} terrain_points={} vs={:p} ps={:p} family={} vgrp={} vidx={} pgrp={} pidx={} vanilla_vs={:p} replacement_vs={:p} vanilla_ps={:p} replacement_ps={:p} selector=0x{:08X} sel_gen={} maps=n{} g{} h{} e{} m{} s0=0x{:08X} s1=0x{:08X} s2=0x{:08X} s3=0x{:08X} s4=0x{:08X} s5=0x{:08X} s6=0x{:08X} s7=0x{:08X} s8=0x{:08X} s9=0x{:08X} s10=0x{:08X} s11=0x{:08X} s12=0x{:08X} s13=0x{:08X}",
        shader_kind.label(),
        pass_index,
        draw_context.pass,
        draw_context.render_pass_enum,
        draw_context.render_pass_num_lights,
        draw_context.render_pass_current_land_texture,
        terrain_tex_count,
        terrain_point_light_count,
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
        stages[0].load(Ordering::Acquire),
        stages[1].load(Ordering::Acquire),
        stages[2].load(Ordering::Acquire),
        stages[3].load(Ordering::Acquire),
        stages[4].load(Ordering::Acquire),
        stages[5].load(Ordering::Acquire),
        stages[6].load(Ordering::Acquire),
        stages[7].load(Ordering::Acquire),
        stages[8].load(Ordering::Acquire),
        stages[9].load(Ordering::Acquire),
        stages[10].load(Ordering::Acquire),
        stages[11].load(Ordering::Acquire),
        stages[12].load(Ordering::Acquire),
        stages[13].load(Ordering::Acquire),
    );
}

fn maybe_log_replacement_apply_summary(applied: u32) {
    if applied < 64 || !applied.is_power_of_two() {
        return;
    }

    let count = REPLACEMENT_APPLY_SUMMARY_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= 8 {
        return;
    }

    log::info!(
        "[PBR] Native PBR apply summary: applied={} object_low_opt={} object_low={} object_low_shadow={} object_low_lights2={} object_low_lights2_shadow={} object_low_specular={} object_low_specular_shadow={} object_low_specular_lights2={} object_low_specular_lights2_shadow={} object_low_stbb={} object_high6={} object_high4={} object_high4_opt={} object_high3_specular={} object_high3_specular_opt={} object_si={} landlod={} close_terrain={} close_terrain_lights0={} close_terrain_lights6={} close_terrain_lights12={} close_terrain_lights24={} close_terrain_tex1={} close_terrain_tex2={} close_terrain_tex3={} close_terrain_tex4={} close_terrain_tex5={} close_terrain_tex6={} close_terrain_tex7={} skips={} no_diffuse={} no_context={} unsupported_family={} unsupported_vertex_abi={} missing_object_row_contract={} skin_vertex_abi={} missing_terrain_contract={} interior_terrain_disabled={} interior_object_light_pass_disabled={} unproven_landlod_shadow={} no_selector={} no_normal={} no_glow={} no_shadow={} no_shader={} bind_failed={} no_vanilla_handle={} handle_write_failed={}",
        applied,
        apply_kind_count(ReplacementShaderKind::ObjectLowOpt),
        apply_kind_count(ReplacementShaderKind::ObjectLow),
        apply_kind_count(ReplacementShaderKind::ObjectLowShadow),
        apply_kind_count(ReplacementShaderKind::ObjectLowLights2),
        apply_kind_count(ReplacementShaderKind::ObjectLowLights2Shadow),
        apply_kind_count(ReplacementShaderKind::ObjectLowSpecular),
        apply_kind_count(ReplacementShaderKind::ObjectLowSpecularShadow),
        apply_kind_count(ReplacementShaderKind::ObjectLowSpecularLights2),
        apply_kind_count(ReplacementShaderKind::ObjectLowSpecularLights2Shadow),
        apply_kind_count(ReplacementShaderKind::ObjectLowStbb),
        apply_kind_count(ReplacementShaderKind::ObjectHigh6),
        apply_kind_count(ReplacementShaderKind::ObjectHigh4),
        apply_kind_count(ReplacementShaderKind::ObjectHigh4Opt),
        apply_kind_count(ReplacementShaderKind::ObjectHigh3Specular),
        apply_kind_count(ReplacementShaderKind::ObjectHigh3SpecularOpt),
        object_si_apply_count(),
        apply_kind_count(ReplacementShaderKind::LandLod),
        close_terrain_apply_count(),
        close_terrain_apply_count_for_lights(0),
        close_terrain_apply_count_for_lights(6),
        close_terrain_apply_count_for_lights(12),
        close_terrain_apply_count_for_lights(24),
        close_terrain_apply_count_for_tex(1),
        close_terrain_apply_count_for_tex(2),
        close_terrain_apply_count_for_tex(3),
        close_terrain_apply_count_for_tex(4),
        close_terrain_apply_count_for_tex(5),
        close_terrain_apply_count_for_tex(6),
        close_terrain_apply_count_for_tex(7),
        REPLACEMENT_SKIP_CHECKS.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_DIFFUSE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_DRAW_CONTEXT.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNSUPPORTED_FAMILY.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI.load(Ordering::Acquire),
        REPLACEMENT_SKIP_MISSING_OBJECT_ROW_CONTRACT.load(Ordering::Acquire),
        REPLACEMENT_SKIP_SKIN_VERTEX_ABI.load(Ordering::Acquire),
        REPLACEMENT_SKIP_MISSING_TERRAIN_CONTRACT.load(Ordering::Acquire),
        REPLACEMENT_SKIP_INTERIOR_TERRAIN_DISABLED.load(Ordering::Acquire),
        REPLACEMENT_SKIP_INTERIOR_OBJECT_LIGHT_PASS_DISABLED.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNPROVEN_LANDLOD_SHADOW.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_SELECTOR_RECORD.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_NORMAL_SOURCE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_GLOW_SOURCE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_SHADOW_SOURCE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_REPLACEMENT_SHADER.load(Ordering::Acquire),
        REPLACEMENT_SKIP_BIND_FAILED.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_VANILLA_HANDLE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_HANDLE_WRITE_FAILED.load(Ordering::Acquire),
    );
}

fn apply_kind_count(kind: ReplacementShaderKind) -> u32 {
    REPLACEMENT_APPLY_KIND_COUNTS[kind.index()].load(Ordering::Acquire)
}

fn object_si_apply_count() -> u32 {
    [
        ReplacementShaderKind::ObjectLowSi,
        ReplacementShaderKind::ObjectLowSiShadow,
        ReplacementShaderKind::ObjectLowLights2Si,
        ReplacementShaderKind::ObjectLowLights2SiShadow,
        ReplacementShaderKind::ObjectLowSpecularSi,
        ReplacementShaderKind::ObjectLowSpecularSiShadow,
        ReplacementShaderKind::ObjectLowSpecularLights2Si,
        ReplacementShaderKind::ObjectLowSpecularLights2SiShadow,
        ReplacementShaderKind::ObjectHigh6Si,
        ReplacementShaderKind::ObjectHigh4Si,
        ReplacementShaderKind::ObjectHigh3SpecularSi,
        ReplacementShaderKind::ObjectOnlyLightLights2Si,
        ReplacementShaderKind::ObjectOnlyLightLights2SiShadow,
        ReplacementShaderKind::ObjectOnlyLightLights3Si,
        ReplacementShaderKind::ObjectOnlyLightLights3SiShadow,
    ]
    .into_iter()
    .map(apply_kind_count)
    .sum()
}

fn close_terrain_apply_count() -> u32 {
    REPLACEMENT_SHADER_KINDS
        .into_iter()
        .filter(|kind| matches!(kind, ReplacementShaderKind::CloseTerrain { .. }))
        .map(apply_kind_count)
        .sum()
}

fn close_terrain_apply_count_for_lights(point_light_count: u8) -> u32 {
    REPLACEMENT_SHADER_KINDS
        .into_iter()
        .filter(|kind| {
            matches!(
                kind,
                ReplacementShaderKind::CloseTerrain {
                    point_light_count: count,
                    ..
                } if *count == point_light_count
            )
        })
        .map(apply_kind_count)
        .sum()
}

fn close_terrain_apply_count_for_tex(tex_count: u8) -> u32 {
    REPLACEMENT_SHADER_KINDS
        .into_iter()
        .filter(|kind| {
            matches!(
                kind,
                ReplacementShaderKind::CloseTerrain {
                    tex_count: count,
                    ..
                } if *count == tex_count
            )
        })
        .map(apply_kind_count)
        .sum()
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
        ReplacementSkipReason::MissingObjectRowContract => {
            REPLACEMENT_SKIP_MISSING_OBJECT_ROW_CONTRACT.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::SkinVertexAbi => {
            REPLACEMENT_SKIP_SKIN_VERTEX_ABI.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::MissingTerrainContract => {
            REPLACEMENT_SKIP_MISSING_TERRAIN_CONTRACT.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::InteriorTerrainDisabled => {
            REPLACEMENT_SKIP_INTERIOR_TERRAIN_DISABLED.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::UnprovenLandLodProjectedShadow => {
            REPLACEMENT_SKIP_UNPROVEN_LANDLOD_SHADOW.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoSelectorRecord => {
            REPLACEMENT_SKIP_NO_SELECTOR_RECORD.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoNormalSource => {
            REPLACEMENT_SKIP_NO_NORMAL_SOURCE.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoGlowSource => {
            REPLACEMENT_SKIP_NO_GLOW_SOURCE.fetch_add(1, Ordering::Relaxed);
        }
        ReplacementSkipReason::NoShadowSource => {
            REPLACEMENT_SKIP_NO_SHADOW_SOURCE.fetch_add(1, Ordering::Relaxed);
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
    let always_log_missing_object_contract =
        matches!(reason, ReplacementSkipReason::MissingObjectRowContract);
    if !DEBUG_LOG_DRAWS.load(Ordering::Acquire) && !always_log_missing_object_contract {
        return;
    }

    let sls2_pair = draw_context.family == PPLIGHTING_FAMILY_VERTEX_C_PIXEL_B
        && draw_context.vertex_membership.group == PPLIGHTING_VERTEX_GROUP_C
        && draw_context.pixel_membership.group == PPLIGHTING_PIXEL_GROUP_B;
    let terrain_candidate = sls2_pair
        && (is_sls2_terrain_vertex_index(draw_context.vertex_membership.index)
            || is_sls2_terrain_pixel_index(draw_context.pixel_membership.index));
    if !matches!(
        reason,
        ReplacementSkipReason::UnsupportedFamily
            | ReplacementSkipReason::UnsupportedVertexAbi
            | ReplacementSkipReason::MissingObjectRowContract
            | ReplacementSkipReason::SkinVertexAbi
            | ReplacementSkipReason::MissingTerrainContract
            | ReplacementSkipReason::InteriorTerrainDisabled
            | ReplacementSkipReason::UnprovenLandLodProjectedShadow
            | ReplacementSkipReason::NoDiffuse
            | ReplacementSkipReason::NoNormalSource
            | ReplacementSkipReason::NoGlowSource
            | ReplacementSkipReason::NoShadowSource
    ) {
        return;
    }

    maybe_log_terrain_candidate_pair(reason, draw_context);

    if !is_sls2_object_candidate_pixel_index(draw_context.pixel_membership.index)
        && !terrain_candidate
    {
        return;
    }

    let count = REPLACEMENT_UNSUPPORTED_PAIR_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_LOGS {
        return;
    }

    let stages = &TEXTURE_CAPTURE.stages;
    log::info!(
        "[PBR] Unsupported replacement pair: reason={} candidate={} family={} vgrp={} vidx={} pgrp={} pidx={} pass={:p} pass_enum={} pass_lights={} pass_land_tex={} vs={:p} ps={:p} s0=0x{:08X} s1=0x{:08X} s2=0x{:08X} s3=0x{:08X} s4=0x{:08X} s5=0x{:08X} s6=0x{:08X} s7=0x{:08X} s8=0x{:08X} s9=0x{:08X} s10=0x{:08X} s11=0x{:08X} s12=0x{:08X} s13=0x{:08X}",
        reason.label(),
        sls2_object_candidate_label(
            draw_context.vertex_membership,
            draw_context.pixel_membership
        ),
        draw_context.family,
        draw_context.vertex_membership.group,
        draw_context.vertex_membership.index,
        draw_context.pixel_membership.group,
        draw_context.pixel_membership.index,
        draw_context.pass,
        draw_context.render_pass_enum,
        draw_context.render_pass_num_lights,
        draw_context.render_pass_current_land_texture,
        draw_context.vertex_shader,
        draw_context.pixel_shader,
        stages[0].load(Ordering::Acquire),
        stages[1].load(Ordering::Acquire),
        stages[2].load(Ordering::Acquire),
        stages[3].load(Ordering::Acquire),
        stages[4].load(Ordering::Acquire),
        stages[5].load(Ordering::Acquire),
        stages[6].load(Ordering::Acquire),
        stages[7].load(Ordering::Acquire),
        stages[8].load(Ordering::Acquire),
        stages[9].load(Ordering::Acquire),
        stages[10].load(Ordering::Acquire),
        stages[11].load(Ordering::Acquire),
        stages[12].load(Ordering::Acquire),
        stages[13].load(Ordering::Acquire),
    );
}

fn sls2_object_candidate_label(
    vertex: ShaderArrayMembership,
    pixel: ShaderArrayMembership,
) -> &'static str {
    if vertex.group != PPLIGHTING_VERTEX_GROUP_C || pixel.group != PPLIGHTING_PIXEL_GROUP_B {
        return "non_sls2";
    }

    match pixel.index {
        PPLIGHTING_PIXEL_SLS2_ADTS_DEFAULT_INDEX => "adts",
        PPLIGHTING_PIXEL_SLS2_ADTS_OPT_INDEX => "adts_opt",
        PPLIGHTING_PIXEL_SLS2_ADTS_OPT_LOD_INDEX => "adts_lod_opt",
        PPLIGHTING_PIXEL_SLS2_ADTS_SI_INDEX => "adts_si",
        PPLIGHTING_PIXEL_SLS2_ADTS_PROJECTED_SHADOW_INDEX => "adts_shadow",
        PPLIGHTING_PIXEL_SLS2_ADTS_SI_PROJECTED_SHADOW_INDEX => "adts_si_shadow",
        PPLIGHTING_PIXEL_SLS2_ADTS_STBB_INDEX => "adts_stbb",
        9 => "adts_hair",
        10 => "adts_hair_shadow",
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_INDEX => "adts_lights2",
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_SI_INDEX => "adts_lights2_si",
        13 => "adts_lights2_hair",
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_PROJECTED_SHADOW_INDEX => "adts_lights2_shadow",
        PPLIGHTING_PIXEL_SLS2_ADTS_LIGHTS2_SI_PROJECTED_SHADOW_INDEX => "adts_lights2_si_shadow",
        16 => "adts_lights2_hair_shadow",
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_INDEX => "adts_specular",
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_SI_INDEX => "adts_specular_si",
        19 => "adts_specular_hair",
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_PROJECTED_SHADOW_INDEX => "adts_specular_shadow",
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_SI_PROJECTED_SHADOW_INDEX => "adts_specular_si_shadow",
        22 => "adts_specular_hair_shadow",
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_INDEX => "adts_specular_lights2",
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_SI_INDEX => "adts_specular_lights2_si",
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_PROJECTED_SHADOW_INDEX => {
            "adts_specular_lights2_shadow"
        }
        PPLIGHTING_PIXEL_SLS2_ADTS_SPECULAR_LIGHTS2_SI_PROJECTED_SHADOW_INDEX => {
            "adts_specular_lights2_si_shadow"
        }
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS9_INDEX => "adts10_lights9",
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS9_SI_INDEX => "adts10_lights9_si",
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_INDEX => "adts10_lights4",
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_OPT_INDEX => "adts10_lights4_opt",
        PPLIGHTING_PIXEL_SLS2_ADTS10_LIGHTS4_SI_INDEX => "adts10_lights4_si",
        PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_INDEX => "adts10_specular_lights4",
        PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_OPT_INDEX => "adts10_specular_lights4_opt",
        PPLIGHTING_PIXEL_SLS2_ADTS10_SPECULAR_LIGHTS4_SI_INDEX => "adts10_specular_lights4_si",
        37 => "only_light_lights2_opt",
        38 => "only_light_lights2_si_opt",
        39 => "only_light_lights2_shadow_opt",
        40 => "only_light_lights2_si_shadow_opt",
        41 => "only_light_lights3_opt",
        42 => "only_light_lights3_si_opt",
        43 => "only_light_lights3_shadow_opt",
        44 => "only_light_lights3_si_shadow_opt",
        45 => "diffuse_lights2",
        46 => "diffuse_lights3",
        47 => "only_specular",
        48 => "only_specular_hair",
        49 => "only_specular_shadow",
        50 => "only_specular_hair_shadow",
        51 => "only_specular_point",
        52 => "only_specular_point_hair",
        53 => "only_specular_point_lights2",
        54 => "only_specular_point_lights2_hair",
        55 => "only_specular_point_lights3",
        56 => "only_specular_point_lights3_hair",
        _ => "unknown_sls2",
    }
}

fn is_sls2_object_candidate_pixel_index(index: u32) -> bool {
    matches!(index, 0..=59)
}

fn maybe_log_terrain_candidate_pair(
    reason: ReplacementSkipReason,
    draw_context: ReplacementDrawContext,
) {
    if !DEBUG_LOG_DRAWS.load(Ordering::Acquire) {
        return;
    }
    if draw_context.family != PPLIGHTING_FAMILY_VERTEX_C_PIXEL_B {
        return;
    }
    if draw_context.vertex_membership.group != PPLIGHTING_VERTEX_GROUP_C
        || draw_context.pixel_membership.group != PPLIGHTING_PIXEL_GROUP_B
    {
        return;
    }
    if !is_sls2_terrain_vertex_index(draw_context.vertex_membership.index)
        && !is_sls2_terrain_pixel_index(draw_context.pixel_membership.index)
    {
        return;
    }

    let count = REPLACEMENT_TERRAIN_CANDIDATE_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= 64 {
        return;
    }

    let stages = &TEXTURE_CAPTURE.stages;
    log::info!(
        "[PBR] Terrain candidate pair skipped: reason={} vgrp={} vidx={} pgrp={} pidx={} pass={:p} pass_enum={} pass_lights={} pass_land_tex={} vs={:p} ps={:p} s0=0x{:08X} s1=0x{:08X} s2=0x{:08X} s3=0x{:08X} s4=0x{:08X} s5=0x{:08X} s6=0x{:08X} s7=0x{:08X} s8=0x{:08X} s9=0x{:08X} s10=0x{:08X} s11=0x{:08X} s12=0x{:08X} s13=0x{:08X}",
        reason.label(),
        draw_context.vertex_membership.group,
        draw_context.vertex_membership.index,
        draw_context.pixel_membership.group,
        draw_context.pixel_membership.index,
        draw_context.pass,
        draw_context.render_pass_enum,
        draw_context.render_pass_num_lights,
        draw_context.render_pass_current_land_texture,
        draw_context.vertex_shader,
        draw_context.pixel_shader,
        stages[0].load(Ordering::Acquire),
        stages[1].load(Ordering::Acquire),
        stages[2].load(Ordering::Acquire),
        stages[3].load(Ordering::Acquire),
        stages[4].load(Ordering::Acquire),
        stages[5].load(Ordering::Acquire),
        stages[6].load(Ordering::Acquire),
        stages[7].load(Ordering::Acquire),
        stages[8].load(Ordering::Acquire),
        stages[9].load(Ordering::Acquire),
        stages[10].load(Ordering::Acquire),
        stages[11].load(Ordering::Acquire),
        stages[12].load(Ordering::Acquire),
        stages[13].load(Ordering::Acquire),
    );
}

fn is_sls2_terrain_vertex_index(index: u32) -> bool {
    matches!(index, 2 | 5 | 53..=62 | 76..=83 | 100..=101)
}

fn is_sls2_terrain_pixel_index(index: u32) -> bool {
    matches!(index, 3 | 6 | 60..=69 | 80..=86 | 92..=149)
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
        "[PBR] Native PBR replacement has not applied yet: checks={} no_diffuse={} no_context={} unsupported_family={} unsupported_vertex_abi={} skin_vertex_abi={} missing_terrain_contract={} interior_terrain_disabled={} interior_object_light_pass_disabled={} unproven_landlod_shadow={} no_selector={} no_normal={} no_glow={} no_shader={} bind_failed={} no_vanilla_handle={} handle_write_failed={} last_family={} last_vgrp={} last_vidx={} last_pgrp={} last_pidx={}",
        checks,
        REPLACEMENT_SKIP_NO_DIFFUSE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_DRAW_CONTEXT.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNSUPPORTED_FAMILY.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNSUPPORTED_VERTEX_ABI.load(Ordering::Acquire),
        REPLACEMENT_SKIP_SKIN_VERTEX_ABI.load(Ordering::Acquire),
        REPLACEMENT_SKIP_MISSING_TERRAIN_CONTRACT.load(Ordering::Acquire),
        REPLACEMENT_SKIP_INTERIOR_TERRAIN_DISABLED.load(Ordering::Acquire),
        REPLACEMENT_SKIP_INTERIOR_OBJECT_LIGHT_PASS_DISABLED.load(Ordering::Acquire),
        REPLACEMENT_SKIP_UNPROVEN_LANDLOD_SHADOW.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_SELECTOR_RECORD.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_NORMAL_SOURCE.load(Ordering::Acquire),
        REPLACEMENT_SKIP_NO_GLOW_SOURCE.load(Ordering::Acquire),
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
