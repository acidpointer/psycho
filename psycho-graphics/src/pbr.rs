//! Native PBR draw-contract layer for FalloutNV.
//!
//! This module owns only the proven engine-side contract for material PBR:
//! draw-scoped current pass capture and final vanilla texture-stage capture.
//! It intentionally does not mutate native shader objects. Visible replacement
//! stays opt-in until a concrete replacement shader input contract exists.

use std::{
    array,
    ffi::c_void,
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
    hook::inline::inlinehook::InlineHookContainer, memory::validate_memory_range,
};

const BS_SHADER_SET_SHADERS_ADDR: usize = 0x00BE1F90;
const CURRENT_PASS_SHADER_APPLY_ADDR: usize = 0x00BD4BA0;
const NIDX9_RENDER_STATE_SET_TEXTURE_ADDR: usize = 0x00E88A20;
const CURRENT_GEOMETRY_SLOT_ADDR: usize = 0x011F91E0;
const CURRENT_PASS_GLOBAL_ADDR: usize = 0x0126F74C;
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
const GEOMETRY_FLAGS_OFFSET: usize = 0x20;
const GEOMETRY_SHADER_ARGS_OFFSET: usize = 0x68;
const GEOMETRY_STATE_OFFSET: usize = 0xB8;
const GEOMETRY_CONTEXT_OFFSET: usize = 0xBC;
const GEOMETRY_STATE_VALUE_OFFSET: usize = 0x34;
const MAX_TEXTURE_STAGES: usize = 16;
const MAX_LOGS: u32 = 16;

const SET_SHADERS_PROLOGUE: &[u8] = &[
    0x8B, 0x0D, 0x4C, 0xF7, 0x26, 0x01, 0x56, 0x57, 0xE8, 0x23, 0xD8, 0x29, 0x00, 0x8B, 0xF0, 0xA1,
];
const SET_TEXTURE_PROLOGUE: &[u8] = &[
    0x8B, 0x44, 0x24, 0x04, 0x8B, 0x54, 0x24, 0x08, 0x39, 0x94, 0x81, 0xA0, 0x10, 0x00, 0x00, 0x74,
];
const PASS_SHADER_APPLY_PROLOGUE: &[u8] = &[
    0x83, 0xEC, 0x0C, 0xA1, 0xE0, 0x91, 0x1F, 0x01, 0x53, 0x55, 0x56, 0x8B, 0x30, 0x8B, 0x46, 0x20,
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

static SET_SHADERS_HOOK: LazyLock<InlineHookContainer<SetShadersFn>> =
    LazyLock::new(InlineHookContainer::new);
static SET_TEXTURE_HOOK: LazyLock<InlineHookContainer<SetTextureFn>> =
    LazyLock::new(InlineHookContainer::new);
static PASS_SHADER_APPLY_HOOK: LazyLock<InlineHookContainer<PassShaderApplyFn>> =
    LazyLock::new(InlineHookContainer::new);

static INSTALLED: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
static DEBUG_LOG_DRAWS: AtomicBool = AtomicBool::new(false);
static EXPERIMENTAL_SHADER_REPLACEMENT: AtomicBool = AtomicBool::new(false);
static DRAW_LOGS: AtomicU32 = AtomicU32::new(0);
static TEXTURE_LOGS: AtomicU32 = AtomicU32::new(0);
static INTERFACE_LOGS: AtomicU32 = AtomicU32::new(0);
static REPLACEMENT_LOGS: AtomicU32 = AtomicU32::new(0);

static TEXTURE_CAPTURE: LazyLock<TextureCapture> = LazyLock::new(TextureCapture::new);
static DRAW_CAPTURE: LazyLock<DrawCapture> = LazyLock::new(DrawCapture::new);
static INTERFACE_CAPTURE: LazyLock<ShaderInterfaceCapture> =
    LazyLock::new(ShaderInterfaceCapture::new);

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePbrSettings {
    pub(crate) enabled: bool,
    pub(crate) experimental_shader_replacement: bool,
    pub(crate) require_vanilla_prologues: bool,
    pub(crate) debug_log_draws: bool,
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

impl Default for NativePbrSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            experimental_shader_replacement: false,
            require_vanilla_prologues: true,
            debug_log_draws: false,
        }
    }
}

struct TextureCapture {
    render_state: AtomicUsize,
    stages: [AtomicUsize; MAX_TEXTURE_STAGES],
    set_calls: AtomicU32,
}

impl TextureCapture {
    fn new() -> Self {
        Self {
            render_state: AtomicUsize::new(0),
            stages: array::from_fn(|_| AtomicUsize::new(0)),
            set_calls: AtomicU32::new(0),
        }
    }

    fn clear(&self) {
        self.render_state.store(0, Ordering::Release);
        for stage in &self.stages {
            stage.store(0, Ordering::Release);
        }
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
        self.param_pixel_interface.store(0, Ordering::Release);
        self.param_vertex_interface.store(0, Ordering::Release);
        self.param_pixel_apply.store(0, Ordering::Release);
        self.param_vertex_apply.store(0, Ordering::Release);
    }
}

pub(crate) fn install(settings: NativePbrSettings) -> Result<()> {
    if !settings.enabled {
        log::info!("[PBR] Native PBR disabled by config");
        return Ok(());
    }

    DEBUG_LOG_DRAWS.store(settings.debug_log_draws, Ordering::Release);
    EXPERIMENTAL_SHADER_REPLACEMENT
        .store(settings.experimental_shader_replacement, Ordering::Release);

    if settings.require_vanilla_prologues && !verify_hook_prologues() {
        log::warn!("[PBR] Native PBR skipped because a target prologue is not vanilla");
        return Ok(());
    }

    if INSTALLED.swap(true, Ordering::AcqRel) {
        ENABLED.store(true, Ordering::Release);
        log::info!("[PBR] Native PBR hooks already installed");
        return Ok(());
    }

    if !install_set_texture_hook() {
        INSTALLED.store(false, Ordering::Release);
        return Ok(());
    }

    if !install_set_shaders_hook() {
        let _ = SET_TEXTURE_HOOK.disable();
        INSTALLED.store(false, Ordering::Release);
        return Ok(());
    }

    if !install_pass_shader_apply_hook() {
        let _ = SET_SHADERS_HOOK.disable();
        let _ = SET_TEXTURE_HOOK.disable();
        INSTALLED.store(false, Ordering::Release);
        return Ok(());
    }

    ENABLED.store(true, Ordering::Release);
    log::info!("[PBR] Native PBR draw, texture, and shader-interface contract hooks installed");

    if settings.experimental_shader_replacement {
        log::warn!(
            "[PBR] Experimental shader replacement requested; draw-time shader handles are captured, but visible replacement is disabled until a concrete replacement shader contract is implemented"
        );
    }

    Ok(())
}

pub(crate) fn reset_runtime_state() {
    TEXTURE_CAPTURE.clear();
    DRAW_CAPTURE.clear();
    INTERFACE_CAPTURE.clear();
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

    set_shaders_ok && set_texture_ok && pass_shader_apply_ok
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

unsafe extern "thiscall" fn hook_set_shaders(shader: *mut c_void, pass_index: u32) {
    if ENABLED.load(Ordering::Acquire) {
        unsafe {
            record_draw_context(pass_index);
        }
        if EXPERIMENTAL_SHADER_REPLACEMENT.load(Ordering::Acquire) {
            log_replacement_blocked();
        }
    }

    let Ok(original) = SET_SHADERS_HOOK.original() else {
        log_limited(&DRAW_LOGS, "[PBR] Missing original SetShaders function");
        return;
    };

    unsafe {
        original(shader, pass_index);
    }
}

unsafe extern "thiscall" fn hook_pass_shader_apply(
    apply_this: *mut c_void,
    apply_param: *mut c_void,
) {
    if ENABLED.load(Ordering::Acquire) {
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

fn record_texture_binding(render_state: *mut c_void, stage: u32, texture: *mut c_void) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }

    if stage as usize >= MAX_TEXTURE_STAGES {
        log_limited(
            &TEXTURE_LOGS,
            "[PBR] Ignoring SetTexture call with stage outside the 16-slot native cache",
        );
        return;
    }

    TEXTURE_CAPTURE
        .render_state
        .store(render_state as usize, Ordering::Release);
    TEXTURE_CAPTURE.stages[stage as usize].store(texture as usize, Ordering::Release);
    TEXTURE_CAPTURE.set_calls.fetch_add(1, Ordering::Relaxed);
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
        );
    }
}

unsafe fn record_shader_interface_context(apply_this: *mut c_void, apply_param: *mut c_void) {
    let pass = unsafe { read_ptr(CURRENT_PASS_GLOBAL_ADDR) };
    let vertex_shader = unsafe { read_ptr_offset(pass, PASS_VERTEX_SHADER_OFFSET) };
    let pixel_shader = unsafe { read_ptr_offset(pass, PASS_PIXEL_SHADER_OFFSET) };
    let selector_object = unsafe {
        read_ptr(
            SHADER_INTERFACE_SELECTOR_ARRAY_ADDR
                + PPLIGHTING_SHADER_SELECTOR_INDEX * size_of::<*mut c_void>(),
        )
    };
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
    let geometry_slot = unsafe { read_ptr(CURRENT_GEOMETRY_SLOT_ADDR) };
    let geometry = unsafe { read_ptr_from(geometry_slot) };
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
            geometry_slot,
            geometry,
            geometry_flags,
            geometry_state,
            geometry_state_value,
            geometry_context,
        );
    }
}

unsafe fn read_ptr(address: usize) -> *mut c_void {
    let slot = address as *const c_void;
    if validate_memory_range(slot, size_of::<*mut c_void>()).is_err() {
        return null_mut();
    }

    unsafe { (address as *const *mut c_void).read() }
}

unsafe fn read_ptr_from(ptr: *mut c_void) -> *mut c_void {
    if ptr.is_null() {
        return null_mut();
    }

    if validate_memory_range(ptr, size_of::<*mut c_void>()).is_err() {
        return null_mut();
    }

    unsafe { (ptr as *const *mut c_void).read() }
}

unsafe fn read_ptr_offset(base: *mut c_void, offset: usize) -> *mut c_void {
    let slot = unsafe { offset_ptr(base, offset) };
    if slot.is_null() {
        return null_mut();
    }

    if validate_memory_range(slot, size_of::<*mut c_void>()).is_err() {
        return null_mut();
    }

    unsafe { (slot as *const *mut c_void).read() }
}

unsafe fn read_u32_offset(base: *mut c_void, offset: usize) -> u32 {
    let slot = unsafe { offset_ptr(base, offset) };
    if slot.is_null() {
        return 0;
    }

    if validate_memory_range(slot, size_of::<u32>()).is_err() {
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
        if validate_memory_range(base, byte_len).is_err() {
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
) {
    let count = DRAW_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_LOGS {
        return;
    }

    let stages = &TEXTURE_CAPTURE.stages;
    log::debug!(
        "[PBR] Draw pass={} pass={:p} vs={:p} ps={:p} vs_handle={:p} ps_handle={:p} family={} vgrp={} vidx={} pgrp={} pidx={} render_state=0x{:08X} s0=0x{:08X} s1=0x{:08X} s2=0x{:08X} s3=0x{:08X}",
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
        "[PBR] ShaderInterface this={:p} param={:p} resource={:p} pass={:p} vs={:p} ps={:p} selector={:p} sel_pi={:p} sel_vi={:p} sel_p78={:p} sel_v78={:p} param_pi={:p} param_vi={:p} param_p78={:p} param_v78={:p} sel_known=({},{}) param_known=({},{}) geom_slot={:p} geom={:p} flags=0x{:08X} geom_state={:p} state_value={:p} geom_ctx=0x{:08X}",
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
        "[PBR] ShaderInterface selector_extra selector={:p} alt_pi={:p} alt_vi={:p} alt_p78={:p} alt_v78={:p} copy_pi={:p} copy_vi={:p} copy_p78={:p} copy_v78={:p} alt_known=({},{}) copy_known=({},{})",
        selector_object,
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

fn log_replacement_blocked() {
    let count = REPLACEMENT_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= 1 {
        return;
    }

    log::warn!(
        "[PBR] Native shader replacement is not active; vanilla handle binding is proven, but no visible replacement shader contract has been enabled"
    );
}

fn log_limited(counter: &AtomicU32, message: &str) {
    let count = counter.fetch_add(1, Ordering::Relaxed);
    if count < MAX_LOGS {
        log::warn!("{message}");
    }
}
