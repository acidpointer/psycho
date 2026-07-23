//! Screen-space shader runtime and in-game menu.

use std::{
    ffi::{CString, c_void},
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use libpsycho::os::windows::{
    directx9::{
        D3DCULL_NONE, D3DFORMAT, D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE,
        D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_ZENABLE,
        D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER,
        D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSBT_ALL, D3DSURFACE_DESC, D3DTA_TEXTURE,
        D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1,
        D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9,
        Device9Ref, Direct3DError as WindowsError, Direct3DResult, PixelShader9, ScreenVertex,
        StateBlock9, Surface9, Texture9, direct3d_failure,
    },
    winapi::{get_active_window, is_window},
};
use parking_lot::Mutex;

use crate::{
    backend::{self, DepthFrame, DepthProvider},
    config::{DepthProviderConfig, GraphicsMenuConfig},
    effects::{
        ambient_occlusion, anti_aliasing, atmosphere, blooming_hdr, depth_of_field, pbr, sky,
        sunshafts,
    },
    luts,
    shaders::{self, EmbeddedEffectKind, ScreenShaderSource, ShaderOptionValue, ShaderPhase},
};

const FIRST_OPTION_REGISTER: u32 = 3;
const ENVIRONMENT_REGISTER: u32 = 6;
const SUN_REGISTER: u32 = 8;
const COLOR_WRITE_ALL: u32 = 0x0F;
const WM_KEYDOWN: u32 = 0x0100;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_KEYUP: u32 = 0x0101;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_CHAR: u32 = 0x0102;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_MBUTTONDOWN: u32 = 0x0207;
const WM_MBUTTONUP: u32 = 0x0208;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_MOUSEHWHEEL: u32 = 0x020E;
const DEFAULT_MENU_TOGGLE_KEY: u32 = 0x2D;
const VK_ESCAPE: usize = 0x1B;

static RUNTIME: LazyLock<Mutex<ScreenShaderRuntime>> =
    LazyLock::new(|| Mutex::new(ScreenShaderRuntime::default()));
static MENU_OPEN: AtomicBool = AtomicBool::new(false);
static IMGUI_READY: AtomicBool = AtomicBool::new(false);
static MENU_DIAGNOSTICS_STATE: AtomicU32 = AtomicU32::new(0);
static MENU_TOGGLE_KEY: AtomicU32 = AtomicU32::new(DEFAULT_MENU_TOGGLE_KEY);
static MENU_KEY_CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING_MENU_TOGGLE_KEY: AtomicU32 = AtomicU32::new(0);
static NATIVE_DOF_QUERY_NEEDED: AtomicBool = AtomicBool::new(false);
static PRESENT_FRAME_TIMING_NEEDED: AtomicBool = AtomicBool::new(false);
static FNV_SCENE_REQUIREMENTS: AtomicU32 = AtomicU32::new(0);
static PRESENT_APPLY_BUSY: AtomicU32 = AtomicU32::new(0);
static PRESENT_FINISH_BUSY: AtomicU32 = AtomicU32::new(0);
static PRESENT_FAILED: AtomicU32 = AtomicU32::new(0);
static SCENE_PHASE_BUSY: AtomicU32 = AtomicU32::new(0);
static WORLD_COLOR_BUSY: AtomicU32 = AtomicU32::new(0);
static RESET_BUSY: AtomicU32 = AtomicU32::new(0);
const FNV_REQUIRE_WORLD_DEPTH: u32 = 1 << 0;
const FNV_REQUIRE_FIRST_PERSON_DEPTH: u32 = 1 << 1;
const FNV_REQUIRE_WORLD_COLOR: u32 = 1 << 2;
const MENU_DIAGNOSTICS_ACTIVE_BIT: u32 = 1;
const MENU_DIAGNOSTICS_SESSION_INCREMENT: u32 = 2;

#[derive(Clone, Copy, Default)]
struct RuntimeLockTelemetry {
    present_apply: u32,
    present_finish: u32,
    failed_present: u32,
    scene_phase: u32,
    world_color: u32,
    reset: u32,
}

impl RuntimeLockTelemetry {
    fn has_rejections(self) -> bool {
        self.present_apply
            | self.present_finish
            | self.failed_present
            | self.scene_phase
            | self.world_color
            | self.reset
            != 0
    }
}

pub(crate) fn menu_diagnostics_active() -> bool {
    MENU_DIAGNOSTICS_STATE.load(Ordering::Relaxed) & MENU_DIAGNOSTICS_ACTIVE_BIT != 0
}

fn menu_diagnostics_session() -> u32 {
    MENU_DIAGNOSTICS_STATE.load(Ordering::Acquire) / MENU_DIAGNOSTICS_SESSION_INCREMENT
}

fn diagnostics_state_transition(state: u32, active: bool) -> Option<u32> {
    if (state & MENU_DIAGNOSTICS_ACTIVE_BIT != 0) == active {
        return None;
    }
    Some(if active {
        state.wrapping_add(MENU_DIAGNOSTICS_SESSION_INCREMENT) | MENU_DIAGNOSTICS_ACTIVE_BIT
    } else {
        state & !MENU_DIAGNOSTICS_ACTIVE_BIT
    })
}

fn set_menu_diagnostics_active(active: bool) {
    let mut state = MENU_DIAGNOSTICS_STATE.load(Ordering::Acquire);
    loop {
        let Some(next) = diagnostics_state_transition(state, active) else {
            return;
        };
        match MENU_DIAGNOSTICS_STATE.compare_exchange_weak(
            state,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(current) => state = current,
        }
    }
    pbr::set_menu_diagnostics_active(active);
    crate::fnv_local_lights::set_diagnostics_active(active);
    crate::fnv_world_pipeline::set_diagnostics_active(active);
}

pub(crate) fn configure(settings: RuntimeSettings) {
    // This runs from NVSEPlugin_Load. Keep the focused FNV world owner dormant
    // until DeferredInit; see graphics_fnv_atmosphere_startup_crash_errata.md.
    MENU_TOGGLE_KEY.store(
        sanitize_menu_toggle_key(settings.menu_toggle_key),
        Ordering::Release,
    );
    update_native_dof_query_needed(&settings.menu_config);
    let mut runtime = RUNTIME.lock();
    runtime.configure(settings);
}

pub(crate) fn prepare_for_game_load() {
    MENU_OPEN.store(false, Ordering::Release);
    MENU_KEY_CAPTURE_ACTIVE.store(false, Ordering::Release);
    PENDING_MENU_TOGGLE_KEY.store(0, Ordering::Release);
    set_menu_diagnostics_active(false);
    crate::input::set_menu_input_blocked(false);
}

#[cfg(test)]
mod load_transition_tests {
    use super::{
        MENU_KEY_CAPTURE_ACTIVE, MENU_OPEN, PENDING_MENU_TOGGLE_KEY, menu_diagnostics_active,
        prepare_for_game_load, set_menu_diagnostics_active,
    };
    use std::sync::atomic::Ordering;

    #[test]
    fn game_load_releases_all_workbench_input_ownership() {
        MENU_OPEN.store(true, Ordering::Release);
        MENU_KEY_CAPTURE_ACTIVE.store(true, Ordering::Release);
        PENDING_MENU_TOGGLE_KEY.store(0x41, Ordering::Release);
        set_menu_diagnostics_active(true);
        crate::input::set_menu_input_blocked_for_test(true);

        prepare_for_game_load();

        assert!(!MENU_OPEN.load(Ordering::Acquire));
        assert!(!MENU_KEY_CAPTURE_ACTIVE.load(Ordering::Acquire));
        assert_eq!(PENDING_MENU_TOGGLE_KEY.load(Ordering::Acquire), 0);
        assert!(!menu_diagnostics_active());
        assert!(!crate::input::menu_input_blocked_for_test());
    }
}

pub(crate) fn needs_native_dof_query() -> bool {
    NATIVE_DOF_QUERY_NEEDED.load(Ordering::Acquire)
}

pub(crate) unsafe fn apply_present_frame(device_ptr: *mut c_void, hwnd_hint: *mut c_void) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        PRESENT_APPLY_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    runtime.begin_render_epoch(crate::hooks::render_epoch());

    if crate::fnv_world_pipeline::config_publish_pending() {
        crate::fnv_world_pipeline::publish_config(runtime.settings.menu_config);
    }

    let result = unsafe { runtime.apply_present_frame(device_ptr, hwnd_hint) };
    if let Err(err) = result {
        runtime.log_frame_error(&err);
    }
}

pub(crate) unsafe fn apply_fnv_scene_pre_image_space(
    device_ptr: *mut c_void,
    source_rendered_texture: *mut c_void,
) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        SCENE_PHASE_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    runtime.begin_render_epoch(crate::hooks::render_epoch());

    let result = unsafe {
        runtime.apply_scene_phase(
            device_ptr,
            ShaderPhase::ScenePreImageSpace,
            ScenePhaseTarget::RenderedTextureSource(source_rendered_texture),
        )
    };
    if let Err(err) = result {
        runtime.log_frame_error(&err);
    }
}

pub(crate) unsafe fn apply_fnv_scene_post_image_space(
    device_ptr: *mut c_void,
    native_dof_active: bool,
) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        SCENE_PHASE_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    runtime.begin_render_epoch(crate::hooks::render_epoch());

    runtime.native_dof_active_this_frame = native_dof_active;
    let result = unsafe {
        runtime.apply_scene_phase(
            device_ptr,
            ShaderPhase::ScenePostImageSpace,
            ScenePhaseTarget::CurrentRenderTarget,
        )
    };
    if let Err(err) = result {
        runtime.log_frame_error(&err);
    }
}

pub(crate) unsafe fn apply_fnv_final_image_space(device_ptr: *mut c_void) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        SCENE_PHASE_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    runtime.begin_render_epoch(crate::hooks::render_epoch());

    let result = unsafe {
        runtime.apply_scene_phase(
            device_ptr,
            ShaderPhase::FinalImageSpace,
            ScenePhaseTarget::CurrentRenderTarget,
        )
    };
    if let Err(err) = result {
        runtime.log_frame_error(&err);
    }
}

pub(crate) unsafe fn capture_fnv_world_color(device_ptr: *mut c_void) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        WORLD_COLOR_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    runtime.begin_render_epoch(crate::hooks::render_epoch());

    let result = unsafe { runtime.capture_fnv_world_color(device_ptr) };
    if let Err(err) = result {
        runtime.log_world_color_error(&err);
    }
}

pub(crate) fn needs_fnv_depth_capture(slot: backend::DepthResolveSlot) -> bool {
    let requirements = FNV_SCENE_REQUIREMENTS.load(Ordering::Acquire);
    match slot {
        backend::DepthResolveSlot::World => requirements & FNV_REQUIRE_WORLD_DEPTH != 0,
        backend::DepthResolveSlot::FirstPerson => {
            requirements & FNV_REQUIRE_FIRST_PERSON_DEPTH != 0
        }
    }
}

pub(crate) fn needs_fnv_world_color_capture() -> bool {
    FNV_SCENE_REQUIREMENTS.load(Ordering::Acquire) & FNV_REQUIRE_WORLD_COLOR != 0
}

pub(crate) unsafe fn try_release_device_resources(device_ptr: *mut c_void) -> bool {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        RESET_BUSY.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    if !crate::fnv_world_pipeline::try_release_device_resources_after(device_ptr, || {
        crate::fnv_local_lights::try_release_device_resources_after(device_ptr as usize, || {
            backend::try_reset_depth_resources()
        })
    }) {
        RESET_BUSY.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    runtime.release_if_device(device_ptr);
    true
}

pub(crate) fn present_frame_started_at() -> Option<Instant> {
    let diagnostics_active =
        MENU_DIAGNOSTICS_STATE.load(Ordering::Acquire) & MENU_DIAGNOSTICS_ACTIVE_BIT != 0;
    (diagnostics_active || PRESENT_FRAME_TIMING_NEEDED.load(Ordering::Acquire)).then(Instant::now)
}

pub(crate) unsafe fn finish_present_frame(
    render_epoch: u32,
    present_started_at: Option<Instant>,
    present_succeeded: bool,
) {
    if !present_succeeded {
        PRESENT_FAILED.fetch_add(1, Ordering::Relaxed);
    }
    let diagnostics_state = MENU_DIAGNOSTICS_STATE.load(Ordering::Acquire);
    let diagnostics_session = (diagnostics_state & MENU_DIAGNOSTICS_ACTIVE_BIT != 0)
        .then_some(diagnostics_state / MENU_DIAGNOSTICS_SESSION_INCREMENT);
    if diagnostics_session.is_none() && !PRESENT_FRAME_TIMING_NEEDED.load(Ordering::Acquire) {
        return;
    }
    let Some(mut runtime) = RUNTIME.try_lock() else {
        PRESENT_FINISH_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };

    runtime.begin_render_epoch(render_epoch);
    runtime.finish_present_frame(
        render_epoch,
        present_succeeded.then_some(present_started_at).flatten(),
        diagnostics_session,
    );
}

fn runtime_lock_telemetry() -> RuntimeLockTelemetry {
    RuntimeLockTelemetry {
        present_apply: PRESENT_APPLY_BUSY.load(Ordering::Relaxed),
        present_finish: PRESENT_FINISH_BUSY.load(Ordering::Relaxed),
        failed_present: PRESENT_FAILED.load(Ordering::Relaxed),
        scene_phase: SCENE_PHASE_BUSY.load(Ordering::Relaxed),
        world_color: WORLD_COLOR_BUSY.load(Ordering::Relaxed),
        reset: RESET_BUSY.load(Ordering::Relaxed),
    }
}

pub(crate) fn handle_window_message(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> Option<isize> {
    let menu_open = MENU_OPEN.load(Ordering::Acquire);
    if menu_open
        && MENU_KEY_CAPTURE_ACTIVE.load(Ordering::Acquire)
        && (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN)
    {
        if wparam == VK_ESCAPE {
            MENU_KEY_CAPTURE_ACTIVE.store(false, Ordering::Release);
        } else if let Some(key) = valid_virtual_key(wparam) {
            PENDING_MENU_TOGGLE_KEY.store(key, Ordering::Release);
            MENU_KEY_CAPTURE_ACTIVE.store(false, Ordering::Release);
        }
        return Some(0);
    }

    let toggle_key = MENU_TOGGLE_KEY.load(Ordering::Acquire) as usize;
    if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) && wparam == toggle_key {
        let open = !menu_open;
        MENU_OPEN.store(open, Ordering::Release);
        set_menu_diagnostics_active(open && IMGUI_READY.load(Ordering::Acquire));
        crate::input::set_menu_input_blocked(open);
        if !open {
            MENU_KEY_CAPTURE_ACTIVE.store(false, Ordering::Release);
            PENDING_MENU_TOGGLE_KEY.store(0, Ordering::Release);
        }
        return Some(0);
    }

    if !menu_open || !IMGUI_READY.load(Ordering::Acquire) {
        return None;
    }

    // SAFETY: This is the HWND/message packet forwarded by the window-proc detour.
    let handled = unsafe { psycho_imgui::wndproc(hwnd, msg, wparam, lparam) };
    if handled != 0 || is_input_message(msg) {
        return Some(1);
    }

    None
}

#[derive(Clone, Copy)]
pub(crate) struct RuntimeSettings {
    pub(crate) menu_config: GraphicsMenuConfig,
    pub(crate) depth_provider: DepthProvider,
    pub(crate) menu_toggle_key: u32,
    pub(crate) shader_scan_interval_ms: u64,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        let menu_config = GraphicsMenuConfig::default();
        Self {
            menu_config,
            depth_provider: menu_config.depth_provider.into(),
            menu_toggle_key: sanitize_menu_toggle_key(menu_config.menu_toggle_key),
            shader_scan_interval_ms: menu_config.shader_scan_interval_ms,
        }
    }
}

struct ScreenShaderRuntime {
    settings: RuntimeSettings,
    sources: Vec<ScreenShaderSource>,
    device_ptr: usize,
    compiled: Option<Vec<CompiledPass>>,
    ambient_occlusion: Option<ambient_occlusion::AmbientOcclusionEffect>,
    anti_aliasing: Option<anti_aliasing::AntiAliasingEffect>,
    blooming_hdr: Option<blooming_hdr::BloomingHdrEffect>,
    final_color_shaders: Option<blooming_hdr::FinalColorShaderBytecode>,
    color_luts: luts::LutCatalog,
    sunshafts: Option<sunshafts::SunshaftsEffect>,
    depth_of_field: Option<depth_of_field::DepthOfFieldEffect>,
    depth_of_field_creation_failed: bool,
    final_color_copy: Option<BackbufferCopy>,
    scene_pre_color_copy: Option<BackbufferCopy>,
    scene_post_color_copy: Option<BackbufferCopy>,
    world_color_copy: Option<BackbufferCopy>,
    world_color_source_target: usize,
    state_block: Option<StateBlock9>,
    imgui: Option<psycho_imgui::Dx9Context>,
    imgui_hwnd: usize,
    imgui_needs_device_objects: bool,
    selected_menu_item: MenuSelection,
    present_timing: PresentFrameTiming,
    frame_pacing: FramePacing,
    next_scan: Option<Instant>,
    render_epoch: u32,
    frame_index: u32,
    last_depth_available: Option<bool>,
    last_fog_available: Option<bool>,
    last_sun_available: Option<bool>,
    error_logs: u32,
    scan_error_logs: u32,
    imgui_error_logs: u32,
    menu_config_error: Option<String>,
    menu_config_notice: Option<String>,
    menu_config_dirty: bool,
    scene_apply_logs: u32,
    scene_target_logs: u32,
    world_color_capture_logs: u32,
    world_color_captured_this_frame: bool,
    applied_phases: AppliedShaderPhases,
    native_dof_active_this_frame: bool,
}

impl Default for ScreenShaderRuntime {
    fn default() -> Self {
        let final_color_shaders = match blooming_hdr::FinalColorShaderBytecode::prepare() {
            Ok(shaders) => Some(shaders),
            Err(err) => {
                log::warn!("[FINAL_COLOR] Startup shader preparation failed: {err:#}");
                None
            }
        };
        Self {
            settings: RuntimeSettings::default(),
            sources: Vec::new(),
            device_ptr: 0,
            compiled: None,
            ambient_occlusion: None,
            anti_aliasing: None,
            blooming_hdr: None,
            final_color_shaders,
            color_luts: luts::LutCatalog::default(),
            sunshafts: None,
            depth_of_field: None,
            depth_of_field_creation_failed: false,
            final_color_copy: None,
            scene_pre_color_copy: None,
            scene_post_color_copy: None,
            world_color_copy: None,
            world_color_source_target: 0,
            state_block: None,
            imgui: None,
            imgui_hwnd: 0,
            imgui_needs_device_objects: false,
            selected_menu_item: MenuSelection::default(),
            present_timing: PresentFrameTiming::default(),
            frame_pacing: FramePacing::default(),
            next_scan: None,
            render_epoch: 0,
            frame_index: 0,
            last_depth_available: None,
            last_fog_available: None,
            last_sun_available: None,
            error_logs: 0,
            scan_error_logs: 0,
            imgui_error_logs: 0,
            menu_config_error: None,
            menu_config_notice: None,
            menu_config_dirty: false,
            scene_apply_logs: 0,
            scene_target_logs: 0,
            world_color_capture_logs: 0,
            world_color_captured_this_frame: false,
            applied_phases: AppliedShaderPhases::default(),
            native_dof_active_this_frame: false,
        }
    }
}

impl ScreenShaderRuntime {
    fn begin_render_epoch(&mut self, render_epoch: u32) {
        if self.render_epoch == render_epoch {
            return;
        }
        self.render_epoch = render_epoch;
        self.applied_phases = AppliedShaderPhases::default();
        self.world_color_captured_this_frame = false;
        self.world_color_source_target = 0;
        self.native_dof_active_this_frame = false;
        self.frame_index = self.frame_index.wrapping_add(1);
    }

    fn configure(&mut self, settings: RuntimeSettings) {
        let master_enabled = settings.menu_config.screen_space_shaders;
        pbr::configure_runtime_options(
            pbr::NativePbrSettings::from(settings.menu_config.native_pbr)
                .with_master_enabled(master_enabled),
        );
        sky::configure_runtime_options(
            sky::NativeSkySettings::from(settings.menu_config.native_sky)
                .with_master_enabled(master_enabled),
        );
        self.settings = settings;
        self.compiled = None;
        self.next_scan = None;
        self.menu_config_error = None;
        self.menu_config_notice = None;
        self.menu_config_dirty = false;
        self.publish_fnv_scene_requirements();
    }

    unsafe fn apply_present_frame(
        &mut self,
        device_ptr: *mut c_void,
        hwnd_hint: *mut c_void,
    ) -> Direct3DResult<()> {
        self.scan_shaders_if_due();

        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Ok(());
        };

        if self.device_ptr != device_ptr as usize {
            self.release_for_new_device();
            self.device_ptr = device_ptr as usize;
        }

        pbr::service_present_frame();
        depth_of_field::service_present_frame();

        self.ensure_imgui(&device, hwnd_hint);

        let menu_open = MENU_OPEN.load(Ordering::Acquire);
        let can_apply_at_present = self.settings.depth_provider == DepthProvider::None;
        let has_shader_work = can_apply_at_present
            && !self.applied_phases.is_applied(ShaderPhase::FinalImageSpace)
            && self.has_enabled_shader_for_phase(ShaderPhase::FinalImageSpace);
        if !menu_open && !has_shader_work {
            return Ok(());
        }

        if has_shader_work {
            self.ensure_shaders(&device);
        }

        let has_drawable_shader = self.has_drawable_shader();
        if !menu_open && !has_drawable_shader {
            return Ok(());
        }

        let shader_target = if has_shader_work && has_drawable_shader {
            let backbuffer = match device.back_buffer(0, 0) {
                Ok(backbuffer) => backbuffer,
                Err(err) => {
                    self.release_default_pool_resources();
                    return Err(err);
                }
            };
            let desc = backbuffer.desc()?;
            if desc.Width == 0 || desc.Height == 0 {
                return Ok(());
            }
            self.ensure_phase_color_copy(&device, &desc, ShaderPhase::FinalImageSpace)?;
            Some((backbuffer, desc))
        } else {
            None
        };

        self.ensure_state_block(&device)?;

        let Some(state_block) = self.state_block.as_ref() else {
            return Err(runtime_error(
                "[SHADERS] Missing D3D state block before capture",
            ));
        };
        state_block.capture()?;

        let draw_result = match shader_target.as_ref() {
            Some((backbuffer, desc)) => {
                self.draw_passes(&device, backbuffer, desc, ShaderPhase::FinalImageSpace)
            }
            None => Ok(()),
        };
        let menu_result = if menu_open { self.draw_menu() } else { Ok(()) };
        let restore_result = if let Some(state_block) = self.state_block.as_ref() {
            state_block.apply()
        } else {
            Err(runtime_error(
                "[SHADERS] Missing D3D state block before restore",
            ))
        };

        restore_result?;
        draw_result?;
        menu_result?;
        if has_shader_work {
            self.applied_phases
                .mark_applied(ShaderPhase::FinalImageSpace);
        }

        Ok(())
    }

    unsafe fn apply_scene_phase(
        &mut self,
        device_ptr: *mut c_void,
        phase: ShaderPhase,
        target: ScenePhaseTarget,
    ) -> Direct3DResult<()> {
        if self.applied_phases.is_applied(phase)
            || self.settings.depth_provider == DepthProvider::None
        {
            return Ok(());
        }

        self.scan_shaders_if_due();
        if !self.has_enabled_shader_for_phase(phase) {
            return Ok(());
        }

        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Ok(());
        };

        if self.device_ptr != device_ptr as usize {
            self.release_for_new_device();
            self.device_ptr = device_ptr as usize;
        }

        self.ensure_shaders(&device);
        if !self.has_drawable_shader_for_phase(phase) {
            return Ok(());
        }

        let restore_target = match device.render_target(0) {
            Ok(restore_target) => restore_target,
            Err(err) => {
                self.release_default_pool_resources();
                return Err(err);
            }
        };

        self.ensure_state_block(&device)?;
        let Some(state_block) = self.state_block.as_ref() else {
            return Err(runtime_error(
                "[SHADERS] Missing D3D state block before scene capture",
            ));
        };
        state_block.capture()?;

        let render_target = match self.scene_phase_render_target(&device, &restore_target, target) {
            Ok(Some(render_target)) => render_target,
            Ok(None) => return Ok(()),
            Err(err) => {
                let _ = device.set_render_target(0, &restore_target);
                return Err(err);
            }
        };

        let desc = match render_target.desc() {
            Ok(desc) => desc,
            Err(err) => {
                let _ = device.set_render_target(0, &restore_target);
                return Err(err);
            }
        };
        if desc.Width == 0 || desc.Height == 0 {
            let _ = device.set_render_target(0, &restore_target);
            return Ok(());
        }

        if let Err(err) = self.ensure_phase_color_copy(&device, &desc, phase) {
            let _ = device.set_render_target(0, &restore_target);
            return Err(err);
        }

        let draw_result = self.draw_passes(&device, &render_target, &desc, phase);
        let restore_result = if let Some(state_block) = self.state_block.as_ref() {
            state_block.apply()
        } else {
            Err(runtime_error(
                "[SHADERS] Missing D3D state block before scene restore",
            ))
        };
        let restore_render_target_result = device.set_render_target(0, &restore_target);

        restore_result?;
        restore_render_target_result?;
        draw_result?;

        self.applied_phases.mark_applied(phase);
        if self.scene_apply_logs < 8 {
            log::debug!(
                "[SHADERS] Applied '{}' screen-space shaders at FNV scene boundary",
                phase.label()
            );
            self.scene_apply_logs += 1;
        }
        Ok(())
    }

    fn scene_phase_render_target(
        &mut self,
        device: &Device9Ref<'_>,
        current_target: &Surface9,
        target: ScenePhaseTarget,
    ) -> Direct3DResult<Option<Surface9>> {
        match target {
            ScenePhaseTarget::CurrentRenderTarget => Ok(Some(current_target.clone())),
            ScenePhaseTarget::RenderedTextureSource(rendered_texture) => {
                let Some(surface) = backend::rendered_texture_color_surface(
                    self.settings.depth_provider,
                    rendered_texture,
                ) else {
                    self.log_scene_target_skip(
                        "[SHADERS] Scene-pre source rendered texture has no readable color surface",
                    );
                    return Ok(None);
                };

                let desc = unsafe { Surface9::raw_desc(surface)? };
                if desc.Width == 0 || desc.Height == 0 {
                    self.log_scene_target_skip(
                        "[SHADERS] Scene-pre source rendered texture has an empty color surface",
                    );
                    return Ok(None);
                }

                unsafe { device.set_raw_render_target(0, surface)? };
                device.render_target(0).map(Some)
            }
        }
    }

    fn log_scene_target_skip(&mut self, message: &'static str) {
        if self.scene_target_logs < 8 {
            log::warn!("{message}");
            self.scene_target_logs += 1;
        }
    }

    unsafe fn capture_fnv_world_color(&mut self, device_ptr: *mut c_void) -> Direct3DResult<()> {
        if !self.fnv_scene_input_requirements().world_color {
            return Ok(());
        }

        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Ok(());
        };

        if self.device_ptr != device_ptr as usize {
            self.release_for_new_device();
            self.device_ptr = device_ptr as usize;
        }

        let render_target = match device.render_target(0) {
            Ok(render_target) => render_target,
            Err(err) => {
                self.release_default_pool_resources();
                return Err(err);
            }
        };
        let desc = render_target.desc()?;
        if desc.Width == 0 || desc.Height == 0 {
            return Ok(());
        }

        self.ensure_world_color_copy(&device, &desc)?;
        let Some(copy) = self.world_color_copy.as_ref() else {
            return Ok(());
        };

        device.stretch_rect(&render_target, None, &copy.surface, None, D3DTEXF_POINT)?;
        self.world_color_captured_this_frame = true;
        self.world_color_source_target = render_target.as_raw() as usize;
        if self.world_color_capture_logs < 8 {
            log::debug!(
                "[FNV] Captured world color before first-person: {}x{}",
                desc.Width,
                desc.Height
            );
            self.world_color_capture_logs += 1;
        }

        Ok(())
    }

    fn scan_shaders_if_due(&mut self) {
        let now = Instant::now();
        if self.next_scan.is_some_and(|next| now < next) {
            return;
        }

        let interval_ms = self.settings.shader_scan_interval_ms.max(50);
        self.next_scan = Some(now + Duration::from_millis(interval_ms));

        // Preserve unsaved embedded menu edits before rebuilding dynamic source
        // options. LUT and shader catalogs are then committed in one scan tick.
        shaders::sync_embedded_effect_config(
            &self.sources,
            &mut self.settings.menu_config.embedded_effects,
        );
        let lut_scan = match luts::scan_luts(&self.color_luts) {
            Ok(scan) => Some(scan),
            Err(err) => {
                if self.scan_error_logs < 8 {
                    log::warn!("[LUT] Live LUT scan failed: {err:#}");
                    self.scan_error_logs += 1;
                }
                None
            }
        };

        match shaders::scan_screen_shaders(&self.sources) {
            Ok(scan) => {
                let old_count = self.sources.len();
                let lut_resources_changed =
                    lut_scan.as_ref().is_some_and(|scan| scan.resources_changed);
                if let Some(lut_scan) = lut_scan {
                    for warning in lut_scan.warnings {
                        if self.scan_error_logs >= 8 {
                            break;
                        }
                        log::warn!("[LUT] {warning}");
                        self.scan_error_logs += 1;
                    }
                    self.color_luts = lut_scan.catalog;
                }
                let (lut_names, lut_ids) = self.color_luts.choices();
                let sources = shaders::merge_embedded_sources_with_luts(
                    &self.settings.menu_config.embedded_effects,
                    &lut_names,
                    &lut_ids,
                    scan.sources,
                );
                let new_count = sources.len();
                if scan.shader_resources_changed {
                    self.compiled = None;
                }
                if lut_resources_changed {
                    self.blooming_hdr = None;
                    log::info!(
                        "[LUT] Live LUT catalog: {} file(s)",
                        self.color_luts.assets.len()
                    );
                }
                self.sources = sources;
                self.publish_fnv_scene_requirements();
                if old_count != new_count {
                    log::info!("[SHADERS] Live shader list: {new_count} shader(s)");
                }
            }
            Err(err) => {
                if self.scan_error_logs < 8 {
                    log::warn!("[SHADERS] Live shader scan failed: {err:#}");
                    self.scan_error_logs += 1;
                }
            }
        }
    }

    fn ensure_imgui(&mut self, device: &Device9Ref<'_>, hwnd_hint: *mut c_void) {
        let Some(hwnd) = valid_hwnd(hwnd_hint).or_else(|| valid_hwnd(get_active_window())) else {
            return;
        };

        if self.imgui.is_some() && self.imgui_hwnd == hwnd as usize {
            return;
        }

        self.imgui = None;
        self.imgui_hwnd = hwnd as usize;
        IMGUI_READY.store(false, Ordering::Release);

        if let Err(err) = crate::hooks::install_window_proc(hwnd) {
            self.log_imgui_error(format_args!("[IMGUI] WndProc hook failed: {err:#}"));
            return;
        }

        match unsafe { psycho_imgui::Dx9Context::new(hwnd, device.as_raw()) } {
            Ok(imgui) => {
                self.imgui = Some(imgui);
                self.imgui_needs_device_objects = false;
                IMGUI_READY.store(true, Ordering::Release);
                set_menu_diagnostics_active(MENU_OPEN.load(Ordering::Acquire));
                log::info!("[IMGUI] In-game shader menu initialized");
            }
            Err(err) => {
                self.log_imgui_error(format_args!("[IMGUI] Init failed: {err}"));
            }
        }
    }

    fn ensure_shaders(&mut self, device: &Device9Ref<'_>) {
        if self.compiled.is_some() {
            return;
        }

        let mut passes = Vec::with_capacity(self.sources.len());
        for (source_index, source) in self.sources.iter().enumerate() {
            if source.is_embedded_effect() {
                passes.push(CompiledPass {
                    source_index,
                    shader: None,
                });
                continue;
            }

            let Some(bytecode) = source.bytecode() else {
                continue;
            };

            match device.create_pixel_shader(bytecode) {
                Ok(shader) => {
                    log::info!("[SHADERS] Loaded screen pass '{}'", source.name);
                    passes.push(CompiledPass {
                        source_index,
                        shader: Some(shader),
                    });
                }
                Err(err) => {
                    log::warn!(
                        "[SHADERS] Failed to create pixel shader '{}': {err}",
                        source.name
                    );
                }
            }
        }

        if passes.is_empty() && self.has_enabled_shader() {
            log::warn!("[SHADERS] No valid screen-space pixel shaders were created");
        }

        self.compiled = Some(passes);
    }

    fn ensure_phase_color_copy(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
        phase: ShaderPhase,
    ) -> Direct3DResult<()> {
        let copy_slot = self.phase_color_copy_mut(phase);
        let needs_copy = copy_slot.as_ref().is_none_or(|copy| !copy.matches(desc));

        if needs_copy {
            *copy_slot = Some(BackbufferCopy::create(device, desc)?);
            log::info!(
                "[SHADERS] Color copy target: phase={}, size={}x{}, format=0x{:08X}",
                phase.label(),
                desc.Width,
                desc.Height,
                desc.Format.0
            );
        }

        Ok(())
    }

    fn phase_color_copy(&self, phase: ShaderPhase) -> Option<&BackbufferCopy> {
        match phase {
            ShaderPhase::ScenePreImageSpace => self.scene_pre_color_copy.as_ref(),
            ShaderPhase::ScenePostImageSpace => self.scene_post_color_copy.as_ref(),
            ShaderPhase::FinalImageSpace => self.final_color_copy.as_ref(),
        }
    }

    fn phase_color_copy_mut(&mut self, phase: ShaderPhase) -> &mut Option<BackbufferCopy> {
        match phase {
            ShaderPhase::ScenePreImageSpace => &mut self.scene_pre_color_copy,
            ShaderPhase::ScenePostImageSpace => &mut self.scene_post_color_copy,
            ShaderPhase::FinalImageSpace => &mut self.final_color_copy,
        }
    }

    fn ensure_world_color_copy(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let needs_copy = self
            .world_color_copy
            .as_ref()
            .is_none_or(|copy| !copy.matches(desc));

        if needs_copy {
            self.world_color_copy = Some(BackbufferCopy::create(device, desc)?);
            log::info!(
                "[SHADERS] FNV world color copy target: {}x{}",
                desc.Width,
                desc.Height
            );
        }

        Ok(())
    }

    fn ensure_state_block(&mut self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        if self.state_block.is_none() {
            self.state_block = Some(device.create_state_block(D3DSBT_ALL)?);
        }

        Ok(())
    }

    fn draw_passes(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        phase: ShaderPhase,
    ) -> Direct3DResult<()> {
        let enabled_count: u32 = self.compiled.as_ref().map_or(0, |passes| {
            passes
                .iter()
                .filter(|pass| {
                    let source = &self.sources[pass.source_index];
                    source.enabled
                        && source.phase() == phase
                        && !source
                            .embedded_effect_kind()
                            .is_some_and(EmbeddedEffectKind::owns_world_boundary)
                })
                .map(|pass| self.sources[pass.source_index].pass_count)
                .sum()
        });
        if enabled_count == 0 {
            return Ok(());
        }

        let needs_frame_inputs = self.phase_needs_frame_inputs(phase);
        let frame_inputs = if needs_frame_inputs {
            let depth = self.current_depth_frame();
            let camera = if depth.world_projection.camera.available {
                depth.world_projection.camera
            } else {
                backend::camera_frame(self.settings.depth_provider, desc)
            };
            let atmosphere_visibility = crate::fnv_world_pipeline::atmosphere_visibility();
            backend::FrameInputs {
                camera,
                depth,
                environment: backend::environment_frame(self.settings.depth_provider),
                sun: backend::sun_frame(self.settings.depth_provider),
                sky: backend::native_sky_frame(),
                atmosphere_visibility: atmosphere_visibility.unwrap_or(0.0),
                atmosphere_available: atmosphere_visibility.is_some(),
                first_person_rendered: backend::fnv_first_person_rendered(),
                material_state: backend::material_state_frame(),
            }
        } else {
            backend::FrameInputs::default()
        };
        if needs_frame_inputs {
            self.log_frame_input_state(&frame_inputs);
        }

        let Some(copy) = self.phase_color_copy(phase).cloned() else {
            return Ok(());
        };
        if self.compiled.is_none() {
            return Ok(());
        }

        self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;

        let pass_count = enabled_count as f32;
        let quad = fullscreen_quad(desc);
        let depth_available = if frame_inputs.depth.is_available() {
            1.0
        } else {
            0.0
        };
        let mut pass_index = 0u32;
        let mut ambient_occlusion_drawn = false;
        let mut final_color_drawn = false;

        let compiled_len = self.compiled.as_ref().map_or(0, Vec::len);
        for pass_position in 0..compiled_len {
            let Some(source_index) = self
                .compiled
                .as_ref()
                .and_then(|passes| passes.get(pass_position))
                .map(|pass| pass.source_index)
            else {
                continue;
            };
            let source = &self.sources[source_index];
            if !source.enabled || source.phase() != phase {
                continue;
            }

            if source
                .embedded_effect_kind()
                .is_some_and(EmbeddedEffectKind::owns_world_boundary)
            {
                // World-only effects are resolved from the RenderWorldSceneGraph
                // hook, not from vanilla image-space phases.
                continue;
            }

            if matches!(
                source.embedded_effect_kind(),
                Some(
                    EmbeddedEffectKind::FastAmbientOcclusion
                        | EmbeddedEffectKind::ContactAmbientOcclusion
                )
            ) {
                let source_pass_count = source.pass_count.max(1);
                if !ambient_occlusion_drawn {
                    let rebind_common_state = self.has_enabled_pass_after(phase, pass_position);
                    let fast_source = self.find_enabled_embedded_source(
                        EmbeddedEffectKind::FastAmbientOcclusion,
                        phase,
                    );
                    let contact_source = self.find_enabled_embedded_source(
                        EmbeddedEffectKind::ContactAmbientOcclusion,
                        phase,
                    );
                    self.draw_ambient_occlusion_pipeline(
                        device,
                        backbuffer,
                        desc,
                        &frame_inputs,
                        &copy,
                        fast_source.as_ref(),
                        contact_source.as_ref(),
                    )?;
                    if rebind_common_state {
                        self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
                    }
                    ambient_occlusion_drawn = true;
                }
                pass_index = pass_index.saturating_add(source_pass_count);
                continue;
            }

            if matches!(
                source.embedded_effect_kind(),
                Some(kind) if kind.is_final_color()
            ) {
                let source_pass_count = source.pass_count.max(1);
                if !final_color_drawn {
                    let rebind_common_state =
                        self.has_enabled_non_final_color_pass_after(phase, pass_position);
                    let bloom_source =
                        self.find_enabled_embedded_source(EmbeddedEffectKind::BloomingHdr, phase);
                    let color_grade_source =
                        self.find_enabled_embedded_source(EmbeddedEffectKind::ColorGrade, phase);
                    self.draw_final_color_pipeline(
                        device,
                        backbuffer,
                        desc,
                        &frame_inputs,
                        &copy,
                        bloom_source.as_ref(),
                        color_grade_source.as_ref(),
                    )?;
                    if rebind_common_state {
                        self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
                    }
                    final_color_drawn = true;
                }
                pass_index = pass_index.saturating_add(source_pass_count);
                continue;
            }

            if source.embedded_effect_kind() == Some(EmbeddedEffectKind::Sunshafts) {
                let rebind_common_state = self.has_enabled_pass_after(phase, pass_position);
                let source = source.clone();
                self.draw_sunshafts_pipeline(
                    device,
                    backbuffer,
                    desc,
                    &frame_inputs,
                    &copy,
                    &source,
                )?;
                if rebind_common_state {
                    self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
                }
                pass_index = pass_index.saturating_add(source.pass_count.max(1));
                continue;
            }

            if source.embedded_effect_kind() == Some(EmbeddedEffectKind::DepthOfField) {
                let rebind_common_state = self.has_enabled_pass_after(phase, pass_position);
                let source_pass_count = source.pass_count.max(1);
                self.draw_depth_of_field_pipeline(device, backbuffer, desc, &frame_inputs, &copy)?;
                if rebind_common_state {
                    self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
                }
                pass_index = pass_index.saturating_add(source_pass_count);
                continue;
            }

            if matches!(
                source.embedded_effect_kind(),
                Some(
                    EmbeddedEffectKind::FastFxaa
                        | EmbeddedEffectKind::Nfaa
                        | EmbeddedEffectKind::Axaa
                        | EmbeddedEffectKind::Dlaa
                        | EmbeddedEffectKind::Smaa
                )
            ) {
                let rebind_common_state = self.has_enabled_pass_after(phase, pass_position);
                let source = source.clone();
                self.draw_anti_aliasing_pipeline(device, backbuffer, desc, &copy, &source)?;
                if rebind_common_state {
                    self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
                }
                pass_index = pass_index.saturating_add(source.pass_count.max(1));
                continue;
            }

            let Some(shader) = self
                .compiled
                .as_ref()
                .and_then(|passes| passes.get(pass_position))
                .and_then(|pass| pass.shader.as_ref())
            else {
                continue;
            };

            for _ in 0..source.pass_count {
                device.clear_texture(0)?;
                device.stretch_rect(backbuffer, None, &copy.surface, None, D3DTEXF_POINT)?;
                device.set_texture(0, &copy.texture)?;
                device.set_pixel_shader(shader)?;
                device.set_pixel_shader_constant_f(
                    0,
                    &[
                        [
                            desc.Width as f32,
                            desc.Height as f32,
                            1.0 / desc.Width as f32,
                            1.0 / desc.Height as f32,
                        ],
                        [
                            self.frame_index as f32,
                            pass_index as f32,
                            pass_count,
                            depth_available,
                        ],
                        [
                            frame_inputs.camera.near_z,
                            frame_inputs.camera.far_z,
                            frame_inputs.camera.aspect_ratio,
                            frame_inputs.depth.provider_id(),
                        ],
                    ],
                )?;
                if !source.option_constants.is_empty() {
                    device.set_pixel_shader_constant_f(
                        FIRST_OPTION_REGISTER,
                        &source.option_constants,
                    )?;
                }
                device.set_pixel_shader_constant_f(
                    ENVIRONMENT_REGISTER,
                    &[[
                        frame_inputs.environment.fog_start,
                        frame_inputs.environment.fog_end,
                        frame_inputs.environment.fog_power,
                        frame_inputs.environment.fog_available_f32(),
                    ]],
                )?;
                device.set_pixel_shader_constant_f(
                    SUN_REGISTER,
                    &[[
                        frame_inputs.sun.screen_x,
                        frame_inputs.sun.screen_y,
                        frame_inputs.sun.available_f32(),
                        frame_inputs.sun.daylight,
                    ]],
                )?;
                bind_depth_contract_constants(device, &frame_inputs)?;

                log::trace!(
                    "[SHADERS] Drawing '{}' screen pass '{}'",
                    phase.label(),
                    source.name
                );
                unsafe {
                    device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad)?;
                }
                pass_index += 1;
            }
        }

        Ok(())
    }

    fn find_enabled_embedded_source(
        &self,
        kind: EmbeddedEffectKind,
        phase: ShaderPhase,
    ) -> Option<ScreenShaderSource> {
        self.sources
            .iter()
            .find(|source| {
                source.enabled
                    && source.embedded_effect_kind() == Some(kind)
                    && source.phase() == phase
            })
            .cloned()
    }

    fn draw_ambient_occlusion_pipeline(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
        current_color_copy: &BackbufferCopy,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
    ) -> Direct3DResult<()> {
        if self.ambient_occlusion.is_none() {
            self.ambient_occlusion =
                Some(ambient_occlusion::AmbientOcclusionEffect::create(device)?);
            log::info!("[AO] Engine-side pipeline initialized");
        }

        let Some(effect) = self.ambient_occlusion.as_mut() else {
            return Ok(());
        };

        device.clear_texture(0)?;
        device.stretch_rect(
            backbuffer,
            None,
            &current_color_copy.surface,
            None,
            D3DTEXF_POINT,
        )?;
        effect.draw(
            device,
            backbuffer,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            &current_color_copy.texture,
            self.frame_index,
        )
    }

    fn draw_anti_aliasing_pipeline(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        current_color_copy: &BackbufferCopy,
        source: &ScreenShaderSource,
    ) -> Direct3DResult<()> {
        if self.anti_aliasing.is_none() {
            self.anti_aliasing = Some(anti_aliasing::AntiAliasingEffect::create());
            log::info!("[AA] Embedded spatial AA pipelines initialized");
        }

        let Some(effect) = self.anti_aliasing.as_mut() else {
            return Ok(());
        };
        if !effect.prepare(device, source)? {
            return Ok(());
        }
        device.clear_texture(0)?;
        device.stretch_rect(
            backbuffer,
            None,
            &current_color_copy.surface,
            None,
            D3DTEXF_POINT,
        )?;
        effect.draw(
            device,
            backbuffer,
            desc,
            source,
            &current_color_copy.texture,
        )
    }

    fn draw_final_color_pipeline(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
        current_color_copy: &BackbufferCopy,
        bloom_source: Option<&ScreenShaderSource>,
        color_grade_source: Option<&ScreenShaderSource>,
    ) -> Direct3DResult<()> {
        let selected_lut_index = color_grade_source.and_then(|source| {
            source.options.iter().find_map(|option| {
                if option.key == "lut_file" {
                    match option.value {
                        ShaderOptionValue::Integer(index) => Some(index),
                        _ => None,
                    }
                } else {
                    None
                }
            })
        });
        let selected_lut = selected_lut_index.and_then(|index| self.color_luts.selected(index));
        let work = blooming_hdr::FinalColorWorkPlan::from_sources_with_lut_available(
            bloom_source,
            color_grade_source,
            selected_lut.is_some(),
        );
        if !work.has_work() {
            return Ok(());
        }
        if self.blooming_hdr.is_none() {
            let Some(shaders) = self.final_color_shaders.as_ref() else {
                return Ok(());
            };
            self.blooming_hdr = Some(blooming_hdr::BloomingHdrEffect::create(device, shaders)?);
            log::info!("[FINAL_COLOR] Bloom/color-grade pipeline initialized");
        }

        let Some(effect) = self.blooming_hdr.as_mut() else {
            return Ok(());
        };

        device.clear_texture(0)?;
        device.stretch_rect(
            backbuffer,
            None,
            &current_color_copy.surface,
            None,
            D3DTEXF_POINT,
        )?;
        effect.draw(
            device,
            backbuffer,
            desc,
            frame_inputs,
            bloom_source,
            color_grade_source,
            selected_lut,
            &current_color_copy.surface,
            &current_color_copy.texture,
            self.frame_index,
        )
    }

    fn draw_sunshafts_pipeline(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
        current_color_copy: &BackbufferCopy,
        source: &ScreenShaderSource,
    ) -> Direct3DResult<()> {
        if self.sunshafts.is_none() {
            self.sunshafts = Some(sunshafts::SunshaftsEffect::create(device)?);
            log::info!("[SUNSHAFTS] Engine-side pipeline initialized");
        }

        let Some(effect) = self.sunshafts.as_mut() else {
            return Ok(());
        };

        device.clear_texture(0)?;
        device.stretch_rect(
            backbuffer,
            None,
            &current_color_copy.surface,
            None,
            D3DTEXF_POINT,
        )?;
        effect.draw(
            device,
            backbuffer,
            desc,
            frame_inputs,
            source,
            &current_color_copy.texture,
            self.frame_index,
        )
    }

    fn draw_depth_of_field_pipeline(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
        current_color_copy: &BackbufferCopy,
    ) -> Direct3DResult<()> {
        if self.depth_of_field_creation_failed {
            return Ok(());
        }
        if self.depth_of_field.is_none() {
            match depth_of_field::DepthOfFieldEffect::create(device) {
                Ok(Some(effect)) => {
                    self.depth_of_field = Some(effect);
                    log::info!("[DOF] Engine-side pipeline initialized");
                }
                Ok(None) => return Ok(()),
                Err(err) => {
                    self.depth_of_field_creation_failed = true;
                    return Err(err);
                }
            }
        }

        let config = self.settings.menu_config.embedded_effects.depth_of_field;
        let frame_seconds = self.present_timing.frame_seconds();
        let native_dof_active = self.native_dof_active_this_frame;
        let frame_index = self.frame_index;
        let Some(effect) = self.depth_of_field.as_mut() else {
            return Ok(());
        };

        device.clear_texture(0)?;
        device.stretch_rect(
            backbuffer,
            None,
            &current_color_copy.surface,
            None,
            D3DTEXF_POINT,
        )?;
        effect.draw(
            device,
            backbuffer,
            desc,
            frame_inputs,
            config,
            &current_color_copy.texture,
            frame_index,
            frame_seconds,
            native_dof_active,
        )
    }

    fn log_frame_input_state(&mut self, frame_inputs: &backend::FrameInputs) {
        let depth_available = frame_inputs.depth.is_available();
        let fog_available = frame_inputs.environment.fog_available;
        let sun_available = frame_inputs.sun.available;
        if self.last_depth_available == Some(depth_available)
            && self.last_fog_available == Some(fog_available)
            && self.last_sun_available == Some(sun_available)
        {
            return;
        }

        self.last_depth_available = Some(depth_available);
        self.last_fog_available = Some(fog_available);
        self.last_sun_available = Some(sun_available);
        log::debug!(
            "[SHADERS] Frame inputs: depth={} (provider={}, epoch={}, near={:.3}, far={:.3}), fog={} (rgb={:.4},{:.4},{:.4}, start={:.3}, end={:.3}, power={:.3}), sun={} (uv={:.3},{:.3}, daylight={:.3})",
            if depth_available {
                "available"
            } else {
                "missing"
            },
            frame_inputs.depth.provider_id(),
            frame_inputs.depth.capture_epoch,
            frame_inputs.camera.near_z,
            frame_inputs.camera.far_z,
            if fog_available {
                "available"
            } else {
                "missing"
            },
            frame_inputs.environment.fog_color[0],
            frame_inputs.environment.fog_color[1],
            frame_inputs.environment.fog_color[2],
            frame_inputs.environment.fog_start,
            frame_inputs.environment.fog_end,
            frame_inputs.environment.fog_power,
            if sun_available {
                "available"
            } else {
                "missing"
            },
            frame_inputs.sun.screen_x,
            frame_inputs.sun.screen_y,
            frame_inputs.sun.daylight
        );
    }

    fn current_depth_frame(&self) -> DepthFrame {
        let provider = self.settings.depth_provider;
        backend::depth_frame(provider)
    }

    fn draw_menu(&mut self) -> Direct3DResult<()> {
        let Some(imgui) = self.imgui.as_mut() else {
            return Ok(());
        };

        set_menu_diagnostics_active(true);
        self.frame_pacing.begin_session(menu_diagnostics_session());

        if self.imgui_needs_device_objects && imgui.create_device_objects() {
            self.imgui_needs_device_objects = false;
        }

        let menu_frame = {
            let frame_pacing = self.frame_pacing.snapshot();
            let feature_status = EngineFeatureStatus {
                pbr: pbr::runtime_status(),
                sky: sky::runtime_status(),
            };
            let mut ui = imgui.new_frame(true);
            draw_shader_menu(
                &mut ui,
                &mut self.settings.menu_config,
                &mut self.sources,
                &mut self.selected_menu_item,
                &frame_pacing,
                feature_status,
                MenuPersistenceView {
                    dirty: self.menu_config_dirty,
                    error: self.menu_config_error.as_deref(),
                    notice: self.menu_config_notice.as_deref(),
                },
            )
        };

        imgui.render();
        if menu_frame.changed {
            self.apply_menu_config_change();
            self.menu_config_dirty = true;
            self.menu_config_error = None;
            self.menu_config_notice = None;
        }
        match menu_frame.action {
            MenuAction::None => {}
            MenuAction::Save => self.save_menu_session(),
            MenuAction::Reload => self.reload_menu_session(),
        }
        Ok(())
    }

    fn apply_menu_config_change(&mut self) {
        self.settings.depth_provider = self.settings.menu_config.depth_provider.into();
        self.settings.menu_toggle_key =
            sanitize_menu_toggle_key(self.settings.menu_config.menu_toggle_key);
        self.settings.menu_config.menu_toggle_key = self.settings.menu_toggle_key;
        self.settings.shader_scan_interval_ms = self.settings.menu_config.shader_scan_interval_ms;
        MENU_TOGGLE_KEY.store(self.settings.menu_toggle_key, Ordering::Release);
        update_native_dof_query_needed(&self.settings.menu_config);
        crate::fnv_world_pipeline::publish_config(self.settings.menu_config);
        self.publish_fnv_scene_requirements();
        let master_enabled = self.settings.menu_config.screen_space_shaders;
        pbr::configure_runtime_options(
            pbr::NativePbrSettings::from(self.settings.menu_config.native_pbr)
                .with_master_enabled(master_enabled),
        );
        sky::configure_runtime_options(
            sky::NativeSkySettings::from(self.settings.menu_config.native_sky)
                .with_master_enabled(master_enabled),
        );
    }

    fn save_menu_session(&mut self) {
        shaders::sync_embedded_effect_config(
            &self.sources,
            &mut self.settings.menu_config.embedded_effects,
        );
        let result = shaders::save_external_shader_configs(&mut self.sources)
            .and_then(|()| crate::config::save_menu_config(&self.settings.menu_config));
        match result {
            Ok(()) => {
                self.menu_config_dirty = false;
                self.menu_config_error = None;
                self.menu_config_notice = Some("Configuration saved to disk".to_owned());
            }
            Err(err) => {
                self.menu_config_error = Some(format!("{err:#}"));
                self.menu_config_notice = None;
            }
        }
    }

    fn reload_menu_session(&mut self) {
        let result = (|| {
            let menu_config = crate::config::load_menu_config_from_disk()?;
            let mut reloaded_sources = self.sources.clone();
            shaders::reload_external_shader_configs(&mut reloaded_sources)?;
            let external_sources = reloaded_sources
                .into_iter()
                .filter(ScreenShaderSource::is_external_file)
                .collect();

            self.settings.menu_config = menu_config;
            let (lut_names, lut_ids) = self.color_luts.choices();
            self.sources = shaders::merge_embedded_sources_with_luts(
                &self.settings.menu_config.embedded_effects,
                &lut_names,
                &lut_ids,
                external_sources,
            );
            self.compiled = None;
            self.next_scan = None;
            self.apply_menu_config_change();
            Ok::<(), anyhow::Error>(())
        })();

        match result {
            Ok(()) => {
                self.menu_config_dirty = false;
                self.menu_config_error = None;
                self.menu_config_notice = Some("Configuration reloaded from disk".to_owned());
            }
            Err(err) => {
                self.menu_config_error = Some(format!("{err:#}"));
                self.menu_config_notice = None;
            }
        }
    }

    fn bind_common_state(
        &self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
        current_color_copy: &BackbufferCopy,
    ) -> Direct3DResult<()> {
        let viewport = D3DVIEWPORT9 {
            X: 0,
            Y: 0,
            Width: desc.Width,
            Height: desc.Height,
            MinZ: 0.0,
            MaxZ: 1.0,
        };

        device.set_render_target(0, backbuffer)?;
        device.set_viewport(&viewport)?;
        device.clear_vertex_shader()?;
        device.set_fvf(ScreenVertex::FVF)?;
        device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
        device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
        device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
        device.set_render_state(D3DRS_ZENABLE, 0)?;
        device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
        device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
        for sampler in [0, 1, 2, 3] {
            device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
            device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
            device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32)?;
            device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32)?;
            device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
        }
        device.set_sampler_state(1, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(1, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(2, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(2, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(3, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(3, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
        if let Some(depth_texture) = frame_inputs.depth.texture {
            unsafe {
                device.set_raw_base_texture(1, depth_texture.as_ptr())?;
            }
        } else {
            device.clear_texture(1)?;
        }
        if let Some(depth_texture) = frame_inputs.depth.first_person_texture {
            unsafe {
                device.set_raw_base_texture(2, depth_texture.as_ptr())?;
            }
        } else {
            device.clear_texture(2)?;
        }
        if self.world_color_captured_this_frame {
            if let Some(world_color) = self.world_color_copy.as_ref() {
                device.set_texture(3, &world_color.texture)?;
            } else {
                device.set_texture(3, &current_color_copy.texture)?;
            }
        } else {
            device.set_texture(3, &current_color_copy.texture)?;
        }
        device.set_texture_stage_state(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1.0 as u32)?;
        device.set_texture_stage_state(0, D3DTSS_COLORARG1, D3DTA_TEXTURE)?;
        device.set_texture_stage_state(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1.0 as u32)?;
        device.set_texture_stage_state(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE)?;
        bind_depth_contract_constants(device, frame_inputs)?;

        Ok(())
    }

    fn has_enabled_shader(&self) -> bool {
        if !self.settings.menu_config.screen_space_shaders {
            return false;
        }

        self.sources.iter().any(|source| {
            source.enabled && (source.is_embedded_effect() || source.bytecode.is_some())
        })
    }

    fn has_enabled_shader_for_phase(&self, phase: ShaderPhase) -> bool {
        if !self.settings.menu_config.screen_space_shaders {
            return false;
        }

        self.sources.iter().any(|source| {
            source.enabled
                && source.phase() == phase
                && !source
                    .embedded_effect_kind()
                    .is_some_and(EmbeddedEffectKind::owns_world_boundary)
                && (source.is_embedded_effect() || source.bytecode.is_some())
        })
    }

    fn fnv_scene_input_requirements(&self) -> SceneInputRequirements {
        if self.settings.depth_provider != DepthProvider::FalloutNewVegas
            || !self.settings.menu_config.screen_space_shaders
        {
            return SceneInputRequirements::default();
        }

        self.sources
            .iter()
            .filter(|source| {
                source.enabled
                    && !source
                        .embedded_effect_kind()
                        .is_some_and(EmbeddedEffectKind::owns_world_boundary)
                    && (source.is_embedded_effect() || source.bytecode.is_some())
            })
            .fold(SceneInputRequirements::default(), |requirements, source| {
                let source_requirements = SceneInputRequirements::for_source(source);
                requirements.union(source_requirements)
            })
    }

    fn publish_fnv_scene_requirements(&self) {
        let requirements = self.fnv_scene_input_requirements();
        let mut bits = 0;
        if requirements.world_depth {
            bits |= FNV_REQUIRE_WORLD_DEPTH;
        }
        if requirements.first_person_depth {
            bits |= FNV_REQUIRE_FIRST_PERSON_DEPTH;
        }
        if requirements.world_color {
            bits |= FNV_REQUIRE_WORLD_COLOR;
        }
        FNV_SCENE_REQUIREMENTS.store(bits, Ordering::Release);
    }

    fn has_enabled_pass_after(&self, phase: ShaderPhase, pass_position: usize) -> bool {
        self.has_enabled_pass_after_matching(phase, pass_position, |_| true)
    }

    fn has_enabled_non_final_color_pass_after(
        &self,
        phase: ShaderPhase,
        pass_position: usize,
    ) -> bool {
        self.has_enabled_pass_after_matching(phase, pass_position, |source| {
            !source
                .embedded_effect_kind()
                .is_some_and(EmbeddedEffectKind::is_final_color)
        })
    }

    fn has_enabled_pass_after_matching(
        &self,
        phase: ShaderPhase,
        pass_position: usize,
        include: impl Fn(&ScreenShaderSource) -> bool,
    ) -> bool {
        self.compiled.as_ref().is_some_and(|passes| {
            passes.iter().skip(pass_position + 1).any(|pass| {
                let source = &self.sources[pass.source_index];
                source.enabled
                    && source.phase() == phase
                    && !source
                        .embedded_effect_kind()
                        .is_some_and(EmbeddedEffectKind::owns_world_boundary)
                    && include(source)
                    && (source.is_embedded_effect() || pass.shader.is_some())
            })
        })
    }

    fn phase_needs_frame_inputs(&self, phase: ShaderPhase) -> bool {
        self.sources.iter().any(|source| {
            source.enabled
                && source.phase() == phase
                && match source.embedded_effect_kind() {
                    None => source.bytecode.is_some(),
                    Some(kind) if kind.owns_world_boundary() => false,
                    Some(
                        EmbeddedEffectKind::FastFxaa
                        | EmbeddedEffectKind::Nfaa
                        | EmbeddedEffectKind::Axaa
                        | EmbeddedEffectKind::Dlaa
                        | EmbeddedEffectKind::Smaa,
                    ) => false,
                    Some(_) => true,
                }
        })
    }

    fn has_drawable_shader(&self) -> bool {
        if !self.settings.menu_config.screen_space_shaders {
            return false;
        }

        self.compiled.as_ref().is_some_and(|passes| {
            passes.iter().any(|pass| {
                let source = &self.sources[pass.source_index];
                source.enabled && (source.is_embedded_effect() || pass.shader.is_some())
            })
        })
    }

    fn has_drawable_shader_for_phase(&self, phase: ShaderPhase) -> bool {
        if !self.settings.menu_config.screen_space_shaders {
            return false;
        }

        self.compiled.as_ref().is_some_and(|passes| {
            passes.iter().any(|pass| {
                let source = &self.sources[pass.source_index];
                source.enabled
                    && source.phase() == phase
                    && !source
                        .embedded_effect_kind()
                        .is_some_and(EmbeddedEffectKind::owns_world_boundary)
                    && (source.is_embedded_effect() || pass.shader.is_some())
            })
        })
    }

    fn release_if_device(&mut self, device_ptr: *mut c_void) {
        if self.device_ptr == 0 || self.device_ptr == device_ptr as usize {
            self.release_device_resources();
        }
    }

    fn finish_present_frame(
        &mut self,
        render_epoch: u32,
        present_started_at: Option<Instant>,
        diagnostics_session: Option<u32>,
    ) {
        let diagnostics_active = diagnostics_session.is_some();
        let depth_of_field_active = self.settings.menu_config.screen_space_shaders
            && self
                .settings
                .menu_config
                .embedded_effects
                .depth_of_field
                .enabled;
        if !diagnostics_active && !depth_of_field_active {
            self.present_timing.pause();
            self.frame_pacing.pause();
            return;
        }

        if let Some(session) = diagnostics_session {
            self.frame_pacing.begin_session(session);
        }
        let Some(now) = present_started_at else {
            self.present_timing.invalidate_origin();
            if diagnostics_active {
                self.frame_pacing.reject_current_present();
            } else {
                self.frame_pacing.invalidate_origin();
            }
            return;
        };

        self.present_timing
            .record_frame_at(now, render_epoch, depth_of_field_active);
        self.frame_pacing.record_frame_at(
            now,
            render_epoch,
            diagnostics_active,
            self.settings.menu_config.frame_pacing_update_interval_ms,
        );
    }

    fn release_for_new_device(&mut self) {
        set_menu_diagnostics_active(false);
        self.release_device_resources();
        self.imgui = None;
        self.imgui_hwnd = 0;
        IMGUI_READY.store(false, Ordering::Release);
        self.device_ptr = 0;
    }

    fn release_device_resources(&mut self) {
        set_menu_diagnostics_active(false);
        self.compiled = None;
        self.ambient_occlusion = None;
        self.anti_aliasing = None;
        self.blooming_hdr = None;
        self.sunshafts = None;
        self.depth_of_field = None;
        self.depth_of_field_creation_failed = false;
        self.release_default_pool_resources();
        if let Some(imgui) = self.imgui.as_mut() {
            imgui.invalidate_device_objects();
            self.imgui_needs_device_objects = true;
        }
    }

    fn release_default_pool_resources(&mut self) {
        self.final_color_copy = None;
        self.scene_pre_color_copy = None;
        self.scene_post_color_copy = None;
        self.world_color_copy = None;
        self.world_color_source_target = 0;
        self.ambient_occlusion = None;
        self.anti_aliasing = None;
        self.blooming_hdr = None;
        self.sunshafts = None;
        self.depth_of_field = None;
        self.depth_of_field_creation_failed = false;
        self.world_color_captured_this_frame = false;
        self.state_block = None;
    }

    fn log_frame_error(&mut self, err: &WindowsError) {
        if self.error_logs < 8 {
            log::warn!("[SHADERS] Screen-space pass skipped: {err}");
            self.error_logs += 1;
        }
    }

    fn log_imgui_error(&mut self, message: std::fmt::Arguments<'_>) {
        if self.imgui_error_logs < 8 {
            log::warn!("{message}");
            self.imgui_error_logs += 1;
        }
    }

    fn log_world_color_error(&mut self, err: &WindowsError) {
        if self.error_logs < 8 {
            log::warn!("[FNV] World color capture skipped: {err}");
            self.error_logs += 1;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SceneInputRequirements {
    world_depth: bool,
    first_person_depth: bool,
    world_color: bool,
}

impl SceneInputRequirements {
    const fn all() -> Self {
        Self {
            world_depth: true,
            first_person_depth: true,
            world_color: true,
        }
    }

    const fn for_embedded(kind: EmbeddedEffectKind) -> Self {
        match kind {
            EmbeddedEffectKind::FastAmbientOcclusion
            | EmbeddedEffectKind::ContactAmbientOcclusion
            | EmbeddedEffectKind::Sunshafts
            | EmbeddedEffectKind::DepthOfField => Self {
                world_depth: true,
                first_person_depth: true,
                world_color: false,
            },
            EmbeddedEffectKind::BloomingHdr => Self {
                world_depth: false,
                first_person_depth: true,
                world_color: false,
            },
            EmbeddedEffectKind::ColorGrade => Self {
                world_depth: false,
                first_person_depth: false,
                world_color: false,
            },
            EmbeddedEffectKind::TemporalAa => Self {
                world_depth: true,
                first_person_depth: false,
                world_color: false,
            },
            EmbeddedEffectKind::VolumetricFog | EmbeddedEffectKind::VolumetricLighting => Self {
                world_depth: true,
                first_person_depth: false,
                world_color: false,
            },
            EmbeddedEffectKind::FastFxaa
            | EmbeddedEffectKind::Nfaa
            | EmbeddedEffectKind::Axaa
            | EmbeddedEffectKind::Dlaa
            | EmbeddedEffectKind::Smaa => Self {
                world_depth: false,
                first_person_depth: false,
                world_color: false,
            },
        }
    }

    fn for_source(source: &ScreenShaderSource) -> Self {
        let Some(kind) = source.embedded_effect_kind() else {
            return Self::all();
        };
        let mut requirements = Self::for_embedded(kind);
        if kind.is_atmosphere() {
            let settings = if kind == EmbeddedEffectKind::VolumetricFog {
                atmosphere::AtmosphereSettings::from_sources(Some(source), None)
            } else {
                atmosphere::AtmosphereSettings::from_sources(None, Some(source))
            };
            requirements.world_depth = settings.requires_depth();
            requirements.world_color = settings.requires_world_color();
        }
        requirements
    }

    const fn union(self, other: Self) -> Self {
        Self {
            world_depth: self.world_depth || other.world_depth,
            first_person_depth: self.first_person_depth || other.first_person_depth,
            world_color: self.world_color || other.world_color,
        }
    }
}

#[cfg(test)]
mod scene_input_requirement_tests {
    use super::{CompiledPass, EmbeddedEffectKind, SceneInputRequirements, ScreenShaderRuntime};
    use crate::{config::EmbeddedEffectsConfig, shaders};

    #[test]
    fn spatial_aa_requires_no_fnv_scene_inputs() {
        for kind in [
            EmbeddedEffectKind::FastFxaa,
            EmbeddedEffectKind::Nfaa,
            EmbeddedEffectKind::Axaa,
            EmbeddedEffectKind::Dlaa,
            EmbeddedEffectKind::Smaa,
        ] {
            assert_eq!(
                SceneInputRequirements::for_embedded(kind),
                SceneInputRequirements::default()
            );
        }
    }

    #[test]
    fn lazy_render_epoch_reconciliation_clears_stale_frame_state() {
        let mut runtime = ScreenShaderRuntime::default();
        assert!(runtime.final_color_shaders.is_some());
        assert!(runtime.color_luts.assets.is_empty());
        runtime.render_epoch = 4;
        runtime.frame_index = 9;
        runtime.world_color_captured_this_frame = true;
        runtime.world_color_source_target = 0x1234;
        runtime.native_dof_active_this_frame = true;

        runtime.begin_render_epoch(4);
        assert!(runtime.world_color_captured_this_frame);
        assert_eq!(runtime.frame_index, 9);

        runtime.begin_render_epoch(5);
        assert!(!runtime.world_color_captured_this_frame);
        assert_eq!(runtime.world_color_source_target, 0);
        assert!(!runtime.native_dof_active_this_frame);
        assert_eq!(runtime.frame_index, 10);

        runtime.release_device_resources();
        assert!(runtime.final_color_shaders.is_some());
        assert!(runtime.color_luts.assets.is_empty());
        assert!(runtime.blooming_hdr.is_none());
    }

    #[test]
    fn temporal_aa_requires_only_world_depth() {
        assert_eq!(
            SceneInputRequirements::for_embedded(EmbeddedEffectKind::TemporalAa),
            SceneInputRequirements {
                world_depth: true,
                first_person_depth: false,
                world_color: false,
            }
        );
    }

    #[test]
    fn atmosphere_requires_world_depth_and_production_fog_requires_color() {
        for kind in [
            EmbeddedEffectKind::VolumetricFog,
            EmbeddedEffectKind::VolumetricLighting,
        ] {
            assert_eq!(
                SceneInputRequirements::for_embedded(kind),
                SceneInputRequirements {
                    world_depth: true,
                    first_person_depth: false,
                    world_color: false,
                }
            );
        }

        let mut config = EmbeddedEffectsConfig::default();
        config.volumetric_fog.enabled = true;
        config.volumetric_fog.debug_view = 0;
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricFog))
            .expect("volumetric fog source");
        assert_eq!(
            SceneInputRequirements::for_source(source),
            SceneInputRequirements {
                world_depth: true,
                first_person_depth: false,
                world_color: true,
            }
        );
    }

    #[test]
    fn embedded_scene_effect_requirements_are_specialized() {
        for kind in [
            EmbeddedEffectKind::FastAmbientOcclusion,
            EmbeddedEffectKind::ContactAmbientOcclusion,
            EmbeddedEffectKind::Sunshafts,
            EmbeddedEffectKind::DepthOfField,
        ] {
            assert_eq!(
                SceneInputRequirements::for_embedded(kind),
                SceneInputRequirements {
                    world_depth: true,
                    first_person_depth: true,
                    world_color: false,
                }
            );
        }
        assert_eq!(
            SceneInputRequirements::for_embedded(EmbeddedEffectKind::BloomingHdr),
            SceneInputRequirements {
                world_depth: false,
                first_person_depth: true,
                world_color: false,
            }
        );
        assert_eq!(
            SceneInputRequirements::for_embedded(EmbeddedEffectKind::ColorGrade),
            SceneInputRequirements::default()
        );
    }

    #[test]
    fn grade_collects_native_environment_without_requesting_scene_captures() {
        let mut config = EmbeddedEffectsConfig::default();
        config.blooming_hdr.enabled = false;
        config.color_grade.enabled = true;
        let mut runtime = ScreenShaderRuntime::default();
        runtime.sources = shaders::merge_embedded_sources(&config, Vec::new());
        assert!(runtime.phase_needs_frame_inputs(crate::shaders::ShaderPhase::FinalImageSpace));

        config.color_grade.enabled = false;
        runtime.sources = shaders::merge_embedded_sources(&config, Vec::new());
        assert!(!runtime.phase_needs_frame_inputs(crate::shaders::ShaderPhase::FinalImageSpace));
    }

    #[test]
    fn fused_color_sources_do_not_trigger_a_redundant_state_rebind() {
        let mut config = EmbeddedEffectsConfig::default();
        config.blooming_hdr.enabled = true;
        config.color_grade.enabled = true;
        config.fast_fxaa.enabled = false;
        config.nfaa.enabled = false;
        config.axaa.enabled = false;
        config.dlaa.enabled = false;
        config.smaa.enabled = false;

        let mut runtime = ScreenShaderRuntime::default();
        runtime.sources = shaders::merge_embedded_sources(&config, Vec::new());
        runtime.compiled = Some(
            (0..runtime.sources.len())
                .map(|source_index| CompiledPass {
                    source_index,
                    shader: None,
                })
                .collect(),
        );
        let bloom_position = runtime
            .sources
            .iter()
            .position(|source| {
                source.embedded_effect_kind() == Some(EmbeddedEffectKind::BloomingHdr)
            })
            .expect("Bloom position");
        assert!(!runtime.has_enabled_non_final_color_pass_after(
            crate::shaders::ShaderPhase::FinalImageSpace,
            bloom_position,
        ));

        config.fast_fxaa.enabled = true;
        runtime.sources = shaders::merge_embedded_sources(&config, Vec::new());
        assert!(runtime.has_enabled_non_final_color_pass_after(
            crate::shaders::ShaderPhase::FinalImageSpace,
            bloom_position,
        ));
    }

    #[test]
    fn external_shader_requirements_preserve_all_inputs() {
        assert_eq!(
            SceneInputRequirements::all(),
            SceneInputRequirements {
                world_depth: true,
                first_person_depth: true,
                world_color: true,
            }
        );
    }
}

fn update_native_dof_query_needed(config: &GraphicsMenuConfig) {
    let dof = config.embedded_effects.depth_of_field;
    let dof_active = config.screen_space_shaders && dof.enabled;
    NATIVE_DOF_QUERY_NEEDED.store(dof_active && dof.respect_vanilla_dof, Ordering::Release);
    PRESENT_FRAME_TIMING_NEEDED.store(dof_active, Ordering::Release);
}

struct CompiledPass {
    source_index: usize,
    shader: Option<PixelShader9>,
}

#[derive(Clone, Copy)]
enum ScenePhaseTarget {
    CurrentRenderTarget,
    RenderedTextureSource(*mut c_void),
}

#[derive(Default)]
struct AppliedShaderPhases {
    scene_pre_image_space: bool,
    scene_post_image_space: bool,
    final_image_space: bool,
}

impl AppliedShaderPhases {
    fn is_applied(&self, phase: ShaderPhase) -> bool {
        match phase {
            ShaderPhase::ScenePreImageSpace => self.scene_pre_image_space,
            ShaderPhase::ScenePostImageSpace => self.scene_post_image_space,
            ShaderPhase::FinalImageSpace => self.final_image_space,
        }
    }

    fn mark_applied(&mut self, phase: ShaderPhase) {
        match phase {
            ShaderPhase::ScenePreImageSpace => self.scene_pre_image_space = true,
            ShaderPhase::ScenePostImageSpace => self.scene_post_image_space = true,
            ShaderPhase::FinalImageSpace => self.final_image_space = true,
        }
    }
}

#[derive(Clone)]
struct BackbufferCopy {
    width: u32,
    height: u32,
    format: D3DFORMAT,
    texture: Texture9,
    surface: Surface9,
}

impl BackbufferCopy {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let texture = device.create_render_target_texture(desc.Width, desc.Height, desc.Format)?;
        let surface = texture.surface_level(0)?;

        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            format: desc.Format,
            texture,
            surface,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height && self.format == desc.Format
    }
}

const FRAME_PACING_HISTORY: usize = 2_048;
const FRAME_PACING_CHART_POINTS: usize = 100;
const FRAME_PACING_WINDOW_MS: f32 = 10_000.0;
const FRAME_PACING_CHART_INTERVAL_MS: f32 = 100.0;
const FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS: u32 = 500;
const FRAME_PACING_EMA_TIME_CONSTANT_MS: f32 = 1_000.0;
const FRAME_PACING_LIVE_SAMPLE_MAX_MS: f32 = 100.0;
const FRAME_PACING_CHART_MAX_MS: f32 = 50.0;
const FRAME_PACING_CHART_PRESERVED_HITCH_MS: f32 = 100.0;
const FRAME_PACING_SPIKE_CHART_MAX_MS: f32 = 50.0;
const FRAME_PACING_HISTOGRAM_BINS: usize = 4_096;
const FRAME_PACING_HISTOGRAM_BIN_MS: f32 = 0.125;
const FRAME_PACING_SPIKE_MEMORY: usize = 64;
const FRAME_PACING_SPIKE_WARMUP_SAMPLES: u32 = 30;
const FRAME_PACING_SPIKE_MIN_DELTA_MS: f32 = 2.0;
const FRAME_PACING_SPIKE_RELATIVE_DELTA: f32 = 0.25;
const FRAME_PACING_SPIKE_NOISE_MULTIPLIER: f32 = 6.0;
const FRAME_PACING_SPIKE_BASELINE_TIME_MS: f32 = 2_000.0;
const FRAME_BUDGET_60_MS: f32 = 1_000.0 / 60.0;
const FRAME_BUDGET_30_MS: f32 = 1_000.0 / 30.0;

fn consecutive_render_epochs(previous: u32, current: u32) -> bool {
    previous.wrapping_add(1) == current
}

#[derive(Clone, Default)]
struct PresentFrameTiming {
    last_present: Option<Instant>,
    last_present_epoch: Option<u32>,
    frame_seconds: f32,
}

impl PresentFrameTiming {
    fn record_frame_at(&mut self, now: Instant, render_epoch: u32, active: bool) {
        if !active {
            self.pause();
            return;
        }
        if let (Some(last_present), Some(last_epoch)) = (self.last_present, self.last_present_epoch)
        {
            if consecutive_render_epochs(last_epoch, render_epoch) {
                if let Some(frame_time) = now.checked_duration_since(last_present) {
                    self.frame_seconds = frame_time.as_secs_f32().clamp(1.0 / 240.0, 0.1);
                } else {
                    self.frame_seconds = 0.0;
                }
            } else {
                self.frame_seconds = 0.0;
            }
        }
        self.last_present = Some(now);
        self.last_present_epoch = Some(render_epoch);
    }

    fn pause(&mut self) {
        let had_present = self.last_present.take().is_some();
        let had_epoch = self.last_present_epoch.take().is_some();
        if had_present || had_epoch {
            self.frame_seconds = 0.0;
        }
    }

    fn invalidate_origin(&mut self) {
        self.last_present = None;
        self.last_present_epoch = None;
        self.frame_seconds = 0.0;
    }

    fn frame_seconds(&self) -> f32 {
        if self.frame_seconds > 0.0 {
            self.frame_seconds
        } else {
            1.0 / 60.0
        }
    }
}

#[derive(Clone)]
struct FramePacing {
    samples: [f32; FRAME_PACING_HISTORY],
    next_index: usize,
    count: usize,
    last_present: Option<Instant>,
    last_present_epoch: Option<u32>,
    smoothed_ms: f32,
    display_elapsed_ms: f32,
    published: FramePacingSnapshot,
    active: bool,
    session: u32,
    update_interval_ms: u32,
    session_elapsed_ms: f64,
    baseline_ms: f32,
    baseline_noise_ms: f32,
    baseline_samples: u32,
    spike_events: [FrameSpikeEvent; FRAME_PACING_SPIKE_MEMORY],
    spike_next_index: usize,
    spike_count: usize,
    rejected_intervals: u32,
    total_slow_spikes: u32,
    total_fast_spikes: u32,
    largest_slow_spike: Option<FrameSpikeEvent>,
    largest_fast_spike: Option<FrameSpikeEvent>,
    last_spike_direction: Option<SpikeDirection>,
}

impl Default for FramePacing {
    fn default() -> Self {
        Self {
            samples: [0.0; FRAME_PACING_HISTORY],
            next_index: 0,
            count: 0,
            last_present: None,
            last_present_epoch: None,
            smoothed_ms: 0.0,
            display_elapsed_ms: 0.0,
            published: FramePacingSnapshot::default(),
            active: false,
            session: 0,
            update_interval_ms: FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS,
            session_elapsed_ms: 0.0,
            baseline_ms: 0.0,
            baseline_noise_ms: 0.0,
            baseline_samples: 0,
            spike_events: [FrameSpikeEvent::default(); FRAME_PACING_SPIKE_MEMORY],
            spike_next_index: 0,
            spike_count: 0,
            rejected_intervals: 0,
            total_slow_spikes: 0,
            total_fast_spikes: 0,
            largest_slow_spike: None,
            largest_fast_spike: None,
            last_spike_direction: None,
        }
    }
}

impl FramePacing {
    fn begin_session(&mut self, session: u32) {
        if self.session != session {
            self.session = session;
            self.reset_samples();
        }
    }

    fn record_frame_at(
        &mut self,
        now: Instant,
        render_epoch: u32,
        active: bool,
        update_interval_ms: u32,
    ) {
        if !active {
            self.pause();
            return;
        }
        if !self.active {
            self.reset_samples();
            self.last_present = Some(now);
            self.last_present_epoch = Some(render_epoch);
            self.active = true;
            return;
        }
        if let (Some(last_present), Some(last_epoch)) = (self.last_present, self.last_present_epoch)
        {
            if let Some(frame_time) = now.checked_duration_since(last_present) {
                if consecutive_render_epochs(last_epoch, render_epoch) {
                    let frame_ms = frame_time.as_secs_f32().mul_add(1000.0, 0.0);
                    self.record_sample_with_interval(frame_ms, update_interval_ms);
                } else {
                    // Keep spike episode ages on wall time without treating an
                    // unknown number of Presents as one measured frame.
                    self.session_elapsed_ms += frame_time.as_secs_f64() * 1_000.0;
                    self.rejected_intervals = self.rejected_intervals.saturating_add(1);
                }
            } else {
                self.rejected_intervals = self.rejected_intervals.saturating_add(1);
            }
        }
        self.last_present = Some(now);
        self.last_present_epoch = Some(render_epoch);
    }

    fn pause(&mut self) {
        if self.active {
            self.last_present = None;
            self.last_present_epoch = None;
            self.active = false;
        }
    }

    fn invalidate_origin(&mut self) {
        self.last_present = None;
        self.last_present_epoch = None;
    }

    fn reject_current_present(&mut self) {
        self.rejected_intervals = self.rejected_intervals.saturating_add(1);
        self.invalidate_origin();
    }

    fn reset_samples(&mut self) {
        self.samples.fill(0.0);
        self.next_index = 0;
        self.count = 0;
        self.last_present = None;
        self.last_present_epoch = None;
        self.smoothed_ms = 0.0;
        self.display_elapsed_ms = 0.0;
        self.published = FramePacingSnapshot::default();
        self.active = false;
        self.session_elapsed_ms = 0.0;
        self.baseline_ms = 0.0;
        self.baseline_noise_ms = 0.0;
        self.baseline_samples = 0;
        self.spike_events.fill(FrameSpikeEvent::default());
        self.spike_next_index = 0;
        self.spike_count = 0;
        self.rejected_intervals = 0;
        self.total_slow_spikes = 0;
        self.total_fast_spikes = 0;
        self.largest_slow_spike = None;
        self.largest_fast_spike = None;
        self.last_spike_direction = None;
    }

    #[cfg(test)]
    fn record_sample(&mut self, frame_ms: f32) {
        self.record_sample_with_interval(frame_ms, FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS);
    }

    fn record_sample_with_interval(&mut self, frame_ms: f32, update_interval_ms: u32) {
        if !frame_ms.is_finite() || frame_ms <= 0.0 {
            return;
        }

        self.update_interval_ms =
            crate::config::sanitize_frame_pacing_update_interval_ms(update_interval_ms);
        self.samples[self.next_index] = frame_ms;
        self.next_index = (self.next_index + 1) % FRAME_PACING_HISTORY;
        self.count = (self.count + 1).min(FRAME_PACING_HISTORY);
        self.observe_spike(frame_ms);

        // Preserve the full sample in history, but bound a suspended process or
        // loading pause so the responsive live-FPS readout recovers promptly.
        let live_sample = frame_ms.min(FRAME_PACING_LIVE_SAMPLE_MAX_MS);
        self.smoothed_ms = if self.smoothed_ms <= f32::EPSILON {
            live_sample
        } else {
            let alpha = live_sample / (FRAME_PACING_EMA_TIME_CONSTANT_MS + live_sample);
            self.smoothed_ms + (live_sample - self.smoothed_ms) * alpha
        };

        self.display_elapsed_ms += frame_ms;
        if self.count <= 2
            || self.update_interval_ms == 0
            || self.display_elapsed_ms >= self.update_interval_ms as f32
        {
            self.publish_snapshot();
        }
    }

    fn publish_snapshot(&mut self) {
        self.published = self.calculate_snapshot();
        self.display_elapsed_ms = 0.0;
    }

    #[cfg(test)]
    fn update_interval_ms(&self) -> u32 {
        self.update_interval_ms
    }

    fn observe_spike(&mut self, frame_ms: f32) {
        self.session_elapsed_ms += f64::from(frame_ms);
        if self.baseline_samples == 0 {
            self.baseline_ms = frame_ms;
            self.baseline_samples = 1;
            return;
        }

        if self.baseline_samples < FRAME_PACING_SPIKE_WARMUP_SAMPLES {
            self.baseline_samples += 1;
            let alpha = 1.0 / self.baseline_samples as f32;
            let residual = frame_ms - self.baseline_ms;
            self.baseline_ms += residual * alpha;
            self.baseline_noise_ms += (residual.abs() - self.baseline_noise_ms) * alpha;
            return;
        }

        let residual = frame_ms - self.baseline_ms;
        let threshold_ms = frame_spike_threshold_ms(self.baseline_ms, self.baseline_noise_ms);
        if residual.abs() >= threshold_ms {
            self.record_spike_event(frame_ms, residual);
            self.last_spike_direction = Some(if residual >= 0.0 {
                SpikeDirection::Slow
            } else {
                SpikeDirection::Fast
            });
        } else {
            self.last_spike_direction = None;
        }

        let bounded_residual = residual.clamp(-threshold_ms, threshold_ms);
        let alpha = frame_ms.min(FRAME_PACING_LIVE_SAMPLE_MAX_MS)
            / (FRAME_PACING_SPIKE_BASELINE_TIME_MS + frame_ms.min(FRAME_PACING_LIVE_SAMPLE_MAX_MS));
        self.baseline_ms += bounded_residual * alpha;
        let bounded_noise = residual.abs().min(threshold_ms);
        self.baseline_noise_ms += (bounded_noise - self.baseline_noise_ms) * alpha;
        self.baseline_samples = self.baseline_samples.saturating_add(1);
    }

    fn record_spike_event(&mut self, frame_ms: f32, delta_ms: f32) {
        let direction = if delta_ms >= 0.0 {
            SpikeDirection::Slow
        } else {
            SpikeDirection::Fast
        };
        let severity = SpikeSeverity::from_excursion(delta_ms.abs(), self.baseline_ms);
        let mut event = FrameSpikeEvent {
            session_time_ms: self.session_elapsed_ms,
            age_ms: 0.0,
            frame_ms,
            baseline_ms: self.baseline_ms,
            delta_ms,
            direction,
            severity,
        };
        if self.last_spike_direction == Some(direction) && self.spike_count > 0 {
            let last_index =
                (self.spike_next_index + FRAME_PACING_SPIKE_MEMORY - 1) % FRAME_PACING_SPIKE_MEMORY;
            let previous = self.spike_events[last_index];
            if previous.delta_ms.abs() > event.delta_ms.abs() {
                event.frame_ms = previous.frame_ms;
                event.baseline_ms = previous.baseline_ms;
                event.delta_ms = previous.delta_ms;
                event.severity = previous.severity;
            }
            self.spike_events[last_index] = event;
            self.update_session_spike_extreme(event);
            return;
        }

        match direction {
            SpikeDirection::Slow => {
                self.total_slow_spikes = self.total_slow_spikes.saturating_add(1);
            }
            SpikeDirection::Fast => {
                self.total_fast_spikes = self.total_fast_spikes.saturating_add(1);
            }
        }
        self.update_session_spike_extreme(event);
        self.spike_events[self.spike_next_index] = event;
        self.spike_next_index = (self.spike_next_index + 1) % FRAME_PACING_SPIKE_MEMORY;
        self.spike_count = (self.spike_count + 1).min(FRAME_PACING_SPIKE_MEMORY);
    }

    fn update_session_spike_extreme(&mut self, event: FrameSpikeEvent) {
        let direction = event.direction;
        let session_largest = match direction {
            SpikeDirection::Slow => &mut self.largest_slow_spike,
            SpikeDirection::Fast => &mut self.largest_fast_spike,
        };
        if session_largest.is_none_or(|largest| event.delta_ms.abs() > largest.delta_ms.abs()) {
            *session_largest = Some(event);
        }
    }

    fn copy_chronological_samples(&self, output: &mut [f32; FRAME_PACING_HISTORY]) -> usize {
        if self.count == FRAME_PACING_HISTORY {
            let tail_count = FRAME_PACING_HISTORY - self.next_index;
            output[..tail_count].copy_from_slice(&self.samples[self.next_index..]);
            output[tail_count..].copy_from_slice(&self.samples[..self.next_index]);
        } else {
            output[..self.count].copy_from_slice(&self.samples[..self.count]);
        }
        self.count
    }

    fn copy_recent_samples(&self, output: &mut [f32; FRAME_PACING_HISTORY]) -> usize {
        let chronological_count = self.copy_chronological_samples(output);
        let mut start = chronological_count;
        let mut elapsed_ms = 0.0f64;
        while start > 0 {
            let sample_ms = f64::from(output[start - 1]);
            if start < chronological_count
                && elapsed_ms + sample_ms > f64::from(FRAME_PACING_WINDOW_MS)
            {
                break;
            }
            start -= 1;
            elapsed_ms += sample_ms;
        }
        let recent_count = chronological_count - start;
        output.copy_within(start..chronological_count, 0);
        recent_count
    }

    fn calculate_snapshot(&self) -> FramePacingSnapshot {
        let mut samples = [0.0; FRAME_PACING_HISTORY];
        let sample_count = self.copy_recent_samples(&mut samples);
        let active_samples = &samples[..sample_count];
        let average_ms = if sample_count == 0 {
            0.0
        } else {
            (active_samples
                .iter()
                .map(|sample| f64::from(*sample))
                .sum::<f64>()
                / sample_count as f64) as f32
        };
        let history_seconds = active_samples
            .iter()
            .map(|sample| f64::from(*sample) * 0.001)
            .sum::<f64>() as f32;

        let mut histogram = [0u16; FRAME_PACING_HISTOGRAM_BINS];
        fill_frame_time_histogram(active_samples, &mut histogram);
        let p50_ms = histogram_percentile(active_samples, &histogram, 0.50);
        let p95_ms = histogram_percentile(active_samples, &histogram, 0.95);
        let p99_ms = histogram_percentile(active_samples, &histogram, 0.99);
        let worst_ms = active_samples
            .iter()
            .copied()
            .max_by(f32::total_cmp)
            .unwrap_or(0.0);

        let mut derived_samples = [0.0f32; FRAME_PACING_HISTORY];
        histogram.fill(0);
        for (index, sample) in active_samples.iter().enumerate() {
            derived_samples[index] = (*sample - p50_ms).abs();
        }
        let active_deviations = &derived_samples[..sample_count];
        fill_frame_time_histogram(active_deviations, &mut histogram);
        let median_absolute_deviation_ms =
            histogram_percentile(active_deviations, &histogram, 0.50);

        let jitter_ms = if sample_count > 1 {
            histogram.fill(0);
            for (index, pair) in active_samples.windows(2).enumerate() {
                derived_samples[index] = (pair[1] - pair[0]).abs();
            }
            let delta_count = sample_count - 1;
            let active_deltas = &derived_samples[..delta_count];
            fill_frame_time_histogram(active_deltas, &mut histogram);
            histogram_percentile(active_deltas, &histogram, 0.95)
        } else {
            0.0
        };
        let budget_60_hits = active_samples
            .iter()
            .filter(|sample| **sample <= FRAME_BUDGET_60_MS)
            .count();
        let budget_30_hits = active_samples
            .iter()
            .filter(|sample| **sample <= FRAME_BUDGET_30_MS)
            .count();
        let budget_percent = |hits: usize| {
            if sample_count == 0 {
                0.0
            } else {
                hits as f32 * 100.0 / sample_count as f32
            }
        };
        let off_scale_samples = active_samples
            .iter()
            .filter(|sample| **sample > FRAME_PACING_CHART_MAX_MS)
            .count();
        let mut chart_samples = [0.0; FRAME_PACING_CHART_POINTS];
        let chart_count = build_frame_time_cadence_chart(active_samples, &mut chart_samples);
        let mut spike_chart_samples = [0.0; FRAME_PACING_CHART_POINTS];
        let spike_chart_count = build_spike_excursion_chart(
            active_samples,
            self.baseline_ms,
            frame_spike_threshold_ms(self.baseline_ms, self.baseline_noise_ms),
            &mut spike_chart_samples,
        );

        FramePacingSnapshot {
            fps: fps_from_ms(self.smoothed_ms),
            live_ms: self.smoothed_ms,
            average_ms,
            average_fps: fps_from_ms(average_ms),
            one_percent_low_fps: fps_from_ms(p99_ms),
            p50_ms,
            p95_ms,
            p99_ms,
            worst_ms,
            jitter_ms,
            median_absolute_deviation_ms,
            baseline_ms: self.baseline_ms,
            history_seconds,
            budget_60_hit_percent: budget_percent(budget_60_hits),
            budget_30_hit_percent: budget_percent(budget_30_hits),
            scale_max: FRAME_PACING_CHART_MAX_MS,
            off_scale_samples,
            sample_count,
            rejected_intervals: self.rejected_intervals,
            chart_count,
            chart_samples,
            spike_chart_count,
            spike_chart_samples,
            spikes: self.spike_summary(),
        }
    }

    fn snapshot(&self) -> FramePacingSnapshot {
        self.published.clone()
    }

    fn copy_spike_events(
        &self,
        output: &mut [FrameSpikeEvent; FRAME_PACING_SPIKE_MEMORY],
    ) -> usize {
        if self.spike_count == FRAME_PACING_SPIKE_MEMORY {
            let tail_count = FRAME_PACING_SPIKE_MEMORY - self.spike_next_index;
            output[..tail_count].copy_from_slice(&self.spike_events[self.spike_next_index..]);
            output[tail_count..].copy_from_slice(&self.spike_events[..self.spike_next_index]);
        } else {
            output[..self.spike_count].copy_from_slice(&self.spike_events[..self.spike_count]);
        }
        self.spike_count
    }

    fn spike_summary(&self) -> FrameSpikeSummary {
        let mut events = [FrameSpikeEvent::default(); FRAME_PACING_SPIKE_MEMORY];
        let event_count = self.copy_spike_events(&mut events);
        let retained = &events[..event_count];
        let latest = retained.last().copied().map(|event| {
            event.with_age((self.session_elapsed_ms - event.session_time_ms).max(0.0) as f32)
        });
        let with_current_age = |event: FrameSpikeEvent| {
            event.with_age((self.session_elapsed_ms - event.session_time_ms).max(0.0) as f32)
        };
        let slow_period = detect_spike_periodicity(retained, SpikeDirection::Slow);
        let fast_period = detect_spike_periodicity(retained, SpikeDirection::Fast);
        let periodic = match (slow_period, fast_period) {
            (Some(slow), Some(fast)) => {
                Some(if slow.confidence_percent >= fast.confidence_percent {
                    slow
                } else {
                    fast
                })
            }
            (Some(period), None) | (None, Some(period)) => Some(period),
            (None, None) => None,
        };

        FrameSpikeSummary {
            retained: event_count,
            total_slow: self.total_slow_spikes,
            total_fast: self.total_fast_spikes,
            latest,
            largest_slow: self.largest_slow_spike.map(with_current_age),
            largest_fast: self.largest_fast_spike.map(with_current_age),
            periodic,
        }
    }
}

fn build_frame_time_cadence_chart(
    samples: &[f32],
    output: &mut [f32; FRAME_PACING_CHART_POINTS],
) -> usize {
    if samples.is_empty() {
        return 0;
    }

    let mut bucket_sum_ms = [0.0f32; FRAME_PACING_CHART_POINTS];
    let mut bucket_count = [0u16; FRAME_PACING_CHART_POINTS];
    let mut bucket_hitch_ms = [0.0f32; FRAME_PACING_CHART_POINTS];
    let interval_ms = f64::from(FRAME_PACING_CHART_INTERVAL_MS);
    let mut age_ms = 0.0f64;
    let mut oldest_bucket = 0usize;

    let mut index = samples.len();
    while index > 0 {
        let newer = samples[index - 1];
        if newer >= FRAME_PACING_CHART_PRESERVED_HITCH_MS {
            let bucket = (age_ms / interval_ms) as usize;
            if bucket >= FRAME_PACING_CHART_POINTS {
                break;
            }
            bucket_hitch_ms[bucket] = bucket_hitch_ms[bucket].max(newer);
            oldest_bucket = oldest_bucket.max(bucket);
            age_ms += f64::from(newer);
            index -= 1;
            continue;
        }

        let (cadence_ms, elapsed_ms, consumed) = if index >= 2 {
            let older = samples[index - 2];
            if older < FRAME_PACING_CHART_PRESERVED_HITCH_MS {
                ((older + newer) * 0.5, older + newer, 2)
            } else {
                (newer, newer, 1)
            }
        } else {
            (newer, newer, 1)
        };
        let bucket = (age_ms / interval_ms) as usize;
        if bucket >= FRAME_PACING_CHART_POINTS {
            break;
        }
        bucket_sum_ms[bucket] += cadence_ms;
        bucket_count[bucket] = bucket_count[bucket].saturating_add(1);
        oldest_bucket = oldest_bucket.max(bucket);
        age_ms += f64::from(elapsed_ms);
        index -= consumed;
    }

    let chart_count = (oldest_bucket + 1).min(FRAME_PACING_CHART_POINTS);
    let mut last_observed_ms = 0.0f32;
    for index in 0..chart_count {
        let bucket = chart_count - 1 - index;
        if bucket_hitch_ms[bucket] > 0.0 {
            last_observed_ms = bucket_hitch_ms[bucket];
        } else if bucket_count[bucket] > 0 {
            last_observed_ms = bucket_sum_ms[bucket] / f32::from(bucket_count[bucket]);
        }
        output[index] = last_observed_ms;
    }
    chart_count
}

fn build_spike_excursion_chart(
    samples: &[f32],
    baseline_ms: f32,
    threshold_ms: f32,
    output: &mut [f32; FRAME_PACING_CHART_POINTS],
) -> usize {
    let chart_count = samples.len().min(FRAME_PACING_CHART_POINTS);
    if chart_count == 0 {
        return 0;
    }
    let start = samples.len() - chart_count;
    for (output_sample, frame_ms) in output[..chart_count].iter_mut().zip(&samples[start..]) {
        let excursion_ms = *frame_ms - baseline_ms;
        *output_sample = if excursion_ms.abs() >= threshold_ms {
            excursion_ms
        } else {
            0.0
        };
    }
    chart_count
}

fn frame_spike_threshold_ms(baseline_ms: f32, baseline_noise_ms: f32) -> f32 {
    FRAME_PACING_SPIKE_MIN_DELTA_MS
        .max(baseline_ms * FRAME_PACING_SPIKE_RELATIVE_DELTA)
        .max(baseline_noise_ms * FRAME_PACING_SPIKE_NOISE_MULTIPLIER)
}

fn fill_frame_time_histogram(samples: &[f32], histogram: &mut [u16; FRAME_PACING_HISTOGRAM_BINS]) {
    for sample in samples {
        increment_histogram(histogram, *sample);
    }
}

fn increment_histogram(histogram: &mut [u16; FRAME_PACING_HISTOGRAM_BINS], value_ms: f32) {
    let index = ((value_ms.max(0.0) / FRAME_PACING_HISTOGRAM_BIN_MS) as usize)
        .min(FRAME_PACING_HISTOGRAM_BINS - 1);
    histogram[index] = histogram[index].saturating_add(1);
}

fn histogram_percentile(
    samples: &[f32],
    histogram: &[u16; FRAME_PACING_HISTOGRAM_BINS],
    percentile: f32,
) -> f32 {
    let sample_count = samples.len();
    if sample_count == 0 {
        return 0.0;
    }
    let rank = (percentile.clamp(0.0, 1.0) * sample_count as f32)
        .ceil()
        .max(1.0) as usize;
    let mut cumulative = 0usize;
    for (index, count) in histogram.iter().enumerate() {
        cumulative += usize::from(*count);
        if cumulative >= rank {
            if index == FRAME_PACING_HISTOGRAM_BINS - 1 {
                let before_overflow = cumulative - usize::from(*count);
                let overflow_rank = rank - before_overflow - 1;
                let overflow_start_ms = index as f32 * FRAME_PACING_HISTOGRAM_BIN_MS;
                let mut overflow = [0.0f32; FRAME_PACING_HISTORY];
                let mut overflow_count = 0usize;
                for sample in samples {
                    if *sample >= overflow_start_ms {
                        overflow[overflow_count] = *sample;
                        overflow_count += 1;
                    }
                }
                let (_, selected, _) = overflow[..overflow_count]
                    .select_nth_unstable_by(overflow_rank, f32::total_cmp);
                return *selected;
            }
            return index as f32 * FRAME_PACING_HISTOGRAM_BIN_MS;
        }
    }
    (FRAME_PACING_HISTOGRAM_BINS - 1) as f32 * FRAME_PACING_HISTOGRAM_BIN_MS
}

fn fps_from_ms(frame_ms: f32) -> f32 {
    if frame_ms > 0.001 {
        1_000.0 / frame_ms
    } else {
        0.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SpikeDirection {
    #[default]
    Slow,
    Fast,
}

impl SpikeDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Slow => "SLOW",
            Self::Fast => "FAST",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SpikeSeverity {
    #[default]
    Notice,
    Major,
    Severe,
}

impl SpikeSeverity {
    fn from_excursion(delta_ms: f32, baseline_ms: f32) -> Self {
        let relative = if baseline_ms > f32::EPSILON {
            delta_ms / baseline_ms
        } else {
            0.0
        };
        if delta_ms >= 50.0 || relative >= 2.0 {
            Self::Severe
        } else if delta_ms >= FRAME_BUDGET_60_MS || relative >= 0.75 {
            Self::Major
        } else {
            Self::Notice
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Notice => "NOTICE",
            Self::Major => "MAJOR",
            Self::Severe => "SEVERE",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FrameSpikeEvent {
    session_time_ms: f64,
    age_ms: f32,
    frame_ms: f32,
    baseline_ms: f32,
    delta_ms: f32,
    direction: SpikeDirection,
    severity: SpikeSeverity,
}

impl FrameSpikeEvent {
    fn with_age(mut self, age_ms: f32) -> Self {
        self.age_ms = age_ms;
        self
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SpikePeriodicity {
    direction: SpikeDirection,
    interval_ms: f32,
    spread_ms: f32,
    confidence_percent: f32,
    repeats: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct FrameSpikeSummary {
    retained: usize,
    total_slow: u32,
    total_fast: u32,
    latest: Option<FrameSpikeEvent>,
    largest_slow: Option<FrameSpikeEvent>,
    largest_fast: Option<FrameSpikeEvent>,
    periodic: Option<SpikePeriodicity>,
}

fn detect_spike_periodicity(
    events: &[FrameSpikeEvent],
    direction: SpikeDirection,
) -> Option<SpikePeriodicity> {
    let mut times = [0.0f64; 17];
    let mut time_count = 0usize;
    for event in events
        .iter()
        .rev()
        .filter(|event| event.direction == direction)
        .take(times.len())
    {
        times[time_count] = event.session_time_ms;
        time_count += 1;
    }
    if time_count < 4 {
        return None;
    }
    times[..time_count].reverse();

    let mut intervals = [0.0f32; 16];
    let interval_count = time_count - 1;
    for index in 0..interval_count {
        intervals[index] = (times[index + 1] - times[index]) as f32;
    }
    let median = median_in_place(&mut intervals, interval_count);
    if median < 100.0 {
        return None;
    }

    let tolerance_ms = (median * 0.15).max(25.0);
    let mut inlier_count = 0usize;
    let mut sum = 0.0f64;
    for interval in &intervals[..interval_count] {
        if (*interval - median).abs() <= tolerance_ms {
            inlier_count += 1;
            sum += f64::from(*interval);
        }
    }
    if inlier_count < 3 || inlier_count * 4 < interval_count * 3 {
        return None;
    }

    let mean = (sum / inlier_count as f64) as f32;
    let mut variance = 0.0f64;
    for interval in &intervals[..interval_count] {
        if (*interval - median).abs() <= tolerance_ms {
            let delta = f64::from(*interval - mean);
            variance += delta * delta;
        }
    }
    let spread_ms = (variance / inlier_count as f64).sqrt() as f32;
    let regularity = (1.0 - spread_ms / mean.max(1.0)).clamp(0.0, 1.0);
    let coverage = inlier_count as f32 / interval_count as f32;

    Some(SpikePeriodicity {
        direction,
        interval_ms: mean,
        spread_ms,
        confidence_percent: regularity * coverage * 100.0,
        repeats: inlier_count + 1,
    })
}

fn median_in_place(values: &mut [f32], count: usize) -> f32 {
    if count == 0 {
        return 0.0;
    }
    let middle = count / 2;
    let (_, median, _) = values[..count].select_nth_unstable_by(middle, f32::total_cmp);
    *median
}

#[derive(Clone)]
struct FramePacingSnapshot {
    fps: f32,
    live_ms: f32,
    average_ms: f32,
    average_fps: f32,
    one_percent_low_fps: f32,
    p50_ms: f32,
    p95_ms: f32,
    p99_ms: f32,
    worst_ms: f32,
    jitter_ms: f32,
    median_absolute_deviation_ms: f32,
    baseline_ms: f32,
    history_seconds: f32,
    budget_60_hit_percent: f32,
    budget_30_hit_percent: f32,
    scale_max: f32,
    off_scale_samples: usize,
    sample_count: usize,
    rejected_intervals: u32,
    chart_count: usize,
    chart_samples: [f32; FRAME_PACING_CHART_POINTS],
    spike_chart_count: usize,
    spike_chart_samples: [f32; FRAME_PACING_CHART_POINTS],
    spikes: FrameSpikeSummary,
}

impl Default for FramePacingSnapshot {
    fn default() -> Self {
        Self {
            fps: 0.0,
            live_ms: 0.0,
            average_ms: 0.0,
            average_fps: 0.0,
            one_percent_low_fps: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            worst_ms: 0.0,
            jitter_ms: 0.0,
            median_absolute_deviation_ms: 0.0,
            baseline_ms: 0.0,
            history_seconds: 0.0,
            budget_60_hit_percent: 0.0,
            budget_30_hit_percent: 0.0,
            scale_max: FRAME_PACING_CHART_MAX_MS,
            off_scale_samples: 0,
            sample_count: 0,
            rejected_intervals: 0,
            chart_count: 0,
            chart_samples: [0.0; FRAME_PACING_CHART_POINTS],
            spike_chart_count: 0,
            spike_chart_samples: [0.0; FRAME_PACING_CHART_POINTS],
            spikes: FrameSpikeSummary::default(),
        }
    }
}

impl FramePacingSnapshot {
    fn samples(&self) -> &[f32] {
        &self.chart_samples[..self.chart_count]
    }

    fn spike_samples(&self) -> &[f32] {
        &self.spike_chart_samples[..self.spike_chart_count]
    }
}

#[cfg(test)]
mod frame_pacing_tests {
    use super::{
        FRAME_BUDGET_30_MS, FRAME_BUDGET_60_MS, FRAME_PACING_CHART_POINTS,
        FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS, FRAME_PACING_HISTORY, FRAME_PACING_SPIKE_MEMORY,
        FRAME_PACING_SPIKE_WARMUP_SAMPLES, FramePacing, MENU_DIAGNOSTICS_ACTIVE_BIT,
        MENU_DIAGNOSTICS_SESSION_INCREMENT, PresentFrameTiming, SpikeDirection,
        build_frame_time_cadence_chart, diagnostics_state_transition,
    };
    use std::time::{Duration, Instant};

    fn assert_close(actual: f32, expected: f32) {
        assert!(
            (actual - expected).abs() < 0.001,
            "expected {expected}, got {actual}"
        );
    }

    #[test]
    fn snapshot_reports_developer_facing_distribution_and_budget_metrics() {
        let mut pacing = FramePacing::default();
        for frame_ms in 1..=100 {
            pacing.record_sample(frame_ms as f32);
        }
        pacing.publish_snapshot();

        let snapshot = pacing.snapshot();
        assert_eq!(snapshot.sample_count, 100);
        assert!(!snapshot.samples().is_empty());
        assert!(snapshot.samples().iter().all(|sample| sample.is_finite()));
        assert_close(snapshot.average_ms, 50.5);
        assert_close(snapshot.p50_ms, 50.0);
        assert_close(snapshot.p95_ms, 95.0);
        assert_close(snapshot.p99_ms, 99.0);
        assert_close(snapshot.worst_ms, 100.0);
        assert_close(snapshot.jitter_ms, 1.0);
        assert_close(snapshot.average_fps, 1000.0 / 50.5);
        assert_close(snapshot.one_percent_low_fps, 1000.0 / 99.0);
        assert_close(snapshot.budget_60_hit_percent, 16.0);
        assert_close(snapshot.budget_30_hit_percent, 33.0);
        assert!(snapshot.scale_max >= FRAME_BUDGET_30_MS);
        assert_eq!(snapshot.off_scale_samples, 50);
    }

    #[test]
    fn histogram_overflow_does_not_clip_reported_percentiles() {
        let mut pacing = FramePacing::default();
        for _ in 0..100 {
            pacing.record_sample(1_000.0);
        }
        pacing.publish_snapshot();

        let snapshot = pacing.snapshot();
        assert_close(snapshot.p50_ms, 1_000.0);
        assert_close(snapshot.p95_ms, 1_000.0);
        assert_close(snapshot.p99_ms, 1_000.0);
        assert_close(snapshot.worst_ms, 1_000.0);
        assert_close(snapshot.jitter_ms, 0.0);
    }

    #[test]
    fn fixed_scale_preserves_normal_detail_and_exposes_an_isolated_hitch() {
        let mut pacing = FramePacing::default();
        for _ in 0..(FRAME_PACING_HISTORY - 1) {
            pacing.record_sample(10.0);
        }
        pacing.record_sample(250.0);
        pacing.publish_snapshot();

        let snapshot = pacing.snapshot();
        assert_close(snapshot.p50_ms, 10.0);
        assert_close(snapshot.p99_ms, 10.0);
        assert_close(snapshot.worst_ms, 250.0);
        assert_close(snapshot.scale_max, 50.0);
        assert!(snapshot.scale_max < snapshot.worst_ms);
        assert_eq!(snapshot.off_scale_samples, 1);
        assert_close(snapshot.jitter_ms, 0.0);
        assert!(snapshot.budget_60_hit_percent > 99.0);
        assert!(snapshot.budget_30_hit_percent > 99.0);
    }

    #[test]
    fn displayed_metrics_hold_long_enough_to_read() {
        let mut pacing = FramePacing::default();
        pacing.record_sample(10.0);
        pacing.record_sample(10.0);
        let initial = pacing.snapshot();

        for _ in 0..10 {
            pacing.record_sample(20.0);
        }
        let held = pacing.snapshot();
        assert_eq!(held.samples(), initial.samples());
        assert_close(held.average_ms, initial.average_ms);

        for _ in 0..15 {
            pacing.record_sample(20.0);
        }
        let refreshed = pacing.snapshot();
        assert!(refreshed.samples().len() > held.samples().len());
        assert!(refreshed.average_ms > held.average_ms);
    }

    #[test]
    fn configurable_update_cadence_includes_true_per_frame_publication() {
        let mut pacing = FramePacing::default();
        pacing.record_sample_with_interval(10.0, 1_000);
        pacing.record_sample_with_interval(10.0, 1_000);
        let held = pacing.snapshot();

        pacing.record_sample_with_interval(30.0, 1_000);
        assert_close(pacing.snapshot().average_ms, held.average_ms);

        pacing.record_sample_with_interval(40.0, 0);
        assert!(pacing.snapshot().average_ms > held.average_ms);

        pacing.record_sample_with_interval(50.0, 99_999);
        assert_eq!(
            pacing.update_interval_ms(),
            crate::config::sanitize_frame_pacing_update_interval_ms(99_999)
        );
        assert_eq!(FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS, 500);
    }

    #[test]
    fn chart_reduces_per_frame_zigzag_without_hiding_persistent_jitter() {
        let mut pacing = FramePacing::default();
        for _ in 0..50 {
            pacing.record_sample(10.0);
            pacing.record_sample(20.0);
        }

        let snapshot = pacing.snapshot();
        let chart_min = snapshot
            .samples()
            .iter()
            .copied()
            .min_by(f32::total_cmp)
            .expect("chart minimum");
        let chart_max = snapshot
            .samples()
            .iter()
            .copied()
            .max_by(f32::total_cmp)
            .expect("chart maximum");
        assert_close(chart_min, 15.0);
        assert_close(chart_max, 15.0);
        assert_close(snapshot.jitter_ms, 10.0);
    }

    #[test]
    fn stable_batched_present_submissions_do_not_form_a_cadence_sawtooth() {
        let mut samples = [0.0f32; 240];
        for (index, sample) in samples.iter_mut().enumerate() {
            *sample = if index % 2 == 0 { 1.0 } else { 32.0 };
        }
        let mut chart = [0.0f32; FRAME_PACING_CHART_POINTS];
        let chart_count = build_frame_time_cadence_chart(&samples, &mut chart);
        let chart = &chart[..chart_count];
        let chart_min = chart
            .iter()
            .copied()
            .min_by(f32::total_cmp)
            .expect("chart minimum");
        let chart_max = chart
            .iter()
            .copied()
            .max_by(f32::total_cmp)
            .expect("chart maximum");

        assert_close(chart_min, 16.5);
        assert_close(chart_max, 16.5);
    }

    #[test]
    fn a_single_long_hitch_is_one_cadence_bucket_event() {
        let mut pacing = FramePacing::default();
        for _ in 0..20 {
            pacing.record_sample(10.0);
        }
        pacing.record_sample(250.0);
        pacing.publish_snapshot();

        let chart = pacing.snapshot();
        assert_eq!(
            chart
                .samples()
                .iter()
                .filter(|frame_ms| **frame_ms >= 250.0)
                .count(),
            1,
            "one long frame must not be drawn as several separate hitches"
        );
        assert!(
            chart.samples().iter().all(|frame_ms| *frame_ms > 0.0),
            "time buckets without a completed frame must retain the last observed cadence"
        );
    }

    #[test]
    fn spike_chart_preserves_short_slow_and_fast_excursions() {
        let mut pacing = FramePacing::default();
        for _ in 0..40 {
            pacing.record_sample(16.0);
        }
        pacing.record_sample(48.0);
        pacing.record_sample(7.0);
        pacing.publish_snapshot();

        let snapshot = pacing.snapshot();
        assert!(
            snapshot
                .spike_samples()
                .iter()
                .any(|deviation| *deviation >= 30.0)
        );
        assert!(
            snapshot
                .spike_samples()
                .iter()
                .any(|deviation| *deviation <= -8.0)
        );
        assert_close(snapshot.worst_ms, 48.0);
    }

    #[test]
    fn stable_quantized_cadence_does_not_draw_a_spike_sawtooth() {
        let mut pacing = FramePacing::default();
        for _ in 0..80 {
            pacing.record_sample(16.0);
            pacing.record_sample(17.0);
        }
        pacing.publish_snapshot();

        assert!(
            pacing
                .snapshot()
                .spike_samples()
                .iter()
                .all(|excursion| excursion.abs() <= f32::EPSILON),
            "normal whole-millisecond timer quantization is not a pacing spike"
        );
    }

    #[test]
    fn retained_spike_analysis_separates_direction_severity_and_periodicity() {
        let mut pacing = FramePacing::default();
        for _ in 0..40 {
            pacing.record_sample(16.0);
        }
        for _ in 0..6 {
            for _ in 0..59 {
                pacing.record_sample(16.0);
            }
            pacing.record_sample(52.0);
        }
        pacing.record_sample(6.0);
        pacing.record_sample(90.0);
        pacing.publish_snapshot();

        let spikes = pacing.snapshot().spikes;
        assert!(spikes.total_slow >= 7);
        assert!(spikes.total_fast >= 1);
        assert_eq!(
            spikes.latest.expect("latest spike").direction,
            SpikeDirection::Slow
        );
        assert!(spikes.largest_slow.expect("largest slow spike").frame_ms >= 90.0);
        assert!(spikes.largest_fast.expect("largest fast spike").frame_ms <= 6.0);
        let periodic = spikes.periodic.expect("periodic slow spikes");
        assert_eq!(periodic.direction, SpikeDirection::Slow);
        assert!((900.0..=1_100.0).contains(&periodic.interval_ms));
        assert!(periodic.repeats >= 5);
    }

    #[test]
    fn sustained_frame_rate_shift_is_one_episode_not_one_spike_per_frame() {
        let mut pacing = FramePacing::default();
        for _ in 0..60 {
            pacing.record_sample(16.0);
        }
        for _ in 0..60 {
            pacing.record_sample(33.0);
        }
        pacing.publish_snapshot();

        let spikes = pacing.snapshot().spikes;
        assert_eq!(spikes.total_slow, 1);
        assert_eq!(spikes.retained, 1);
        assert!(spikes.periodic.is_none());
    }

    #[test]
    fn rare_session_extreme_survives_spike_ring_rollover() {
        let mut pacing = FramePacing {
            baseline_ms: 16.0,
            baseline_samples: FRAME_PACING_SPIKE_WARMUP_SAMPLES,
            ..FramePacing::default()
        };
        pacing.session_elapsed_ms = 1_000.0;
        pacing.record_spike_event(90.0, 74.0);
        pacing.last_spike_direction = None;

        for index in 0..FRAME_PACING_SPIKE_MEMORY {
            pacing.session_elapsed_ms = 2_000.0 + index as f64 * 1_000.0;
            pacing.record_spike_event(30.0, 14.0);
            pacing.last_spike_direction = None;
        }

        let spikes = pacing.spike_summary();
        assert_eq!(spikes.retained, FRAME_PACING_SPIKE_MEMORY);
        assert!(spikes.total_slow as usize > spikes.retained);
        assert_eq!(
            spikes.largest_slow.expect("session slow extreme").frame_ms,
            90.0
        );
    }

    #[test]
    fn distribution_uses_a_bounded_ten_second_time_window() {
        let mut pacing = FramePacing::default();
        for _ in 0..1_000 {
            pacing.record_sample(20.0);
        }
        pacing.publish_snapshot();

        let snapshot = pacing.snapshot();
        assert_eq!(snapshot.sample_count, 500);
        assert_close(snapshot.history_seconds, 10.0);
        assert_close(snapshot.average_ms, 20.0);
        assert_eq!(snapshot.samples().len(), FRAME_PACING_CHART_POINTS);
    }

    #[test]
    fn ring_snapshot_is_chronological_and_fixed_to_the_latest_frames() {
        let mut pacing = FramePacing::default();
        for frame_ms in 1..=(FRAME_PACING_HISTORY + 2) {
            pacing.record_sample(frame_ms as f32);
        }

        let mut samples = [0.0; FRAME_PACING_HISTORY];
        let count = pacing.copy_chronological_samples(&mut samples);
        assert_eq!(count, FRAME_PACING_HISTORY);
        assert_close(samples[0], 3.0);
        assert_close(samples[count - 1], (FRAME_PACING_HISTORY + 2) as f32);
    }

    #[test]
    fn invalid_samples_cannot_poison_the_timeline() {
        let mut pacing = FramePacing::default();
        pacing.record_sample(f32::NAN);
        pacing.record_sample(f32::INFINITY);
        pacing.record_sample(-1.0);
        pacing.record_sample(10.0);

        let snapshot = pacing.snapshot();
        assert_eq!(snapshot.samples(), &[10.0]);
        assert!(snapshot.fps.is_finite());
        assert!(snapshot.live_ms.is_finite());
        assert!(snapshot.average_ms.is_finite());
        assert!(snapshot.jitter_ms.is_finite());
        assert!(FRAME_BUDGET_60_MS < FRAME_BUDGET_30_MS);
    }

    #[test]
    fn diagnostics_state_advances_session_only_on_reactivation() {
        assert_eq!(diagnostics_state_transition(0, false), None);
        let first_active = diagnostics_state_transition(0, true).expect("first activation");
        assert_eq!(first_active & MENU_DIAGNOSTICS_ACTIVE_BIT, 1);
        assert_eq!(first_active / MENU_DIAGNOSTICS_SESSION_INCREMENT, 1);
        assert_eq!(diagnostics_state_transition(first_active, true), None);

        let inactive = diagnostics_state_transition(first_active, false).expect("deactivation");
        assert_eq!(inactive & MENU_DIAGNOSTICS_ACTIVE_BIT, 0);
        let second_active =
            diagnostics_state_transition(inactive, true).expect("second activation");
        assert_eq!(second_active / MENU_DIAGNOSTICS_SESSION_INCREMENT, 2);
    }

    #[test]
    fn closed_menu_does_not_collect_frame_pacing() {
        let mut pacing = FramePacing::default();
        let start = Instant::now();
        pacing.record_frame_at(start, 1, false, FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS);
        pacing.record_frame_at(
            start + Duration::from_millis(10),
            2,
            false,
            FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS,
        );
        assert!(pacing.snapshot().samples().is_empty());

        pacing.begin_session(1);
        pacing.record_frame_at(
            start + Duration::from_millis(20),
            3,
            true,
            FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS,
        );
        pacing.record_frame_at(
            start + Duration::from_millis(30),
            4,
            true,
            FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS,
        );
        assert_eq!(pacing.snapshot().samples(), &[10.0]);

        pacing.begin_session(1);
        assert_eq!(pacing.snapshot().samples(), &[10.0]);

        // The production fast gate makes no collector call while closed. A
        // new session token must still discard the old time origin/history.
        pacing.begin_session(2);
        assert!(pacing.snapshot().samples().is_empty());
        pacing.record_frame_at(
            start + Duration::from_millis(50),
            6,
            true,
            FRAME_PACING_DEFAULT_UPDATE_INTERVAL_MS,
        );
        assert!(pacing.snapshot().samples().is_empty());
    }

    #[test]
    fn skipped_present_callback_cannot_become_a_fake_long_frame() {
        let mut pacing = FramePacing::default();
        let start = Instant::now();
        pacing.begin_session(1);
        pacing.record_frame_at(start, 10, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(16), 11, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(48), 13, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(64), 14, true, 0);

        let snapshot = pacing.snapshot();
        assert_eq!(snapshot.sample_count, 2);
        assert_eq!(snapshot.rejected_intervals, 1);
        assert_close(snapshot.worst_ms, 16.0);
        assert_close(snapshot.average_ms, 16.0);
    }

    #[test]
    fn successful_present_timeline_reconstructs_exact_interval_metrics() {
        let mut pacing = FramePacing::default();
        let start = Instant::now();
        pacing.begin_session(1);
        pacing.record_frame_at(start, 30, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(10), 31, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(30), 32, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(35), 33, true, 0);

        let mut raw = [0.0; FRAME_PACING_HISTORY];
        let raw_count = pacing.copy_chronological_samples(&mut raw);
        assert_eq!(raw_count, 3);
        for (actual, expected) in raw[..raw_count].iter().zip([10.0, 20.0, 5.0]) {
            assert_close(*actual, expected);
        }

        let snapshot = pacing.snapshot();
        assert_eq!(snapshot.sample_count, 3);
        assert_eq!(snapshot.rejected_intervals, 0);
        assert_close(snapshot.average_ms, 35.0 / 3.0);
        assert_close(snapshot.p50_ms, 10.0);
        assert_close(snapshot.p95_ms, 20.0);
        assert_close(snapshot.p99_ms, 20.0);
        assert_close(snapshot.worst_ms, 20.0);
        assert_close(snapshot.jitter_ms, 15.0);
    }

    #[test]
    fn a_failed_present_origin_cannot_leak_into_the_next_interval() {
        let mut pacing = FramePacing::default();
        let start = Instant::now();
        pacing.begin_session(1);
        pacing.record_frame_at(start, 20, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(16), 21, true, 0);
        pacing.reject_current_present();
        pacing.record_frame_at(start + Duration::from_millis(80), 23, true, 0);
        pacing.record_frame_at(start + Duration::from_millis(96), 24, true, 0);

        let snapshot = pacing.snapshot();
        assert_eq!(snapshot.sample_count, 2);
        assert_eq!(snapshot.rejected_intervals, 1);
        assert_close(snapshot.worst_ms, 16.0);
    }

    #[test]
    fn diagnostics_hot_path_has_no_allocation_sort_logging_or_locking() {
        let source = include_str!("runtime.rs");
        let start = source
            .find("fn record_sample_with_interval")
            .expect("frame-pacing capture");
        let end = source[start..]
            .find("fn publish_snapshot")
            .map(|offset| start + offset)
            .expect("snapshot publication");
        let capture = &source[start..end];

        for forbidden in [
            "Vec<",
            "vec![",
            "format!(",
            "sort_by",
            "Instant::now",
            "log::",
            ".lock(",
        ] {
            assert!(
                !capture.contains(forbidden),
                "capture hot path contains {forbidden}"
            );
        }

        let finish_start = source
            .find("    fn finish_present_frame(\n        &mut self,")
            .expect("finish-present callback");
        let finish_end = source[finish_start..]
            .find("fn release_for_new_device")
            .map(|offset| finish_start + offset)
            .expect("finish-present boundary");
        let finish = &source[finish_start..finish_end];
        let disabled_return = finish
            .find("if !diagnostics_active && !depth_of_field_active")
            .expect("disabled diagnostics early return");
        let failed_present = finish
            .find("let Some(now) = present_started_at")
            .expect("successful-present gate");
        assert!(disabled_return < failed_present);

        let capture_start = source
            .find("pub(crate) fn present_frame_started_at")
            .expect("present-start capture");
        let public_start = source[capture_start..]
            .find("pub(crate) unsafe fn finish_present_frame")
            .map(|offset| capture_start + offset)
            .expect("public finish-present callback");
        let capture = &source[capture_start..public_start];
        let diagnostics_gate = capture
            .find("diagnostics_active || PRESENT_FRAME_TIMING_NEEDED")
            .expect("top-level diagnostics gate");
        let timestamp = capture
            .find(".then(Instant::now)")
            .expect("present-start timestamp");
        assert!(diagnostics_gate < timestamp);

        let public_end = source[public_start..]
            .find("fn runtime_lock_telemetry")
            .map(|offset| public_start + offset)
            .expect("public finish-present boundary");
        let public_finish = &source[public_start..public_end];
        let runtime_lock = public_finish
            .find("RUNTIME.try_lock")
            .expect("runtime acquisition");
        assert!(!public_finish.contains("Instant::now"));
        assert!(
            public_finish
                .find("if diagnostics_session.is_none()")
                .unwrap()
                < runtime_lock
        );
    }

    #[test]
    fn diagnostics_storage_and_snapshot_work_have_fixed_small_bounds() {
        assert_eq!(FRAME_PACING_HISTORY, 2_048);
        assert_eq!(FRAME_PACING_CHART_POINTS, 100);
        assert_eq!(super::FRAME_PACING_SPIKE_MEMORY, 64);
        assert_eq!(super::FRAME_PACING_HISTOGRAM_BINS, 4_096);
        assert!(std::mem::size_of::<FramePacing>() <= 16 * 1024);
    }

    #[test]
    fn production_frame_delta_is_independent_of_menu_diagnostics() {
        let mut timing = PresentFrameTiming::default();
        let start = Instant::now();
        timing.record_frame_at(start, 40, true);
        timing.record_frame_at(start + Duration::from_millis(20), 41, true);
        assert_close(timing.frame_seconds(), 0.020);

        timing.record_frame_at(start + Duration::from_millis(30), 42, false);
        assert_close(timing.frame_seconds(), 1.0 / 60.0);
    }

    #[test]
    fn production_frame_delta_rejects_a_missing_present_callback() {
        let mut timing = PresentFrameTiming::default();
        let start = Instant::now();
        timing.record_frame_at(start, 100, true);
        timing.record_frame_at(start + Duration::from_millis(20), 101, true);
        assert_close(timing.frame_seconds(), 0.020);

        timing.record_frame_at(start + Duration::from_millis(70), 103, true);
        assert_close(timing.frame_seconds(), 1.0 / 60.0);

        timing.record_frame_at(start + Duration::from_millis(90), 104, true);
        assert_close(timing.frame_seconds(), 0.020);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuSelection {
    NativePbr,
    NativeSky,
    Shader(usize),
}

#[derive(Clone, Copy)]
struct EngineFeatureStatus {
    pbr: pbr::NativePbrRuntimeStatus,
    sky: sky::NativeSkyStatus,
}

impl Default for MenuSelection {
    fn default() -> Self {
        Self::NativePbr
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MenuAction {
    #[default]
    None,
    Save,
    Reload,
}

#[derive(Clone, Copy, Debug, Default)]
struct MenuFrameResult {
    changed: bool,
    action: MenuAction,
}

#[derive(Clone, Copy, Debug, Default)]
struct MenuHeaderResult {
    sources_changed: bool,
    settings_changed: bool,
    action: MenuAction,
}

#[derive(Clone, Copy)]
struct MenuPersistenceView<'a> {
    dirty: bool,
    error: Option<&'a str>,
    notice: Option<&'a str>,
}

const MENU_MUTED_TEXT: [f32; 4] = [0.56, 0.62, 0.67, 1.0];
const MENU_GOOD_TEXT: [f32; 4] = [0.35, 0.88, 0.78, 1.0];
const MENU_WARN_TEXT: [f32; 4] = [0.95, 0.70, 0.30, 1.0];
const MENU_ERROR_TEXT: [f32; 4] = [1.0, 0.40, 0.35, 1.0];
const MENU_ACCENT_TEXT: [f32; 4] = [0.58, 0.86, 0.96, 1.0];
const MENU_SAVE_BUTTON: [f32; 4] = [0.10, 0.42, 0.29, 1.0];
const MENU_SAVE_BUTTON_HOVERED: [f32; 4] = [0.14, 0.61, 0.39, 1.0];
const MENU_SAVE_BUTTON_ACTIVE: [f32; 4] = [0.08, 0.74, 0.44, 1.0];
const MENU_RELOAD_BUTTON: [f32; 4] = [0.43, 0.27, 0.08, 1.0];
const MENU_RELOAD_BUTTON_HOVERED: [f32; 4] = [0.67, 0.42, 0.10, 1.0];
const MENU_RELOAD_BUTTON_ACTIVE: [f32; 4] = [0.86, 0.54, 0.12, 1.0];
fn draw_shader_menu(
    ui: &mut psycho_imgui::Ui<'_>,
    menu_config: &mut GraphicsMenuConfig,
    sources: &mut [ScreenShaderSource],
    selected_item: &mut MenuSelection,
    frame_pacing: &FramePacingSnapshot,
    feature_status: EngineFeatureStatus,
    persistence: MenuPersistenceView<'_>,
) -> MenuFrameResult {
    ui.set_next_window_centered(
        0.82,
        0.86,
        840.0,
        560.0,
        1180.0,
        860.0,
        psycho_imgui::Condition::FirstUseEver,
    );

    let title = cstring("OH MY VEGAS // GRAPHICS WORKBENCH");
    let window = ui.window(&title, None);
    if !window.is_visible() {
        return MenuFrameResult::default();
    }

    let header = draw_shader_menu_header(
        ui,
        menu_config,
        sources,
        frame_pacing,
        persistence.dirty,
        persistence.error,
        persistence.notice,
    );
    let mut result = MenuFrameResult {
        changed: header.sources_changed || header.settings_changed,
        action: header.action,
    };
    if header.sources_changed {
        shaders::sync_embedded_effect_config(sources, &mut menu_config.embedded_effects);
    }
    ui.separator();
    result.changed |= draw_global_config(ui, menu_config);
    ui.separator();

    clamp_menu_selection(sources, selected_item);
    let available_width = ui.content_region_available_width().max(1.0);
    let list_width = (available_width * 0.28)
        .clamp(260.0, 380.0)
        .min((available_width - 320.0).max(180.0));

    {
        let item_list = cstring("graphics_feature_list");
        let child = ui.child(&item_list, list_width, 0.0, true);
        if child.is_visible() {
            draw_feature_list(
                ui,
                menu_config,
                sources,
                selected_item,
                feature_status.pbr,
                feature_status.sky,
            );
        }
    }

    ui.same_line();

    {
        let item_details = cstring("graphics_feature_details");
        let child = ui.child(&item_details, 0.0, 0.0, true);
        if child.is_visible() {
            match *selected_item {
                MenuSelection::NativePbr => {
                    result.changed |=
                        draw_native_pbr_config(ui, &mut menu_config.native_pbr, feature_status.pbr);
                }
                MenuSelection::NativeSky => {
                    result.changed |=
                        draw_native_sky_config(ui, &mut menu_config.native_sky, feature_status.sky);
                }
                MenuSelection::Shader(index) => {
                    if let Some(source) = sources.get_mut(index) {
                        let is_embedded = source.is_embedded_effect();
                        let source_changed = draw_shader_details(ui, source);
                        if source_changed && is_embedded {
                            shaders::sync_embedded_effect_config(
                                sources,
                                &mut menu_config.embedded_effects,
                            );
                        }
                        result.changed |= source_changed;
                    }
                }
            }
        }
    }

    result
}

fn draw_shader_menu_header(
    ui: &mut psycho_imgui::Ui<'_>,
    menu_config: &mut GraphicsMenuConfig,
    sources: &mut [ScreenShaderSource],
    frame_pacing: &FramePacingSnapshot,
    menu_config_dirty: bool,
    menu_config_error: Option<&str>,
    menu_config_notice: Option<&str>,
) -> MenuHeaderResult {
    let mut result = MenuHeaderResult::default();
    let (enabled_count, error_count, scene_count, final_count) = shader_counts(sources);
    let title = cstring("OMV RENDER LAB");
    ui.text_colored(MENU_ACCENT_TEXT, &title);
    let session = if menu_config_dirty {
        cstring("SESSION MODIFIED // NOT SAVED")
    } else {
        cstring("SESSION MATCHES DISK")
    };
    ui.text_colored(
        if menu_config_dirty {
            MENU_WARN_TEXT
        } else {
            MENU_GOOD_TEXT
        },
        &session,
    );

    let subtitle =
        cstring("Live graphics tuning for the Mojave. Changes remain temporary until Save.");
    ui.text_colored(MENU_MUTED_TEXT, &subtitle);
    let controls_hint = cstring(
        "Ctrl-click a slider to type an exact number. Hold -/+ to repeat; Ctrl uses a larger step.",
    );
    ui.text_colored(MENU_MUTED_TEXT, &controls_hint);

    let save = cstring("SAVE TO DISK##config_save");
    if ui.button_colored(
        &save,
        MENU_SAVE_BUTTON,
        MENU_SAVE_BUTTON_HOVERED,
        MENU_SAVE_BUTTON_ACTIVE,
    ) {
        result.action = MenuAction::Save;
    }
    ui.same_line();
    let reload = cstring("RELOAD FROM DISK##config_reload");
    if ui.button_colored(
        &reload,
        MENU_RELOAD_BUTTON,
        MENU_RELOAD_BUTTON_HOVERED,
        MENU_RELOAD_BUTTON_ACTIVE,
    ) {
        result.action = MenuAction::Reload;
    }
    let path = cstring(crate::config::CONFIG_PATH);
    ui.spacing();
    ui.text_colored(MENU_MUTED_TEXT, &path);

    if let Some(error) = menu_config_error {
        let text = cstring(format!("Disk operation failed: {error}"));
        ui.text_colored(MENU_ERROR_TEXT, &text);
    } else if let Some(notice) = menu_config_notice {
        ui.text_colored(MENU_GOOD_TEXT, &cstring(notice));
    } else if menu_config_dirty {
        let warning = cstring("Reload discards every unsaved session edit.");
        ui.text_colored(MENU_WARN_TEXT, &warning);
    }

    ui.separator();
    let title = cstring("RENDER STACK");
    ui.text_colored(MENU_ACCENT_TEXT, &title);
    let summary = cstring(format!(
        "{} effects | {} enabled | {} scene | {} final | {} issue{}",
        sources.len(),
        enabled_count,
        scene_count,
        final_count,
        error_count,
        if error_count == 1 { "" } else { "s" }
    ));
    ui.text_colored(MENU_MUTED_TEXT, &summary);

    if !sources.is_empty() {
        let fraction = enabled_count as f32 / sources.len() as f32;
        let overlay = cstring(format!("{enabled_count}/{} enabled", sources.len()));
        ui.progress_bar(fraction, 220.0, 0.0, &overlay);
        ui.same_line();
    }

    let enable_all = cstring("Enable all");
    if ui.button(&enable_all) {
        result.sources_changed |= set_all_sources_enabled(sources, true);
    }
    ui.same_line();
    let disable_all = cstring("Disable all");
    if ui.button(&disable_all) {
        result.sources_changed |= set_all_sources_enabled(sources, false);
    }

    ui.spacing();
    result.settings_changed |= draw_frame_pacing_panel(
        ui,
        frame_pacing,
        &mut menu_config.frame_pacing_update_interval_ms,
    );

    result
}

fn draw_frame_pacing_panel(
    ui: &mut psycho_imgui::Ui<'_>,
    frame_pacing: &FramePacingSnapshot,
    update_interval_ms: &mut u32,
) -> bool {
    let mut changed = false;
    let heading = cstring(format!(
        "FRAME PACING // {:.2} S ROLLING WINDOW",
        frame_pacing.history_seconds
    ));
    ui.text_colored(MENU_ACCENT_TEXT, &heading);
    ui.same_line();
    ui.text_colored(MENU_MUTED_TEXT, &cstring("// UPDATE"));
    ui.same_line();
    let preview = frame_pacing_update_label(*update_interval_ms);
    let combo_label = cstring("##frame_pacing_update_interval");
    {
        let _width = ui.push_item_width(182.0);
        if ui.begin_combo(&combo_label, &preview) {
            for (interval_ms, label) in [
                (0, "Every frame // instant"),
                (50, "50 ms // 20 Hz"),
                (100, "100 ms // 10 Hz"),
                (250, "250 ms // 4 Hz"),
                (500, "500 ms // 2 Hz"),
                (1_000, "1 second"),
                (2_000, "2 seconds"),
            ] {
                let choice = cstring(format!("{label}##frame_pacing_update_{interval_ms}"));
                if ui.selectable(&choice, *update_interval_ms == interval_ms) {
                    *update_interval_ms = interval_ms;
                    changed = true;
                }
            }
            ui.end_combo();
        }
    }

    let live = cstring(format!(
        "LIVE {:>5.1} FPS / {:>5.2} ms (1 S EMA)",
        frame_pacing.fps, frame_pacing.live_ms
    ));
    ui.text_colored(frame_time_color(frame_pacing.live_ms), &live);
    ui.same_line();
    let average = cstring(format!(
        "AVG {:>5.1} FPS / {:>5.2} ms",
        frame_pacing.average_fps, frame_pacing.average_ms
    ));
    ui.text_colored(MENU_MUTED_TEXT, &average);
    ui.same_line();
    let one_percent_low = cstring(format!(
        "1% LOW (P99) {:>5.1} FPS",
        frame_pacing.one_percent_low_fps
    ));
    ui.text_colored(frame_time_color(frame_pacing.p99_ms), &one_percent_low);

    let distribution = cstring(format!(
        "RAW P50 {:>5.2} | P95 {:>5.2} | P99 {:>5.2} | WORST {:>6.2} | JITTER {:>5.2} | MAD {:>5.2} ms",
        frame_pacing.p50_ms,
        frame_pacing.p95_ms,
        frame_pacing.p99_ms,
        frame_pacing.worst_ms,
        frame_pacing.jitter_ms,
        frame_pacing.median_absolute_deviation_ms
    ));
    ui.text_colored(MENU_MUTED_TEXT, &distribution);
    let chart_contract = cstring(format!(
        "{} RAW CPU PRESENT INTERVALS // CHART = PAIR-NORMALIZED 100 MS TREND // SPIKES = FILTERED RAW IMPULSES",
        frame_pacing.sample_count
    ));
    ui.text_colored(MENU_MUTED_TEXT, &chart_contract);
    let quality_color = if frame_pacing.rejected_intervals == 0 {
        MENU_GOOD_TEXT
    } else {
        MENU_WARN_TEXT
    };
    let quality = cstring(format!(
        "DATA QUALITY // {} REJECTED INTERVAL{} THIS SESSION",
        frame_pacing.rejected_intervals,
        if frame_pacing.rejected_intervals == 1 {
            ""
        } else {
            "S"
        }
    ));
    ui.text_colored(quality_color, &quality);

    let contention = runtime_lock_telemetry();
    if contention.has_rejections() {
        let contention_text = cstring(format!(
            "PROCESS REJECTIONS // APPLY {} | FINISH {} | FAILED PRESENT {} | SCENE {} | COLOR {} | RESET {}",
            contention.present_apply,
            contention.present_finish,
            contention.failed_present,
            contention.scene_phase,
            contention.world_color,
            contention.reset,
        ));
        ui.text_colored(MENU_WARN_TEXT, &contention_text);
    }

    ui.text_colored(MENU_MUTED_TEXT, &cstring("BUDGET HIT //"));
    ui.same_line();
    let budget_60 = cstring(format!(
        "60 FPS {:>5.1}%",
        frame_pacing.budget_60_hit_percent
    ));
    ui.text_colored(
        budget_hit_color(frame_pacing.budget_60_hit_percent),
        &budget_60,
    );
    ui.same_line();
    ui.text_colored(MENU_MUTED_TEXT, &cstring("|"));
    ui.same_line();
    let budget_30 = cstring(format!(
        "30 FPS {:>5.1}%",
        frame_pacing.budget_30_hit_percent
    ));
    ui.text_colored(
        budget_hit_color(frame_pacing.budget_30_hit_percent),
        &budget_30,
    );
    ui.same_line();
    let graph_scale = cstring(format!("| FIXED GRAPH 0-{:.1} ms", frame_pacing.scale_max));
    ui.text_colored(MENU_MUTED_TEXT, &graph_scale);
    if frame_pacing.off_scale_samples > 0 {
        ui.same_line();
        let off_scale = cstring(format!(
            "| {} RAW OFF-SCALE FRAME{}",
            frame_pacing.off_scale_samples,
            if frame_pacing.off_scale_samples == 1 {
                ""
            } else {
                "S"
            }
        ));
        ui.text_colored(MENU_ERROR_TEXT, &off_scale);
    }

    draw_spike_summary(ui, frame_pacing);

    if frame_pacing.samples().len() > 1 {
        let label = cstring("##frame_pacing");
        let warning_label = cstring("60 FPS // 16.7 ms");
        let critical_label = cstring("30 FPS // 33.3 ms");
        let suffix = cstring(" ms");
        let chart = psycho_imgui::TelemetryChart {
            values: frame_pacing.samples(),
            scale_min: 0.0,
            scale_max: frame_pacing.scale_max,
            width: 0.0,
            height: 104.0,
            warning_threshold: FRAME_BUDGET_60_MS,
            critical_threshold: FRAME_BUDGET_30_MS,
            danger_below: false,
            sample_interval_seconds: FRAME_PACING_CHART_INTERVAL_MS * 0.001,
            impulse_from_zero: false,
            line_color: MENU_ACCENT_TEXT,
            fill_color: [0.20, 0.66, 0.78, 0.16],
            warning_label: &warning_label,
            critical_label: &critical_label,
            value_suffix: &suffix,
        };
        ui.telemetry_chart(&label, &chart);

        let spike_label = cstring("##frame_pacing_spikes");
        let baseline_label = cstring("BASELINE // 0 ms");
        let no_label = cstring("");
        let spike_suffix = cstring(" ms vs baseline");
        let spike_chart = psycho_imgui::TelemetryChart {
            values: frame_pacing.spike_samples(),
            scale_min: -FRAME_PACING_SPIKE_CHART_MAX_MS,
            scale_max: FRAME_PACING_SPIKE_CHART_MAX_MS,
            width: 0.0,
            height: 70.0,
            warning_threshold: 0.0,
            critical_threshold: f32::NAN,
            danger_below: false,
            sample_interval_seconds: 0.0,
            impulse_from_zero: true,
            line_color: MENU_WARN_TEXT,
            fill_color: [0.95, 0.70, 0.30, 0.0],
            warning_label: &baseline_label,
            critical_label: &no_label,
            value_suffix: &spike_suffix,
        };
        ui.telemetry_chart(&spike_label, &spike_chart);
    } else {
        let collecting = cstring("Collecting frame history...");
        ui.text_colored(MENU_MUTED_TEXT, &collecting);
    }

    changed
}

fn frame_pacing_update_label(interval_ms: u32) -> CString {
    match interval_ms {
        0 => cstring("Every frame // instant"),
        50 => cstring("50 ms // 20 Hz"),
        100 => cstring("100 ms // 10 Hz"),
        250 => cstring("250 ms // 4 Hz"),
        500 => cstring("500 ms // 2 Hz"),
        1_000 => cstring("1 second"),
        2_000 => cstring("2 seconds"),
        custom => cstring(format!("{custom} ms // custom")),
    }
}

fn draw_spike_summary(ui: &mut psycho_imgui::Ui<'_>, frame_pacing: &FramePacingSnapshot) {
    let spikes = frame_pacing.spikes;
    let count = cstring(format!(
        "SPIKES // {} SLOW + {} FAST // {} RETAINED // BASELINE {:.2} ms",
        spikes.total_slow, spikes.total_fast, spikes.retained, frame_pacing.baseline_ms
    ));
    let count_color = if spikes.total_slow == 0 && spikes.total_fast == 0 {
        MENU_GOOD_TEXT
    } else {
        MENU_WARN_TEXT
    };
    ui.text_colored(count_color, &count);

    if let Some(periodic) = spikes.periodic {
        let periodic_text = cstring(format!(
            "PERIODIC {} // {:.2} s +/- {:.0} ms // {} repeats // {:.0}% confidence",
            periodic.direction.label(),
            periodic.interval_ms * 0.001,
            periodic.spread_ms,
            periodic.repeats,
            periodic.confidence_percent
        ));
        ui.text_colored(MENU_ERROR_TEXT, &periodic_text);
    } else {
        ui.text_colored(
            MENU_MUTED_TEXT,
            &cstring("PERIODICITY // no repeatable cadence detected"),
        );
    }

    if let Some(latest) = spikes.latest {
        let latest_text = cstring(format!(
            "LATEST {} / {} // {:.2} ms ({:+.2} from {:.2}) // {:.2} s ago",
            latest.direction.label(),
            latest.severity.label(),
            latest.frame_ms,
            latest.delta_ms,
            latest.baseline_ms,
            latest.age_ms * 0.001
        ));
        ui.text_colored(spike_severity_color(latest.severity), &latest_text);
    }

    let slow = spikes
        .largest_slow
        .map(|event| format!("SLOW {:.2} ms ({:+.2})", event.frame_ms, event.delta_ms))
        .unwrap_or_else(|| "SLOW --".to_owned());
    let fast = spikes
        .largest_fast
        .map(|event| format!("FAST {:.2} ms ({:+.2})", event.frame_ms, event.delta_ms))
        .unwrap_or_else(|| "FAST --".to_owned());
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(format!("LARGEST SESSION // {slow} // {fast}")),
    );
}

fn spike_severity_color(severity: SpikeSeverity) -> [f32; 4] {
    match severity {
        SpikeSeverity::Notice => MENU_WARN_TEXT,
        SpikeSeverity::Major | SpikeSeverity::Severe => MENU_ERROR_TEXT,
    }
}

fn frame_time_color(frame_ms: f32) -> [f32; 4] {
    if frame_ms > FRAME_BUDGET_30_MS {
        MENU_ERROR_TEXT
    } else if frame_ms > FRAME_BUDGET_60_MS {
        MENU_WARN_TEXT
    } else {
        MENU_GOOD_TEXT
    }
}

fn budget_hit_color(hit_percent: f32) -> [f32; 4] {
    if hit_percent >= 99.0 {
        MENU_GOOD_TEXT
    } else if hit_percent >= 90.0 {
        MENU_WARN_TEXT
    } else {
        MENU_ERROR_TEXT
    }
}

fn draw_global_config(ui: &mut psycho_imgui::Ui<'_>, config: &mut GraphicsMenuConfig) -> bool {
    let mut changed = false;

    let heading = cstring("SESSION CONTROLS");
    ui.separator_text(&heading);

    changed |= draw_config_checkbox(
        ui,
        "Master effects switch",
        "global.screen_space_shaders",
        &mut config.screen_space_shaders,
    );

    changed |= draw_menu_keybind_control(ui, &mut config.menu_toggle_key);

    let mut scan_interval = config.shader_scan_interval_ms.clamp(50, 5_000) as i32;
    if draw_int_slider(
        ui,
        "Shader hot-reload scan (ms)",
        "global.shader_scan_interval_ms",
        &mut scan_interval,
        50,
        5_000,
    ) {
        config.shader_scan_interval_ms = scan_interval.clamp(50, 5_000) as u64;
        changed = true;
    }

    changed |= draw_depth_provider_config(ui, &mut config.depth_provider);

    changed
}

fn draw_config_checkbox(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    value: &mut bool,
) -> bool {
    let checkbox = cstring(format!("{label}##{id}"));
    ui.checkbox(&checkbox, value)
}

fn draw_menu_keybind_control(ui: &mut psycho_imgui::Ui<'_>, key: &mut u32) -> bool {
    let mut changed = false;
    let pending_key = PENDING_MENU_TOGGLE_KEY.swap(0, Ordering::AcqRel);
    if pending_key != 0 {
        *key = sanitize_menu_toggle_key(pending_key);
        changed = true;
    }

    let normalized = sanitize_menu_toggle_key(*key);
    if normalized != *key {
        *key = normalized;
        changed = true;
    }

    let label = cstring("Menu key");
    ui.text(&label);
    ui.same_line();

    let key_text = cstring(virtual_key_label(*key));
    ui.text_colored(MENU_GOOD_TEXT, &key_text);
    ui.same_line();

    if MENU_KEY_CAPTURE_ACTIVE.load(Ordering::Acquire) {
        let listening = cstring("Listening...");
        ui.text_colored(MENU_WARN_TEXT, &listening);
        ui.same_line();

        let cancel = cstring("Cancel##global.menu_toggle_key.cancel");
        if ui.button(&cancel) {
            MENU_KEY_CAPTURE_ACTIVE.store(false, Ordering::Release);
            PENDING_MENU_TOGGLE_KEY.store(0, Ordering::Release);
        }
    } else {
        let change = cstring("Change##global.menu_toggle_key.capture");
        if ui.button(&change) {
            PENDING_MENU_TOGGLE_KEY.store(0, Ordering::Release);
            MENU_KEY_CAPTURE_ACTIVE.store(true, Ordering::Release);
        }
        ui.same_line();

        let reset = cstring("Reset##global.menu_toggle_key.reset");
        if ui.button(&reset) && *key != DEFAULT_MENU_TOGGLE_KEY {
            *key = DEFAULT_MENU_TOGGLE_KEY;
            changed = true;
        }
    }

    changed
}

fn draw_depth_provider_config(
    ui: &mut psycho_imgui::Ui<'_>,
    depth_provider: &mut DepthProviderConfig,
) -> bool {
    let provider_name = match depth_provider {
        DepthProviderConfig::None => "Disabled",
        DepthProviderConfig::FalloutNewVegas => "Fallout New Vegas native depth",
    };
    let text = cstring(format!("Depth source: {provider_name}"));
    ui.text(&text);

    let mut changed = false;
    let none = cstring("Disable depth##global.depth_provider.none");
    if ui.button(&none) && *depth_provider != DepthProviderConfig::None {
        *depth_provider = DepthProviderConfig::None;
        changed = true;
    }
    ui.same_line();
    let fnv = cstring("Use Fallout NV depth##global.depth_provider.fnv");
    if ui.button(&fnv) && *depth_provider != DepthProviderConfig::FalloutNewVegas {
        *depth_provider = DepthProviderConfig::FalloutNewVegas;
        changed = true;
    }

    changed
}

fn draw_native_pbr_config(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &mut crate::config::NativePbrConfig,
    status: pbr::NativePbrRuntimeStatus,
) -> bool {
    let heading = cstring("PBR MATERIALS");
    ui.separator_text(&heading);
    let subtitle = cstring("Native material response for terrain, architecture, and objects.");
    ui.text_colored(MENU_MUTED_TEXT, &subtitle);

    let any_shader_failure = status.active_contracts_failed
        || status.land_lod_contract_failed
        || status.terrain_fade_contract_failed
        || status.close_terrain_contract_failed;
    let any_resource_ready = status.object_resources_ready != 0
        || status.land_lod_resources_ready != 0
        || status.terrain_fade_resources_ready != 0
        || status.close_terrain_resources_ready != 0;
    let (status_color, status_text) = if let Some(reason) = status.block_reason {
        (MENU_WARN_TEXT, format!("Blocked: {reason}"))
    } else if status.installed && status.shader_enabled && any_shader_failure {
        (MENU_WARN_TEXT, "Active with per-draw fallback".to_owned())
    } else if status.installed && status.shader_enabled && !any_resource_ready {
        (MENU_WARN_TEXT, "Shader warmup".to_owned())
    } else if status.installed && status.shader_enabled {
        (
            MENU_GOOD_TEXT,
            "Active - exact pairs replace as soon as ready".to_owned(),
        )
    } else {
        (MENU_MUTED_TEXT, "Disabled".to_owned())
    };
    let status_text = cstring(status_text);
    ui.text_colored(status_color, &status_text);
    ui.separator();

    let mut changed = false;
    changed |= draw_config_checkbox(ui, "Enable PBR", "native_pbr.enabled", &mut config.enabled);

    if config.enabled {
        let section = cstring("LIVE PIPELINES");
        ui.separator_text(&section);
        draw_pbr_family_status(
            ui,
            "Objects",
            status.shader_enabled,
            status.object_contract_ready,
            status.object_resources_ready,
            status.object_bytecode_ready,
            status.object_shader_total,
            status.object_resources_failed + status.object_bytecode_failed,
            status.object_replacements_last_frame,
            status.object_fallbacks_last_frame,
        );
        draw_pbr_family_status(
            ui,
            "Close terrain",
            status.close_terrain_enabled,
            status.terrain_engine_contract_ready,
            status.close_terrain_resources_ready,
            status.close_terrain_bytecode_ready,
            status.close_terrain_shader_total,
            status.close_terrain_resources_failed + status.close_terrain_bytecode_failed,
            status.close_terrain_replacements_last_frame,
            status.close_terrain_fallbacks_last_frame,
        );
        draw_pbr_family_status(
            ui,
            "Terrain fade",
            status.terrain_fade_enabled,
            status.terrain_engine_contract_ready,
            status.terrain_fade_resources_ready,
            status.terrain_fade_bytecode_ready,
            status.terrain_fade_shader_total,
            status.terrain_fade_resources_failed + status.terrain_fade_bytecode_failed,
            status.terrain_fade_replacements_last_frame,
            status.terrain_fade_fallbacks_last_frame,
        );
        draw_pbr_family_status(
            ui,
            "LandLOD",
            status.terrain_lod_enabled,
            status.terrain_engine_contract_ready,
            status.land_lod_resources_ready,
            status.land_lod_bytecode_ready,
            status.land_lod_shader_total,
            status.land_lod_resources_failed + status.land_lod_bytecode_failed,
            status.land_lod_replacements_last_frame,
            status.land_lod_fallbacks_last_frame,
        );

        let section = cstring("OBJECT MATERIAL");
        ui.separator_text(&section);
        changed |= draw_float_slider(
            ui,
            "Roughness",
            "native_pbr.object_roughness_scale",
            &mut config.object_roughness_scale,
            0.05,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Light",
            "native_pbr.object_light_scale",
            &mut config.object_light_scale,
            0.0,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Ambient",
            "native_pbr.object_ambient_scale",
            &mut config.object_ambient_scale,
            0.0,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Material saturation",
            "native_pbr.object_albedo_saturation",
            &mut config.object_albedo_saturation,
            0.0,
            2.0,
        );
        let section = cstring("TERRAIN MATERIAL");
        ui.separator_text(&section);
        changed |= draw_float_slider(
            ui,
            "Metal response",
            "native_pbr.terrain_metallicness",
            &mut config.terrain_metallicness,
            0.0,
            1.0,
        );
        changed |= draw_float_slider(
            ui,
            "Roughness",
            "native_pbr.terrain_roughness_scale",
            &mut config.terrain_roughness_scale,
            0.05,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Light",
            "native_pbr.terrain_light_scale",
            &mut config.terrain_light_scale,
            0.0,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Ambient",
            "native_pbr.terrain_ambient_scale",
            &mut config.terrain_ambient_scale,
            0.0,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Material saturation",
            "native_pbr.terrain_albedo_saturation",
            &mut config.terrain_albedo_saturation,
            0.0,
            2.0,
        );
        let section = cstring("DISTANT TERRAIN DETAIL");
        ui.separator_text(&section);
        let scope = cstring(
            "Affects TerrainFade and LandLOD only; close terrain keeps native layer detail.",
        );
        ui.text_colored(MENU_MUTED_TEXT, &scope);
        changed |= draw_float_slider(
            ui,
            "Detail strength",
            "native_pbr.terrain_lod_noise_scale",
            &mut config.terrain_lod_noise_scale,
            0.0,
            1.0,
        );
        changed |= draw_float_slider(
            ui,
            "Detail tiling",
            "native_pbr.terrain_lod_noise_tile",
            &mut config.terrain_lod_noise_tile,
            0.05,
            16.0,
        );

        let section = cstring("TRANSITION DIAGNOSTICS");
        ui.separator_text(&section);
        changed |= draw_config_checkbox(
            ui,
            "Track object lighting transitions",
            "native_pbr.debug_log_draws",
            &mut config.debug_log_draws,
        );
        let diagnostic_cost = cstring(
            "Development aid: collected only while this menu is open; logs state changes, not every draw.",
        );
        ui.text_colored(MENU_MUTED_TEXT, &diagnostic_cost);
        if config.debug_log_draws {
            let transition = cstring(format!(
                "Last contract change: {} -> {}  |  changes last frame: {}",
                status.object_last_contract_transition_from,
                status.object_last_contract_transition_to,
                status.object_contract_transitions_last_frame,
            ));
            ui.text(&transition);
            let fallback = cstring(format!(
                "Last fallback: {}  |  row {}  |  selector 0x{:08X}",
                status.object_last_reject_reason,
                status.object_last_reject_row,
                status.object_last_reject_selector,
            ));
            ui.text(&fallback);
            if status.object_last_fade_geometry != 0 {
                let fade = cstring(format!(
                    "Specular fade: distance {:.2}  range {:.2}..{:.2}  expected {:.4}  staged {:.4}  c25.w {:.4}",
                    status.object_last_fade_distance,
                    status.object_last_fade_start,
                    status.object_last_fade_end,
                    status.object_last_fade_expected,
                    status.object_last_fade_staged,
                    status.object_last_fade_c25,
                ));
                ui.text(&fade);
                let identity = cstring(format!(
                    "Fade object: geometry 0x{:08X}  property 0x{:08X}  light capacity {} / 0x{:08X}",
                    status.object_last_fade_geometry,
                    status.object_last_fade_property,
                    status.object_last_light_capacity,
                    status.object_last_light_signature,
                ));
                ui.text_colored(MENU_MUTED_TEXT, &identity);
                let material = cstring(format!(
                    "Material resources: base 0x{:08X}  normal 0x{:08X}",
                    status.object_last_base_texture, status.object_last_normal_texture,
                ));
                ui.text_colored(MENU_MUTED_TEXT, &material);
            } else {
                let waiting = cstring("Waiting for a combined-specular object draw.");
                ui.text_colored(MENU_MUTED_TEXT, &waiting);
            }
        }
    }

    changed
}

#[allow(clippy::too_many_arguments)]
fn draw_pbr_family_status(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    enabled: bool,
    contract_ready: bool,
    resources_ready: usize,
    bytecode_ready: usize,
    total: usize,
    failed: usize,
    replacements: u32,
    fallbacks: u32,
) {
    let (color, state) = if !enabled {
        (MENU_MUTED_TEXT, "disabled".to_owned())
    } else if !contract_ready {
        (MENU_WARN_TEXT, "engine contract unavailable".to_owned())
    } else if failed != 0 {
        (
            MENU_WARN_TEXT,
            format!("degraded - {resources_ready}/{total} ready, {failed} failed"),
        )
    } else if resources_ready == total {
        (MENU_GOOD_TEXT, format!("ready {resources_ready}/{total}"))
    } else if resources_ready != 0 {
        (
            MENU_GOOD_TEXT,
            format!("live {resources_ready}/{total}; remaining variants warming"),
        )
    } else {
        (
            MENU_WARN_TEXT,
            format!("warming {}/{total}", bytecode_ready.max(resources_ready)),
        )
    };
    ui.text_colored(color, &cstring(format!("{label}: {state}")));
    if replacements != 0 || fallbacks != 0 {
        ui.text_colored(
            MENU_MUTED_TEXT,
            &cstring(format!(
                "  Last frame: {replacements} PBR draws, {fallbacks} vanilla fallbacks"
            )),
        );
    }
}

fn draw_native_sky_config(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &mut crate::config::NativeSkyConfig,
    status: sky::NativeSkyStatus,
) -> bool {
    let heading = cstring("NATIVE SKY");
    ui.separator_text(&heading);
    let subtitle = cstring("Atmosphere, celestial light, clouds, stars, and Mojave sunsets.");
    ui.text_colored(MENU_MUTED_TEXT, &subtitle);
    let (status_color, status_text) = if status.failed {
        (MENU_ERROR_TEXT, "Shader error".to_owned())
    } else if status.enabled && status.created == status.total {
        (MENU_GOOD_TEXT, "Active".to_owned())
    } else if status.enabled {
        (
            MENU_WARN_TEXT,
            format!(
                "Loading {}/{}",
                status.created.max(status.compiled),
                status.total
            ),
        )
    } else if status.installed {
        (MENU_MUTED_TEXT, "Disabled".to_owned())
    } else {
        (MENU_WARN_TEXT, "Hook unavailable".to_owned())
    };
    ui.text_colored(status_color, &cstring(status_text));
    ui.separator();

    let mut changed = false;
    changed |= draw_config_checkbox(ui, "Enable sky", "native_sky.enabled", &mut config.enabled);
    if !config.enabled {
        return changed;
    }

    let section = cstring("ATMOSPHERE AND SUN");
    ui.separator_text(&section);
    changed |= draw_float_slider(
        ui,
        "Atmosphere",
        "native_sky.atmosphere",
        &mut config.atmosphere_thickness,
        0.0,
        8.0,
    );
    changed |= draw_float_slider(
        ui,
        "Sun spread",
        "native_sky.sun_influence",
        &mut config.sun_influence,
        0.05,
        8.0,
    );
    changed |= draw_float_slider(
        ui,
        "Sun strength",
        "native_sky.sun_strength",
        &mut config.sun_strength,
        0.0,
        8.0,
    );
    changed |= draw_float_slider(
        ui,
        "Sun glare",
        "native_sky.glare_strength",
        &mut config.glare_strength,
        0.0,
        8.0,
    );
    changed |= draw_float_slider(
        ui,
        "Sky brightness",
        "native_sky.sky_multiplier",
        &mut config.sky_multiplier,
        0.0,
        4.0,
    );
    let section = cstring("CLOUD LAYER");
    ui.separator_text(&section);
    changed |= draw_float_slider(
        ui,
        "Cloud opacity",
        "native_sky.cloud_transparency",
        &mut config.cloud_transparency,
        0.05,
        1.0,
    );
    changed |= draw_float_slider(
        ui,
        "Cloud brightness",
        "native_sky.cloud_brightness",
        &mut config.cloud_brightness,
        0.0,
        4.0,
    );
    changed |= draw_config_checkbox(
        ui,
        "Normal-map clouds",
        "native_sky.cloud_normals",
        &mut config.cloud_normals,
    );
    let section = cstring("STARS AND SUNSET");
    ui.separator_text(&section);
    changed |= draw_float_slider(
        ui,
        "Star strength",
        "native_sky.star_strength",
        &mut config.star_strength,
        0.0,
        8.0,
    );
    changed |= draw_float_slider(
        ui,
        "Star twinkle",
        "native_sky.star_twinkle",
        &mut config.star_twinkle,
        0.0,
        8.0,
    );
    changed |= draw_config_checkbox(
        ui,
        "Weather sun color",
        "native_sky.use_sun_disk_color",
        &mut config.use_sun_disk_color,
    );
    changed |= draw_float_slider(
        ui,
        "Sunset red",
        "native_sky.sunset_red",
        &mut config.sunset_red,
        0.0,
        4.0,
    );
    changed |= draw_float_slider(
        ui,
        "Sunset green",
        "native_sky.sunset_green",
        &mut config.sunset_green,
        0.0,
        4.0,
    );
    changed |= draw_float_slider(
        ui,
        "Sunset blue",
        "native_sky.sunset_blue",
        &mut config.sunset_blue,
        0.0,
        4.0,
    );
    changed
}

fn draw_feature_list(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &GraphicsMenuConfig,
    sources: &[ScreenShaderSource],
    selected_item: &mut MenuSelection,
    pbr_status: pbr::NativePbrRuntimeStatus,
    sky_status: sky::NativeSkyStatus,
) {
    let heading = cstring("ENGINE RENDERING");
    ui.separator_text(&heading);
    let pbr_label = cstring(native_pbr_list_label(
        config.screen_space_shaders && config.native_pbr.enabled,
        pbr_status,
    ));
    if ui.selectable(&pbr_label, *selected_item == MenuSelection::NativePbr) {
        *selected_item = MenuSelection::NativePbr;
    }
    let sky_label = cstring(native_sky_list_label(
        config.screen_space_shaders && config.native_sky.enabled,
        sky_status,
    ));
    if ui.selectable(&sky_label, *selected_item == MenuSelection::NativeSky) {
        *selected_item = MenuSelection::NativeSky;
    }

    let heading = cstring("BUILT-IN EFFECTS");
    ui.separator_text(&heading);
    let mut embedded_count = 0usize;
    for (index, source) in sources.iter().enumerate() {
        if !source.is_embedded_effect() {
            continue;
        }
        embedded_count += 1;
        let label = cstring(shader_list_label(source, index));
        if ui.selectable(&label, *selected_item == MenuSelection::Shader(index)) {
            *selected_item = MenuSelection::Shader(index);
        }
    }
    if embedded_count == 0 {
        let empty = cstring("No embedded effects");
        ui.text_colored(MENU_MUTED_TEXT, &empty);
    }

    let heading = cstring("MOD SHADERS");
    ui.separator_text(&heading);
    let mut external_count = 0usize;
    for (index, source) in sources.iter().enumerate() {
        if !source.is_external_file() {
            continue;
        }
        external_count += 1;
        let label = cstring(shader_list_label(source, index));
        if ui.selectable(&label, *selected_item == MenuSelection::Shader(index)) {
            *selected_item = MenuSelection::Shader(index);
        }
    }
    if external_count == 0 {
        let empty = cstring(format!("No .hlsl files in {}", crate::shaders::SHADER_DIR));
        ui.text_colored(MENU_MUTED_TEXT, &empty);
    }
}

fn draw_shader_details(ui: &mut psycho_imgui::Ui<'_>, source: &mut ScreenShaderSource) -> bool {
    let mut changed = false;
    let name = cstring(shader_display_name(source));
    ui.separator_text(&name);

    if let Some(description) = embedded_effect_description(source.embedded_effect_kind()) {
        ui.text_colored(MENU_MUTED_TEXT, &cstring(description));
    }

    let mut enabled = source.enabled;
    let enabled_name =
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricLighting) {
            "Directional sun lighting"
        } else {
            "Enabled"
        };
    let enabled_label = cstring(format!("{enabled_name}##{}.enabled", source.name));
    if ui.checkbox(&enabled_label, &mut enabled) {
        if let Err(err) = source.set_enabled(enabled) {
            source.config_error = Some(format!("{err:#}"));
        } else {
            changed = true;
        }
    }

    draw_shader_status(ui, source);

    let source_kind = if source.is_embedded_effect() {
        "Type: embedded engine effect"
    } else {
        "Type: external HLSL shader"
    };
    let source_kind = cstring(source_kind);
    ui.text_colored(MENU_MUTED_TEXT, &source_kind);

    let stage = if source
        .embedded_effect_kind()
        .is_some_and(EmbeddedEffectKind::owns_world_boundary)
    {
        "World / before first-person and UI"
    } else {
        shader_phase_display(source.phase())
    };
    let phase_text = cstring(format!("Render stage: {stage}"));
    ui.text_colored(MENU_MUTED_TEXT, &phase_text);

    if source.is_external_file() {
        let path_text = cstring(format!("Shader: {}", source.path.display()));
        ui.text_wrapped(&path_text);
        let config_text = cstring(format!("Config: {}", source.config_path.display()));
        ui.text_wrapped(&config_text);
    } else {
        let config_text = cstring(format!("Config: {}", crate::config::CONFIG_PATH));
        ui.text_wrapped(&config_text);
    }
    if matches!(
        source.embedded_effect_kind(),
        Some(
            EmbeddedEffectKind::FastFxaa
                | EmbeddedEffectKind::Nfaa
                | EmbeddedEffectKind::Axaa
                | EmbeddedEffectKind::Dlaa
                | EmbeddedEffectKind::Smaa
                | EmbeddedEffectKind::TemporalAa
        )
    ) {
        let warning = cstring(
            "Enable one AA effect at a time. Stacking is supported for comparison but softens the image and adds cost.",
        );
        ui.text_colored(MENU_WARN_TEXT, &warning);
    }

    if let Some(error) = &source.shader_error {
        let text = cstring(format!("Shader error: {error}"));
        ui.text_colored(MENU_ERROR_TEXT, &text);
    }
    if let Some(error) = &source.config_error {
        let text = cstring(format!("Config error: {error}"));
        ui.text_colored(MENU_ERROR_TEXT, &text);
    }

    ui.spacing();
    if source.is_external_file() {
        let pass_heading = cstring("PASS SCHEDULE");
        ui.separator_text(&pass_heading);
        let mut pass_count = source.pass_count as i32;
        if draw_int_slider(
            ui,
            "Passes",
            &format!("{}.passes", source.name),
            &mut pass_count,
            1,
            8,
        ) {
            let pass_count = pass_count.clamp(1, 8) as u32;
            if let Err(err) = source.set_pass_count(pass_count) {
                source.config_error = Some(format!("{err:#}"));
            } else {
                changed = true;
            }
        }
    }

    if source.embedded_effect_kind() == Some(EmbeddedEffectKind::DepthOfField) {
        ui.spacing();
        let preset_heading = cstring("VISUAL PROFILES");
        ui.separator_text(&preset_heading);
        let hybrid = cstring("OMV Hybrid##dof_preset_hybrid");
        if ui.button(&hybrid) {
            changed |=
                shaders::apply_depth_of_field_preset(source, shaders::DepthOfFieldPreset::Hybrid);
        }
        ui.same_line();
        let eye = cstring("Eye Focus##dof_preset_eye");
        if ui.button(&eye) {
            changed |=
                shaders::apply_depth_of_field_preset(source, shaders::DepthOfFieldPreset::Eye);
        }
        ui.same_line();
        let souls = cstring("Souls Far DOF##dof_preset_souls");
        if ui.button(&souls) {
            changed |= shaders::apply_depth_of_field_preset(
                source,
                shaders::DepthOfFieldPreset::SoulsSoft,
            );
        }
    }

    if source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricFog) {
        ui.spacing();
        let calibration_heading = cstring("FOG CALIBRATION");
        ui.separator_text(&calibration_heading);
        let reset = cstring("Reset calibrated fog defaults##volumetric_fog.reset");
        if ui.button(&reset) {
            changed |= shaders::reset_volumetric_fog_defaults(source);
        }
        if let Some((distance_bound, transmittance)) = crate::fnv_world_pipeline::fog_estimate() {
            let estimate = cstring(format!(
                "Current bound: {:.0} units // estimated horizontal transmission: {:.1}%",
                distance_bound,
                transmittance * 100.0,
            ));
            ui.text_colored(MENU_MUTED_TEXT, &estimate);
        } else {
            let estimate =
                cstring("Fog estimate becomes available after one eligible world frame.");
            ui.text_colored(MENU_MUTED_TEXT, &estimate);
        }
    }

    ui.spacing();
    let option_heading = cstring("TUNING CONTROLS");
    ui.separator_text(&option_heading);
    if source.options.is_empty() {
        let text = cstring("No dynamic options");
        ui.text_colored(MENU_MUTED_TEXT, &text);
        return changed;
    }

    for option_index in 0..source.options.len() {
        let option = source.options[option_index].clone();
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricLighting)
            && option.key == "local_lights_enabled"
        {
            ui.spacing();
            let heading = cstring("LOCAL LIGHTS");
            ui.separator_text(&heading);
            let telemetry = crate::fnv_local_lights::telemetry();
            let hook_status = if !telemetry.hooks_ready {
                "capture hooks unavailable"
            } else if telemetry.capture_enabled {
                if telemetry.shadow_hook_ready {
                    "scene capture active; native shadows optional"
                } else {
                    "scene capture active; shadowless fallback"
                }
            } else {
                "capture disabled by local toggle or global graphics switch"
            };
            let status = cstring(format!(
                "{} // epochs={} scene={} rendered={} shadowed={} // shadow_slots={} accepted={} rejected={} overflow={} // R32F={} A8={} bad_format={}",
                hook_status,
                telemetry.traversals,
                telemetry.scene_lights,
                telemetry.rendered,
                telemetry.shadowed_lights,
                telemetry.captured,
                telemetry.accepted,
                telemetry.rejected,
                telemetry.overflow,
                telemetry.r32f,
                telemetry.a8r8g8b8,
                telemetry.rejected_formats,
            ));
            ui.text_colored(
                if telemetry.hooks_ready && telemetry.capture_enabled {
                    MENU_GOOD_TEXT
                } else {
                    MENU_WARN_TEXT
                },
                &status,
            );
            let lock_status = cstring(format!(
                "Nonblocking misses: capture={} publish={} consume={} reset={}",
                telemetry.staging_busy,
                telemetry.publish_busy,
                telemetry.consume_busy,
                telemetry.reset_busy,
            ));
            ui.text_colored(MENU_MUTED_TEXT, &lock_status);
            let local_quality = source
                .options
                .iter()
                .find(|option| option.key == "local_lights_quality")
                .and_then(|option| match option.value {
                    ShaderOptionValue::Integer(value) => Some(value),
                    _ => None,
                })
                .unwrap_or(1);
            let budget = match local_quality {
                0 => "Performance: quarter resolution, 2 lights, 4 samples, 2 shadowless draws",
                2 => "Ultra: half resolution, 4 lights, 10 samples, 2 shadowless draws",
                _ => "High: half resolution, 4 lights, 6 samples, 2 shadowless draws",
            };
            ui.text_colored(MENU_MUTED_TEXT, &cstring(budget));
        }
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::DepthOfField) {
            if !depth_of_field_option_visible(source, option.key.as_str()) {
                continue;
            }
            if let Some(section) = depth_of_field_option_section(option.key.as_str()) {
                ui.spacing();
                let heading = cstring(section.to_ascii_uppercase());
                ui.separator_text(&heading);
            }
        }

        match option.value {
            ShaderOptionValue::Float(value) => {
                let mut value = value;
                let atmosphere_density = matches!(
                    (source.embedded_effect_kind(), option.key.as_str()),
                    (
                        Some(EmbeddedEffectKind::VolumetricFog),
                        "density" | "height_density"
                    ) | (
                        Some(EmbeddedEffectKind::VolumetricLighting),
                        "medium_density"
                    )
                );
                let value_changed = if atmosphere_density {
                    draw_atmosphere_density_control(
                        ui,
                        option.label.as_str(),
                        &format!("{}.{}", source.name, option.key),
                        &mut value,
                        option.max,
                    )
                } else {
                    draw_float_slider(
                        ui,
                        option.label.as_str(),
                        &format!("{}.{}", source.name, option.key),
                        &mut value,
                        option.min,
                        option.max,
                    )
                };
                if value_changed {
                    if let Err(err) = source.set_option_float(option_index, value) {
                        source.config_error = Some(format!("{err:#}"));
                    } else {
                        changed = true;
                    }
                }
            }
            ShaderOptionValue::Integer(value) => {
                let selected = if let Some(choices) = option.choices.as_ref() {
                    let label =
                        cstring(format!("{}##{}.{}", option.label, source.name, option.key));
                    let preview = choices
                        .get(value.max(0) as usize)
                        .map(String::as_str)
                        .unwrap_or("No LUT files found");
                    let preview = cstring(preview);
                    let mut selected = None;
                    if ui.begin_combo(&label, &preview) {
                        for (choice_index, choice) in choices.iter().enumerate() {
                            let choice_label = cstring(format!(
                                "{}##{}.{}.{}",
                                choice, source.name, option.key, choice_index
                            ));
                            if ui.selectable(&choice_label, value == choice_index as i32) {
                                selected = Some(choice_index as i32);
                            }
                        }
                        ui.end_combo();
                    }
                    selected
                } else {
                    let mut value = value;
                    let (min, max) = integer_option_bounds(&option);
                    draw_int_slider(
                        ui,
                        option.label.as_str(),
                        &format!("{}.{}", source.name, option.key),
                        &mut value,
                        min,
                        max,
                    )
                    .then_some(value)
                };

                if let Some(value) = selected {
                    if let Err(err) = source.set_option_integer(option_index, value) {
                        source.config_error = Some(format!("{err:#}"));
                    } else {
                        changed = true;
                    }
                }
            }
            ShaderOptionValue::Bool(value) => {
                let mut value = value;
                let label = cstring(format!("{}##{}.{}", option.label, source.name, option.key));
                if ui.checkbox(&label, &mut value) {
                    if let Err(err) = source.set_option_bool(option_index, value) {
                        source.config_error = Some(format!("{err:#}"));
                    } else {
                        changed = true;
                    }
                }
            }
        }
    }

    changed
}

fn depth_of_field_option_visible(source: &ScreenShaderSource, key: &str) -> bool {
    let focus_mode = source
        .options
        .iter()
        .find(|option| option.key == "focus_mode")
        .and_then(|option| match &option.value {
            ShaderOptionValue::Integer(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(0);
    let blur_style = source
        .options
        .iter()
        .find(|option| option.key == "blur_style")
        .and_then(|option| match &option.value {
            ShaderOptionValue::Integer(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(1);

    match key {
        "manual_focus_distance" => focus_mode == 1,
        "focus_sample_radius"
        | "focus_cluster_tolerance"
        | "focus_deadband"
        | "focus_near_seconds"
        | "focus_far_seconds" => focus_mode == 0,
        "softness" => blur_style == 1,
        _ => true,
    }
}

fn depth_of_field_option_section(key: &str) -> Option<&'static str> {
    match key {
        "respect_vanilla_dof" => Some("Pipeline"),
        "focus_mode" => Some("Focus"),
        "focus_range" => Some("Optical blur"),
        "distant_blur_strength" => Some("Distant / Souls blur"),
        "softness" => Some("Reconstruction"),
        _ => None,
    }
}

fn draw_float_slider(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    value: &mut f32,
    min: f32,
    max: f32,
) -> bool {
    let label = cstring(label);
    let id = cstring(id);
    let step = float_control_step(min, max);
    let logarithmic = min > 0.0 && max / min >= 1_000.0;
    ui.precise_float(&label, &id, value, min, max, step, step * 10.0, logarithmic)
}

fn draw_atmosphere_density_control(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    value: &mut f32,
    max: f32,
) -> bool {
    const MIN_NONZERO_DENSITY: f32 = 0.0000001;

    let mut changed = false;
    let zero = cstring(format!("Zero##{id}.zero"));
    if ui.button(&zero) && *value != 0.0 {
        *value = 0.0;
        changed = true;
    }
    ui.same_line();

    let mut nonzero = if *value > 0.0 {
        *value
    } else {
        MIN_NONZERO_DENSITY
    };
    let label = cstring(label);
    let control_id = cstring(id);
    if ui.precise_float(
        &label,
        &control_id,
        &mut nonzero,
        MIN_NONZERO_DENSITY,
        max.max(MIN_NONZERO_DENSITY),
        MIN_NONZERO_DENSITY,
        0.000001,
        true,
    ) {
        *value = nonzero;
        changed = true;
    }
    changed
}

fn draw_int_slider(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    value: &mut i32,
    min: i32,
    max: i32,
) -> bool {
    let label = cstring(label);
    let id = cstring(id);
    let fast_step = if max.saturating_sub(min) <= 10 { 1 } else { 10 };
    ui.precise_int(&label, &id, value, min, max, fast_step)
}

fn float_control_step(min: f32, max: f32) -> f32 {
    let span = (max - min).abs();
    if !span.is_finite() || span <= f32::EPSILON {
        return 0.001;
    }

    let exponent = (span / 1_000.0).log10().floor();
    10.0_f32.powf(exponent).max(f32::EPSILON)
}

fn integer_option_bounds(option: &crate::shaders::ShaderOption) -> (i32, i32) {
    let min = finite_i32(option.min.round());
    let max = finite_i32(option.max.round());
    if min <= max { (min, max) } else { (max, min) }
}

fn finite_i32(value: f32) -> i32 {
    if !value.is_finite() {
        return 0;
    }

    value.clamp(i32::MIN as f32, i32::MAX as f32) as i32
}

fn draw_shader_status(ui: &mut psycho_imgui::Ui<'_>, source: &ScreenShaderSource) {
    let (color, label) = if shader_has_error(source) {
        (MENU_ERROR_TEXT, "Status: error")
    } else if !source.enabled {
        (MENU_WARN_TEXT, "Status: disabled")
    } else if source.bytecode.is_none() && source.is_external_file() {
        (MENU_ERROR_TEXT, "Status: no bytecode")
    } else {
        (MENU_GOOD_TEXT, "Status: active")
    };
    let text = cstring(label);
    ui.text_colored(color, &text);
}

fn shader_counts(sources: &[ScreenShaderSource]) -> (usize, usize, usize, usize) {
    let mut enabled_count = 0usize;
    let mut error_count = 0usize;
    let mut scene_count = 0usize;
    let mut final_count = 0usize;

    for source in sources {
        if source.enabled {
            enabled_count += 1;
        }
        if shader_has_error(source) {
            error_count += 1;
        }
        match source.phase() {
            ShaderPhase::ScenePreImageSpace | ShaderPhase::ScenePostImageSpace => scene_count += 1,
            ShaderPhase::FinalImageSpace => final_count += 1,
        }
    }

    (enabled_count, error_count, scene_count, final_count)
}

fn shader_list_label(source: &ScreenShaderSource, index: usize) -> String {
    let status = if shader_has_error(source) {
        "ERR"
    } else if source.enabled {
        "LIVE"
    } else {
        "OFF"
    };
    format!(
        "[{status}]  {}##shader_select_{index}",
        shader_display_name(source)
    )
}

fn shader_display_name(source: &ScreenShaderSource) -> String {
    if source.is_embedded_effect() {
        return source.name.clone();
    }

    let stem = source.name.trim_start_matches(|character: char| {
        character.is_ascii_digit() || matches!(character, '_' | '-' | '.' | ' ')
    });
    let mut display = String::new();
    for word in stem.split(['_', '-', '.']).filter(|word| !word.is_empty()) {
        if !display.is_empty() {
            display.push(' ');
        }
        if word
            .chars()
            .all(|character| !character.is_ascii_lowercase())
        {
            display.push_str(word);
            continue;
        }
        let mut characters = word.chars();
        if let Some(first) = characters.next() {
            display.extend(first.to_uppercase());
            display.extend(characters);
        }
    }
    if display.is_empty() {
        source.name.clone()
    } else {
        display
    }
}

fn shader_phase_display(phase: ShaderPhase) -> &'static str {
    match phase {
        ShaderPhase::ScenePreImageSpace => "Scene / before image-space",
        ShaderPhase::ScenePostImageSpace => "Scene / after image-space",
        ShaderPhase::FinalImageSpace => "Final image-space",
    }
}

fn embedded_effect_description(kind: Option<EmbeddedEffectKind>) -> Option<&'static str> {
    match kind {
        Some(EmbeddedEffectKind::FastAmbientOcclusion) => {
            Some("Broad ambient grounding for terrain, structures, and world geometry.")
        }
        Some(EmbeddedEffectKind::ContactAmbientOcclusion) => {
            Some("Fine contact shadows for creases, intersections, and close geometry.")
        }
        Some(EmbeddedEffectKind::VolumetricFog) => Some(
            "World-only supplemental exterior height and heterogeneous fog; Off uses production composition, modes 6/7 inspect the reduced medium, and mode 8 shows bilateral acceptance.",
        ),
        Some(EmbeddedEffectKind::VolumetricLighting) => Some(
            "World-only native-sun single scattering with deterministic depth-occluded shafts; lighting-only and shared-fog media use one dual-layer composition, while legacy Sunshafts remain independent.",
        ),
        Some(EmbeddedEffectKind::BloomingHdr) => {
            Some("Quarter-resolution atmospheric highlight bloom fused with final color output.")
        }
        Some(EmbeddedEffectKind::ColorGrade) => {
            Some("Display-referred grading, bundled OMV LUTs, debanding, grain, and film finish.")
        }
        Some(EmbeddedEffectKind::Sunshafts) => {
            Some("Depth-aware exterior god rays driven by the native sun contract.")
        }
        Some(EmbeddedEffectKind::DepthOfField) => {
            Some("Optical near focus, cinematic far blur, and soft Souls-style depth.")
        }
        Some(EmbeddedEffectKind::FastFxaa) => Some("Low-cost single-pass edge smoothing."),
        Some(EmbeddedEffectKind::Nfaa) => {
            Some("Normal-filter edge smoothing with mask and normal debug views.")
        }
        Some(EmbeddedEffectKind::Axaa) => {
            Some("Adaptive single-pass edge smoothing with bounded directional taps.")
        }
        Some(EmbeddedEffectKind::Dlaa) => Some("Two-pass directionally localized anti-aliasing."),
        Some(EmbeddedEffectKind::Smaa) => {
            Some("Three-pass LUT-free morphological AA using private edge and weight buffers.")
        }
        Some(EmbeddedEffectKind::TemporalAa) => Some(
            "World-only temporal resolve with engine projection jitter; first-person and UI stay unjittered.",
        ),
        None => None,
    }
}

fn native_pbr_list_label(configured_enabled: bool, status: pbr::NativePbrRuntimeStatus) -> String {
    let any_failure = status.active_contracts_failed
        || status.land_lod_contract_failed
        || status.terrain_fade_contract_failed
        || status.close_terrain_contract_failed;
    let any_resource_ready = status.object_resources_ready != 0
        || status.land_lod_resources_ready != 0
        || status.terrain_fade_resources_ready != 0
        || status.close_terrain_resources_ready != 0;
    let status = if status.block_reason.is_some() {
        "BLOCKED"
    } else if status.installed && configured_enabled && any_failure {
        "PARTIAL"
    } else if status.installed && configured_enabled && !any_resource_ready {
        "WARMUP"
    } else if status.installed && configured_enabled {
        "LIVE"
    } else if status.installed {
        "OFF"
    } else {
        "UNAVAILABLE"
    };
    format!("[{status}]  PBR Materials##native_pbr_select")
}

fn native_sky_list_label(configured_enabled: bool, status: sky::NativeSkyStatus) -> String {
    let state = if status.failed {
        "ERR"
    } else if !status.installed {
        "UNAVAILABLE"
    } else if configured_enabled && status.created == status.total {
        "LIVE"
    } else if configured_enabled {
        "WARMUP"
    } else {
        "OFF"
    };
    format!("[{state}]  Native Sky##native_sky_select")
}

fn shader_has_error(source: &ScreenShaderSource) -> bool {
    source.shader_error.is_some()
        || source.config_error.is_some()
        || (source.bytecode.is_none() && source.is_external_file())
}

fn set_all_sources_enabled(sources: &mut [ScreenShaderSource], enabled: bool) -> bool {
    let mut changed = false;
    for source in sources {
        let source_changed = source.enabled != enabled;
        if let Err(err) = source.set_enabled(enabled) {
            source.config_error = Some(format!("{err:#}"));
        } else if source_changed {
            changed = true;
        }
    }
    changed
}

fn clamp_menu_selection(sources: &[ScreenShaderSource], selected_item: &mut MenuSelection) {
    if let MenuSelection::Shader(index) = *selected_item
        && index >= sources.len()
    {
        *selected_item = MenuSelection::NativePbr;
    }
}

fn valid_hwnd(hwnd: *mut c_void) -> Option<*mut c_void> {
    if is_window(hwnd) { Some(hwnd) } else { None }
}

fn sanitize_menu_toggle_key(key: u32) -> u32 {
    if valid_virtual_key(key as usize).is_some() {
        key
    } else {
        DEFAULT_MENU_TOGGLE_KEY
    }
}

fn valid_virtual_key(value: usize) -> Option<u32> {
    (1..=255).contains(&value).then_some(value as u32)
}

fn virtual_key_label(key: u32) -> String {
    match key {
        0x08 => "Backspace".to_owned(),
        0x09 => "Tab".to_owned(),
        0x0D => "Enter".to_owned(),
        0x10 => "Shift".to_owned(),
        0x11 => "Ctrl".to_owned(),
        0x12 => "Alt".to_owned(),
        0x13 => "Pause".to_owned(),
        0x14 => "Caps Lock".to_owned(),
        0x1B => "Esc".to_owned(),
        0x20 => "Space".to_owned(),
        0x21 => "Page Up".to_owned(),
        0x22 => "Page Down".to_owned(),
        0x23 => "End".to_owned(),
        0x24 => "Home".to_owned(),
        0x25 => "Left".to_owned(),
        0x26 => "Up".to_owned(),
        0x27 => "Right".to_owned(),
        0x28 => "Down".to_owned(),
        0x2C => "Print Screen".to_owned(),
        0x2D => "Insert".to_owned(),
        0x2E => "Delete".to_owned(),
        0x30..=0x39 | 0x41..=0x5A => (key as u8 as char).to_string(),
        0x5B => "Left Win".to_owned(),
        0x5C => "Right Win".to_owned(),
        0x5D => "App Menu".to_owned(),
        0x60..=0x69 => format!("Numpad {}", key - 0x60),
        0x6A => "Numpad *".to_owned(),
        0x6B => "Numpad +".to_owned(),
        0x6C => "Separator".to_owned(),
        0x6D => "Numpad -".to_owned(),
        0x6E => "Numpad .".to_owned(),
        0x6F => "Numpad /".to_owned(),
        0x70..=0x87 => format!("F{}", key - 0x6F),
        0x90 => "Num Lock".to_owned(),
        0x91 => "Scroll Lock".to_owned(),
        0xA0 => "Left Shift".to_owned(),
        0xA1 => "Right Shift".to_owned(),
        0xA2 => "Left Ctrl".to_owned(),
        0xA3 => "Right Ctrl".to_owned(),
        0xA4 => "Left Alt".to_owned(),
        0xA5 => "Right Alt".to_owned(),
        0xBA => ";".to_owned(),
        0xBB => "=".to_owned(),
        0xBC => ",".to_owned(),
        0xBD => "-".to_owned(),
        0xBE => ".".to_owned(),
        0xBF => "/".to_owned(),
        0xC0 => "`".to_owned(),
        0xDB => "[".to_owned(),
        0xDC => "\\".to_owned(),
        0xDD => "]".to_owned(),
        0xDE => "'".to_owned(),
        _ => format!("VK 0x{key:02X}"),
    }
}

fn is_input_message(msg: u32) -> bool {
    matches!(
        msg,
        WM_KEYDOWN
            | WM_SYSKEYDOWN
            | WM_KEYUP
            | WM_SYSKEYUP
            | WM_CHAR
            | WM_MOUSEMOVE
            | WM_LBUTTONDOWN
            | WM_LBUTTONUP
            | WM_RBUTTONDOWN
            | WM_RBUTTONUP
            | WM_MBUTTONDOWN
            | WM_MBUTTONUP
            | WM_MOUSEWHEEL
            | WM_MOUSEHWHEEL
    )
}

fn cstring(text: impl AsRef<str>) -> CString {
    let mut bytes = text.as_ref().as_bytes().to_vec();
    for byte in &mut bytes {
        if *byte == 0 {
            *byte = b' ';
        }
    }
    bytes.push(0);

    unsafe { CString::from_vec_with_nul_unchecked(bytes) }
}

fn runtime_error(message: &'static str) -> WindowsError {
    log::warn!("{message}");
    direct3d_failure()
}

fn bind_depth_contract_constants(
    device: &Device9Ref<'_>,
    frame_inputs: &backend::FrameInputs,
) -> Direct3DResult<()> {
    let world = frame_inputs.depth.world_projection;
    let first_person = frame_inputs.depth.first_person_projection;
    let world_camera = if world.camera.available {
        world.camera
    } else {
        frame_inputs.camera
    };
    device.set_pixel_shader_constant_f(
        11,
        &[
            [
                world.reversed_depth_f32(),
                first_person.reversed_depth_f32(),
                world_camera.available_f32(),
                first_person.camera.available_f32(),
            ],
            [
                world_camera.frustum_left,
                world_camera.frustum_right,
                world_camera.frustum_bottom,
                world_camera.frustum_top,
            ],
            [
                first_person.camera.near_z,
                first_person.camera.far_z,
                first_person.camera.aspect_ratio,
                0.0,
            ],
            [
                first_person.camera.frustum_left,
                first_person.camera.frustum_right,
                first_person.camera.frustum_bottom,
                first_person.camera.frustum_top,
            ],
        ],
    )
}

fn fullscreen_quad(desc: &D3DSURFACE_DESC) -> [ScreenVertex; 4] {
    let width = desc.Width as f32;
    let height = desc.Height as f32;

    [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(width - 0.5, -0.5, 1.0, 0.0),
        ScreenVertex::new(-0.5, height - 0.5, 0.0, 1.0),
        ScreenVertex::new(width - 0.5, height - 0.5, 1.0, 1.0),
    ]
}
