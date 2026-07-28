//! Screen-space shader runtime and in-game menu.

use std::{
    ffi::{CString, c_void},
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering},
    },
    time::Instant,
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
    winapi::{
        get_active_window, is_window, query_performance_counter, query_performance_frequency,
    },
};
use parking_lot::Mutex;

use crate::{
    asset_scanner::AssetScanner,
    backend::{self, DepthFrame, DepthProvider},
    config::{DepthProviderConfig, GraphicsMenuConfig},
    current_look::{
        AutosaveCoordinator, CurrentLookEvent, CurrentLookOperation, CurrentLookService,
        CurrentLookSnapshot,
    },
    effects::{
        ambient_occlusion, anti_aliasing, atmosphere, blooming_hdr, depth_of_field, motion_blur,
        pbr, sky, sunshafts,
    },
    luts,
    presets::{
        PresetActiveState, PresetCatalog, PresetEvent, PresetKey, PresetPublishRequest,
        PresetService, suggest_next_patch_version,
    },
    render_state::{
        RenderAttachments, RenderTargetSlots, copy_scene_color_for_sampling,
        finish_render_transaction,
    },
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
static MASTER_EFFECTS_ENABLED: AtomicBool = AtomicBool::new(true);
static MENU_DIAGNOSTICS_STATE: AtomicU32 = AtomicU32::new(0);
static MENU_TOGGLE_KEY: AtomicU32 = AtomicU32::new(DEFAULT_MENU_TOGGLE_KEY);
static MENU_KEY_CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING_MENU_TOGGLE_KEY: AtomicU32 = AtomicU32::new(0);
static CURRENT_LOOK_FLUSH_REQUEST: AtomicBool = AtomicBool::new(false);
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
    PERFORMANCE_COUNTER_FREQUENCY.store(
        query_performance_frequency().unwrap_or(0).max(0),
        Ordering::Release,
    );
    MENU_TOGGLE_KEY.store(
        sanitize_menu_toggle_key(settings.menu_toggle_key),
        Ordering::Release,
    );
    MASTER_EFFECTS_ENABLED.store(settings.menu_config.screen_space_shaders, Ordering::Release);
    update_native_dof_query_needed(&settings.menu_config);
    let mut runtime = RUNTIME.lock();
    runtime.configure(settings);
}

pub(crate) fn prepare_for_game_load() {
    MENU_OPEN.store(false, Ordering::Release);
    MENU_KEY_CAPTURE_ACTIVE.store(false, Ordering::Release);
    PENDING_MENU_TOGGLE_KEY.store(0, Ordering::Release);
    CURRENT_LOOK_FLUSH_REQUEST.store(true, Ordering::Release);
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

#[cfg(test)]
mod render_callback_io_tests {
    use super::present_services_required_for;

    #[test]
    fn periodic_asset_scans_never_run_on_the_render_thread() {
        let source = include_str!("runtime.rs");
        let lut_scan = ["luts::", "scan_luts("].concat();
        let shader_scan = ["shaders::", "scan_screen_shaders("].concat();
        let shader_compile = ["compile_hlsl_", "uncached("].concat();
        let cache_commit = ["commit_hlsl_", "cache("].concat();
        let config_save = ["save_menu_", "config("].concat();
        let config_reload = ["load_menu_config_", "from_disk("].concat();
        let sidecar_save = ["save_config_", "to_disk("].concat();
        let sidecar_reload = ["reload_external_shader_", "configs("].concat();

        assert!(!source.contains(&lut_scan));
        assert!(!source.contains(&shader_scan));
        assert!(!source.contains(&shader_compile));
        assert!(!source.contains(&cache_commit));
        assert!(!source.contains(&config_save));
        assert!(!source.contains(&config_reload));
        assert!(!source.contains(&sidecar_save));
        assert!(!source.contains(&sidecar_reload));
    }

    #[test]
    fn disabled_master_keeps_only_the_live_menu_boundary() {
        assert!(!present_services_required_for(false, false, true));
        assert!(present_services_required_for(false, true, true));
        assert!(present_services_required_for(false, false, false));
        assert!(present_services_required_for(true, false, true));
    }

    #[test]
    fn rejected_depth_effects_exit_before_creation_and_backbuffer_copy() {
        let source = include_str!("runtime.rs");
        for (suffix, predicate) in [
            (
                "ambient_occlusion_pipeline(",
                "ambient_occlusion::should_draw",
            ),
            ("sunshafts_pipeline(", "sunshafts::should_draw"),
            ("depth_of_field_pipeline(", "depth_of_field::should_draw"),
        ] {
            let function = ["\n    fn draw_", suffix].concat();
            let body = source
                .split_once(&function)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once("\n    fn "))
                .map(|(body, _)| body)
                .expect("effect pipeline body");
            let preflight = body
                .find(predicate)
                .expect("effect applicability preflight");
            let creation = body
                .find("::create(device)")
                .expect("effect resource creation");
            let copy = body
                .find("copy_phase_color_for_sampling")
                .expect("backbuffer copy");
            assert!(preflight < creation);
            assert!(preflight < copy);
        }

        let motion_function = ["\n    fn draw_motion_", "blur_pipeline("].concat();
        let motion_body = source
            .split_once(&motion_function)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    fn "))
            .map(|(body, _)| body)
            .expect("motion-blur pipeline body");
        let prepared = motion_body
            .find("prepared_motion_blur_frame.take()")
            .expect("motion preflight packet");
        let creation = motion_body
            .find("MotionBlurEffect::create(device)")
            .expect("motion shader creation");
        let copy = motion_body
            .find("copy_phase_color_for_sampling")
            .expect("motion color copy");
        assert!(prepared < creation);
        assert!(prepared < copy);
    }

    #[test]
    fn a_phase_with_only_rejected_effects_allocates_no_color_copy() {
        let source = include_str!("runtime.rs");
        for suffix in ["present_frame(", "scene_phase("] {
            let function = ["\n    unsafe fn apply_", suffix].concat();
            let body = source
                .split_once(&function)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once("\n    fn "))
                .map(|(body, _)| body)
                .expect("phase body");
            let preflight = body
                .find("phase_has_applicable_work")
                .expect("phase applicability preflight");
            let allocation = body
                .find("ensure_phase_color_copy")
                .expect("phase color-copy allocation");
            let state_block = body
                .find("ensure_state_block")
                .expect("phase D3D state-block preparation");
            assert!(preflight < allocation);
            assert!(preflight < state_block);
        }
    }

    #[test]
    fn every_phase_color_write_uses_the_feedback_safe_copy_helper() {
        let source = include_str!("runtime.rs");
        for suffix in [
            "passes(",
            "ambient_occlusion_pipeline(",
            "anti_aliasing_pipeline(",
            "final_color_pipeline(",
            "sunshafts_pipeline(",
            "depth_of_field_pipeline(",
            "motion_blur_pipeline(",
        ] {
            let function = ["\n    fn draw_", suffix].concat();
            let body = source
                .split_once(&function)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once("\n    fn "))
                .map(|(body, _)| body)
                .expect("screen effect pipeline body");
            assert!(
                body.contains("copy_phase_color_for_sampling("),
                "{function} can write the phase copy without unbinding all aliases"
            );
            assert!(
                !body.contains("device.stretch_rect("),
                "{function} bypasses the phase-copy hazard guard"
            );
        }
    }

    #[test]
    fn screen_transactions_restore_attachments_before_state_blocks() {
        let source = include_str!("runtime.rs");
        for suffix in ["present_frame(", "scene_phase("] {
            let function = ["\n    unsafe fn apply_", suffix].concat();
            let body = source
                .split_once(&function)
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once("\n    fn "))
                .map(|(body, _)| body)
                .expect("screen transaction body");
            let capture = body
                .find("RenderAttachments::capture")
                .expect("render attachment capture");
            let draw = body.find("draw_passes").expect("screen draw");
            let restore = body
                .find("finish_render_transaction")
                .expect("ordered render transaction restore");

            assert!(capture < draw);
            assert!(draw < restore);
        }

        let transaction = include_str!("render_state.rs");
        let function = ["pub(crate) fn finish_render_", "transaction("].concat();
        let body = transaction
            .split_once(&function)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("render transaction restore body");
        let attachments = body
            .find("attachments.restore")
            .expect("render attachment restore");
        let state_apply = body
            .find("StateBlock9::apply")
            .expect("state-block restore");
        assert!(
            attachments < state_apply,
            "SetRenderTarget must precede viewport/scissor restoration"
        );
    }
}

pub(crate) fn needs_native_dof_query() -> bool {
    NATIVE_DOF_QUERY_NEEDED.load(Ordering::Acquire)
}

#[inline]
pub(crate) fn effects_enabled() -> bool {
    MASTER_EFFECTS_ENABLED.load(Ordering::Acquire)
}

#[inline]
pub(crate) fn present_services_required() -> bool {
    present_services_required_for(
        effects_enabled(),
        MENU_OPEN.load(Ordering::Acquire),
        IMGUI_READY.load(Ordering::Acquire),
    )
}

fn present_services_required_for(
    effects_enabled: bool,
    menu_open: bool,
    imgui_ready: bool,
) -> bool {
    effects_enabled || menu_open || !imgui_ready
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
    if !effects_enabled() {
        return;
    }
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
    if !effects_enabled() {
        return;
    }
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
    if !effects_enabled() {
        return;
    }
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

#[derive(Clone, Copy)]
pub(crate) struct PresentFrameStart {
    performance_counter: Option<i64>,
    production_instant: Option<Instant>,
}

pub(crate) fn present_frame_started_at() -> PresentFrameStart {
    PresentFrameStart {
        performance_counter: query_performance_counter().ok(),
        production_instant: PRESENT_FRAME_TIMING_NEEDED
            .load(Ordering::Acquire)
            .then(Instant::now),
    }
}

pub(crate) unsafe fn finish_present_frame(
    render_epoch: u32,
    present_started_at: PresentFrameStart,
    present_succeeded: bool,
) {
    if !present_succeeded {
        PRESENT_FAILED.fetch_add(1, Ordering::Relaxed);
    }
    record_continuous_present_interval(
        present_started_at.performance_counter,
        render_epoch,
        present_succeeded,
    );

    if !PRESENT_FRAME_TIMING_NEEDED.load(Ordering::Acquire) {
        return;
    }
    let Some(mut runtime) = RUNTIME.try_lock() else {
        PRESENT_FINISH_BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };

    runtime.begin_render_epoch(render_epoch);
    runtime.finish_present_frame(
        render_epoch,
        present_succeeded
            .then_some(present_started_at.production_instant)
            .flatten(),
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
        set_menu_diagnostics_active(false);
        crate::input::set_menu_input_blocked(open);
        if !open {
            MENU_KEY_CAPTURE_ACTIVE.store(false, Ordering::Release);
            PENDING_MENU_TOGGLE_KEY.store(0, Ordering::Release);
            CURRENT_LOOK_FLUSH_REQUEST.store(true, Ordering::Release);
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

struct ActivePreset {
    key: PresetKey,
    name: String,
    version: String,
    payload_revision: u64,
    built_in: bool,
    modified: bool,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum PresetUiView {
    #[default]
    Closed,
    Manager,
    Update,
    Create,
}

struct PresetUiState {
    service: Option<PresetService>,
    catalog: PresetCatalog,
    selected: Option<usize>,
    pending_published: Option<PresetKey>,
    pending_saved_state: Option<PresetActiveState>,
    saved_state_loaded: bool,
    active: Option<ActivePreset>,
    catalog_page: usize,
    filter: [u8; 96],
    create_name: [u8; 81],
    create_version: [u8; 65],
    create_author: [u8; 81],
    create_description: [u8; 513],
    update_version: [u8; 65],
    create_pending: bool,
    update_pending: bool,
    view: PresetUiView,
    show_technical_details: bool,
    notice: Option<String>,
    error: Option<String>,
}

impl Default for PresetUiState {
    fn default() -> Self {
        let mut state = Self {
            service: None,
            catalog: PresetCatalog::default(),
            selected: None,
            pending_published: None,
            pending_saved_state: None,
            saved_state_loaded: false,
            active: None,
            catalog_page: 0,
            filter: [0; 96],
            create_name: [0; 81],
            create_version: [0; 65],
            create_author: [0; 81],
            create_description: [0; 513],
            update_version: [0; 65],
            create_pending: false,
            update_pending: false,
            view: PresetUiView::Closed,
            show_technical_details: false,
            notice: None,
            error: None,
        };
        write_text_buffer(&mut state.create_version, "1.0.0");
        state
    }
}

impl PresetUiState {
    fn mark_modified(&mut self) {
        if let Some(active) = self.active.as_mut() {
            active.modified = true;
        }
    }

    fn clear_create_form(&mut self) {
        self.create_name.fill(0);
        self.create_author.fill(0);
        self.create_description.fill(0);
        self.create_version.fill(0);
        write_text_buffer(&mut self.create_version, "1.0.0");
    }

    fn suggest_update_version(&mut self, version: &str) {
        let next_version = suggest_next_patch_version(version);
        write_text_buffer(&mut self.update_version, &next_version);
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
    motion_blur: Option<motion_blur::MotionBlurEffect>,
    motion_blur_creation_failed: bool,
    motion_blur_temporal: motion_blur::MotionBlurTemporalState,
    prepared_motion_blur_frame: Option<motion_blur::PreparedMotionBlurFrame>,
    final_color_copy: Option<BackbufferCopy>,
    scene_pre_color_copy: Option<BackbufferCopy>,
    scene_post_color_copy: Option<BackbufferCopy>,
    world_color_copy: Option<BackbufferCopy>,
    world_color_source_target: usize,
    state_block: Option<StateBlock9>,
    render_target_slots: Option<RenderTargetSlots>,
    imgui: Option<psycho_imgui::Dx9Context>,
    imgui_hwnd: usize,
    imgui_needs_device_objects: bool,
    active_menu_tab: MenuTab,
    menu_diagnostics_visible: bool,
    selected_menu_item: MenuSelection,
    menu_sidebar_width: f32,
    present_timing: PresentFrameTiming,
    frame_pacing: FramePacing,
    asset_scanner: Option<AssetScanner>,
    current_look_service: Option<CurrentLookService>,
    current_look_autosave: AutosaveCoordinator,
    preset_ui: PresetUiState,
    shader_catalog_generation: u64,
    lut_catalog_generation: u64,
    render_epoch: u32,
    frame_index: u32,
    last_depth_available: Option<bool>,
    last_fog_available: Option<bool>,
    last_sun_available: Option<bool>,
    error_logs: u32,
    imgui_error_logs: u32,
    menu_config_error: Option<String>,
    scene_apply_logs: u32,
    scene_target_logs: u32,
    world_color_capture_logs: u32,
    world_color_captured_this_frame: bool,
    applied_phases: AppliedShaderPhases,
    native_dof_active_this_frame: bool,
}

impl Default for ScreenShaderRuntime {
    fn default() -> Self {
        let default_settings = RuntimeSettings::default();
        let final_color_shaders = match blooming_hdr::FinalColorShaderBytecode::prepare() {
            Ok(shaders) => Some(shaders),
            Err(err) => {
                log::warn!("[FINAL_COLOR] Startup shader preparation failed: {err:#}");
                None
            }
        };
        Self {
            settings: default_settings,
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
            motion_blur: None,
            motion_blur_creation_failed: false,
            motion_blur_temporal: motion_blur::MotionBlurTemporalState::default(),
            prepared_motion_blur_frame: None,
            final_color_copy: None,
            scene_pre_color_copy: None,
            scene_post_color_copy: None,
            world_color_copy: None,
            world_color_source_target: 0,
            state_block: None,
            render_target_slots: None,
            imgui: None,
            imgui_hwnd: 0,
            imgui_needs_device_objects: false,
            active_menu_tab: MenuTab::default(),
            menu_diagnostics_visible: false,
            selected_menu_item: MenuSelection::default(),
            menu_sidebar_width: 270.0,
            present_timing: PresentFrameTiming::default(),
            frame_pacing: FramePacing::default(),
            asset_scanner: None,
            current_look_service: None,
            current_look_autosave: AutosaveCoordinator::default(),
            preset_ui: PresetUiState::default(),
            shader_catalog_generation: 0,
            lut_catalog_generation: 0,
            render_epoch: 0,
            frame_index: 0,
            last_depth_available: None,
            last_fog_available: None,
            last_sun_available: None,
            error_logs: 0,
            imgui_error_logs: 0,
            menu_config_error: None,
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
        match self.asset_scanner.as_ref() {
            Some(scanner) => scanner.reconfigure(settings.shader_scan_interval_ms, master_enabled),
            None => match AssetScanner::start(settings.shader_scan_interval_ms, master_enabled) {
                Ok(scanner) => self.asset_scanner = Some(scanner),
                Err(err) => log::warn!("[SHADERS] Live asset scanner unavailable: {err:#}"),
            },
        }
        if self.preset_ui.service.is_none() {
            match PresetService::start() {
                Ok(service) => self.preset_ui.service = Some(service),
                Err(err) => {
                    self.preset_ui.error = Some(format!("Preset catalog unavailable: {err:#}"))
                }
            }
        }
        if self.current_look_service.is_none() {
            match CurrentLookService::start() {
                Ok(service) => self.current_look_service = Some(service),
                Err(err) => {
                    self.menu_config_error =
                        Some(format!("Current Look autosave unavailable: {err:#}"));
                }
            }
        }
        let external_sources = self
            .sources
            .iter()
            .filter(|source| source.is_external_file())
            .cloned()
            .collect();
        let (lut_names, lut_ids) = self.color_luts.choices();
        self.sources = shaders::merge_embedded_sources_with_luts(
            &settings.menu_config.embedded_effects,
            &lut_names,
            &lut_ids,
            external_sources,
        );
        self.settings = settings;
        self.compiled = None;
        self.current_look_autosave = AutosaveCoordinator::default();
        self.publish_fnv_scene_requirements();
    }

    unsafe fn apply_present_frame(
        &mut self,
        device_ptr: *mut c_void,
        hwnd_hint: *mut c_void,
    ) -> Direct3DResult<()> {
        self.poll_asset_scanner();
        self.poll_preset_service();
        self.service_current_look();

        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Ok(());
        };

        if self.device_ptr != device_ptr as usize {
            self.release_for_new_device();
            self.device_ptr = device_ptr as usize;
        }

        if self.settings.menu_config.screen_space_shaders {
            if self.settings.menu_config.native_pbr.enabled {
                pbr::service_present_frame();
            }
            if self
                .settings
                .menu_config
                .embedded_effects
                .depth_of_field
                .enabled
            {
                depth_of_field::service_present_frame();
            }
            let motion_blur_config = self.settings.menu_config.embedded_effects.motion_blur;
            if motion_blur_config.enabled && motion_blur_config.shutter_angle > f32::EPSILON {
                motion_blur::service_present_frame();
            }
        }

        self.ensure_imgui(&device, hwnd_hint);

        let menu_open = MENU_OPEN.load(Ordering::Acquire);
        let pbr_preparation = pbr::preparation_status();
        let preparation_overlay = !menu_open && pbr_preparation.active() && self.imgui.is_some();
        let can_apply_at_present = self.settings.depth_provider == DepthProvider::None;
        let has_shader_work = can_apply_at_present
            && !self.applied_phases.is_applied(ShaderPhase::FinalImageSpace)
            && self.has_enabled_shader_for_phase(ShaderPhase::FinalImageSpace);
        if !menu_open && !has_shader_work && !preparation_overlay {
            return Ok(());
        }

        if has_shader_work {
            self.ensure_shaders(&device);
        }

        let has_drawable_shader = self.has_drawable_shader();
        if !menu_open && !has_drawable_shader && !preparation_overlay {
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
            let frame_inputs = self.build_frame_inputs(&desc, ShaderPhase::FinalImageSpace);
            if self.phase_has_applicable_work(ShaderPhase::FinalImageSpace, &desc, &frame_inputs) {
                self.ensure_phase_color_copy(&device, &desc, ShaderPhase::FinalImageSpace)?;
                Some((backbuffer, desc, frame_inputs))
            } else {
                self.maintain_rejected_phase_state(ShaderPhase::FinalImageSpace, &frame_inputs);
                None
            }
        } else {
            None
        };

        if shader_target.is_none() && !menu_open && !preparation_overlay {
            if has_shader_work {
                self.applied_phases
                    .mark_applied(ShaderPhase::FinalImageSpace);
            }
            return Ok(());
        }

        let render_target_slots = self.render_target_slots(&device)?;
        let attachments = RenderAttachments::capture(&device, render_target_slots)?;
        self.ensure_state_block(&device)?;

        let Some(state_block) = self.state_block.as_ref() else {
            return Err(runtime_error(
                "[SHADERS] Missing D3D state block before capture",
            ));
        };
        state_block.capture()?;

        let draw_result = match shader_target.as_ref() {
            Some((backbuffer, desc, frame_inputs)) => render_target_slots
                .prepare_target_change(&device)
                .and_then(|()| {
                    self.draw_passes(
                        &device,
                        backbuffer,
                        desc,
                        ShaderPhase::FinalImageSpace,
                        frame_inputs,
                    )
                }),
            None => Ok(()),
        };
        let menu_result = if menu_open {
            self.draw_menu()
        } else if preparation_overlay {
            self.draw_pbr_preparation(pbr_preparation)
        } else {
            Ok(())
        };
        finish_render_transaction(
            &device,
            &attachments,
            self.state_block.as_ref(),
            draw_result.and(menu_result),
        )?;
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

        self.poll_asset_scanner();
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

        let Some(prepared_target) = self.prepare_scene_phase_target(&device, target)? else {
            return Ok(());
        };
        let desc = *prepared_target.desc();
        let frame_inputs = self.build_frame_inputs(&desc, phase);
        if !self.phase_has_applicable_work(phase, &desc, &frame_inputs) {
            self.maintain_rejected_phase_state(phase, &frame_inputs);
            self.applied_phases.mark_applied(phase);
            return Ok(());
        }
        self.ensure_phase_color_copy(&device, &desc, phase)?;

        let render_target_slots = self.render_target_slots(&device)?;
        let attachments = RenderAttachments::capture(&device, render_target_slots)?;
        self.ensure_state_block(&device)?;
        let Some(state_block) = self.state_block.as_ref() else {
            return Err(runtime_error(
                "[SHADERS] Missing D3D state block before scene capture",
            ));
        };
        state_block.capture()?;

        let draw_result = (|| {
            // The engine attachments can differ in size or multisample mode
            // from the rendered-texture source used by scene-pre effects.
            // Detach them before switching RT0; the transaction restores the
            // exact native set even if selection or drawing fails.
            render_target_slots.prepare_target_change(&device)?;
            let render_target = unsafe { prepared_target.bind(&device)? };
            self.draw_passes(&device, &render_target, &desc, phase, &frame_inputs)
        })();

        finish_render_transaction(
            &device,
            &attachments,
            self.state_block.as_ref(),
            draw_result,
        )?;

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

    fn prepare_scene_phase_target(
        &mut self,
        device: &Device9Ref<'_>,
        target: ScenePhaseTarget,
    ) -> Direct3DResult<Option<PreparedScenePhaseTarget>> {
        match target {
            ScenePhaseTarget::CurrentRenderTarget => {
                let surface = match device.render_target(0) {
                    Ok(surface) => surface,
                    Err(err) => {
                        self.release_default_pool_resources();
                        return Err(err);
                    }
                };
                let desc = surface.desc()?;
                if desc.Width == 0 || desc.Height == 0 {
                    return Ok(None);
                }
                Ok(Some(PreparedScenePhaseTarget::Current { surface, desc }))
            }
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

                Ok(Some(PreparedScenePhaseTarget::RenderedTexture {
                    surface,
                    desc,
                }))
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

    fn poll_asset_scanner(&mut self) {
        let Some(scanner) = self.asset_scanner.as_ref() else {
            return;
        };
        let Some(mut snapshot) = scanner.try_take_latest() else {
            return;
        };

        // Preserve live embedded edits that may still be inside the autosave
        // debounce window before rebuilding dynamic source options. Background
        // discoveries are committed in one render tick without file I/O here.
        shaders::sync_embedded_effect_config(
            &self.sources,
            &mut self.settings.menu_config.embedded_effects,
        );

        let old_count = self.sources.len();
        let shader_resources_changed = snapshot.shader_generation != self.shader_catalog_generation;
        let lut_resources_changed = snapshot.lut_generation != self.lut_catalog_generation;
        if !shader_resources_changed && !lut_resources_changed {
            return;
        }

        shaders::preserve_external_runtime_config(&self.sources, &mut snapshot.external_sources);
        if lut_resources_changed {
            self.color_luts = snapshot.color_luts;
            self.blooming_hdr = None;
            self.lut_catalog_generation = snapshot.lut_generation;
            log::info!(
                "[LUT] Live LUT catalog: {} file(s)",
                self.color_luts.assets.len()
            );
        }
        if shader_resources_changed {
            self.compiled = None;
            self.shader_catalog_generation = snapshot.shader_generation;
        }
        let (lut_names, lut_ids) = self.color_luts.choices();
        self.sources = shaders::merge_embedded_sources_with_luts(
            &self.settings.menu_config.embedded_effects,
            &lut_names,
            &lut_ids,
            snapshot.external_sources,
        );
        if let Some(service) = self.current_look_service.as_ref()
            && let Err(err) = service.track_sources(&self.sources)
        {
            self.menu_config_error = Some(format!(
                "Could not monitor external shader settings: {err:#}"
            ));
        }
        self.publish_fnv_scene_requirements();
        let new_count = self.sources.len();
        if old_count != new_count {
            log::info!("[SHADERS] Live shader list: {new_count} shader(s)");
        }
        self.refresh_active_preset_status();
    }

    fn poll_preset_service(&mut self) {
        let Some(service) = self.preset_ui.service.as_ref() else {
            return;
        };
        let events = service.try_take_events();
        for event in events {
            match event {
                PresetEvent::Catalog(catalog) => {
                    let selected_key = self
                        .preset_ui
                        .selected
                        .and_then(|index| self.preset_ui.catalog.entries.get(index))
                        .and_then(|entry| entry.key());
                    self.preset_ui.catalog = catalog;
                    let preferred = self
                        .preset_ui
                        .pending_published
                        .as_ref()
                        .or(selected_key.as_ref());
                    self.preset_ui.selected = preferred
                        .and_then(|key| {
                            self.preset_ui
                                .catalog
                                .entries
                                .iter()
                                .position(|entry| entry.key().as_ref() == Some(key))
                        })
                        .or_else(|| (!self.preset_ui.catalog.entries.is_empty()).then_some(0));

                    if let Some(created_key) = self.preset_ui.pending_published.take()
                        && let Some(entry) = self
                            .preset_ui
                            .catalog
                            .entries
                            .iter()
                            .find(|entry| entry.key().as_ref() == Some(&created_key))
                    {
                        let Some(payload_revision) = entry
                            .document
                            .as_ref()
                            .and_then(|document| document.payload_revision().ok())
                        else {
                            self.preset_ui.create_pending = false;
                            self.preset_ui.update_pending = false;
                            self.preset_ui.error =
                                Some("Created preset payload could not be verified".to_owned());
                            continue;
                        };
                        let was_update = self.preset_ui.update_pending;
                        let created_version = entry.version.clone();
                        self.preset_ui.active = Some(ActivePreset {
                            key: created_key,
                            name: entry.display_name.clone(),
                            version: created_version.clone(),
                            payload_revision,
                            built_in: entry.built_in,
                            modified: false,
                        });
                        self.preset_ui.create_pending = false;
                        self.preset_ui.update_pending = false;
                        self.preset_ui.view = PresetUiView::Closed;
                        self.preset_ui.suggest_update_version(&created_version);
                        if was_update {
                            self.preset_ui.notice = Some(format!(
                                "Updated to version {created_version} and enabled it."
                            ));
                        } else {
                            self.preset_ui.clear_create_form();
                            self.preset_ui.notice =
                                Some("New preset created and enabled.".to_owned());
                        }
                        self.preset_ui.error = None;
                        // Publication changes only the preset provenance. The
                        // Current Look was already autosaved independently, so
                        // recording this identity must not schedule a redundant
                        // rewrite of omv.toml or the new preset file.
                        self.record_active_preset_state();
                    }
                }
                PresetEvent::Published(key) => {
                    self.preset_ui.pending_published = Some(key);
                    self.preset_ui.notice =
                        Some("Preset written; refreshing the catalog".to_owned());
                    self.preset_ui.error = None;
                }
                PresetEvent::ActiveState(state) => {
                    self.preset_ui.pending_saved_state = state;
                    self.preset_ui.saved_state_loaded = true;
                }
                PresetEvent::Error(error) => {
                    self.preset_ui.create_pending = false;
                    self.preset_ui.update_pending = false;
                    self.preset_ui.error = Some(error);
                    self.preset_ui.notice = None;
                }
            }
        }
        self.reconcile_saved_preset_state();
    }

    /// Services the Current Look worker without performing file I/O or waiting
    /// on the render thread.
    ///
    /// Snapshot cloning happens only after the debounce coordinator grants one
    /// revision. This keeps slider drags allocation-free between changes and
    /// prevents a stale worker completion from clearing newer live edits.
    fn service_current_look(&mut self) {
        let events = self
            .current_look_service
            .as_ref()
            .map(CurrentLookService::try_take_events)
            .unwrap_or_default();
        for event in events {
            match event {
                CurrentLookEvent::Saved { revision } => {
                    self.current_look_autosave
                        .save_succeeded(revision, Instant::now());
                    self.menu_config_error = None;
                    if !self.current_look_autosave.is_dirty() {
                        self.record_active_preset_state();
                    }
                }
                CurrentLookEvent::Reloaded {
                    menu_config,
                    sources,
                } => {
                    self.settings.menu_config = menu_config;
                    let external_sources = sources
                        .into_iter()
                        .filter(ScreenShaderSource::is_external_file)
                        .collect();
                    let (lut_names, lut_ids) = self.color_luts.choices();
                    self.sources = shaders::merge_embedded_sources_with_luts(
                        &self.settings.menu_config.embedded_effects,
                        &lut_names,
                        &lut_ids,
                        external_sources,
                    );
                    self.compiled = None;
                    self.apply_menu_config_change();
                    self.current_look_autosave.reload_succeeded();
                    self.refresh_active_preset_status();
                    self.menu_config_error = None;
                }
                CurrentLookEvent::ExternalChange { blocked_revision } => {
                    self.current_look_autosave
                        .external_change_detected(blocked_revision);
                }
                CurrentLookEvent::Error { operation, message } => match operation {
                    CurrentLookOperation::Save(revision) => {
                        self.current_look_autosave
                            .save_failed(revision, Instant::now());
                        self.menu_config_error =
                            Some(format!("Could not autosave Current Look: {message}"));
                    }
                    CurrentLookOperation::Reload => {
                        self.current_look_autosave.reload_failed();
                        self.menu_config_error =
                            Some(format!("Could not reload external file changes: {message}"));
                    }
                    CurrentLookOperation::Monitor => {
                        self.menu_config_error =
                            Some(format!("Could not monitor Current Look files: {message}"));
                    }
                },
            }
        }

        if CURRENT_LOOK_FLUSH_REQUEST.swap(false, Ordering::AcqRel) {
            self.current_look_autosave.flush_pending(Instant::now());
        }
        if !self.current_look_autosave.has_pending_deadline() {
            return;
        }
        let Some(revision) = self.current_look_autosave.take_due_save(Instant::now()) else {
            return;
        };
        self.queue_current_look_save(revision, false);
    }

    fn queue_current_look_save(&mut self, revision: u64, overwrite_external: bool) {
        shaders::sync_embedded_effect_config(
            &self.sources,
            &mut self.settings.menu_config.embedded_effects,
        );
        let snapshot =
            CurrentLookSnapshot::capture(revision, self.settings.menu_config, &self.sources);
        let result = self
            .current_look_service
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Current Look worker is unavailable"))
            .and_then(|service| service.save(snapshot, overwrite_external));
        if let Err(err) = result {
            self.current_look_autosave
                .save_failed(revision, Instant::now());
            self.menu_config_error =
                Some(format!("Could not queue Current Look autosave: {err:#}"));
        }
    }

    fn reload_current_look_from_disk(&mut self) {
        if !self.current_look_autosave.begin_reload() {
            return;
        }
        let result = self
            .current_look_service
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Current Look worker is unavailable"))
            .and_then(|service| service.reload(&self.sources));
        if let Err(err) = result {
            self.current_look_autosave.reload_failed();
            self.menu_config_error = Some(format!("Could not queue Current Look reload: {err:#}"));
        }
    }

    fn keep_current_look_over_external_files(&mut self) {
        let Some(revision) = self.current_look_autosave.begin_external_overwrite() else {
            return;
        };
        self.queue_current_look_save(revision, true);
    }

    fn reconcile_saved_preset_state(&mut self) {
        if !self.preset_ui.saved_state_loaded
            || self.shader_catalog_generation == 0
            || self.lut_catalog_generation == 0
        {
            return;
        }
        self.preset_ui.saved_state_loaded = false;
        let Some(state) = self.preset_ui.pending_saved_state.take() else {
            self.preset_ui.active = None;
            return;
        };
        let key = state.key();
        let Some(entry) = self
            .preset_ui
            .catalog
            .entries
            .iter()
            .find(|entry| entry.key().as_ref() == Some(&key))
        else {
            self.preset_ui.active = None;
            self.preset_ui.error =
                Some("Previously active preset is no longer installed".to_owned());
            return;
        };
        let entry_name = entry.display_name.clone();
        let entry_version = entry.version.clone();
        let entry_built_in = entry.built_in;
        let Some(document) = entry.document.as_ref() else {
            self.preset_ui.active = None;
            self.preset_ui.error = entry.error.clone();
            return;
        };
        let expected_revision = match state.payload_revision() {
            Ok(revision) => revision,
            Err(err) => {
                self.preset_ui.active = None;
                self.preset_ui.error = Some(format!("{err:#}"));
                return;
            }
        };
        let document_revision = match document.payload_revision() {
            Ok(revision) => revision,
            Err(err) => {
                self.preset_ui.active = None;
                self.preset_ui.error = Some(format!("{err:#}"));
                return;
            }
        };
        if document_revision != expected_revision {
            self.preset_ui.active = None;
            self.preset_ui.error =
                Some("Previously active preset changed without a version change".to_owned());
            return;
        }
        let modified = !document
            .matches_current(&self.settings.menu_config, &self.sources, &self.color_luts)
            .unwrap_or(false);
        self.preset_ui.active = Some(ActivePreset {
            key,
            name: entry_name,
            version: entry_version.clone(),
            payload_revision: document_revision,
            built_in: entry_built_in,
            modified,
        });
        self.preset_ui.suggest_update_version(&entry_version);
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
        self.active_menu_tab = MenuTab::default();
        self.menu_diagnostics_visible = false;
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
                set_menu_diagnostics_active(false);
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

    fn render_target_slots(
        &mut self,
        device: &Device9Ref<'_>,
    ) -> Direct3DResult<RenderTargetSlots> {
        if let Some(slots) = self.render_target_slots {
            return Ok(slots);
        }

        let slots = RenderTargetSlots::query(device)?;
        self.render_target_slots = Some(slots);
        Ok(slots)
    }

    fn copy_phase_color_for_sampling(
        &self,
        device: &Device9Ref<'_>,
        source: &Surface9,
        copy: &BackbufferCopy,
    ) -> Direct3DResult<()> {
        copy_scene_color_for_sampling(
            device,
            source,
            &copy.surface,
            self.sampler3_scene_color(&copy.texture),
        )
    }

    fn sampler3_scene_color<'a>(&'a self, fallback: &'a Texture9) -> &'a Texture9 {
        if self.world_color_captured_this_frame {
            self.world_color_copy
                .as_ref()
                .map_or(fallback, |copy| &copy.texture)
        } else {
            fallback
        }
    }

    fn build_frame_inputs(
        &mut self,
        desc: &D3DSURFACE_DESC,
        phase: ShaderPhase,
    ) -> backend::FrameInputs {
        if !self.phase_needs_frame_inputs(phase) {
            return backend::FrameInputs::default();
        }

        let depth = self.current_depth_frame();
        let camera = if depth.world_projection.camera.available {
            depth.world_projection.camera
        } else {
            backend::camera_frame(self.settings.depth_provider, desc)
        };
        let atmosphere_visibility = crate::fnv_world_pipeline::atmosphere_visibility();
        let frame_inputs = backend::FrameInputs {
            camera,
            depth,
            environment: backend::environment_frame(self.settings.depth_provider),
            sun: backend::sun_frame(self.settings.depth_provider),
            sky: backend::native_sky_frame(),
            atmosphere_visibility: atmosphere_visibility.unwrap_or(0.0),
            atmosphere_available: atmosphere_visibility.is_some(),
            first_person_rendered: backend::fnv_first_person_rendered(),
            third_person_view: (phase == ShaderPhase::ScenePostImageSpace)
                .then(backend::fnv_third_person_view)
                .flatten(),
            material_state: backend::material_state_frame(),
        };
        self.log_frame_input_state(&frame_inputs);
        frame_inputs
    }

    fn phase_has_applicable_work(
        &mut self,
        phase: ShaderPhase,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
    ) -> bool {
        self.prepared_motion_blur_frame = None;
        let motion_blur_enabled = self.sources.iter().any(|source| {
            source.enabled
                && source.phase() == phase
                && source.embedded_effect_kind() == Some(EmbeddedEffectKind::MotionBlur)
        });
        if motion_blur_enabled {
            let config = self.settings.menu_config.embedded_effects.motion_blur;
            if motion_blur::should_prepare(frame_inputs, config) {
                let prepared = self
                    .motion_blur_temporal
                    .prepare_frame(desc, frame_inputs, config);
                if !self.motion_blur_creation_failed
                    && (self.motion_blur.is_some() || motion_blur::preparation_ready())
                {
                    self.prepared_motion_blur_frame = prepared;
                }
            } else {
                self.motion_blur_temporal.reset();
            }
        }

        let Some(compiled) = self.compiled.as_ref() else {
            return false;
        };
        let fast_ao = self.sources.iter().find(|source| {
            source.enabled
                && source.phase() == phase
                && source.embedded_effect_kind() == Some(EmbeddedEffectKind::FastAmbientOcclusion)
        });
        let contact_ao = self.sources.iter().find(|source| {
            source.enabled
                && source.phase() == phase
                && source.embedded_effect_kind()
                    == Some(EmbeddedEffectKind::ContactAmbientOcclusion)
        });
        let mut ao_checked = false;

        for pass in compiled {
            let source = &self.sources[pass.source_index];
            if !source.enabled || source.phase() != phase {
                continue;
            }
            let Some(kind) = source.embedded_effect_kind() else {
                return true;
            };
            if kind.owns_world_boundary() {
                continue;
            }
            match kind {
                EmbeddedEffectKind::FastAmbientOcclusion
                | EmbeddedEffectKind::ContactAmbientOcclusion => {
                    if !ao_checked {
                        ao_checked = true;
                        if ambient_occlusion::should_draw(frame_inputs, fast_ao, contact_ao) {
                            return true;
                        }
                    }
                }
                EmbeddedEffectKind::Sunshafts => {
                    if sunshafts::should_draw(frame_inputs, source) {
                        return true;
                    }
                }
                EmbeddedEffectKind::DepthOfField => {
                    if (self.depth_of_field.is_some() || depth_of_field::preparation_ready())
                        && depth_of_field::should_draw(
                            frame_inputs,
                            self.settings.menu_config.embedded_effects.depth_of_field,
                            self.native_dof_active_this_frame,
                        )
                    {
                        return true;
                    }
                }
                EmbeddedEffectKind::MotionBlur => {
                    if self.prepared_motion_blur_frame.is_some_and(|frame| {
                        self.motion_blur
                            .as_ref()
                            .is_none_or(|effect| effect.has_applicable_work(frame))
                    }) {
                        return true;
                    }
                }
                _ => return true,
            }
        }

        false
    }

    fn maintain_rejected_phase_state(
        &mut self,
        phase: ShaderPhase,
        frame_inputs: &backend::FrameInputs,
    ) {
        let fast_ao = self.sources.iter().find(|source| {
            source.enabled
                && source.phase() == phase
                && source.embedded_effect_kind() == Some(EmbeddedEffectKind::FastAmbientOcclusion)
        });
        let contact_ao = self.sources.iter().find(|source| {
            source.enabled
                && source.phase() == phase
                && source.embedded_effect_kind()
                    == Some(EmbeddedEffectKind::ContactAmbientOcclusion)
        });
        if (fast_ao.is_some() || contact_ao.is_some())
            && !ambient_occlusion::family_selected(fast_ao, contact_ao)
            && let Some(effect) = self.ambient_occlusion.as_mut()
        {
            effect.reset_history();
        }

        let dof_enabled = self.sources.iter().any(|source| {
            source.enabled
                && source.phase() == phase
                && source.embedded_effect_kind() == Some(EmbeddedEffectKind::DepthOfField)
        });
        if dof_enabled {
            let config = self.settings.menu_config.embedded_effects.depth_of_field;
            if let Some(effect) = self.depth_of_field.as_mut() {
                effect.note_skipped(config, self.native_dof_active_this_frame);
            }
        }

        let motion_blur_enabled = self.sources.iter().any(|source| {
            source.enabled
                && source.phase() == phase
                && source.embedded_effect_kind() == Some(EmbeddedEffectKind::MotionBlur)
        });
        if !motion_blur_enabled
            || !motion_blur::should_prepare(
                frame_inputs,
                self.settings.menu_config.embedded_effects.motion_blur,
            )
        {
            self.motion_blur_temporal.reset();
            self.prepared_motion_blur_frame = None;
        }
    }

    fn draw_passes(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        phase: ShaderPhase,
        frame_inputs: &backend::FrameInputs,
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

        let Some(copy) = self.phase_color_copy(phase).cloned() else {
            return Ok(());
        };
        if self.compiled.is_none() {
            return Ok(());
        }

        self.bind_common_state(device, backbuffer, desc, frame_inputs, &copy)?;

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
                        frame_inputs,
                        &copy,
                        fast_source.as_ref(),
                        contact_source.as_ref(),
                    )?;
                    if rebind_common_state {
                        self.bind_common_state(device, backbuffer, desc, frame_inputs, &copy)?;
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
                        frame_inputs,
                        &copy,
                        bloom_source.as_ref(),
                        color_grade_source.as_ref(),
                    )?;
                    if rebind_common_state {
                        self.bind_common_state(device, backbuffer, desc, frame_inputs, &copy)?;
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
                    frame_inputs,
                    &copy,
                    &source,
                )?;
                if rebind_common_state {
                    self.bind_common_state(device, backbuffer, desc, frame_inputs, &copy)?;
                }
                pass_index = pass_index.saturating_add(source.pass_count.max(1));
                continue;
            }

            if source.embedded_effect_kind() == Some(EmbeddedEffectKind::DepthOfField) {
                let rebind_common_state = self.has_enabled_pass_after(phase, pass_position);
                let source_pass_count = source.pass_count.max(1);
                self.draw_depth_of_field_pipeline(device, backbuffer, desc, frame_inputs, &copy)?;
                if rebind_common_state {
                    self.bind_common_state(device, backbuffer, desc, frame_inputs, &copy)?;
                }
                pass_index = pass_index.saturating_add(source_pass_count);
                continue;
            }

            if source.embedded_effect_kind() == Some(EmbeddedEffectKind::MotionBlur) {
                let rebind_common_state = self.has_enabled_pass_after(phase, pass_position);
                let source_pass_count = source.pass_count.max(1);
                self.draw_motion_blur_pipeline(device, backbuffer, desc, frame_inputs, &copy)?;
                if rebind_common_state {
                    self.bind_common_state(device, backbuffer, desc, frame_inputs, &copy)?;
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
                    self.bind_common_state(device, backbuffer, desc, frame_inputs, &copy)?;
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
                self.copy_phase_color_for_sampling(device, backbuffer, &copy)?;
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
                bind_depth_contract_constants(device, frame_inputs)?;

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
        if !ambient_occlusion::should_draw(frame_inputs, fast_source, contact_source) {
            if !ambient_occlusion::family_selected(fast_source, contact_source)
                && let Some(effect) = self.ambient_occlusion.as_mut()
            {
                effect.reset_history();
            }
            return Ok(());
        }
        if self.ambient_occlusion.is_none() {
            self.ambient_occlusion =
                Some(ambient_occlusion::AmbientOcclusionEffect::create(device)?);
            log::info!("[AO] Engine-side pipeline initialized");
        }

        self.copy_phase_color_for_sampling(device, backbuffer, current_color_copy)?;
        let Some(effect) = self.ambient_occlusion.as_mut() else {
            return Ok(());
        };
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

        let prepared = match self.anti_aliasing.as_mut() {
            Some(effect) => effect.prepare(device, source)?,
            None => return Ok(()),
        };
        if !prepared {
            return Ok(());
        }
        self.copy_phase_color_for_sampling(device, backbuffer, current_color_copy)?;
        let Some(effect) = self.anti_aliasing.as_mut() else {
            return Ok(());
        };
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
            let render_target_slots = self
                .render_target_slots
                .ok_or_else(|| runtime_error("[SHADERS] Missing D3D render-target capabilities"))?;
            self.blooming_hdr = Some(blooming_hdr::BloomingHdrEffect::create(
                device,
                shaders,
                render_target_slots,
            )?);
            log::info!("[FINAL_COLOR] Bloom/color-grade pipeline initialized");
        }

        self.copy_phase_color_for_sampling(device, backbuffer, current_color_copy)?;
        let Some(effect) = self.blooming_hdr.as_mut() else {
            return Ok(());
        };
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
        if !sunshafts::should_draw(frame_inputs, source) {
            return Ok(());
        }
        if self.sunshafts.is_none() {
            self.sunshafts = Some(sunshafts::SunshaftsEffect::create(device)?);
            log::info!("[SUNSHAFTS] Engine-side pipeline initialized");
        }

        self.copy_phase_color_for_sampling(device, backbuffer, current_color_copy)?;
        let Some(effect) = self.sunshafts.as_mut() else {
            return Ok(());
        };
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
        let config = self.settings.menu_config.embedded_effects.depth_of_field;
        let native_dof_active = self.native_dof_active_this_frame;
        if !depth_of_field::should_draw(frame_inputs, config, native_dof_active) {
            if let Some(effect) = self.depth_of_field.as_mut() {
                effect.note_skipped(config, native_dof_active);
            }
            return Ok(());
        }
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

        let frame_seconds = self.present_timing.frame_seconds();
        let frame_index = self.frame_index;
        self.copy_phase_color_for_sampling(device, backbuffer, current_color_copy)?;
        let Some(effect) = self.depth_of_field.as_mut() else {
            return Ok(());
        };
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

    fn draw_motion_blur_pipeline(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
        current_color_copy: &BackbufferCopy,
    ) -> Direct3DResult<()> {
        let Some(frame) = self.prepared_motion_blur_frame.take() else {
            return Ok(());
        };
        if self.motion_blur_creation_failed {
            return Ok(());
        }
        if self.motion_blur.is_none() {
            match motion_blur::MotionBlurEffect::create(device) {
                Ok(Some(effect)) => {
                    self.motion_blur = Some(effect);
                    log::info!("[MOTION_BLUR] Camera reprojection pipeline initialized");
                }
                Ok(None) => return Ok(()),
                Err(err) => {
                    self.motion_blur_creation_failed = true;
                    return Err(err);
                }
            }
        }

        let Some(effect) = self.motion_blur.as_ref() else {
            return Ok(());
        };
        let requires_color_copy = effect.requires_color_copy(desc, frame);
        if requires_color_copy {
            self.copy_phase_color_for_sampling(device, backbuffer, current_color_copy)?;
        }
        let Some(effect) = self.motion_blur.as_mut() else {
            return Ok(());
        };
        effect.draw(
            device,
            backbuffer,
            desc,
            frame_inputs,
            requires_color_copy.then_some(&current_color_copy.texture),
            frame,
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

        let diagnostics_active = diagnostics_should_be_active(
            true,
            IMGUI_READY.load(Ordering::Acquire),
            self.active_menu_tab,
            self.menu_diagnostics_visible,
        );
        set_menu_diagnostics_active(diagnostics_active);

        if self.imgui_needs_device_objects && imgui.create_device_objects() {
            self.imgui_needs_device_objects = false;
        }

        let menu_frame = {
            let frame_pacing = if diagnostics_active {
                self.frame_pacing.snapshot_for_ui()
            } else {
                FramePacingSnapshot::default()
            };
            let feature_status = EngineFeatureStatus {
                pbr: pbr::runtime_status(),
                sky: sky::runtime_status(),
                depth: backend::depth_resolve_status(self.settings.depth_provider),
            };
            let mut ui = imgui.new_frame(true);
            draw_shader_menu(
                &mut ui,
                &mut self.settings.menu_config,
                &mut self.sources,
                &mut self.preset_ui,
                &mut self.active_menu_tab,
                &mut self.selected_menu_item,
                &mut self.menu_sidebar_width,
                &frame_pacing,
                feature_status,
                MenuPersistenceView {
                    external_change: self.current_look_autosave.has_external_change(),
                    error: self.menu_config_error.as_deref(),
                },
            )
        };

        self.menu_diagnostics_visible = menu_frame.diagnostics_visible;
        set_menu_diagnostics_active(diagnostics_should_be_active(
            true,
            IMGUI_READY.load(Ordering::Acquire),
            self.active_menu_tab,
            self.menu_diagnostics_visible,
        ));
        imgui.render();
        if menu_frame.changed {
            self.apply_menu_config_change();
            self.current_look_autosave.note_change(Instant::now());
            self.preset_ui.mark_modified();
            self.menu_config_error = None;
        }
        match menu_frame.action {
            MenuAction::None => {}
            MenuAction::ReloadFiles => self.reload_current_look_from_disk(),
            MenuAction::KeepCurrentLook => self.keep_current_look_over_external_files(),
            MenuAction::RefreshPresets => self.refresh_presets(),
            MenuAction::CreatePreset => self.create_preset_from_current(),
            MenuAction::PublishPresetVersion => self.publish_active_preset_version(),
            MenuAction::ActivatePreset(index) => self.activate_preset(index),
        }
        Ok(())
    }

    fn draw_pbr_preparation(&mut self, status: pbr::PbrPreparationStatus) -> Direct3DResult<()> {
        let Some(imgui) = self.imgui.as_mut() else {
            return Ok(());
        };
        if self.imgui_needs_device_objects && imgui.create_device_objects() {
            self.imgui_needs_device_objects = false;
        }

        {
            let mut ui = imgui.new_frame(false);
            draw_pbr_preparation_window(&mut ui, status);
        }
        imgui.render();
        Ok(())
    }

    fn apply_menu_config_change(&mut self) {
        MASTER_EFFECTS_ENABLED.store(
            self.settings.menu_config.screen_space_shaders,
            Ordering::Release,
        );
        self.settings.depth_provider = self.settings.menu_config.depth_provider.into();
        self.settings.menu_toggle_key =
            sanitize_menu_toggle_key(self.settings.menu_config.menu_toggle_key);
        self.settings.menu_config.menu_toggle_key = self.settings.menu_toggle_key;
        self.settings.shader_scan_interval_ms = self.settings.menu_config.shader_scan_interval_ms;
        if let Some(scanner) = self.asset_scanner.as_ref() {
            scanner.reconfigure(
                self.settings.shader_scan_interval_ms,
                self.settings.menu_config.screen_space_shaders,
            );
        }
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

    fn record_active_preset_state(&mut self) {
        let state = self
            .preset_ui
            .active
            .as_ref()
            .map(|active| PresetActiveState::new(&active.key, active.payload_revision));
        let result = self
            .preset_ui
            .service
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("preset worker is unavailable"))
            .and_then(|service| service.record_active_state(state));
        if let Err(err) = result {
            self.preset_ui.error = Some(format!("Could not record active preset: {err:#}"));
        }
    }

    fn refresh_active_preset_status(&mut self) {
        let Some(active) = self.preset_ui.active.as_ref() else {
            return;
        };
        let key = active.key.clone();
        let modified = self
            .preset_ui
            .catalog
            .entries
            .iter()
            .find(|entry| entry.key().as_ref() == Some(&key))
            .and_then(|entry| entry.document.as_ref())
            .and_then(|document| {
                document
                    .matches_current(&self.settings.menu_config, &self.sources, &self.color_luts)
                    .ok()
            })
            .is_none_or(|matches| !matches);
        if let Some(active) = self.preset_ui.active.as_mut() {
            active.modified = modified;
        }
    }

    fn refresh_presets(&mut self) {
        if let Some(scanner) = self.asset_scanner.as_ref() {
            scanner.request_scan();
        }
        let result = self
            .preset_ui
            .service
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("preset worker is unavailable"))
            .and_then(PresetService::request_refresh);
        match result {
            Ok(()) => {
                self.preset_ui.notice = Some("Refreshing preset catalog".to_owned());
                self.preset_ui.error = None;
            }
            Err(err) => {
                self.preset_ui.error = Some(format!("{err:#}"));
                self.preset_ui.notice = None;
            }
        }
    }

    fn create_preset_from_current(&mut self) {
        shaders::sync_embedded_effect_config(
            &self.sources,
            &mut self.settings.menu_config.embedded_effects,
        );
        let name = text_buffer(&self.preset_ui.create_name).to_owned();
        let version = text_buffer(&self.preset_ui.create_version).to_owned();
        let author = text_buffer(&self.preset_ui.create_author).to_owned();
        let description = text_buffer(&self.preset_ui.create_description).to_owned();
        let result = PresetPublishRequest::capture(
            &name,
            &version,
            &author,
            &description,
            &self.settings.menu_config,
            &self.sources,
            &self.color_luts,
        )
        .and_then(|request| {
            self.preset_ui
                .service
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("preset worker is unavailable"))?
                .request_publish(request)
        });
        match result {
            Ok(()) => {
                self.preset_ui.create_pending = true;
                self.preset_ui.notice = Some("Creating preset in the background".to_owned());
                self.preset_ui.error = None;
            }
            Err(err) => {
                self.preset_ui.error = Some(format!("{err:#}"));
                self.preset_ui.notice = None;
            }
        }
    }

    fn publish_active_preset_version(&mut self) {
        shaders::sync_embedded_effect_config(
            &self.sources,
            &mut self.settings.menu_config.embedded_effects,
        );
        let result = (|| {
            let active =
                self.preset_ui.active.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("activate a preset before publishing an update")
                })?;
            if active.built_in {
                anyhow::bail!(
                    "the built-in preset family is read-only; save the current configuration as a new preset"
                );
            }
            if !active.modified {
                anyhow::bail!("change the active preset before publishing a new version");
            }
            let (source, source_path, source_content_hash) = self
                .preset_ui
                .catalog
                .entries
                .iter()
                .find(|entry| entry.key().as_ref() == Some(&active.key))
                .and_then(|entry| {
                    Some((
                        entry.document.as_ref()?.clone(),
                        entry.path.as_ref()?.clone(),
                        entry.content_hash,
                    ))
                })
                .ok_or_else(|| anyhow::anyhow!("the active preset is no longer available"))?;
            let version = text_buffer(&self.preset_ui.update_version);
            let request = PresetPublishRequest::capture_new_version(
                &source,
                &source_path,
                source_content_hash,
                version,
                &self.settings.menu_config,
                &self.sources,
                &self.color_luts,
            )?;
            self.preset_ui
                .service
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("preset worker is unavailable"))?
                .request_publish(request)
        })();
        match result {
            Ok(()) => {
                self.preset_ui.update_pending = true;
                self.preset_ui.notice =
                    Some("Updating the preset file atomically in the background".to_owned());
                self.preset_ui.error = None;
            }
            Err(err) => {
                self.preset_ui.error = Some(format!("{err:#}"));
                self.preset_ui.notice = None;
            }
        }
    }

    fn activate_preset(&mut self, index: usize) {
        let Some(entry) = self.preset_ui.catalog.entries.get(index) else {
            return;
        };
        let Some(document) = entry.document.clone() else {
            self.preset_ui.error = entry.error.clone();
            self.preset_ui.notice = None;
            return;
        };
        let name = entry.display_name.clone();
        let version = entry.version.clone();
        let built_in = entry.built_in;
        let key = document.key();
        let payload_revision = match document.payload_revision() {
            Ok(revision) => revision,
            Err(err) => {
                self.preset_ui.error = Some(format!("Could not activate preset: {err:#}"));
                self.preset_ui.notice = None;
                return;
            }
        };
        let result = document.apply(
            &mut self.settings.menu_config,
            &mut self.sources,
            &self.color_luts,
        );
        match result {
            Ok(()) => {
                let external_sources = self
                    .sources
                    .iter()
                    .filter(|source| source.is_external_file())
                    .cloned()
                    .collect();
                let (lut_names, lut_ids) = self.color_luts.choices();
                self.sources = shaders::merge_embedded_sources_with_luts(
                    &self.settings.menu_config.embedded_effects,
                    &lut_names,
                    &lut_ids,
                    external_sources,
                );
                self.compiled = None;
                self.apply_menu_config_change();
                // A preset is a template copied into the Current Look. Its
                // file is never mounted as a live layer and activation does
                // not require a separate user-facing save step.
                self.current_look_autosave
                    .note_immediate_change(Instant::now());
                self.preset_ui.active = Some(ActivePreset {
                    key,
                    name: name.clone(),
                    version: version.clone(),
                    payload_revision,
                    built_in,
                    modified: false,
                });
                self.preset_ui.suggest_update_version(&version);
                self.preset_ui.error = None;
                self.preset_ui.notice = Some(format!("Using {name} {version} now."));
                self.menu_config_error = None;
            }
            Err(err) => {
                self.preset_ui.error = Some(format!("Could not activate preset: {err:#}"));
                self.preset_ui.notice = None;
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
        device.set_texture(3, self.sampler3_scene_color(&current_color_copy.texture))?;
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

    fn finish_present_frame(&mut self, render_epoch: u32, present_started_at: Option<Instant>) {
        let depth_of_field_active = self.settings.menu_config.screen_space_shaders
            && self
                .settings
                .menu_config
                .embedded_effects
                .depth_of_field
                .enabled;
        if !depth_of_field_active {
            self.present_timing.pause();
            return;
        }

        let Some(now) = present_started_at else {
            self.present_timing.invalidate_origin();
            return;
        };

        self.present_timing
            .record_frame_at(now, render_epoch, depth_of_field_active);
    }

    fn release_for_new_device(&mut self) {
        set_menu_diagnostics_active(false);
        self.release_device_resources();
        self.imgui = None;
        self.imgui_hwnd = 0;
        self.render_target_slots = None;
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
        self.motion_blur = None;
        self.motion_blur_creation_failed = false;
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
        self.motion_blur = None;
        self.motion_blur_creation_failed = false;
        self.motion_blur_temporal.reset();
        self.prepared_motion_blur_frame = None;
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
            | EmbeddedEffectKind::DepthOfField
            | EmbeddedEffectKind::MotionBlur => Self {
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

enum PreparedScenePhaseTarget {
    Current {
        surface: Surface9,
        desc: D3DSURFACE_DESC,
    },
    RenderedTexture {
        surface: *mut c_void,
        desc: D3DSURFACE_DESC,
    },
}

impl PreparedScenePhaseTarget {
    fn desc(&self) -> &D3DSURFACE_DESC {
        match self {
            Self::Current { desc, .. } | Self::RenderedTexture { desc, .. } => desc,
        }
    }

    /// Bind the validated target and return an owned surface reference.
    ///
    /// # Safety
    ///
    /// A `RenderedTexture` pointer must remain owned by the engine for the
    /// duration of the image-space callback.
    unsafe fn bind(&self, device: &Device9Ref<'_>) -> Direct3DResult<Surface9> {
        match self {
            Self::Current { surface, .. } => Ok(surface.clone()),
            Self::RenderedTexture { surface, .. } => {
                unsafe { device.set_raw_render_target(0, *surface)? };
                device.render_target(0)
            }
        }
    }
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
const FRAME_PACING_CHART_POINTS: usize = 240;
const FRAME_PACING_WINDOW_MS: f32 = 10_000.0;
const FRAME_PACING_AGGREGATE_UPDATE_INTERVAL_MS: u32 = 250;
const FRAME_PACING_EMA_TIME_CONSTANT_MS: f32 = 1_000.0;
const FRAME_PACING_LIVE_SAMPLE_MAX_MS: f32 = 100.0;
const FRAME_PACING_CHART_MIN_SCALE_MS: f32 = 35.0;
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

static PERFORMANCE_COUNTER_FREQUENCY: AtomicI64 = AtomicI64::new(0);
static CONTINUOUS_PRESENT_WRITER: AtomicBool = AtomicBool::new(false);
static CONTINUOUS_PRESENT_LAST_COUNTER: AtomicI64 = AtomicI64::new(0);
static CONTINUOUS_PRESENT_LAST_EPOCH: AtomicU32 = AtomicU32::new(0);
static CONTINUOUS_PRESENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CONTINUOUS_PRESENT_REJECTED: AtomicU32 = AtomicU32::new(0);
static CONTINUOUS_PRESENT_SAMPLES: [AtomicU32; FRAME_PACING_HISTORY] =
    [const { AtomicU32::new(0) }; FRAME_PACING_HISTORY];

fn consecutive_render_epochs(previous: u32, current: u32) -> bool {
    previous.wrapping_add(1) == current
}

fn present_interval_ms(
    previous_counter: i64,
    previous_epoch: u32,
    counter: Option<i64>,
    render_epoch: u32,
    present_succeeded: bool,
    frequency: i64,
) -> Option<Result<f32, ()>> {
    if previous_counter <= 0 {
        return None;
    }
    let Some(counter) = counter.filter(|counter| *counter > 0) else {
        return Some(Err(()));
    };
    if !present_succeeded
        || frequency <= 0
        || !consecutive_render_epochs(previous_epoch, render_epoch)
    {
        return Some(Err(()));
    }

    let ticks = counter - previous_counter;
    if ticks <= 0 {
        return Some(Err(()));
    }
    let frame_ms = ticks as f64 * 1_000.0 / frequency as f64;
    if frame_ms.is_finite() && frame_ms > 0.0 && frame_ms <= f64::from(f32::MAX) {
        Some(Ok(frame_ms as f32))
    } else {
        Some(Err(()))
    }
}

fn record_continuous_present_interval(
    counter: Option<i64>,
    render_epoch: u32,
    present_succeeded: bool,
) {
    if CONTINUOUS_PRESENT_WRITER
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        CONTINUOUS_PRESENT_REJECTED.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let previous_counter = CONTINUOUS_PRESENT_LAST_COUNTER.load(Ordering::Relaxed);
    let previous_epoch = CONTINUOUS_PRESENT_LAST_EPOCH.load(Ordering::Relaxed);
    let frequency = PERFORMANCE_COUNTER_FREQUENCY.load(Ordering::Relaxed);
    let observation = present_interval_ms(
        previous_counter,
        previous_epoch,
        counter,
        render_epoch,
        present_succeeded,
        frequency,
    );
    let next_counter = if present_succeeded {
        counter.filter(|counter| *counter > 0).unwrap_or(0)
    } else {
        0
    };
    CONTINUOUS_PRESENT_LAST_COUNTER.store(next_counter, Ordering::Relaxed);
    CONTINUOUS_PRESENT_LAST_EPOCH.store(render_epoch, Ordering::Relaxed);
    match observation {
        Some(Ok(frame_ms)) => {
            let sequence = CONTINUOUS_PRESENT_SEQUENCE.load(Ordering::Relaxed);
            CONTINUOUS_PRESENT_SAMPLES[sequence as usize % CONTINUOUS_PRESENT_SAMPLES.len()]
                .store(frame_ms.to_bits(), Ordering::Relaxed);
            CONTINUOUS_PRESENT_SEQUENCE.store(sequence.wrapping_add(1), Ordering::Release);
        }
        Some(Err(())) => {
            CONTINUOUS_PRESENT_REJECTED.fetch_add(1, Ordering::Relaxed);
        }
        None => {}
    }
    CONTINUOUS_PRESENT_WRITER.store(false, Ordering::Release);
}

fn copy_continuous_present_samples(
    cursor: &mut u64,
    output: &mut [f32; FRAME_PACING_HISTORY],
) -> usize {
    let end = CONTINUOUS_PRESENT_SEQUENCE.load(Ordering::Acquire);
    let oldest = end.saturating_sub(FRAME_PACING_HISTORY as u64);
    let start = (*cursor).max(oldest).min(end);
    let count = (end - start) as usize;
    for (output_index, sequence) in (start..end).enumerate() {
        output[output_index] = f32::from_bits(
            CONTINUOUS_PRESENT_SAMPLES[sequence as usize % CONTINUOUS_PRESENT_SAMPLES.len()]
                .load(Ordering::Relaxed),
        );
    }
    *cursor = end;
    count
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
    smoothed_ms: f32,
    display_elapsed_ms: f32,
    published: FramePacingSnapshot,
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
    continuous_cursor: u64,
}

impl Default for FramePacing {
    fn default() -> Self {
        Self {
            samples: [0.0; FRAME_PACING_HISTORY],
            next_index: 0,
            count: 0,
            smoothed_ms: 0.0,
            display_elapsed_ms: 0.0,
            published: FramePacingSnapshot::default(),
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
            continuous_cursor: 0,
        }
    }
}

impl FramePacing {
    #[cfg(test)]
    fn record_sample(&mut self, frame_ms: f32) {
        if !self.capture_sample(frame_ms) {
            return;
        }
        if self.count <= 2
            || self.display_elapsed_ms >= FRAME_PACING_AGGREGATE_UPDATE_INTERVAL_MS as f32
        {
            self.publish_snapshot();
        }
    }

    fn capture_sample(&mut self, frame_ms: f32) -> bool {
        if !frame_ms.is_finite() || frame_ms <= 0.0 {
            return false;
        }

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
        true
    }

    fn publish_snapshot(&mut self) {
        self.published = self.calculate_snapshot();
        self.display_elapsed_ms = 0.0;
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

    fn copy_latest_chart_samples(&self, output: &mut [f32; FRAME_PACING_CHART_POINTS]) -> usize {
        let count = self.count.min(FRAME_PACING_CHART_POINTS);
        let first = (self.next_index + FRAME_PACING_HISTORY - count) % FRAME_PACING_HISTORY;
        for (index, output_sample) in output[..count].iter_mut().enumerate() {
            *output_sample = self.samples[(first + index) % FRAME_PACING_HISTORY];
        }
        count
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
        let scale_max = frame_pacing_chart_scale(p99_ms);
        let off_scale_samples = active_samples
            .iter()
            .filter(|sample| **sample > scale_max)
            .count();
        let mut chart_samples = [0.0; FRAME_PACING_CHART_POINTS];
        let chart_count = copy_latest_frame_times(active_samples, &mut chart_samples);

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
            scale_max,
            off_scale_samples,
            sample_count,
            rejected_intervals: self.rejected_intervals,
            chart_count,
            chart_samples,
            spikes: self.spike_summary(),
        }
    }

    #[cfg(test)]
    fn snapshot(&self) -> FramePacingSnapshot {
        self.published.clone()
    }

    fn snapshot_for_ui(&mut self) -> FramePacingSnapshot {
        let mut captured = [0.0f32; FRAME_PACING_HISTORY];
        let captured_count =
            copy_continuous_present_samples(&mut self.continuous_cursor, &mut captured);
        for frame_ms in &captured[..captured_count] {
            self.capture_sample(*frame_ms);
        }
        self.rejected_intervals = CONTINUOUS_PRESENT_REJECTED.load(Ordering::Relaxed);
        if self.count > 0
            && (self.published.sample_count == 0
                || self.display_elapsed_ms >= FRAME_PACING_AGGREGATE_UPDATE_INTERVAL_MS as f32)
        {
            self.publish_snapshot();
        }

        let mut snapshot = self.published.clone();
        snapshot.live_ms = self.smoothed_ms;
        snapshot.fps = fps_from_ms(self.smoothed_ms);
        snapshot.replace_chart_with_recent_raw(self);
        snapshot
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
            total_slow: self.total_slow_spikes,
            total_fast: self.total_fast_spikes,
            latest,
            largest_slow: self.largest_slow_spike.map(with_current_age),
            largest_fast: self.largest_fast_spike.map(with_current_age),
            periodic,
        }
    }
}

fn copy_latest_frame_times(
    samples: &[f32],
    output: &mut [f32; FRAME_PACING_CHART_POINTS],
) -> usize {
    let count = samples.len().min(FRAME_PACING_CHART_POINTS);
    output[..count].copy_from_slice(&samples[samples.len() - count..]);
    count
}

fn frame_pacing_chart_scale(p99_ms: f32) -> f32 {
    if p99_ms <= 28.0 {
        FRAME_PACING_CHART_MIN_SCALE_MS
    } else if p99_ms <= 42.0 {
        50.0
    } else if p99_ms <= 65.0 {
        75.0
    } else {
        100.0
    }
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
            scale_max: FRAME_PACING_CHART_MIN_SCALE_MS,
            off_scale_samples: 0,
            sample_count: 0,
            rejected_intervals: 0,
            chart_count: 0,
            chart_samples: [0.0; FRAME_PACING_CHART_POINTS],
            spikes: FrameSpikeSummary::default(),
        }
    }
}

impl FramePacingSnapshot {
    fn samples(&self) -> &[f32] {
        &self.chart_samples[..self.chart_count]
    }

    fn replace_chart_with_recent_raw(&mut self, pacing: &FramePacing) {
        self.chart_count = pacing.copy_latest_chart_samples(&mut self.chart_samples);
        self.scale_max = frame_pacing_chart_scale(self.p99_ms);
        self.off_scale_samples = self
            .samples()
            .iter()
            .filter(|sample| **sample > self.scale_max)
            .count();
    }
}

#[cfg(test)]
mod frame_pacing_tests {
    use super::{
        FRAME_BUDGET_30_MS, FRAME_BUDGET_60_MS, FRAME_PACING_AGGREGATE_UPDATE_INTERVAL_MS,
        FRAME_PACING_CHART_POINTS, FRAME_PACING_HISTORY, FRAME_PACING_SPIKE_MEMORY,
        FRAME_PACING_SPIKE_WARMUP_SAMPLES, FramePacing, MENU_DIAGNOSTICS_ACTIVE_BIT,
        MENU_DIAGNOSTICS_SESSION_INCREMENT, MenuTab, PresentFrameTiming, SpikeDirection,
        copy_latest_frame_times, diagnostics_should_be_active, diagnostics_state_transition,
        frame_pacing_chart_scale, present_interval_ms,
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
        assert_eq!(snapshot.off_scale_samples, 0);
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
    fn adaptive_scale_preserves_normal_detail_and_exposes_an_isolated_hitch() {
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
        assert_close(snapshot.scale_max, 35.0);
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
    fn aggregate_metrics_use_a_fixed_readable_update_cadence() {
        let mut pacing = FramePacing::default();
        pacing.record_sample(10.0);
        pacing.record_sample(10.0);
        let held = pacing.snapshot();

        pacing.record_sample(30.0);
        for _ in 0..10 {
            pacing.record_sample(20.0);
        }
        assert_close(pacing.snapshot().average_ms, held.average_ms);
        pacing.record_sample(20.0);
        assert!(pacing.snapshot().average_ms > held.average_ms);
        assert_eq!(FRAME_PACING_AGGREGATE_UPDATE_INTERVAL_MS, 250);
    }

    #[test]
    fn raw_chart_preserves_each_present_interval_and_persistent_jitter() {
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
        assert_close(chart_min, 10.0);
        assert_close(chart_max, 20.0);
        assert_close(snapshot.jitter_ms, 10.0);
    }

    #[test]
    fn raw_chart_keeps_the_latest_240_frames_in_order() {
        let mut samples = [0.0f32; 300];
        for (index, sample) in samples.iter_mut().enumerate() {
            *sample = (index + 1) as f32;
        }
        let mut chart = [0.0f32; FRAME_PACING_CHART_POINTS];
        let chart_count = copy_latest_frame_times(&samples, &mut chart);

        assert_eq!(chart_count, FRAME_PACING_CHART_POINTS);
        assert_close(chart[0], 61.0);
        assert_close(chart[chart_count - 1], 300.0);
    }

    #[test]
    fn chart_scale_has_stable_budget_aware_tiers() {
        assert_close(frame_pacing_chart_scale(16.0), 35.0);
        assert_close(frame_pacing_chart_scale(33.0), 50.0);
        assert_close(frame_pacing_chart_scale(50.0), 75.0);
        assert_close(frame_pacing_chart_scale(90.0), 100.0);
        assert!(frame_pacing_chart_scale(0.0) >= FRAME_BUDGET_30_MS);
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
    fn raw_chart_preserves_short_slow_and_fast_excursions() {
        let mut pacing = FramePacing::default();
        for _ in 0..40 {
            pacing.record_sample(16.0);
        }
        pacing.record_sample(48.0);
        pacing.record_sample(7.0);
        pacing.publish_snapshot();

        let snapshot = pacing.snapshot();
        assert!(snapshot.samples().contains(&48.0));
        assert!(snapshot.samples().contains(&7.0));
        assert_close(snapshot.worst_ms, 48.0);
    }

    #[test]
    fn stable_quantized_cadence_does_not_create_spike_events() {
        let mut pacing = FramePacing::default();
        for _ in 0..80 {
            pacing.record_sample(16.0);
            pacing.record_sample(17.0);
        }
        pacing.publish_snapshot();

        let spikes = pacing.snapshot().spikes;
        assert_eq!(spikes.total_slow, 0);
        assert_eq!(spikes.total_fast, 0);
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
        assert_eq!(pacing.spike_count, 1);
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
        assert_eq!(pacing.spike_count, FRAME_PACING_SPIKE_MEMORY);
        assert!(spikes.total_slow as usize > pacing.spike_count);
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
    fn diagnostics_collection_follows_the_diagnostics_tab_only() {
        assert!(!diagnostics_should_be_active(
            true,
            true,
            MenuTab::Configuration,
            true,
        ));
        assert!(diagnostics_should_be_active(
            true,
            true,
            MenuTab::Diagnostics,
            true,
        ));
        assert!(!diagnostics_should_be_active(
            false,
            true,
            MenuTab::Diagnostics,
            true,
        ));
        assert!(!diagnostics_should_be_active(
            true,
            false,
            MenuTab::Diagnostics,
            true,
        ));
        assert!(!diagnostics_should_be_active(
            true,
            true,
            MenuTab::Diagnostics,
            false,
        ));
    }

    #[test]
    fn present_intervals_are_collected_without_a_menu_gate() {
        let mut pacing = FramePacing::default();
        let frame_ms = present_interval_ms(1_000, 1, Some(1_010), 2, true, 1_000)
            .expect("interval")
            .expect("valid interval");
        pacing.capture_sample(frame_ms);
        pacing.publish_snapshot();

        assert_eq!(pacing.snapshot().samples(), &[10.0]);
    }

    #[test]
    fn skipped_present_callback_cannot_become_a_fake_long_frame() {
        assert_close(
            present_interval_ms(1_000, 10, Some(1_016), 11, true, 1_000)
                .expect("interval")
                .expect("valid interval"),
            16.0,
        );
        assert_eq!(
            present_interval_ms(1_016, 11, Some(1_048), 13, true, 1_000),
            Some(Err(()))
        );
        assert_close(
            present_interval_ms(1_048, 13, Some(1_064), 14, true, 1_000)
                .expect("interval")
                .expect("valid interval"),
            16.0,
        );
    }

    #[test]
    fn successful_present_timeline_reconstructs_exact_interval_metrics() {
        let mut pacing = FramePacing::default();
        for (previous, previous_epoch, current, current_epoch) in [
            (1_000, 30, 1_010, 31),
            (1_010, 31, 1_030, 32),
            (1_030, 32, 1_035, 33),
        ] {
            let frame_ms = present_interval_ms(
                previous,
                previous_epoch,
                Some(current),
                current_epoch,
                true,
                1_000,
            )
            .expect("interval")
            .expect("valid interval");
            pacing.record_sample(frame_ms);
        }
        pacing.publish_snapshot();

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
        assert_eq!(
            present_interval_ms(1_000, 20, Some(1_016), 21, false, 1_000),
            Some(Err(()))
        );
        assert_eq!(
            present_interval_ms(0, 21, Some(1_080), 23, true, 1_000),
            None,
            "the successful callback after a failure only establishes an origin"
        );
        assert_close(
            present_interval_ms(1_080, 23, Some(1_096), 24, true, 1_000)
                .expect("interval")
                .expect("valid interval"),
            16.0,
        );
    }

    #[test]
    fn continuous_capture_hot_path_has_no_allocation_sort_logging_or_runtime_lock() {
        let source = include_str!("runtime.rs");
        let start = source
            .find("fn record_continuous_present_interval")
            .expect("frame-pacing capture");
        let end = source[start..]
            .find("fn copy_continuous_present_samples")
            .map(|offset| start + offset)
            .expect("capture boundary");
        let capture = &source[start..end];

        for forbidden in [
            "Vec<",
            "vec![",
            "format!(",
            "sort_by",
            "Instant::now",
            "query_performance_frequency",
            "log::",
            ".lock(",
            "RUNTIME",
            "Direct3D",
        ] {
            assert!(
                !capture.contains(forbidden),
                "capture hot path contains {forbidden}"
            );
        }
        assert!(
            source
                .split_once("pub(crate) fn configure(")
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once("pub(crate) fn prepare_for_game_load"))
                .map(|(body, _)| body)
                .expect("runtime configuration body")
                .contains("query_performance_frequency()"),
            "counter frequency must be initialized outside the render path"
        );

        let capture_start = source
            .find("pub(crate) fn present_frame_started_at")
            .expect("present-start capture");
        let public_start = source[capture_start..]
            .find("pub(crate) unsafe fn finish_present_frame")
            .map(|offset| capture_start + offset)
            .expect("public finish-present callback");
        let capture = &source[capture_start..public_start];
        assert!(
            capture
                .find("query_performance_counter()")
                .expect("continuous QPC capture")
                < capture
                    .find("PRESENT_FRAME_TIMING_NEEDED")
                    .expect("production timer gate")
        );
        let production_timestamp = capture
            .find(".then(Instant::now)")
            .expect("production timestamp");
        assert!(
            capture
                .find("PRESENT_FRAME_TIMING_NEEDED")
                .expect("production timer gate")
                < production_timestamp
        );

        let public_end = source[public_start..]
            .find("fn runtime_lock_telemetry")
            .map(|offset| public_start + offset)
            .expect("public finish-present boundary");
        let public_finish = &source[public_start..public_end];
        let continuous_capture = public_finish
            .find("record_continuous_present_interval")
            .expect("continuous interval capture");
        let production_gate = public_finish
            .find("if !PRESENT_FRAME_TIMING_NEEDED")
            .expect("production timer early return");
        let runtime_lock = public_finish
            .find("RUNTIME.try_lock")
            .expect("runtime acquisition");
        assert!(!public_finish.contains("Instant::now"));
        assert!(continuous_capture < production_gate);
        assert!(production_gate < runtime_lock);
    }

    #[test]
    fn diagnostics_storage_and_snapshot_work_have_fixed_small_bounds() {
        assert_eq!(FRAME_PACING_HISTORY, 2_048);
        assert_eq!(FRAME_PACING_CHART_POINTS, 240);
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

    #[test]
    fn workbench_separates_presets_configuration_and_diagnostics() {
        let source = include_str!("runtime.rs");
        let menu = source
            .split_once("\nfn draw_shader_menu(\n    ui:")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_shader_menu_toolbar("))
            .map(|(body, _)| body)
            .expect("workbench menu body");

        assert!(menu.contains("Presets##workbench_presets"));
        assert!(menu.contains("Customize##workbench_configuration"));
        assert!(menu.contains("Diagnostics##workbench_diagnostics"));
        assert!(menu.contains("result.diagnostics_visible = true"));
        assert!(!menu.contains("graphics_overview"));
    }

    #[test]
    fn every_effect_badge_uses_one_separator_space() {
        for (status, expected) in [
            ("ON", "[ON] Effect Name##effect"),
            ("OFF", "[OFF] Effect Name##effect"),
            ("ERR", "[ERR] Effect Name##effect"),
        ] {
            assert_eq!(
                super::feature_list_label("  Effect Name  ", "effect", status),
                expected
            );
        }
    }

    #[test]
    fn workbench_header_is_compact_and_persistence_is_automatic() {
        let source = include_str!("runtime.rs");
        let toolbar = source
            .split_once("\nfn draw_shader_menu_toolbar(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_external_change_panel("))
            .map(|(body, _)| body)
            .expect("workbench toolbar body");
        let external = source
            .split_once("\nfn draw_external_change_panel(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_configuration_tab("))
            .map(|(body, _)| body)
            .expect("external-change panel body");

        assert!(toolbar.contains("ui.frame_rate()"));
        assert!(toolbar.contains("FPS"));
        assert!(toolbar.contains("graphics_workbench_header"));
        assert!(toolbar.contains("ui.child_static"));
        assert!(toolbar.contains("ui.panel_background"));
        assert!(toolbar.contains("if external_change"));
        assert!(!toolbar.contains("active_preset"));
        assert!(!toolbar.contains("CURRENT LOOK"));
        assert!(!toolbar.contains("Save for Next Launch"));
        assert!(!toolbar.contains("Undo Changes"));
        assert!(!toolbar.contains("//"));
        assert!(!toolbar.contains("FramePacingSnapshot"));

        assert!(external.contains("FILES CHANGED OUTSIDE THE GAME"));
        assert!(external.contains("Reload Files from Disk"));
        assert!(external.contains("Keep In-Game Look"));
        assert!(!external.contains("//"));
    }

    #[test]
    fn finishing_families_are_separate_editors_over_one_fused_source() {
        assert_eq!(super::FinishingPanel::ALL.len(), 8);
        assert_eq!(
            super::FinishingPanel::ALL.map(super::FinishingPanel::title),
            [
                "Final Output",
                "Color Grading",
                "LUT",
                "Debanding",
                "Film Grain",
                "Vignette",
                "Halation",
                "Chromatic Aberration",
            ]
        );

        let shaders = include_str!("shaders.rs");
        assert!(shaders.contains("\"Final Color Pipeline\""));
        assert!(!shaders.contains("\"Color Grade and Film\""));
        let runtime = include_str!("runtime.rs");
        assert!(runtime.contains("MenuSelection::Finishing(panel)"));
        assert!(runtime.contains("draw_shader_details(ui, source, Some(panel))"));
    }

    #[test]
    fn frame_pacing_ui_has_fixed_cadence_and_no_frequency_selector() {
        let source = include_str!("runtime.rs");
        let panel = source
            .split_once("\nfn draw_frame_pacing_panel(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_diagnostics_metric_card("))
            .map(|(body, _)| body)
            .expect("frame-pacing panel body");

        assert!(panel.contains("automatically four times per second"));
        assert!(panel.contains("AT A GLANCE"));
        assert!(panel.contains("FRAME-TIME SHAPE"));
        assert!(panel.contains("TARGET DELIVERY"));
        assert!(!panel.contains("begin_combo"));
        assert!(!panel.contains("frame_pacing_update_interval"));
    }

    #[test]
    fn preset_library_hides_management_until_requested() {
        let source = include_str!("runtime.rs");
        let library = source
            .split_once("\nfn draw_preset_library(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_preset_manager("))
            .map(|(body, _)| body)
            .expect("preset library body");
        let manager = source
            .split_once("\nfn draw_preset_manager(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_labeled_input_text("))
            .map(|(body, _)| body)
            .expect("preset manager body");

        assert!(library.contains("Choose a Look"));
        assert!(library.contains("Manage Presets"));
        assert!(library.contains("Use This Preset"));
        assert!(library.contains("Reset to Preset"));
        assert!(!library.contains("Replace Changes & Use Preset"));
        assert!(library.contains("Details"));
        assert!(!library.contains("##preset_update_version"));
        assert!(!library.contains("Create Preset & Use It"));
        assert!(!library.contains("//"));

        assert!(manager.contains("Back to Preset Library"));
        assert!(manager.contains("Update Current Preset"));
        assert!(manager.contains("Update Preset & Keep Using It"));
        assert!(manager.contains("##preset_update_version"));
        assert!(manager.contains("Create a New Preset"));
        assert!(manager.contains("Create Preset & Use It"));
        assert!(!manager.contains("//"));
    }

    #[test]
    fn current_look_persistence_has_no_manual_save_or_undo_path() {
        let source = include_str!("runtime.rs");
        let manual_save = ["fn save_menu_", "session("].concat();
        let manual_reload = ["fn reload_menu_", "session("].concat();
        let save_action = ["MenuAction::", "Save"].concat();
        assert!(!source.contains(&manual_save));
        assert!(!source.contains(&manual_reload));
        assert!(!source.contains(&save_action));
        assert!(source.contains("self.current_look_autosave.note_change(Instant::now())"));
        assert!(source.contains("CurrentLookSnapshot::capture"));
    }

    #[test]
    fn published_preset_identity_is_recorded_without_rewriting_the_current_look() {
        let source = include_str!("runtime.rs");
        let events = source
            .split_once("\n    fn poll_preset_service(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    fn reconcile_saved_preset_state("))
            .map(|(body, _)| body)
            .expect("preset event handling");

        assert!(!events.contains("note_change"));
        assert!(events.contains("self.record_active_preset_state();"));
        assert!(events.contains("New preset created and enabled."));
    }

    #[test]
    fn effect_configuration_contains_no_live_diagnostics() {
        let source = include_str!("runtime.rs");
        for (function, boundary, forbidden) in [
            (
                "fn draw_native_pbr_config(",
                "\nfn draw_pbr_diagnostics(",
                &["LIVE PIPELINES", "TRANSITION DIAGNOSTICS"][..],
            ),
            (
                "fn draw_shader_details(",
                "\nfn depth_of_field_option_visible(",
                &["fnv_local_lights::telemetry"][..],
            ),
        ] {
            let signature = format!("\n{function}");
            let body = source
                .split_once(signature.as_str())
                .map(|(_, tail)| tail)
                .and_then(|tail| tail.split_once(boundary))
                .map(|(body, _)| body)
                .expect("configuration panel body");
            for marker in forbidden {
                assert!(
                    !body.contains(marker),
                    "{function} still exposes live diagnostic marker {marker}"
                );
            }
        }
    }

    #[test]
    fn preset_text_fields_draw_labels_above_full_width_hidden_id_widgets() {
        let source = include_str!("runtime.rs");
        let preset_ui = source
            .split_once("\nfn draw_presets_tab(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_labeled_input_text("))
            .map(|(body, _)| body)
            .expect("preset UI body");
        for call in [
            "\"Name\", \"##preset_name\"",
            "\"Version\", \"##preset_version\"",
            "\"Author\", \"##preset_author\"",
            "\"Description\",\n                \"##preset_description\"",
        ] {
            assert!(preset_ui.contains(call), "missing labeled input {call}");
        }
        for clipped_label in [
            "Name##preset_name",
            "Version##preset_version",
            "Author##preset_author",
            "Description##preset_description",
        ] {
            assert!(
                !preset_ui.contains(clipped_label),
                "visible label is still attached after a full-width widget: {clipped_label}"
            );
        }

        let helper = source
            .split_once("\nfn draw_labeled_input_text(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_labeled_input_text_multiline("))
            .map(|(body, _)| body)
            .expect("single-line labeled input helper");
        assert!(
            helper.find("ui.text_colored").expect("visible label")
                < helper.find("ui.input_text").expect("text widget")
        );
        assert!(helper.contains("ui.push_item_width(-1.0)"));
    }

    #[test]
    fn effect_sidebar_is_resizable_with_bounded_persistent_session_width() {
        let source = include_str!("runtime.rs");
        let configuration = source
            .split_once("\nfn draw_configuration_tab(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\nfn draw_presets_tab("))
            .map(|(body, _)| body)
            .expect("configuration tab body");

        assert!(source.contains("menu_sidebar_width: f32"));
        assert!(source.contains("menu_sidebar_width: 270.0"));
        assert!(configuration.contains("ui.vertical_splitter("));
        assert!(configuration.contains("min_sidebar_width = 190.0"));
        assert!(configuration.contains("available_width - 360.0"));
        assert!(configuration.contains("(*sidebar_width).clamp("));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuTab {
    Configuration,
    Presets,
    Diagnostics,
}

impl Default for MenuTab {
    fn default() -> Self {
        Self::Configuration
    }
}

fn diagnostics_should_be_active(
    menu_open: bool,
    imgui_ready: bool,
    tab: MenuTab,
    tab_content_visible: bool,
) -> bool {
    menu_open && imgui_ready && tab == MenuTab::Diagnostics && tab_content_visible
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuSelection {
    General,
    NativePbr,
    NativeSky,
    Finishing(FinishingPanel),
    Shader(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinishingPanel {
    FinalOutput,
    ColorGrading,
    Lut,
    Debanding,
    FilmGrain,
    Vignette,
    Halation,
    ChromaticAberration,
}

impl FinishingPanel {
    const ALL: [Self; 8] = [
        Self::FinalOutput,
        Self::ColorGrading,
        Self::Lut,
        Self::Debanding,
        Self::FilmGrain,
        Self::Vignette,
        Self::Halation,
        Self::ChromaticAberration,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::FinalOutput => "Final Output",
            Self::ColorGrading => "Color Grading",
            Self::Lut => "LUT",
            Self::Debanding => "Debanding",
            Self::FilmGrain => "Film Grain",
            Self::Vignette => "Vignette",
            Self::Halation => "Halation",
            Self::ChromaticAberration => "Chromatic Aberration",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::FinalOutput => {
                "Master control and before/after preview for OMV's fused final-color pipeline."
            }
            Self::ColorGrading => {
                "Exposure, contrast, color balance, saturation, and highlight shaping."
            }
            Self::Lut => "Creative color transform with bundled or installed LUT assets.",
            Self::Debanding => "Subtle dithering that smooths visible gradients and color bands.",
            Self::FilmGrain => "Fine animated texture that reduces sterile digital uniformity.",
            Self::Vignette => {
                "Gentle edge darkening that guides attention toward the image center."
            }
            Self::Halation => "Warm highlight bloom inspired by light scattering through film.",
            Self::ChromaticAberration => {
                "Controlled color separation near the frame edges, measured in pixels."
            }
        }
    }

    fn enabled_key(self) -> Option<&'static str> {
        match self {
            Self::FinalOutput => None,
            Self::ColorGrading => Some("color_grading_enabled"),
            Self::Lut => Some("lut_enabled"),
            Self::Debanding => Some("deband_enabled"),
            Self::FilmGrain => Some("film_grain_enabled"),
            Self::Vignette => Some("vignette_enabled"),
            Self::Halation => Some("halation_enabled"),
            Self::ChromaticAberration => Some("chromatic_aberration_enabled"),
        }
    }

    fn owns_option(self, key: &str) -> bool {
        match self {
            Self::FinalOutput => matches!(key, "strength" | "debug_split"),
            Self::ColorGrading => matches!(
                key,
                "exposure"
                    | "contrast"
                    | "saturation"
                    | "vibrance"
                    | "temperature"
                    | "tint"
                    | "black_fade"
                    | "highlight_rolloff"
            ),
            Self::Lut => matches!(key, "lut_file" | "lut_strength" | "environment_response"),
            Self::Debanding => key == "deband",
            Self::FilmGrain => matches!(key, "film_grain" | "film_grain_size"),
            Self::Vignette => key == "vignette",
            Self::Halation => key == "halation",
            Self::ChromaticAberration => key == "chromatic_aberration",
        }
    }

    fn is_enabled(self, source: &ScreenShaderSource) -> bool {
        if self == Self::FinalOutput {
            return source.enabled;
        }
        source.enabled
            && self.enabled_key().is_some_and(|key| {
                source.options.iter().any(|option| {
                    option.key == key && matches!(option.value, ShaderOptionValue::Bool(true))
                })
            })
    }
}

#[derive(Clone, Copy)]
struct EngineFeatureStatus {
    pbr: pbr::NativePbrRuntimeStatus,
    sky: sky::NativeSkyStatus,
    depth: backend::DepthResolveStatus,
}

impl Default for MenuSelection {
    fn default() -> Self {
        Self::General
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MenuAction {
    #[default]
    None,
    ReloadFiles,
    KeepCurrentLook,
    RefreshPresets,
    CreatePreset,
    PublishPresetVersion,
    ActivatePreset(usize),
}

#[derive(Clone, Copy, Debug, Default)]
struct MenuFrameResult {
    changed: bool,
    action: MenuAction,
    diagnostics_visible: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct MenuToolbarResult {
    action: MenuAction,
}

#[derive(Clone, Copy)]
struct MenuPersistenceView<'a> {
    external_change: bool,
    error: Option<&'a str>,
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

fn draw_pbr_preparation_window(ui: &mut psycho_imgui::Ui<'_>, status: pbr::PbrPreparationStatus) {
    ui.set_next_window_centered(
        0.42,
        0.22,
        460.0,
        170.0,
        620.0,
        240.0,
        psycho_imgui::Condition::Always,
    );
    let title = cstring("OH MY VEGAS // LOCAL SHADER PREPARATION");
    let window = ui.window(&title, None);
    if !window.is_visible() {
        return;
    }

    let stage = match status.phase {
        pbr::PbrPreparationPhase::Inventory => "Checking the local shader cache",
        pbr::PbrPreparationPhase::Compiling => "Compiling missing shaders locally",
        pbr::PbrPreparationPhase::CreatingResources => "Creating Direct3D shader resources",
        pbr::PbrPreparationPhase::Ready => "Ready",
        pbr::PbrPreparationPhase::Failed => "Preparation failed",
        pbr::PbrPreparationPhase::Disabled => "Disabled",
    };
    ui.text_wrapped(&cstring(
        "OMV ships shader source only. This preparation runs after an install or shader change; later launches reuse the verified local cache.",
    ));
    ui.separator();
    ui.text_colored(MENU_ACCENT_TEXT, &cstring(stage));

    let (completed, total, detail) = match status.phase {
        pbr::PbrPreparationPhase::Inventory => (
            status.bytecode_ready,
            status.total,
            format!(
                "{} valid cache entries found",
                status.cache_hits.max(status.bytecode_ready)
            ),
        ),
        pbr::PbrPreparationPhase::Compiling => (
            status.compiled,
            status.cache_misses.max(1),
            format!(
                "{} compiled; {} cache hits; {} missing",
                status.compiled, status.cache_hits, status.cache_misses
            ),
        ),
        pbr::PbrPreparationPhase::CreatingResources => (
            status.resources_ready,
            status.total,
            format!(
                "{} verified bytecode entries; {} D3D resources",
                status.bytecode_ready, status.resources_ready
            ),
        ),
        _ => (
            status.bytecode_ready,
            status.total,
            format!("{} ready; {} failed", status.bytecode_ready, status.failed),
        ),
    };
    let fraction = if total == 0 {
        0.0
    } else {
        (completed as f32 / total as f32).clamp(0.0, 1.0)
    };
    ui.progress_bar(
        fraction,
        ui.content_region_available_width().max(1.0),
        0.0,
        &cstring(format!("{completed}/{total}")),
    );
    ui.text_colored(MENU_MUTED_TEXT, &cstring(detail));
}

fn draw_shader_menu(
    ui: &mut psycho_imgui::Ui<'_>,
    menu_config: &mut GraphicsMenuConfig,
    sources: &mut [ScreenShaderSource],
    preset_ui: &mut PresetUiState,
    active_tab: &mut MenuTab,
    selected_item: &mut MenuSelection,
    sidebar_width: &mut f32,
    frame_pacing: &FramePacingSnapshot,
    feature_status: EngineFeatureStatus,
    persistence: MenuPersistenceView<'_>,
) -> MenuFrameResult {
    ui.set_next_window_centered(
        0.86,
        0.88,
        780.0,
        520.0,
        1280.0,
        900.0,
        psycho_imgui::Condition::FirstUseEver,
    );

    let title = cstring("Oh My Vegas - Graphics");
    let window = ui.window(&title, None);
    if !window.is_visible() {
        return MenuFrameResult::default();
    }

    let mut result = MenuFrameResult::default();
    result.action =
        draw_shader_menu_toolbar(ui, persistence.external_change, persistence.error).action;

    let tabs = ui.tab_bar(&cstring("graphics_workbench_tabs"));
    if !tabs.is_visible() {
        return result;
    }

    {
        let presets = ui.tab_item(&cstring("Presets##workbench_presets"));
        if presets.is_visible() {
            *active_tab = MenuTab::Presets;
            if let Some(action) = draw_presets_tab(ui, preset_ui) {
                result.action = action;
            }
        }
    }

    {
        let configuration = ui.tab_item(&cstring("Customize##workbench_configuration"));
        if configuration.is_visible() {
            *active_tab = MenuTab::Configuration;
            result.changed |= draw_configuration_tab(
                ui,
                menu_config,
                sources,
                selected_item,
                sidebar_width,
                feature_status,
            );
        }
    }

    {
        let diagnostics = ui.tab_item(&cstring("Diagnostics##workbench_diagnostics"));
        if diagnostics.is_visible() {
            *active_tab = MenuTab::Diagnostics;
            result.diagnostics_visible = true;
            result.changed |=
                draw_diagnostics_tab(ui, menu_config, sources, frame_pacing, feature_status);
        }
    }

    result
}

fn draw_shader_menu_toolbar(
    ui: &mut psycho_imgui::Ui<'_>,
    external_change: bool,
    menu_config_error: Option<&str>,
) -> MenuToolbarResult {
    let mut result = MenuToolbarResult::default();
    let frame_rate = ui.frame_rate();
    let (frame_rate_color, frame_rate_text) = if frame_rate.is_finite() && frame_rate > 0.0 {
        (
            frame_time_color(1_000.0 / frame_rate),
            format!("{frame_rate:.1} FPS"),
        )
    } else {
        (MENU_MUTED_TEXT, "-- FPS".to_owned())
    };

    {
        let header = ui.child_static(&cstring("graphics_workbench_header"), 0.0, 46.0, true);
        if header.is_visible() {
            ui.panel_background([0.22, 0.90, 0.72, 0.82]);
            ui.text_colored(MENU_ACCENT_TEXT, &cstring("OH MY VEGAS"));
            ui.same_line();
            ui.text_colored(MENU_MUTED_TEXT, &cstring("GRAPHICS"));
            ui.same_line();
            ui.text_colored(frame_rate_color, &cstring(frame_rate_text));
        }
    }

    if external_change {
        result.action = draw_external_change_panel(ui).action;
    }

    if let Some(error) = menu_config_error {
        ui.text_colored(MENU_ERROR_TEXT, &cstring(error));
    }

    result
}

fn draw_external_change_panel(ui: &mut psycho_imgui::Ui<'_>) -> MenuToolbarResult {
    let mut result = MenuToolbarResult::default();
    let panel = ui.child_static(&cstring("graphics_external_changes"), 0.0, 128.0, true);
    if panel.is_visible() {
        ui.panel_background([0.95, 0.70, 0.30, 0.82]);
        ui.text_colored(MENU_WARN_TEXT, &cstring("FILES CHANGED OUTSIDE THE GAME"));
        ui.text_wrapped(&cstring(
            "Automatic saving is paused so OMV cannot overwrite an external edit. Load those files, or explicitly keep the look currently visible in game.",
        ));
        if ui.button_colored(
            &cstring("Reload Files from Disk##config_reload_external"),
            MENU_RELOAD_BUTTON,
            MENU_RELOAD_BUTTON_HOVERED,
            MENU_RELOAD_BUTTON_ACTIVE,
        ) {
            result.action = MenuAction::ReloadFiles;
        }
        ui.same_line();
        if ui.button_colored(
            &cstring("Keep In-Game Look##config_keep_current"),
            MENU_SAVE_BUTTON,
            MENU_SAVE_BUTTON_HOVERED,
            MENU_SAVE_BUTTON_ACTIVE,
        ) {
            result.action = MenuAction::KeepCurrentLook;
        }
    }
    result
}

fn draw_configuration_tab(
    ui: &mut psycho_imgui::Ui<'_>,
    menu_config: &mut GraphicsMenuConfig,
    sources: &mut [ScreenShaderSource],
    selected_item: &mut MenuSelection,
    sidebar_width: &mut f32,
    feature_status: EngineFeatureStatus,
) -> bool {
    let mut changed = false;
    clamp_menu_selection(sources, selected_item);
    let available_width = ui.content_region_available_width().max(1.0);
    let available_height = ui.content_region_available_height().max(1.0);
    let min_sidebar_width = 190.0;
    let max_sidebar_width = (available_width - 360.0).max(min_sidebar_width);
    *sidebar_width = (*sidebar_width).clamp(min_sidebar_width, max_sidebar_width);

    {
        let item_list = cstring("graphics_feature_list");
        let child = ui.child(&item_list, *sidebar_width, 0.0, true);
        if child.is_visible() {
            draw_feature_list(ui, menu_config, sources, selected_item);
        }
    }

    ui.same_line();
    ui.vertical_splitter(
        &cstring("##graphics_feature_splitter"),
        sidebar_width,
        min_sidebar_width,
        max_sidebar_width,
        available_height,
    );
    ui.same_line();

    {
        let item_details = cstring("graphics_feature_details");
        let child = ui.child(&item_details, 0.0, 0.0, true);
        if child.is_visible() {
            match *selected_item {
                MenuSelection::General => {
                    changed |= draw_global_config(ui, menu_config, feature_status.depth);
                    let sources_changed = draw_render_stack_config(ui, sources);
                    if sources_changed {
                        shaders::sync_embedded_effect_config(
                            sources,
                            &mut menu_config.embedded_effects,
                        );
                    }
                    changed |= sources_changed;
                }
                MenuSelection::NativePbr => {
                    changed |=
                        draw_native_pbr_config(ui, &mut menu_config.native_pbr, feature_status.pbr);
                }
                MenuSelection::NativeSky => {
                    changed |=
                        draw_native_sky_config(ui, &mut menu_config.native_sky, feature_status.sky);
                }
                MenuSelection::Finishing(panel) => {
                    if let Some(source) = sources.iter_mut().find(|source| {
                        source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade)
                    }) {
                        let source_changed = draw_shader_details(ui, source, Some(panel));
                        if source_changed {
                            shaders::sync_embedded_effect_config(
                                sources,
                                &mut menu_config.embedded_effects,
                            );
                        }
                        changed |= source_changed;
                    }
                }
                MenuSelection::Shader(index) => {
                    if let Some(source) = sources.get_mut(index) {
                        let is_embedded = source.is_embedded_effect();
                        let source_changed = draw_shader_details(ui, source, None);
                        if source_changed && is_embedded {
                            shaders::sync_embedded_effect_config(
                                sources,
                                &mut menu_config.embedded_effects,
                            );
                        }
                        changed |= source_changed;
                    }
                }
            }
        }
    }

    changed
}

fn draw_render_stack_config(
    ui: &mut psycho_imgui::Ui<'_>,
    sources: &mut [ScreenShaderSource],
) -> bool {
    let (enabled_count, error_count, scene_count, final_count) = shader_counts(sources);
    ui.separator_text(&cstring("EFFECT STACK"));
    let summary = cstring(format!(
        "{} effects, {} enabled, {} scene, {} final, {} issue{}",
        sources.len(),
        enabled_count,
        scene_count,
        final_count,
        error_count,
        if error_count == 1 { "" } else { "s" }
    ));
    ui.text_colored(MENU_MUTED_TEXT, &summary);

    let mut changed = false;
    let enable_all = cstring("Enable all");
    if ui.button(&enable_all) {
        changed |= set_all_sources_enabled(sources, true);
    }
    ui.same_line();
    let disable_all = cstring("Disable all");
    if ui.button(&disable_all) {
        changed |= set_all_sources_enabled(sources, false);
    }

    changed
}

fn draw_presets_tab(
    ui: &mut psycho_imgui::Ui<'_>,
    state: &mut PresetUiState,
) -> Option<MenuAction> {
    match state.view {
        PresetUiView::Closed => draw_preset_library(ui, state),
        PresetUiView::Manager | PresetUiView::Update | PresetUiView::Create => {
            draw_preset_manager(ui, state)
        }
    }
}

fn draw_preset_library(
    ui: &mut psycho_imgui::Ui<'_>,
    state: &mut PresetUiState,
) -> Option<MenuAction> {
    let mut action = None;
    ui.text_colored(MENU_ACCENT_TEXT, &cstring("Choose a Look"));
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(
            "Browse installed presets and apply one whenever you want a different atmosphere.",
        ),
    );
    if ui.button(&cstring("Manage Presets##preset_manage")) {
        state.view = PresetUiView::Manager;
    }
    if let Some(error) = state.error.as_deref() {
        ui.text_colored(MENU_ERROR_TEXT, &cstring(error));
    } else if let Some(notice) = state.notice.as_deref() {
        ui.text_colored(MENU_GOOD_TEXT, &cstring(notice));
    }

    let available_width = ui.content_region_available_width().max(1.0);
    let list_width = (available_width * 0.38).clamp(280.0, 430.0);
    {
        let list = ui.child(&cstring("preset_catalog"), list_width, 0.0, true);
        if list.is_visible() {
            if draw_labeled_input_text(ui, "Search presets", "##preset_filter", &mut state.filter) {
                state.catalog_page = 0;
            }
            if ui.button(&cstring("Refresh##preset_refresh")) {
                action = Some(MenuAction::RefreshPresets);
            }
            ui.same_line();
            ui.text_colored(
                MENU_MUTED_TEXT,
                &cstring(format!("{} installed", state.catalog.entries.len())),
            );
            ui.separator();

            let filter = text_buffer(&state.filter).to_ascii_lowercase();
            const PAGE_SIZE: usize = 100;
            let matching_count = state
                .catalog
                .entries
                .iter()
                .filter(|entry| filter.is_empty() || entry.search_key.contains(&filter))
                .count();
            let page_count = matching_count.div_ceil(PAGE_SIZE).max(1);
            state.catalog_page = state.catalog_page.min(page_count - 1);
            if page_count > 1 {
                if state.catalog_page > 0 && ui.button(&cstring("Previous##preset_page")) {
                    state.catalog_page -= 1;
                }
                if state.catalog_page > 0 {
                    ui.same_line();
                }
                ui.text_colored(
                    MENU_MUTED_TEXT,
                    &cstring(format!("Page {} / {}", state.catalog_page + 1, page_count)),
                );
                if state.catalog_page + 1 < page_count {
                    ui.same_line();
                    if ui.button(&cstring("Next##preset_page")) {
                        state.catalog_page += 1;
                    }
                }
            } else if matching_count == 0 {
                ui.text_colored(MENU_MUTED_TEXT, &cstring("No presets match this search."));
            }

            let first_match = state.catalog_page * PAGE_SIZE;
            let mut visible_match = 0usize;
            for (index, entry) in state.catalog.entries.iter().enumerate() {
                if !filter.is_empty() && !entry.search_key.contains(&filter) {
                    continue;
                }
                if visible_match < first_match {
                    visible_match += 1;
                    continue;
                }
                if visible_match >= first_match + PAGE_SIZE {
                    break;
                }
                visible_match += 1;
                let active = state
                    .active
                    .as_ref()
                    .is_some_and(|active| entry.key().as_ref() == Some(&active.key));
                let status = if active {
                    "  (In use)"
                } else if entry.error.is_some() {
                    "  (Unavailable)"
                } else if entry.built_in {
                    "  (Included)"
                } else {
                    ""
                };
                let label = cstring(format!("{}{status}##preset_{index}", entry.display_name,));
                if ui.selectable(&label, state.selected == Some(index)) {
                    state.selected = Some(index);
                    state.show_technical_details = false;
                }
            }
        }
    }

    ui.same_line();
    {
        let details = ui.child(&cstring("preset_details"), 0.0, 0.0, true);
        if details.is_visible() {
            if let Some(index) = state.selected {
                if let Some(entry) = state.catalog.entries.get(index) {
                    let display_name = entry.display_name.clone();
                    let version = entry.version.clone();
                    let author = entry.author.clone();
                    let description = entry.description.clone();
                    let error = entry.error.clone();
                    let selected_key = entry.key();
                    let created_with = entry
                        .document
                        .as_ref()
                        .map(|document| document.metadata.created_with.clone());
                    let source = entry.path.as_ref().map_or_else(
                        || "Compiled into OMV".to_owned(),
                        |path| path.display().to_string(),
                    );
                    let activatable = entry.document.is_some() && error.is_none();
                    let selected_is_active = state
                        .active
                        .as_ref()
                        .is_some_and(|active| selected_key.as_ref() == Some(&active.key));
                    let active_is_modified = selected_is_active
                        && state.active.as_ref().is_some_and(|active| active.modified);

                    ui.separator_text(&cstring("ABOUT THIS LOOK"));
                    ui.text_colored(MENU_ACCENT_TEXT, &cstring(&display_name));
                    ui.label_value(
                        &cstring("Author"),
                        &cstring(if author.is_empty() {
                            "Unknown"
                        } else {
                            &author
                        }),
                        MENU_MUTED_TEXT,
                    );
                    ui.text_wrapped(&cstring(if description.is_empty() {
                        "No description supplied."
                    } else {
                        &description
                    }));

                    if let Some(error) = error {
                        ui.text_colored(MENU_ERROR_TEXT, &cstring(error));
                    } else if selected_is_active && !active_is_modified {
                        ui.text_colored(MENU_GOOD_TEXT, &cstring("Currently in use"));
                    } else if activatable {
                        let use_label = if selected_is_active {
                            "Reset to Preset##preset_activate"
                        } else {
                            "Use This Preset##preset_activate"
                        };
                        if active_is_modified {
                            ui.text_colored(
                                MENU_WARN_TEXT,
                                &cstring(
                                    "Your current look started here, but now contains live changes.",
                                ),
                            );
                        }
                        if ui.button_colored(
                            &cstring(use_label),
                            MENU_SAVE_BUTTON,
                            MENU_SAVE_BUTTON_HOVERED,
                            MENU_SAVE_BUTTON_ACTIVE,
                        ) {
                            action = Some(MenuAction::ActivatePreset(index));
                        }
                    }

                    let technical_details_label = if state.show_technical_details {
                        "Hide Details##preset_technical_details"
                    } else {
                        "Details##preset_technical_details"
                    };
                    if ui.button(&cstring(technical_details_label)) {
                        state.show_technical_details = !state.show_technical_details;
                    }
                    if state.show_technical_details {
                        ui.label_value(
                            &cstring("Version"),
                            &cstring(if version.is_empty() { "-" } else { &version }),
                            MENU_GOOD_TEXT,
                        );
                        ui.text_colored(MENU_MUTED_TEXT, &cstring(format!("File: {source}")));
                        if let Some(created_with) = created_with {
                            ui.label_value(
                                &cstring("Created with"),
                                &cstring(format!("OMV {}", created_with.omv_version)),
                                MENU_MUTED_TEXT,
                            );
                            let dirty = if created_with.git_dirty == Some(true) {
                                " (dirty working tree)"
                            } else {
                                ""
                            };
                            ui.label_value(
                                &cstring("Git commit"),
                                &cstring(format!("{}{dirty}", created_with.git_commit)),
                                MENU_MUTED_TEXT,
                            );
                            ui.label_value(
                                &cstring("Git branch"),
                                &cstring(&created_with.git_branch),
                                MENU_MUTED_TEXT,
                            );
                            ui.label_value(
                                &cstring("Git tag"),
                                &cstring(if created_with.git_tag.is_empty() {
                                    "None"
                                } else {
                                    &created_with.git_tag
                                }),
                                MENU_MUTED_TEXT,
                            );
                        }
                    }
                }
            } else {
                ui.text_colored(
                    MENU_MUTED_TEXT,
                    &cstring("Choose a preset on the left to learn more."),
                );
            }
        }
    }
    action
}

fn draw_preset_manager(
    ui: &mut psycho_imgui::Ui<'_>,
    state: &mut PresetUiState,
) -> Option<MenuAction> {
    let mut action = None;
    let active = state.active.as_ref().map(|active| {
        (
            active.name.clone(),
            active.version.clone(),
            active.built_in,
            active.modified,
        )
    });
    let can_update = matches!(active, Some((_, _, false, true)));
    if state.view == PresetUiView::Update && !can_update {
        state.view = PresetUiView::Manager;
    }

    if ui.button(&cstring("Back to Preset Library##preset_manager_close")) {
        state.view = PresetUiView::Closed;
        return action;
    }
    ui.text_colored(MENU_ACCENT_TEXT, &cstring("Manage Presets"));
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(
            "Create a shareable preset from your current look, or update a preset you already own.",
        ),
    );
    if let Some(error) = state.error.as_deref() {
        ui.text_colored(MENU_ERROR_TEXT, &cstring(error));
    } else if let Some(notice) = state.notice.as_deref() {
        ui.text_colored(MENU_GOOD_TEXT, &cstring(notice));
    }

    match state.view {
        PresetUiView::Closed => {}
        PresetUiView::Manager => {
            ui.separator_text(&cstring("AVAILABLE ACTIONS"));
            match active.as_ref() {
                Some((_, _, false, true)) => {
                    if ui.button_colored(
                        &cstring("Update Current Preset##preset_manager_update"),
                        MENU_SAVE_BUTTON,
                        MENU_SAVE_BUTTON_HOVERED,
                        MENU_SAVE_BUTTON_ACTIVE,
                    ) {
                        state.view = PresetUiView::Update;
                    }
                    ui.text_wrapped(&cstring(
                        "Store your latest edits as a newer version of the preset you are using.",
                    ));
                }
                Some((name, version, true, _)) => ui.text_wrapped(&cstring(format!(
                    "{name} {version} is included with OMV and cannot be overwritten. Create your own preset instead."
                ))),
                Some((name, version, false, false)) => ui.text_wrapped(&cstring(format!(
                    "{name} {version} has no new edits. Customize the look first if you want to update it."
                ))),
                None => ui.text_wrapped(&cstring(
                    "Your current look is custom. You can save it as a new preset.",
                )),
            }
            if ui.button(&cstring("Create a New Preset##preset_manager_create")) {
                state.view = PresetUiView::Create;
            }
            ui.text_wrapped(&cstring(
                "Give the current look its own name, version, author, and description.",
            ));
        }
        PresetUiView::Update => {
            let Some((name, version, false, true)) = active else {
                return action;
            };
            if ui.button(&cstring("Choose Another Action##preset_manager_home")) {
                state.view = PresetUiView::Manager;
                return action;
            }
            ui.separator_text(&cstring("UPDATE PRESET"));
            ui.text_wrapped(&cstring(format!(
                "Save the current look as the next version of {name}. The preset filename stays the same; its version changes from {version}."
            )));
            draw_labeled_input_text(
                ui,
                "New version",
                "##preset_update_version",
                &mut state.update_version,
            );
            if state.update_pending {
                ui.text_colored(MENU_MUTED_TEXT, &cstring("Updating preset..."));
            } else if state.create_pending {
                ui.text_colored(
                    MENU_MUTED_TEXT,
                    &cstring("Finish creating the new preset first."),
                );
            } else if ui.button_colored(
                &cstring("Update Preset & Keep Using It##preset_publish_version"),
                MENU_SAVE_BUTTON,
                MENU_SAVE_BUTTON_HOVERED,
                MENU_SAVE_BUTTON_ACTIVE,
            ) {
                action = Some(MenuAction::PublishPresetVersion);
            }
        }
        PresetUiView::Create => {
            if ui.button(&cstring("Choose Another Action##preset_manager_home")) {
                state.view = PresetUiView::Manager;
                return action;
            }
            ui.separator_text(&cstring("CREATE A NEW PRESET"));
            ui.text_wrapped(&cstring(
                "Make a new shareable preset from the current live look. This does not alter the preset you started from.",
            ));
            draw_labeled_input_text(ui, "Name", "##preset_name", &mut state.create_name);
            draw_labeled_input_text(ui, "Version", "##preset_version", &mut state.create_version);
            draw_labeled_input_text(ui, "Author", "##preset_author", &mut state.create_author);
            draw_labeled_input_text_multiline(
                ui,
                "Description",
                "##preset_description",
                &mut state.create_description,
                72.0,
            );
            if state.create_pending {
                ui.text_colored(MENU_MUTED_TEXT, &cstring("Creating preset..."));
            } else if state.update_pending {
                ui.text_colored(
                    MENU_MUTED_TEXT,
                    &cstring("Finish updating the active preset first."),
                );
            } else if ui.button_colored(
                &cstring("Create Preset & Use It##preset_create"),
                MENU_SAVE_BUTTON,
                MENU_SAVE_BUTTON_HOVERED,
                MENU_SAVE_BUTTON_ACTIVE,
            ) {
                action = Some(MenuAction::CreatePreset);
            }
        }
    }

    action
}

fn draw_labeled_input_text(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    buffer: &mut [u8],
) -> bool {
    ui.text_colored(MENU_MUTED_TEXT, &cstring(label));
    let _width = ui.push_item_width(-1.0);
    ui.input_text(&cstring(id), buffer)
}

fn draw_labeled_input_text_multiline(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    buffer: &mut [u8],
    height: f32,
) -> bool {
    ui.text_colored(MENU_MUTED_TEXT, &cstring(label));
    let _width = ui.push_item_width(-1.0);
    ui.input_text_multiline(&cstring(id), buffer, height)
}

fn draw_diagnostics_tab(
    ui: &mut psycho_imgui::Ui<'_>,
    menu_config: &mut GraphicsMenuConfig,
    sources: &[ScreenShaderSource],
    frame_pacing: &FramePacingSnapshot,
    feature_status: EngineFeatureStatus,
) -> bool {
    let diagnostics = ui.child(&cstring("graphics_diagnostics"), 0.0, 0.0, false);
    if !diagnostics.is_visible() {
        return false;
    }

    ui.text_colored(MENU_ACCENT_TEXT, &cstring("LIVE DIAGNOSTICS"));
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(
            "Frame intervals are captured continuously. Detailed effect counters run only while this tab is visible.",
        ),
    );

    draw_frame_pacing_panel(ui, frame_pacing);
    let mut changed = false;
    draw_render_stack_diagnostics(ui, sources);
    draw_depth_diagnostics(ui, menu_config.depth_provider, feature_status.depth);
    draw_native_sky_diagnostics(ui, feature_status.sky);
    changed |= draw_pbr_diagnostics(ui, &mut menu_config.native_pbr, feature_status.pbr);
    draw_local_lights_diagnostics(ui, sources);
    draw_world_pipeline_diagnostics(ui);
    changed
}

fn draw_render_stack_diagnostics(ui: &mut psycho_imgui::Ui<'_>, sources: &[ScreenShaderSource]) {
    let (enabled_count, error_count, scene_count, final_count) = shader_counts(sources);
    ui.separator_text(&cstring("RENDER STACK"));
    ui.text_colored(
        if error_count == 0 {
            MENU_GOOD_TEXT
        } else {
            MENU_WARN_TEXT
        },
        &cstring(format!(
            "{} enabled of {} // {} scene // {} final // {} issue{}",
            enabled_count,
            sources.len(),
            scene_count,
            final_count,
            error_count,
            if error_count == 1 { "" } else { "s" },
        )),
    );
    for source in sources.iter().filter(|source| shader_has_error(source)) {
        ui.text_colored(
            MENU_ERROR_TEXT,
            &cstring(format!(
                "{}: shader or configuration error",
                shader_display_name(source)
            )),
        );
    }
}

fn draw_depth_diagnostics(
    ui: &mut psycho_imgui::Ui<'_>,
    configured_provider: DepthProviderConfig,
    status: backend::DepthResolveStatus,
) {
    ui.separator_text(&cstring("DEPTH"));
    let configured = match configured_provider {
        DepthProviderConfig::None => "Disabled",
        DepthProviderConfig::FalloutNewVegas => "Fallout New Vegas native depth",
    };
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(format!("Configured source: {configured}")),
    );
    let (color, route) = match status.route {
        backend::DepthResolveRouteStatus::Unprobed => (MENU_WARN_TEXT, "Waiting for D3D device"),
        backend::DepthResolveRouteStatus::Resz => (MENU_GOOD_TEXT, "RESZ"),
        backend::DepthResolveRouteStatus::Nvapi => (MENU_GOOD_TEXT, "NVIDIA NvAPI"),
        backend::DepthResolveRouteStatus::Unavailable => (MENU_ERROR_TEXT, "Unavailable"),
    };
    ui.text_colored(color, &cstring(format!("Resolve route: {route}")));
    if status.route == backend::DepthResolveRouteStatus::Unavailable {
        ui.text_wrapped(&cstring(status.reason));
    }
}

fn draw_native_sky_diagnostics(ui: &mut psycho_imgui::Ui<'_>, status: sky::NativeSkyStatus) {
    ui.separator_text(&cstring("NATIVE SKY"));
    let (color, text) = native_sky_status_summary(status);
    ui.text_colored(color, &cstring(text));
    if status.enabled {
        ui.text_colored(
            MENU_MUTED_TEXT,
            &cstring(format!(
                "Shader resources: {}/{} ready",
                status.created.max(status.compiled),
                status.total
            )),
        );
    }
}

fn draw_frame_pacing_panel(ui: &mut psycho_imgui::Ui<'_>, frame_pacing: &FramePacingSnapshot) {
    ui.separator_text(&cstring("FRAME PACING"));
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(
            "Every successful Present advances the raw graph. Readable summary metrics refresh automatically four times per second.",
        ),
    );

    if frame_pacing.samples().len() > 1 {
        let label = cstring("##frame_pacing");
        let warning_label = cstring("60 FPS");
        let critical_label = cstring("30 FPS");
        let suffix = cstring(" ms");
        let chart = psycho_imgui::TelemetryChart {
            values: frame_pacing.samples(),
            scale_min: 0.0,
            scale_max: frame_pacing.scale_max,
            width: 0.0,
            height: 190.0,
            warning_threshold: FRAME_BUDGET_60_MS,
            critical_threshold: FRAME_BUDGET_30_MS,
            danger_below: false,
            sample_interval_seconds: 0.0,
            impulse_from_zero: false,
            color_by_threshold: true,
            line_color: MENU_ACCENT_TEXT,
            fill_color: [0.20, 0.78, 0.67, 0.18],
            warning_label: &warning_label,
            critical_label: &critical_label,
            value_suffix: &suffix,
        };
        ui.telemetry_chart(&label, &chart);
    } else {
        let collecting = cstring("Waiting for two successful Present intervals...");
        ui.text_colored(MENU_MUTED_TEXT, &collecting);
    }
    if frame_pacing.sample_count < 2 {
        return;
    }

    ui.separator_text(&cstring("AT A GLANCE"));
    let card_width = ((ui.content_region_available_width() - 16.0) / 3.0).max(150.0);
    draw_diagnostics_metric_card(
        ui,
        "frame_live",
        "CURRENT",
        &format!("{:.1} FPS", frame_pacing.fps),
        &format!("{:.2} ms right now", frame_pacing.live_ms),
        frame_time_color(frame_pacing.live_ms),
        card_width,
    );
    ui.same_line();
    draw_diagnostics_metric_card(
        ui,
        "frame_average",
        "AVERAGE",
        &format!("{:.1} FPS", frame_pacing.average_fps),
        &format!(
            "{:.2} ms over {:.1} s",
            frame_pacing.average_ms, frame_pacing.history_seconds
        ),
        frame_time_color(frame_pacing.average_ms),
        card_width,
    );
    ui.same_line();
    draw_diagnostics_metric_card(
        ui,
        "frame_low",
        "1% LOW",
        &format!("{:.1} FPS", frame_pacing.one_percent_low_fps),
        "Slowest one percent of recent frames",
        frame_time_color(frame_pacing.p99_ms),
        card_width,
    );

    ui.separator_text(&cstring("FRAME-TIME SHAPE"));
    draw_diagnostics_metric_card(
        ui,
        "frame_typical",
        "TYPICAL FRAME",
        &format!("{:.2} ms", frame_pacing.p50_ms),
        "Half of recent frames were faster",
        frame_time_color(frame_pacing.p50_ms),
        card_width,
    );
    ui.same_line();
    draw_diagnostics_metric_card(
        ui,
        "frame_slow_edge",
        "SLOW EDGE",
        &format!("P95  {:.2} ms", frame_pacing.p95_ms),
        &format!("P99  {:.2} ms", frame_pacing.p99_ms),
        frame_time_color(frame_pacing.p99_ms),
        card_width,
    );
    ui.same_line();
    draw_diagnostics_metric_card(
        ui,
        "frame_worst",
        "WORST RECENT FRAME",
        &format!("{:.2} ms", frame_pacing.worst_ms),
        &format!("Across {} captured frames", frame_pacing.sample_count),
        frame_time_color(frame_pacing.worst_ms),
        card_width,
    );

    let half_width = ((ui.content_region_available_width() - 8.0) / 2.0).max(180.0);
    draw_diagnostics_metric_card(
        ui,
        "frame_jitter",
        "FRAME-TO-FRAME JITTER",
        &format!("{:.2} ms", frame_pacing.jitter_ms),
        "95th percentile change between neighbors",
        frame_time_color(frame_pacing.jitter_ms),
        half_width,
    );
    ui.same_line();
    draw_diagnostics_metric_card(
        ui,
        "frame_mad",
        "STABLE VARIATION",
        &format!("{:.2} ms", frame_pacing.median_absolute_deviation_ms),
        "Normal spread around the typical frame",
        frame_time_color(frame_pacing.median_absolute_deviation_ms),
        half_width,
    );

    ui.separator_text(&cstring("TARGET DELIVERY"));
    draw_diagnostics_metric_card(
        ui,
        "budget_60",
        "60 FPS TARGET",
        &format!("{:.1}% ON TIME", frame_pacing.budget_60_hit_percent),
        "Frames delivered within 16.67 ms",
        budget_hit_color(frame_pacing.budget_60_hit_percent),
        half_width,
    );
    ui.same_line();
    draw_diagnostics_metric_card(
        ui,
        "budget_30",
        "30 FPS TARGET",
        &format!("{:.1}% ON TIME", frame_pacing.budget_30_hit_percent),
        "Frames delivered within 33.33 ms",
        budget_hit_color(frame_pacing.budget_30_hit_percent),
        half_width,
    );

    if frame_pacing.off_scale_samples > 0 {
        ui.text_colored(
            MENU_ERROR_TEXT,
            &cstring(format!(
                "{} recent frame{} exceeded the {:.0} ms chart scale; metrics retain the exact values.",
                frame_pacing.off_scale_samples,
                if frame_pacing.off_scale_samples == 1 {
                    ""
                } else {
                    "s"
                },
                frame_pacing.scale_max,
            )),
        );
    }
    draw_spike_summary(ui, frame_pacing);

    let contention = runtime_lock_telemetry();
    if frame_pacing.rejected_intervals > 0 || contention.has_rejections() {
        let optional_samples_skipped = contention.present_apply
            + contention.present_finish
            + contention.failed_present
            + contention.scene_phase
            + contention.world_color
            + contention.reset;
        ui.separator_text(&cstring("MEASUREMENT HEALTH"));
        ui.text_colored(
            MENU_WARN_TEXT,
            &cstring(format!(
                "{} Present interval{} could not be measured cleanly.",
                frame_pacing.rejected_intervals,
                if frame_pacing.rejected_intervals == 1 {
                    ""
                } else {
                    "s"
                },
            )),
        );
        if optional_samples_skipped > 0 {
            ui.text_wrapped(&cstring(format!(
                "OMV skipped {optional_samples_skipped} optional diagnostic sample{} because the render state was busy. Skipping avoids stalling the game.",
                if optional_samples_skipped == 1 { "" } else { "s" },
            )));
        }
    }
}

fn draw_diagnostics_metric_card(
    ui: &mut psycho_imgui::Ui<'_>,
    id: &str,
    title: &str,
    value: &str,
    detail: &str,
    accent: [f32; 4],
    width: f32,
) {
    let card = ui.child(
        &cstring(format!("diagnostics_card_{id}")),
        width,
        94.0,
        true,
    );
    if card.is_visible() {
        ui.panel_background(accent);
        ui.text_colored(MENU_MUTED_TEXT, &cstring(title));
        ui.text_colored(accent, &cstring(value));
        ui.text_wrapped(&cstring(detail));
    }
}

fn draw_spike_summary(ui: &mut psycho_imgui::Ui<'_>, frame_pacing: &FramePacingSnapshot) {
    let spikes = frame_pacing.spikes;
    ui.separator_text(&cstring("PACING EVENTS"));
    if spikes.total_slow == 0 && spikes.total_fast == 0 {
        ui.text_colored(
            MENU_GOOD_TEXT,
            &cstring(format!(
                "Pacing looks stable around the {:.2} ms adaptive baseline.",
                frame_pacing.baseline_ms
            )),
        );
        ui.text_colored(
            MENU_MUTED_TEXT,
            &cstring("No significant slow or unusually fast frame-time excursions detected."),
        );
        return;
    }

    let latest = spikes.latest.map_or_else(
        || "latest unavailable".to_owned(),
        |event| {
            format!(
                "latest {} {:.2} ms ({:+.2}) {:.1} s ago",
                event.direction.label(),
                event.frame_ms,
                event.delta_ms,
                event.age_ms * 0.001,
            )
        },
    );
    let largest_slow = spikes.largest_slow.map_or_else(
        || "--".to_owned(),
        |event| format!("{:+.2} ms", event.delta_ms),
    );
    let largest_fast = spikes.largest_fast.map_or_else(
        || "--".to_owned(),
        |event| format!("{:+.2} ms", event.delta_ms),
    );
    ui.text_colored(
        MENU_WARN_TEXT,
        &cstring(format!(
            "Detected {} slow pacing event{} and {} unusually fast event{}.",
            spikes.total_slow,
            if spikes.total_slow == 1 { "" } else { "s" },
            spikes.total_fast,
            if spikes.total_fast == 1 { "" } else { "s" },
        )),
    );
    ui.label_value(&cstring("Latest"), &cstring(latest), MENU_MUTED_TEXT);
    ui.label_value(
        &cstring("Largest slow excursion"),
        &cstring(largest_slow),
        MENU_WARN_TEXT,
    );
    ui.label_value(
        &cstring("Largest fast excursion"),
        &cstring(largest_fast),
        MENU_MUTED_TEXT,
    );
    if let Some(periodic) = spikes.periodic {
        ui.text_colored(
            MENU_ERROR_TEXT,
            &cstring(format!(
                "Repeating {} event every {:.2} s (+/- {:.1} ms): {} repeats, {:.0}% confidence.",
                periodic.direction.label(),
                periodic.interval_ms * 0.001,
                periodic.spread_ms,
                periodic.repeats,
                periodic.confidence_percent,
            )),
        );
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

fn draw_global_config(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &mut GraphicsMenuConfig,
    depth_status: backend::DepthResolveStatus,
) -> bool {
    let mut changed = false;

    let heading = cstring("GENERAL");
    ui.separator_text(&heading);
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring("Workbench access, effect ownership, and asset refresh behavior."),
    );

    changed |= draw_config_checkbox(
        ui,
        "Enable OMV graphics",
        "global.screen_space_shaders",
        &mut config.screen_space_shaders,
    );

    changed |= draw_menu_keybind_control(ui, &mut config.menu_toggle_key);

    changed |= draw_depth_provider_config(ui, &mut config.depth_provider, depth_status);

    ui.separator_text(&cstring("ADVANCED"));
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
    status: backend::DepthResolveStatus,
) -> bool {
    let provider_name = match depth_provider {
        DepthProviderConfig::None => "Disabled",
        DepthProviderConfig::FalloutNewVegas => "Fallout New Vegas",
    };
    ui.separator_text(&cstring("DEPTH SOURCE"));
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(format!("Current: {provider_name}")),
    );
    if status.route == backend::DepthResolveRouteStatus::Unavailable
        && *depth_provider == DepthProviderConfig::FalloutNewVegas
    {
        ui.text_colored(
            MENU_ERROR_TEXT,
            &cstring("Depth is unavailable. See Diagnostics for the resolver reason."),
        );
    }

    let mut changed = false;
    let none = cstring("Disabled##global.depth_provider.none");
    if ui.button(&none) && *depth_provider != DepthProviderConfig::None {
        *depth_provider = DepthProviderConfig::None;
        changed = true;
    }
    ui.same_line();
    let fnv = cstring("Fallout New Vegas##global.depth_provider.fnv");
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

    let preparation_active = matches!(
        status.preparation.phase,
        pbr::PbrPreparationPhase::Inventory
            | pbr::PbrPreparationPhase::Compiling
            | pbr::PbrPreparationPhase::CreatingResources
            | pbr::PbrPreparationPhase::Failed
    );
    let contract_degraded = status.active_contracts_failed
        || status.land_lod_contract_failed
        || status.terrain_fade_contract_failed
        || status.close_terrain_contract_failed;
    if preparation_active || status.block_reason.is_some() || (config.enabled && contract_degraded)
    {
        let (status_color, status_text) = native_pbr_status_summary(status);
        ui.text_colored(status_color, &cstring(status_text));
    }
    if status.preparation.phase == pbr::PbrPreparationPhase::Failed {
        let retry = cstring("Retry local shader preparation##native_pbr.retry");
        if ui.button(&retry) {
            pbr::retry_preparation();
        }
    }
    ui.separator();

    let mut changed = false;
    changed |= draw_config_checkbox(ui, "Enable PBR", "native_pbr.enabled", &mut config.enabled);

    if config.enabled {
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
    }

    changed
}

fn draw_pbr_diagnostics(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &mut crate::config::NativePbrConfig,
    status: pbr::NativePbrRuntimeStatus,
) -> bool {
    ui.separator_text(&cstring("PBR PIPELINES"));
    let (status_color, status_text) = native_pbr_status_summary(status);
    ui.text_colored(status_color, &cstring(status_text));
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(format!(
            "Local preparation: {} cache hits, {} compiled, {}/{} resources ready, {} failed",
            status.preparation.cache_hits,
            status.preparation.compiled,
            status.preparation.resources_ready,
            status.preparation.total,
            status.preparation.failed,
        )),
    );
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

    ui.separator_text(&cstring("OBJECT TRANSITIONS"));
    let changed = draw_config_checkbox(
        ui,
        "Track object lighting transitions",
        "native_pbr.debug_log_draws",
        &mut config.debug_log_draws,
    );
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring("Development telemetry is sampled only while Diagnostics is visible."),
    );
    if config.debug_log_draws {
        ui.text(&cstring(format!(
            "Last contract change: {} -> {} // {} changes last frame",
            status.object_last_contract_transition_from,
            status.object_last_contract_transition_to,
            status.object_contract_transitions_last_frame,
        )));
        ui.text(&cstring(format!(
            "Last fallback: {} // row {} // selector 0x{:08X}",
            status.object_last_reject_reason,
            status.object_last_reject_row,
            status.object_last_reject_selector,
        )));
        if status.object_last_fade_geometry != 0 {
            ui.text(&cstring(format!(
                "Specular fade: distance {:.2} // range {:.2}..{:.2} // expected {:.4} // staged {:.4} // c25.w {:.4}",
                status.object_last_fade_distance,
                status.object_last_fade_start,
                status.object_last_fade_end,
                status.object_last_fade_expected,
                status.object_last_fade_staged,
                status.object_last_fade_c25,
            )));
            ui.text_colored(
                MENU_MUTED_TEXT,
                &cstring(format!(
                    "Geometry 0x{:08X} // property 0x{:08X} // light capacity {} / 0x{:08X}",
                    status.object_last_fade_geometry,
                    status.object_last_fade_property,
                    status.object_last_light_capacity,
                    status.object_last_light_signature,
                )),
            );
            ui.text_colored(
                MENU_MUTED_TEXT,
                &cstring(format!(
                    "Material resources: base 0x{:08X} // normal 0x{:08X}",
                    status.object_last_base_texture, status.object_last_normal_texture,
                )),
            );
        } else {
            ui.text_colored(
                MENU_MUTED_TEXT,
                &cstring("Waiting for a combined-specular object draw."),
            );
        }
    }

    changed
}

fn native_pbr_status_summary(status: pbr::NativePbrRuntimeStatus) -> ([f32; 4], String) {
    let any_shader_failure = status.active_contracts_failed
        || status.land_lod_contract_failed
        || status.terrain_fade_contract_failed
        || status.close_terrain_contract_failed;
    let any_resource_ready = status.object_resources_ready != 0
        || status.land_lod_resources_ready != 0
        || status.terrain_fade_resources_ready != 0
        || status.close_terrain_resources_ready != 0;
    match status.preparation.phase {
        pbr::PbrPreparationPhase::Inventory => {
            (MENU_WARN_TEXT, "Checking the local shader cache".to_owned())
        }
        pbr::PbrPreparationPhase::Compiling => (
            MENU_WARN_TEXT,
            "Compiling missing shaders locally".to_owned(),
        ),
        pbr::PbrPreparationPhase::CreatingResources => {
            (MENU_WARN_TEXT, "Preparing graphics resources".to_owned())
        }
        pbr::PbrPreparationPhase::Failed => (
            MENU_ERROR_TEXT,
            format!(
                "Local shader preparation failed for {} variant(s)",
                status.preparation.failed
            ),
        ),
        _ if status.block_reason.is_some() => (
            MENU_WARN_TEXT,
            format!("Blocked: {}", status.block_reason.unwrap_or("unknown")),
        ),
        _ if status.installed && status.shader_enabled && any_shader_failure => {
            (MENU_WARN_TEXT, "Active with fallback".to_owned())
        }
        _ if status.installed && status.shader_enabled && !any_resource_ready => {
            (MENU_WARN_TEXT, "Preparing graphics resources".to_owned())
        }
        _ if status.installed && status.shader_enabled => (MENU_GOOD_TEXT, "Active".to_owned()),
        _ => (MENU_MUTED_TEXT, "Disabled".to_owned()),
    }
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
    if status.failed
        || !status.installed
        || (status.enabled && status.created.max(status.compiled) != status.total)
    {
        let (status_color, status_text) = native_sky_status_summary(status);
        ui.text_colored(status_color, &cstring(status_text));
    }
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

fn native_sky_status_summary(status: sky::NativeSkyStatus) -> ([f32; 4], String) {
    if status.failed {
        (MENU_ERROR_TEXT, "Shader error".to_owned())
    } else if status.enabled && status.created == status.total {
        (MENU_GOOD_TEXT, "Active".to_owned())
    } else if status.enabled {
        (MENU_WARN_TEXT, "Preparing graphics resources".to_owned())
    } else if status.installed {
        (MENU_MUTED_TEXT, "Disabled".to_owned())
    } else {
        (MENU_WARN_TEXT, "Hook unavailable".to_owned())
    }
}

fn draw_local_lights_diagnostics(ui: &mut psycho_imgui::Ui<'_>, sources: &[ScreenShaderSource]) {
    ui.separator_text(&cstring("LOCAL VOLUMETRIC LIGHTS"));
    let telemetry = crate::fnv_local_lights::telemetry();
    let hook_status = if !telemetry.hooks_ready {
        "Capture hooks unavailable"
    } else if telemetry.capture_enabled {
        if telemetry.shadow_hook_ready {
            "Scene capture active; native shadows available"
        } else {
            "Scene capture active; using shadowless fallback"
        }
    } else {
        "Capture disabled by configuration"
    };
    ui.text_colored(
        if telemetry.hooks_ready && telemetry.capture_enabled {
            MENU_GOOD_TEXT
        } else {
            MENU_WARN_TEXT
        },
        &cstring(hook_status),
    );
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(format!(
            "Traversal {} // scene {} // rendered {} // shadowed {}",
            telemetry.traversals,
            telemetry.scene_lights,
            telemetry.rendered,
            telemetry.shadowed_lights,
        )),
    );
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(format!(
            "Shadow slots {} // accepted {} // rejected {} // overflow {} // R32F {} // A8 {} // bad format {}",
            telemetry.captured,
            telemetry.accepted,
            telemetry.rejected,
            telemetry.overflow,
            telemetry.r32f,
            telemetry.a8r8g8b8,
            telemetry.rejected_formats,
        )),
    );
    ui.text_colored(
        MENU_MUTED_TEXT,
        &cstring(format!(
            "Nonblocking misses: capture {} // publish {} // consume {} // reset {}",
            telemetry.staging_busy,
            telemetry.publish_busy,
            telemetry.consume_busy,
            telemetry.reset_busy,
        )),
    );

    let quality = sources
        .iter()
        .find(|source| {
            source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricLighting)
        })
        .and_then(|source| {
            source
                .options
                .iter()
                .find(|option| option.key == "local_lights_quality")
        })
        .and_then(|option| match option.value {
            ShaderOptionValue::Integer(value) => Some(value),
            _ => None,
        })
        .unwrap_or(1);
    let budget = match quality {
        0 => "Performance: quarter resolution, 2 lights, 4 samples, 2 shadowless draws",
        2 => "Ultra: half resolution, 4 lights, 10 samples, 2 shadowless draws",
        _ => "High: half resolution, 4 lights, 6 samples, 2 shadowless draws",
    };
    ui.text_colored(MENU_MUTED_TEXT, &cstring(budget));
}

fn draw_world_pipeline_diagnostics(ui: &mut psycho_imgui::Ui<'_>) {
    ui.separator_text(&cstring("WORLD FOG"));
    if let Some((distance_bound, transmittance)) = crate::fnv_world_pipeline::fog_estimate() {
        ui.text_colored(
            MENU_GOOD_TEXT,
            &cstring(format!(
                "Current bound: {:.0} units // estimated horizontal transmission: {:.1}%",
                distance_bound,
                transmittance * 100.0,
            )),
        );
    } else {
        ui.text_colored(
            MENU_MUTED_TEXT,
            &cstring("Waiting for an eligible world frame."),
        );
    }
}

fn draw_feature_list(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &GraphicsMenuConfig,
    sources: &[ScreenShaderSource],
    selected_item: &mut MenuSelection,
) {
    let heading = cstring("SETTINGS");
    ui.separator_text(&heading);
    if ui.selectable(
        &cstring("General##general_select"),
        *selected_item == MenuSelection::General,
    ) {
        *selected_item = MenuSelection::General;
    }

    let heading = cstring("ENGINE FEATURES");
    ui.separator_text(&heading);
    let pbr_label = cstring(configured_feature_label(
        "PBR Materials",
        "native_pbr_select",
        config.native_pbr.enabled,
    ));
    if ui.selectable(&pbr_label, *selected_item == MenuSelection::NativePbr) {
        *selected_item = MenuSelection::NativePbr;
    }
    let sky_label = cstring(configured_feature_label(
        "Native Sky",
        "native_sky_select",
        config.native_sky.enabled,
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
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade) {
            for panel in FinishingPanel::ALL {
                let label = cstring(configured_feature_label(
                    panel.title(),
                    &format!("finishing_{panel:?}"),
                    panel.is_enabled(source),
                ));
                if ui.selectable(&label, *selected_item == MenuSelection::Finishing(panel)) {
                    *selected_item = MenuSelection::Finishing(panel);
                }
            }
            embedded_count += FinishingPanel::ALL.len();
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

fn configured_feature_label(name: &str, id: &str, enabled: bool) -> String {
    feature_list_label(name, id, if enabled { "ON" } else { "OFF" })
}

fn feature_list_label(name: &str, id: impl std::fmt::Display, status: &str) -> String {
    format!("[{status}] {}##{id}", name.trim())
}

fn draw_shader_details(
    ui: &mut psycho_imgui::Ui<'_>,
    source: &mut ScreenShaderSource,
    finishing_panel: Option<FinishingPanel>,
) -> bool {
    let mut changed = false;
    let name = cstring(finishing_panel.map_or_else(
        || shader_display_name(source),
        |panel| panel.title().to_owned(),
    ));
    ui.separator_text(&name);

    if let Some(description) = finishing_panel
        .map(FinishingPanel::description)
        .or_else(|| embedded_effect_description(source.embedded_effect_kind()))
    {
        ui.text_colored(MENU_MUTED_TEXT, &cstring(description));
    }

    if let Some(key) = finishing_panel.and_then(FinishingPanel::enabled_key) {
        if let Some(option_index) = source.options.iter().position(|option| option.key == key) {
            let mut enabled = matches!(
                source.options[option_index].value,
                ShaderOptionValue::Bool(true)
            );
            let enabled_label = cstring(format!("Enabled##{}.{}", source.name, key));
            if ui.checkbox(&enabled_label, &mut enabled) {
                if let Err(err) = source.set_option_bool(option_index, enabled) {
                    source.config_error = Some(format!("{err:#}"));
                } else {
                    changed = true;
                }
            }
            if !source.enabled {
                ui.text_colored(
                    MENU_WARN_TEXT,
                    &cstring("Final Output is disabled, so this effect is currently bypassed."),
                );
            }
        }
    } else {
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
    }

    if source.is_external_file() {
        let path_text = cstring(format!("External shader: {}", source.path.display()));
        ui.text_wrapped(&path_text);
        let config_text = cstring(format!("Config: {}", source.config_path.display()));
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
        if finishing_panel.is_some_and(|panel| !panel.owns_option(option.key.as_str())) {
            continue;
        }
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::VolumetricLighting)
            && option.key == "local_lights_enabled"
        {
            ui.spacing();
            let heading = cstring("LOCAL LIGHTS");
            ui.separator_text(&heading);
            ui.text_colored(
                MENU_MUTED_TEXT,
                &cstring("Adds nearby scene lights to volumetric scattering."),
            );
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
        "ON"
    } else {
        "OFF"
    };
    feature_list_label(
        &shader_display_name(source),
        format_args!("shader_select_{index}"),
        status,
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

fn embedded_effect_description(kind: Option<EmbeddedEffectKind>) -> Option<&'static str> {
    match kind {
        Some(EmbeddedEffectKind::FastAmbientOcclusion) => {
            Some("Broad ambient grounding for terrain, structures, and world geometry.")
        }
        Some(EmbeddedEffectKind::ContactAmbientOcclusion) => {
            Some("Fine contact shadows for creases, intersections, and close geometry.")
        }
        Some(EmbeddedEffectKind::VolumetricFog) => {
            Some("Depth-aware exterior fog with height and natural local variation.")
        }
        Some(EmbeddedEffectKind::VolumetricLighting) => {
            Some("Depth-aware sun and local-light scattering for exterior scenes.")
        }
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
        Some(EmbeddedEffectKind::MotionBlur) => Some(
            "Depth-aware camera shutter blur with cut rejection and isolated first-person motion.",
        ),
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
    match *selected_item {
        MenuSelection::Shader(index) if index >= sources.len() => {
            *selected_item = MenuSelection::General;
        }
        MenuSelection::Finishing(_)
            if !sources.iter().any(|source| {
                source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade)
            }) =>
        {
            *selected_item = MenuSelection::General;
        }
        _ => {}
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

fn text_buffer(buffer: &[u8]) -> &str {
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    std::str::from_utf8(&buffer[..length]).unwrap_or_default()
}

fn write_text_buffer(buffer: &mut [u8], text: &str) {
    buffer.fill(0);
    let length = text.len().min(buffer.len().saturating_sub(1));
    buffer[..length].copy_from_slice(&text.as_bytes()[..length]);
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
