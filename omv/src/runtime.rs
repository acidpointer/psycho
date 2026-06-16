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
        D3DCULL_NONE, D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE, D3DRS_COLORWRITEENABLE,
        D3DRS_CULLMODE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV,
        D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSBT_ALL, D3DTA_TEXTURE,
        D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1,
        D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, Device9Ref,
        Direct3DResult, PixelShader9, ScreenVertex, StateBlock9, Surface9, Texture9,
    },
    winapi::{get_active_window, is_window},
};
use parking_lot::Mutex;
use windows::{
    Win32::{
        Foundation::E_FAIL,
        Graphics::Direct3D9::{D3DSURFACE_DESC, D3DVIEWPORT9},
    },
    core::Error as WindowsError,
};

use crate::{
    backend::{self, DepthFrame, DepthProvider, DepthTexture},
    config::{DepthProviderConfig, GraphicsMenuConfig},
    effects::{ambient_occlusion, blooming_hdr, pbr, sunshafts},
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
static MENU_TOGGLE_KEY: AtomicU32 = AtomicU32::new(DEFAULT_MENU_TOGGLE_KEY);
static MENU_KEY_CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING_MENU_TOGGLE_KEY: AtomicU32 = AtomicU32::new(0);

pub(crate) fn configure(settings: RuntimeSettings) {
    MENU_TOGGLE_KEY.store(
        sanitize_menu_toggle_key(settings.menu_toggle_key),
        Ordering::Release,
    );

    let mut runtime = RUNTIME.lock();
    runtime.configure(settings);
}

pub(crate) unsafe fn apply_present_frame(device_ptr: *mut c_void, hwnd_hint: *mut c_void) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        return;
    };

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
        return;
    };

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

pub(crate) unsafe fn apply_fnv_scene_post_image_space(device_ptr: *mut c_void) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        return;
    };

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
        return;
    };

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
        return;
    };

    let result = unsafe { runtime.capture_fnv_world_color(device_ptr) };
    if let Err(err) = result {
        runtime.log_world_color_error(&err);
    }
}

pub(crate) fn needs_fnv_depth_capture() -> bool {
    let Some(runtime) = RUNTIME.try_lock() else {
        return false;
    };

    runtime.needs_fnv_scene_inputs()
}

pub(crate) unsafe fn release_device_resources(device_ptr: *mut c_void) {
    let mut runtime = RUNTIME.lock();
    runtime.release_if_device(device_ptr);
}

pub(crate) unsafe fn finish_present_frame(device_ptr: *mut c_void) {
    let Some(mut runtime) = RUNTIME.try_lock() else {
        return;
    };

    runtime.finish_present_frame(device_ptr);
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

    let handled = psycho_imgui::wndproc(hwnd, msg, wparam, lparam);
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
    blooming_hdr: Option<blooming_hdr::BloomingHdrEffect>,
    sunshafts: Option<sunshafts::SunshaftsEffect>,
    final_color_copy: Option<BackbufferCopy>,
    scene_pre_color_copy: Option<BackbufferCopy>,
    scene_post_color_copy: Option<BackbufferCopy>,
    world_color_copy: Option<BackbufferCopy>,
    state_block: Option<StateBlock9>,
    imgui: Option<psycho_imgui::Dx9Context>,
    imgui_hwnd: usize,
    imgui_needs_device_objects: bool,
    selected_menu_item: MenuSelection,
    frame_pacing: FramePacing,
    next_scan: Option<Instant>,
    frame_index: u32,
    last_depth_available: Option<bool>,
    last_fog_available: Option<bool>,
    last_sun_available: Option<bool>,
    error_logs: u32,
    scan_error_logs: u32,
    imgui_error_logs: u32,
    menu_config_error: Option<String>,
    scene_apply_logs: u32,
    scene_target_logs: u32,
    world_color_capture_logs: u32,
    world_color_captured_this_frame: bool,
    applied_phases: AppliedShaderPhases,
}

impl Default for ScreenShaderRuntime {
    fn default() -> Self {
        Self {
            settings: RuntimeSettings::default(),
            sources: Vec::new(),
            device_ptr: 0,
            compiled: None,
            ambient_occlusion: None,
            blooming_hdr: None,
            sunshafts: None,
            final_color_copy: None,
            scene_pre_color_copy: None,
            scene_post_color_copy: None,
            world_color_copy: None,
            state_block: None,
            imgui: None,
            imgui_hwnd: 0,
            imgui_needs_device_objects: false,
            selected_menu_item: MenuSelection::default(),
            frame_pacing: FramePacing::default(),
            next_scan: None,
            frame_index: 0,
            last_depth_available: None,
            last_fog_available: None,
            last_sun_available: None,
            error_logs: 0,
            scan_error_logs: 0,
            imgui_error_logs: 0,
            menu_config_error: None,
            scene_apply_logs: 0,
            scene_target_logs: 0,
            world_color_capture_logs: 0,
            world_color_captured_this_frame: false,
            applied_phases: AppliedShaderPhases::default(),
        }
    }
}

impl ScreenShaderRuntime {
    fn configure(&mut self, settings: RuntimeSettings) {
        pbr::configure_runtime_options(settings.menu_config.native_pbr.into());
        self.settings = settings;
        self.compiled = None;
        self.next_scan = None;
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
        if !self.needs_fnv_scene_inputs() {
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

        match shaders::scan_screen_shaders(&self.sources) {
            Ok(scan) => {
                let old_count = self.sources.len();
                let sources = shaders::merge_embedded_sources(
                    &self.settings.menu_config.embedded_effects,
                    scan.sources,
                );
                let new_count = sources.len();
                if scan.shader_resources_changed {
                    self.compiled = None;
                }
                self.sources = sources;
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
                    source.enabled && source.phase() == phase
                })
                .map(|pass| self.sources[pass.source_index].pass_count)
                .sum()
        });
        if enabled_count == 0 {
            return Ok(());
        }

        let frame_inputs = backend::FrameInputs {
            camera: backend::camera_frame(self.settings.depth_provider, desc),
            depth: self.current_depth_frame(),
            environment: backend::environment_frame(self.settings.depth_provider),
            sun: backend::sun_frame(self.settings.depth_provider),
        };
        self.log_frame_input_state(&frame_inputs);

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

            if matches!(
                source.embedded_effect_kind(),
                Some(
                    EmbeddedEffectKind::FastAmbientOcclusion
                        | EmbeddedEffectKind::ContactAmbientOcclusion
                )
            ) {
                let source_pass_count = source.pass_count.max(1);
                if !ambient_occlusion_drawn {
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
                    self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
                    ambient_occlusion_drawn = true;
                }
                pass_index = pass_index.saturating_add(source_pass_count);
                continue;
            }

            if source.embedded_effect_kind() == Some(EmbeddedEffectKind::BloomingHdr) {
                let source = source.clone();
                self.draw_blooming_hdr_pipeline(
                    device,
                    backbuffer,
                    desc,
                    &frame_inputs,
                    &copy,
                    &source,
                )?;
                self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
                pass_index = pass_index.saturating_add(source.pass_count.max(1));
                continue;
            }

            if source.embedded_effect_kind() == Some(EmbeddedEffectKind::Sunshafts) {
                let source = source.clone();
                self.draw_sunshafts_pipeline(
                    device,
                    backbuffer,
                    desc,
                    &frame_inputs,
                    &copy,
                    &source,
                )?;
                self.bind_common_state(device, backbuffer, desc, &frame_inputs, &copy)?;
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

    fn draw_blooming_hdr_pipeline(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &backend::FrameInputs,
        current_color_copy: &BackbufferCopy,
        source: &ScreenShaderSource,
    ) -> Direct3DResult<()> {
        if self.blooming_hdr.is_none() {
            self.blooming_hdr = Some(blooming_hdr::BloomingHdrEffect::create(device)?);
            log::info!("[BLOOM_HDR] Engine-side pipeline initialized");
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
            source,
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
            "[SHADERS] Frame inputs: depth={} (provider={}, near={:.3}, far={:.3}), fog={} (start={:.3}, end={:.3}, power={:.3}), sun={} (uv={:.3},{:.3}, daylight={:.3})",
            if depth_available {
                "available"
            } else {
                "missing"
            },
            frame_inputs.depth.provider_id(),
            frame_inputs.camera.near_z,
            frame_inputs.camera.far_z,
            if fog_available {
                "available"
            } else {
                "missing"
            },
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
        if provider == DepthProvider::None {
            return DepthFrame::none();
        }

        let Some(texture) = backend::depth_texture_ptr(provider).and_then(DepthTexture::new) else {
            return DepthFrame::none();
        };

        let first_person_texture =
            backend::first_person_depth_texture_ptr(provider).and_then(DepthTexture::new);
        DepthFrame::from_textures(provider, texture, first_person_texture)
    }

    fn draw_menu(&mut self) -> Direct3DResult<()> {
        let Some(imgui) = self.imgui.as_mut() else {
            return Ok(());
        };

        if self.imgui_needs_device_objects && imgui.create_device_objects() {
            self.imgui_needs_device_objects = false;
        }

        let menu_config_changed = {
            let frame_pacing = self.frame_pacing.snapshot();
            let pbr_status = pbr::runtime_status();
            let mut ui = imgui.new_frame(true);
            draw_shader_menu(
                &mut ui,
                &mut self.settings.menu_config,
                &mut self.sources,
                &mut self.selected_menu_item,
                &frame_pacing,
                pbr_status,
                self.menu_config_error.as_deref(),
            )
        };

        imgui.render();
        if menu_config_changed {
            self.apply_menu_config_change();
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
        pbr::configure_runtime_options(self.settings.menu_config.native_pbr.into());

        match crate::config::save_menu_config(&self.settings.menu_config) {
            Ok(()) => self.menu_config_error = None,
            Err(err) => self.menu_config_error = Some(format!("{err:#}")),
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
                && (source.is_embedded_effect() || source.bytecode.is_some())
        })
    }

    fn needs_fnv_scene_inputs(&self) -> bool {
        self.settings.depth_provider == DepthProvider::FalloutNewVegas
            && !self.applied_phases.is_applied(ShaderPhase::FinalImageSpace)
            && self.has_enabled_shader()
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
                    && (source.is_embedded_effect() || pass.shader.is_some())
            })
        })
    }

    fn release_if_device(&mut self, device_ptr: *mut c_void) {
        if self.device_ptr == 0 || self.device_ptr == device_ptr as usize {
            self.release_device_resources();
        }
    }

    fn finish_present_frame(&mut self, device_ptr: *mut c_void) {
        let _ = device_ptr;
        self.frame_pacing.record_frame();
        self.applied_phases = AppliedShaderPhases::default();
        self.world_color_captured_this_frame = false;
        self.frame_index = self.frame_index.wrapping_add(1);
        backend::finish_frame();
    }

    fn release_for_new_device(&mut self) {
        self.release_device_resources();
        self.imgui = None;
        self.imgui_hwnd = 0;
        IMGUI_READY.store(false, Ordering::Release);
        self.device_ptr = 0;
    }

    fn release_device_resources(&mut self) {
        self.compiled = None;
        self.ambient_occlusion = None;
        self.blooming_hdr = None;
        self.sunshafts = None;
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
        self.ambient_occlusion = None;
        self.blooming_hdr = None;
        self.sunshafts = None;
        self.world_color_captured_this_frame = false;
        self.state_block = None;
    }

    fn log_frame_error(&mut self, err: &windows::core::Error) {
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

    fn log_world_color_error(&mut self, err: &windows::core::Error) {
        if self.error_logs < 8 {
            log::warn!("[FNV] World color capture skipped: {err}");
            self.error_logs += 1;
        }
    }
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
    format: windows::Win32::Graphics::Direct3D9::D3DFORMAT,
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

const FRAME_PACING_HISTORY: usize = 180;
const FRAME_PACING_MAX_MS: f32 = 100.0;

#[derive(Clone)]
struct FramePacing {
    samples: [f32; FRAME_PACING_HISTORY],
    next_index: usize,
    count: usize,
    last_present: Option<Instant>,
    smoothed_ms: f32,
}

impl Default for FramePacing {
    fn default() -> Self {
        Self {
            samples: [0.0; FRAME_PACING_HISTORY],
            next_index: 0,
            count: 0,
            last_present: None,
            smoothed_ms: 0.0,
        }
    }
}

impl FramePacing {
    fn record_frame(&mut self) {
        let now = Instant::now();
        if let Some(last_present) = self.last_present {
            let frame_ms = now
                .duration_since(last_present)
                .as_secs_f32()
                .mul_add(1000.0, 0.0)
                .clamp(0.0, FRAME_PACING_MAX_MS);
            self.samples[self.next_index] = frame_ms;
            self.next_index = (self.next_index + 1) % FRAME_PACING_HISTORY;
            self.count = (self.count + 1).min(FRAME_PACING_HISTORY);
            self.smoothed_ms = if self.smoothed_ms <= f32::EPSILON {
                frame_ms
            } else {
                self.smoothed_ms * 0.92 + frame_ms * 0.08
            };
        }
        self.last_present = Some(now);
    }

    fn snapshot(&self) -> FramePacingSnapshot {
        let mut samples = Vec::with_capacity(self.count);
        if self.count == FRAME_PACING_HISTORY {
            samples.extend_from_slice(&self.samples[self.next_index..]);
            samples.extend_from_slice(&self.samples[..self.next_index]);
        } else {
            samples.extend_from_slice(&self.samples[..self.count]);
        }

        let last_ms = samples.last().copied().unwrap_or(0.0);
        let fps = if self.smoothed_ms > 0.001 {
            1000.0 / self.smoothed_ms
        } else {
            0.0
        };
        let scale_max = samples
            .iter()
            .copied()
            .fold(33.3_f32, f32::max)
            .clamp(16.7, FRAME_PACING_MAX_MS);

        FramePacingSnapshot {
            fps,
            last_ms,
            scale_max,
            samples,
        }
    }
}

struct FramePacingSnapshot {
    fps: f32,
    last_ms: f32,
    scale_max: f32,
    samples: Vec<f32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuSelection {
    NativePbr,
    Shader(usize),
}

impl Default for MenuSelection {
    fn default() -> Self {
        Self::NativePbr
    }
}

const MENU_MUTED_TEXT: [f32; 4] = [0.56, 0.62, 0.67, 1.0];
const MENU_GOOD_TEXT: [f32; 4] = [0.35, 0.88, 0.78, 1.0];
const MENU_WARN_TEXT: [f32; 4] = [0.95, 0.70, 0.30, 1.0];
const MENU_ERROR_TEXT: [f32; 4] = [1.0, 0.40, 0.35, 1.0];
const MENU_ACCENT_TEXT: [f32; 4] = [0.58, 0.86, 0.96, 1.0];
const MENU_SLIDER_WIDTH: f32 = 480.0;

fn draw_shader_menu(
    ui: &mut psycho_imgui::Ui<'_>,
    menu_config: &mut GraphicsMenuConfig,
    sources: &mut [ScreenShaderSource],
    selected_item: &mut MenuSelection,
    frame_pacing: &FramePacingSnapshot,
    pbr_status: pbr::NativePbrRuntimeStatus,
    menu_config_error: Option<&str>,
) -> bool {
    ui.set_next_window_pos(24.0, 36.0, psycho_imgui::Condition::FirstUseEver);
    ui.set_next_window_size(860.0, 680.0, psycho_imgui::Condition::FirstUseEver);

    let title = cstring("Oh My Vegas!");
    let window = ui.window(&title, None);
    if !window.is_visible() {
        return false;
    }

    let mut menu_config_changed = false;
    if draw_shader_menu_header(ui, sources, frame_pacing) {
        shaders::sync_embedded_effect_config(sources, &mut menu_config.embedded_effects);
        menu_config_changed = true;
    }
    ui.separator();
    menu_config_changed |= draw_global_config(ui, menu_config, menu_config_error);
    ui.separator();

    clamp_menu_selection(sources, selected_item);

    {
        let item_list = cstring("graphics_feature_list");
        let child = ui.child(&item_list, 300.0, 0.0, true);
        if child.is_visible() {
            draw_feature_list(ui, menu_config, sources, selected_item, pbr_status);
        }
    }

    ui.same_line();

    {
        let item_details = cstring("graphics_feature_details");
        let child = ui.child(&item_details, 0.0, 0.0, true);
        if child.is_visible() {
            match *selected_item {
                MenuSelection::NativePbr => {
                    menu_config_changed |=
                        draw_native_pbr_config(ui, &mut menu_config.native_pbr, pbr_status);
                }
                MenuSelection::Shader(index) => {
                    if let Some(source) = sources.get_mut(index) {
                        let embedded_changed = draw_shader_details(ui, source);
                        if embedded_changed {
                            shaders::sync_embedded_effect_config(
                                sources,
                                &mut menu_config.embedded_effects,
                            );
                            menu_config_changed = true;
                        }
                    }
                }
            }
        }
    }

    menu_config_changed
}

fn draw_shader_menu_header(
    ui: &mut psycho_imgui::Ui<'_>,
    sources: &mut [ScreenShaderSource],
    frame_pacing: &FramePacingSnapshot,
) -> bool {
    let mut embedded_changed = false;
    let (enabled_count, error_count, scene_count, final_count) = shader_counts(sources);
    let title = cstring("Screen-space shaders");
    ui.text_colored(MENU_ACCENT_TEXT, &title);
    ui.same_line();
    let summary = cstring(format!(
        "{} loaded | {} enabled | {} scene | {} final | {} issue{}",
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
        embedded_changed |= set_all_sources_enabled(sources, true);
    }
    ui.same_line();
    let disable_all = cstring("Disable all");
    if ui.button(&disable_all) {
        embedded_changed |= set_all_sources_enabled(sources, false);
    }

    ui.same_line();
    draw_frame_pacing_panel(ui, frame_pacing);

    embedded_changed
}

fn draw_frame_pacing_panel(ui: &mut psycho_imgui::Ui<'_>, frame_pacing: &FramePacingSnapshot) {
    let summary = cstring(format!(
        "FPS {:>5.1} | {:>5.2} ms",
        frame_pacing.fps, frame_pacing.last_ms
    ));
    ui.text_colored(MENU_GOOD_TEXT, &summary);

    if frame_pacing.samples.len() > 1 {
        let label = cstring("##frame_pacing");
        ui.plot_lines(
            &label,
            &frame_pacing.samples,
            0.0,
            frame_pacing.scale_max,
            300.0,
            42.0,
        );
    }
}

fn draw_global_config(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &mut GraphicsMenuConfig,
    menu_config_error: Option<&str>,
) -> bool {
    let mut changed = false;

    let heading = cstring("Global config");
    ui.text_colored(MENU_ACCENT_TEXT, &heading);
    let path = cstring(format!("File: {}", crate::config::CONFIG_PATH));
    ui.text_colored(MENU_MUTED_TEXT, &path);

    changed |= draw_config_checkbox(
        ui,
        "Screen-space shaders",
        "global.screen_space_shaders",
        &mut config.screen_space_shaders,
    );
    ui.same_line();
    changed |= draw_config_checkbox(ui, "Debug log", "global.debug_log", &mut config.debug_log);

    changed |= draw_menu_keybind_control(ui, &mut config.menu_toggle_key);

    let mut scan_interval = config.shader_scan_interval_ms.clamp(50, 5_000) as i32;
    if draw_int_slider(
        ui,
        "Shader scan interval ms",
        "global.shader_scan_interval_ms",
        &mut scan_interval,
        50,
        5_000,
    ) {
        config.shader_scan_interval_ms = scan_interval.clamp(50, 5_000) as u64;
        changed = true;
    }

    changed |= draw_depth_provider_config(ui, &mut config.depth_provider);

    if let Some(error) = menu_config_error {
        let text = cstring(format!("Config save error: {error}"));
        ui.text_colored(MENU_ERROR_TEXT, &text);
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
) -> bool {
    let text = cstring(format!("Depth provider: {}", depth_provider.config_value()));
    ui.text(&text);

    let mut changed = false;
    let none = cstring("None##global.depth_provider.none");
    if ui.button(&none) && *depth_provider != DepthProviderConfig::None {
        *depth_provider = DepthProviderConfig::None;
        changed = true;
    }
    ui.same_line();
    let fnv = cstring("Fallout NV##global.depth_provider.fnv");
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
    let heading = cstring("Native PBR");
    ui.text_colored(MENU_ACCENT_TEXT, &heading);

    let kind = cstring("Type: engine material hook");
    ui.text_colored(MENU_MUTED_TEXT, &kind);
    let path = cstring(format!("Config: {}", crate::config::CONFIG_PATH));
    ui.text_wrapped(&path);

    let (status_color, status_text) = if let Some(reason) = status.block_reason {
        (MENU_WARN_TEXT, format!("PBR blocked: {reason}"))
    } else if status.installed && status.shader_enabled {
        (MENU_GOOD_TEXT, "PBR shader: active".to_owned())
    } else if status.installed {
        (
            MENU_WARN_TEXT,
            "PBR hooks: active, shader disabled".to_owned(),
        )
    } else {
        (MENU_WARN_TEXT, "PBR hooks: not installed".to_owned())
    };
    let status_text = cstring(status_text);
    ui.text_colored(status_color, &status_text);
    let terrain_text = if status.terrain_contract_available {
        "Terrain contract: VPT/FSL/LODFF available"
    } else {
        "Terrain contract: missing, LandLOD/terrain PBR disabled"
    };
    let terrain_text = cstring(terrain_text);
    ui.text_colored(MENU_MUTED_TEXT, &terrain_text);
    let reload_note = cstring("Hooks install automatically at startup; shader toggle is runtime");
    ui.text_colored(MENU_MUTED_TEXT, &reload_note);
    ui.separator();

    let mut changed = false;
    changed |= draw_config_checkbox(
        ui,
        "PBR material shader",
        "native_pbr.enabled",
        &mut config.enabled,
    );
    ui.same_line();
    changed |= draw_config_checkbox(
        ui,
        "Debug draw logs",
        "native_pbr.debug_log_draws",
        &mut config.debug_log_draws,
    );
    if config.enabled {
        let text = cstring("Visible scope: non-skin ADTS/ADTS10 objects; VPT-gated LandLOD");
        ui.text_colored(MENU_WARN_TEXT, &text);
        let text = cstring("Object PBR uses c32/c33; terrain PBR uses c38/c89/c90");
        ui.text_colored(MENU_MUTED_TEXT, &text);
        ui.separator();
        changed |= draw_float_slider(
            ui,
            "Metallicness",
            "native_pbr.metallicness",
            &mut config.metallicness,
            0.0,
            1.0,
        );
        changed |= draw_float_slider(
            ui,
            "Roughness scale",
            "native_pbr.roughness_scale",
            &mut config.roughness_scale,
            0.05,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Light scale",
            "native_pbr.light_scale",
            &mut config.light_scale,
            0.0,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Ambient scale",
            "native_pbr.ambient_scale",
            &mut config.ambient_scale,
            0.0,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "Albedo saturation",
            "native_pbr.albedo_saturation",
            &mut config.albedo_saturation,
            0.0,
            2.0,
        );
        changed |= draw_float_slider(
            ui,
            "LandLOD noise",
            "native_pbr.terrain_lod_noise_scale",
            &mut config.terrain_lod_noise_scale,
            0.0,
            4.0,
        );
        changed |= draw_float_slider(
            ui,
            "LandLOD noise tile",
            "native_pbr.terrain_lod_noise_tile",
            &mut config.terrain_lod_noise_tile,
            0.05,
            16.0,
        );
    }

    changed
}

fn draw_feature_list(
    ui: &mut psycho_imgui::Ui<'_>,
    config: &GraphicsMenuConfig,
    sources: &[ScreenShaderSource],
    selected_item: &mut MenuSelection,
    pbr_status: pbr::NativePbrRuntimeStatus,
) {
    let heading = cstring("Engine features");
    ui.text_colored(MENU_ACCENT_TEXT, &heading);
    let pbr_label = cstring(native_pbr_list_label(config.native_pbr.enabled, pbr_status));
    if ui.selectable(&pbr_label, *selected_item == MenuSelection::NativePbr) {
        *selected_item = MenuSelection::NativePbr;
    }

    ui.separator();
    let heading = cstring("Embedded effects");
    ui.text_colored(MENU_ACCENT_TEXT, &heading);
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

    ui.separator();
    let heading = cstring("External shaders");
    ui.text_colored(MENU_ACCENT_TEXT, &heading);
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
    let mut embedded_changed = false;
    let name = cstring(source.name.as_str());
    ui.text_colored(MENU_ACCENT_TEXT, &name);
    ui.same_line();

    let mut enabled = source.enabled;
    let enabled_label = cstring(format!("Enabled##{}.enabled", source.name));
    if ui.checkbox(&enabled_label, &mut enabled) {
        let is_embedded = source.is_embedded_effect();
        if let Err(err) = source.set_enabled(enabled) {
            source.config_error = Some(format!("{err:#}"));
        } else {
            embedded_changed |= is_embedded;
        }
    }

    ui.separator();
    draw_shader_status(ui, source);

    let source_kind = if source.is_embedded_effect() {
        "Type: embedded engine effect"
    } else {
        "Type: external HLSL shader"
    };
    let source_kind = cstring(source_kind);
    ui.text_colored(MENU_MUTED_TEXT, &source_kind);

    let phase_text = cstring(format!("Phase: {}", source.phase().label()));
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
        let pass_heading = cstring("Pass schedule");
        ui.text_colored(MENU_ACCENT_TEXT, &pass_heading);
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
            }
        }
    }

    ui.spacing();
    let option_heading = cstring("Options");
    ui.text_colored(MENU_ACCENT_TEXT, &option_heading);
    if source.options.is_empty() {
        let text = cstring("No dynamic options");
        ui.text_colored(MENU_MUTED_TEXT, &text);
        return embedded_changed;
    }

    for option_index in 0..source.options.len() {
        let option = source.options[option_index].clone();

        match option.value {
            ShaderOptionValue::Float(value) => {
                let mut value = value;
                if draw_float_slider(
                    ui,
                    option.label.as_str(),
                    &format!("{}.{}", source.name, option.key),
                    &mut value,
                    option.min,
                    option.max,
                ) {
                    if let Err(err) = source.set_option_float(option_index, value) {
                        source.config_error = Some(format!("{err:#}"));
                    } else {
                        embedded_changed |= source.is_embedded_effect();
                    }
                }
            }
            ShaderOptionValue::Integer(value) => {
                let mut value = value;
                let (min, max) = integer_option_bounds(&option);
                if draw_int_slider(
                    ui,
                    option.label.as_str(),
                    &format!("{}.{}", source.name, option.key),
                    &mut value,
                    min,
                    max,
                ) {
                    if let Err(err) = source.set_option_integer(option_index, value) {
                        source.config_error = Some(format!("{err:#}"));
                    } else {
                        embedded_changed |= source.is_embedded_effect();
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
                        embedded_changed |= source.is_embedded_effect();
                    }
                }
            }
        }
    }

    embedded_changed
}

fn draw_float_slider(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    value: &mut f32,
    min: f32,
    max: f32,
) -> bool {
    let display = cstring(format!("{label}: {:.3}", *value));
    ui.text(&display);
    let slider_id = cstring(format!("##{id}"));
    let _width = ui.push_item_width(MENU_SLIDER_WIDTH);
    ui.slider_float(&slider_id, value, min, max)
}

fn draw_int_slider(
    ui: &mut psycho_imgui::Ui<'_>,
    label: &str,
    id: &str,
    value: &mut i32,
    min: i32,
    max: i32,
) -> bool {
    let display = cstring(format!("{label}: {}", *value));
    ui.text(&display);
    let slider_id = cstring(format!("##{id}"));
    let _width = ui.push_item_width(MENU_SLIDER_WIDTH);
    ui.slider_int(&slider_id, value, min, max)
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
        "ON "
    } else {
        "OFF"
    };
    format!("{status}  {}##shader_select_{index}", source.name)
}

fn native_pbr_list_label(configured_enabled: bool, status: pbr::NativePbrRuntimeStatus) -> String {
    let status = if status.installed && configured_enabled {
        "ON "
    } else if status.block_reason.is_some() {
        "BLK"
    } else if status.installed {
        "HOK"
    } else if configured_enabled {
        "OFF"
    } else {
        "OFF"
    };
    format!("{status}  Native PBR##native_pbr_select")
}

fn shader_has_error(source: &ScreenShaderSource) -> bool {
    source.shader_error.is_some()
        || source.config_error.is_some()
        || (source.bytecode.is_none() && source.is_external_file())
}

fn set_all_sources_enabled(sources: &mut [ScreenShaderSource], enabled: bool) -> bool {
    let mut embedded_changed = false;
    for source in sources {
        let is_embedded = source.is_embedded_effect();
        if let Err(err) = source.set_enabled(enabled) {
            source.config_error = Some(format!("{err:#}"));
        } else {
            embedded_changed |= is_embedded;
        }
    }
    embedded_changed
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
    WindowsError::from_hresult(E_FAIL)
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
