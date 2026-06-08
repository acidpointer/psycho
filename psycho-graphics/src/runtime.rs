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
    shaders::{self, ScreenShaderSource, ShaderOptionValue, ShaderPhase},
};

const DEFAULT_SCAN_INTERVAL_MS: u64 = 200;
const FIRST_OPTION_REGISTER: u32 = 3;
const ENVIRONMENT_REGISTER: u32 = 6;
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

static RUNTIME: LazyLock<Mutex<ScreenShaderRuntime>> =
    LazyLock::new(|| Mutex::new(ScreenShaderRuntime::default()));
static MENU_OPEN: AtomicBool = AtomicBool::new(false);
static IMGUI_READY: AtomicBool = AtomicBool::new(false);
static MENU_TOGGLE_KEY: AtomicU32 = AtomicU32::new(0x2D);

pub(crate) fn configure(settings: RuntimeSettings) {
    MENU_TOGGLE_KEY.store(settings.menu_toggle_key, Ordering::Release);

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
    let toggle_key = MENU_TOGGLE_KEY.load(Ordering::Acquire) as usize;
    if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) && wparam == toggle_key {
        let open = !MENU_OPEN.load(Ordering::Acquire);
        MENU_OPEN.store(open, Ordering::Release);
        crate::input::set_menu_input_blocked(open);
        return Some(0);
    }

    if !MENU_OPEN.load(Ordering::Acquire) || !IMGUI_READY.load(Ordering::Acquire) {
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
    pub(crate) depth_provider: DepthProvider,
    pub(crate) imgui_menu: bool,
    pub(crate) menu_toggle_key: u32,
    pub(crate) shader_scan_interval_ms: u64,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            depth_provider: DepthProvider::default(),
            imgui_menu: true,
            menu_toggle_key: 0x2D,
            shader_scan_interval_ms: DEFAULT_SCAN_INTERVAL_MS,
        }
    }
}

struct ScreenShaderRuntime {
    settings: RuntimeSettings,
    sources: Vec<ScreenShaderSource>,
    device_ptr: usize,
    compiled: Option<Vec<CompiledPass>>,
    backbuffer_copy: Option<BackbufferCopy>,
    world_color_copy: Option<BackbufferCopy>,
    state_block: Option<StateBlock9>,
    imgui: Option<psycho_imgui::Dx9Context>,
    imgui_hwnd: usize,
    imgui_needs_device_objects: bool,
    next_scan: Option<Instant>,
    frame_index: u32,
    last_depth_available: Option<bool>,
    last_fog_available: Option<bool>,
    error_logs: u32,
    scan_error_logs: u32,
    imgui_error_logs: u32,
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
            backbuffer_copy: None,
            world_color_copy: None,
            state_block: None,
            imgui: None,
            imgui_hwnd: 0,
            imgui_needs_device_objects: false,
            next_scan: None,
            frame_index: 0,
            last_depth_available: None,
            last_fog_available: None,
            error_logs: 0,
            scan_error_logs: 0,
            imgui_error_logs: 0,
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
        if !settings.imgui_menu {
            MENU_OPEN.store(false, Ordering::Release);
            crate::input::set_menu_input_blocked(false);
        }
        self.settings = settings;
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

        self.ensure_imgui(&device, hwnd_hint);

        let menu_open = self.settings.imgui_menu && MENU_OPEN.load(Ordering::Acquire);
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
            self.ensure_backbuffer_copy(&device, &desc)?;
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

        if let Err(err) = self.ensure_backbuffer_copy(&device, &desc) {
            let _ = device.set_render_target(0, &restore_target);
            return Err(err);
        }

        self.resolve_scene_phase_depth(&device, phase, target);

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

    fn resolve_scene_phase_depth(
        &mut self,
        device: &Device9Ref<'_>,
        phase: ShaderPhase,
        target: ScenePhaseTarget,
    ) {
        if phase != ShaderPhase::ScenePreImageSpace {
            return;
        }

        let ScenePhaseTarget::RenderedTextureSource(rendered_texture) = target else {
            return;
        };

        let resolved = unsafe {
            backend::resolve_rendered_texture_depth(
                self.settings.depth_provider,
                device.as_raw(),
                rendered_texture,
                backend::DepthResolveSlot::FirstPerson,
                "FNV scene-pre source first-person depth",
            )
        };
        if resolved && self.scene_apply_logs < 8 {
            log::debug!(
                "[SHADERS] Scene-pre first-person depth resolved from source render target"
            );
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
                let new_count = scan.sources.len();
                if scan.shader_resources_changed {
                    self.compiled = None;
                }
                self.sources = scan.sources;
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
        if !self.settings.imgui_menu {
            return;
        }

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
            let Some(bytecode) = source.bytecode() else {
                continue;
            };

            match device.create_pixel_shader(bytecode) {
                Ok(shader) => {
                    log::info!("[SHADERS] Loaded screen pass '{}'", source.name);
                    passes.push(CompiledPass {
                        source_index,
                        shader,
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

    fn ensure_backbuffer_copy(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let needs_copy = self
            .backbuffer_copy
            .as_ref()
            .is_none_or(|copy| !copy.matches(desc));

        if needs_copy {
            self.backbuffer_copy = Some(BackbufferCopy::create(device, desc)?);
            log::info!(
                "[SHADERS] Backbuffer copy target: {}x{}",
                desc.Width,
                desc.Height
            );
        }

        Ok(())
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
        };
        self.log_frame_input_state(&frame_inputs);

        let Some(copy) = self.backbuffer_copy.as_ref() else {
            return Ok(());
        };
        let Some(passes) = self.compiled.as_ref() else {
            return Ok(());
        };

        self.bind_common_state(device, backbuffer, desc, &frame_inputs, copy)?;

        let pass_count = enabled_count as f32;
        let quad = fullscreen_quad(desc);
        let depth_available = if frame_inputs.depth.is_available() {
            1.0
        } else {
            0.0
        };
        let mut pass_index = 0u32;

        for pass in passes {
            let source = &self.sources[pass.source_index];
            if !source.enabled || source.phase() != phase {
                continue;
            }

            for _ in 0..source.pass_count {
                device.clear_texture(0)?;
                device.stretch_rect(backbuffer, None, &copy.surface, None, D3DTEXF_POINT)?;
                device.set_texture(0, &copy.texture)?;
                device.set_pixel_shader(&pass.shader)?;
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

    fn log_frame_input_state(&mut self, frame_inputs: &backend::FrameInputs) {
        let depth_available = frame_inputs.depth.is_available();
        let fog_available = frame_inputs.environment.fog_available;
        if self.last_depth_available == Some(depth_available)
            && self.last_fog_available == Some(fog_available)
        {
            return;
        }

        self.last_depth_available = Some(depth_available);
        self.last_fog_available = Some(fog_available);
        log::info!(
            "[SHADERS] Frame inputs: depth={} (provider={}, near={:.3}, far={:.3}), fog={} (start={:.3}, end={:.3}, power={:.3})",
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
            frame_inputs.environment.fog_power
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

        {
            let mut ui = imgui.new_frame(true);
            draw_shader_menu(&mut ui, &mut self.sources);
        }

        imgui.render();
        Ok(())
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
        self.sources
            .iter()
            .any(|source| source.enabled && source.bytecode.is_some())
    }

    fn has_enabled_shader_for_phase(&self, phase: ShaderPhase) -> bool {
        self.sources
            .iter()
            .any(|source| source.enabled && source.phase() == phase && source.bytecode.is_some())
    }

    fn needs_fnv_scene_inputs(&self) -> bool {
        self.settings.depth_provider == DepthProvider::FalloutNewVegas
            && !self.applied_phases.is_applied(ShaderPhase::FinalImageSpace)
            && self.has_enabled_shader()
    }

    fn has_drawable_shader(&self) -> bool {
        self.compiled.as_ref().is_some_and(|passes| {
            passes
                .iter()
                .any(|pass| self.sources[pass.source_index].enabled)
        })
    }

    fn has_drawable_shader_for_phase(&self, phase: ShaderPhase) -> bool {
        self.compiled.as_ref().is_some_and(|passes| {
            passes.iter().any(|pass| {
                let source = &self.sources[pass.source_index];
                source.enabled && source.phase() == phase
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
        self.release_default_pool_resources();
        if let Some(imgui) = self.imgui.as_mut() {
            imgui.invalidate_device_objects();
            self.imgui_needs_device_objects = true;
        }
    }

    fn release_default_pool_resources(&mut self) {
        self.backbuffer_copy = None;
        self.world_color_copy = None;
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
    shader: PixelShader9,
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

fn draw_shader_menu(ui: &mut psycho_imgui::Ui<'_>, sources: &mut [ScreenShaderSource]) {
    let title = cstring("Psycho Graphics");
    let window = ui.window(&title, None);
    if !window.is_visible() {
        return;
    }

    let header = cstring(format!("Screen-space shaders: {}", sources.len()));
    ui.text(&header);
    ui.separator();

    if sources.is_empty() {
        let empty = cstring("No shader files found in ./mods/psycho_shaders");
        ui.text(&empty);
        return;
    }

    for source in sources {
        draw_shader_entry(ui, source);
        ui.separator();
    }
}

fn draw_shader_entry(ui: &mut psycho_imgui::Ui<'_>, source: &mut ScreenShaderSource) {
    let mut enabled = source.enabled;
    let enabled_label = cstring(format!("{}##{}.enabled", source.name, source.name));
    if ui.checkbox(&enabled_label, &mut enabled)
        && let Err(err) = source.set_enabled(enabled)
    {
        source.config_error = Some(format!("{err:#}"));
    }

    let path_text = cstring(source.path.display().to_string());
    ui.text(&path_text);

    let phase_text = cstring(format!("Phase: {}", source.phase().label()));
    ui.text(&phase_text);

    if let Some(error) = &source.shader_error {
        let text = cstring(format!("Shader error: {error}"));
        ui.text(&text);
    }
    if let Some(error) = &source.config_error {
        let text = cstring(format!("Config error: {error}"));
        ui.text(&text);
    }

    let mut pass_count = source.pass_count as f32;
    let pass_label = cstring(format!("Passes##{}.passes", source.name));
    if ui.slider_float(&pass_label, &mut pass_count, 1.0, 8.0) {
        let pass_count = pass_count.round().clamp(1.0, 8.0) as u32;
        if let Err(err) = source.set_pass_count(pass_count) {
            source.config_error = Some(format!("{err:#}"));
        }
    }

    if source.options.is_empty() {
        let text = cstring("No dynamic options");
        ui.text(&text);
        return;
    }

    for option_index in 0..source.options.len() {
        let option = source.options[option_index].clone();
        let label = cstring(format!("{}##{}.{}", option.label, source.name, option.key));

        match option.value {
            ShaderOptionValue::Float(value) => {
                let mut value = value;
                if ui.slider_float(&label, &mut value, option.min, option.max)
                    && let Err(err) = source.set_option_float(option_index, value)
                {
                    source.config_error = Some(format!("{err:#}"));
                }
            }
            ShaderOptionValue::Bool(value) => {
                let mut value = value;
                if ui.checkbox(&label, &mut value)
                    && let Err(err) = source.set_option_bool(option_index, value)
                {
                    source.config_error = Some(format!("{err:#}"));
                }
            }
        }
    }
}

fn valid_hwnd(hwnd: *mut c_void) -> Option<*mut c_void> {
    if is_window(hwnd) { Some(hwnd) } else { None }
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
