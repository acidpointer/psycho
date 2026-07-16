//! Native PBR integration.
//!
//! This module is intentionally a small facade. The old implementation mixed
//! hook ownership, shader compilation, terrain probing, draw classification,
//! constants, diagnostics, and UI state in one file. The replacement follows
//! NVR's subsystem boundaries while keeping OMV storage independent from NVR's
//! native object-size patches.

mod compiler;
mod constants;
mod device_resources;
mod diagnostics;
mod engine_contracts;
mod hooks;
mod object_contracts;
mod object_replacement_record;
mod samplers;
mod shader_record;
mod shader_registry;

use std::sync::{
    LazyLock,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use parking_lot::Mutex;

const OBJECT_PBR_PROFILE_VALUE_COUNT: usize = 4;
const TERRAIN_PBR_PROFILE_VALUE_COUNT: usize = 5;

static INSTALLED: AtomicBool = AtomicBool::new(false);
static SHADER_ENABLED: AtomicBool = AtomicBool::new(false);
static TERRAIN_ENABLED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_ENABLED: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_ENABLED: AtomicBool = AtomicBool::new(false);
static TERRAIN_LOD_ENABLED: AtomicBool = AtomicBool::new(false);
static DEBUG_LOG_DRAWS: AtomicBool = AtomicBool::new(false);
static DRAW_BOUNDARY_READY: AtomicBool = AtomicBool::new(false);
static ACTIVE_CONTRACTS_READY: AtomicBool = AtomicBool::new(false);
static ACTIVE_CONTRACTS_FAILED: AtomicBool = AtomicBool::new(false);
static INSTALL_BOUNDARY_REACHED: AtomicBool = AtomicBool::new(false);
static ENABLE_PENDING: AtomicBool = AtomicBool::new(false);
static BLOCK_REASON: LazyLock<Mutex<Option<&'static str>>> = LazyLock::new(|| Mutex::new(None));

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePbrSettings {
    enabled: bool,
    debug_log_draws: bool,
    object_profile: ObjectPbrProfileSettings,
    terrain_profile: TerrainPbrProfileSettings,
    terrain_lod_noise_scale: f32,
    terrain_lod_noise_tile: f32,
}

#[derive(Clone, Copy, Debug)]
struct ObjectPbrProfileSettings {
    roughness_scale: f32,
    light_scale: f32,
    ambient_scale: f32,
    albedo_saturation: f32,
}

#[derive(Clone, Copy, Debug)]
struct TerrainPbrProfileSettings {
    metallicness: f32,
    roughness_scale: f32,
    light_scale: f32,
    ambient_scale: f32,
    albedo_saturation: f32,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct NativePbrRuntimeStatus {
    pub(crate) installed: bool,
    pub(crate) shader_enabled: bool,
    pub(crate) terrain_enabled: bool,
    pub(crate) close_terrain_enabled: bool,
    pub(crate) terrain_fade_enabled: bool,
    pub(crate) terrain_lod_enabled: bool,
    pub(crate) shader_creation_identity_ready: bool,
    pub(crate) captured_shader_records: u32,
    pub(crate) adopted_shader_records: u32,
    pub(crate) active_shader_records: usize,
    pub(crate) active_object_replacement_records: usize,
    pub(crate) recorded_shader_templates: usize,
    pub(crate) shader_package_lifetime_contract_ready: bool,
    pub(crate) eye_position_contract_ready: bool,
    pub(crate) active_contracts_ready: bool,
    pub(crate) active_contracts_failed: bool,
    pub(crate) object_shader_total: usize,
    pub(crate) object_bytecode_ready: usize,
    pub(crate) object_bytecode_failed: usize,
    pub(crate) object_last_compile_failed: &'static str,
    pub(crate) object_resources_ready: usize,
    pub(crate) object_resources_failed: usize,
    pub(crate) object_last_create_failed: &'static str,
    pub(crate) object_replacements_last_frame: u32,
    pub(crate) object_fallbacks_last_frame: u32,
    pub(crate) object_draw_gate_rejections_last_frame: u32,
    pub(crate) object_terrain_rejections_last_frame: u32,
    pub(crate) object_constant_uploads_last_frame: u32,
    pub(crate) object_constant_generation: u32,
    pub(crate) object_d3d_to_replacement_last_frame: u32,
    pub(crate) object_d3d_to_other_last_frame: u32,
    pub(crate) object_texture_tracking_ready: bool,
    pub(crate) object_texture_binds_last_frame: u32,
    pub(crate) object_sampler_checks_last_frame: u32,
    pub(crate) object_sampler_fallbacks_last_frame: u32,
    pub(crate) object_sampler_selector_mismatches_last_frame: u32,
    pub(crate) object_last_sampler_layout: &'static str,
    pub(crate) object_last_sampler_fallback: &'static str,
    pub(crate) object_last_sampler_selector: usize,
    pub(crate) object_last_sampler_expected_mask: u32,
    pub(crate) object_last_sampler_observed_mask: u32,
    pub(crate) object_last_sampler_failed_stage: u32,
    pub(crate) object_last_vertex_sls: u32,
    pub(crate) object_last_pixel_sls: u32,
    pub(crate) object_last_vertex_template: &'static str,
    pub(crate) object_last_pixel_template: &'static str,
    pub(crate) object_last_vertex_table: u32,
    pub(crate) object_last_vertex_index: u32,
    pub(crate) object_last_normalized_vertex_index: u32,
    pub(crate) object_last_pixel_table: u32,
    pub(crate) object_last_pixel_index: u32,
    pub(crate) object_last_pair_class: &'static str,
    pub(crate) object_contract_transitions_last_frame: u32,
    pub(crate) object_last_contract_transition_from: &'static str,
    pub(crate) object_last_contract_transition_to: &'static str,
    pub(crate) object_last_vertex_replacement_ready: bool,
    pub(crate) object_last_pixel_replacement_ready: bool,
    pub(crate) object_last_vertex_wrapper: usize,
    pub(crate) object_last_pixel_wrapper: usize,
    pub(crate) object_last_vertex_replacement: usize,
    pub(crate) object_last_pixel_replacement: usize,
    pub(crate) object_last_vertex_d3d: usize,
    pub(crate) object_last_pixel_d3d: usize,
    pub(crate) object_last_vertex_d3d_is_replacement: bool,
    pub(crate) object_last_pixel_d3d_is_replacement: bool,
    pub(crate) object_last_d3d_pair_state: &'static str,
    pub(crate) object_last_selector: usize,
    pub(crate) object_last_selector_state: u32,
    pub(crate) object_last_active_layer_count: u32,
    pub(crate) object_last_scanned_entries: u32,
    pub(crate) object_last_pass_entry_list: usize,
    pub(crate) object_last_reject_reason: &'static str,
    pub(crate) object_last_reject_row: u32,
    pub(crate) object_last_reject_selector: usize,
    pub(crate) terrain_contract_available: bool,
    pub(crate) land_lod_contract_active: bool,
    pub(crate) land_lod_contract_failed: bool,
    pub(crate) close_terrain_contract_proven: bool,
    pub(crate) terrain_fade_contract_proven: bool,
    pub(crate) block_reason: Option<&'static str>,
}
impl Default for NativePbrSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            debug_log_draws: false,
            object_profile: ObjectPbrProfileSettings::default(),
            terrain_profile: TerrainPbrProfileSettings::default(),
            terrain_lod_noise_scale: 1.0,
            terrain_lod_noise_tile: 1.75,
        }
    }
}

impl Default for ObjectPbrProfileSettings {
    fn default() -> Self {
        Self {
            roughness_scale: 1.0,
            light_scale: 1.0,
            ambient_scale: 1.0,
            albedo_saturation: 1.0,
        }
    }
}

impl Default for TerrainPbrProfileSettings {
    fn default() -> Self {
        Self {
            metallicness: 0.0,
            roughness_scale: 0.82,
            light_scale: 1.15,
            ambient_scale: 1.10,
            albedo_saturation: 1.02,
        }
    }
}

impl From<crate::config::NativePbrConfig> for NativePbrSettings {
    fn from(value: crate::config::NativePbrConfig) -> Self {
        Self {
            enabled: value.enabled,
            debug_log_draws: value.debug_log_draws,
            object_profile: ObjectPbrProfileSettings {
                roughness_scale: value.object_roughness_scale,
                light_scale: value.object_light_scale,
                ambient_scale: value.object_ambient_scale,
                albedo_saturation: value.object_albedo_saturation,
            },
            terrain_profile: TerrainPbrProfileSettings {
                metallicness: value.terrain_metallicness,
                roughness_scale: value.terrain_roughness_scale,
                light_scale: value.terrain_light_scale,
                ambient_scale: value.terrain_ambient_scale,
                albedo_saturation: value.terrain_albedo_saturation,
            },
            terrain_lod_noise_scale: value.terrain_lod_noise_scale,
            terrain_lod_noise_tile: value.terrain_lod_noise_tile,
        }
    }
}

impl ObjectPbrProfileSettings {
    fn sanitized_values(self) -> [f32; OBJECT_PBR_PROFILE_VALUE_COUNT] {
        [
            sanitize_scale(self.roughness_scale, 1.0, 0.05, 4.0),
            sanitize_scale(self.light_scale, 1.0, 0.0, 4.0),
            sanitize_scale(self.ambient_scale, 1.0, 0.0, 4.0),
            sanitize_scale(self.albedo_saturation, 1.0, 0.0, 2.0),
        ]
    }
}

impl TerrainPbrProfileSettings {
    fn sanitized_values(self) -> [f32; TERRAIN_PBR_PROFILE_VALUE_COUNT] {
        [
            sanitize_scale(self.metallicness, 0.0, 0.0, 1.0),
            sanitize_scale(self.roughness_scale, 1.0, 0.05, 4.0),
            sanitize_scale(self.light_scale, 1.0, 0.0, 4.0),
            sanitize_scale(self.ambient_scale, 1.0, 0.0, 4.0),
            sanitize_scale(self.albedo_saturation, 1.0, 0.0, 2.0),
        ]
    }
}

pub(crate) fn install(settings: NativePbrSettings) -> Result<()> {
    constants::store_settings(settings);
    DEBUG_LOG_DRAWS.store(settings.debug_log_draws, Ordering::Release);
    diagnostics::set_detailed_enabled(settings.debug_log_draws);
    store_terrain_options(settings);
    INSTALL_BOUNDARY_REACHED.store(true, Ordering::Release);
    if !settings.enabled {
        SHADER_ENABLED.store(false, Ordering::Release);
        INSTALLED.store(false, Ordering::Release);
        refresh_block_reason();
        log::info!("[PBR] Native PBR disabled; no PBR hooks or engine contracts installed");
        return Ok(());
    }

    activate()
}

pub(crate) fn configure_terrain_contract(available: bool) {
    engine_contracts::set_terrain_contract_available(available);
    refresh_block_reason();
}

pub(crate) fn set_draw_boundary_ready(ready: bool) {
    DRAW_BOUNDARY_READY.store(ready, Ordering::Release);
}

pub(crate) fn prepare_direct_draw() {
    hooks::prepare_direct_draw();
}

pub(crate) fn finish_draw_batches() {
    hooks::finish_draw_batches();
}

pub(crate) fn configure_runtime_options(settings: NativePbrSettings) {
    constants::store_settings(settings);
    store_terrain_options(settings);
    DEBUG_LOG_DRAWS.store(settings.debug_log_draws, Ordering::Release);
    diagnostics::set_detailed_enabled(settings.debug_log_draws);
    if !INSTALL_BOUNDARY_REACHED.load(Ordering::Acquire) {
        SHADER_ENABLED.store(settings.enabled, Ordering::Release);
        refresh_block_reason();
        return;
    }

    let was_enabled = SHADER_ENABLED.load(Ordering::Acquire);
    if was_enabled && !settings.enabled {
        ENABLE_PENDING.store(false, Ordering::Release);
        SHADER_ENABLED.store(false, Ordering::Release);
        ACTIVE_CONTRACTS_READY.store(false, Ordering::Release);
        ACTIVE_CONTRACTS_FAILED.store(false, Ordering::Release);
        log::info!(
            "[PBR] Native PBR disabled; hooks and engine contracts remain resident; draw replacements are passive"
        );
    } else if !was_enabled && settings.enabled {
        if !ENABLE_PENDING.swap(true, Ordering::AcqRel) {
            log::info!("[PBR] Native PBR activation queued for the next Present boundary");
        }
    } else if !settings.enabled {
        ENABLE_PENDING.store(false, Ordering::Release);
    }
    refresh_block_reason();
}

pub(crate) fn runtime_status() -> NativePbrRuntimeStatus {
    let object_last_vertex_sls = diagnostics::object_last_vertex_sls();
    let object_last_pixel_sls = diagnostics::object_last_pixel_sls();

    NativePbrRuntimeStatus {
        installed: INSTALLED.load(Ordering::Acquire),
        shader_enabled: SHADER_ENABLED.load(Ordering::Acquire),
        terrain_enabled: TERRAIN_ENABLED.load(Ordering::Acquire),
        close_terrain_enabled: CLOSE_TERRAIN_ENABLED.load(Ordering::Acquire),
        terrain_fade_enabled: TERRAIN_FADE_ENABLED.load(Ordering::Acquire),
        terrain_lod_enabled: TERRAIN_LOD_ENABLED.load(Ordering::Acquire),
        shader_creation_identity_ready: shader_record::identity_ready(),
        captured_shader_records: shader_record::captured_records(),
        adopted_shader_records: shader_record::adopted_records(),
        active_shader_records: shader_record::active_record_count(),
        active_object_replacement_records: 0,
        recorded_shader_templates: shader_record::recorded_template_count(),
        shader_package_lifetime_contract_ready: engine_contracts::shader_package_lifetime_ready(),
        eye_position_contract_ready: engine_contracts::eye_position_ready(),
        active_contracts_ready: ACTIVE_CONTRACTS_READY.load(Ordering::Acquire),
        active_contracts_failed: ACTIVE_CONTRACTS_FAILED.load(Ordering::Acquire),
        object_shader_total: shader_registry::object_template_count(),
        object_bytecode_ready: compiler::object_ready_count(),
        object_bytecode_failed: compiler::object_failed_count(),
        object_last_compile_failed: compiler::object_last_failed_template_label(),
        object_resources_ready: device_resources::object_created_count(),
        object_resources_failed: device_resources::object_create_failed_count(),
        object_last_create_failed: device_resources::object_last_create_failed_template_label(),
        object_replacements_last_frame: diagnostics::object_replacements_last_frame(),
        object_fallbacks_last_frame: diagnostics::object_fallbacks_last_frame(),
        object_draw_gate_rejections_last_frame: diagnostics::object_draw_gate_rejections_last_frame(
        ),
        object_terrain_rejections_last_frame: diagnostics::object_terrain_rejections_last_frame(),
        object_constant_uploads_last_frame: diagnostics::object_constant_uploads_last_frame(),
        object_constant_generation: constants::object_constant_version(),
        object_d3d_to_replacement_last_frame: diagnostics::object_d3d_to_replacement_last_frame(),
        object_d3d_to_other_last_frame: diagnostics::object_d3d_to_other_last_frame(),
        object_texture_tracking_ready: samplers::texture_tracking_ready(),
        object_texture_binds_last_frame: samplers::texture_binds_last_frame(),
        object_sampler_checks_last_frame: samplers::object_sampler_checks_last_frame(),
        object_sampler_fallbacks_last_frame: samplers::object_sampler_fallbacks_last_frame(),
        object_sampler_selector_mismatches_last_frame:
            samplers::object_sampler_selector_mismatches_last_frame(),
        object_last_sampler_layout: samplers::object_last_sampler_layout_label(),
        object_last_sampler_fallback: samplers::object_last_sampler_fallback_label(),
        object_last_sampler_selector: samplers::object_last_sampler_selector(),
        object_last_sampler_expected_mask: samplers::object_last_sampler_expected_mask(),
        object_last_sampler_observed_mask: samplers::object_last_sampler_observed_mask(),
        object_last_sampler_failed_stage: samplers::object_last_sampler_failed_stage(),
        object_last_vertex_sls,
        object_last_pixel_sls,
        object_last_vertex_template: object_template_label(
            shader_registry::ShaderStage::Vertex,
            object_last_vertex_sls,
        ),
        object_last_pixel_template: object_template_label(
            shader_registry::ShaderStage::Pixel,
            object_last_pixel_sls,
        ),
        object_last_vertex_table: diagnostics::object_last_vertex_table(),
        object_last_vertex_index: diagnostics::object_last_vertex_index(),
        object_last_normalized_vertex_index: diagnostics::object_last_normalized_vertex_index(),
        object_last_pixel_table: diagnostics::object_last_pixel_table(),
        object_last_pixel_index: diagnostics::object_last_pixel_index(),
        object_last_pair_class: diagnostics::object_last_pair_class_label(),
        object_contract_transitions_last_frame: diagnostics::object_contract_transitions_last_frame(
        ),
        object_last_contract_transition_from: diagnostics::object_last_contract_transition_from(),
        object_last_contract_transition_to: diagnostics::object_last_contract_transition_to(),
        object_last_vertex_replacement_ready: diagnostics::object_last_vertex_replacement_ready(),
        object_last_pixel_replacement_ready: diagnostics::object_last_pixel_replacement_ready(),
        object_last_vertex_wrapper: diagnostics::object_last_vertex_wrapper(),
        object_last_pixel_wrapper: diagnostics::object_last_pixel_wrapper(),
        object_last_vertex_replacement: diagnostics::object_last_vertex_replacement(),
        object_last_pixel_replacement: diagnostics::object_last_pixel_replacement(),
        object_last_vertex_d3d: diagnostics::object_last_vertex_d3d(),
        object_last_pixel_d3d: diagnostics::object_last_pixel_d3d(),
        object_last_vertex_d3d_is_replacement: diagnostics::object_last_vertex_d3d_is_replacement(),
        object_last_pixel_d3d_is_replacement: diagnostics::object_last_pixel_d3d_is_replacement(),
        object_last_d3d_pair_state: diagnostics::object_last_d3d_pair_state_label(),
        object_last_selector: diagnostics::object_last_selector(),
        object_last_selector_state: diagnostics::object_last_selector_state(),
        object_last_active_layer_count: diagnostics::object_last_active_layer_count(),
        object_last_scanned_entries: diagnostics::object_last_scanned_entries(),
        object_last_pass_entry_list: diagnostics::object_last_pass_entry_list(),
        object_last_reject_reason: diagnostics::object_last_reject_reason_label(),
        object_last_reject_row: diagnostics::object_last_reject_row(),
        object_last_reject_selector: diagnostics::object_last_reject_selector(),
        terrain_contract_available: engine_contracts::terrain_contract_available(),
        land_lod_contract_active: terrain_lod_enabled() && land_lod_contracts_ready(),
        land_lod_contract_failed: compiler::land_lod_compile_failed()
            || compiler::terrain_fade_compile_failed()
            || compiler::close_terrain_compile_failed()
            || device_resources::land_lod_create_failed()
            || device_resources::terrain_fade_create_failed()
            || device_resources::close_terrain_create_failed(),
        close_terrain_contract_proven: close_terrain_contract_available(),
        terrain_fade_contract_proven: terrain_fade_contracts_ready(),
        block_reason: *BLOCK_REASON.lock(),
    }
}

fn object_template_label(stage: shader_registry::ShaderStage, sls_number: u32) -> &'static str {
    if sls_number == 0 {
        return "none";
    }

    u16::try_from(sls_number)
        .ok()
        .and_then(|sls_number| shader_registry::object_template_id(stage, sls_number))
        .map_or("unknown", |template_ref| template_ref.template.label)
}

pub(crate) fn service_present_frame() {
    if ENABLE_PENDING.swap(false, Ordering::AcqRel) {
        if let Err(err) = activate() {
            SHADER_ENABLED.store(false, Ordering::Release);
            log::error!("[PBR] Native PBR activation failed: {err:#}");
        }
    }
    let enabled = SHADER_ENABLED.load(Ordering::Acquire);
    if enabled {
        engine_contracts::service_frame();
        compiler::ensure_object_prewarm_started();
        device_resources::service_frame();
        let failed = compiler::object_compile_failed() || device_resources::object_create_failed();
        let ready = compiler::object_compile_finished()
            && !failed
            && device_resources::object_resources_ready();
        ACTIVE_CONTRACTS_FAILED.store(failed, Ordering::Release);
        ACTIVE_CONTRACTS_READY.store(ready, Ordering::Release);
    } else {
        ACTIVE_CONTRACTS_READY.store(false, Ordering::Release);
        ACTIVE_CONTRACTS_FAILED.store(false, Ordering::Release);
    }

    refresh_block_reason();
    samplers::service_frame();
    diagnostics::service_frame(enabled, DEBUG_LOG_DRAWS.load(Ordering::Acquire));
}

fn activate() -> Result<()> {
    SHADER_ENABLED.store(true, Ordering::Release);
    hooks::install()?;
    INSTALLED.store(true, Ordering::Release);
    ACTIVE_CONTRACTS_READY.store(false, Ordering::Release);
    ACTIVE_CONTRACTS_FAILED.store(false, Ordering::Release);
    refresh_block_reason();

    let registry = shader_registry::summary();
    log::info!(
        "[PBR] Native PBR object path activated: object={} landlod={} terrain_fade={} close_terrain={}",
        registry.object_records,
        registry.land_lod_records,
        registry.terrain_fade_records,
        registry.close_terrain_records
    );
    Ok(())
}

pub(crate) fn reset_runtime_state() {
    shader_record::reset();
    compiler::reset();
    device_resources::reset();
    samplers::reset();
    samplers::set_texture_tracking_ready(hooks::hooks_ready());
    diagnostics::reset();
    diagnostics::set_detailed_enabled(DEBUG_LOG_DRAWS.load(Ordering::Acquire));
    ACTIVE_CONTRACTS_READY.store(false, Ordering::Release);
    ACTIVE_CONTRACTS_FAILED.store(false, Ordering::Release);
    refresh_block_reason();
}

fn refresh_block_reason() {
    let reason = if !SHADER_ENABLED.load(Ordering::Acquire) {
        None
    } else if !hooks::hooks_ready() {
        Some("object shader hooks unavailable")
    } else if !engine_contracts::eye_position_ready() {
        Some("EyePosition contract unavailable")
    } else if !engine_contracts::shader_package_lifetime_ready() {
        Some("shader package lifetime contract unavailable")
    } else {
        None
    };
    *BLOCK_REASON.lock() = reason;
}

fn shader_enabled() -> bool {
    SHADER_ENABLED.load(Ordering::Acquire)
}

fn object_contract_available() -> bool {
    hooks::hooks_ready()
        && DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        && engine_contracts::eye_position_ready()
        && engine_contracts::shader_package_lifetime_ready()
}

fn terrain_lod_enabled() -> bool {
    TERRAIN_LOD_ENABLED.load(Ordering::Acquire)
}

fn terrain_fade_enabled() -> bool {
    TERRAIN_FADE_ENABLED.load(Ordering::Acquire)
}

fn close_terrain_enabled() -> bool {
    CLOSE_TERRAIN_ENABLED.load(Ordering::Acquire)
}

fn land_lod_contracts_ready() -> bool {
    hooks::hooks_ready()
        && DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        && engine_contracts::terrain_contract_available()
        && compiler::land_lod_compile_ready()
        && !compiler::land_lod_compile_failed()
        && device_resources::land_lod_resources_ready()
        && !device_resources::land_lod_create_failed()
}

fn terrain_fade_contracts_ready() -> bool {
    hooks::hooks_ready()
        && DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        && engine_contracts::terrain_contract_available()
        && compiler::terrain_fade_compile_ready()
        && device_resources::terrain_fade_resources_ready()
}

fn close_terrain_contract_available() -> bool {
    hooks::hooks_ready()
        && DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        && engine_contracts::terrain_contract_available()
}

fn store_terrain_options(settings: NativePbrSettings) {
    TERRAIN_ENABLED.store(settings.enabled, Ordering::Release);
    CLOSE_TERRAIN_ENABLED.store(settings.enabled, Ordering::Release);
    TERRAIN_FADE_ENABLED.store(settings.enabled, Ordering::Release);
    TERRAIN_LOD_ENABLED.store(settings.enabled, Ordering::Release);
}

fn sanitize_scale(value: f32, fallback: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        fallback
    }
}
