//! Native PBR integration.
//!
//! This module owns PBR configuration, preparation state, and the public
//! boundary used by OMV's renderer geometry hooks. Shader compilation, engine contracts,
//! device resources, draw classification, constants, diagnostics, and terrain
//! light capture live in focused child modules. OMV storage remains independent
//! from NVR's native object-size patches.
//!
//! Replacement binding follows the engine's own shader-state model. OMV exposes
//! replacement handles transiently during `BSShader::SetShaders`, then restores
//! native wrapper fields while `NiDX9RenderState` remains authoritative for the
//! active D3D pair. Draw hooks validate samplers and constants without rebinding
//! successful draws. Close terrain is admitted per draw because the engine can
//! submit several geometries after one `SetShaders` call; only rejected draws
//! temporarily switch to vanilla and require a replacement restore afterward.
//!
//! Runtime disable is a passive engine-contract boundary. The proven PBR
//! inline hooks remain resident because restoring stale shader-wrapper or
//! shared package state was a prior corruption defect documented in the PBR
//! errata. Their detours bypass before selector/sampler work, while the shared
//! renderer geometry hooks remain resident and PBR device resources are
//! released.
//! Process-owned compiled bytecode and observed engine-wrapper identities
//! remain cached for safe live re-enable.
//!
//! CPU-only bytecode preparation may begin during `NVSEPlugin_Load` after the
//! enabled settings snapshot is staged. That early worker owns only embedded
//! source, the reconstructible cache, and process memory. Engine inspection,
//! hook installation, world publication, D3D resource creation, and PBR
//! activation remain exclusively behind DeferredInit and DisplayScene.

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
mod terrain_lights;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use anyhow::Result;

const OBJECT_PBR_PROFILE_VALUE_COUNT: usize = 4;
const TERRAIN_PBR_PROFILE_VALUE_COUNT: usize = 5;
const BLOCK_REASON_NONE: u32 = 0;
const BLOCK_REASON_HOOKS: u32 = 1;
const BLOCK_REASON_EYE_POSITION: u32 = 2;
const BLOCK_REASON_SHADER_PACKAGE: u32 = 3;

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
static BLOCK_REASON: AtomicU32 = AtomicU32::new(BLOCK_REASON_NONE);

/// Cleanup token for PBR state acquired at one native D3D draw boundary.
///
/// Callers obtain this token from [`prepare_direct_draw`] and must pass it to
/// [`finish_direct_draw`] after the corresponding draw, regardless of the
/// draw's HRESULT.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub(crate) struct PbrDirectDrawScope {
    restore_after_draw: bool,
}

/// Immutable native-PBR settings staged from startup or the runtime menu.
///
/// The snapshot is `Copy` so startup can hand the same sanitized ownership to
/// the CPU prewarm decision and the later DeferredInit installation without a
/// shared configuration lock.
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

/// User-visible phase of native-PBR bytecode and device preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PbrPreparationPhase {
    /// Native PBR is disabled and owns no active preparation transaction.
    Disabled,
    /// The process compiler is grouping inputs and validating cache entries.
    Inventory,
    /// Background workers are compiling missing unique inputs.
    Compiling,
    /// Process bytecode is ready and D3D resources are being created.
    CreatingResources,
    /// The complete logical catalog and current-device resources are ready.
    Ready,
    /// Bytecode compilation, cache publication, or D3D creation failed.
    Failed,
}

/// Logical shader-catalog progress reported by OMV diagnostics.
///
/// Source-equivalent templates may share one compiler result internally, but
/// these counts retain engine-visible logical identities so readiness matches
/// the device resource catalog exactly.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PbrPreparationStatus {
    /// Current preparation lifecycle phase.
    pub(crate) phase: PbrPreparationPhase,
    /// Total logical shader templates required by native PBR.
    pub(crate) total: usize,
    /// Logical templates restored from memory or the verified disk cache.
    pub(crate) cache_hits: usize,
    /// Logical templates whose compiler input was absent from the cache.
    pub(crate) cache_misses: usize,
    /// Logical templates completed during the current compiler transaction.
    pub(crate) compiled: usize,
    /// Logical templates with process-owned verified bytecode.
    pub(crate) bytecode_ready: usize,
    /// Logical templates with current-device D3D shader resources.
    pub(crate) resources_ready: usize,
    /// Logical templates whose preparation or creation failed.
    pub(crate) failed: usize,
}

impl PbrPreparationStatus {
    /// Return whether preparation still has background or device work pending.
    pub(crate) fn active(self) -> bool {
        matches!(
            self.phase,
            PbrPreparationPhase::Inventory
                | PbrPreparationPhase::Compiling
                | PbrPreparationPhase::CreatingResources
        )
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct NativePbrRuntimeStatus {
    pub(crate) preparation: PbrPreparationStatus,
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
    pub(crate) object_contract_ready: bool,
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
    pub(crate) object_last_fade_geometry: usize,
    pub(crate) object_last_fade_property: usize,
    pub(crate) object_last_fade_distance: f32,
    pub(crate) object_last_fade_start: f32,
    pub(crate) object_last_fade_end: f32,
    pub(crate) object_last_fade_expected: f32,
    pub(crate) object_last_fade_staged: f32,
    pub(crate) object_last_fade_c25: f32,
    pub(crate) object_last_light_capacity: u32,
    pub(crate) object_last_light_signature: u32,
    pub(crate) object_last_base_texture: usize,
    pub(crate) object_last_normal_texture: usize,
    pub(crate) terrain_contract_available: bool,
    pub(crate) terrain_engine_contract_ready: bool,
    pub(crate) land_lod_shader_total: usize,
    pub(crate) land_lod_bytecode_ready: usize,
    pub(crate) land_lod_bytecode_failed: usize,
    pub(crate) land_lod_resources_ready: usize,
    pub(crate) land_lod_resources_failed: usize,
    pub(crate) terrain_fade_shader_total: usize,
    pub(crate) terrain_fade_bytecode_ready: usize,
    pub(crate) terrain_fade_bytecode_failed: usize,
    pub(crate) terrain_fade_resources_ready: usize,
    pub(crate) terrain_fade_resources_failed: usize,
    pub(crate) close_terrain_shader_total: usize,
    pub(crate) close_terrain_bytecode_ready: usize,
    pub(crate) close_terrain_bytecode_failed: usize,
    pub(crate) close_terrain_resources_ready: usize,
    pub(crate) close_terrain_resources_failed: usize,
    pub(crate) land_lod_replacements_last_frame: u32,
    pub(crate) land_lod_fallbacks_last_frame: u32,
    pub(crate) terrain_fade_replacements_last_frame: u32,
    pub(crate) terrain_fade_fallbacks_last_frame: u32,
    pub(crate) close_terrain_replacements_last_frame: u32,
    pub(crate) close_terrain_fallbacks_last_frame: u32,
    pub(crate) land_lod_contract_active: bool,
    pub(crate) land_lod_contract_failed: bool,
    pub(crate) terrain_fade_contract_failed: bool,
    pub(crate) close_terrain_contract_failed: bool,
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

impl NativePbrSettings {
    /// Apply the OMV master-effects gate without mutating persisted settings.
    pub(crate) const fn with_master_enabled(mut self, master_enabled: bool) -> Self {
        self.enabled = self.enabled && master_enabled;
        self
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

/// Start CPU-only native-PBR preparation when the staged settings enable it.
///
/// This deliberately does not store runtime settings or mark PBR configured.
/// It is safe during `NVSEPlugin_Load` because the compiler boundary cannot
/// access the D3D device, hooks, engine objects, or focused world pipeline.
/// [`install`] remains the sole DeferredInit owner of those transitions.
pub(crate) fn start_cpu_preparation(settings: NativePbrSettings) {
    if settings.enabled {
        compiler::ensure_object_prewarm_started();
    }
}

/// Publish native-PBR settings and install its resident engine observers.
///
/// The shared `SetTexture` observer remains resident even when PBR starts
/// disabled because native sky consumes the same getter-free stage mirror.
/// Shader selection and package ownership are installed only for enabled PBR.
pub(crate) fn install(settings: NativePbrSettings) -> Result<()> {
    constants::store_settings(settings);
    DEBUG_LOG_DRAWS.store(settings.debug_log_draws, Ordering::Release);
    set_menu_diagnostics_active(crate::runtime::menu_diagnostics_active());
    store_terrain_options(settings);
    INSTALL_BOUNDARY_REACHED.store(true, Ordering::Release);
    if !settings.enabled {
        let tracking_ready = hooks::install_texture_tracking();
        SHADER_ENABLED.store(false, Ordering::Release);
        INSTALLED.store(false, Ordering::Release);
        refresh_block_reason();
        log::info!(
            "[PBR] Native PBR disabled; shared texture observer resident={tracking_ready}, PBR selection and engine contracts remain passive"
        );
        return Ok(());
    }

    activate()
}

/// Publish whether the close-terrain executable and resource contract exists.
pub(crate) fn configure_terrain_contract(available: bool) {
    engine_contracts::set_terrain_contract_available(available);
    refresh_block_reason();
}

/// Publish whether both executable-proven renderer geometry hooks are active.
pub(crate) fn set_draw_boundary_ready(ready: bool) {
    DRAW_BOUNDARY_READY.store(ready, Ordering::Release);
}

/// Prepares a pending native PBR replacement immediately before a D3D draw.
///
/// The returned token must be passed to [`finish_direct_draw`] after the native
/// draw returns, including on D3D failure.
#[must_use]
pub(crate) fn prepare_direct_draw(geometry: *mut std::ffi::c_void) -> PbrDirectDrawScope {
    PbrDirectDrawScope {
        restore_after_draw: hooks::prepare_direct_draw(geometry),
    }
}

/// Releases draw-scoped PBR state represented by `scope`.
///
/// This function is deliberately cheap when the scope owns no draw-local
/// state: batch-scoped families remain active until [`finish_draw_batches`] or
/// another native pass.
pub(crate) fn finish_direct_draw(scope: PbrDirectDrawScope) {
    hooks::finish_direct_draw(scope.restore_after_draw);
}

/// Clears all batch-scoped PBR draw ownership at the frame boundary.
pub(crate) fn finish_draw_batches() {
    hooks::finish_draw_batches();
}

/// Return a texture identity observed by the resident engine `SetTexture` hook.
///
/// `None` means that the stage is unknown or known-null. Consumers must fail
/// closed rather than query D3D state, because driver readback at geometry rate
/// is outside OMV's render-thread performance contract.
pub(crate) fn tracked_texture(stage: u32) -> Option<usize> {
    samplers::tracked_texture(stage)
}

/// Return the generation of semantic texture-stage transitions.
///
/// Equal repeated `SetTexture` calls do not advance this value. It is suitable
/// for generation-keyed draw caches shared by PBR and native sky.
pub(crate) fn texture_generation() -> u32 {
    samplers::texture_generation()
}

/// Apply live PBR settings at the serialized DisplayScene boundary.
///
/// Disabling makes resident hooks passive and releases device resources.
/// Enabling queues activation so no configuration thread mutates render-owned
/// hooks, wrappers, or COM resources.
pub(crate) fn configure_runtime_options(settings: NativePbrSettings) {
    constants::store_settings(settings);
    store_terrain_options(settings);
    DEBUG_LOG_DRAWS.store(settings.debug_log_draws, Ordering::Release);
    set_menu_diagnostics_active(crate::runtime::menu_diagnostics_active());
    if !INSTALL_BOUNDARY_REACHED.load(Ordering::Acquire) {
        SHADER_ENABLED.store(settings.enabled, Ordering::Release);
        refresh_block_reason();
        return;
    }

    let was_enabled = SHADER_ENABLED.load(Ordering::Acquire);
    if was_enabled && !settings.enabled {
        ENABLE_PENDING.store(false, Ordering::Release);
        SHADER_ENABLED.store(false, Ordering::Release);
        compiler::cancel_preparation();
        if release_disabled_device_resources() {
            log::info!(
                "[PBR] Native PBR disabled; engine hooks are passive and device resources were released"
            );
        }
    } else if !was_enabled && settings.enabled {
        if !ENABLE_PENDING.swap(true, Ordering::AcqRel) {
            log::info!("[PBR] Native PBR activation queued for the next DisplayScene boundary");
        }
    } else if !settings.enabled {
        ENABLE_PENDING.store(false, Ordering::Release);
    }
    refresh_block_reason();
}

/// Release PBR device ownership without tearing down shared engine contracts.
///
/// Compiled shader bytecode and observed wrapper identities are process-owned
/// and deliberately retained. The installed detours perform an early
/// configured-state bypass while disabled; this avoids the stale-handle
/// restoration defect described in `graphics_fnv_pbr_errata.md`. A `false`
/// result means the nonblocking resource owner was busy and nothing changed.
#[must_use]
pub(crate) fn release_disabled_device_resources() -> bool {
    if !device_resources::try_reset_after(hooks::release_device_resources) {
        return false;
    }
    terrain_lights::invalidate_draw_cache();
    samplers::reset();
    diagnostics::reset();
    ACTIVE_CONTRACTS_READY.store(false, Ordering::Release);
    ACTIVE_CONTRACTS_FAILED.store(false, Ordering::Release);
    true
}

pub(crate) fn set_menu_diagnostics_active(active: bool) {
    let enabled = detailed_diagnostics_enabled(active, DEBUG_LOG_DRAWS.load(Ordering::Acquire));
    if enabled && !diagnostics::detailed_enabled() {
        diagnostics::reset();
    }
    diagnostics::set_detailed_enabled(enabled);
}

fn detailed_diagnostics_enabled(menu_open: bool, configured: bool) -> bool {
    menu_open && configured
}

pub(crate) fn runtime_status() -> NativePbrRuntimeStatus {
    let object_last_vertex_sls = diagnostics::object_last_vertex_sls();
    let object_last_pixel_sls = diagnostics::object_last_pixel_sls();

    let registry = shader_registry::summary();
    NativePbrRuntimeStatus {
        preparation: preparation_status(),
        installed: INSTALLED.load(Ordering::Acquire),
        shader_enabled: shader_enabled(),
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
        object_contract_ready: object_contract_available(),
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
        object_last_fade_geometry: diagnostics::object_last_fade_geometry(),
        object_last_fade_property: diagnostics::object_last_fade_property(),
        object_last_fade_distance: diagnostics::object_last_fade_distance(),
        object_last_fade_start: diagnostics::object_last_fade_start(),
        object_last_fade_end: diagnostics::object_last_fade_end(),
        object_last_fade_expected: diagnostics::object_last_fade_expected(),
        object_last_fade_staged: diagnostics::object_last_fade_staged(),
        object_last_fade_c25: diagnostics::object_last_fade_c25(),
        object_last_light_capacity: diagnostics::object_last_light_capacity(),
        object_last_light_signature: diagnostics::object_last_light_signature(),
        object_last_base_texture: diagnostics::object_last_base_texture(),
        object_last_normal_texture: diagnostics::object_last_normal_texture(),
        terrain_contract_available: engine_contracts::terrain_contract_available(),
        terrain_engine_contract_ready: terrain_engine_contract_ready(),
        land_lod_shader_total: registry.land_lod_records,
        land_lod_bytecode_ready: compiler::land_lod_ready_count(),
        land_lod_bytecode_failed: compiler::land_lod_failed_count(),
        land_lod_resources_ready: device_resources::land_lod_created_count(),
        land_lod_resources_failed: device_resources::land_lod_create_failed_count(),
        terrain_fade_shader_total: registry.terrain_fade_records,
        terrain_fade_bytecode_ready: compiler::terrain_fade_ready_count(),
        terrain_fade_bytecode_failed: compiler::terrain_fade_failed_count(),
        terrain_fade_resources_ready: device_resources::terrain_fade_created_count(),
        terrain_fade_resources_failed: device_resources::terrain_fade_create_failed_count(),
        close_terrain_shader_total: registry.close_terrain_records,
        close_terrain_bytecode_ready: compiler::close_terrain_ready_count(),
        close_terrain_bytecode_failed: compiler::close_terrain_failed_count(),
        close_terrain_resources_ready: device_resources::close_terrain_created_count(),
        close_terrain_resources_failed: device_resources::close_terrain_create_failed_count(),
        land_lod_replacements_last_frame: diagnostics::land_lod_replacements_last_frame(),
        land_lod_fallbacks_last_frame: diagnostics::land_lod_fallbacks_last_frame(),
        terrain_fade_replacements_last_frame: diagnostics::terrain_fade_replacements_last_frame(),
        terrain_fade_fallbacks_last_frame: diagnostics::terrain_fade_fallbacks_last_frame(),
        close_terrain_replacements_last_frame: diagnostics::close_terrain_replacements_last_frame(),
        close_terrain_fallbacks_last_frame: diagnostics::close_terrain_fallbacks_last_frame(),
        land_lod_contract_active: terrain_lod_enabled() && land_lod_contracts_ready(),
        land_lod_contract_failed: compiler::land_lod_compile_failed()
            || device_resources::land_lod_create_failed(),
        terrain_fade_contract_failed: compiler::terrain_fade_compile_failed()
            || device_resources::terrain_fade_create_failed(),
        close_terrain_contract_failed: compiler::close_terrain_compile_failed()
            || device_resources::close_terrain_create_failed(),
        close_terrain_contract_proven: close_terrain_contract_available(),
        terrain_fade_contract_proven: terrain_fade_contracts_ready(),
        block_reason: block_reason_label(BLOCK_REASON.load(Ordering::Acquire)),
    }
}

pub(crate) fn preparation_status() -> PbrPreparationStatus {
    let compile = compiler::preparation_status();
    let configured = SHADER_ENABLED.load(Ordering::Acquire);
    let resources_ready = device_resources::object_created_count()
        + device_resources::land_lod_created_count()
        + device_resources::terrain_fade_created_count()
        + device_resources::close_terrain_created_count();
    let phase = if !configured {
        PbrPreparationPhase::Disabled
    } else {
        match compile.phase {
            compiler::PreparationPhase::Dormant | compiler::PreparationPhase::Inventory => {
                PbrPreparationPhase::Inventory
            }
            compiler::PreparationPhase::Compiling => PbrPreparationPhase::Compiling,
            compiler::PreparationPhase::Ready if device_resources::all_resources_ready() => {
                PbrPreparationPhase::Ready
            }
            compiler::PreparationPhase::Ready => PbrPreparationPhase::CreatingResources,
            compiler::PreparationPhase::Failed => PbrPreparationPhase::Failed,
        }
    };

    PbrPreparationStatus {
        phase,
        total: compile.total,
        cache_hits: compile.cache_hits,
        cache_misses: compile.cache_misses,
        compiled: compile.compiled,
        bytecode_ready: compile.ready,
        resources_ready,
        failed: compile.failed,
    }
}

pub(crate) fn retry_preparation() {
    if !SHADER_ENABLED.load(Ordering::Acquire) {
        return;
    }
    if !device_resources::try_reset_after(|| {
        compiler::cancel_preparation();
        hooks::release_device_resources();
    }) {
        return;
    }
    compiler::ensure_object_prewarm_started();
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
    let configured = SHADER_ENABLED.load(Ordering::Acquire);
    if configured {
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
    if diagnostics::detailed_enabled() {
        samplers::service_frame();
        diagnostics::service_frame(shader_enabled(), DEBUG_LOG_DRAWS.load(Ordering::Acquire));
    }
}

fn activate() -> Result<()> {
    SHADER_ENABLED.store(true, Ordering::Release);
    hooks::install()?;
    INSTALLED.store(true, Ordering::Release);
    compiler::ensure_object_prewarm_started();
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

/// Release all current-device PBR ownership without waiting.
///
/// A `false` result leaves resource publication unchanged so Recreate can
/// abort before native reset invalidates a still-owned shader.
#[must_use]
pub(crate) fn reset_runtime_state() -> bool {
    if !device_resources::try_reset_after(hooks::release_device_resources) {
        return false;
    }
    terrain_lights::invalidate_draw_cache();
    shader_record::reset();
    samplers::reset();
    samplers::set_texture_tracking_ready(hooks::hooks_ready());
    diagnostics::reset();
    set_menu_diagnostics_active(crate::runtime::menu_diagnostics_active());
    ACTIVE_CONTRACTS_READY.store(false, Ordering::Release);
    ACTIVE_CONTRACTS_FAILED.store(false, Ordering::Release);
    refresh_block_reason();
    true
}

fn refresh_block_reason() {
    let reason = if !SHADER_ENABLED.load(Ordering::Acquire) {
        BLOCK_REASON_NONE
    } else if !hooks::hooks_ready() {
        BLOCK_REASON_HOOKS
    } else if !engine_contracts::eye_position_ready() {
        BLOCK_REASON_EYE_POSITION
    } else if !engine_contracts::shader_package_lifetime_ready() {
        BLOCK_REASON_SHADER_PACKAGE
    } else {
        BLOCK_REASON_NONE
    };
    BLOCK_REASON.store(reason, Ordering::Release);
}

fn block_reason_label(reason: u32) -> Option<&'static str> {
    match reason {
        BLOCK_REASON_HOOKS => Some("object shader hooks unavailable"),
        BLOCK_REASON_EYE_POSITION => Some("EyePosition contract unavailable"),
        BLOCK_REASON_SHADER_PACKAGE => Some("shader package lifetime contract unavailable"),
        _ => None,
    }
}

fn shader_enabled() -> bool {
    SHADER_ENABLED.load(Ordering::Acquire)
        && compiler::preparation_ready()
        && device_resources::all_resources_ready()
}

#[inline]
fn replacement_configured() -> bool {
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

fn terrain_engine_contract_ready() -> bool {
    hooks::hooks_ready()
        && DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        && engine_contracts::terrain_contract_available()
}

fn terrain_fade_contracts_ready() -> bool {
    hooks::hooks_ready()
        && DRAW_BOUNDARY_READY.load(Ordering::Acquire)
        && engine_contracts::terrain_contract_available()
        && compiler::terrain_fade_compile_ready()
        && device_resources::terrain_fade_resources_ready()
}

fn close_terrain_contract_available() -> bool {
    close_terrain_activation_gate(
        hooks::hooks_ready()
            && DRAW_BOUNDARY_READY.load(Ordering::Acquire)
            && engine_contracts::terrain_contract_available(),
        compiler::close_terrain_compile_ready(),
        compiler::close_terrain_compile_failed(),
        device_resources::close_terrain_resources_ready(),
        device_resources::close_terrain_create_failed(),
    )
}

fn close_terrain_activation_gate(
    engine_contract_ready: bool,
    family_bytecode_ready: bool,
    compile_failed: bool,
    family_resources_ready: bool,
    create_failed: bool,
) -> bool {
    engine_contract_ready
        && family_bytecode_ready
        && !compile_failed
        && family_resources_ready
        && !create_failed
}

fn store_terrain_options(settings: NativePbrSettings) {
    TERRAIN_ENABLED.store(settings.enabled, Ordering::Release);
    CLOSE_TERRAIN_ENABLED.store(settings.enabled, Ordering::Release);
    TERRAIN_FADE_ENABLED.store(settings.enabled, Ordering::Release);
    TERRAIN_LOD_ENABLED.store(settings.enabled, Ordering::Release);
    crate::fnv_local_lights::configure_terrain(settings.enabled);
}

fn sanitize_scale(value: f32, fallback: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        fallback
    }
}

#[cfg(test)]
mod master_setting_tests {
    use super::{NativePbrSettings, close_terrain_activation_gate, detailed_diagnostics_enabled};

    #[test]
    fn one_ready_variant_cannot_activate_the_close_terrain_family() {
        let engine_contract_ready = true;
        let selected_variant_ready = true;
        let family_bytecode_ready = false;
        let family_resources_ready = false;

        let legacy_partial_family_gate = engine_contract_ready && selected_variant_ready;
        assert!(legacy_partial_family_gate);
        assert!(!close_terrain_activation_gate(
            engine_contract_ready,
            family_bytecode_ready,
            false,
            family_resources_ready,
            false,
        ));
        assert!(close_terrain_activation_gate(
            engine_contract_ready,
            true,
            false,
            true,
            false,
        ));
        assert!(!close_terrain_activation_gate(
            engine_contract_ready,
            true,
            true,
            true,
            false,
        ));
        assert!(!close_terrain_activation_gate(
            engine_contract_ready,
            true,
            false,
            true,
            true,
        ));
    }

    #[test]
    fn master_switch_is_a_runtime_override_not_a_config_mutation() {
        let configured = NativePbrSettings::from(crate::config::NativePbrConfig::default());
        assert!(configured.enabled);
        assert!(!configured.with_master_enabled(false).enabled);
        assert!(configured.with_master_enabled(true).enabled);
    }

    #[test]
    fn detailed_diagnostics_require_an_open_menu_and_explicit_configuration() {
        assert!(!detailed_diagnostics_enabled(false, false));
        assert!(!detailed_diagnostics_enabled(false, true));
        assert!(!detailed_diagnostics_enabled(true, false));
        assert!(detailed_diagnostics_enabled(true, true));
    }

    #[test]
    fn device_reset_preserves_the_process_owned_compiler_catalog() {
        let source = include_str!("pbr.rs");
        let reset = source
            .split_once("pub(crate) fn reset_runtime_state()")
            .and_then(|(_, tail)| tail.split_once("fn refresh_block_reason()"))
            .map(|(body, _)| body)
            .expect("reset runtime state body");

        assert!(reset.contains("device_resources::try_reset_after"));
        assert!(
            !reset.contains("compiler::reset"),
            "D3D device reset must not invalidate process-owned shader bytecode"
        );
    }

    #[test]
    fn disabling_native_pbr_cancels_local_preparation() {
        let source = include_str!("pbr.rs");
        let configure = source
            .split_once("pub(crate) fn configure_runtime_options(")
            .and_then(|(_, tail)| tail.split_once("pub(crate) fn set_menu_diagnostics_active("))
            .map(|(body, _)| body)
            .expect("runtime PBR configuration body");

        assert!(configure.contains("compiler::cancel_preparation()"));
        assert!(configure.contains("release_disabled_device_resources()"));
    }

    #[test]
    fn disabled_pbr_releases_resources_without_tearing_down_engine_contracts() {
        let source = include_str!("pbr.rs");
        let release = source
            .split_once("pub(crate) fn release_disabled_device_resources()")
            .and_then(|(_, tail)| tail.split_once("pub(crate) fn set_menu_diagnostics_active("))
            .map(|(body, _)| body)
            .expect("disabled PBR release body");

        assert!(release.contains("device_resources::try_reset_after"));
        assert!(release.contains("hooks::release_device_resources"));
        assert!(!release.contains("hooks::reset()"));
        assert!(!release.contains("shader_record::reset()"));
        assert!(
            !release.contains("compiler::reset"),
            "process-owned bytecode remains reusable across live disable"
        );
    }

    #[test]
    fn pbr_render_resource_paths_never_wait_for_an_owner() {
        let resources = include_str!("pbr/device_resources.rs");
        let blocking_resource_lock = ["RESOURCES", ".lock()"].concat();
        assert!(resources.contains("RESOURCES.try_lock()"));
        assert!(
            !resources.contains(&blocking_resource_lock),
            "presentation and Recreate paths must defer instead of blocking"
        );

        let compiler = include_str!("pbr/compiler.rs");
        let prepared = compiler
            .split_once("pub(super) fn prepared_bytecode(")
            .and_then(|(_, tail)| tail.split_once("pub(super) fn preparation_status()"))
            .map(|(body, _)| body)
            .expect("prepared bytecode reader");
        assert!(prepared.contains("PREPARED_BYTECODE"));
        assert!(prepared.contains(".try_lock()?"));
        assert!(!prepared.contains("PREPARED_BYTECODE.lock()"));
    }
}
