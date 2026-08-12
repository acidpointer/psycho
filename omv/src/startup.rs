//! xNVSE-owned graphics startup and DeferredInit hook publication.
//!
//! `NVSEPlugin_Load` performs configuration and process-owned worker
//! preparation only. Native-PBR prewarm may read embedded source and its
//! reconstructible cache there, but it cannot inspect the engine or D3D device.
//! Device inspection, initial depth-producer selection, world-pipeline
//! publication, and executable hook installation occur at `DeferredInit`,
//! after data loading and outside render callbacks. Optional depth capability
//! may select a safe session fallback, but it never gates unrelated OMV hooks.
//! Deferred installation is guarded transactionally: concurrent calls do not
//! overlap, a failed attempt is retryable, and only full success is published
//! as installed.
//!
//! # Frozen pre-Deferred footprint
//!
//! `NVSEPlugin_Load` runs while other plugins are still constructing engine
//! data. BaseObjectSwapper has a known uninitialized `ConditionalInput` path
//! whose outcome changes when OMV alters this phase's layout, allocation, or
//! publication footprint. A call is not safe here merely because it is CPU
//! only, atomic, lock-free, or never dereferences an engine pointer.
//!
//! Treat [`initialize_for_nvse`], every value it constructs, and every worker
//! it starts as a frozen compatibility ABI. In particular, do not add a
//! deferred graphics feature to `GraphicsConfig`, `GraphicsMenuConfig`,
//! `RuntimeSettings`, `DeferredHookSettings`, or a worker command/snapshot.
//! Do not publish a new route, generation, or settings atomic from this phase.
//! The required extension pattern is the Shadows pattern: retain the durable
//! TOML table, parse it through a feature-specific loader after
//! `DeferredInit`, publish passive settings there, and open the route only
//! immediately before its resident hook group becomes reachable.
//!
//! See `docs/nvse_startup_phase_safety.md` and
//! `docs/graphics_fnv_atmosphere_startup_crash_errata.md`. The structural tests
//! in this module intentionally reject deferred feature state in every known
//! pre-Deferred owner; extend that owner list whenever startup adds a new
//! container.

use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

use anyhow::{Context, Result};
use libpsycho::logger::Logger;
use parking_lot::Mutex;

const LOG_FILE: &str = "./omv-latest.log";

/// Frozen handoff built during `NVSEPlugin_Load` and consumed at DeferredInit.
///
/// Do not add settings for a new/deferred graphics route here. A field changes
/// the `Option`/mutex payload constructed during plugin loading even when the
/// field is plain `Copy` data. Load route-specific configuration inside
/// [`install_deferred_hooks_once`] instead, following native Shadows.
#[derive(Clone, Copy)]
struct DeferredHookSettings {
    native_pbr: crate::effects::pbr::NativePbrSettings,
    native_sky: crate::effects::sky::NativeSkySettings,
    depth_provider: crate::backend::DepthProvider,
}

static DEFERRED_HOOK_SETTINGS: LazyLock<Mutex<Option<DeferredHookSettings>>> =
    LazyLock::new(|| Mutex::new(None));
const DEFERRED_INSTALL_NOT_STARTED: u8 = 0;
const DEFERRED_INSTALL_IN_PROGRESS: u8 = 1;
const DEFERRED_INSTALL_COMPLETE: u8 = 2;

static DEFERRED_INSTALL_STATE: AtomicU8 = AtomicU8::new(DEFERRED_INSTALL_NOT_STARTED);
static COMPAT_REPORT_LOGGED: AtomicBool = AtomicBool::new(false);

struct DeferredInstallAttempt<'a> {
    state: &'a AtomicU8,
    completed: bool,
}

impl DeferredInstallAttempt<'_> {
    fn complete(mut self) {
        self.state
            .store(DEFERRED_INSTALL_COMPLETE, Ordering::Release);
        self.completed = true;
    }
}

impl Drop for DeferredInstallAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // Every DeferredInit installer is idempotent or re-enables its
            // prepared hook. Resetting the gate permits recovery from a
            // transient mailbox, device, or worker-spawn failure without ever
            // publishing a partial attempt as complete.
            self.state
                .store(DEFERRED_INSTALL_NOT_STARTED, Ordering::Release);
        }
    }
}

fn begin_deferred_install(
    state: &AtomicU8,
) -> Result<Option<DeferredInstallAttempt<'_>>, &'static str> {
    match state.compare_exchange(
        DEFERRED_INSTALL_NOT_STARTED,
        DEFERRED_INSTALL_IN_PROGRESS,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Ok(Some(DeferredInstallAttempt {
            state,
            completed: false,
        })),
        Err(DEFERRED_INSTALL_COMPLETE) => Ok(None),
        Err(_) => Err("deferred graphics hook installation is already in progress"),
    }
}

/// Stage configuration and process-owned workers during `NVSEPlugin_Load`.
///
/// This boundary must not inspect engine graphics objects, publish focused
/// world state, or install hooks. [`install_deferred_hooks`] owns those later
/// transitions after xNVSE reports `DeferredInit`. It also must not load,
/// stage, copy, or atomically publish settings for a newly added deferred
/// route; atomic-only startup publication caused the rejected Shadows
/// footprint that reproduced the known BaseObjectSwapper crash.
pub(crate) fn initialize_for_nvse() -> Result<()> {
    let cfg = crate::config::load_config();

    initialize_logging(&cfg.diagnostics)?;
    // Normal builds compile this call away. Attribution builds still require
    // the explicit diagnostics switch and sample only one frame per 120, so
    // installing a diagnostic binary does not imply per-draw timing traffic.
    crate::graphics_diagnostics::configure(cfg.diagnostics.debug_log, 120);
    log::info!("[INIT] Oh My Vegas graphics initialized through xNVSE");
    log::info!(
        "[INIT] OMV build unix={} target={} profile={}",
        option_env!("OMV_BUILD_UNIX").unwrap_or("unknown"),
        option_env!("OMV_BUILD_TARGET").unwrap_or("unknown"),
        option_env!("OMV_BUILD_PROFILE").unwrap_or("unknown")
    );
    log::info!(
        "[INIT] OMV source commit={} branch={} tag={} dirty={}",
        option_env!("OMV_GIT_COMMIT").unwrap_or("unknown"),
        option_env!("OMV_GIT_BRANCH").unwrap_or("unknown"),
        option_env!("OMV_GIT_TAG")
            .filter(|tag| !tag.is_empty())
            .unwrap_or("<none>"),
        option_env!("OMV_GIT_DIRTY").unwrap_or("unknown")
    );
    log::info!(
        "[CONFIG] Working path '{}'; distribution fallback '{}' (read-only startup)",
        crate::config::CONFIG_PATH,
        crate::config::DEFAULT_CONFIG_PATH
    );
    crate::shaders::start_shader_cache_maintenance();

    let menu_config = crate::config::GraphicsMenuConfig::from(cfg);
    let native_pbr = crate::effects::pbr::NativePbrSettings::from(cfg.graphics.native_pbr)
        .with_master_enabled(cfg.graphics.screen_space_shaders);
    let native_sky = crate::effects::sky::NativeSkySettings::from(cfg.graphics.native_sky)
        .with_master_enabled(cfg.graphics.screen_space_shaders);

    if !cfg.graphics.screen_space_shaders {
        log::info!("[SHADERS] OMV effects disabled by the master config switch");
    }

    let depth_provider = crate::backend::DepthProvider::from(cfg.graphics.depth_provider);
    log::info!(
        "[CONFIG] Requested depth provider: {}",
        depth_provider.label()
    );
    crate::runtime::configure(crate::runtime::RuntimeSettings {
        menu_config,
        depth_provider,
        menu_toggle_key: cfg.graphics.menu_toggle_key,
        shader_scan_interval_ms: cfg.graphics.shader_scan_interval_ms,
    });
    log::info!(
        "[SHADERS] Watching screen-space shaders in '{}'",
        crate::shaders::SHADER_DIR
    );
    log::info!("[IMGUI] Shader menu enabled");

    *DEFERRED_HOOK_SETTINGS.lock() = Some(DeferredHookSettings {
        native_pbr,
        native_sky,
        depth_provider,
    });
    // Start only after the deferred settings handoff is complete. If the
    // worker finishes immediately, DeferredInit can adopt its bytecode without
    // changing the proven first-publication or hook-install ordering.
    crate::effects::pbr::start_cpu_preparation(native_pbr);

    Ok(())
}

/// Record compatibility state after xNVSE completes normal plugin loading.
pub(crate) fn observe_post_load() {
    log_compatibility_report(crate::compat::GraphicsCompatibility::detect());
}

/// Publish initial graphics ownership and install hooks at `DeferredInit`.
///
/// Installation is transactional and idempotent: a completed attempt latches
/// success, while a partial failure releases the gate for a later retry. New
/// route-specific config loaders belong inside this boundary, before their
/// route is admitted and resident hooks become reachable, not in
/// [`initialize_for_nvse`] or a value staged by it.
pub(crate) fn install_deferred_hooks() -> Result<()> {
    let Some(install_attempt) =
        begin_deferred_install(&DEFERRED_INSTALL_STATE).map_err(anyhow::Error::msg)?
    else {
        log::info!("[INIT] Deferred graphics hooks already installed");
        return Ok(());
    };

    let result = install_deferred_hooks_once();
    if result.is_err() {
        // Inline or device hooks may already be resident when a later step
        // fails. Publishing the no-depth state makes those callbacks inert and
        // ensures an external producer is never suppressed by a partial
        // startup attempt. The transactional gate remains retryable.
        crate::backend::abandon_initial_depth_provider();
        crate::runtime::abandon_deferred_first_person_motion_blur_admission();
    }
    result?;
    install_attempt.complete();
    log::info!("[INIT] Deferred OMV graphics hooks initialized");

    Ok(())
}

fn install_deferred_hooks_once() -> Result<()> {
    let settings = DEFERRED_HOOK_SETTINGS
        .lock()
        .as_ref()
        .copied()
        .context("graphics startup settings were not initialized")?;
    let compatibility = crate::compat::GraphicsCompatibility::detect();
    log_compatibility_report(compatibility);

    // Shadows intentionally have a separate config parser. Loading them only
    // after xNVSE enters DeferredInit restores the proven plugin/data-loading
    // value graph without removing the schema-one table or any runtime route.
    let native_shadows = match crate::config::load_native_shadows_config_from_disk() {
        Ok(config) => crate::effects::shadows::NativeShadowsSettings::from(config),
        Err(error) => {
            log::error!("[SHADOWS] Could not load deferred configuration: {error:#}");
            crate::effects::shadows::NativeShadowsSettings::from(
                crate::config::NativeShadowsConfig::default(),
            )
        }
    };

    crate::backend::publish_initial_d3d_device()
        .map_err(anyhow::Error::msg)
        .context("could not publish the DeferredInit D3D9 device")?;
    let depth_activation = crate::backend::initialize_depth_provider(settings.depth_provider);
    let menu_config = crate::runtime::apply_initial_depth_activation(depth_activation);
    crate::backend::startup_log(depth_activation.active);

    // This must remain the first world-pipeline config publication. Publishing
    // from NVSEPlugin_Load caused the 2026-07-18 data-loading crash.
    if !crate::fnv_world_pipeline::publish_config(menu_config) {
        anyhow::bail!("world-effects config owner was busy before hook installation");
    }
    log::info!("[FNV WORLD] Initial config published at DeferredInit");

    crate::effects::pbr::configure_terrain_contract(compatibility.has_vpt_terrain_contract());
    crate::effects::pbr::install(settings.native_pbr)?;
    crate::effects::sky::install(settings.native_sky)?;
    crate::hooks::install_engine_hooks()
        .context("could not establish engine-owned render lifecycle hooks")?;

    // Shadow ownership opens immediately before the already-proven common
    // entry becomes resident. Until its complete shader family is prepared,
    // the hook keeps executing the original native prefix.
    crate::effects::shadows::install(native_shadows)?;
    crate::fnv_local_lights::install_hooks();
    // The complete group becomes resident while DeferredInit is quiescent.
    // Runtime settings alter passive gates only; no render-time executable
    // patch transition is permitted after this point.
    crate::fnv_render::install_scene_boundary_hook()
        .context("could not establish resident FNV scene-boundary hooks")?;
    Ok(())
}

#[cfg(test)]
mod deferred_install_tests {
    use super::*;

    #[test]
    fn failed_attempt_releases_the_gate_for_retry() {
        let state = AtomicU8::new(DEFERRED_INSTALL_NOT_STARTED);
        let attempt = begin_deferred_install(&state)
            .expect("first attempt")
            .expect("new attempt guard");
        assert_eq!(state.load(Ordering::Acquire), DEFERRED_INSTALL_IN_PROGRESS);
        drop(attempt);
        assert_eq!(state.load(Ordering::Acquire), DEFERRED_INSTALL_NOT_STARTED);
        assert!(begin_deferred_install(&state).expect("retry").is_some());
    }

    #[test]
    fn only_completed_attempts_latch_success() {
        let state = AtomicU8::new(DEFERRED_INSTALL_NOT_STARTED);
        begin_deferred_install(&state)
            .expect("first attempt")
            .expect("new attempt guard")
            .complete();
        assert_eq!(state.load(Ordering::Acquire), DEFERRED_INSTALL_COMPLETE);
        assert!(begin_deferred_install(&state).expect("repeat").is_none());
    }

    #[test]
    fn shadow_state_is_absent_from_every_pre_deferred_value_owner() {
        fn declaration_body<'a>(source: &'a str, declaration: &str) -> &'a str {
            source
                .split_once(declaration)
                .and_then(|(_, tail)| tail.split_once("\n}"))
                .map(|(body, _)| body)
                .unwrap_or_else(|| panic!("missing declaration {declaration}"))
        }

        let config = include_str!("config.rs");
        let runtime = include_str!("runtime.rs");
        let current_look = include_str!("current_look.rs");
        let startup = include_str!("startup.rs");
        for (owner, body) in [
            (
                "GraphicsConfig",
                declaration_body(config, "pub(crate) struct GraphicsConfig {"),
            ),
            (
                "GraphicsMenuConfig",
                declaration_body(config, "pub(crate) struct GraphicsMenuConfig {"),
            ),
            (
                "RuntimeSettings",
                declaration_body(runtime, "pub(crate) struct RuntimeSettings {"),
            ),
            (
                "ScreenShaderRuntime",
                declaration_body(runtime, "struct ScreenShaderRuntime {"),
            ),
            (
                "CurrentLookSnapshot",
                declaration_body(current_look, "pub(crate) struct CurrentLookSnapshot {"),
            ),
            (
                "CurrentLookEvent",
                declaration_body(current_look, "pub(crate) enum CurrentLookEvent {"),
            ),
            (
                "CurrentLookCommand",
                declaration_body(current_look, "enum CurrentLookCommand {"),
            ),
            (
                "DeferredHookSettings",
                declaration_body(startup, "struct DeferredHookSettings {"),
            ),
        ] {
            assert!(
                !body.contains("native_shadows") && !body.contains("NativeShadows"),
                "{owner} reintroduced Shadows into the pre-Deferred value graph"
            );
        }
    }

    #[test]
    fn pre_deferred_preparation_cannot_publish_or_install_graphics_state() {
        let source = include_str!("startup.rs");
        let deferred_settings = source
            .split_once("struct DeferredHookSettings {")
            .and_then(|(_, tail)| tail.split_once("\n}"))
            .map(|(body, _)| body)
            .expect("deferred settings value graph");
        assert!(
            !deferred_settings.contains("native_shadows"),
            "shadow state must not enlarge the pre-Deferred handoff"
        );
        let initialize = source
            .split_once("pub(crate) fn initialize_for_nvse()")
            .and_then(|(_, tail)| tail.split_once("pub(crate) fn observe_post_load()"))
            .map(|(body, _)| body)
            .expect("NVSE initialization body");
        let staged = initialize
            .find("*DEFERRED_HOOK_SETTINGS.lock()")
            .expect("deferred settings handoff");
        let prewarm = initialize
            .find("pbr::start_cpu_preparation(native_pbr)")
            .expect("early PBR prewarm");
        assert!(staged < prewarm);
        assert!(!initialize.contains("fnv_world_pipeline::publish_config"));
        assert!(!initialize.contains("pbr::install("));
        assert!(!initialize.contains("shadows::install("));
        assert!(!initialize.contains("shadows::start_preparation"));
        assert!(
            !initialize.contains("native_shadows"),
            "NVSEPlugin_Load must not load, copy, or publish shadow settings"
        );
        assert!(!initialize.contains("shadows::configure_runtime_options"));

        let runtime = include_str!("runtime.rs");
        let runtime_configure = runtime
            .split_once("\n    fn configure(&mut self, settings: RuntimeSettings)")
            .and_then(|(_, tail)| tail.split_once("\n    unsafe fn apply_present_frame("))
            .map(|(body, _)| body)
            .expect("pre-Deferred screen runtime configuration");
        assert!(
            !runtime_configure.contains("shadows::")
                && !runtime_configure.contains("native_shadows"),
            "runtime::configure must not indirectly publish Shadows"
        );

        let deferred = source
            .split_once("fn install_deferred_hooks_once()")
            .and_then(|(_, tail)| tail.split_once("\n#[cfg(test)]"))
            .map(|(body, _)| body)
            .expect("DeferredInit installation body");
        assert!(deferred.contains("fnv_world_pipeline::publish_config(menu_config)"));
        assert!(deferred.contains("pbr::install(settings.native_pbr)"));
        let shadow_config = deferred
            .find("config::load_native_shadows_config_from_disk()")
            .expect("deferred shadow config load");
        let engine = deferred
            .find("hooks::install_engine_hooks()")
            .expect("engine lifecycle hooks");
        let shadows = deferred
            .find("shadows::install(native_shadows)")
            .expect("shadow route admission");
        let common = deferred
            .find("fnv_local_lights::install_hooks()")
            .expect("common shadow hook residency");
        let scene = deferred
            .find("fnv_render::install_scene_boundary_hook()")
            .expect("scene consumer hook residency");
        assert!(shadow_config < engine && engine < shadows && shadows < common && common < scene);
    }

    #[test]
    fn shadow_consumer_and_reset_ownership_have_fixed_source_order() {
        let render = include_str!("fnv_render.rs");
        let pre_alpha = render
            .split_once("unsafe extern \"cdecl\" fn hook_render_pre_depth_groups(")
            .and_then(|(_, tail)| tail.split_once("\nfn current_render_target"))
            .map(|(body, _)| body)
            .expect("opaque pre-alpha entry");
        let shadows = pre_alpha
            .find("shadows::apply_before_alpha")
            .expect("shadow composition");
        let atmosphere = pre_alpha
            .find("fnv_world_pipeline::apply_before_alpha")
            .expect("atmosphere composition");
        assert!(shadows < atmosphere);

        let hooks = include_str!("hooks.rs");
        let recreate = hooks
            .split_once("unsafe extern \"thiscall\" fn recreate_detour(")
            .and_then(|(_, tail)| tail.split_once("unsafe extern \"thiscall\" fn"))
            .map(|(body, _)| body)
            .expect("renderer recreate detour");
        let runtime_release = recreate
            .find("runtime::try_release_device_resources")
            .expect("screen resource release");
        let shadow_release = recreate
            .find("shadows::reset_runtime_state")
            .expect("shadow resource release");
        let native_recreate = recreate[shadow_release..]
            .find("original(renderer, request_a, request_b)")
            .map(|offset| shadow_release + offset)
            .expect("native recreate after resource release");
        assert!(runtime_release < shadow_release && shadow_release < native_recreate);
    }
}

fn log_compatibility_report(compatibility: crate::compat::GraphicsCompatibility) {
    if COMPAT_REPORT_LOGGED.swap(true, Ordering::AcqRel) {
        return;
    }

    compatibility.log_report();
}

fn initialize_logging(diagnostics: &crate::config::DiagnosticsConfig) -> Result<()> {
    let log_level = if diagnostics.debug_log {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    Logger::new()
        .with_file_rotating(LOG_FILE)
        .with_level(log_level)
        .with_module_level("libpsycho::os::windows::memory", log::LevelFilter::Warn)
        .init()
        .map_err(|err| anyhow::anyhow!("logger init failed: {:?}", err))?;

    Logger::start_deferred();
    Ok(())
}
