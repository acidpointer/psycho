//! Deferred runtime ownership for Atom.
//!
//! `NVSEPlugin_Load` captures the runtime directory and event-manager wrapper
//! while xNVSE permits service acquisition. Path construction, Serde/INI
//! parsing, QPC setup, event subscription, and native hook preparation first
//! occur at `DeferredInit`. The overlapping first-person render callsites are
//! installed once from the first subsequent `MainGameLoop`, after synchronous
//! DeferredInit dispatch has exposed the complete graphics-owner chain. MCM
//! Extender remains the only writer of `Atom.ini`; its close event causes a
//! main-thread reload and atomic publication.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use libnvse::TESObjectREFR;
use libnvse::api::event_manager::{EventFlags, EventManager, EventManagerError, EventParamType};
use libnvse::api::interface::NVSEInterfaceError;
use libnvse::api::player_controls::PlayerControls;
use libpsycho::logger::Logger;
use libpsycho::os::windows::winapi::query_performance_frequency;
use thiserror::Error;

use crate::ballistics;
use crate::camera;
use crate::config::{AtomConfig, AtomConfigError};
use crate::input::{self, InputInstallError};

const STATE_COLD: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_ACTIVE: u8 = 2;
const STATE_UNAVAILABLE: u8 = 3;

const HOOK_GATE_COLD: u8 = 0;
const HOOK_GATE_ARMED: u8 = 1;
const HOOK_GATE_INSTALLING: u8 = 2;
const HOOK_GATE_ACTIVE: u8 = 3;
const HOOK_GATE_UNAVAILABLE: u8 = 4;

static STATE: AtomicU8 = AtomicU8::new(STATE_COLD);
static QPC_FREQUENCY: AtomicU32 = AtomicU32::new(0);
static SUMMARY_LATCH: AtomicBool = AtomicBool::new(false);
static BALLISTICS_SUMMARY_LATCH: AtomicBool = AtomicBool::new(false);
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
static FIRST_PERSON_RENDER_HOOK_GATE: PostDeferredHookGate = PostDeferredHookGate::new();
const LOG_FILE: &str = "./atom-latest.log";
const MCM_UPDATE_EVENT: &str = "MCMExtUpdate";
static MCM_UPDATE_PARAMETERS: [EventParamType; 1] = [EventParamType::Array];

/// One-shot admission for callsites shared with deferred graphics plugins.
///
/// xNVSE dispatches every DeferredInit listener synchronously and then emits
/// MainGameLoop from the same main-loop boundary. Arming here and activating
/// there makes Atom the outer callsite owner regardless of DeferredInit
/// listener order. The atomic state also prevents a loading-screen callback or
/// an unexpected duplicate main-loop dispatch from initializing a hook
/// container twice.
struct PostDeferredHookGate {
    state: AtomicU8,
}

impl PostDeferredHookGate {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(HOOK_GATE_COLD),
        }
    }

    fn arm(&self) -> bool {
        self.state
            .compare_exchange(
                HOOK_GATE_COLD,
                HOOK_GATE_ARMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn is_armed(&self) -> bool {
        self.state.load(Ordering::Acquire) == HOOK_GATE_ARMED
    }

    fn activate<T, E>(&self, install: impl FnOnce() -> Result<T, E>) -> Option<Result<T, E>> {
        // MainGameLoop is a recurring message. Keep the terminal fast path to
        // one acquire load instead of issuing a failed read-modify-write every
        // frame after the one-shot installation has completed.
        if self.state.load(Ordering::Acquire) != HOOK_GATE_ARMED {
            return None;
        }
        self.state
            .compare_exchange(
                HOOK_GATE_ARMED,
                HOOK_GATE_INSTALLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;

        let result = install();
        self.state.store(
            if result.is_ok() {
                HOOK_GATE_ACTIVE
            } else {
                HOOK_GATE_UNAVAILABLE
            },
            Ordering::Release,
        );
        Some(result)
    }

    #[cfg(test)]
    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }
}

/// Deferred Atom initialization failure.
#[derive(Debug, Error)]
pub(crate) enum RuntimeError {
    #[error("Psycho logger initialization failed: {0}")]
    Logger(#[from] log::SetLoggerError),
    #[error("could not read {path}: {source}")]
    ReadConfig {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid configuration in {path}: {source}")]
    InvalidConfig {
        path: PathBuf,
        #[source]
        source: AtomConfigError,
    },
    #[error(transparent)]
    Input(#[from] InputInstallError),
}

/// Initialize Atom exactly once at xNVSE `DeferredInit`.
pub(crate) fn initialize(
    runtime_directory: &Path,
    event_manager: Result<&EventManager, &NVSEInterfaceError>,
    player_controls: Result<&PlayerControls, &NVSEInterfaceError>,
) -> Result<(), RuntimeError> {
    if STATE
        .compare_exchange(
            STATE_COLD,
            STATE_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Ok(());
    }

    if let Err(error) = initialize_logging() {
        STATE.store(STATE_UNAVAILABLE, Ordering::Release);
        return Err(error);
    }
    log::info!("[INIT] Atom DeferredInit started");

    match initialize_inner(runtime_directory, event_manager, player_controls) {
        Ok(()) => {
            STATE.store(STATE_ACTIVE, Ordering::Release);
            log::info!("[INIT] Atom initialized successfully");
            Ok(())
        }
        Err(error) => {
            STATE.store(STATE_UNAVAILABLE, Ordering::Release);
            Err(error)
        }
    }
}

fn initialize_inner(
    runtime_directory: &Path,
    event_manager: Result<&EventManager, &NVSEInterfaceError>,
    player_controls: Result<&PlayerControls, &NVSEInterfaceError>,
) -> Result<(), RuntimeError> {
    let config_path = runtime_directory
        .join("Data")
        .join("config")
        .join("Atom")
        .join("Atom.ini");
    let _ = CONFIG_PATH.set(config_path.clone());

    let frequency = match query_performance_frequency() {
        Ok(value) => match u32::try_from(value) {
            Ok(frequency) if frequency != 0 => frequency,
            _ => {
                log::warn!(
                    "[INPUT_TELEMETRY] QPC frequency is outside Atom's supported 32-bit range. Input remains active, but latency collection is disabled"
                );
                0
            }
        },
        Err(error) => {
            log::warn!(
                "[INPUT_TELEMETRY] QPC frequency is unavailable: {error}. Input remains active, but latency collection is disabled"
            );
            0
        }
    };
    QPC_FREQUENCY.store(frequency, Ordering::Relaxed);

    let config = load_config(&config_path)?;
    apply_config(config, false, true);
    let hooks = input::install_native_bridge()?;
    match player_controls {
        Ok(controls) => match controls.reader() {
            Ok(reader) => {
                let complete_camera_entry = match camera::install_shared_update_entry(reader) {
                    Ok(shared_hook) => {
                        log::info!("[CAMERA] Complete UpdateCamera entry installed");
                        log::debug!(
                            "[CAMERA] Shared predecessor: update_entry=0x{:08X}",
                            shared_hook.update_entry,
                        );
                        true
                    }
                    Err(error) => {
                        log::warn!(
                            "[CAMERA] Complete UpdateCamera ownership is unavailable: {error:#}. Camera systems remain native; Atom Input remains active"
                        );
                        false
                    }
                };
                if complete_camera_entry {
                    if FIRST_PERSON_RENDER_HOOK_GATE.arm() {
                        log::info!(
                            "[CAMERA] First-person render hooks queued for post-Deferred installation"
                        );
                    }
                    match camera::third_person::install_native_system(reader) {
                        Ok(hooks) => {
                            if let Some(predecessor) = hooks.zoom_predecessor {
                                log::info!("[CAMERA] Fine third-person zoom installed");
                                log::debug!("[CAMERA] Fine zoom predecessor: 0x{predecessor:08X}");
                            }
                            if let Some(predecessor) = hooks.follow_predecessor {
                                log::info!("[CAMERA] Third-person follow hooks installed");
                                log::debug!(
                                    "[CAMERA] Third-person follow predecessor: 0x{predecessor:08X}"
                                );
                            }
                            if hooks.framing_admitted {
                                log::info!("[CAMERA] Third-person framing controls are available");
                            }
                            if hooks.motion_admitted {
                                log::info!("[CAMERA] Third-person render bob is available");
                            }
                            if let Some(predecessor) = hooks.motion_position_predecessor {
                                log::info!("[CAMERA] Third-person motion translation is available");
                                log::debug!(
                                    "[CAMERA] Motion position predecessor: 0x{predecessor:08X}"
                                );
                            }
                            if let (Some(heading), Some(pitch), Some(scope), Some(movement)) = (
                                hooks.camera_heading_predecessor,
                                hooks.camera_pitch_predecessor,
                                hooks.movement_scope_predecessor,
                                hooks.player_movement_predecessor,
                            ) {
                                log::info!("[CAMERA] Camera-relative movement hooks installed");
                                log::debug!(
                                    "[CAMERA] Movement predecessors: heading=0x{heading:08X}, pitch=0x{pitch:08X}, scope=0x{scope:08X}, wrapper=0x{movement:08X}"
                                );
                            }
                            if hooks.reticle_admitted {
                                log::info!(
                                    "[CAMERA] Third-person crosshair and object selection are aligned"
                                );
                                if let Some(reticle) = hooks.reticle_predecessor {
                                    log::debug!("[CAMERA] Reticle predecessor: 0x{reticle:08X}");
                                }
                            }
                            if hooks.aim_admitted {
                                log::info!(
                                    "[AIM] Native reticle and real-muzzle convergence are available"
                                );
                                if let (Some(reticle), Some(spawn)) =
                                    (hooks.reticle_predecessor, hooks.spawn_predecessor)
                                {
                                    log::debug!(
                                        "[AIM] Convergence predecessors: reticle=0x{reticle:08X}, spawn=0x{spawn:08X}"
                                    );
                                }
                            } else if hooks.reticle_admitted {
                                log::info!(
                                    "[AIM] Projectile convergence remains with its existing owner"
                                );
                            } else if hooks.camera_heading_predecessor.is_some() {
                                log::warn!(
                                    "[CAMERA] Another owner or an unrecognized caller controls the reticle; crosshair alignment remains native"
                                );
                            } else {
                                log::info!(
                                    "[AIM] Convergence remains native because camera-relative movement is unavailable"
                                );
                            }
                            if hooks.hip_fire_pose_admitted {
                                log::info!(
                                    "[AIM] Debounced third-person hip-fire pose is available"
                                );
                                if let Some(predecessor) = hooks.hip_fire_pose_predecessor {
                                    log::debug!(
                                        "[AIM] Hip-fire animation predecessor: 0x{predecessor:08X}"
                                    );
                                }
                            }
                        }
                        Err(error) => log::warn!(
                            "[CAMERA] Third-person follow and movement are unavailable: {error:#}. Other Atom systems remain active"
                        ),
                    }
                }
            }
            Err(error) => log::warn!(
                "[CAMERA] Combined player-control ownership is unavailable: {error}. Camera systems remain native"
            ),
        },
        Err(error) => log::warn!(
            "[CAMERA] xNVSE's player-controls interface was unavailable during plugin load: {error:#}. Camera systems remain native"
        ),
    }
    match ballistics::install_native_observer() {
        Ok(ballistics_hooks) => {
            log::info!("[BALLISTICS] Native physical-flight policy is active");
            log::debug!(
                "[BALLISTICS] Chained predecessors: count=0x{:08X}, launch=0x{:08X}, hit_build=0x{:08X}, hit_commit=0x{:08X}, collision=0x{:08X}, hitscan_policy=0x{:08X}, missile_update=0x{:08X}",
                ballistics_hooks.count_predecessor,
                ballistics_hooks.launch_predecessor,
                ballistics_hooks.hit_build_predecessor,
                ballistics_hooks.hit_commit_predecessor,
                ballistics_hooks.collision_predecessor,
                ballistics_hooks.hitscan_policy_predecessor,
                ballistics_hooks.missile_update_predecessor,
            );
        }
        Err(error) => log::warn!(
            "[BALLISTICS] Native physical-flight policy is unavailable: {error:#}. Ballistics remains native"
        ),
    }

    // MCM Extender is optional at native runtime. Failure to subscribe leaves
    // settings restart-applied while preserving the already validated input
    // bridge and the menu's normal persistence behavior.
    match event_manager {
        Ok(events) => {
            if let Err(error) = register_mcm_update_handler(events) {
                log::warn!(
                    "[CONFIG] Live MCM reload is unavailable: {error:#}. Settings will apply after restart"
                );
            } else {
                log::info!("[CONFIG] Live MCM reload registered for menu-close updates");
            }
        }
        Err(error) => log::warn!(
            "[CONFIG] xNVSE's event manager was unavailable during plugin load: {error:#}. Settings will apply after restart"
        ),
    }

    log::info!(
        "[INPUT] Direct camera, controller, action, and buffered keyboard bridges are active"
    );
    log::debug!(
        "[INPUT] Chained predecessors: sampler=0x{:08X}, mouse_x=0x{:08X}, mouse_y=0x{:08X}, heading_x=0x{:08X}, heading_y=0x{:08X}, controller_abs=0x{:08X}, keyboard_data=0x{:08X}, bound_action=0x{:08X}",
        hooks.sampler_predecessor,
        hooks.mouse_x_predecessor,
        hooks.mouse_y_predecessor,
        hooks.heading_x_predecessor,
        hooks.heading_y_predecessor,
        hooks.controller_abs_predecessor,
        hooks.keyboard_data_predecessor,
        hooks.bound_action_predecessor,
    );
    Ok(())
}

/// Install Atom's shared first-person render callsites after DeferredInit.
///
/// xNVSE's first `MainGameLoop` message follows completion of the synchronous
/// DeferredInit listener walk and precedes the frame's world renderer. That
/// ordering lets Atom capture any graphics wrappers installed later in the
/// DeferredInit list and hold its temporary camera pose around their complete
/// pre/native/post transaction.
pub(crate) fn activate_post_deferred_render_hooks() {
    if !FIRST_PERSON_RENDER_HOOK_GATE.is_armed() || STATE.load(Ordering::Acquire) != STATE_ACTIVE {
        return;
    }
    let Some(result) = FIRST_PERSON_RENDER_HOOK_GATE.activate(camera::install_first_person_system)
    else {
        return;
    };

    match result {
        Ok(first_person_hooks) => {
            log::info!(
                "[CAMERA] First-person render hooks installed after all DeferredInit listeners"
            );
            log::debug!(
                "[CAMERA] First-person routes: route_a=0x{:08X}, route_b=0x{:08X}, first_special=0x{:08X}, first_a=0x{:08X}, first_b=0x{:08X}",
                first_person_hooks.route_a,
                first_person_hooks.route_b,
                first_person_hooks.first_person_special,
                first_person_hooks.first_person_a,
                first_person_hooks.first_person_b,
            );
        }
        Err(error) => log::warn!(
            "[CAMERA] First-person render motion is unavailable: {error:#}. Third-person capabilities remain independently active"
        ),
    }
}

fn register_mcm_update_handler(events: &EventManager) -> Result<(), EventManagerError> {
    // MCMExtUpdate is script-dispatched with one array argument. Script
    // handlers create it implicitly, but xNVSE's native API rejects unknown
    // events. Define MCM's published contract first. Registration returning
    // false normally means another handler already defined the event, so only
    // native-handler admission is decisive here.
    let _ = events.register_event(
        MCM_UPDATE_EVENT,
        &MCM_UPDATE_PARAMETERS,
        EventFlags::ALLOW_SCRIPT_DISPATCH,
    );
    events.set_native_handler(MCM_UPDATE_EVENT, Some(mcm_update_handler))
}

fn initialize_logging() -> Result<(), RuntimeError> {
    Logger::new()
        .with_file_rotating(LOG_FILE)
        .with_level(log::LevelFilter::Debug)
        .with_module_level("libpsycho::os::windows::memory", log::LevelFilter::Warn)
        .init()?;
    Logger::start_deferred();
    Ok(())
}

unsafe extern "C" fn mcm_update_handler(
    _calling_ref: *mut TESObjectREFR,
    _parameters: *mut c_void,
) {
    let Some(path) = CONFIG_PATH.get() else {
        return;
    };
    match load_config(path) {
        Ok(config) => apply_config(config, true, false),
        Err(error) => log::warn!(
            "[CONFIG] MCM update was rejected; the previous safe configuration remains active: {error:#}"
        ),
    }
}

fn load_config(path: &Path) -> Result<AtomConfig, RuntimeError> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let config =
                AtomConfig::from_ini(&text).map_err(|source| RuntimeError::InvalidConfig {
                    path: path.to_owned(),
                    source,
                })?;
            log::debug!("[CONFIG] Read '{}' without writeback", path.display());
            Ok(config)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            log::info!(
                "[CONFIG] '{}' does not exist yet; safe defaults remain active until MCM saves it",
                path.display()
            );
            Ok(AtomConfig::default())
        }
        Err(source) => Err(RuntimeError::ReadConfig {
            path: path.to_owned(),
            source,
        }),
    }
}

fn apply_config(config: AtomConfig, process_summary_request: bool, report_unchanged: bool) {
    let input_config = config.input();
    let previous = input::current_config();
    if input_config.telemetry_enabled() && !previous.telemetry_enabled() {
        input::telemetry::reset();
        camera::reset_diagnostics();
    }
    input::telemetry::configure(
        input_config.telemetry_enabled(),
        i64::from(QPC_FREQUENCY.load(Ordering::Relaxed)),
    );
    camera::configure_diagnostics(input_config.telemetry_enabled());
    if input_config.telemetry_enabled()
        && QPC_FREQUENCY.load(Ordering::Relaxed) == 0
        && (input_config != previous || report_unchanged)
    {
        log::warn!(
            "[INPUT_TELEMETRY] Collection was requested but QPC setup is unavailable; no latency samples will be recorded"
        );
    }
    if input_config != previous {
        input::publish_config(input_config);
    }
    if input_config != previous || report_unchanged {
        log::info!(
            "[CONFIG] Atom Input settings active: enabled={}, mouse_profile={:?}, telemetry={}",
            input_config.enabled(),
            input_config.mouse().profile(),
            input_config.telemetry_enabled(),
        );
    }

    let camera_config = config.first_person();
    let previous_camera = camera::current_config();
    if camera_config != previous_camera {
        camera::publish_config(camera_config);
    }

    let third_person_config = config.third_person();
    let previous_third_person = camera::third_person::current_config();
    if third_person_config != previous_third_person {
        camera::third_person::publish_config(third_person_config);
    }
    if third_person_config != previous_third_person || report_unchanged {
        log::info!(
            "[CONFIG] Third-person settings active: follow={}, movement={}, drawn_360={}, framing={}, distance={:.0}-{:.0}, motion={}, zoom_step={:.1}",
            third_person_config.follow_enabled(),
            third_person_config.movement_enabled(),
            third_person_config.drawn_360(),
            third_person_config.framing_enabled(),
            third_person_config.minimum_distance(),
            third_person_config.maximum_distance(),
            third_person_config.motion_enabled(),
            third_person_config.zoom_step(),
        );
    }
    if camera_config != previous_camera || report_unchanged {
        log::info!(
            "[CONFIG] First-person settings active: enabled={}, camera_motion={:.2}, weapon_motion={:.2}, landing_motion={:.2}, aim_motion={:.2}",
            camera_config.enabled(),
            camera_config.camera_motion(),
            camera_config.weapon_motion(),
            camera_config.landing_motion(),
            camera_config.aim_motion(),
        );
    }

    let ballistics_config = config.ballistics();
    let previous_ballistics = ballistics::current_config();
    ballistics::publish_config(
        ballistics_config,
        i64::from(QPC_FREQUENCY.load(Ordering::Relaxed)),
    );
    if ballistics_config != previous_ballistics || report_unchanged {
        log::info!(
            "[CONFIG] Ballistics settings active: enabled={}, trace={}",
            ballistics_config.enabled(),
            ballistics_config.trace_enabled(),
        );
    }

    if process_summary_request {
        let was_requested = SUMMARY_LATCH.swap(input_config.summary_requested(), Ordering::AcqRel);
        if input_config.summary_requested() && !was_requested {
            log_telemetry_summary();
            camera::log_diagnostics_summary();
        }
        let ballistics_was_requested =
            BALLISTICS_SUMMARY_LATCH.swap(ballistics_config.summary_requested(), Ordering::AcqRel);
        if ballistics_config.summary_requested() && !ballistics_was_requested {
            ballistics::log_requested_summary();
        }
    }
}

fn log_telemetry_summary() {
    let snapshot = input::telemetry::snapshot();
    let keyboard = input::buffered_keyboard_diagnostics();
    let bounds = input::TelemetrySnapshot::bucket_upper_microseconds();
    log::info!("[INPUT_TELEMETRY] --------------------------------------------------------");
    log::info!("[INPUT_TELEMETRY] Requested latency summary");
    log::info!("[INPUT_TELEMETRY] Intervals begin after FNV and xNVSE finish the native sample");
    log_histogram(
        "Sample to first player-camera consumer",
        bounds,
        snapshot.sample_to_consumer(),
    );
    log_histogram(
        "Sample to xNVSE OnFramePresent",
        bounds,
        snapshot.sample_to_present(),
    );
    log::info!(
        "[INPUT_TELEMETRY] Invalid or discontinuous intervals: {}",
        snapshot.invalid_intervals()
    );
    log_mouse_heading("Horizontal heading", snapshot.mouse_x());
    log_mouse_heading("Vertical heading", snapshot.mouse_y());
    log::info!(
        "[INPUT_TELEMETRY] Buffered keyboard: overflows={}, lock contentions={}, native failures={}",
        keyboard.overflows(),
        keyboard.lock_contentions(),
        keyboard.native_failures(),
    );
    log::info!(
        "[INPUT_TELEMETRY] Presentation after OnFramePresent remains owned by FNV, DXVK, and the compositor"
    );
    log::info!("[INPUT_TELEMETRY] --------------------------------------------------------");
}

fn log_mouse_heading(label: &str, summary: input::MouseHeadingSummary) {
    let microradians_per_count = if summary.absolute_counts() == 0 {
        0.0
    } else {
        f64::from(summary.absolute_microradians()) / f64::from(summary.absolute_counts())
    };
    log::info!(
        "[INPUT_TELEMETRY] {label}: samples={}, counts={}, angle={} urad, mean={microradians_per_count:.3} urad/count",
        summary.samples(),
        summary.absolute_counts(),
        summary.absolute_microradians(),
    );
}

fn log_histogram(label: &str, bounds: &[u32; 11], counts: [u32; 12]) {
    log::info!("[INPUT_TELEMETRY] {label}");
    for (index, count) in counts.into_iter().enumerate() {
        if let Some(upper) = bounds.get(index) {
            log::info!("[INPUT_TELEMETRY]   <= {upper:>6} us : {count}");
        } else {
            log::info!(
                "[INPUT_TELEMETRY]   >  {:>6} us : {count}",
                bounds.last().copied().unwrap_or_default()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::{HOOK_GATE_ACTIVE, HOOK_GATE_ARMED, HOOK_GATE_UNAVAILABLE, PostDeferredHookGate};

    #[test]
    fn post_deferred_hook_gate_delays_installation_and_runs_it_once() {
        let gate = PostDeferredHookGate::new();
        let calls = Cell::new(0_u32);

        assert!(gate.arm());
        assert_eq!(gate.state(), HOOK_GATE_ARMED);
        assert_eq!(calls.get(), 0);

        let first = gate.activate(|| {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(0x1234_usize)
        });
        assert_eq!(first, Some(Ok(0x1234)));
        assert_eq!(calls.get(), 1);
        assert_eq!(gate.state(), HOOK_GATE_ACTIVE);

        assert_eq!(gate.activate(|| Ok::<_, ()>(0x5678_usize)), None);
        assert_eq!(calls.get(), 1);
        assert!(!gate.arm());
    }

    #[test]
    fn failed_post_deferred_installation_is_terminal() {
        let gate = PostDeferredHookGate::new();
        assert!(gate.arm());

        assert_eq!(
            gate.activate(|| Err::<(), _>("conflict")),
            Some(Err("conflict"))
        );
        assert_eq!(gate.state(), HOOK_GATE_UNAVAILABLE);
        assert_eq!(gate.activate(|| Ok::<_, &str>(())), None);
    }
}
