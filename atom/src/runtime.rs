//! Deferred runtime ownership for Atom.
//!
//! `NVSEPlugin_Load` captures the runtime directory and event-manager wrapper
//! while xNVSE permits service acquisition. Path construction, Serde/INI
//! parsing, QPC setup, event subscription, and native hook installation first
//! occur at `DeferredInit`. MCM Extender remains the only writer of `Atom.ini`;
//! its close event causes a main-thread reload and atomic publication.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use libnvse::TESObjectREFR;
use libnvse::api::event_manager::{EventFlags, EventManager, EventManagerError, EventParamType};
use libnvse::api::interface::NVSEInterfaceError;
use libpsycho::logger::Logger;
use libpsycho::os::windows::winapi::query_performance_frequency;
use thiserror::Error;

use crate::input::{self, ConfigError, InputConfig, InputInstallError};

const STATE_COLD: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_ACTIVE: u8 = 2;
const STATE_UNAVAILABLE: u8 = 3;

static STATE: AtomicU8 = AtomicU8::new(STATE_COLD);
static QPC_FREQUENCY: AtomicU32 = AtomicU32::new(0);
static SUMMARY_LATCH: AtomicBool = AtomicBool::new(false);
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
const LOG_FILE: &str = "./atom-latest.log";
const MCM_UPDATE_EVENT: &str = "MCMExtUpdate";
static MCM_UPDATE_PARAMETERS: [EventParamType; 1] = [EventParamType::Array];

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
        source: ConfigError,
    },
    #[error(transparent)]
    Input(#[from] InputInstallError),
}

/// Initialize Atom exactly once at xNVSE `DeferredInit`.
pub(crate) fn initialize(
    runtime_directory: &Path,
    event_manager: Result<&EventManager, &NVSEInterfaceError>,
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

    match initialize_inner(runtime_directory, event_manager) {
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

fn load_config(path: &Path) -> Result<InputConfig, RuntimeError> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let config =
                InputConfig::from_ini(&text).map_err(|source| RuntimeError::InvalidConfig {
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
            Ok(InputConfig::default())
        }
        Err(source) => Err(RuntimeError::ReadConfig {
            path: path.to_owned(),
            source,
        }),
    }
}

fn apply_config(config: InputConfig, process_summary_request: bool, report_unchanged: bool) {
    let previous = input::current_config();
    if config.telemetry_enabled() && !previous.telemetry_enabled() {
        input::telemetry::reset();
    }
    input::telemetry::configure(
        config.telemetry_enabled(),
        i64::from(QPC_FREQUENCY.load(Ordering::Relaxed)),
    );
    if config.telemetry_enabled()
        && QPC_FREQUENCY.load(Ordering::Relaxed) == 0
        && (config != previous || report_unchanged)
    {
        log::warn!(
            "[INPUT_TELEMETRY] Collection was requested but QPC setup is unavailable; no latency samples will be recorded"
        );
    }
    if config != previous {
        input::publish_config(config);
    }
    if config != previous || report_unchanged {
        log::info!(
            "[CONFIG] Atom Input settings active: enabled={}, mouse_profile={:?}, telemetry={}",
            config.enabled(),
            config.mouse().profile(),
            config.telemetry_enabled(),
        );
    }

    if process_summary_request {
        let was_requested = SUMMARY_LATCH.swap(config.summary_requested(), Ordering::AcqRel);
        if config.summary_requested() && !was_requested {
            log_telemetry_summary();
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
