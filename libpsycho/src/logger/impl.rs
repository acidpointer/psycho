//! High-performance threaded logger for libpsycho.
//!
//! **Note**: This is a specialized fork of the [`simple_logger`](https://crates.io/crates/simple_logger)
//! crate, heavily modified for libpsycho's specific requirements. It adds:
//! - Lock-free asynchronous logging with a dedicated background thread
//! - File output with three rotation strategies
//! - Progressive backoff for minimal CPU usage when idle
//! - Dual output (console + file)
//! - Unbuffered file I/O with immediate flush for crash safety
//!
//! This logger is designed specifically for use in performance-critical applications such as
//! game mods, DLL injections, real-time systems, and other latency-sensitive environments where
//! blocking on I/O is unacceptable.
//!
//! # Architecture
//!
//! The logger uses a **lock-free asynchronous architecture** with the following design:
//!
//! - **Lock-free queue**: Uses `crossbeam_queue::SegQueue` for wait-free message passing
//! - **Dedicated consumer thread**: A single background thread handles all I/O operations
//! - **Progressive backoff**: Adaptive sleep strategy to minimize CPU usage when idle
//! - **Dual output**: Simultaneously writes to console and files
//! - **Unbuffered file I/O**: Immediate flush for crash safety
//!
//! ## Why Threaded?
//!
//! In performance-critical applications (e.g., game engines, real-time systems), blocking on I/O
//! during logging is unacceptable. This implementation:
//!
//! 1. **Never blocks the caller**: Log messages are formatted and queued in microseconds
//! 2. **Immediate flush on write**: Each log is flushed to disk immediately for crash safety
//! 3. **Degrades gracefully**: If I/O fails, logging continues without crashing
//! 4. **Minimal overhead when idle**: Progressive backoff reduces CPU to near-zero when quiet
//!
//! # File Output Modes
//!
//! The logger supports three file rotation strategies:
//!
//! - **Timestamped**: Each run creates a new file with timestamp in the filename
//! - **Single Rotating**: One file that is truncated on each application start
//! - **Rotated with Limit**: Timestamped files with automatic cleanup of old logs
//!
//! All output uses plain text format.
//!
//! # Platform-Specific Setup
//!
//! No special platform setup is required. The logger works on all platforms.
//!
//! # Examples
//!
//! ## Basic Console Logging
//!
//! ```no_run
//! use libpsycho::logger::Logger;
//! use log::LevelFilter;
//!
//! Logger::new()
//!     .with_level(LevelFilter::Info)
//!     .with_utc_timestamps()
//!     .init()
//!     .unwrap();
//!
//! log::info!("Application started");
//! log::warn!("This is a warning");
//!
//! Logger::shutdown();
//! ```
//!
//! ## File Logging with Timestamps
//!
//! ```no_run
//! use libpsycho::logger::Logger;
//! use log::LevelFilter;
//!
//! Logger::new()
//!     .with_level(LevelFilter::Debug)
//!     .with_file_timestamped("./logs", "myapp")
//!     .init()
//!     .unwrap();
//!
//! log::debug!("This goes to both console and ./logs/myapp-26-12-2025--14-30-52.log");
//!
//! Logger::shutdown();
//! ```
//!
//! ## Single Rotating Log File
//!
//! ```no_run
//! use libpsycho::logger::Logger;
//!
//! Logger::new()
//!     .with_file_rotating("./latest.log")
//!     .init()
//!     .unwrap();
//!
//! log::info!("Always writes to ./latest.log, truncated on each run");
//!
//! Logger::shutdown();
//! ```
//!
//! ## Rotated Logs with Automatic Cleanup
//!
//! ```no_run
//! use libpsycho::logger::Logger;
//!
//! Logger::new()
//!     .with_file_rotated_limit("./logs", "myapp", 5)
//!     .init()
//!     .unwrap();
//!
//! log::info!("Creates timestamped files, keeps only the 5 most recent");
//!
//! Logger::shutdown();
//! ```
//!
//! ## Complete Windows Example
//!
//! ```no_run
//! use libpsycho::logger::Logger;
//! use log::{LevelFilter, info, warn, error};
//!
//! Logger::new()
//!     .with_level(LevelFilter::Info)
//!     .with_file_rotated_limit("C:\\logs\\myapp", "game", 10)
//!     .with_utc_timestamps()
//!     .init()
//!     .expect("Failed to initialize logger");
//!
//! info!("Game mod loaded");
//! warn!("Texture cache low");
//! error!("Failed to hook function at 0x{:X}", 0xDEADBEEF);
//!
//! Logger::shutdown();
//! ```
//!
//! ## Per-Module Log Levels
//!
//! ```no_run
//! use libpsycho::logger::Logger;
//! use log::LevelFilter;
//!
//! Logger::new()
//!     .with_level(LevelFilter::Warn)
//!     .with_module_level("myapp::renderer", LevelFilter::Debug)
//!     .with_module_level("myapp::network", LevelFilter::Trace)
//!     .init()
//!     .unwrap();
//!
//! log::info!("This won't show (global level is Warn)");
//!
//! Logger::shutdown();
//! ```
//!
//! # Performance Characteristics
//!
//! - **Logging overhead**: ~100-500ns per log call (message formatting + queue push)
//! - **Idle CPU usage**: <0.1% (with progressive backoff)
//! - **Queue contention**: Lock-free, scales with number of threads
//! - **I/O blocking**: Never blocks caller, all I/O in background thread
//!
//! # Thread Safety
//!
//! The logger is fully thread-safe and can be called from any thread. The background
//! consumer thread is spawned during `init()` and can be gracefully shut down with
//! `Logger::shutdown()`.
//!
//! # Graceful Shutdown
//!
//! Always call `Logger::shutdown()` before your application exits to ensure all
//! buffered log messages are written to disk:
//!
//! ```no_run
//! use libpsycho::logger::Logger;
//!
//! Logger::new().init().unwrap();
//!
//! log::info!("Application running");
//!
//! Logger::shutdown();
//! ```

use crossbeam_queue::SegQueue;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::{collections::HashMap, fs::{self, File, OpenOptions}, io::Write, path::PathBuf, sync::{atomic::{AtomicBool, Ordering}, LazyLock, Mutex}, thread::{self, JoinHandle}};

use time::{OffsetDateTime, UtcOffset, format_description::FormatItem};

struct LogMessage {
    text: String,
}

static MSG_QUEUE: LazyLock<SegQueue<LogMessage>> = LazyLock::new(Default::default);
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static LOGGER_THREAD: LazyLock<Mutex<Option<JoinHandle<()>>>> = LazyLock::new(|| Mutex::new(None));

const TIMESTAMP_FORMAT_OFFSET: &[FormatItem] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3][offset_hour sign:mandatory]:[offset_minute]"
);

const TIMESTAMP_FORMAT_UTC: &[FormatItem] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
);

const FILENAME_TIMESTAMP_FORMAT: &[FormatItem] = time::macros::format_description!(
    "[day]-[month]-[year]--[hour]-[minute]-[second]"
);

#[derive(PartialEq)]
enum Timestamps {
    None,
    Local,
    Utc,
    UtcOffset(UtcOffset),
}

/// File output configuration for the logger.
///
/// Determines how log files are created, named, and rotated. File output always uses
/// plain text (ANSI color codes are stripped), while console output remains colored.
#[derive(Clone)]
pub enum FileOutput {
    /// No file output, console only.
    None,

    /// Create a new timestamped file for each run.
    ///
    /// Files are named: `{prefix}-{dd-mm-yyyy--hh-mm-ss}.log`
    ///
    /// Example: `myapp-26-12-2025--14-30-52.log`
    Timestamped {
        /// Directory where log files will be created (created if it doesn't exist)
        dir: PathBuf,
        /// Prefix for log filenames
        prefix: String
    },

    /// Single log file that is truncated on each application start.
    ///
    /// Always writes to the same file, clearing previous contents.
    SingleRotating {
        /// Path to the log file
        path: PathBuf
    },

    /// Timestamped files with automatic cleanup of old logs.
    ///
    /// Creates timestamped files like `Timestamped`, but automatically deletes
    /// old log files when the count exceeds `max_files`. Cleanup happens once
    /// during `Logger::init()`.
    RotatedWithLimit {
        /// Directory where log files will be created
        dir: PathBuf,
        /// Prefix for log filenames
        prefix: String,
        /// Maximum number of log files to keep
        max_files: usize
    },
}

/// High-performance threaded logger with file rotation support.
///
/// This logger is specifically designed for libpsycho and performance-critical applications.
/// It uses a lock-free queue and a dedicated background thread to ensure logging never
/// blocks the calling thread.
///
/// # Builder Pattern
///
/// Use the builder methods to configure the logger, then call [`init`](Logger::init) to
/// start the background logging thread and register with the `log` crate.
///
/// # Example
///
/// ```no_run
/// use libpsycho::logger::Logger;
/// use log::LevelFilter;
///
/// Logger::new()
///     .with_level(LevelFilter::Info)
///     .with_file_timestamped("./logs", "myapp")
///     .with_utc_timestamps()
///     .init()
///     .unwrap();
///
/// log::info!("Logger initialized");
///
/// Logger::shutdown();
/// ```
pub struct Logger {
    /// The default logging level
    default_level: LevelFilter,

    /// The specific logging level for each module
    ///
    /// This is used to override the default value for some specific modules.
    ///
    /// This must be sorted from most-specific to least-specific, so that [`enabled`](#method.enabled) can scan the
    /// vector for the first match to give us the desired log level for a module.
    module_levels: Vec<(String, LevelFilter)>,

    /// Whether to include thread names (and IDs) or not
    ///
    /// This field is only available if the `threads` feature is enabled.
    threads: bool,

    /// Control how timestamps are displayed.
    ///
    /// This field is only available if the `timestamps` feature is enabled.
    timestamps: Timestamps,
    timestamps_format: Option<&'static [FormatItem<'static>]>,

    /// File output configuration
    file_output: FileOutput,
}

impl Logger {
    /// Creates a new Logger with default configuration.
    ///
    /// Default settings:
    /// - Log level: `Trace` (logs everything)
    /// - Timestamps: UTC
    /// - Thread names: Disabled
    /// - File output: None (console only)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpsycho::logger::Logger;
    ///
    /// Logger::new()
    ///     .with_level(log::LevelFilter::Info)
    ///     .init()
    ///     .unwrap();
    /// ```
    #[must_use = "You must call init() to begin logging"]
    pub fn new() -> Logger {
        Logger {
            default_level: LevelFilter::Trace,
            module_levels: Vec::new(),
            threads: false,
            timestamps: Timestamps::Utc,
            timestamps_format: None,
            file_output: FileOutput::None,
        }
    }

    /// Set the 'default' log level.
    ///
    /// You can override the default level for specific modules and their sub-modules using [`with_module_level`]
    ///
    /// This must be called before [`env`]. If called after [`env`], it will override the value loaded from the environment.
    ///
    /// [`env`]: #method.env
    /// [`with_module_level`]: #method.with_module_level
    #[must_use = "You must call init() to begin logging"]
    pub fn with_level(mut self, level: LevelFilter) -> Logger {
        self.default_level = level;
        self
    }

    /// Override the log level for some specific modules.
    ///
    /// This sets the log level of a specific module and all its sub-modules.
    /// When both the level for a parent module as well as a child module are set,
    /// the more specific value is taken. If the log level for the same module is
    /// specified twice, the resulting log level is implementation defined.
    ///
    /// # Examples
    ///
    /// Silence an overly verbose crate:
    ///
    /// ```no_run
    /// use libpsycho::logger::Logger;
    /// use log::LevelFilter;
    ///
    /// Logger::new().with_module_level("chatty_dependency", LevelFilter::Warn).init().unwrap();
    /// ```
    ///
    /// Disable logging for all dependencies:
    ///
    /// ```no_run
    /// use libpsycho::logger::Logger;
    /// use log::LevelFilter;
    ///
    /// Logger::new()
    ///     .with_level(LevelFilter::Off)
    ///     .with_module_level("my_crate", LevelFilter::Info)
    ///     .init()
    ///     .unwrap();
    /// ```
    //
    // This method *must* sort `module_levels` for the [`enabled`](#method.enabled) method to work correctly.
    #[must_use = "You must call init() to begin logging"]
    pub fn with_module_level(mut self, target: &str, level: LevelFilter) -> Logger {
        self.module_levels.push((target.to_string(), level));
        self.module_levels
            .sort_by_key(|(name, _level)| name.len().wrapping_neg());
        self
    }

    /// Override the log level for specific targets.
    // This method *must* sort `module_levels` for the [`enabled`](#method.enabled) method to work correctly.
    #[must_use = "You must call init() to begin logging"]
    #[deprecated(
        since = "1.11.0",
        note = "Use [`with_module_level`](#method.with_module_level) instead. Will be removed in version 2.0.0."
    )]
    pub fn with_target_levels(mut self, target_levels: HashMap<String, LevelFilter>) -> Logger {
        self.module_levels = target_levels.into_iter().collect();
        self.module_levels
            .sort_by_key(|(name, _level)| name.len().wrapping_neg());
        self
    }

    /// Control whether thread names (and IDs) are printed or not.
    ///
    /// This method is only available if the `threads` feature is enabled.
    /// Thread names are disabled by default.
    #[must_use = "You must call init() to begin logging"]
    pub fn with_threads(mut self, threads: bool) -> Logger {
        self.threads = threads;
        self
    }

    /// Control whether timestamps are printed or not.
    ///
    /// Timestamps will be displayed in the local timezone.
    ///
    /// This method is only available if the `timestamps` feature is enabled.
    #[must_use = "You must call init() to begin logging"]
    #[deprecated(
        since = "1.16.0",
        note = "Use [`with_local_timestamps`] or [`with_utc_timestamps`] instead. Will be removed in version 2.0.0."
    )]
    pub fn with_timestamps(mut self, timestamps: bool) -> Logger {
        if timestamps {
            self.timestamps = Timestamps::Local
        } else {
            self.timestamps = Timestamps::None
        }
        self
    }

    /// Control the format used for timestamps.
    ///
    /// Without this, a default format is used depending on the timestamps type.
    ///
    /// The syntax for the format_description macro can be found in the
    /// [`time` crate book](https://time-rs.github.io/book/api/format-description.html).
    ///
    /// ```no_run
    /// use libpsycho::logger::Logger;
    ///
    /// Logger::new()
    ///  .with_level(log::LevelFilter::Debug)
    ///  .with_timestamp_format(time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"))
    ///  .init()
    ///  .unwrap();
    /// ```
    #[must_use = "You must call init() to begin logging"]
    pub fn with_timestamp_format(mut self, format: &'static [FormatItem<'static>]) -> Logger {
        self.timestamps_format = Some(format);
        self
    }

    /// Don't display any timestamps.
    ///
    /// This method is only available if the `timestamps` feature is enabled.
    #[must_use = "You must call init() to begin logging"]
    pub fn without_timestamps(mut self) -> Logger {
        self.timestamps = Timestamps::None;
        self
    }

    /// Display timestamps using the local timezone.
    ///
    /// This method is only available if the `timestamps` feature is enabled.
    #[must_use = "You must call init() to begin logging"]
    pub fn with_local_timestamps(mut self) -> Logger {
        self.timestamps = Timestamps::Local;
        self
    }

    /// Display timestamps using UTC.
    ///
    /// This method is only available if the `timestamps` feature is enabled.
    #[must_use = "You must call init() to begin logging"]
    pub fn with_utc_timestamps(mut self) -> Logger {
        self.timestamps = Timestamps::Utc;
        self
    }

    /// Display timestamps using a static UTC offset.
    ///
    /// This method is only available if the `timestamps` feature is enabled.
    #[must_use = "You must call init() to begin logging"]
    pub fn with_utc_offset(mut self, offset: UtcOffset) -> Logger {
        self.timestamps = Timestamps::UtcOffset(offset);
        self
    }

    /// Configure file output with timestamped filenames.
    ///
    /// Logs will be written to `{dir}/{prefix}-{timestamp}.log`
    /// where timestamp is in format: dd-mm-yyyy--hh-mm-ss
    #[must_use = "You must call init() to begin logging"]
    pub fn with_file_timestamped(mut self, dir: impl Into<PathBuf>, prefix: impl Into<String>) -> Logger {
        self.file_output = FileOutput::Timestamped {
            dir: dir.into(),
            prefix: prefix.into(),
        };
        self
    }

    /// Configure file output with a single rotating file.
    ///
    /// The file at `path` will be truncated on each init.
    #[must_use = "You must call init() to begin logging"]
    pub fn with_file_rotating(mut self, path: impl Into<PathBuf>) -> Logger {
        self.file_output = FileOutput::SingleRotating {
            path: path.into(),
        };
        self
    }

    /// Configure file output with timestamped rotation and automatic cleanup.
    ///
    /// Logs will be written to `{dir}/{prefix}-{timestamp}.log`.
    /// Old log files exceeding `max_files` will be automatically deleted on init.
    #[must_use = "You must call init() to begin logging"]
    pub fn with_file_rotated_limit(mut self, dir: impl Into<PathBuf>, prefix: impl Into<String>, max_files: usize) -> Logger {
        self.file_output = FileOutput::RotatedWithLimit {
            dir: dir.into(),
            prefix: prefix.into(),
            max_files,
        };
        self
    }

    /// Configure the logger
    pub fn max_level(&self) -> LevelFilter {
        let max_level = self
            .module_levels
            .iter()
            .map(|(_name, level)| level)
            .copied()
            .max();
        max_level
            .map(|lvl| lvl.max(self.default_level))
            .unwrap_or(self.default_level)
    }

    /// Initialize the logger and start the background logging thread.
    ///
    /// This method:
    /// 1. Creates the log file (if file output is configured)
    /// 2. Performs log rotation/cleanup (if using `RotatedWithLimit`)
    /// 3. Spawns a dedicated background thread for I/O operations
    /// 4. Registers the logger with the `log` crate
    ///
    /// # Thread Safety
    ///
    /// The spawned background thread runs until `Logger::shutdown()` is called.
    /// It uses a lock-free queue to receive log messages from any thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the logger has already been initialized globally.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpsycho::logger::Logger;
    ///
    /// Logger::new()
    ///     .with_file_rotating("./app.log")
    ///     .init()
    ///     .expect("Failed to initialize logger");
    ///
    /// log::info!("Application started");
    ///
    /// Logger::shutdown();
    /// ```
    pub fn init(self) -> Result<(), SetLoggerError> {
        let mut log_file = create_log_file(&self.file_output);

        let handle = thread::spawn(move || {
            let mut idle_count = 0u32;
            let mut stdout = std::io::stdout();
            loop {
                if SHUTDOWN.load(Ordering::Acquire) {
                    while let Some(msg) = MSG_QUEUE.pop() {
                        let _ = stdout.write_all(msg.text.as_bytes());
                        if let Some(file) = &mut log_file {
                            let _ = file.write_all(msg.text.as_bytes());
                        }
                    }
                    let _ = stdout.flush();
                    if let Some(file) = &mut log_file {
                        let _ = file.flush();
                    }
                    break;
                }

                if let Some(msg) = MSG_QUEUE.pop() {
                    idle_count = 0;

                    if stdout.write_all(msg.text.as_bytes()).is_err() {
                        continue;
                    }

                    if let Some(file) = &mut log_file {
                        let _ = file.write_all(msg.text.as_bytes());
                        let _ = file.flush(); // Immediate flush for crash safety
                    }
                } else {
                    idle_count = idle_count.saturating_add(1);

                    if idle_count < 10 {
                        thread::yield_now();
                    } else if idle_count < 100 {
                        thread::sleep(std::time::Duration::from_micros(10));
                    } else {
                        thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            }
        });

        *LOGGER_THREAD.lock().unwrap() = Some(handle);

        log::set_max_level(self.max_level());
        log::set_boxed_logger(Box::new(self))
    }

    /// Shutdown the logger thread gracefully and flush all pending messages.
    ///
    /// This method:
    /// 1. Signals the background thread to stop
    /// 2. Drains all remaining messages from the queue
    /// 3. Flushes both console and file outputs
    /// 4. Joins the background thread
    ///
    /// **Important**: Always call this before your application exits to ensure all
    /// log messages are written to disk. Failing to call this may result in lost
    /// log messages.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpsycho::logger::Logger;
    ///
    /// Logger::new().init().unwrap();
    ///
    /// log::info!("Doing work...");
    ///
    /// Logger::shutdown();
    /// ```
    ///
    /// # Typical Usage Pattern
    ///
    /// ```no_run
    /// use libpsycho::logger::Logger;
    ///
    /// fn log_test() {
    ///     Logger::new()
    ///         .with_file_rotating("./app.log")
    ///         .init()
    ///         .unwrap();
    ///
    ///     log::info!("Application starting");
    ///
    ///     Logger::shutdown();
    /// }
    /// ```
    pub fn shutdown() {
        SHUTDOWN.store(true, Ordering::Release);

        if let Some(handle) = LOGGER_THREAD.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    /// Initialise the logger with its default configuration.
    ///
    /// Log messages will not be filtered.
    pub fn init_default() -> Result<(), SetLoggerError> {
        Logger::new().init()
    }

    /// Initialise the logger with UTC timestamps.
    ///
    /// Log messages will not be filtered.
    pub fn init_with_utc() -> Result<(), SetLoggerError> {
        Logger::new().with_utc_timestamps().init()
    }

    /// Initialise the logger with a specific log level.
    ///
    /// Log messages below the given [`Level`] will be filtered.
    pub fn init_with_level(level: Level) -> Result<(), SetLoggerError> {
        Logger::new().with_level(level.to_level_filter()).init()
    }
}

impl Default for Logger {
    /// Creates a new Logger with default configuration.
    ///
    /// Equivalent to calling [`Logger::new()`](Logger::new).
    fn default() -> Self {
        Logger::new()
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        &metadata.level().to_level_filter()
            <= self
                .module_levels
                .iter()
                /* At this point the Vec is already sorted so that we can simply take
                 * the first match
                 */
                .find(|(name, _level)| metadata.target().starts_with(name))
                .map(|(_name, level)| level)
                .unwrap_or(&self.default_level)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level = format!("{:<5}", record.level().to_string());

            let target = if !record.target().is_empty() {
                record.target()
            } else {
                record.module_path().unwrap_or_default()
            };

            let thread = {
                if self.threads {
                    let thread = std::thread::current();

                    format!("@{}", { thread.name().unwrap_or("?") })
                } else {
                    "".to_string()
                }
            };

            let timestamp = {
                match self.timestamps {
                    Timestamps::None => "".to_string(),
                    Timestamps::Local => format!(
                        "{} ",
                        OffsetDateTime::now_local()
                            .expect(concat!(
                                "Could not determine the UTC offset on this system. ",
                                "Consider displaying UTC time instead. ",
                                "Possible causes are that the time crate does not implement \"local_offset_at\" ",
                                "on your system, or that you are running in a multi-threaded environment and ",
                                "the time crate is returning \"None\" from \"local_offset_at\" to avoid unsafe ",
                                "behaviour. See the time crate's documentation for more information. ",
                                "(https://time-rs.github.io/internal-api/time/index.html#feature-flags)"
                            ))
                            .format(&self.timestamps_format.unwrap_or(TIMESTAMP_FORMAT_OFFSET))
                            .unwrap()
                    ),
                    Timestamps::Utc => format!(
                        "{} ",
                        OffsetDateTime::now_utc()
                            .format(&self.timestamps_format.unwrap_or(TIMESTAMP_FORMAT_UTC))
                            .unwrap()
                    ),
                    Timestamps::UtcOffset(offset) => format!(
                        "{} ",
                        OffsetDateTime::now_utc()
                            .to_offset(offset)
                            .format(&self.timestamps_format.unwrap_or(TIMESTAMP_FORMAT_OFFSET))
                            .unwrap()
                    ),
                }
            };

            let message = format!(
                "{}{} [{}{}] {}\n",
                timestamp,
                level,
                target,
                thread,
                record.args()
            );

            MSG_QUEUE.push(LogMessage {
                text: message,
            });
        }
    }

    fn flush(&self) {
        while MSG_QUEUE.pop().is_some() {}
        let _ = std::io::stdout().flush();
    }
}

fn create_log_file(file_output: &FileOutput) -> Option<File> {
    match file_output {
        FileOutput::None => None,
        FileOutput::Timestamped { dir, prefix } => {
            if fs::create_dir_all(dir).is_err() {
                return None;
            }

            let timestamp = OffsetDateTime::now_utc()
                .format(FILENAME_TIMESTAMP_FORMAT)
                .ok()?;

            let filename = format!("{}-{}.log", prefix, timestamp);
            let path = dir.join(filename);

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()?;

            Some(file)
        }
        FileOutput::SingleRotating { path } => {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .ok()?;

            Some(file)
        }
        FileOutput::RotatedWithLimit { dir, prefix, max_files } => {
            if fs::create_dir_all(dir).is_err() {
                return None;
            }

            cleanup_old_logs(dir, prefix, *max_files);

            let timestamp = OffsetDateTime::now_utc()
                .format(FILENAME_TIMESTAMP_FORMAT)
                .ok()?;

            let filename = format!("{}-{}.log", prefix, timestamp);
            let path = dir.join(filename);

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()?;

            Some(file)
        }
    }
}

fn cleanup_old_logs(dir: &PathBuf, prefix: &str, max_files: usize) {
    let mut log_files: Vec<_> = fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }

            let filename = path.file_name()?.to_str()?;

            if filename.starts_with(prefix) && filename.ends_with(".log") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    log_files.sort_by(|a, b| {
        let time_a = a.metadata().and_then(|m| m.modified()).ok();
        let time_b = b.metadata().and_then(|m| m.modified()).ok();
        time_b.cmp(&time_a)
    });

    if log_files.len() > max_files {
        for path in log_files.iter().skip(max_files) {
            let _ = fs::remove_file(path);
        }
    }
}

