use std::{fs, time::SystemTime};

pub use log::LevelFilter;
use parking_lot::Once;

/// Global logger instance
/// Based on crate "fern"
pub struct GlobalLogger {}

static LOGGER_INITIALIZED: Once = Once::new();

impl GlobalLogger {
    pub fn init() {
        LOGGER_INITIALIZED.call_once(|| {
            match GlobalLogger::setup("logs/psycho.log", log::LevelFilter::Debug) {
                Ok(_) => {}

                Err(err) => {
                    let _ = fs::write(
                        "logs/orion_query_error.txt",
                        format!("Failed to initialize logger in F4SEPlugin_Load: {:?}", err),
                    );
                }
            }
        });
    }

    fn setup(log_path: &str, level_filter: LevelFilter) -> Result<(), fern::InitError> {
        // TODO: Get rid of (maybe) built-in to fern log rotation
        // Remove log file if already exist
        if fs::exists(log_path)? {
            fs::remove_file(log_path)?;
        }


        fern::Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "[{} {} {}] {}",
                    humantime::format_rfc3339_seconds(SystemTime::now()),
                    record.level(),
                    record.target(),
                    message
                ))
            })
            .level(level_filter)
            .chain(std::io::stdout())
            .chain(fern::log_file(log_path)?)
            .apply()?;
        Ok(())
    }
}
