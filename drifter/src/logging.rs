use std::path::Path;

pub fn setup_logging() -> Result<(), fern::InitError> {
    let log_dir = "logs";
    if !Path::new(log_dir).exists() {
        std::fs::create_dir_all(log_dir).expect("Failed to create logs directory");
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file = format!("{}/drifter_{}.log", log_dir, timestamp);

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}:{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                message
            ))
        })
        .level(log::LevelFilter::Trace)
        .chain(std::io::stdout())
        .chain(fern::log_file(&log_file)?)
        .apply()?;

    log::info!("Logging initialized, writing to: {}", log_file);

    cleanup_old_logs(log_dir, 10);

    Ok(())
}

fn cleanup_old_logs(log_dir: &str, keep_count: usize) {
    log::debug!(
        "Cleaning up old log files, keeping {} most recent",
        keep_count
    );

    let mut log_files: Vec<_> = match std::fs::read_dir(log_dir) {
        Ok(entries) => entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()? == "log" {
                    let metadata = entry.metadata().ok()?;
                    let modified = metadata.modified().ok()?;
                    Some((path, modified))
                } else {
                    None
                }
            })
            .collect(),
        Err(e) => {
            log::warn!("Failed to read log directory: {}", e);
            return;
        }
    };

    if log_files.len() <= keep_count {
        log::debug!(
            "Only {} log files found, no cleanup needed",
            log_files.len()
        );
        return;
    }

    log_files.sort_by(|a, b| b.1.cmp(&a.1));

    for (path, _) in log_files.into_iter().skip(keep_count) {
        match std::fs::remove_file(&path) {
            Ok(()) => log::debug!("Removed old log file: {:?}", path),
            Err(e) => log::warn!("Failed to remove old log file {:?}: {}", path, e),
        }
    }
}
