//! TOML Configuration Loader
//!
//! Generic configuration module for loading, saving, and managing TOML-based
//! configuration files. Provides automatic default generation when config
//! files are missing, with serde-based deserialization/serialization.
//!
//! # Usage
//!
//! ```no_run
//! use serde::{Deserialize, Serialize};
//! use libpsycho::config::Config;
//!
//! #[derive(Debug, Deserialize, Serialize)]
//! struct MyConfig {
//!     enabled: bool,
//!     sleep_ms: u32,
//! }
//!
//! impl Default for MyConfig {
//!     fn default() -> Self {
//!         Self { enabled: true, sleep_ms: 5 }
//!     }
//! }
//!
//! let config = Config::load_or_default::<MyConfig>("./my_plugin.toml")
//!     .expect("config load failed");
//! ```

use std::path::Path;

use serde::{Serialize, de::DeserializeOwned};

use super::errors::{ConfigError, ConfigResult};

/// TOML configuration loader with automatic default generation.
pub struct Config;

impl Config {
    /// Load a configuration file from disk, deserializing into `T`.
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load<T: DeserializeOwned>(path: impl AsRef<Path>) -> ConfigResult<T> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
            path: path.display().to_string(),
            source: e,
        })?;

        let config: T = toml::from_str(&content)?;

        log::info!("Config loaded from '{}'", path.display());

        Ok(config)
    }

    /// Save a configuration to disk as TOML.
    pub fn save<T: Serialize>(path: impl AsRef<Path>, config: &T) -> ConfigResult<()> {
        let path = path.as_ref();
        let content = toml::to_string_pretty(config)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ConfigError::WriteFile {
                path: parent.display().to_string(),
                source: e,
            })?;
        }

        std::fs::write(path, content).map_err(|e| ConfigError::WriteFile {
            path: path.display().to_string(),
            source: e,
        })?;

        log::info!("Config saved to '{}'", path.display());

        Ok(())
    }

    /// Load config from disk, or create a default config file if it doesn't exist.
    ///
    /// If the file is missing, `T::default()` is serialized to disk and returned.
    /// If the file exists but fails to parse, the error is returned (not swallowed).
    pub fn load_or_default<T>(path: impl AsRef<Path>) -> ConfigResult<T>
    where
        T: DeserializeOwned + Serialize + Default,
    {
        let path = path.as_ref();

        if path.exists() {
            Self::load(path)
        } else {
            let config = T::default();
            Self::save(path, &config)?;

            log::info!(
                "Config not found at '{}', created default",
                path.display()
            );

            Ok(config)
        }
    }
}
