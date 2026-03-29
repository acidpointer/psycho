//! TOML Configuration Loader
//!
//! Generic configuration module for loading, saving, and managing TOML-based
//! configuration files. Provides automatic default generation, and schema
//! migration (adds missing fields, removes stale ones).
//!
//! # Usage
//!
//! ```no_run
//! use serde::{Deserialize, Serialize};
//! use libpsycho::config::Config;
//!
//! #[derive(Debug, Default, Deserialize, Serialize)]
//! #[serde(default)]
//! struct MyConfig {
//!     enabled: bool,
//!     sleep_ms: u32,
//! }
//!
//! // Simple load (no migration):
//! let cfg = Config::load_or_default::<MyConfig>("./my_plugin.toml").unwrap();
//!
//! // Load with automatic schema migration:
//! let cfg = Config::load_or_migrate::<MyConfig>("./my_plugin.toml");
//! ```

use std::path::Path;

use serde::{Serialize, de::DeserializeOwned};

use super::errors::{ConfigError, ConfigResult};

/// TOML configuration loader with automatic default generation and migration.
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

    /// Load config from disk (read-only, no write-back).
    ///
    /// Safe to call under the Windows loader lock — only does a single file
    /// read and TOML parse. If the file is missing or unparseable, returns
    /// `T::default()`.
    ///
    /// Call [`sync_to_disk`] later (outside DllMain) to write back schema
    /// changes.
    pub fn load_readonly<T>(path: impl AsRef<Path>) -> T
    where
        T: DeserializeOwned + Default,
    {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).unwrap_or_default();

        match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(err) => {
                if !content.is_empty() {
                    log::warn!(
                        "Config parse error in '{}': {}. Using defaults.",
                        path.display(),
                        err
                    );
                }
                T::default()
            }
        }
    }

    /// Write config to disk if the schema has changed.
    ///
    /// Must be called OUTSIDE DllMain (no loader lock).
    /// Typically called from NVSEPlugin_Load after the loader lock is released.
    pub fn sync_to_disk<T>(path: impl AsRef<Path>, cfg: &T)
    where
        T: Serialize,
    {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).unwrap_or_default();

        if let Ok(updated) = toml::to_string_pretty(cfg)
            && updated != content {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(err) = std::fs::write(path, &updated) {
                    log::warn!("Failed to sync config '{}': {}", path.display(), err);
                } else if content.is_empty() {
                    log::info!("Config created at '{}'", path.display());
                } else {
                    log::info!("Config schema updated in '{}'", path.display());
                }
            }
    }

    /// Load config with automatic schema migration.
    ///
    /// - If the file doesn't exist → creates it with defaults.
    /// - If the file has missing fields → fills them with defaults.
    /// - If the file has removed fields → prunes them.
    /// - Re-writes the file only when the schema changed.
    /// - On parse error → logs warning, returns defaults, overwrites file.
    ///
    /// Requires `T` to derive `Default` and use `#[serde(default)]` on all
    /// structs so that missing fields deserialize to their defaults.
    pub fn load_or_migrate<T>(path: impl AsRef<Path>) -> T
    where
        T: DeserializeOwned + Serialize + Default,
    {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).unwrap_or_default();

        let cfg: T = match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(err) => {
                if !content.is_empty() {
                    log::warn!(
                        "Config parse error in '{}': {}. Using defaults.",
                        path.display(),
                        err
                    );
                }
                T::default()
            }
        };

        // Re-serialize and write back if schema changed
        if let Ok(updated) = toml::to_string_pretty(&cfg)
            && updated != content {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(err) = std::fs::write(path, &updated) {
                    log::warn!("Failed to sync config '{}': {}", path.display(), err);
                } else if content.is_empty() {
                    log::info!("Config created at '{}'", path.display());
                } else {
                    log::info!("Config schema updated in '{}'", path.display());
                }
            }

        cfg
    }
}
