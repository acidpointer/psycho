//! Early repair of Bethesda's Fallout installation-path registry values.
//!
//! FalloutNV 1.4.0.525 reads `Installed Path` from the 32-bit
//! `HKLM\Software\Bethesda Softworks\FalloutNV` key before falling back to
//! `FalloutNVLauncher.exe`. Fallout 3 1.7.0.3 uses the equivalent `Fallout3`
//! key before launching `FalloutLauncher.exe`. Both vanilla readers use fixed
//! 260-byte ANSI buffers, while the stock launchers read the same values with
//! 260-wide-character buffers.
//!
//! New Vegas is authoritative for its own location: the value always comes
//! from the directory containing the running `FalloutNV.exe`. Fallout 3 is
//! optional and config-owned. Its path may be fully qualified or relative to
//! that New Vegas directory; resolving it never probes the filesystem. Repair
//! runs once in Syringe's pre-CRT activation interval and failures are logged
//! per game without aborting unrelated engine initialization.

use std::path::{Component, Path, PathBuf, Prefix};

use anyhow::{Context, Result, bail};
use libpsycho::os::windows::{
    registry::{RegistryKey, RegistryStringValue, ansi_byte_len_with_nul},
    winapi::get_module_file_name_w,
};

use crate::config::EngineFixesConfig;

const FALLOUT_NV_KEY: &str = r"Software\Bethesda Softworks\FalloutNV";
const FALLOUT_3_KEY: &str = r"Software\Bethesda Softworks\Fallout3";
const INSTALLED_PATH_VALUE: &str = "Installed Path";
const FALLOUT_NV_LAUNCHER: &str = "FalloutNVLauncher.exe";
const FALLOUT_3_LAUNCHER: &str = "FalloutLauncher.exe";
const ENGINE_PATH_BUFFER_BYTES: usize = 260;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepairOutcome {
    Unchanged,
    Repaired,
}

/// Repair configured installation-path values before vanilla can consume them.
///
/// The function is deliberately fail-open: inaccessible HKLM keys or invalid
/// configured text produce a targeted warning while the game continues.
pub(super) fn repair(config: &EngineFixesConfig) {
    if !config.install_path_registry_repair {
        log::info!("[INSTALL_PATHS] Registry repair disabled by config");
        return;
    }

    let new_vegas_dir = match main_executable_directory() {
        Ok(path) => path,
        Err(error) => {
            log::warn!("[INSTALL_PATHS] Cannot derive FalloutNV directory: {error:#}");
            return;
        }
    };

    match prepare_registry_path(&new_vegas_dir, FALLOUT_NV_LAUNCHER)
        .and_then(|path| repair_value(FALLOUT_NV_KEY, &path).map(|outcome| (path, outcome)))
    {
        Ok((path, RepairOutcome::Unchanged)) => {
            log::info!("[INSTALL_PATHS] FalloutNV registry path already correct: {path}");
        }
        Ok((path, RepairOutcome::Repaired)) => {
            log::info!("[INSTALL_PATHS] Repaired FalloutNV registry path: {path}");
        }
        Err(error) => {
            log::warn!("[INSTALL_PATHS] FalloutNV registry repair failed: {error:#}");
        }
    }

    if config.fallout3_install_path.trim().is_empty() {
        log::info!("[INSTALL_PATHS] Fallout 3 registry repair skipped: no path configured");
        return;
    }

    match resolve_configured_path(&new_vegas_dir, &config.fallout3_install_path)
        .and_then(|path| prepare_registry_path(&path, FALLOUT_3_LAUNCHER))
        .and_then(|path| repair_value(FALLOUT_3_KEY, &path).map(|outcome| (path, outcome)))
    {
        Ok((path, RepairOutcome::Unchanged)) => {
            log::info!("[INSTALL_PATHS] Fallout 3 registry path already correct: {path}");
        }
        Ok((path, RepairOutcome::Repaired)) => {
            log::info!("[INSTALL_PATHS] Repaired Fallout 3 registry path: {path}");
        }
        Err(error) => {
            log::warn!("[INSTALL_PATHS] Fallout 3 registry repair failed: {error:#}");
        }
    }
}

fn main_executable_directory() -> Result<PathBuf> {
    let executable = get_module_file_name_w(None).context("GetModuleFileNameW(NULL)")?;
    let executable = Path::new(&executable);
    let directory = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("the main executable path has no parent directory")?;
    normalize_absolute_path(directory)
}

fn resolve_configured_path(new_vegas_dir: &Path, configured: &str) -> Result<PathBuf> {
    if configured.trim().is_empty() {
        bail!("the configured path is empty");
    }
    if configured.contains('\0') {
        bail!("the configured path contains NUL");
    }

    let path = Path::new(configured);
    let first = path.components().next();
    if let Some(Component::Prefix(prefix)) = first
        && matches!(
            prefix.kind(),
            Prefix::Verbatim(_)
                | Prefix::VerbatimDisk(_)
                | Prefix::VerbatimUNC(_, _)
                | Prefix::DeviceNS(_)
        )
    {
        bail!("Win32 device and verbatim path namespaces are not supported");
    }

    let combined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        // A drive-relative path such as C:Fallout3 and a root-only path such as
        // \Fallout3 both depend on ambient drive state. Refusing them keeps the
        // config deterministic across Steam, xNVSE, Windows, Wine, and Proton.
        if path.has_root() || matches!(first, Some(Component::Prefix(_))) {
            bail!("the configured path is neither fully qualified nor normally relative");
        }
        new_vegas_dir.join(path)
    };

    normalize_absolute_path(&combined)
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("path is not fully qualified: {}", path.display());
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                // `PathBuf::pop` refuses to remove a prefix or root. A failure
                // therefore means that `..` would escape the selected volume.
                if !normalized.pop() {
                    bail!("path traverses above its volume root: {}", path.display());
                }
            }
        }
    }
    Ok(normalized)
}

fn prepare_registry_path(path: &Path, launcher: &str) -> Result<String> {
    let mut text = path
        .to_str()
        .context("path cannot be represented as Unicode text")?
        .replace('/', "\\");
    if !text.ends_with('\\') {
        text.push('\\');
    }

    // The engine reads through RegQueryValueExA into a 260-byte buffer and
    // appends the launcher in that same buffer. Measure the exact active-code-
    // page conversion as well as UTF-16 so both the engine and wide launcher
    // readers are proven to fit on every supported locale.
    let full_launcher_path = format!("{text}{launcher}");
    let ansi_required = ansi_byte_len_with_nul(&full_launcher_path)
        .context("measure path in the active Windows ANSI code page")?;
    let wide_required = full_launcher_path
        .encode_utf16()
        .count()
        .checked_add(1)
        .context("path length overflow")?;
    let required = ansi_required.max(wide_required);
    if required > ENGINE_PATH_BUFFER_BYTES {
        bail!(
            "path plus {launcher} requires {required} characters/bytes; vanilla allows {}",
            ENGINE_PATH_BUFFER_BYTES
        );
    }
    Ok(text)
}

fn repair_value(subkey: &str, expected: &str) -> Result<RepairOutcome> {
    let current = match RegistryKey::open_local_machine_32(subkey)
        .with_context(|| format!("open HKLM\\{subkey} for query"))?
    {
        Some(key) => key
            .query_string(INSTALLED_PATH_VALUE)
            .with_context(|| format!("query HKLM\\{subkey}\\{INSTALLED_PATH_VALUE}"))?,
        None => RegistryStringValue::Missing,
    };

    if !requires_repair(&current, expected) {
        return Ok(RepairOutcome::Unchanged);
    }

    let key = RegistryKey::create_local_machine_32(subkey)
        .with_context(|| format!("create or open HKLM\\{subkey} for repair"))?;
    key.set_string(INSTALLED_PATH_VALUE, expected)
        .with_context(|| format!("set HKLM\\{subkey}\\{INSTALLED_PATH_VALUE}"))?;
    Ok(RepairOutcome::Repaired)
}

fn requires_repair(current: &RegistryStringValue, expected: &str) -> bool {
    !matches!(current, RegistryStringValue::String(value) if value == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r"Z:\Games\FalloutNV_TTW\FalloutNV";

    #[test]
    fn absolute_fallout3_path_is_preserved_and_terminated() {
        let path = resolve_configured_path(Path::new(BASE), r"D:\Games\Fallout 3")
            .expect("resolve absolute path");
        assert_eq!(
            prepare_registry_path(&path, FALLOUT_3_LAUNCHER).expect("prepare registry path"),
            r"D:\Games\Fallout 3\"
        );
    }

    #[test]
    fn unc_fallout3_path_is_supported() {
        let path = resolve_configured_path(Path::new(BASE), r"\\server\share\Fallout 3")
            .expect("resolve UNC path");
        assert_eq!(
            prepare_registry_path(&path, FALLOUT_3_LAUNCHER).expect("prepare registry path"),
            r"\\server\share\Fallout 3\"
        );
    }

    #[test]
    fn relative_fallout3_path_uses_new_vegas_directory() {
        let path = resolve_configured_path(Path::new(BASE), r"..\Fallout 3")
            .expect("resolve sibling path");
        assert_eq!(path, Path::new(r"Z:\Games\FalloutNV_TTW\Fallout 3"));
    }

    #[test]
    fn relative_resolution_is_lexical_and_does_not_require_files() {
        let path = resolve_configured_path(Path::new(BASE), r".\missing\..\Fallout 3")
            .expect("resolve nonexistent lexical path");
        assert_eq!(
            path,
            Path::new(r"Z:\Games\FalloutNV_TTW\FalloutNV\Fallout 3")
        );
    }

    #[test]
    fn ambiguous_windows_paths_are_rejected() {
        assert!(resolve_configured_path(Path::new(BASE), r"C:Fallout 3").is_err());
        assert!(resolve_configured_path(Path::new(BASE), r"\Fallout 3").is_err());
    }

    #[test]
    fn paths_that_overflow_vanilla_launcher_buffer_are_rejected() {
        let long_component = "x".repeat(ENGINE_PATH_BUFFER_BYTES);
        let path = PathBuf::from(format!(r"Z:\{long_component}"));
        assert!(prepare_registry_path(&path, FALLOUT_3_LAUNCHER).is_err());
    }

    #[test]
    fn only_an_exact_well_formed_registry_string_is_unchanged() {
        let expected = r"Z:\Games\Fallout 3\";
        assert!(!requires_repair(
            &RegistryStringValue::String(expected.to_owned()),
            expected
        ));
        assert!(requires_repair(
            &RegistryStringValue::String(r"D:\Fallout 3\".to_owned()),
            expected
        ));
        assert!(requires_repair(&RegistryStringValue::Missing, expected));
        assert!(requires_repair(&RegistryStringValue::Invalid, expected));
    }
}
