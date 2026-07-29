//! Capability-based Wine and Proton detection.
//!
//! Wine is proven by the documented `wine_get_version` export from the loaded
//! `ntdll.dll`. Proton is classified only when Wine is already proven and
//! Steam's non-empty `STEAM_COMPAT_DATA_PATH` marker is present. Environment
//! variables alone never turn native Windows into Wine or Proton.

use core::ffi::c_char;
use std::ffi::{CStr, OsString};
use std::ptr;

use crate::ffi::fnptr::FnPtr;
use crate::os::windows::winapi::{get_module_handle_w, get_proc_address};

use super::{DetectionIssue, HardwareComponent};

/// Compatibility runtime hosting the Windows process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityRuntime {
    /// Microsoft Windows with no Wine export evidence.
    NativeWindows,
    /// Wine without a Proton launch marker.
    Wine,
    /// Wine launched through a Proton/Steam compatibility prefix.
    Proton,
}

/// Version and host evidence exported by Wine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WineInfo {
    /// Wine version string.
    pub version: Option<String>,
    /// Wine build identifier, when exported.
    pub build_id: Option<String>,
    /// Host operating-system name returned by Wine.
    pub host_system: Option<String>,
    /// Host operating-system release returned by Wine.
    pub host_release: Option<String>,
}

/// Cached compatibility-runtime profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeInfo {
    /// Normalized native Windows, Wine, or Proton classification.
    pub compatibility: CompatibilityRuntime,
    /// Wine-export details when Wine was proven.
    pub wine: Option<WineInfo>,
    /// Whether Steam supplied a non-empty compatibility-data path.
    pub steam_compat_data_path_present: bool,
    /// Steam application identifier, when supplied.
    pub steam_app_id: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct EnvironmentEvidence {
    compat_data_path_present: bool,
    app_id: Option<String>,
}

pub(super) fn detect(issues: &mut Vec<DetectionIssue>) -> RuntimeInfo {
    let environment = environment_evidence();
    let wine = match query_wine_exports() {
        Ok(wine) => wine,
        Err(error) => {
            // Failure to acquire ntdll is abnormal, unlike a missing optional
            // Wine export. Preserve native classification but make the
            // uncertainty visible in the cached profile.
            issues.push(DetectionIssue::new(HardwareComponent::Runtime, error));
            None
        }
    };
    classify_runtime(wine, environment)
}

fn query_wine_exports() -> Result<Option<WineInfo>, String> {
    type GetString = unsafe extern "C" fn() -> *const c_char;
    type GetHostVersion = unsafe extern "C" fn(*mut *const c_char, *mut *const c_char);

    let module = get_module_handle_w(Some("ntdll.dll")).map_err(|error| error.to_string())?;
    let Ok(version_address) = get_proc_address(module, "wine_get_version") else {
        return Ok(None);
    };
    let version_function = unsafe {
        FnPtr::<GetString>::from_raw(version_address).map_err(|error| error.to_string())?
    };
    let version = unsafe { copy_exported_string((version_function.as_fn())()) };

    let build_id = optional_export::<GetString>(module, "wine_get_build_id")
        .and_then(|function| unsafe { copy_exported_string((function.as_fn())()) });

    let (host_system, host_release) = if let Some(function) =
        optional_export::<GetHostVersion>(module, "wine_get_host_version")
    {
        let mut system = ptr::null();
        let mut release = ptr::null();
        unsafe { (function.as_fn())(&mut system, &mut release) };
        (unsafe { copy_exported_string(system) }, unsafe {
            copy_exported_string(release)
        })
    } else {
        (None, None)
    };

    Ok(Some(WineInfo {
        version,
        build_id,
        host_system,
        host_release,
    }))
}

fn optional_export<F>(module: crate::os::windows::winapi::HModule, name: &str) -> Option<FnPtr<F>>
where
    F: crate::ffi::fnptr::Function,
{
    let address = get_proc_address(module, name).ok()?;
    // The function type at each call site is the signature documented by
    // Wine's ntdll export contract. GetProcAddress provides no runtime type
    // metadata, so this is the single audited conversion boundary.
    unsafe { FnPtr::from_raw(address).ok() }
}

unsafe fn copy_exported_string(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // Wine owns these process-lifetime, NUL-terminated strings. CStr cannot
    // impose a length bound, so this relies on the proven Wine export rather
    // than accepting an arbitrary caller-provided pointer.
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    let text = String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned();
    (!text.is_empty()).then_some(text)
}

fn environment_evidence() -> EnvironmentEvidence {
    EnvironmentEvidence {
        compat_data_path_present: nonempty_environment("STEAM_COMPAT_DATA_PATH").is_some(),
        app_id: nonempty_environment("SteamAppId")
            .or_else(|| nonempty_environment("SteamGameId"))
            .map(|value| value.to_string_lossy().trim().to_owned())
            .filter(|value| !value.is_empty()),
    }
}

fn nonempty_environment(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

fn classify_runtime(wine: Option<WineInfo>, environment: EnvironmentEvidence) -> RuntimeInfo {
    let compatibility = match (&wine, environment.compat_data_path_present) {
        (Some(_), true) => CompatibilityRuntime::Proton,
        (Some(_), false) => CompatibilityRuntime::Wine,
        (None, _) => CompatibilityRuntime::NativeWindows,
    };
    RuntimeInfo {
        compatibility,
        wine,
        steam_compat_data_path_present: environment.compat_data_path_present,
        steam_app_id: environment.app_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wine() -> WineInfo {
        WineInfo {
            version: Some("test".to_owned()),
            build_id: None,
            host_system: Some("Linux".to_owned()),
            host_release: None,
        }
    }

    #[test]
    fn steam_marker_cannot_turn_native_windows_into_proton() {
        let runtime = classify_runtime(
            None,
            EnvironmentEvidence {
                compat_data_path_present: true,
                app_id: Some("22380".to_owned()),
            },
        );
        assert_eq!(runtime.compatibility, CompatibilityRuntime::NativeWindows);
    }

    #[test]
    fn proton_requires_wine_and_nonempty_compat_path() {
        let runtime = classify_runtime(
            Some(wine()),
            EnvironmentEvidence {
                compat_data_path_present: true,
                app_id: None,
            },
        );
        assert_eq!(runtime.compatibility, CompatibilityRuntime::Proton);
    }
}
