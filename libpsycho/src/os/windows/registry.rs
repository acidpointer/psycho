//! Safe, core-only Win32 registry operations for legacy game discovery.
//!
//! This module is intentionally separate from [`super::winapi`]. Most Psycho
//! DLLs use that broad Win32 boundary, so placing registry calls in the same
//! code-generation unit can make otherwise unrelated DLLs inherit registry
//! imports. In particular, the thin xNVSE helper must not make the Windows
//! loader resolve core-only registry machinery during plugin load.
//!
//! The API exposes only bounded UTF-16 `REG_SZ` reads and writes beneath the
//! 32-bit `HKEY_LOCAL_MACHINE` view. Handles are owned through RAII, malformed
//! registry-controlled lengths never drive unbounded allocation, and legacy
//! ANSI sizing rejects any conversion that changes the original text.
//!
//! The FFI-bearing functions are intentionally `#[inline]`. This is an image
//! ownership boundary, not a performance tweak: `libpsycho` is statically
//! linked into several DLLs, and out-of-line public wrappers can share a codegen
//! unit with helper-used code. Inlining lets the final consumer instantiate the
//! registry calls only when it actually uses them. The helper's PE-import test
//! guards the resulting loader contract in addition to release-image inspection.

use std::ffi::{CString, NulError, OsStr};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;

use thiserror::Error;
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::Globalization::{
    CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar, WideCharToMultiByte,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_32KEY,
    REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW,
};
use windows::core::{PCSTR, PCWSTR};

const MAX_REGISTRY_STRING_BYTES: u32 = 64 * 1024;

/// Error returned by the bounded registry and legacy-text helpers.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// A Win32 API that reports through `GetLastError` failed.
    #[error("Windows core API error: {0}")]
    WindowsCore(#[from] windows::core::Error),
    /// A key, value name, or value contained an interior string terminator.
    #[error("Interior nul bytes found: {0}")]
    Nul(#[from] NulError),
    /// A Rust extent could not be represented by the Win32 API's integer type.
    #[error("Windows value overflowed while converting {0}")]
    IntegerOverflow(&'static str),
    /// A registry API returned the enclosed Win32 status code.
    #[error("Registry API failed with Win32 error code {0}")]
    Api(u32),
    /// The active ANSI code page would change at least one input character.
    #[error("Text cannot be represented exactly in the active Windows ANSI code page")]
    LossyAnsiConversion,
}

/// Result type for bounded registry and legacy-text operations.
pub type RegistryResult<T> = std::result::Result<T, RegistryError>;

/// Result of reading a registry value as a UTF-16 `REG_SZ` string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryStringValue {
    /// The named value does not exist.
    Missing,
    /// The value is a well-formed, null-terminated `REG_SZ` string.
    String(String),
    /// The value exists but its type, extent, termination, or UTF-16 is invalid.
    Invalid,
}

/// Owned handle to a non-predefined Windows registry key.
///
/// Instances close their handle automatically and expose only the string
/// operations needed by Psycho. This prevents engine features from leaking
/// raw `HKEY` ownership or accidentally closing a predefined root handle.
#[derive(Debug)]
pub struct RegistryKey {
    handle: HKEY,
}

impl RegistryKey {
    /// Open an existing `HKEY_LOCAL_MACHINE` subkey read-only in the 32-bit view.
    ///
    /// Requesting only `KEY_QUERY_VALUE` keeps a correct key usable under
    /// read-only ACLs. A missing key is reported as `Ok(None)`.
    #[inline]
    pub fn open_local_machine_32(subkey: &str) -> RegistryResult<Option<Self>> {
        let subkey = wide_nul(subkey)?;
        let mut handle = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                None,
                KEY_QUERY_VALUE | KEY_WOW64_32KEY,
                &mut handle,
            )
        };
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        registry_status(status)?;
        Ok(Some(Self { handle }))
    }

    /// Create or open an `HKEY_LOCAL_MACHINE` subkey in the 32-bit registry view.
    ///
    /// Missing intermediate keys are created as non-volatile keys. The returned
    /// handle permits querying and setting values but requests no broader rights.
    #[inline]
    pub fn create_local_machine_32(subkey: &str) -> RegistryResult<Self> {
        let subkey = wide_nul(subkey)?;
        let mut handle = HKEY::default();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_32KEY,
                None,
                &mut handle,
                None,
            )
        };
        registry_status(status)?;
        Ok(Self { handle })
    }

    /// Read a named registry value as a bounded, null-terminated `REG_SZ`.
    ///
    /// Windows permits malformed string values that omit their terminator. The
    /// method reports those values as `Invalid` instead of exposing an unsafe or
    /// lossy string. It also bounds the allocation made from registry-controlled
    /// size metadata.
    #[inline]
    pub fn query_string(&self, value_name: &str) -> RegistryResult<RegistryStringValue> {
        // Keep the backing vector visibly named for the complete two-call
        // query. The raw PCWSTR is borrowed by both Win32 calls and must not
        // outlive or obscure the allocation that owns its code units.
        let value_name_wide = wide_nul(value_name)?;
        let value_name = PCWSTR(value_name_wide.as_ptr());
        let mut value_type = REG_VALUE_TYPE::default();
        let mut byte_len = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                self.handle,
                value_name,
                None,
                Some(&mut value_type),
                None,
                Some(&mut byte_len),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(RegistryStringValue::Missing);
        }
        registry_status(status)?;

        if value_type != REG_SZ
            || byte_len < size_of::<u16>() as u32
            || byte_len % size_of::<u16>() as u32 != 0
            || byte_len > MAX_REGISTRY_STRING_BYTES
        {
            return Ok(RegistryStringValue::Invalid);
        }

        let mut bytes = vec![0u8; byte_len as usize];
        let mut returned_type = REG_VALUE_TYPE::default();
        let mut returned_len = byte_len;
        let status = unsafe {
            RegQueryValueExW(
                self.handle,
                value_name,
                None,
                Some(&mut returned_type),
                Some(bytes.as_mut_ptr()),
                Some(&mut returned_len),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(RegistryStringValue::Missing);
        }
        // A concurrent writer can grow the value between the size probe and
        // the read. Treat that race as invalid state for this observation; the
        // caller can reopen and replace it without trusting partial data.
        if status == ERROR_MORE_DATA {
            return Ok(RegistryStringValue::Invalid);
        }
        registry_status(status)?;
        if returned_type != REG_SZ
            || returned_len < size_of::<u16>() as u32
            || returned_len > byte_len
            || returned_len % size_of::<u16>() as u32 != 0
        {
            return Ok(RegistryStringValue::Invalid);
        }
        bytes.truncate(returned_len as usize);

        let wide: Vec<u16> = bytes
            .chunks_exact(size_of::<u16>())
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        let Some(terminator) = wide.iter().position(|unit| *unit == 0) else {
            return Ok(RegistryStringValue::Invalid);
        };
        if wide[terminator + 1..].iter().any(|unit| *unit != 0) {
            return Ok(RegistryStringValue::Invalid);
        }
        match String::from_utf16(&wide[..terminator]) {
            Ok(value) => Ok(RegistryStringValue::String(value)),
            Err(_) => Ok(RegistryStringValue::Invalid),
        }
    }

    /// Store a named, null-terminated UTF-16 `REG_SZ` value.
    #[inline]
    pub fn set_string(&self, value_name: &str, value: &str) -> RegistryResult<()> {
        let value_name = wide_nul(value_name)?;
        let wide = wide_nul(value)?;
        let byte_len = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(RegistryError::IntegerOverflow(
                "registry string byte length",
            ))?;
        // `u16` has no padding and the byte slice borrows `wide` for exactly
        // this call, so the Win32 API cannot outlive or mis-size its backing data.
        let bytes =
            unsafe { std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), byte_len as usize) };
        let status = unsafe {
            RegSetValueExW(
                self.handle,
                PCWSTR(value_name.as_ptr()),
                None,
                REG_SZ,
                Some(bytes),
            )
        };
        registry_status(status)
    }
}

impl Drop for RegistryKey {
    #[inline]
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = RegCloseKey(self.handle);
            }
            self.handle = HKEY::default();
        }
    }
}

#[inline]
fn registry_status(status: WIN32_ERROR) -> RegistryResult<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(RegistryError::Api(status.0))
    }
}

#[inline]
fn wide_nul(value: &str) -> RegistryResult<Vec<u16>> {
    // UTF-16 `REG_SZ` and Win32 names cannot represent an interior terminator.
    // Checking the UTF-8 input first prevents a safe caller from publishing a
    // truncated value followed by hidden data.
    let _ = CString::new(value)?;
    Ok(OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

/// Return the exact active-ANSI-code-page byte length of `value` plus one NUL.
///
/// This matches the conversion performed when legacy code queries a Unicode
/// registry string through `RegQueryValueExA`. Interior NULs and conversions
/// that substitute or best-fit any character are rejected, because the legacy
/// consumer would observe a truncated or different path. The helper is useful
/// when a consumer's fixed buffer is measured in bytes rather than UTF-16 code
/// units.
#[inline]
pub fn ansi_byte_len_with_nul(value: &str) -> RegistryResult<usize> {
    let wide = wide_nul(value)?;
    let length = unsafe { WideCharToMultiByte(CP_ACP, 0, &wide, None, PCSTR::null(), None) };
    if length == 0 {
        return Err(RegistryError::WindowsCore(
            windows::core::Error::from_win32(),
        ));
    }

    let mut ansi = vec![0u8; length as usize];
    let converted =
        unsafe { WideCharToMultiByte(CP_ACP, 0, &wide, Some(&mut ansi), PCSTR::null(), None) };
    if converted != length {
        return Err(RegistryError::WindowsCore(
            windows::core::Error::from_win32(),
        ));
    }

    // Asking Windows to decode its own conversion avoids assumptions about
    // locale-specific single-byte, DBCS, UTF-8, or Wine code-page behavior. A
    // byte count alone is insufficient: best-fit conversion can preserve the
    // size while silently changing a directory name that vanilla then opens.
    let round_trip_length = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MULTI_BYTE_TO_WIDE_CHAR_FLAGS::default(),
            &ansi,
            None,
        )
    };
    if round_trip_length == 0 {
        return Err(RegistryError::WindowsCore(
            windows::core::Error::from_win32(),
        ));
    }
    let mut round_trip = vec![0u16; round_trip_length as usize];
    let decoded = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MULTI_BYTE_TO_WIDE_CHAR_FLAGS::default(),
            &ansi,
            Some(&mut round_trip),
        )
    };
    if decoded != round_trip_length {
        return Err(RegistryError::WindowsCore(
            windows::core::Error::from_win32(),
        ));
    }
    if round_trip != wide {
        return Err(RegistryError::LossyAnsiConversion);
    }
    Ok(length as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_length_includes_the_terminator_and_rejects_interior_nul() {
        assert_eq!(
            ansi_byte_len_with_nul("FalloutNV").expect("measure ASCII text"),
            10
        );
        assert!(matches!(
            ansi_byte_len_with_nul("Fallout\0NV"),
            Err(RegistryError::Nul(_))
        ));
    }
}
