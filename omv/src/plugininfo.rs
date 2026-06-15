//! Static xNVSE plugin metadata.

use std::ffi::CStr;

use libpsycho::common::exe_version::ExeVersion;

/// xNVSE plugin identity used by plugin checks and logs.
pub static PLUGIN_NAME: &CStr = c"oh-my-vegas";
pub static PLUGIN_VERSION: u32 = ExeVersion::new(0, 1, 0, 0).get_version_packed();
