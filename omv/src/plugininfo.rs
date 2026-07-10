//! Static xNVSE plugin metadata.

use std::ffi::CStr;

use libpsycho::common::packed_version::PackedVersion;

/// xNVSE plugin identity used by plugin checks and logs.
pub static PLUGIN_NAME: &CStr = c"oh-my-vegas";
pub static PLUGIN_VERSION: u32 = PackedVersion::new(0, 1, 0, 0).as_u32();
