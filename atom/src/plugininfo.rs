//! Static xNVSE plugin metadata.

use std::ffi::CStr;

/// xNVSE's current `PluginInfo` structure version.
pub const PLUGIN_INFO_VERSION: u32 = 1;

/// Stable identity used by xNVSE plugin queries and the MCM Extender gate.
pub static PLUGIN_NAME: &CStr = c"Atom";

/// Public plugin version returned by `GetPluginVersion`.
pub const PLUGIN_VERSION: u32 = 2;
