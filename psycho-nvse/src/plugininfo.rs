use std::ffi::CStr;

use libpsycho::common::exe_version::ExeVersion;

pub static PLUGIN_NAME: &CStr = c"psycho-nvse";
pub static PLUGIN_VERSION: u32 = ExeVersion::new(0, 0, 1, 0).get_version_packed();
