use std::ffi::CStr;

use libnvse::UInt32;
use libpsycho::common::exe_version::ExeVersion;

pub static PLUGIN_NAME: &CStr = c"psycho-nvse";
pub static PLUGIN_VERSION: UInt32 = ExeVersion::new(0, 0, 1, 0).get_version_packed();
