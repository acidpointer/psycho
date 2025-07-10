//! F4SE entry point for Fallout 4
//!
//! This module is entry point for F4SE plugin.
//! Functions: F4SEPlugin_Load and F4SEPlugin_Query are exported FFI functions
//! which will be executed by F4SE. But actual Rust side entry point here is
//! function 'entry', which being called by those two FFI functions.
//!
//! Rust's entry return anyhow::Result, which properly handled by FFI functions, so
//! feel free to return result to upper level and avoid any error handling.
//!
//! Important note. I strongly NOT RECOMMEND allow any panics in your code. Seriously.
//! Panic is Rust feature which may lead to undefined behaviour on F4SE side.
//!
//! Crates like libpsycho and libf4se will help you to develop high quality and safe
//! plugin.

use std::{ffi::CStr, ptr::NonNull};

use libf4se::prelude::{
    f4se::{F4SEInterface, PluginInfo, UInt32},
    *,
};

use crate::{allocator::init_allocator_patch, logger::GlobalLogger};

// ========================================== //
static PLUGIN_NAME: &CStr = c"PSYCHO";
static PLUGIN_VERSION: UInt32 = 1000;
// ========================================== //

#[unsafe(no_mangle)]
unsafe extern "C" fn F4SEPlugin_Query(f4se: *const F4SEInterface, info: *mut PluginInfo) -> bool {
    if f4se.is_null() || info.is_null() {
        return false;
    }

    let info = unsafe { &mut *info };

    info.infoVersion = PluginInfo::kInfoVersion;
    info.name = PLUGIN_NAME.as_ptr();
    info.version = PLUGIN_VERSION;

    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn F4SEPlugin_Load(f4se: *const F4SEInterface) -> bool {
    if f4se.is_null() {
        return false;
    }

    let f4se_interface = unsafe { NonNull::new_unchecked(f4se as *mut F4SEInterface) };

    match entry(f4se_interface) {
        Ok(_) => {
            log::info!("Plugin ready!");

            true
        }
        Err(err) => {
            log::error!("Plugin init error: {:?}", err);
            false
        }
    }
}

fn entry(f4se: NonNull<F4SEInterface>) -> anyhow::Result<()> {
    GlobalLogger::init();
    F4SEContext::instantiate(f4se);

    init_allocator_patch()?;

    Ok(())
}