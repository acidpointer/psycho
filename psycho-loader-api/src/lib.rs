#![no_std]

//! Generic ABI for DLLs loaded by `psycho-loader`.

use core::mem::size_of;

pub const PSYCHO_LOADER_MAGIC: u32 = 0x4C44_5950; // PYDL
pub const PSYCHO_LOADER_API_VERSION: u32 = 1;
pub const PSYCHO_LOADER_MOD_INIT: &str = "PsychoLoader_ModInit";

#[repr(C)]
pub struct PsychoLoaderInfo {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub loader_module: usize,
    pub mod_module: usize,
}

impl PsychoLoaderInfo {
    pub const fn new(loader_module: usize, mod_module: usize) -> Self {
        Self {
            magic: PSYCHO_LOADER_MAGIC,
            version: PSYCHO_LOADER_API_VERSION,
            size: size_of::<Self>() as u32,
            loader_module,
            mod_module,
        }
    }
}

pub type PsychoLoaderModInitFn = unsafe extern "system" fn(*const PsychoLoaderInfo) -> i32;
