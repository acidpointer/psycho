#![no_std]

//! Generic ABI for DLLs loaded by `syringe`.

use core::mem::size_of;

pub const SYRINGE_MAGIC: u32 = 0x4752_5953; // SYRG
pub const SYRINGE_API_VERSION: u32 = 1;
pub const SYRINGE_MOD_INIT: &str = "Syringe_ModInit";

#[repr(C)]
pub struct SyringeInfo {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub loader_module: usize,
    pub mod_module: usize,
}

impl SyringeInfo {
    pub const fn new(loader_module: usize, mod_module: usize) -> Self {
        Self {
            magic: SYRINGE_MAGIC,
            version: SYRINGE_API_VERSION,
            size: size_of::<Self>() as u32,
            loader_module,
            mod_module,
        }
    }
}

pub type SyringeModInitFn = unsafe extern "system" fn(*const SyringeInfo) -> i32;
