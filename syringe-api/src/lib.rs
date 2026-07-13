#![no_std]

//! Generic ABI for DLLs loaded by `syringe`.
//!
//! `SyringeInfo` is borrowed for the duration of `Syringe_ModInit`. A mod must
//! copy any values it needs after the callback returns.

use core::mem::size_of;

/// Identifies a [`SyringeInfo`] structure supplied by Syringe.
pub const SYRINGE_MAGIC: u32 = 0x4752_5953; // SYRG
/// Current ABI version. Appending fields remains compatible through `size`.
pub const SYRINGE_API_VERSION: u32 = 1;
/// Undecorated first-phase callback export name.
pub const SYRINGE_MOD_INIT: &str = "Syringe_ModInit";
/// Undecorated second-phase callback export name.
pub const SYRINGE_MOD_ACTIVATE: &str = "Syringe_ModActivate";
/// The current loader pass owns the executable's pre-CRT startup barrier.
pub const SYRINGE_INFO_PRE_CRT_BARRIER: u32 = 1 << 0;

/// Borrowed loader context passed to each optional mod callback.
///
/// Consumers must check `magic`, `version`, and `size` before reading fields
/// introduced after the ABI version they support. The pointer is valid only
/// for the duration of the callback.
#[repr(C)]
pub struct SyringeInfo {
    /// [`SYRINGE_MAGIC`].
    pub magic: u32,
    /// [`SYRINGE_API_VERSION`].
    pub version: u32,
    /// Size of this structure in bytes.
    pub size: u32,
    /// Module handle of the Syringe proxy.
    pub loader_module: usize,
    /// Module handle of the callback recipient.
    pub mod_module: usize,
    /// Loader capabilities such as [`SYRINGE_INFO_PRE_CRT_BARRIER`].
    pub flags: u32,
}

impl SyringeInfo {
    /// Build callback context with no optional capabilities set.
    pub const fn new(loader_module: usize, mod_module: usize) -> Self {
        Self {
            magic: SYRINGE_MAGIC,
            version: SYRINGE_API_VERSION,
            size: size_of::<Self>() as u32,
            loader_module,
            mod_module,
            flags: 0,
        }
    }

    /// Set loader capability flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }
}

/// First-phase callback called after every DLL has been loaded.
///
/// The exported symbol must be the exact undecorated name `Syringe_ModInit`.
/// On i686, use a module definition file when a toolchain decorates stdcall
/// exports. Returning zero reports initialization failure, but does not prevent
/// the loader from offering the optional activation callback; a mod must keep
/// enough local state to reject activation after its own failed initialization.
pub type SyringeModInitFn = unsafe extern "system" fn(*const SyringeInfo) -> i32;

/// Optional second-phase callback. Syringe calls it only after every loaded
/// mod has received `Syringe_ModInit`. Returning zero reports activation
/// failure without stopping other mods.
pub type SyringeModActivateFn = unsafe extern "system" fn(*const SyringeInfo) -> i32;
