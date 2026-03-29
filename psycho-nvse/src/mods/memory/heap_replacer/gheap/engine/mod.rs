//! Safe wrappers for Fallout: New Vegas engine internals.
//!
//! All raw game addresses live in addr.rs. All unsafe pointer reads and
//! game function calls are wrapped in safe (or explicitly-unsafe-with-docs)
//! functions in globals.rs. IO spin-lock and BSTaskManagerThread semaphore
//! probing live in io_sync.rs.
//!
//! Nothing outside this module should ever cast a raw integer to a pointer
//! or call a game function through FnPtr directly.

pub mod addr;
pub mod cell_unload;
pub mod globals;
