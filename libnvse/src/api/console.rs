//! Safe wrapper for the NVSE console interface.
//!
//! Allows executing console commands programmatically from Rust plugins.
//!
//! # Usage
//!
//! ```no_run
//! // Execute a console command
//! console.run("player.additem 000000F 100")?;
//!
//! // Execute silently (no console echo)
//! console.run_silent("set MyGlobal to 1")?;
//!
//! // Execute on a specific reference (target a form)
//! // Pass a raw TESObjectREFR pointer obtained from the game engine.
//! console.run_on(some_ref_ptr, "disable")?;
//! ```

use std::ptr::NonNull;

use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

use crate::NVSEConsoleInterface as NVSEConsoleInterfaceFFI;
use crate::TESObjectREFR;

#[derive(Debug, Error)]
pub enum ConsoleError {
    #[error("NVSEConsoleInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("RunScriptLine function pointer is NULL")]
    RunScriptLineIsNull,

    #[error("Console command execution failed")]
    ExecutionFailed,

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type ConsoleResult<T> = Result<T, ConsoleError>;

/// Safe wrapper around NVSEConsoleInterface.
///
/// Provides methods to execute console commands from Rust code,
/// equivalent to typing them in the in-game console (~).
pub struct Console {
    ptr: NonNull<NVSEConsoleInterfaceFFI>,
}

impl Console {
    /// Create a Console wrapper from a raw FFI pointer.
    ///
    /// Returns an error if the pointer is NULL.
    pub fn from_raw(raw: *mut NVSEConsoleInterfaceFFI) -> ConsoleResult<Self> {
        let ptr = NonNull::new(raw).ok_or(ConsoleError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Get the raw FFI pointer.
    pub fn as_raw_ptr(&self) -> *mut NVSEConsoleInterfaceFFI {
        self.ptr.as_ptr()
    }

    /// Execute a console command string.
    ///
    /// Equivalent to typing the command in the game console.
    /// Output will appear in the console window.
    pub fn run(&self, command: &str) -> ConsoleResult<()> {
        self.run_on_ref(command, std::ptr::null_mut(), false)
    }

    /// Execute a console command silently (suppresses console output).
    pub fn run_silent(&self, command: &str) -> ConsoleResult<()> {
        self.run_on_ref(command, std::ptr::null_mut(), true)
    }

    /// Execute a console command on a specific object reference.
    ///
    /// # Safety contract
    ///
    /// The caller must ensure `object` points to a valid TESObjectREFR
    /// or is NULL (in which case the command runs without a target).
    pub fn run_on(&self, object: *mut TESObjectREFR, command: &str) -> ConsoleResult<()> {
        self.run_on_ref(command, object, false)
    }

    fn run_on_ref(
        &self,
        command: &str,
        object: *mut TESObjectREFR,
        suppress_output: bool,
    ) -> ConsoleResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let cmd = WinString::new(command)?;

        // Prefer RunScriptLine2 (has suppress_output param).
        // Fall back to RunScriptLine (no suppress param) only if
        // RunScriptLine2 is unavailable.
        let success = if let Some(run2) = iface.RunScriptLine2 {
            cmd.with_ansi(|buf| unsafe { run2(buf, object, suppress_output) })
        } else {
            let run1 = iface
                .RunScriptLine
                .ok_or(ConsoleError::RunScriptLineIsNull)?;
            cmd.with_ansi(|buf| unsafe { run1(buf, object) })
        };

        if success {
            Ok(())
        } else {
            Err(ConsoleError::ExecutionFailed)
        }
    }
}
