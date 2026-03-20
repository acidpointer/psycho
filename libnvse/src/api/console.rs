//! Safe wrapper for the NVSE console interface.
//!
//! # Usage
//!
//! ```no_run
//! console.run("player.additem 000000F 100")?;
//! console.run_silent("set MyGlobal to 1")?;
//! console.print("Hello from Rust!")?;
//! ```

use std::ptr::NonNull;
use std::sync::OnceLock;

use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

use crate::NVSEConsoleInterface as NVSEConsoleInterfaceFFI;
use crate::TESObjectREFR;

/// Stored console interface pointer for `console_print`.
/// Set once via `Console::set_global`, used by `console_print`.
static GLOBAL_CONSOLE: OnceLock<usize> = OnceLock::new();

#[derive(Debug, Error)]
pub enum ConsoleError {
    #[error("NVSEConsoleInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("RunScriptLine function pointer is NULL")]
    RunScriptLineIsNull,

    #[error("Console command execution failed")]
    ExecutionFailed,

    #[error("Console not initialized (call Console::set_global first)")]
    NotInitialized,

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type ConsoleResult<T> = Result<T, ConsoleError>;

/// Safe wrapper around NVSEConsoleInterface.
pub struct Console {
    ptr: NonNull<NVSEConsoleInterfaceFFI>,
}

impl Console {
    pub fn from_raw(raw: *mut NVSEConsoleInterfaceFFI) -> ConsoleResult<Self> {
        let ptr = NonNull::new(raw).ok_or(ConsoleError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Store this console instance's pointer globally for `console_print`.
    ///
    /// Call once during plugin load after querying the console interface.
    pub fn set_global(&self) {
        let _ = GLOBAL_CONSOLE.set(self.ptr.as_ptr() as usize);
    }

    pub fn as_raw_ptr(&self) -> *mut NVSEConsoleInterfaceFFI {
        self.ptr.as_ptr()
    }

    /// Print text to the console via `RunScriptLine("print ...")`.
    pub fn print(&self, message: &str) -> ConsoleResult<()> {
        let cmd = format!("print \"{}\"", message.replace('"', "'"));
        self.run_silent(&cmd)
    }

    pub fn run(&self, command: &str) -> ConsoleResult<()> {
        self.run_on_ref(command, std::ptr::null_mut(), false)
    }

    pub fn run_silent(&self, command: &str) -> ConsoleResult<()> {
        self.run_on_ref(command, std::ptr::null_mut(), true)
    }

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

/// Print a line to the in-game console.
///
/// Uses the globally stored Console interface pointer. Call
/// `Console::set_global()` during plugin load to initialize.
///
/// Safe to call from command handlers and the main game thread.
pub fn console_print(message: &str) -> ConsoleResult<()> {
    let &ptr = GLOBAL_CONSOLE.get().ok_or(ConsoleError::NotInitialized)?;
    let console = Console::from_raw(ptr as *mut NVSEConsoleInterfaceFFI)?;
    console.print(message)
}
