//! Command ABI for late host adapters.
//!
//! The xNVSE helper owns command registration. The core owns command behavior
//! and returns text through a caller-owned buffer so no allocation crosses DLLs.

use std::ptr;

use crate::mods::heap_replacer::mem_stats;

const COMMAND_INFO: u32 = 1;

#[derive(Clone, Copy)]
enum Command {
    Info,
}

impl Command {
    fn from_id(id: u32) -> Option<Self> {
        match id {
            COMMAND_INFO => Some(Self::Info),
            _ => None,
        }
    }

    fn run(self) -> CommandResponse {
        match self {
            Self::Info => CommandResponse::text(mem_stats::MemStats::detailed_report()),
        }
    }
}

struct CommandResponse {
    text: String,
}

impl CommandResponse {
    fn text(text: String) -> Self {
        Self { text }
    }

    unsafe fn write_to(self, output: &mut CommandOutput) {
        let bytes = self.text.as_bytes();
        output.written = bytes.len();
        output.flags = 0;
        output.result = 0.0;

        if !output.text.is_null() && output.text_len > 0 {
            let copy_len = bytes.len().min(output.text_len);
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output.text, copy_len) };
        }
    }
}

/// Caller-owned output buffer for `PsychoEngineFixes_RunCommand`.
///
/// `written` is always the full response length, even when `text_len` is too
/// small and the text is truncated.
#[repr(C)]
pub struct CommandOutput {
    pub text: *mut u8,
    pub text_len: usize,
    pub written: usize,
    pub result: f64,
    pub flags: u32,
}

/// Run a diagnostic/control command requested by a host adapter.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_RunCommand(
    command: u32,
    output: *mut CommandOutput,
) -> i32 {
    if output.is_null() {
        return 0;
    }

    if !crate::entry::is_initialized() {
        return 0;
    }

    let Some(command) = Command::from_id(command) else {
        return 0;
    };

    unsafe { command.run().write_to(&mut *output) };
    1
}
