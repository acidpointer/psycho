//! Deferred Task Budget Fix
//!
//! FUN_00c458f0 processes a deferred task queue (ref-counted object cleanup).
//! When the queue exceeds 200 items, it adds 1000ms to its time budget:
//!
//!   deadline = GetTickCount() + base_budget;
//!   if (queue_size > 200) {
//!       deadline += 1000;  // <-- ONE FULL SECOND
//!   }
//!
//! This function acquires a lock before processing. Holding it for up to 1
//! second while draining a large queue can stall any thread that needs the
//! same lock, including the main thread - manifesting as a massive frame
//! time spike.
//!
//! Fix: Reduce 1000ms -> 100ms. Still clears backlogs faster than the base
//! budget alone, but won't cause perceptible frame stalls.
//!
//! Instruction at 0x00C45934:
//!   81 C2 E8 03 00 00   ADD EDX, 0x3E8  (1000)
//!   =>  81 C2 64 00 00 00   ADD EDX, 0x64   (100)

use libc::c_void;
use libpsycho::os::windows::winapi::patch_bytes;

/// Reduce the deferred task overflow budget from 1000ms to 100ms.
pub fn patch_deferred_task_budget() -> anyhow::Result<()> {
    unsafe {
        // ADD EDX, imm32 at 0x00C45934: opcode 81 C2 [imm32]
        // The immediate starts at 0x00C45936: E8 03 00 00 -> 64 00 00 00
        patch_bytes(0x00C45936 as *mut c_void, &[0x64, 0x00, 0x00, 0x00])?;
    }

    log::info!("[PERF] Deferred task budget reduced: 1000ms -> 100ms (queue overflow)");

    Ok(())
}
