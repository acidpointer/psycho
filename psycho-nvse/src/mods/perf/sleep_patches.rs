//! Sleep Duration Patches
//!
//! The game uses polling loops with Sleep(50ms) and Sleep(10ms) for I/O
//! thread coordination. These add 10-50ms of latency per synchronization
//! point during asset streaming (cell transitions, new objects entering
//! view, combat with many actors/effects).
//!
//! The three functions form a coordination triangle:
//!   - FUN_00b01080: Sets ready flag, spins Sleep(50ms) waiting for state change
//!   - FUN_00b010d0: Sets state=2, spins Sleep(10ms) waiting for ready flag
//!   - FUN_00b01130: Sets state=3, spins Sleep(10ms) waiting for ready flag
//!
//! Reducing these to Sleep(1ms) cuts coordination latency by 10-50x while
//! still yielding the timeslice (no busy-wait CPU burn).
//!
//! Additionally, FUN_00c3dfa0 (data loading) uses Sleep(50ms) as a throttle
//! when the loader is ahead of the consumer. Reducing to 1ms speeds up
//! loading without risk - it's purely a yield.

use libc::c_void;
use libpsycho::os::windows::winapi::patch_bytes;

/// Patch all oversized Sleep durations to 1ms.
pub fn install_sleep_patches() -> anyhow::Result<()> {
    unsafe {
        // FUN_00b01080: I/O thread sync - Sleep(50ms) -> Sleep(1ms)
        // Instruction: PUSH 0x32 (6A 32) at 0x00b010ba
        // Patch the immediate byte from 0x32 to 0x01
        patch_bytes(0x00B010BB as *mut c_void, &[0x01])?;

        // FUN_00b010d0: I/O "begin op" wait - Sleep(10ms) -> Sleep(1ms)
        // Instruction: PUSH 0x0A (6A 0A) at 0x00b01121
        patch_bytes(0x00B01122 as *mut c_void, &[0x01])?;

        // FUN_00b01130: I/O "begin op" wait - Sleep(10ms) -> Sleep(1ms)
        // Instruction: PUSH 0x0A (6A 0A) at 0x00b01195
        patch_bytes(0x00B01196 as *mut c_void, &[0x01])?;

        // FUN_00c3dfa0: Data loading throttle - Sleep(50ms) -> Sleep(1ms)
        // Instruction: PUSH 0x32 (6A 32) at 0x00c3e105
        patch_bytes(0x00C3E106 as *mut c_void, &[0x01])?;
    }

    log::info!("[PERF] Sleep patches applied: 50ms->1ms (x2), 10ms->1ms (x2)");

    Ok(())
}
