//! Windows Timer Resolution Fix
//!
//! FNV never calls timeBeginPeriod, leaving the default Windows timer
//! resolution at ~15.6ms. This means Sleep(1ms) actually sleeps ~15ms,
//! completely defeating our sleep patches and causing inconsistent
//! frame pacing for any timing that relies on Sleep or GetTickCount.
//!
//! Calling timeBeginPeriod(1) sets the minimum timer resolution to 1ms,
//! making Sleep(1ms) actually sleep ~1ms and improving GetTickCount
//! granularity from ~15.6ms to ~1ms.
//!
//! Note: This is process-wide and slightly increases power consumption,
//! but the game is already a foreground, CPU-intensive application.

/// Set Windows timer resolution to 1ms.
///
/// Must be called early, before any timing-dependent code runs.
pub fn set_timer_resolution() -> anyhow::Result<()> {
    let result = unsafe { windows::Win32::Media::timeBeginPeriod(1) };

    if result == 0 {
        // TIMERR_NOERROR = 0
        log::info!("[PERF] Timer resolution set to 1ms (timeBeginPeriod)");
        Ok(())
    } else {
        anyhow::bail!("timeBeginPeriod(1) failed with code {}", result);
    }
}
