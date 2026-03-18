//! Game heap monitor thread.
//!
//! Periodically logs mimalloc process stats, gheap balance, and pressure
//! relief stats. Runs on its own thread, separate from sbm2 GC.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libmimalloc::process_info::MiMallocProcessInfo;

use super::pressure::PressureRelief;
use super::stats;

const MONITOR_INTERVAL: Duration = Duration::from_secs(5);

pub struct Monitor {
    run: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Monitor {
    pub fn start() -> Self {
        let run = Arc::new(AtomicBool::new(true));
        let run_clone = run.clone();

        let handle = thread::spawn(move || {

            loop {
                if !run_clone.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(MONITOR_INTERVAL);

                // --- mimalloc process stats ---
                let info = MiMallocProcessInfo::get();
                log::info!(
                    "[MEM] RSS: {} | Peak: {} | Commit: {} | PeakCommit: {} | Faults: {:.1}/s | CPU eff: {:.0}%",
                    info.memory_usage_human(),
                    info.peak_memory_usage_human(),
                    info.virtual_memory_usage_human(),
                    libpsycho::common::helpers::format_bytes(info.get_peak_commit()),
                    info.page_fault_rate_per_second(),
                    info.cpu_efficiency_percent(),
                );

                // --- gheap balance ---
                let s = stats::instance();
                let (relief, cells) = PressureRelief::instance()
                    .map(|pr| pr.stats())
                    .unwrap_or((0, 0));
                log::info!(
                    "[GHEAP] balance: {} (allocs: {}, frees: {}) | pressure: {} reliefs, {} cells unloaded",
                    s.balance(),
                    s.alloc_count(),
                    s.free_count(),
                    relief,
                    cells,
                );
            }
        });

        log::info!("[GHEAP] Monitor thread started");

        Self {
            run,
            handle: Some(handle),
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.run.store(false, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
