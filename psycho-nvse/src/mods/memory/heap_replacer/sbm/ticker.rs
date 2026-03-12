//! Very simple ticker

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// Duration between ticks
const TICK_DURATION: Duration = Duration::from_millis(100);

pub struct Ticker {
    /// Current tick
    current_tick: Arc<AtomicU64>,

    /// Flag to control thread execution
    run_flag: Arc<AtomicBool>,

    /// Ticker thread handle
    thread_handle: Option<JoinHandle<()>>,
}

impl Ticker {
    pub fn new() -> Self {
        let run_flag = Arc::new(AtomicBool::new(true));
        let current_tick = Arc::new(AtomicU64::new(0));

        Self {
            current_tick: current_tick.clone(),
            run_flag: run_flag.clone(),
            thread_handle: Some(std::thread::spawn(move || {
                loop {
                    let is_run = run_flag.load(Ordering::Acquire);

                    if !is_run {
                        return;
                    }

                    thread::sleep(TICK_DURATION);

                    current_tick.fetch_add(1, Ordering::Release);
                }
            })),
        }
    }

    #[inline]
    pub fn get_current_tick(&self) -> u64 {
        self.current_tick.load(Ordering::Acquire)
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.run_flag.store(false, Ordering::Release);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}