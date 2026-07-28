//! Background discovery for live shader and LUT assets.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result};

use crate::{
    luts::{self, LutCatalog},
    shaders::{self, ScreenShaderSource},
};

const MIN_SCAN_INTERVAL_MS: u64 = 50;
const MAX_SCAN_INTERVAL_MS: u64 = 5_000;
const MAX_SCAN_ERROR_LOGS: u32 = 8;

pub(crate) struct AssetCatalogSnapshot {
    pub(crate) shader_generation: u64,
    pub(crate) lut_generation: u64,
    pub(crate) external_sources: Vec<ScreenShaderSource>,
    pub(crate) color_luts: LutCatalog,
}

pub(crate) struct AssetScanner {
    enabled: Arc<AtomicBool>,
    force_scan: Arc<AtomicBool>,
    interval_ms: Arc<AtomicU64>,
    receiver: Receiver<AssetCatalogSnapshot>,
    stop: Arc<AtomicBool>,
    worker: thread::Thread,
}

impl AssetScanner {
    pub(crate) fn start(interval_ms: u64, enabled: bool) -> Result<Self> {
        let enabled = Arc::new(AtomicBool::new(enabled));
        let force_scan = Arc::new(AtomicBool::new(true));
        let interval_ms = Arc::new(AtomicU64::new(sanitize_interval(interval_ms)));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_enabled = Arc::clone(&enabled);
        let worker_force_scan = Arc::clone(&force_scan);
        let worker_interval = Arc::clone(&interval_ms);
        let worker_stop = Arc::clone(&stop);
        let (sender, receiver) = sync_channel(1);
        let worker = thread::Builder::new()
            .name("omv-asset-scan".to_owned())
            .spawn(move || {
                scan_worker(
                    worker_enabled,
                    worker_force_scan,
                    worker_interval,
                    worker_stop,
                    sender,
                )
            })
            .context("failed to start shader/LUT asset scanner")?;
        let worker_thread = worker.thread().clone();
        drop(worker);
        Ok(Self {
            enabled,
            force_scan,
            interval_ms,
            receiver,
            stop,
            worker: worker_thread,
        })
    }

    pub(crate) fn reconfigure(&self, interval_ms: u64, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        self.interval_ms
            .store(sanitize_interval(interval_ms), Ordering::Release);
        self.worker.unpark();
    }

    pub(crate) fn request_scan(&self) {
        self.force_scan.store(true, Ordering::Release);
        self.worker.unpark();
    }

    pub(crate) fn try_take_latest(&self) -> Option<AssetCatalogSnapshot> {
        let mut latest = None;
        loop {
            match self.receiver.try_recv() {
                Ok(snapshot) => latest = Some(snapshot),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return latest,
            }
        }
    }
}

impl Drop for AssetScanner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.unpark();
    }
}

fn scan_worker(
    enabled: Arc<AtomicBool>,
    force_scan: Arc<AtomicBool>,
    interval_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    sender: SyncSender<AssetCatalogSnapshot>,
) {
    let mut external_sources = Vec::new();
    let mut color_luts = LutCatalog::default();
    let mut shader_generation = 0u64;
    let mut lut_generation = 0u64;
    let mut pending = None;
    let mut error_logs = 0u32;

    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        let continuously_enabled = enabled.load(Ordering::Acquire);
        let scan_requested = force_scan.swap(false, Ordering::AcqRel);
        if !should_scan(continuously_enabled, scan_requested) {
            thread::park();
            continue;
        }
        let mut catalog_changed = false;

        match luts::scan_luts(&color_luts) {
            Ok(scan) => {
                for warning in scan.warnings {
                    log_scan_warning(&mut error_logs, format_args!("[LUT] {warning}"));
                }
                if lut_generation == 0 || scan.resources_changed {
                    lut_generation = lut_generation.wrapping_add(1).max(1);
                    catalog_changed = true;
                }
                color_luts = scan.catalog;
            }
            Err(err) => log_scan_warning(
                &mut error_logs,
                format_args!("[LUT] Live LUT scan failed: {err:#}"),
            ),
        }

        match shaders::scan_screen_shaders(&external_sources) {
            Ok(scan) => {
                if shader_generation == 0 || scan.shader_resources_changed {
                    shader_generation = shader_generation.wrapping_add(1).max(1);
                    catalog_changed = true;
                }
                external_sources = scan.sources;
            }
            Err(err) => log_scan_warning(
                &mut error_logs,
                format_args!("[SHADERS] Live shader scan failed: {err:#}"),
            ),
        }

        if shader_generation == 0 {
            shader_generation = 1;
            catalog_changed = true;
        }
        if lut_generation == 0 {
            lut_generation = 1;
            catalog_changed = true;
        }
        if catalog_changed {
            pending = Some(AssetCatalogSnapshot {
                shader_generation,
                lut_generation,
                external_sources: external_sources.clone(),
                color_luts: color_luts.clone(),
            });
        }

        if let Some(snapshot) = pending.take() {
            match sender.try_send(snapshot) {
                Ok(()) => {}
                Err(TrySendError::Full(snapshot)) => pending = Some(snapshot),
                Err(TrySendError::Disconnected(_)) => return,
            }
        }

        if continuously_enabled {
            thread::park_timeout(Duration::from_millis(interval_ms.load(Ordering::Acquire)));
        } else if force_scan.load(Ordering::Acquire) {
            continue;
        } else {
            thread::park();
        }
    }
}

fn should_scan(continuously_enabled: bool, scan_requested: bool) -> bool {
    continuously_enabled || scan_requested
}

fn sanitize_interval(interval_ms: u64) -> u64 {
    interval_ms.clamp(MIN_SCAN_INTERVAL_MS, MAX_SCAN_INTERVAL_MS)
}

fn log_scan_warning(error_logs: &mut u32, message: std::fmt::Arguments<'_>) {
    if *error_logs >= MAX_SCAN_ERROR_LOGS {
        return;
    }
    log::warn!("{message}");
    *error_logs += 1;
}

#[cfg(test)]
mod tests {
    use super::{sanitize_interval, should_scan};

    #[test]
    fn scan_interval_is_bounded_away_from_busy_polling() {
        assert_eq!(sanitize_interval(0), 50);
        assert_eq!(sanitize_interval(200), 200);
        assert_eq!(sanitize_interval(20_000), 5_000);
    }

    #[test]
    fn disabled_effects_allow_explicit_catalog_refresh_without_polling() {
        assert!(!should_scan(false, false));
        assert!(should_scan(false, true));
        assert!(should_scan(true, false));
    }
}
