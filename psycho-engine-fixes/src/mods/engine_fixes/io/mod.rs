//! Native IOManager parallelism and the shared-state guards it requires.

use crate::config::{DiagnosticsConfig, IoConfig};

mod scheduler;
mod speedtree_lifetime;
mod vertex_buffers;

#[derive(Clone, Copy)]
pub(super) struct SafetyStatus {
    pub speedtree_ready: bool,
    pub vertex_buffers_ready: bool,
}

pub(super) struct DiagnosticSnapshot {
    pub scheduler: scheduler::Snapshot,
    pub speedtree: speedtree_lifetime::Snapshot,
    pub vertex_buffers: vertex_buffers::Snapshot,
}

pub(super) fn install(
    config: &IoConfig,
    diagnostics: &DiagnosticsConfig,
    safety_required_by_lod: bool,
) -> SafetyStatus {
    scheduler::configure(config.parallel_enabled);

    let safety_required = config.parallel_enabled || safety_required_by_lod;
    let speedtree_ready = if safety_required {
        match speedtree_lifetime::install(diagnostics.lod_streaming_trace) {
            Ok(()) => true,
            Err(error) => {
                log::warn!("[IO] SpeedTree shared-state guards unavailable: {error:#}");
                false
            }
        }
    } else {
        false
    };
    let vertex_buffers_ready = if safety_required {
        match vertex_buffers::install() {
            Ok(()) => true,
            Err(error) => {
                log::warn!("[IO] Static vertex-buffer guards unavailable: {error:#}");
                false
            }
        }
    } else {
        false
    };

    if config.parallel_enabled && speedtree_ready && vertex_buffers_ready {
        if let Err(error) = scheduler::install_parallel_io() {
            log::warn!(
                "[IO] Parallel transaction rolled back; native worker topology retained: {error:#}"
            );
        }
    } else if !config.parallel_enabled {
        log::info!("[IO] Parallel IO not requested by config");
    }

    let scheduler = scheduler::snapshot();
    log::info!(
        "[IO] Active parallel={} speedtree={} vertex_buffers={}",
        scheduler.parallel_installed,
        speedtree_ready,
        vertex_buffers_ready,
    );

    SafetyStatus {
        speedtree_ready,
        vertex_buffers_ready,
    }
}

pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        scheduler: scheduler::snapshot(),
        speedtree: speedtree_lifetime::snapshot(),
        vertex_buffers: vertex_buffers::snapshot(),
    }
}
