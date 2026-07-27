//! Native IOManager parallelism and the shared-state guards it requires.

use crate::config::IoConfig;

mod scheduler;
mod speedtree_lifetime;
mod vertex_buffers;

pub(in crate::mods::engine_fixes) use scheduler::supplemental_priority_guard;

#[derive(Clone, Copy)]
pub(super) struct SafetyStatus {
    pub speedtree_ready: bool,
    pub vertex_buffers_ready: bool,
    /// Whether process-global model scene post-processing is serialized.
    pub model_postprocess_ready: bool,
}

pub(super) struct DiagnosticSnapshot {
    pub scheduler: scheduler::Snapshot,
    pub speedtree: speedtree_lifetime::Snapshot,
    pub vertex_buffers: vertex_buffers::Snapshot,
}

pub(super) fn install(
    config: &IoConfig,
    safety_required_by_lod: bool,
    model_postprocess_ready: bool,
) -> SafetyStatus {
    scheduler::configure(config.parallel_enabled);

    let safety_required = config.parallel_enabled || safety_required_by_lod;
    let speedtree_ready = if safety_required {
        match speedtree_lifetime::install() {
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

    if parallel_prerequisites_ready(
        config.parallel_enabled,
        speedtree_ready,
        vertex_buffers_ready,
        model_postprocess_ready,
    ) {
        if let Err(error) = scheduler::install_parallel_io() {
            log::warn!(
                "[IO] Parallel transaction rolled back; native worker topology retained: {error:#}"
            );
        }
    } else if !config.parallel_enabled {
        log::info!("[IO] Parallel IO not requested by config");
    } else if !model_postprocess_ready {
        log::warn!(
            "[IO] Native worker topology retained because model postprocess serialization is unavailable"
        );
    }

    let scheduler = scheduler::snapshot();
    log::info!(
        "[IO] Active parallel={} speedtree={} vertex_buffers={} model_postprocess={}",
        scheduler.parallel_installed,
        speedtree_ready,
        vertex_buffers_ready,
        model_postprocess_ready,
    );

    SafetyStatus {
        speedtree_ready,
        vertex_buffers_ready,
        model_postprocess_ready,
    }
}

fn parallel_prerequisites_ready(
    requested: bool,
    speedtree_ready: bool,
    vertex_buffers_ready: bool,
    model_postprocess_ready: bool,
) -> bool {
    requested && speedtree_ready && vertex_buffers_ready && model_postprocess_ready
}

pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        scheduler: scheduler::snapshot(),
        speedtree: speedtree_lifetime::snapshot(),
        vertex_buffers: vertex_buffers::snapshot(),
    }
}

#[cfg(test)]
mod tests {
    use super::parallel_prerequisites_ready;

    #[test]
    fn parallel_io_requires_model_postprocess_serialization() {
        assert!(parallel_prerequisites_ready(true, true, true, true));
        assert!(!parallel_prerequisites_ready(true, true, true, false));
        assert!(!parallel_prerequisites_ready(false, true, true, true));
    }
}
