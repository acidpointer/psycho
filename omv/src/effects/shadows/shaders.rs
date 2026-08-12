//! Immutable shader sources and verified process-owned bytecode catalog.
//!
//! The generation equations and register layout are adapted from modern New
//! Vegas Reloaded under GPL-3.0-or-later. OMV keeps those inputs recognizable,
//! while the resource topology and deferred consumers are OMV-specific.

use std::{
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Instant,
};

use anyhow::Result;
use parking_lot::Mutex;

/// Quality-preserving directional caster vertex shader.
pub(super) const DIRECTIONAL_VERTEX_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_directional.vs.hlsl");
/// FP16 EVSM4 directional caster pixel shader.
pub(super) const DIRECTIONAL_PIXEL_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_directional.hlsl");
/// Radial-depth point-cube vertex shader.
pub(super) const CUBE_VERTEX_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_cube.vs.hlsl");
/// Radial-depth point-cube pixel shader.
pub(super) const CUBE_PIXEL_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_cube.hlsl");
/// Exact far-depth EVSM4 clear shader used before caster submission.
pub(super) const FAR_CLEAR_PIXEL_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_far_clear.hlsl");
/// Coverage-bounded point receiver geometry shared by all light batches.
pub(super) const POINT_GEOMETRY_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_point_geometry.hlsl");
/// Six-light scissored point-shadow accumulation pass.
pub(super) const POINT_ACCUMULATION_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_point_accumulate.hlsl");
/// Half-resolution screen-space contact visibility pass.
pub(super) const CONTACT_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_contact.hlsl");
/// Depth-aware separable contact filter.
pub(super) const CONTACT_BLUR_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_contact_blur.hlsl");
/// Camera-reprojected contact-history resolve with depth rejection.
pub(super) const CONTACT_TEMPORAL_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_contact_temporal.hlsl");
/// Final directional/point shadow compositor.
pub(super) const COMPOSITE_PIXEL_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_composite.hlsl");

static PREPARATION_STARTED: AtomicBool = AtomicBool::new(false);
static PREPARATION_READY: AtomicBool = AtomicBool::new(false);
static PREPARATION_FAILED: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Option<Arc<ShadowBytecode>>>> = LazyLock::new(|| Mutex::new(None));

/// Complete immutable bytecode family required by shadow production/consume.
pub(super) struct ShadowBytecode {
    /// Directional caster vertex program.
    pub(super) directional_vertex: Vec<u32>,
    /// Directional EVSM4 caster pixel program.
    pub(super) directional_pixel: Vec<u32>,
    /// Point-cube caster vertex program.
    pub(super) cube_vertex: Vec<u32>,
    /// Point-cube radial-depth pixel program.
    pub(super) cube_pixel: Vec<u32>,
    /// Exact EVSM4 far-moment clear program.
    pub(super) far_clear_pixel: Vec<u32>,
    /// Shared point receiver-geometry program.
    pub(super) point_geometry: Vec<u32>,
    /// Six-cube point-shadow accumulation program.
    pub(super) point_accumulation: Vec<u32>,
    /// Screen-space contact visibility program.
    pub(super) contact: Vec<u32>,
    /// Depth-aware contact filter program.
    pub(super) contact_blur: Vec<u32>,
    /// Camera-reprojected contact-history resolve program.
    pub(super) contact_temporal: Vec<u32>,
    /// Final scene-color composition program.
    pub(super) composite: Vec<u32>,
}

impl ShadowBytecode {
    fn compile() -> Result<Self> {
        Ok(Self {
            directional_vertex: compile(
                "shadow_directional.vs.hlsl",
                DIRECTIONAL_VERTEX_SOURCE,
                "vs_3_0",
            )?,
            directional_pixel: compile(
                "shadow_directional.hlsl",
                DIRECTIONAL_PIXEL_SOURCE,
                "ps_3_0",
            )?,
            cube_vertex: compile("shadow_cube.vs.hlsl", CUBE_VERTEX_SOURCE, "vs_3_0")?,
            cube_pixel: compile("shadow_cube.hlsl", CUBE_PIXEL_SOURCE, "ps_3_0")?,
            far_clear_pixel: compile("shadow_far_clear.hlsl", FAR_CLEAR_PIXEL_SOURCE, "ps_3_0")?,
            point_geometry: compile(
                "shadow_point_geometry.hlsl",
                POINT_GEOMETRY_SOURCE,
                "ps_3_0",
            )?,
            point_accumulation: compile(
                "shadow_point_accumulate.hlsl",
                POINT_ACCUMULATION_SOURCE,
                "ps_3_0",
            )?,
            contact: compile("shadow_contact.hlsl", CONTACT_SOURCE, "ps_3_0")?,
            contact_blur: compile("shadow_contact_blur.hlsl", CONTACT_BLUR_SOURCE, "ps_3_0")?,
            contact_temporal: compile(
                "shadow_contact_temporal.hlsl",
                CONTACT_TEMPORAL_SOURCE,
                "ps_3_0",
            )?,
            composite: compile("shadow_composite.hlsl", COMPOSITE_PIXEL_SOURCE, "ps_3_0")?,
        })
    }

    fn program_words(&self) -> usize {
        [
            &self.directional_vertex,
            &self.directional_pixel,
            &self.cube_vertex,
            &self.cube_pixel,
            &self.far_clear_pixel,
            &self.point_geometry,
            &self.point_accumulation,
            &self.contact,
            &self.contact_blur,
            &self.contact_temporal,
            &self.composite,
        ]
        .into_iter()
        .map(Vec::len)
        .sum()
    }
}

fn compile(name: &str, source: &[u8], target: &str) -> Result<Vec<u32>> {
    crate::shaders::compile_hlsl_source_target(name, source, target)
}

/// Start shadow shader compilation after the `DeferredInit` safety boundary.
///
/// This function is idempotent. It owns no engine or D3D object and publishes
/// bytecode only after the entire family compiled successfully.
pub(super) fn start_preparation() {
    if PREPARATION_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Err(error) = thread::Builder::new()
        .name("omv-shadows-compile".to_owned())
        .spawn(|| {
            let started = Instant::now();
            match crate::effects::shader_preparation::run_serialized(ShadowBytecode::compile) {
                Ok(bytecode) => {
                    let words = bytecode.program_words();
                    *BYTECODE.lock() = Some(Arc::new(bytecode));
                    PREPARATION_READY.store(true, Ordering::Release);
                    log::info!(
                        "[SHADOWS] Complete shader family prepared (10 programs, {words} DWORDs, {} ms)",
                        started.elapsed().as_millis()
                    );
                }
                Err(error) => {
                    PREPARATION_FAILED.store(true, Ordering::Release);
                    log::warn!("[SHADOWS] Shader preparation failed: {error:#}");
                }
            }
        })
    {
        PREPARATION_FAILED.store(true, Ordering::Release);
        log::warn!("[SHADOWS] Could not start shader preparation: {error}");
    }
}

/// Borrow the complete bytecode family through a cheap shared owner.
pub(super) fn prepared_bytecode() -> Option<Arc<ShadowBytecode>> {
    if !PREPARATION_READY.load(Ordering::Acquire) || PREPARATION_FAILED.load(Ordering::Acquire) {
        return None;
    }
    BYTECODE.try_lock()?.as_ref().cloned()
}
