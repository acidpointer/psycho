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
/// Twelve-light scissored point-shadow accumulation and receiver pass.
pub(super) const POINT_ACCUMULATION_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_point_accumulate.hlsl");
/// Full-resolution screen-space contact visibility pass.
pub(super) const CONTACT_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_contact.hlsl");
/// Deferred full-resolution directional visibility and receiver depth.
pub(super) const DIRECTIONAL_MASK_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_directional_mask.hlsl");
/// Final directional/point shadow compositor.
pub(super) const COMPOSITE_PIXEL_SOURCE: &[u8] =
    include_bytes!("../../../shaders/embedded/shadow_composite.hlsl");
const DIRECTIONAL_COMPOSITE_DEFINE: &[u8] = b"#define OMV_POINT_LIGHTS 0\n";
const POINT_ONLY_COMPOSITE_DEFINE: &[u8] = b"#define OMV_POINT_ONLY 1\n";
const POINT_SUN_COMPETITION_DEFINE: &[u8] = b"#define OMV_POINT_SUN_COMPETITION 1\n";
const FUSED_DIRECTIONAL_DEFINE: &[u8] = b"#define OMV_FUSED_DIRECTIONAL 1\n";

fn fused_exterior_composite_source(point_lights: bool) -> Vec<u8> {
    let point_define = if point_lights {
        &b"#define OMV_POINT_LIGHTS 1\n"[..]
    } else {
        DIRECTIONAL_COMPOSITE_DEFINE
    };
    let mut source = Vec::with_capacity(
        point_define.len()
            + FUSED_DIRECTIONAL_DEFINE.len()
            + DIRECTIONAL_MASK_SOURCE.len()
            + COMPOSITE_PIXEL_SOURCE.len(),
    );
    source.extend_from_slice(point_define);
    source.extend_from_slice(FUSED_DIRECTIONAL_DEFINE);
    source.extend_from_slice(DIRECTIONAL_MASK_SOURCE);
    source.extend_from_slice(COMPOSITE_PIXEL_SOURCE);
    source
}

/// Build the exterior point-light compositor with fused directional work.
pub(super) fn exterior_composite_source() -> Vec<u8> {
    fused_exterior_composite_source(true)
}

/// Build the point-free exterior compositor source used by production/tests.
pub(super) fn directional_composite_source() -> Vec<u8> {
    fused_exterior_composite_source(false)
}

/// Build the point-only compositor used by interior scenes.
///
/// Interiors have no native directional-sun owner. This specialization keeps
/// their accepted five-sample deficit/total path free of exterior depth-normal
/// reconstruction and sunlight constants.
pub(super) fn point_only_composite_source() -> Vec<u8> {
    let mut source =
        Vec::with_capacity(POINT_ONLY_COMPOSITE_DEFINE.len() + COMPOSITE_PIXEL_SOURCE.len());
    source.extend_from_slice(POINT_ONLY_COMPOSITE_DEFINE);
    source.extend_from_slice(COMPOSITE_PIXEL_SOURCE);
    source
}

/// Build the dynamic-only exterior compositor with native sunlight competition.
///
/// This remains separate from both the interior point-only program and the
/// experimental directional-map program. Consequently a disabled sun-map
/// family performs no cascade work, while interiors and the directional path
/// retain their established shader instruction and sampler footprints.
pub(super) fn exterior_point_only_composite_source() -> Vec<u8> {
    let mut source = Vec::with_capacity(
        POINT_ONLY_COMPOSITE_DEFINE.len()
            + POINT_SUN_COMPETITION_DEFINE.len()
            + COMPOSITE_PIXEL_SOURCE.len(),
    );
    source.extend_from_slice(POINT_ONLY_COMPOSITE_DEFINE);
    source.extend_from_slice(POINT_SUN_COMPETITION_DEFINE);
    source.extend_from_slice(COMPOSITE_PIXEL_SOURCE);
    source
}

/// Build a point receiver specialized for the maximum lights in one draw.
///
/// The capacity changes only statically present uniform branches and samplers;
/// all receiver reconstruction and per-light equations remain byte-for-byte
/// shared with the twelve-light program.
///
/// # Panics
///
/// Panics unless `capacity` is one of the three production specializations:
/// 1, 6, or 12.
pub(super) fn point_accumulation_source(capacity: usize) -> Vec<u8> {
    assert!(matches!(capacity, 1 | 6 | 12));
    let define = format!("#define OMV_POINT_CAPACITY {capacity}\n");
    let mut source = Vec::with_capacity(define.len() + POINT_ACCUMULATION_SOURCE.len());
    source.extend_from_slice(define.as_bytes());
    source.extend_from_slice(POINT_ACCUMULATION_SOURCE);
    source
}

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
    /// Scene-depth receiver specialized for one point light.
    pub(super) point_accumulation_one: Vec<u32>,
    /// Scene-depth receiver specialized for up to six point lights.
    pub(super) point_accumulation_six: Vec<u32>,
    /// Scene-depth receiver specialized for up to twelve point lights.
    pub(super) point_accumulation_twelve: Vec<u32>,
    /// Screen-space contact visibility program.
    pub(super) contact: Vec<u32>,
    /// Final scene-color composition program.
    pub(super) composite: Vec<u32>,
    /// Point-only fractional-occlusion composition program.
    pub(super) point_only_composite: Vec<u32>,
    /// Dynamic-only exterior composition with native sunlight competition.
    pub(super) exterior_point_only_composite: Vec<u32>,
    /// Point-free exterior composition specialization.
    pub(super) directional_composite: Vec<u32>,
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
            point_accumulation_one: compile(
                "shadow_point_accumulate_1.hlsl",
                &point_accumulation_source(1),
                "ps_3_0",
            )?,
            point_accumulation_six: compile(
                "shadow_point_accumulate_6.hlsl",
                &point_accumulation_source(6),
                "ps_3_0",
            )?,
            point_accumulation_twelve: compile(
                "shadow_point_accumulate_12.hlsl",
                &point_accumulation_source(12),
                "ps_3_0",
            )?,
            contact: compile("shadow_contact.hlsl", CONTACT_SOURCE, "ps_3_0")?,
            composite: compile(
                "shadow_composite_exterior.hlsl",
                &exterior_composite_source(),
                "ps_3_0",
            )?,
            point_only_composite: compile(
                "shadow_composite_point_only.hlsl",
                &point_only_composite_source(),
                "ps_3_0",
            )?,
            exterior_point_only_composite: compile(
                "shadow_composite_exterior_point_only.hlsl",
                &exterior_point_only_composite_source(),
                "ps_3_0",
            )?,
            directional_composite: compile(
                "shadow_composite_directional.hlsl",
                &directional_composite_source(),
                "ps_3_0",
            )?,
        })
    }

    fn program_metrics(&self) -> (usize, usize) {
        let programs = [
            &self.directional_vertex,
            &self.directional_pixel,
            &self.cube_vertex,
            &self.cube_pixel,
            &self.far_clear_pixel,
            &self.point_accumulation_one,
            &self.point_accumulation_six,
            &self.point_accumulation_twelve,
            &self.contact,
            &self.composite,
            &self.point_only_composite,
            &self.exterior_point_only_composite,
            &self.directional_composite,
        ];
        (programs.len(), programs.into_iter().map(Vec::len).sum())
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
                    let (programs, words) = bytecode.program_metrics();
                    *BYTECODE.lock() = Some(Arc::new(bytecode));
                    PREPARATION_READY.store(true, Ordering::Release);
                    log::info!(
                        "[SHADOWS] Complete shader family prepared ({programs} programs, {words} DWORDs, {} ms)",
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
