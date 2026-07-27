//! Shader bytecode preparation boundary.
//!
//! Native PBR source is compiled locally. Preparation inventories the complete
//! content-addressed cache before invoking D3DCompile, compiles only missing
//! entries, verifies every committed cache entry, and retains bytecode across
//! D3D device resets. No render callback performs shader compilation or cache
//! I/O.

use std::{
    collections::VecDeque,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread,
    time::Instant,
};

use anyhow::Result;
use parking_lot::Mutex;

use super::shader_registry;

const WORKER_COUNT: usize = 2;
const BYTECODE_MISSING: u32 = 0;
const BYTECODE_QUEUED: u32 = 1;
const BYTECODE_READY: u32 = 2;
const BYTECODE_FAILED: u32 = 3;
const TEMPLATE_ID_NONE: u32 = u32::MAX;
const SHADER_CONTRACT_REVISION: &[u8] = b"native-pbr-object-lighting-contract-v5";

static STARTED: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU32 = AtomicU32::new(0);
static PHASE: AtomicU32 = AtomicU32::new(PreparationPhase::Dormant as u32);
static CACHE_HITS: AtomicU32 = AtomicU32::new(0);
static CACHE_MISSES: AtomicU32 = AtomicU32::new(0);
static COMPILED: AtomicU32 = AtomicU32::new(0);
static CLOSE_TERRAIN_READY: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_FAILED: AtomicBool = AtomicBool::new(false);
static LAST_FAILED_TEMPLATE_ID: AtomicU32 = AtomicU32::new(TEMPLATE_ID_NONE);
static STATES: LazyLock<Vec<AtomicU32>> = LazyLock::new(|| {
    (0..shader_registry::template_count())
        .map(|_| AtomicU32::new(BYTECODE_MISSING))
        .collect()
});
static PREPARED_BYTECODE: LazyLock<Mutex<Vec<Option<Arc<[u32]>>>>> =
    LazyLock::new(|| Mutex::new(vec![None; shader_registry::template_count()]));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(super) enum PreparationPhase {
    Dormant = 0,
    Inventory = 1,
    Compiling = 2,
    Ready = 3,
    Failed = 4,
}

impl PreparationPhase {
    fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::Inventory,
            2 => Self::Compiling,
            3 => Self::Ready,
            4 => Self::Failed,
            _ => Self::Dormant,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PreparationStatus {
    pub(super) phase: PreparationPhase,
    pub(super) total: usize,
    pub(super) cache_hits: usize,
    pub(super) cache_misses: usize,
    pub(super) compiled: usize,
    pub(super) ready: usize,
    pub(super) failed: usize,
}

#[derive(Clone, Copy)]
struct CompileJob {
    template_id: u16,
}

pub(super) fn ensure_object_prewarm_started() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }

    crate::shaders::start_shader_cache_maintenance();
    if all_bytecode_ready() {
        FINISHED.store(true, Ordering::Release);
        PHASE.store(PreparationPhase::Ready as u32, Ordering::Release);
        return;
    }

    FINISHED.store(false, Ordering::Release);
    FAILED.store(false, Ordering::Release);
    CLOSE_TERRAIN_FAILED.store(false, Ordering::Release);
    CLOSE_TERRAIN_READY.store(
        family_states(close_terrain_range())
            .all(|state| state.load(Ordering::Acquire) == BYTECODE_READY),
        Ordering::Release,
    );
    CACHE_HITS.store(0, Ordering::Release);
    CACHE_MISSES.store(0, Ordering::Release);
    COMPILED.store(0, Ordering::Release);
    LAST_FAILED_TEMPLATE_ID.store(TEMPLATE_ID_NONE, Ordering::Release);
    PHASE.store(PreparationPhase::Inventory as u32, Ordering::Release);
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel).wrapping_add(1);

    if let Err(err) = thread::Builder::new()
        .name("omv-pbr-prepare".to_owned())
        .spawn(move || inventory_cache(generation))
    {
        log::warn!("[PBR] PBR preparation worker failed to start: {err}");
        FAILED.store(true, Ordering::Release);
        FINISHED.store(true, Ordering::Release);
        PHASE.store(PreparationPhase::Failed as u32, Ordering::Release);
    }
}

pub(super) fn cancel_preparation() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    STARTED.store(false, Ordering::Release);
    FINISHED.store(false, Ordering::Release);
    PHASE.store(PreparationPhase::Dormant as u32, Ordering::Release);
    for state in STATES.iter() {
        if state.load(Ordering::Acquire) != BYTECODE_READY {
            state.store(BYTECODE_MISSING, Ordering::Release);
        }
    }
}

pub(super) fn prepared_bytecode(template_id: u16) -> Option<Arc<[u32]>> {
    PREPARED_BYTECODE
        .lock()
        .get(template_id as usize)
        .and_then(Clone::clone)
}

pub(super) fn preparation_status() -> PreparationStatus {
    PreparationStatus {
        phase: PreparationPhase::from_raw(PHASE.load(Ordering::Acquire)),
        total: shader_registry::template_count(),
        cache_hits: CACHE_HITS.load(Ordering::Acquire) as usize,
        cache_misses: CACHE_MISSES.load(Ordering::Acquire) as usize,
        compiled: COMPILED.load(Ordering::Acquire) as usize,
        ready: STATES
            .iter()
            .filter(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
            .count(),
        failed: STATES
            .iter()
            .filter(|state| state.load(Ordering::Acquire) == BYTECODE_FAILED)
            .count(),
    }
}

pub(super) fn preparation_ready() -> bool {
    PHASE.load(Ordering::Acquire) == PreparationPhase::Ready as u32 && all_bytecode_ready()
}

pub(super) fn object_compile_finished() -> bool {
    family_states(0..shader_registry::object_template_count()).all(|state| {
        matches!(
            state.load(Ordering::Acquire),
            BYTECODE_READY | BYTECODE_FAILED
        )
    })
}

pub(super) fn object_compile_failed() -> bool {
    object_failed_count() != 0
        || (FINISHED.load(Ordering::Acquire)
            && object_ready_count() != shader_registry::object_template_count())
}

pub(super) fn object_ready_count() -> usize {
    family_ready_count(0..shader_registry::object_template_count())
}

pub(super) fn object_failed_count() -> usize {
    family_failed_count(0..shader_registry::object_template_count())
}

pub(super) fn land_lod_compile_ready() -> bool {
    family_states(land_lod_range()).all(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
}

pub(super) fn land_lod_ready_count() -> usize {
    family_ready_count(land_lod_range())
}

pub(super) fn land_lod_failed_count() -> usize {
    family_failed_count(land_lod_range())
}

pub(super) fn land_lod_compile_failed() -> bool {
    family_states(land_lod_range()).any(|state| state.load(Ordering::Acquire) == BYTECODE_FAILED)
        || (FINISHED.load(Ordering::Acquire) && !land_lod_compile_ready())
}

pub(super) fn terrain_fade_compile_ready() -> bool {
    family_states(terrain_fade_range()).all(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
}

pub(super) fn terrain_fade_ready_count() -> usize {
    family_ready_count(terrain_fade_range())
}

pub(super) fn terrain_fade_failed_count() -> usize {
    family_failed_count(terrain_fade_range())
}

pub(super) fn terrain_fade_compile_failed() -> bool {
    family_states(terrain_fade_range())
        .any(|state| state.load(Ordering::Acquire) == BYTECODE_FAILED)
        || (FINISHED.load(Ordering::Acquire) && !terrain_fade_compile_ready())
}

pub(super) fn close_terrain_compile_failed() -> bool {
    CLOSE_TERRAIN_FAILED.load(Ordering::Acquire)
}

pub(super) fn close_terrain_compile_ready() -> bool {
    CLOSE_TERRAIN_READY.load(Ordering::Acquire)
}

pub(super) fn close_terrain_ready_count() -> usize {
    family_ready_count(close_terrain_range())
}

pub(super) fn close_terrain_failed_count() -> usize {
    family_failed_count(close_terrain_range())
}

pub(super) fn object_last_failed_template_label() -> &'static str {
    template_label(LAST_FAILED_TEMPLATE_ID.load(Ordering::Acquire))
}

fn inventory_cache(generation: u32) {
    let mut misses = Vec::new();
    let mut cache_hits = 0u32;
    let mut inventory_failed = false;

    for template_id in 0..shader_registry::template_count() {
        if !generation_is_current(generation) {
            return;
        }
        if STATES[template_id].load(Ordering::Acquire) == BYTECODE_READY
            && PREPARED_BYTECODE.lock()[template_id].is_some()
        {
            cache_hits = cache_hits.saturating_add(1);
            continue;
        }

        let job = CompileJob {
            template_id: template_id as u16,
        };
        match load_cached(job) {
            Ok(Some(bytecode)) => {
                publish_ready(job.template_id, bytecode);
                cache_hits = cache_hits.saturating_add(1);
            }
            Ok(None) => misses.push(job),
            Err(err) => {
                mark_failed(job.template_id);
                inventory_failed = true;
                log::warn!(
                    "[PBR] PBR cache inventory failed shader={}: {err:#}",
                    template_label(u32::from(job.template_id))
                );
            }
        }
    }

    if !generation_is_current(generation) {
        return;
    }
    CACHE_HITS.store(cache_hits, Ordering::Release);
    CACHE_MISSES.store(misses.len() as u32, Ordering::Release);
    log::info!(
        "[PBR] PBR cache inventory: {} valid, {} missing, {} failed",
        cache_hits,
        misses.len(),
        if inventory_failed { 1 } else { 0 }
    );

    if inventory_failed {
        finish_preparation(PreparationPhase::Failed);
        return;
    }
    if misses.is_empty() {
        finish_preparation(PreparationPhase::Ready);
        return;
    }

    for job in &misses {
        STATES[job.template_id as usize].store(BYTECODE_QUEUED, Ordering::Release);
    }
    PHASE.store(PreparationPhase::Compiling as u32, Ordering::Release);
    let job_count = misses.len();
    let worker_count = WORKER_COUNT.min(job_count).max(1);
    let queue = Arc::new(Mutex::new(VecDeque::from(misses)));
    let live_workers = Arc::new(AtomicU32::new(worker_count as u32));
    log::info!(
        "[PBR] PBR local compilation: {job_count} missing shader(s) on {worker_count} worker(s)"
    );

    for worker_index in 0..worker_count {
        let queue = Arc::clone(&queue);
        let worker_live_workers = Arc::clone(&live_workers);
        if let Err(err) = thread::Builder::new()
            .name(format!("omv-pbr-compile-{worker_index}"))
            .spawn(move || compile_worker(generation, worker_index, queue, worker_live_workers))
        {
            log::warn!("[PBR] PBR compile worker {worker_index} failed to start: {err}");
            FAILED.store(true, Ordering::Release);
            if live_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
                finish_workers(generation);
            }
        }
    }
}

fn compile_worker(
    generation: u32,
    worker_index: usize,
    queue: Arc<Mutex<VecDeque<CompileJob>>>,
    live_workers: Arc<AtomicU32>,
) {
    while generation_is_current(generation) {
        let Some(job) = queue.lock().pop_front() else {
            break;
        };
        compile_job(generation, worker_index, job);
    }

    if live_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
        finish_workers(generation);
    }
}

fn compile_job(generation: u32, worker_index: usize, job: CompileJob) {
    let started = Instant::now();
    let result = compile_and_commit(generation, job);
    if !generation_is_current(generation) {
        return;
    }

    match result {
        Ok(bytecode) => {
            publish_ready(job.template_id, bytecode);
            let completed = COMPILED.fetch_add(1, Ordering::AcqRel) + 1;
            log::debug!(
                "[PBR] PBR local compile worker={worker_index} shader={} completed={}/{} ms={}",
                template_label(u32::from(job.template_id)),
                completed,
                CACHE_MISSES.load(Ordering::Acquire),
                started.elapsed().as_millis()
            );
        }
        Err(err) => {
            mark_failed(job.template_id);
            log::warn!(
                "[PBR] PBR local compile failed shader={}: {err:#}",
                template_label(u32::from(job.template_id))
            );
        }
    }
}

fn compile_and_commit(generation: u32, job: CompileJob) -> Result<Vec<u32>> {
    let (template, source, spec) = shader_input(job)?;
    let bytecode =
        crate::shaders::compile_hlsl_uncached(template.label, source.as_ref(), spec.target)?;
    if !generation_is_current(generation) {
        anyhow::bail!("PBR preparation was cancelled");
    }
    crate::shaders::commit_hlsl_cache(spec, source.as_ref(), &bytecode)
}

fn load_cached(job: CompileJob) -> Result<Option<Vec<u32>>> {
    let (_, source, spec) = shader_input(job)?;
    crate::shaders::load_cached_hlsl(spec, source.as_ref())
}

fn shader_input(
    job: CompileJob,
) -> Result<(
    &'static shader_registry::ShaderTemplate,
    std::borrow::Cow<'static, [u8]>,
    crate::shaders::HlslCacheSpec<'static>,
)> {
    let template = shader_registry::template_at(job.template_id)
        .ok_or_else(|| anyhow::anyhow!("unknown shader template {}", job.template_id))?;
    let source = shader_registry::template_source(job.template_id, template);
    let spec = crate::shaders::HlslCacheSpec {
        namespace: "native_pbr",
        family: Some(shader_family(job.template_id)),
        cache_label: template.label,
        source_name: template.label,
        target: shader_registry::shader_profile(template.stage),
        cache_tag: shader_registry::shader_cache_suffix(template.stage),
        contract_revision: SHADER_CONTRACT_REVISION,
    };
    Ok((template, source, spec))
}

fn publish_ready(template_id: u16, bytecode: Vec<u32>) {
    PREPARED_BYTECODE.lock()[template_id as usize] = Some(Arc::from(bytecode));
    STATES[template_id as usize].store(BYTECODE_READY, Ordering::Release);
    if shader_registry::template_is_close_terrain(template_id)
        && family_states(close_terrain_range())
            .all(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
    {
        CLOSE_TERRAIN_READY.store(true, Ordering::Release);
    }
}

fn mark_failed(template_id: u16) {
    STATES[template_id as usize].store(BYTECODE_FAILED, Ordering::Release);
    FAILED.store(true, Ordering::Release);
    if shader_registry::template_is_close_terrain(template_id) {
        CLOSE_TERRAIN_FAILED.store(true, Ordering::Release);
    }
    LAST_FAILED_TEMPLATE_ID.store(u32::from(template_id), Ordering::Release);
}

fn finish_workers(generation: u32) {
    if !generation_is_current(generation) {
        return;
    }
    let phase = if FAILED.load(Ordering::Acquire) || !all_bytecode_ready() {
        PreparationPhase::Failed
    } else {
        PreparationPhase::Ready
    };
    finish_preparation(phase);
}

fn finish_preparation(phase: PreparationPhase) {
    FINISHED.store(true, Ordering::Release);
    PHASE.store(phase as u32, Ordering::Release);
    match phase {
        PreparationPhase::Ready => log::info!(
            "[PBR] PBR preparation complete: {}/{} locally cached",
            preparation_status().ready,
            shader_registry::template_count()
        ),
        PreparationPhase::Failed => log::warn!(
            "[PBR] PBR preparation failed: ready={}, failed={}",
            preparation_status().ready,
            preparation_status().failed
        ),
        _ => {}
    }
}

fn generation_is_current(generation: u32) -> bool {
    GENERATION.load(Ordering::Acquire) == generation
}

fn all_bytecode_ready() -> bool {
    STATES
        .iter()
        .all(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
}

fn shader_family(template_id: u16) -> &'static str {
    if shader_registry::template_is_land_lod(template_id) {
        "land_lod"
    } else if shader_registry::template_is_terrain_fade(template_id) {
        "terrain_fade"
    } else if shader_registry::template_is_close_terrain(template_id) {
        "close_terrain"
    } else {
        "object"
    }
}

fn template_label(template_id: u32) -> &'static str {
    if template_id == TEMPLATE_ID_NONE {
        return "none";
    }

    u16::try_from(template_id)
        .ok()
        .and_then(shader_registry::template_at)
        .map_or("unknown", |template| template.label)
}

fn family_states(range: std::ops::Range<usize>) -> impl Iterator<Item = &'static AtomicU32> {
    STATES[range].iter()
}

fn family_ready_count(range: std::ops::Range<usize>) -> usize {
    family_states(range)
        .filter(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
        .count()
}

fn family_failed_count(range: std::ops::Range<usize>) -> usize {
    family_states(range)
        .filter(|state| state.load(Ordering::Acquire) == BYTECODE_FAILED)
        .count()
}

fn land_lod_range() -> std::ops::Range<usize> {
    let start = shader_registry::object_template_count();
    start..start + 2
}

fn terrain_fade_range() -> std::ops::Range<usize> {
    let start = land_lod_range().end;
    start..start + 2
}

fn close_terrain_range() -> std::ops::Range<usize> {
    terrain_fade_range().end..shader_registry::template_count()
}
