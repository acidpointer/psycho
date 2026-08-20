//! Process-owned native PBR shader preparation.
//!
//! The registry contains logical engine shader identities, not necessarily
//! unique compiler inputs. Preparation groups entries by exact source bytes,
//! target, compiler flags, and contract revision. One canonical cache entry and
//! one `D3DCompile` call then serve every logical alias in that group. Each
//! alias still receives its own readiness/failure state because draw selection
//! and D3D resource ownership are keyed by the engine's SLS identity.
//! Close terrain intentionally does not alias its even/odd pixel pair: the even
//! input preprocesses out supplemental ownership, while the odd input retains
//! the portable-light program. Both are prepared by this same established
//! worker phase before close-terrain readiness can be published.
//!
//! Cache inventory and compilation run entirely on background threads. Worker
//! count is derived from host parallelism, limited to half of the available
//! logical CPUs and capped at eight so Fallout retains CPU headroom while a
//! cold cache is prepared. Verified bytecode is retained across D3D device
//! resets and shared between aliases through `Arc`; no render callback performs
//! shader compilation, cache I/O, grouping, or allocation.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use libpsycho::os::windows::directx9::HLSL_COMPILER_FLAGS;
use parking_lot::Mutex;

use super::shader_registry;

const MAX_WORKER_COUNT: usize = 8;
const BYTECODE_MISSING: u32 = 0;
const BYTECODE_QUEUED: u32 = 1;
const BYTECODE_READY: u32 = 2;
const BYTECODE_FAILED: u32 = 3;
const TEMPLATE_ID_NONE: u32 = u32::MAX;
const SHADER_CONTRACT_REVISION: &[u8] = b"native-pbr-object-lighting-contract-v10";

static STARTED: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU32 = AtomicU32::new(0);
static PHASE: AtomicU32 = AtomicU32::new(PreparationPhase::Dormant as u32);
static CACHE_HITS: AtomicU32 = AtomicU32::new(0);
static CACHE_MISSES: AtomicU32 = AtomicU32::new(0);
static COMPILED: AtomicU32 = AtomicU32::new(0);
static UNIQUE_INPUTS: AtomicU32 = AtomicU32::new(0);
static UNIQUE_CACHE_HITS: AtomicU32 = AtomicU32::new(0);
static UNIQUE_CACHE_MISSES: AtomicU32 = AtomicU32::new(0);
static UNIQUE_COMPILED: AtomicU32 = AtomicU32::new(0);
static COMPILER_WORK_MILLIS: AtomicU32 = AtomicU32::new(0);
static CACHE_WORK_MILLIS: AtomicU32 = AtomicU32::new(0);
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

/// Lifecycle of the process-owned PBR bytecode catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(super) enum PreparationPhase {
    /// No cache inventory or compilation transaction is active.
    Dormant = 0,
    /// The background owner is grouping inputs and validating cache entries.
    Inventory = 1,
    /// One or more workers are compiling and publishing cache misses.
    Compiling = 2,
    /// Every logical template owns verified process bytecode.
    Ready = 3,
    /// At least one logical template could not be prepared.
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

/// Logical-template progress exposed to the OMV runtime and diagnostics UI.
///
/// Counts deliberately remain logical rather than deduplicated so callers can
/// compare them directly with the shader registry and device-resource catalog.
#[derive(Clone, Copy, Debug)]
pub(super) struct PreparationStatus {
    /// Current process-bytecode preparation phase.
    pub(super) phase: PreparationPhase,
    /// Number of engine-visible logical templates in the registry.
    pub(super) total: usize,
    /// Logical templates restored from memory or verified cache entries.
    pub(super) cache_hits: usize,
    /// Logical templates represented by missing unique compiler inputs.
    pub(super) cache_misses: usize,
    /// Logical templates compiled during the current transaction.
    pub(super) compiled: usize,
    /// Logical templates with verified process-owned bytecode.
    pub(super) ready: usize,
    /// Logical templates whose cache or compiler transaction failed.
    pub(super) failed: usize,
}

/// Fields that can change the bytecode produced by the fixed `Main` entry.
///
/// Logical labels and shader families are intentionally absent: they select
/// engine/cache ownership but are not compiler inputs. `Arc<[u8]>` hashes and
/// compares the complete source, so a hash collision cannot merge programs.
#[derive(Clone, Hash, Eq, PartialEq)]
struct CompileInputKey {
    source: Arc<[u8]>,
    target: &'static str,
    compiler_flags: u32,
    contract_revision: &'static [u8],
}

/// One compiler/cache transaction and every logical template it satisfies.
///
/// The lowest registry ID becomes the stable representative whose label and
/// family own the canonical cache path. Alias IDs remain explicit so state and
/// D3D resource publication still match engine SLS identities.
struct CompileGroup {
    representative_id: u16,
    template_ids: Vec<u16>,
    source: Arc<[u8]>,
    cache_spec: crate::shaders::HlslCacheSpec<'static>,
}

impl CompileGroup {
    fn logical_count(&self) -> usize {
        self.template_ids.len()
    }
}

/// Wall-clock anchors shared by all workers in one preparation generation.
#[derive(Clone, Copy)]
struct PreparationTiming {
    started: Instant,
    inventory_elapsed: Duration,
    compilation_started: Option<Instant>,
}

/// Verified output plus per-operation work time for aggregate diagnostics.
///
/// These durations are summed across workers and therefore are work counters,
/// not substitutes for the transaction's wall-clock duration.
struct CompiledGroup {
    bytecode: Vec<u32>,
    compile_elapsed: Duration,
    cache_elapsed: Duration,
}

/// Start the process-owned cache inventory and compiler transaction once.
///
/// This entry point is safe before DeferredInit because it touches only HLSL
/// source, the reconstructible disk cache, atomics, and worker-owned memory. It
/// must never acquire a D3D device, install hooks, or publish world-pipeline
/// state; those owners remain behind the deferred graphics boundary.
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
    UNIQUE_INPUTS.store(0, Ordering::Release);
    UNIQUE_CACHE_HITS.store(0, Ordering::Release);
    UNIQUE_CACHE_MISSES.store(0, Ordering::Release);
    UNIQUE_COMPILED.store(0, Ordering::Release);
    COMPILER_WORK_MILLIS.store(0, Ordering::Release);
    CACHE_WORK_MILLIS.store(0, Ordering::Release);
    LAST_FAILED_TEMPLATE_ID.store(TEMPLATE_ID_NONE, Ordering::Release);
    PHASE.store(PreparationPhase::Inventory as u32, Ordering::Release);
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    let started = Instant::now();

    if let Err(err) = thread::Builder::new()
        .name("omv-pbr-prepare".to_owned())
        .spawn(move || inventory_cache(generation, started))
    {
        log::warn!("[PBR] PBR preparation worker failed to start: {err}");
        FAILED.store(true, Ordering::Release);
        FINISHED.store(true, Ordering::Release);
        PHASE.store(PreparationPhase::Failed as u32, Ordering::Release);
    }
}

/// Cancel the active generation while retaining already verified bytecode.
///
/// Workers observe the generation change before publishing results. A later
/// enable starts a fresh transaction that inventories the retained ready
/// aliases and any cache files completed before cancellation.
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

/// Return shared verified bytecode for one logical template, if prepared.
///
/// The render-side resource service treats a busy publication as not ready and
/// retries on a later presentation instead of waiting for a compiler worker.
pub(super) fn prepared_bytecode(template_id: u16) -> Option<Arc<[u32]>> {
    PREPARED_BYTECODE
        .try_lock()?
        .get(template_id as usize)
        .and_then(Clone::clone)
}

/// Snapshot logical preparation progress without acquiring the bytecode lock.
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

/// Return whether every object template reached a terminal preparation state.
pub(super) fn object_compile_finished() -> bool {
    family_states(0..shader_registry::object_template_count()).all(|state| {
        matches!(
            state.load(Ordering::Acquire),
            BYTECODE_READY | BYTECODE_FAILED
        )
    })
}

/// Return whether the object family has any failure or incomplete final state.
pub(super) fn object_compile_failed() -> bool {
    object_failed_count() != 0
        || (FINISHED.load(Ordering::Acquire)
            && object_ready_count() != shader_registry::object_template_count())
}

/// Count object templates with verified process-owned bytecode.
pub(super) fn object_ready_count() -> usize {
    family_ready_count(0..shader_registry::object_template_count())
}

/// Count object templates whose preparation failed.
pub(super) fn object_failed_count() -> usize {
    family_failed_count(0..shader_registry::object_template_count())
}

/// Return whether the complete land-LOD family owns verified bytecode.
pub(super) fn land_lod_compile_ready() -> bool {
    family_states(land_lod_range()).all(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
}

/// Count land-LOD templates with verified process-owned bytecode.
pub(super) fn land_lod_ready_count() -> usize {
    family_ready_count(land_lod_range())
}

/// Count land-LOD templates whose preparation failed.
pub(super) fn land_lod_failed_count() -> usize {
    family_failed_count(land_lod_range())
}

/// Return whether land-LOD preparation failed or finished incompletely.
pub(super) fn land_lod_compile_failed() -> bool {
    family_states(land_lod_range()).any(|state| state.load(Ordering::Acquire) == BYTECODE_FAILED)
        || (FINISHED.load(Ordering::Acquire) && !land_lod_compile_ready())
}

/// Return whether the complete terrain-fade family owns verified bytecode.
pub(super) fn terrain_fade_compile_ready() -> bool {
    family_states(terrain_fade_range()).all(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
}

/// Count terrain-fade templates with verified process-owned bytecode.
pub(super) fn terrain_fade_ready_count() -> usize {
    family_ready_count(terrain_fade_range())
}

/// Count terrain-fade templates whose preparation failed.
pub(super) fn terrain_fade_failed_count() -> usize {
    family_failed_count(terrain_fade_range())
}

/// Return whether terrain-fade preparation failed or finished incompletely.
pub(super) fn terrain_fade_compile_failed() -> bool {
    family_states(terrain_fade_range())
        .any(|state| state.load(Ordering::Acquire) == BYTECODE_FAILED)
        || (FINISHED.load(Ordering::Acquire) && !terrain_fade_compile_ready())
}

/// Return whether any mandatory close-terrain alias failed preparation.
pub(super) fn close_terrain_compile_failed() -> bool {
    CLOSE_TERRAIN_FAILED.load(Ordering::Acquire)
}

/// Return whether every mandatory close-terrain alias owns verified bytecode.
pub(super) fn close_terrain_compile_ready() -> bool {
    CLOSE_TERRAIN_READY.load(Ordering::Acquire)
}

/// Count close-terrain aliases with verified process-owned bytecode.
pub(super) fn close_terrain_ready_count() -> usize {
    family_ready_count(close_terrain_range())
}

/// Count close-terrain aliases whose preparation failed.
pub(super) fn close_terrain_failed_count() -> usize {
    family_failed_count(close_terrain_range())
}

/// Return the stable label of the most recently failed representative input.
pub(super) fn object_last_failed_template_label() -> &'static str {
    template_label(LAST_FAILED_TEMPLATE_ID.load(Ordering::Acquire))
}

fn inventory_cache(generation: u32, started: Instant) {
    let groups = match build_compile_groups() {
        Ok(groups) => groups,
        Err(err) => {
            if !generation_is_current(generation) {
                return;
            }
            FAILED.store(true, Ordering::Release);
            log::warn!("[PBR] PBR compiler input grouping failed: {err:#}");
            finish_preparation(
                PreparationPhase::Failed,
                PreparationTiming {
                    started,
                    inventory_elapsed: started.elapsed(),
                    compilation_started: None,
                },
            );
            return;
        }
    };
    if !generation_is_current(generation) {
        return;
    }
    let mut misses = Vec::new();
    let mut cache_hits = 0u32;
    let mut unique_cache_hits = 0u32;
    let mut inventory_failed = false;
    UNIQUE_INPUTS.store(groups.len() as u32, Ordering::Release);

    for group in groups {
        if !generation_is_current(generation) {
            return;
        }
        if group_is_prepared(&group) {
            cache_hits = cache_hits.saturating_add(group.logical_count() as u32);
            unique_cache_hits = unique_cache_hits.saturating_add(1);
            continue;
        }

        let cached = load_cached(&group);
        // Cache I/O may wait behind maintenance or another publisher. Recheck
        // after that blocking boundary so a live disable cannot publish ready
        // aliases or failures into the next preparation generation.
        if !generation_is_current(generation) {
            return;
        }
        match cached {
            Ok(Some(bytecode)) => {
                cache_hits = cache_hits.saturating_add(group.logical_count() as u32);
                unique_cache_hits = unique_cache_hits.saturating_add(1);
                publish_ready(&group, bytecode);
            }
            Ok(None) => misses.push(group),
            Err(err) => {
                mark_failed(&group);
                inventory_failed = true;
                log::warn!(
                    "[PBR] PBR cache inventory failed shader={} aliases={}: {err:#}",
                    template_label(u32::from(group.representative_id)),
                    group.logical_count()
                );
            }
        }
    }

    if !generation_is_current(generation) {
        return;
    }
    let missing_logical = misses
        .iter()
        .map(CompileGroup::logical_count)
        .sum::<usize>();
    CACHE_HITS.store(cache_hits, Ordering::Release);
    CACHE_MISSES.store(missing_logical as u32, Ordering::Release);
    UNIQUE_CACHE_HITS.store(unique_cache_hits, Ordering::Release);
    UNIQUE_CACHE_MISSES.store(misses.len() as u32, Ordering::Release);
    log::info!(
        "[PBR] PBR cache inventory: {} valid, {} missing, {} failed; unique_inputs={}, unique_valid={}, unique_missing={}",
        cache_hits,
        missing_logical,
        preparation_status().failed,
        UNIQUE_INPUTS.load(Ordering::Acquire),
        unique_cache_hits,
        misses.len()
    );

    let inventory_elapsed = started.elapsed();
    let timing = PreparationTiming {
        started,
        inventory_elapsed,
        compilation_started: None,
    };

    if inventory_failed {
        finish_preparation(PreparationPhase::Failed, timing);
        return;
    }
    if misses.is_empty() {
        finish_preparation(PreparationPhase::Ready, timing);
        return;
    }

    for group in &misses {
        store_group_state(&STATES, &group.template_ids, BYTECODE_QUEUED);
    }
    PHASE.store(PreparationPhase::Compiling as u32, Ordering::Release);
    let unique_job_count = misses.len();
    let worker_count = selected_worker_count(unique_job_count);
    let queue = Arc::new(Mutex::new(VecDeque::from(misses)));
    let live_workers = Arc::new(AtomicU32::new(worker_count as u32));
    let timing = PreparationTiming {
        compilation_started: Some(Instant::now()),
        ..timing
    };
    log::info!(
        "[PBR] PBR local compilation: {missing_logical} missing logical shader(s), {unique_job_count} unique input(s), {worker_count} worker(s)"
    );

    for worker_index in 0..worker_count {
        let queue = Arc::clone(&queue);
        let worker_live_workers = Arc::clone(&live_workers);
        if let Err(err) = thread::Builder::new()
            .name(format!("omv-pbr-compile-{worker_index}"))
            .spawn(move || {
                compile_worker(generation, worker_index, queue, worker_live_workers, timing)
            })
        {
            log::warn!("[PBR] PBR compile worker {worker_index} failed to start: {err}");
            FAILED.store(true, Ordering::Release);
            if live_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
                finish_workers(generation, timing);
            }
        }
    }
}

fn compile_worker(
    generation: u32,
    worker_index: usize,
    queue: Arc<Mutex<VecDeque<CompileGroup>>>,
    live_workers: Arc<AtomicU32>,
    timing: PreparationTiming,
) {
    while generation_is_current(generation) {
        let Some(job) = queue.lock().pop_front() else {
            break;
        };
        compile_job(generation, worker_index, job);
    }

    if live_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
        finish_workers(generation, timing);
    }
}

fn compile_job(generation: u32, worker_index: usize, group: CompileGroup) {
    let result = compile_and_commit(generation, &group);
    if !generation_is_current(generation) {
        return;
    }

    match result {
        Ok(compiled) => {
            COMPILER_WORK_MILLIS
                .fetch_add(duration_millis(compiled.compile_elapsed), Ordering::AcqRel);
            CACHE_WORK_MILLIS.fetch_add(duration_millis(compiled.cache_elapsed), Ordering::AcqRel);
            publish_ready(&group, compiled.bytecode);
            let logical_count = group.logical_count() as u32;
            let completed = COMPILED.fetch_add(logical_count, Ordering::AcqRel) + logical_count;
            let unique_completed = UNIQUE_COMPILED.fetch_add(1, Ordering::AcqRel) + 1;
            log::debug!(
                "[PBR] PBR local compile worker={worker_index} shader={} aliases={} logical_completed={}/{} unique_completed={}/{} compile_ms={} cache_ms={}",
                template_label(u32::from(group.representative_id)),
                group.logical_count(),
                completed,
                CACHE_MISSES.load(Ordering::Acquire),
                unique_completed,
                UNIQUE_CACHE_MISSES.load(Ordering::Acquire),
                compiled.compile_elapsed.as_millis(),
                compiled.cache_elapsed.as_millis()
            );
        }
        Err(err) => {
            mark_failed(&group);
            log::warn!(
                "[PBR] PBR local compile failed shader={} aliases={}: {err:#}",
                template_label(u32::from(group.representative_id)),
                group.logical_count()
            );
        }
    }
}

fn compile_and_commit(generation: u32, group: &CompileGroup) -> Result<CompiledGroup> {
    let compile_started = Instant::now();
    let bytecode = crate::shaders::compile_hlsl_uncached(
        group.cache_spec.source_name,
        group.source.as_ref(),
        group.cache_spec.target,
    )?;
    let compile_elapsed = compile_started.elapsed();
    if !generation_is_current(generation) {
        anyhow::bail!("PBR preparation was cancelled");
    }
    let cache_started = Instant::now();
    let bytecode =
        crate::shaders::commit_hlsl_cache(group.cache_spec, group.source.as_ref(), &bytecode)?;
    Ok(CompiledGroup {
        bytecode,
        compile_elapsed,
        cache_elapsed: cache_started.elapsed(),
    })
}

fn load_cached(group: &CompileGroup) -> Result<Option<Vec<u32>>> {
    crate::shaders::load_cached_hlsl(group.cache_spec, group.source.as_ref())
}

fn build_compile_groups() -> Result<Vec<CompileGroup>> {
    let mut group_by_input = HashMap::<CompileInputKey, usize>::new();
    let mut groups = Vec::<CompileGroup>::new();
    for template_index in 0..shader_registry::template_count() {
        let template_id = template_index as u16;
        let template = shader_registry::template_at(template_id)
            .ok_or_else(|| anyhow::anyhow!("unknown shader template {template_id}"))?;
        let source: Arc<[u8]> = Arc::from(
            shader_registry::template_source(template_id, template)
                .as_ref()
                .to_vec(),
        );
        let target = shader_registry::shader_profile(template.stage);
        // `source_name` is only a diagnostic name for the fixed compiler API
        // and is not embedded with the current non-debug flags. Existing
        // base/canopy bytecode-equality tests are the negative control: their
        // names differ while their exact source produces identical bytecode.
        let key = CompileInputKey {
            source: Arc::clone(&source),
            target,
            compiler_flags: HLSL_COMPILER_FLAGS,
            contract_revision: SHADER_CONTRACT_REVISION,
        };
        if let Some(&group_index) = group_by_input.get(&key) {
            groups[group_index].template_ids.push(template_id);
            continue;
        }

        let group_index = groups.len();
        group_by_input.insert(key, group_index);
        groups.push(CompileGroup {
            representative_id: template_id,
            template_ids: vec![template_id],
            source,
            cache_spec: cache_spec(template_id, template),
        });
    }
    Ok(groups)
}

fn cache_spec(
    template_id: u16,
    template: &'static shader_registry::ShaderTemplate,
) -> crate::shaders::HlslCacheSpec<'static> {
    crate::shaders::HlslCacheSpec {
        namespace: "native_pbr",
        family: Some(shader_family(template_id)),
        cache_label: template.label,
        source_name: template.label,
        target: shader_registry::shader_profile(template.stage),
        cache_tag: shader_registry::shader_cache_suffix(template.stage),
        contract_revision: SHADER_CONTRACT_REVISION,
    }
}

fn group_is_prepared(group: &CompileGroup) -> bool {
    let bytecode = PREPARED_BYTECODE.lock();
    group.template_ids.iter().all(|template_id| {
        STATES[*template_id as usize].load(Ordering::Acquire) == BYTECODE_READY
            && bytecode[*template_id as usize].is_some()
    })
}

fn publish_ready(group: &CompileGroup, bytecode: Vec<u32>) {
    let bytecode: Arc<[u32]> = Arc::from(bytecode);
    {
        let mut prepared = PREPARED_BYTECODE.lock();
        install_prepared_aliases(&mut prepared, &group.template_ids, bytecode);
    }
    // Publish readiness only after every alias points at the immutable shared
    // payload. A render-side acquire can therefore never observe a ready alias
    // whose bytecode slot is still empty.
    store_group_state(&STATES, &group.template_ids, BYTECODE_READY);
    if group
        .template_ids
        .iter()
        .copied()
        .any(shader_registry::template_is_close_terrain)
        && family_states(close_terrain_range())
            .all(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
    {
        CLOSE_TERRAIN_READY.store(true, Ordering::Release);
    }
}

fn install_prepared_aliases(
    prepared: &mut [Option<Arc<[u32]>>],
    template_ids: &[u16],
    bytecode: Arc<[u32]>,
) {
    for template_id in template_ids {
        prepared[*template_id as usize] = Some(Arc::clone(&bytecode));
    }
}

fn store_group_state(states: &[AtomicU32], template_ids: &[u16], state: u32) {
    for template_id in template_ids {
        states[*template_id as usize].store(state, Ordering::Release);
    }
}

fn mark_failed(group: &CompileGroup) {
    store_group_state(&STATES, &group.template_ids, BYTECODE_FAILED);
    FAILED.store(true, Ordering::Release);
    if group
        .template_ids
        .iter()
        .copied()
        .any(shader_registry::template_is_close_terrain)
    {
        CLOSE_TERRAIN_FAILED.store(true, Ordering::Release);
    }
    LAST_FAILED_TEMPLATE_ID.store(u32::from(group.representative_id), Ordering::Release);
}

fn finish_workers(generation: u32, timing: PreparationTiming) {
    if !generation_is_current(generation) {
        return;
    }
    let phase = if FAILED.load(Ordering::Acquire) || !all_bytecode_ready() {
        PreparationPhase::Failed
    } else {
        PreparationPhase::Ready
    };
    finish_preparation(phase, timing);
}

fn finish_preparation(phase: PreparationPhase, timing: PreparationTiming) {
    FINISHED.store(true, Ordering::Release);
    PHASE.store(phase as u32, Ordering::Release);
    let status = preparation_status();
    match phase {
        PreparationPhase::Ready => log::info!(
            "[PBR] PBR preparation complete: {}/{} locally cached",
            status.ready,
            shader_registry::template_count()
        ),
        PreparationPhase::Failed => log::warn!(
            "[PBR] PBR preparation failed: ready={}, failed={}",
            status.ready,
            status.failed
        ),
        _ => {}
    }
    log::info!(
        "[PBR] PBR preparation timing: total_ms={} inventory_ms={} compile_phase_ms={} compiler_work_ms={} cache_work_ms={} unique_inputs={} unique_compiled={}",
        timing.started.elapsed().as_millis(),
        timing.inventory_elapsed.as_millis(),
        timing
            .compilation_started
            .map_or(0, |started| started.elapsed().as_millis()),
        COMPILER_WORK_MILLIS.load(Ordering::Acquire),
        CACHE_WORK_MILLIS.load(Ordering::Acquire),
        UNIQUE_INPUTS.load(Ordering::Acquire),
        UNIQUE_COMPILED.load(Ordering::Acquire)
    );
}

fn selected_worker_count(job_count: usize) -> usize {
    let parallelism = thread::available_parallelism().map_or(1, usize::from);
    worker_count_for(job_count, parallelism)
}

fn worker_count_for(job_count: usize, parallelism: usize) -> usize {
    if job_count == 0 {
        return 0;
    }
    // Half the logical CPUs preserves capacity for Fallout and other startup
    // workers. The cap also bounds memory if a compiler implementation keeps
    // substantial optimization state per concurrent call.
    let half_parallelism = parallelism.max(1).saturating_add(1) / 2;
    job_count.min(half_parallelism.clamp(1, MAX_WORKER_COUNT))
}

fn duration_millis(duration: Duration) -> u32 {
    // Preparation is finite, but saturating telemetry keeps an unexpected
    // multi-day stall from wrapping a diagnostic counter on the 32-bit target.
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
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

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc, thread};

    use parking_lot::Mutex;

    use super::{
        BYTECODE_FAILED, CompileGroup, build_compile_groups, install_prepared_aliases,
        store_group_state, worker_count_for,
    };
    use crate::effects::pbr::shader_registry::{self, ShaderStage, close_terrain_template_id};

    #[test]
    fn adaptive_worker_policy_reserves_cpu_and_stays_bounded() {
        assert_eq!(worker_count_for(0, 16), 0);
        assert_eq!(worker_count_for(20, 1), 1);
        assert_eq!(worker_count_for(20, 2), 1);
        assert_eq!(worker_count_for(20, 4), 2);
        assert_eq!(worker_count_for(20, 8), 4);
        assert_eq!(worker_count_for(20, 16), 8);
        assert_eq!(worker_count_for(20, 64), 8);
        assert_eq!(worker_count_for(3, 16), 3);
    }

    #[test]
    fn compile_groups_cover_every_logical_template_exactly_once() {
        let groups = build_compile_groups().expect("PBR compile groups");
        let mut template_ids = groups
            .iter()
            .flat_map(|group| group.template_ids.iter().copied())
            .collect::<Vec<_>>();
        template_ids.sort_unstable();
        assert_eq!(
            template_ids,
            (0..shader_registry::template_count() as u16).collect::<Vec<_>>()
        );
        assert_eq!(
            groups.len(),
            160,
            "PBR compiler-input growth requires an explicit preparation-cost review"
        );

        for group in &groups {
            assert_group_inputs_are_identical(group);
        }
    }

    #[test]
    fn close_terrain_fast_and_supplemental_pairs_are_distinct_compiler_inputs() {
        let groups = build_compile_groups().expect("PBR compile groups");
        let close_groups = groups
            .iter()
            .filter(|group| {
                group
                    .template_ids
                    .iter()
                    .copied()
                    .any(shader_registry::template_is_close_terrain)
            })
            .collect::<Vec<_>>();
        assert_eq!(close_groups.len(), 57);
        assert_eq!(
            close_groups
                .iter()
                .map(|group| group.logical_count())
                .sum::<usize>(),
            57
        );

        for base_sls in (2092..=2146).step_by(2) {
            let base = close_terrain_template_id(ShaderStage::Pixel, base_sls).unwrap();
            let canopy = close_terrain_template_id(ShaderStage::Pixel, base_sls + 1).unwrap();
            assert!(
                close_groups
                    .iter()
                    .any(|group| group.template_ids == [base])
            );
            assert!(
                close_groups
                    .iter()
                    .any(|group| group.template_ids == [canopy])
            );
        }
    }

    #[test]
    fn aliases_share_one_bytecode_allocation_and_one_state_transition() {
        let shared: Arc<[u32]> = Arc::from([0xFFFF_0300, 0x0000_FFFF]);
        let mut prepared = vec![None, None, None];
        install_prepared_aliases(&mut prepared, &[0, 2], Arc::clone(&shared));
        assert!(Arc::ptr_eq(prepared[0].as_ref().unwrap(), &shared));
        assert!(prepared[1].is_none());
        assert!(Arc::ptr_eq(prepared[2].as_ref().unwrap(), &shared));

        let states = (0..3)
            .map(|_| std::sync::atomic::AtomicU32::new(0))
            .collect::<Vec<_>>();
        store_group_state(&states, &[0, 2], BYTECODE_FAILED);
        assert_eq!(
            states[0].load(std::sync::atomic::Ordering::Acquire),
            BYTECODE_FAILED
        );
        assert_eq!(states[1].load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(
            states[2].load(std::sync::atomic::Ordering::Acquire),
            BYTECODE_FAILED
        );
    }

    #[test]
    fn legacy_compiler_accepts_eight_concurrent_unique_inputs() {
        let jobs = build_compile_groups()
            .expect("PBR compile groups")
            .into_iter()
            .filter(|group| {
                group
                    .template_ids
                    .iter()
                    .copied()
                    .any(shader_registry::template_is_close_terrain)
                    && group.cache_spec.target == "ps_3_0"
            })
            .take(8)
            .collect::<VecDeque<_>>();
        assert_eq!(jobs.len(), 8);

        // The override is test-only and supports manual scaling sweeps through
        // the game's exact native compiler. Normal repository validation always
        // exercises the production maximum of eight concurrent calls.
        let worker_count = std::env::var("OMV_TEST_PBR_WORKERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(8)
            .clamp(1, 8);
        let jobs = Arc::new(Mutex::new(jobs));
        let failures = Arc::new(Mutex::new(Vec::new()));
        let workers = (0..worker_count)
            .map(|worker_index| {
                let jobs = Arc::clone(&jobs);
                let failures = Arc::clone(&failures);
                thread::spawn(move || {
                    while let Some(group) = jobs.lock().pop_front() {
                        if let Err(err) = crate::shaders::compile_hlsl_uncached(
                            group.cache_spec.source_name,
                            group.source.as_ref(),
                            group.cache_spec.target,
                        ) {
                            failures.lock().push(format!(
                                "worker {worker_index} failed {}: {err:#}",
                                group.cache_spec.source_name
                            ));
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("PBR compiler test worker");
        }
        let failures = failures.lock();
        assert!(
            failures.is_empty(),
            "concurrent PBR compilation failed:\n{}",
            failures.join("\n")
        );
    }

    fn assert_group_inputs_are_identical(group: &CompileGroup) {
        for template_id in &group.template_ids {
            let template = shader_registry::template_at(*template_id).unwrap();
            let source = shader_registry::template_source(*template_id, template);
            assert_eq!(source.as_ref(), group.source.as_ref());
            assert_eq!(
                shader_registry::shader_profile(template.stage),
                group.cache_spec.target
            );
        }
    }
}
