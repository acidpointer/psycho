//! Shader bytecode preparation boundary.
//!
//! The replacement system must not compile HLSL from the draw path. This module
//! compiles object PBR bytecode asynchronously, writes a small cache, and hands
//! ready bytecode to the D3D resource owner.

use std::{
    collections::VecDeque,
    fs,
    mem::size_of,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread,
    time::Instant,
};

use anyhow::Result;
use parking_lot::Mutex;

use super::shader_registry::{self, ShaderStage};

const WORKER_COUNT: usize = 2;
const BYTECODE_MISSING: u32 = 0;
const BYTECODE_QUEUED: u32 = 1;
const BYTECODE_READY: u32 = 2;
const BYTECODE_FAILED: u32 = 3;
const TEMPLATE_ID_NONE: u32 = u32::MAX;

static STARTED: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);
static LAST_FAILED_TEMPLATE_ID: AtomicU32 = AtomicU32::new(TEMPLATE_ID_NONE);
static STATES: LazyLock<Vec<AtomicU32>> = LazyLock::new(|| {
    (0..shader_registry::object_template_count())
        .map(|_| AtomicU32::new(BYTECODE_MISSING))
        .collect()
});
static READY_BYTECODE: LazyLock<Mutex<Vec<CompiledObjectShader>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

#[derive(Clone, Copy)]
struct CompileJob {
    template_id: u16,
}

struct CompiledObjectShader {
    template_id: u16,
    bytecode: Vec<u32>,
}

pub(super) fn ensure_object_prewarm_started() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }

    FINISHED.store(false, Ordering::Release);
    FAILED.store(false, Ordering::Release);

    let jobs = queue_jobs();
    if jobs.is_empty() {
        FINISHED.store(true, Ordering::Release);
        return;
    }

    let job_count = jobs.len();
    let worker_count = WORKER_COUNT.min(job_count).max(1);
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let live_workers = Arc::new(AtomicU32::new(worker_count as u32));

    log::info!("[PBR] Object PBR compile queued {job_count} shader(s) on {worker_count} worker(s)");

    for worker_index in 0..worker_count {
        let queue = Arc::clone(&queue);
        let worker_live_workers = Arc::clone(&live_workers);
        if let Err(err) = thread::Builder::new()
            .name(format!("omv-pbr-object-compile-{worker_index}"))
            .spawn(move || compile_worker(worker_index, queue, worker_live_workers))
        {
            log::warn!("[PBR] Object PBR compile worker {worker_index} failed to start: {err}");
            FAILED.store(true, Ordering::Release);
            if live_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
                FINISHED.store(true, Ordering::Release);
            }
        }
    }
}

pub(super) fn take_ready_bytecode(template_id: u16) -> Option<Vec<u32>> {
    let mut ready = READY_BYTECODE.lock();
    let index = ready
        .iter()
        .position(|entry| entry.template_id == template_id)?;
    Some(ready.swap_remove(index).bytecode)
}

pub(super) fn object_compile_finished() -> bool {
    FINISHED.load(Ordering::Acquire)
}

pub(super) fn object_compile_failed() -> bool {
    FAILED.load(Ordering::Acquire)
}

pub(super) fn object_ready_count() -> usize {
    STATES
        .iter()
        .filter(|state| state.load(Ordering::Acquire) == BYTECODE_READY)
        .count()
}

pub(super) fn object_failed_count() -> usize {
    STATES
        .iter()
        .filter(|state| state.load(Ordering::Acquire) == BYTECODE_FAILED)
        .count()
}

pub(super) fn object_last_failed_template_label() -> &'static str {
    template_label(LAST_FAILED_TEMPLATE_ID.load(Ordering::Acquire))
}

pub(super) fn reset() {
    STARTED.store(false, Ordering::Release);
    FINISHED.store(false, Ordering::Release);
    FAILED.store(false, Ordering::Release);
    LAST_FAILED_TEMPLATE_ID.store(TEMPLATE_ID_NONE, Ordering::Release);
    for state in STATES.iter() {
        state.store(BYTECODE_MISSING, Ordering::Release);
    }
    READY_BYTECODE.lock().clear();
}

fn queue_jobs() -> Vec<CompileJob> {
    let mut jobs = Vec::with_capacity(shader_registry::object_template_count());
    for template_id in 0..shader_registry::object_template_count() {
        if STATES[template_id]
            .compare_exchange(
                BYTECODE_MISSING,
                BYTECODE_QUEUED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            jobs.push(CompileJob {
                template_id: template_id as u16,
            });
        }
    }
    jobs
}

fn compile_worker(
    worker_index: usize,
    queue: Arc<Mutex<VecDeque<CompileJob>>>,
    live_workers: Arc<AtomicU32>,
) {
    loop {
        let Some(job) = queue.lock().pop_front() else {
            if live_workers.fetch_sub(1, Ordering::AcqRel) == 1 {
                FINISHED.store(true, Ordering::Release);
            }
            log::info!("[PBR] Object PBR compile worker {worker_index} finished");
            return;
        };

        compile_job(worker_index, job);
    }
}

fn compile_job(worker_index: usize, job: CompileJob) {
    let started = Instant::now();
    let result = load_or_compile(job);
    match result {
        Ok((bytecode, source)) => {
            READY_BYTECODE.lock().push(CompiledObjectShader {
                template_id: job.template_id,
                bytecode,
            });
            STATES[job.template_id as usize].store(BYTECODE_READY, Ordering::Release);
            if let Some(template) = shader_registry::object_template_at(job.template_id) {
                log::info!(
                    "[PBR] Object PBR compile worker={} shader={} stage={:?} source={} ms={}",
                    worker_index,
                    template.label,
                    template.stage,
                    source,
                    started.elapsed().as_millis()
                );
            } else {
                log::error!(
                    "[PBR] Compiled unknown object shader template {} on worker {}",
                    job.template_id,
                    worker_index
                );
            }
        }
        Err(err) => {
            STATES[job.template_id as usize].store(BYTECODE_FAILED, Ordering::Release);
            FAILED.store(true, Ordering::Release);
            LAST_FAILED_TEMPLATE_ID.store(u32::from(job.template_id), Ordering::Release);
            let label = shader_registry::object_template_at(job.template_id)
                .map(|template| template.label)
                .unwrap_or("unknown");
            log::warn!("[PBR] Object PBR compile failed shader={label}: {err:#}");
        }
    }
}

fn load_or_compile(job: CompileJob) -> Result<(Vec<u32>, &'static str)> {
    let template = shader_registry::object_template_at(job.template_id)
        .ok_or_else(|| anyhow::anyhow!("unknown object shader template {}", job.template_id))?;
    let source = shader_registry::object_template_source(template);
    let source_hash = source_hash(template.stage, template.label, source.as_ref());
    let cache_path = cache_path(template.stage, template.label, source_hash);

    if let Some(bytecode) = read_cache(&cache_path) {
        return Ok((bytecode, "cache"));
    }

    let bytecode = crate::shaders::compile_hlsl_source_target(
        template.label,
        source.as_ref(),
        shader_registry::shader_profile(template.stage),
    )?;
    write_cache(&cache_path, &bytecode);
    Ok((bytecode, "compiler"))
}

fn source_hash(stage: ShaderStage, label: &str, source: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    hash = fnv1a_hash_bytes(hash, label.as_bytes());
    hash = fnv1a_hash_bytes(hash, shader_registry::shader_profile(stage).as_bytes());
    fnv1a_hash_bytes(hash, source)
}

fn fnv1a_hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn cache_path(stage: ShaderStage, label: &str, source_hash: u64) -> PathBuf {
    let mut path = PathBuf::from(crate::config::CONFIG_PATH);
    let _ = path.pop();
    path.push("cache");
    path.push("native_pbr");
    path.push("object");
    path.push(format!(
        "{}_{}_{source_hash:016x}.cso",
        label,
        shader_registry::shader_cache_suffix(stage)
    ));
    path
}

fn read_cache(path: &Path) -> Option<Vec<u32>> {
    let bytes = fs::read(path).ok()?;
    match dword_aligned_bytecode(&bytes) {
        Ok(bytecode) => Some(bytecode),
        Err(err) => {
            log::warn!(
                "[PBR] Ignoring invalid object PBR shader cache '{}': {err:#}",
                path.display()
            );
            None
        }
    }
}

fn write_cache(path: &Path, bytecode: &[u32]) {
    if let Some(parent) = path.parent()
        && let Err(err) = fs::create_dir_all(parent)
    {
        log::warn!(
            "[PBR] Object PBR shader cache directory '{}' could not be created: {err}",
            parent.display()
        );
        return;
    }

    let mut bytes = Vec::with_capacity(std::mem::size_of_val(bytecode));
    for word in bytecode {
        bytes.extend_from_slice(&word.to_le_bytes());
    }

    if let Err(err) = fs::write(path, bytes) {
        log::warn!(
            "[PBR] Object PBR shader cache '{}' could not be written: {err}",
            path.display()
        );
    }
}

fn dword_aligned_bytecode(bytes: &[u8]) -> Result<Vec<u32>> {
    if bytes.is_empty() {
        anyhow::bail!("shader bytecode is empty");
    }
    if bytes.len() % size_of::<u32>() != 0 {
        anyhow::bail!("shader bytecode length is not DWORD aligned");
    }

    Ok(bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn template_label(template_id: u32) -> &'static str {
    if template_id == TEMPLATE_ID_NONE {
        return "none";
    }

    u16::try_from(template_id)
        .ok()
        .and_then(shader_registry::object_template_at)
        .map_or("unknown", |template| template.label)
}
