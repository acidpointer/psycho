//! Native LOD demand and current-reference handoff ownership.
//!
//! The core installs transactional hooks at its existing startup boundary.
//! Native managers continue to own blocks, tasks, dependencies, visibility,
//! scene publication, and destruction; this module extends eligible demand
//! and observes real membership/readiness transitions. Worldspace and cell
//! resets invalidate sidecar identity. Invalid geometry retains native demand;
//! ambiguous handoff membership keeps coverage. Demand hooks allocate nothing,
//! take no locks, and do no IO or scene mutation.

use std::{
    ffi::c_void,
    ptr,
    sync::{
        LazyLock, OnceLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, ensure};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::transaction::ModificationTransaction, patch::OwnedCodePatch, winapi::virtual_query,
    },
};

use crate::{
    config::{DiagnosticsConfig, LodConfig},
    mods::diagnostics::should_log_power_of_two,
};

use super::{io::SafetyStatus, patching, statics, types::GameSettingFloatFn};

mod coverage;
mod distance;
mod membership;
mod metrics;
mod native;
mod scheduler;
mod service;
mod state;
mod task_observation;
mod terrain_lifetime;

const NODE_LEVEL_OFFSET: usize = 0x04;
const MANAGER_ROOT_LEVEL_OFFSET: usize = 0x1C;
const TERRAIN_BLOCK_OFFSET: usize = 0x10;
const OBJECT_BLOCK_OFFSET: usize = 0x14;
const TREE_BLOCK_OFFSET: usize = 0x18;
const NODE_CENTER_X_OFFSET: usize = 0x34;
const NODE_CENTER_Y_OFFSET: usize = 0x38;
const TERRAIN_DISTANCE_OFFSET: usize = 0x44;
const LOD_BLOCK_WORLD_SIZE_ADDR: usize = 0x0101_7A10;

const CELL_VWD_TOTAL_OFFSET: usize = 0xA8;
const CELL_VWD_READY_OFFSET: usize = 0xAA;

const ALTERNATE_REMOVE_CALL_ORIGINAL: [u8; 5] = [0xE8, 0x99, 0x03, 0x00, 0x00];
const ALTERNATE_REMOVE_CALL_MASK: [u8; 5] = [0xFF, 0x00, 0x00, 0x00, 0x00];
const READY_CALL_ORIGINAL: [u8; 5] = [0xE8, 0xC7, 0x02, 0x00, 0x00];
const READY_CALL_MASK: [u8; 5] = [0xFF, 0x00, 0x00, 0x00, 0x00];

const TERRAIN: usize = 0;
const OBJECT: usize = 1;
const TREE: usize = 2;

#[derive(Clone, Copy)]
struct RuntimeConfig {
    trace: bool,
    object_prefetch: f32,
    object_retention: f32,
    tree_prefetch: f32,
    tree_retention: f32,
    terrain_prefetch: f32,
    terrain_retention: f32,
}

impl From<&LodConfig> for RuntimeConfig {
    fn from(config: &LodConfig) -> Self {
        Self {
            trace: false,
            object_prefetch: config.object_prefetch_multiplier,
            object_retention: config.object_retention_multiplier,
            tree_prefetch: config.tree_prefetch_multiplier,
            tree_retention: config.tree_retention_multiplier,
            terrain_prefetch: config.terrain_prefetch_multiplier,
            terrain_retention: config.terrain_retention_multiplier,
        }
    }
}

/// Provider ownership, installation state, and process-wide diagnostic counts.
///
/// State collection briefly locks the identity ledger and does not dereference
/// its engine-address keys. Concurrent observations are not policy inputs.
pub(super) struct DiagnosticSnapshot {
    pub streaming_installed: bool,
    pub handoff_installed: bool,
    pub worldspace_reset_installed: bool,
    pub alternate_remove_predecessor: usize,
    pub alternate_removals: u64,
    pub alternate_remove_mismatches: u64,
    pub ready_predecessor: usize,
    pub ready_predecessor_mismatches: u64,
    pub membership: membership::Snapshot,
    pub demand: metrics::Snapshot,
    pub scheduler: scheduler::Snapshot,
    pub state: state::Snapshot,
}

/// Lock-free counters for the existing helper dashboard ABI.
pub(super) struct DashboardSnapshot {
    pub streaming_installed: bool,
    pub handoff_installed: bool,
    pub demand: metrics::Snapshot,
    pub state: state::DashboardCounters,
}

static CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();
static STREAMING_INSTALLED: AtomicBool = AtomicBool::new(false);
static HANDOFF_INSTALLED: AtomicBool = AtomicBool::new(false);
static PREFETCH_ADMITTED: AtomicBool = AtomicBool::new(false);
static ALTERNATE_REMOVE_PREDECESSOR: AtomicUsize =
    AtomicUsize::new(statics::LOD_CELL_ALTERNATE_DECREMENT_ADDR);
static ALTERNATE_REMOVALS: AtomicU32 = AtomicU32::new(0);
static ALTERNATE_REMOVE_MISMATCHES: AtomicU32 = AtomicU32::new(0);
static READY_PREDECESSOR: AtomicUsize = AtomicUsize::new(statics::LOD_READY_INCREMENT_ADDR);
static READY_PREDECESSOR_MISMATCHES: AtomicU32 = AtomicU32::new(0);

static ALTERNATE_REMOVE_CALL_REPLACEMENT: LazyLock<[u8; 5]> = LazyLock::new(|| {
    let displacement = (alternate_remove_entry as *const () as usize)
        .wrapping_sub(statics::LOD_ALTERNATE_REMOVE_CALL_ADDR + 5) as i32;
    let mut replacement = [0u8; 5];
    replacement[0] = 0xE8;
    replacement[1..].copy_from_slice(&displacement.to_le_bytes());
    replacement
});

static ALTERNATE_REMOVE_CALL_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    OwnedCodePatch::masked(
        "lod_alternate_remove_call",
        statics::LOD_ALTERNATE_REMOVE_CALL_ADDR,
        &ALTERNATE_REMOVE_CALL_ORIGINAL,
        &ALTERNATE_REMOVE_CALL_MASK,
        &*ALTERNATE_REMOVE_CALL_REPLACEMENT,
    )
});

static READY_CALL_REPLACEMENT: LazyLock<[u8; 5]> = LazyLock::new(|| {
    let displacement = (ready_publication_entry as *const () as usize)
        .wrapping_sub(statics::LOD_READY_INCREMENT_CALL_ADDR + 5) as i32;
    let mut replacement = [0u8; 5];
    replacement[0] = 0xE8;
    replacement[1..].copy_from_slice(&displacement.to_le_bytes());
    replacement
});

static READY_CALL_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    OwnedCodePatch::masked(
        "lod_ready_publication_call",
        statics::LOD_READY_INCREMENT_CALL_ADDR,
        &READY_CALL_ORIGINAL,
        &READY_CALL_MASK,
        &*READY_CALL_REPLACEMENT,
    )
});

/// Install requested LOD groups at the core's existing quiescent startup point.
///
/// Configuration is published once. Missing IO safety or conflicting providers
/// leave the affected group native; each group owns transactional rollback.
/// This function logs installation outcomes and must not race engine execution.
pub(super) fn install(config: &LodConfig, diagnostics: &DiagnosticsConfig, safety: SafetyStatus) {
    // Native terrain retirement needs an owning cancellation reference even
    // when streaming, handoff, trace and priority policies are disabled.
    if let Err(error) = terrain_lifetime::install() {
        log::error!(
            "[LOD] Terrain task ownership fix unavailable; ownership intervention not admitted: {error:#}"
        );
    }
    scheduler::configure(config.enabled && config.priority_boost_enabled);
    if !config.enabled {
        log::info!("[LOD] Streaming and handoff fixes disabled by config");
        return;
    }

    if config.validation_adjusted {
        log::warn!(
            "[LOD] Invalid distance multipliers were clamped or replaced with safe defaults"
        );
    }
    let mut runtime = RuntimeConfig::from(config);
    runtime.trace = diagnostics.lod_streaming_trace;
    if CONFIG.set(runtime).is_err() {
        log::warn!("[LOD] Runtime configuration was already published");
        return;
    }
    state::configure_trace(diagnostics.lod_streaming_trace);
    metrics::configure(diagnostics.lod_streaming_trace);

    if !config.prefetch_enabled
        && !config.handoff_fix_enabled
        && !config.priority_boost_enabled
        && !config.attachment_budget_enabled
        && !diagnostics.lod_streaming_trace
    {
        log::info!("[LOD] All LOD subfeatures disabled by config");
        return;
    }

    let reset_ready = if config.prefetch_enabled
        || config.handoff_fix_enabled
        || config.priority_boost_enabled
        || diagnostics.lod_streaming_trace
    {
        match prepare_worldspace_reset_hook() {
            Ok(()) => true,
            Err(error) => {
                log::warn!(
                    "[LOD] Prefetch and handoff disabled: worldspace reset hook unavailable: {error:#}"
                );
                false
            }
        }
    } else {
        false
    };

    if config.priority_boost_enabled || diagnostics.lod_streaming_trace {
        if let Err(error) = scheduler::install() {
            log::warn!(
                "[LOD] Priority boost transaction rolled back; native priority retained: {error:#}"
            );
        }
    } else {
        log::info!("[LOD] Native priority boost disabled by config");
    }

    let prefetch_admitted = config.prefetch_enabled
        && safety.speedtree_ready
        && safety.vertex_buffers_ready
        && safety.model_postprocess_ready;
    if reset_ready
        && (prefetch_admitted || config.priority_boost_enabled || diagnostics.lod_streaming_trace)
    {
        match install_streaming_hooks() {
            Ok(()) => {
                STREAMING_INSTALLED.store(prefetch_admitted, Ordering::Release);
                PREFETCH_ADMITTED.store(prefetch_admitted, Ordering::Release);
            }
            Err(error) => log::warn!(
                "[LOD] Native prefetch transaction rolled back; vanilla demand retained: {error:#}"
            ),
        }
    } else if !config.prefetch_enabled {
        log::info!("[LOD] Native prefetch disabled by config");
    }

    if config.attachment_budget_enabled
        || config.priority_boost_enabled
        || diagnostics.lod_streaming_trace
    {
        if let Err(error) = service::install(config.attachment_budget_enabled) {
            log::warn!(
                "[LOD] Attachment service transaction rolled back; full native drain retained: {error:#}"
            );
        }
    }
    task_observation::admit(
        config.priority_boost_enabled
            && service::installed()
            && scheduler::snapshot().priority_installed
            && statics::LOD_OBJECT_DEMAND_HOOK.is_enabled()
            && statics::LOD_WORLDSPACE_RESET_HOOK.is_enabled(),
    );

    if config.handoff_fix_enabled && reset_ready {
        match install_handoff_hooks() {
            Ok(()) => HANDOFF_INSTALLED.store(true, Ordering::Release),
            Err(error) => log::warn!(
                "[LOD] Identity handoff transaction rolled back; vanilla counters retained: {error:#}"
            ),
        }
    } else if !config.handoff_fix_enabled {
        log::info!("[LOD] Identity handoff fix disabled by config");
    }

    if diagnostics.lod_streaming_trace {
        if !HANDOFF_INSTALLED.load(Ordering::Acquire) {
            let ready = prepare_ready_callsite().and_then(|()| {
                let mut transaction = ModificationTransaction::new();
                transaction.apply_patch(&READY_CALL_PATCH)?;
                transaction.commit();
                Ok(())
            });
            if let Err(error) = ready {
                log::warn!(
                    "[LOD] Ready trace unavailable; attachment credits uncorrelated: {error:#}"
                );
            }
        }
        if let Err(error) = metrics::install() {
            log::warn!(
                "[LOD] Native stage trace transaction rolled back; stage measurements unavailable: {error:#}"
            );
        }
    }

    let runtime = CONFIG.get().expect("LOD configuration was published");
    let scheduler = scheduler::snapshot();
    log::info!(
        "[LOD] Active streaming={} handoff={} priority={} trace={} object={:.2}/{:.2} tree={:.2}/{:.2} terrain={:.2}/{:.2}",
        STREAMING_INSTALLED.load(Ordering::Acquire),
        HANDOFF_INSTALLED.load(Ordering::Acquire),
        scheduler.priority_installed,
        diagnostics.lod_streaming_trace,
        runtime.object_prefetch,
        runtime.object_retention,
        runtime.tree_prefetch,
        runtime.tree_retention,
        runtime.terrain_prefetch,
        runtime.terrain_retention,
    );
}

fn prepare_worldspace_reset_hook() -> anyhow::Result<()> {
    if statics::LOD_WORLDSPACE_RESET_HOOK.is_initialized() {
        return Ok(());
    }
    unsafe {
        statics::LOD_WORLDSPACE_RESET_HOOK.init(
            "lod_worldspace_reset",
            statics::LOD_WORLDSPACE_RESET_ADDR as *mut c_void,
            hook_worldspace_reset,
        )
    }
    .context("prepare LOD worldspace reset hook")
}

fn install_streaming_hooks() -> anyhow::Result<()> {
    unsafe {
        statics::LOD_TERRAIN_DEMAND_HOOK.init(
            "lod_terrain_prefetch",
            statics::LOD_TERRAIN_DEMAND_ADDR as *mut c_void,
            hook_terrain_demand,
        )?;
        statics::LOD_OBJECT_DEMAND_HOOK.init(
            "lod_object_prefetch",
            statics::LOD_OBJECT_DEMAND_ADDR as *mut c_void,
            hook_object_demand,
        )?;
        statics::LOD_TREE_DEMAND_HOOK.init(
            "lod_tree_prefetch",
            statics::LOD_TREE_DEMAND_ADDR as *mut c_void,
            hook_tree_demand,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::LOD_TERRAIN_DEMAND_HOOK)?;
    transaction.enable_inline(&statics::LOD_OBJECT_DEMAND_HOOK)?;
    transaction.enable_inline(&statics::LOD_TREE_DEMAND_HOOK)?;
    if !statics::LOD_WORLDSPACE_RESET_HOOK.is_enabled() {
        transaction.enable_inline(&statics::LOD_WORLDSPACE_RESET_HOOK)?;
    }
    transaction.commit();
    Ok(())
}

fn install_handoff_hooks() -> anyhow::Result<()> {
    prepare_alternate_remove_callsite()?;
    prepare_ready_callsite()?;
    unsafe {
        statics::LOD_CELL_READY_GATE_HOOK.init(
            "lod_cell_ready_gate",
            statics::LOD_CELL_READY_GATE_ADDR as *mut c_void,
            hook_cell_ready_gate,
        )?;
        statics::LOD_CELL_TEARDOWN_HOOK.init(
            "lod_cell_teardown",
            statics::LOD_CELL_TEARDOWN_ADDR as *mut c_void,
            hook_cell_teardown,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    if !statics::LOD_WORLDSPACE_RESET_HOOK.is_enabled() {
        transaction.enable_inline(&statics::LOD_WORLDSPACE_RESET_HOOK)?;
    }
    membership::install(&mut transaction)?;
    coverage::install(&mut transaction)?;
    transaction.enable_inline(&statics::LOD_CELL_TEARDOWN_HOOK)?;
    transaction.enable_inline(&statics::LOD_CELL_READY_GATE_HOOK)?;
    transaction.apply_patch(&ALTERNATE_REMOVE_CALL_PATCH)?;
    transaction.apply_patch(&READY_CALL_PATCH)?;
    transaction.commit();
    Ok(())
}

fn prepare_alternate_remove_callsite() -> anyhow::Result<()> {
    unsafe {
        patching::verify_bytes(
            statics::LOD_ALTERNATE_REMOVE_CALL_PREFIX_ADDR,
            &statics::LOD_ALTERNATE_REMOVE_CALL_PREFIX_BYTES,
        )?;
        patching::verify_bytes(
            statics::LOD_ALTERNATE_REMOVE_CALL_SUFFIX_ADDR,
            &statics::LOD_ALTERNATE_REMOVE_CALL_SUFFIX_BYTES,
        )?;
    }
    let predecessor =
        unsafe { patching::relative_call_target(statics::LOD_ALTERNATE_REMOVE_CALL_ADDR) }
            .context("read LOD alternate removal predecessor")?;
    ensure!(
        predecessor != alternate_remove_entry as *const () as usize,
        "LOD alternate removal call already points to Psycho"
    );
    ensure!(
        is_executable(predecessor),
        "LOD alternate removal predecessor 0x{predecessor:08X} is not executable"
    );
    ALTERNATE_REMOVE_PREDECESSOR.store(predecessor, Ordering::Release);
    ALTERNATE_REMOVE_CALL_PATCH.verify()?;
    Ok(())
}

fn prepare_ready_callsite() -> anyhow::Result<()> {
    unsafe {
        patching::verify_bytes(
            statics::LOD_READY_CALL_PREFIX_ADDR,
            &statics::LOD_READY_CALL_PREFIX_BYTES,
        )?;
        patching::verify_bytes(
            statics::LOD_READY_CALL_SUFFIX_ADDR,
            &statics::LOD_READY_CALL_SUFFIX_BYTES,
        )?;
    }
    let predecessor =
        unsafe { patching::relative_call_target(statics::LOD_READY_INCREMENT_CALL_ADDR) }
            .context("read LOD ready publication predecessor")?;
    ensure!(
        predecessor != ready_publication_entry as *const () as usize,
        "LOD ready publication call already points to Psycho"
    );
    ensure!(
        is_executable(predecessor),
        "LOD ready predecessor 0x{predecessor:08X} is not executable"
    );
    READY_PREDECESSOR.store(predecessor, Ordering::Release);
    READY_CALL_PATCH.verify()?;
    Ok(())
}

unsafe extern "thiscall" fn hook_terrain_demand(node: *mut c_void, camera: *const f32) -> u8 {
    let vanilla = call_demand_original(&statics::LOD_TERRAIN_DEMAND_HOOK, node, camera);
    extend_demand(TERRAIN, node, camera, vanilla, TERRAIN_BLOCK_OFFSET)
}

unsafe extern "thiscall" fn hook_object_demand(node: *mut c_void, camera: *const f32) -> u8 {
    let vanilla = call_demand_original(&statics::LOD_OBJECT_DEMAND_HOOK, node, camera);
    extend_demand(OBJECT, node, camera, vanilla, OBJECT_BLOCK_OFFSET)
}

unsafe extern "thiscall" fn hook_tree_demand(node: *mut c_void, camera: *const f32) -> u8 {
    let vanilla = call_demand_original(&statics::LOD_TREE_DEMAND_HOOK, node, camera);
    extend_demand(TREE, node, camera, vanilla, TREE_BLOCK_OFFSET)
}

fn call_demand_original(
    hook: &'static LazyLock<
        libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer<
            super::types::LodDemandFn,
        >,
    >,
    node: *mut c_void,
    camera: *const f32,
) -> u8 {
    let Ok(original) = hook.original() else {
        return 0;
    };
    unsafe { original(node, camera) }
}

fn extend_demand(
    kind: usize,
    node: *mut c_void,
    camera: *const f32,
    vanilla: u8,
    block_offset: usize,
) -> u8 {
    scheduler::visible_demand(kind, node as usize, vanilla != 0);
    let config = CONFIG.get();
    let trace = config
        .filter(|config| config.trace)
        .and_then(|_| metrics::begin(kind));
    if vanilla != 0 {
        scheduler::clear_speculative(kind, node);
        return vanilla;
    }

    let Some(config) = config else {
        return vanilla;
    };
    if !PREFETCH_ADMITTED.load(Ordering::Acquire) {
        return vanilla;
    }
    // Native demand is the common path. Fetch settings and extra geometry
    // only after AL says false, avoiding redundant getter calls in that path.
    let base_distance = match kind {
        TERRAIN => terrain_base_distance(node),
        OBJECT => setting_distance(statics::BLOCK_LOAD_DISTANCE_SETTING),
        TREE => setting_distance(statics::TREE_LOAD_DISTANCE_SETTING),
        _ => return vanilla,
    };
    let Some(base_distance) =
        base_distance.filter(|distance| distance.is_finite() && *distance > 0.0)
    else {
        return vanilla;
    };
    let Some(distance) = node_distance(node, camera) else {
        return vanilla;
    };
    let loaded = read_pointer(node, block_offset).is_some_and(|pointer| !pointer.is_null());
    let (prefetch, retention) = match kind {
        TERRAIN => (config.terrain_prefetch, config.terrain_retention),
        OBJECT => (config.object_prefetch, config.object_retention),
        TREE => (config.tree_prefetch, config.tree_retention),
        _ => return vanilla,
    };
    let multiplier = if loaded { retention } else { prefetch };
    if distance < base_distance * multiplier {
        if let Some(trace) = trace {
            trace.extended(loaded);
        }
        if loaded {
            scheduler::clear_speculative(kind, node);
        } else {
            scheduler::mark_speculative(kind, node);
        }
        1
    } else {
        if loaded && let Some(trace) = trace {
            trace.release();
        }
        scheduler::clear_speculative(kind, node);
        vanilla
    }
}

fn node_distance(node: *mut c_void, camera: *const f32) -> Option<f32> {
    if node.is_null() || camera.is_null() {
        return None;
    }
    let camera_x = unsafe { ptr::read_unaligned(camera) };
    let camera_y = unsafe { ptr::read_unaligned(camera.add(1)) };
    let center_x = read_f32(node, NODE_CENTER_X_OFFSET)?;
    let center_y = read_f32(node, NODE_CENTER_Y_OFFSET)?;
    let level = f64::from(read_u32(node, NODE_LEVEL_OFFSET)?);
    // Supported native predicates multiply the unsigned level by this double
    // and then store a float. Reading its low float word would yield zero.
    let unit = unsafe { ptr::read_unaligned(LOD_BLOCK_WORLD_SIZE_ADDR as *const f64) };
    let size = (level * unit) as f32;
    distance::distance_to_block([camera_x, camera_y], [center_x, center_y], size)
}

fn terrain_base_distance(node: *mut c_void) -> Option<f32> {
    // 0x006FE550 rejects the manager's root level before testing distance.
    // Prefetch may extend a distance rejection, never that structural one.
    let manager = read_pointer(node, 0)?;
    let root = read_u32(manager, MANAGER_ROOT_LEVEL_OFFSET)?;
    if read_u32(node, NODE_LEVEL_OFFSET)? == root {
        return None;
    }
    read_f32(node, TERRAIN_DISTANCE_OFFSET)
}

fn setting_distance(setting_address: usize) -> Option<f32> {
    let accessor = unsafe {
        FnPtr::<GameSettingFloatFn>::from_address_unchecked(statics::FLOAT_SETTING_ACCESSOR_ADDR)
    }
    .as_fn();
    // Native callers pass the setting object's address in ECX. Its first
    // word is a vtable, not an indirection to another setting object.
    let value = unsafe { accessor(setting_address as *mut c_void) };
    if value.is_null() {
        None
    } else {
        Some(unsafe { ptr::read_unaligned(value) })
    }
}

unsafe extern "fastcall" fn hook_worldspace_reset(owner: *mut c_void) {
    scheduler::reset_speculative();
    state::reset_worldspace();
    task_observation::reset();
    metrics::reset();
    if let Ok(original) = statics::LOD_WORLDSPACE_RESET_HOOK.original() {
        unsafe { original(owner) };
    }
}

unsafe extern "fastcall" fn hook_cell_teardown(cell: *mut c_void) {
    state::teardown_cell(
        cell,
        read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET).unwrap_or(i16::MIN),
        read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN),
    );
    if let Ok(original) = statics::LOD_CELL_TEARDOWN_HOOK.original() {
        unsafe { original(cell) };
    }
}

unsafe extern "fastcall" fn hook_cell_ready_gate(cell: *mut c_void) -> u8 {
    unsafe { membership::reconcile(cell) };
    let vanilla = statics::LOD_CELL_READY_GATE_HOOK
        .original()
        .map(|original| unsafe { original(cell) != 0 })
        .unwrap_or(false);
    let native_total = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET).unwrap_or(i16::MIN);
    let native_ready = read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN);
    u8::from(state::ready_gate(cell, native_total, native_ready, vanilla))
}

#[unsafe(naked)]
unsafe extern "fastcall" fn alternate_remove_entry(_cell: *mut c_void) {
    core::arch::naked_asm!(
        "mov edx, [ebp - 0x68]",
        "jmp {}",
        sym alternate_remove_body,
    );
}

unsafe extern "fastcall" fn alternate_remove_body(cell: *mut c_void, reference: *mut c_void) {
    let total_before = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET);
    let predecessor = ALTERNATE_REMOVE_PREDECESSOR.load(Ordering::Acquire);
    if predecessor != 0 && predecessor != alternate_remove_entry as *const () as usize {
        let function =
            unsafe { FnPtr::<super::types::LodCellOwnerFn>::from_address_unchecked(predecessor) }
                .as_fn();
        unsafe { function(cell) };
    }

    let total_after = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET);
    let ready_after = read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN);
    if counter_decreased(total_before, total_after) && !reference.is_null() {
        ALTERNATE_REMOVALS.fetch_add(1, Ordering::Relaxed);
        state::retire_enrollment(cell as usize, reference as usize);
        return;
    }

    let count = ALTERNATE_REMOVE_MISMATCHES.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log_power_of_two(u64::from(count)) {
        log::warn!(
            "[LOD] Alternate removal predecessor did not preserve the exact transaction cell=0x{:08X} ref=0x{:08X} before={:?} after={:?} count={count}",
            cell as usize,
            reference as usize,
            total_before,
            total_after,
        );
    }
    state::mark_uncertain(cell, total_after.unwrap_or(i16::MIN), ready_after);
}

#[unsafe(naked)]
unsafe extern "fastcall" fn ready_publication_entry(_cell: *mut c_void) {
    core::arch::naked_asm!(
        "mov edx, [ebp + 8]",
        "jmp {}",
        sym ready_publication_body,
    );
}

unsafe extern "fastcall" fn ready_publication_body(cell: *mut c_void, reference: *mut c_void) {
    let identity = if HANDOFF_INSTALLED.load(Ordering::Acquire) {
        state::ready_identity(cell as usize, reference as usize)
    } else {
        None
    };
    let ready_before = read_cell_counter(cell, CELL_VWD_READY_OFFSET);
    let predecessor = READY_PREDECESSOR.load(Ordering::Acquire);
    if predecessor != 0 && predecessor != ready_publication_entry as *const () as usize {
        let function = unsafe {
            FnPtr::<super::types::LodReadyIncrementFn>::from_address_unchecked(predecessor)
        }
        .as_fn();
        unsafe { function(cell) };
    }

    let native_total = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET).unwrap_or(i16::MIN);
    let ready_after = read_cell_counter(cell, CELL_VWD_READY_OFFSET);
    if counter_increased(ready_before, ready_after) {
        let accepted = if HANDOFF_INSTALLED.load(Ordering::Acquire) {
            state::observe_ready(
                cell,
                reference,
                native_total,
                ready_after.unwrap_or(i16::MIN),
                identity,
            )
        } else {
            false
        };
        metrics::ready(cell as usize, reference as usize, accepted);
    } else {
        let count = READY_PREDECESSOR_MISMATCHES.fetch_add(1, Ordering::Relaxed) + 1;
        if should_log_power_of_two(u64::from(count)) {
            log::warn!(
                "[LOD] Ready predecessor did not publish exactly one credit cell=0x{:08X} ref=0x{:08X} before={:?} after={:?} count={count}",
                cell as usize,
                reference as usize,
                ready_before,
                ready_after,
            );
        }
        if HANDOFF_INSTALLED.load(Ordering::Acquire) {
            state::mark_uncertain(cell, native_total, ready_after.unwrap_or(i16::MIN));
        }
    }
}

fn read_cell_counter(cell: *mut c_void, offset: usize) -> Option<i16> {
    if cell.is_null() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned((cell as *const u8).add(offset) as *const i16) })
}

fn counter_increased(before: Option<i16>, after: Option<i16>) -> bool {
    before
        .zip(after)
        .is_some_and(|(before, after)| after == before.wrapping_add(1))
}

fn counter_decreased(before: Option<i16>, after: Option<i16>) -> bool {
    before
        .zip(after)
        .is_some_and(|(before, after)| after == before.wrapping_sub(1))
}

fn read_f32(base: *mut c_void, offset: usize) -> Option<f32> {
    if base.is_null() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned((base as *const u8).add(offset) as *const f32) })
}

fn read_u32(base: *mut c_void, offset: usize) -> Option<u32> {
    if base.is_null() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned((base as *const u8).add(offset) as *const u32) })
}

fn read_pointer(base: *mut c_void, offset: usize) -> Option<*mut c_void> {
    if base.is_null() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned((base as *const u8).add(offset) as *const *mut c_void) })
}

fn is_executable(address: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    virtual_query(address as *mut c_void).is_ok_and(|info| info.is_executable())
}

/// Collect installation/provider state and diagnostic counts without engine IO.
pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        streaming_installed: STREAMING_INSTALLED.load(Ordering::Acquire),
        handoff_installed: HANDOFF_INSTALLED.load(Ordering::Acquire),
        worldspace_reset_installed: statics::LOD_WORLDSPACE_RESET_HOOK.is_enabled(),
        alternate_remove_predecessor: ALTERNATE_REMOVE_PREDECESSOR.load(Ordering::Acquire),
        alternate_removals: u64::from(ALTERNATE_REMOVALS.load(Ordering::Relaxed)),
        alternate_remove_mismatches: u64::from(ALTERNATE_REMOVE_MISMATCHES.load(Ordering::Relaxed)),
        ready_predecessor: READY_PREDECESSOR.load(Ordering::Acquire),
        ready_predecessor_mismatches: u64::from(
            READY_PREDECESSOR_MISMATCHES.load(Ordering::Relaxed),
        ),
        membership: membership::snapshot(),
        demand: metrics::snapshot(),
        scheduler: scheduler::snapshot(),
        state: state::snapshot(),
    }
}

/// Collect atomic dashboard counts without taking the handoff ledger lock.
pub(super) fn dashboard_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        streaming_installed: STREAMING_INSTALLED.load(Ordering::Acquire),
        handoff_installed: HANDOFF_INSTALLED.load(Ordering::Acquire),
        demand: metrics::snapshot(),
        state: state::dashboard_counters(),
    }
}

/// Append the bounded enabled handoff trace to the caller-owned report buffer.
///
/// May grow `out`; intended only for explicit diagnostic reports, not hot paths.
pub(super) fn append_trace_report(out: &mut String) {
    state::append_trace_report(out);
    coverage::append_report(out);
    service::append_report(out);
    task_observation::append_report(out);
    metrics::append_report(out);
}
