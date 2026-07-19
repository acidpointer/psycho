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

use super::{patching, statics, types::GameSettingFloatFn};

mod scheduler;
mod speedtree_lifetime;
mod state;
mod vertex_buffers;

const NODE_LEVEL_OFFSET: usize = 0x04;
const TERRAIN_BLOCK_OFFSET: usize = 0x10;
const OBJECT_BLOCK_OFFSET: usize = 0x14;
const TREE_BLOCK_OFFSET: usize = 0x18;
const NODE_ORIGIN_X_OFFSET: usize = 0x34;
const NODE_ORIGIN_Y_OFFSET: usize = 0x38;
const TERRAIN_DISTANCE_OFFSET: usize = 0x44;
const LOD_BLOCK_WORLD_SIZE_ADDR: usize = 0x0101_7A10;

const CELL_VWD_TOTAL_OFFSET: usize = 0xA8;
const CELL_VWD_READY_OFFSET: usize = 0xAA;

const READY_CALL_ORIGINAL: [u8; 5] = [0xE8, 0xC7, 0x02, 0x00, 0x00];
const READY_CALL_MASK: [u8; 5] = [0xFF, 0x00, 0x00, 0x00, 0x00];

const TERRAIN: usize = 0;
const OBJECT: usize = 1;
const TREE: usize = 2;

#[derive(Clone, Copy)]
struct RuntimeConfig {
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
            object_prefetch: config.object_prefetch_multiplier,
            object_retention: config.object_retention_multiplier,
            tree_prefetch: config.tree_prefetch_multiplier,
            tree_retention: config.tree_retention_multiplier,
            terrain_prefetch: config.terrain_prefetch_multiplier,
            terrain_retention: config.terrain_retention_multiplier,
        }
    }
}

pub(super) struct DiagnosticSnapshot {
    pub streaming_installed: bool,
    pub handoff_installed: bool,
    pub worldspace_reset_installed: bool,
    pub ready_predecessor: usize,
    pub ready_predecessor_mismatches: u64,
    pub demand_calls: [u64; 3],
    pub extended_demands: [u64; 3],
    pub retained_demands: [u64; 3],
    pub release_passthroughs: [u64; 3],
    pub scheduler: scheduler::Snapshot,
    pub speedtree: speedtree_lifetime::Snapshot,
    pub vertex_buffers: vertex_buffers::Snapshot,
    pub state: state::Snapshot,
}

static CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();
static STREAMING_INSTALLED: AtomicBool = AtomicBool::new(false);
static HANDOFF_INSTALLED: AtomicBool = AtomicBool::new(false);
static READY_PREDECESSOR: AtomicUsize = AtomicUsize::new(statics::LOD_READY_INCREMENT_ADDR);
static READY_PREDECESSOR_MISMATCHES: AtomicU32 = AtomicU32::new(0);

static DEMAND_CALLS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static EXTENDED_DEMANDS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static RETAINED_DEMANDS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static RELEASE_PASSTHROUGHS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

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

pub(super) fn install(config: &LodConfig, diagnostics: &DiagnosticsConfig) {
    scheduler::configure(
        config.enabled && config.priority_boost_enabled,
        config.enabled && config.parallel_io_enabled,
    );
    if !config.enabled {
        log::info!("[LOD] Streaming and handoff fixes disabled by config");
        return;
    }

    if config.validation_adjusted {
        log::warn!(
            "[LOD] Invalid distance multipliers were clamped or replaced with safe defaults"
        );
    }
    if CONFIG.set(RuntimeConfig::from(config)).is_err() {
        log::warn!("[LOD] Runtime configuration was already published");
        return;
    }
    state::configure_trace(diagnostics.lod_streaming_trace);

    if !config.prefetch_enabled
        && !config.handoff_fix_enabled
        && !config.priority_boost_enabled
        && !config.parallel_io_enabled
    {
        log::info!("[LOD] All LOD subfeatures disabled by config");
        return;
    }

    let reset_ready = if config.prefetch_enabled || config.handoff_fix_enabled {
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

    let speedtree_ready = if config.prefetch_enabled || config.parallel_io_enabled {
        match speedtree_lifetime::install(diagnostics.lod_streaming_trace) {
            Ok(()) => true,
            Err(error) => {
                log::warn!(
                    "[LOD] Native prefetch and parallel IO disabled: SpeedTree lifetime hooks unavailable: {error:#}"
                );
                false
            }
        }
    } else {
        false
    };

    let vertex_buffers_ready = if config.prefetch_enabled || config.parallel_io_enabled {
        match vertex_buffers::install() {
            Ok(()) => true,
            Err(error) => {
                log::warn!(
                    "[LOD] Native prefetch and parallel IO unavailable: static vertex-buffer lifetime hooks failed: {error:#}"
                );
                false
            }
        }
    } else {
        false
    };

    if config.priority_boost_enabled {
        if let Err(error) = scheduler::install_priority() {
            log::warn!(
                "[LOD] Priority boost transaction rolled back; native priority retained: {error:#}"
            );
        }
    } else {
        log::info!("[LOD] Native priority boost disabled by config");
    }

    if config.parallel_io_enabled && speedtree_ready && vertex_buffers_ready {
        if let Err(error) = scheduler::install_parallel_io() {
            log::warn!(
                "[LOD] Parallel IO transaction rolled back; one native worker retained: {error:#}"
            );
        }
    } else if !config.parallel_io_enabled {
        log::info!("[LOD] Parallel IO disabled by config");
    }

    if config.prefetch_enabled && speedtree_ready && vertex_buffers_ready && reset_ready {
        match install_streaming_hooks() {
            Ok(()) => STREAMING_INSTALLED.store(true, Ordering::Release),
            Err(error) => log::warn!(
                "[LOD] Native prefetch transaction rolled back; vanilla demand retained: {error:#}"
            ),
        }
    } else if !config.prefetch_enabled {
        log::info!("[LOD] Native prefetch disabled by config");
    }

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

    let runtime = CONFIG.get().expect("LOD configuration was published");
    let scheduler = scheduler::snapshot();
    log::info!(
        "[LOD] Active streaming={} handoff={} priority={} parallel={} vb={} trace={} object={:.2}/{:.2} tree={:.2}/{:.2} terrain={:.2}/{:.2}",
        STREAMING_INSTALLED.load(Ordering::Acquire),
        HANDOFF_INSTALLED.load(Ordering::Acquire),
        scheduler.priority_installed,
        scheduler.parallel_installed,
        vertex_buffers_ready,
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
    prepare_ready_callsite()?;
    unsafe {
        statics::LOD_CELL_INSERT_HOOK.init(
            "lod_cell_membership_insert",
            statics::LOD_CELL_INSERT_ADDR as *mut c_void,
            hook_cell_insert,
        )?;
        statics::LOD_CELL_REMOVE_HOOK.init(
            "lod_cell_membership_remove",
            statics::LOD_CELL_REMOVE_ADDR as *mut c_void,
            hook_cell_remove,
        )?;
        statics::LOD_CELL_ALTERNATE_DECREMENT_HOOK.init(
            "lod_cell_identityless_decrement",
            statics::LOD_CELL_ALTERNATE_DECREMENT_ADDR as *mut c_void,
            hook_cell_alternate_decrement,
        )?;
        statics::LOD_CELL_READY_GATE_HOOK.init(
            "lod_cell_ready_gate",
            statics::LOD_CELL_READY_GATE_ADDR as *mut c_void,
            hook_cell_ready_gate,
        )?;
        statics::LOD_CELL_RELOAD_RESET_HOOK.init(
            "lod_cell_reload_reset",
            statics::LOD_CELL_RELOAD_RESET_ADDR as *mut c_void,
            hook_cell_reload_reset,
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
    transaction.enable_inline(&statics::LOD_CELL_INSERT_HOOK)?;
    transaction.enable_inline(&statics::LOD_CELL_REMOVE_HOOK)?;
    transaction.enable_inline(&statics::LOD_CELL_ALTERNATE_DECREMENT_HOOK)?;
    transaction.enable_inline(&statics::LOD_CELL_RELOAD_RESET_HOOK)?;
    transaction.enable_inline(&statics::LOD_CELL_TEARDOWN_HOOK)?;
    transaction.enable_inline(&statics::LOD_CELL_READY_GATE_HOOK)?;
    transaction.apply_patch(&READY_CALL_PATCH)?;
    transaction.commit();
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

unsafe extern "thiscall" fn hook_terrain_demand(node: *mut c_void, camera: *const f32) -> i32 {
    let vanilla = call_demand_original(&statics::LOD_TERRAIN_DEMAND_HOOK, node, camera);
    extend_demand(
        TERRAIN,
        node,
        camera,
        vanilla,
        TERRAIN_BLOCK_OFFSET,
        terrain_base_distance(node),
    )
}

unsafe extern "thiscall" fn hook_object_demand(node: *mut c_void, camera: *const f32) -> i32 {
    let vanilla = call_demand_original(&statics::LOD_OBJECT_DEMAND_HOOK, node, camera);
    extend_demand(
        OBJECT,
        node,
        camera,
        vanilla,
        OBJECT_BLOCK_OFFSET,
        setting_distance(statics::BLOCK_LOAD_DISTANCE_SETTING),
    )
}

unsafe extern "thiscall" fn hook_tree_demand(node: *mut c_void, camera: *const f32) -> i32 {
    let vanilla = call_demand_original(&statics::LOD_TREE_DEMAND_HOOK, node, camera);
    extend_demand(
        TREE,
        node,
        camera,
        vanilla,
        TREE_BLOCK_OFFSET,
        setting_distance(statics::TREE_LOAD_DISTANCE_SETTING),
    )
}

fn call_demand_original(
    hook: &'static LazyLock<
        libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer<
            super::types::LodDemandFn,
        >,
    >,
    node: *mut c_void,
    camera: *const f32,
) -> i32 {
    let Ok(original) = hook.original() else {
        return 0;
    };
    unsafe { original(node, camera) }
}

fn extend_demand(
    kind: usize,
    node: *mut c_void,
    camera: *const f32,
    vanilla: i32,
    block_offset: usize,
    base_distance: Option<f32>,
) -> i32 {
    DEMAND_CALLS[kind].fetch_add(1, Ordering::Relaxed);
    if vanilla != 0 {
        return vanilla;
    }

    let Some(config) = CONFIG.get() else {
        return vanilla;
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
        if loaded {
            RETAINED_DEMANDS[kind].fetch_add(1, Ordering::Relaxed);
        } else {
            EXTENDED_DEMANDS[kind].fetch_add(1, Ordering::Relaxed);
        }
        1
    } else {
        if loaded {
            RELEASE_PASSTHROUGHS[kind].fetch_add(1, Ordering::Relaxed);
        }
        vanilla
    }
}

fn node_distance(node: *mut c_void, camera: *const f32) -> Option<f32> {
    if node.is_null() || camera.is_null() {
        return None;
    }
    let camera_x = unsafe { ptr::read_unaligned(camera) };
    let camera_y = unsafe { ptr::read_unaligned(camera.add(1)) };
    let origin_x = read_f32(node, NODE_ORIGIN_X_OFFSET)?;
    let origin_y = read_f32(node, NODE_ORIGIN_Y_OFFSET)?;
    let level = read_u32(node, NODE_LEVEL_OFFSET)? as f32;
    let unit = unsafe { ptr::read_unaligned(LOD_BLOCK_WORLD_SIZE_ADDR as *const f32) };
    let size = level * unit;
    if !camera_x.is_finite()
        || !camera_y.is_finite()
        || !origin_x.is_finite()
        || !origin_y.is_finite()
        || !size.is_finite()
        || size <= 0.0
    {
        return None;
    }

    let dx = axis_distance(camera_x, origin_x, size);
    let dy = axis_distance(camera_y, origin_y, size);
    Some((dx * dx + dy * dy).sqrt())
}

fn axis_distance(point: f32, origin: f32, size: f32) -> f32 {
    if point <= origin {
        origin - point
    } else if origin + size < point {
        point - (origin + size)
    } else {
        0.0
    }
}

fn terrain_base_distance(node: *mut c_void) -> Option<f32> {
    read_f32(node, TERRAIN_DISTANCE_OFFSET)
}

fn setting_distance(setting_global: usize) -> Option<f32> {
    let setting = unsafe { ptr::read_unaligned(setting_global as *const *mut c_void) };
    if setting.is_null() {
        return None;
    }
    let accessor = unsafe {
        FnPtr::<GameSettingFloatFn>::from_address_unchecked(statics::FLOAT_SETTING_ACCESSOR_ADDR)
    }
    .as_fn();
    let value = unsafe { accessor(setting) };
    if value.is_null() {
        None
    } else {
        Some(unsafe { ptr::read_unaligned(value) })
    }
}

unsafe extern "fastcall" fn hook_worldspace_reset(owner: *mut c_void) {
    state::reset_worldspace();
    if let Ok(original) = statics::LOD_WORLDSPACE_RESET_HOOK.original() {
        unsafe { original(owner) };
    }
}

unsafe extern "thiscall" fn hook_cell_insert(
    cell: *mut c_void,
    reference: *mut c_void,
    argument: u8,
) {
    let before = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET);
    if let Ok(original) = statics::LOD_CELL_INSERT_HOOK.original() {
        unsafe { original(cell, reference, argument) };
    }
    let after = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET);
    if counter_increased(before, after) {
        state::observe_insert(
            cell,
            reference,
            after.unwrap_or(i16::MIN),
            read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN),
        );
    }
}

unsafe extern "thiscall" fn hook_cell_remove(cell: *mut c_void, reference: *mut c_void) {
    let before = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET);
    if let Ok(original) = statics::LOD_CELL_REMOVE_HOOK.original() {
        unsafe { original(cell, reference) };
    }
    let after = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET);
    if counter_decreased(before, after) {
        state::observe_remove(
            cell,
            reference,
            after.unwrap_or(i16::MIN),
            read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN),
        );
    }
}

unsafe extern "fastcall" fn hook_cell_alternate_decrement(cell: *mut c_void) {
    state::mark_uncertain(
        cell,
        read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET).unwrap_or(i16::MIN),
        read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN),
    );
    if let Ok(original) = statics::LOD_CELL_ALTERNATE_DECREMENT_HOOK.original() {
        unsafe { original(cell) };
    }
}

unsafe extern "fastcall" fn hook_cell_reload_reset(cell: *mut c_void) {
    state::reset_cell(
        cell,
        read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET).unwrap_or(i16::MIN),
        read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN),
    );
    if let Ok(original) = statics::LOD_CELL_RELOAD_RESET_HOOK.original() {
        unsafe { original(cell) };
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
    let vanilla = statics::LOD_CELL_READY_GATE_HOOK
        .original()
        .map(|original| unsafe { original(cell) != 0 })
        .unwrap_or(false);
    let native_total = read_cell_counter(cell, CELL_VWD_TOTAL_OFFSET).unwrap_or(i16::MIN);
    let native_ready = read_cell_counter(cell, CELL_VWD_READY_OFFSET).unwrap_or(i16::MIN);
    u8::from(state::ready_gate(cell, native_total, native_ready, vanilla))
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
        state::observe_ready(
            cell,
            reference,
            native_total,
            ready_after.unwrap_or(i16::MIN),
        );
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

pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        streaming_installed: STREAMING_INSTALLED.load(Ordering::Acquire),
        handoff_installed: HANDOFF_INSTALLED.load(Ordering::Acquire),
        worldspace_reset_installed: statics::LOD_WORLDSPACE_RESET_HOOK.is_enabled(),
        ready_predecessor: READY_PREDECESSOR.load(Ordering::Acquire),
        ready_predecessor_mismatches: u64::from(
            READY_PREDECESSOR_MISMATCHES.load(Ordering::Relaxed),
        ),
        demand_calls: std::array::from_fn(|index| {
            u64::from(DEMAND_CALLS[index].load(Ordering::Relaxed))
        }),
        extended_demands: std::array::from_fn(|index| {
            u64::from(EXTENDED_DEMANDS[index].load(Ordering::Relaxed))
        }),
        retained_demands: std::array::from_fn(|index| {
            u64::from(RETAINED_DEMANDS[index].load(Ordering::Relaxed))
        }),
        release_passthroughs: std::array::from_fn(|index| {
            u64::from(RELEASE_PASSTHROUGHS[index].load(Ordering::Relaxed))
        }),
        scheduler: scheduler::snapshot(),
        speedtree: speedtree_lifetime::snapshot(),
        vertex_buffers: vertex_buffers::snapshot(),
        state: state::snapshot(),
    }
}

pub(super) fn append_trace_report(out: &mut String) {
    state::append_trace_report(out);
}
