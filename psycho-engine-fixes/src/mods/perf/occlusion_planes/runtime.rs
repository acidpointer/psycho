//! Native `BSOcclusionPlane` lifecycle for runtime-generated planes.
//!
//! Planes are created through the engine's own authored `XOCP` path, retained
//! once, appended to the scene-graph occluder list, and removed and released
//! when the cell or scene graph changes. A plane whose support rectangle nearly
//! fills its vertex hull on a thick (solid-volume) mesh keeps the constructor's
//! two-sided window (`+0xEA = 1`), matching the engine's authored
//! `BSOcclusionPlane`; an irregular, thin-panel or partly open face stays
//! one-sided so `0x00C358A0` activates it only while the camera is on its
//! outward side. All work runs on the xNVSE
//! event thread. The per-frame path compares two atomics and returns
//! immediately on an unchanged cell; allocation, list scans, generation and
//! logging happen only on a transition.
//!
//! The runtime collector derives a cell's planes from live cell geometry. A
//! new cell identity must persist for a few frames before it replaces the
//! current set, so cell-seam alternation cannot make the occluders flicker.
//! The module never clears the whole list and never touches an authored plane.
//! A replacement scene graph means the old nodes were already retired by the
//! engine, so the module releases its references without dereferencing the old
//! list. A load/new/exit event defers cleanup to the next frame so the module
//! never scans a list that may be under teardown.
//!
//! # Frame budget
//!
//! Walking a dense cell's meshes and proving every face hole-free is larger
//! than one frame (a release build measured 20-32 ms for the Fairfax exterior
//! cells). The walk is therefore resumable: each frame advances a fixed
//! triangle and wall-clock slice, and the plane set is installed only when the
//! whole reference list has been walked. A steady frame with a generation in
//! flight touches only that slice; the previous cell's planes are dropped once
//! at the target change so a stale rectangle cannot cull the new cell.

use core::ffi::c_void;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use libpsycho::ffi::fnptr::FnPtr;
use parking_lot::Mutex;

use super::cache::{self, CachedPlane, PlaneCache};
use super::contract::{
    ALLOC, APPEND, CELL_EXTERIOR_COORDS, CELL_FORM_ID, CELL_INTERIOR_FLAG, CELL_INTERIOR_MASK,
    CELL_WORLDSPACE, CONSTRUCT, COORDS_X, COORDS_Y, FREE_NODE, GRID_CELLS, GRID_SIZE, GRID_WORLD_X,
    GRID_WORLD_Y, LIST_COUNT, LIST_HEAD, LIST_OFFSET, LIST_TAIL, NODE_NEXT, NODE_PLANE, NODE_PREV,
    OWNER_POSITION, OWNER_SCENE_GRAPH, PLANE_ACTIVE_OFFSET, PLANE_SIDE_FLAG, PLANE_SIZE,
    PLAYER_PTR, REFCOUNT_OFFSET, SET_POSITION, SET_ROTATION, SET_SIZE, SIGNATURES, SINGLETON,
    TES_GRID_CELL_ARRAY, TES_SINGLETON, TESFORM_REF_ID, VTABLE_DELETE_THIS,
};
use super::contract::{
    AllocFn, AppendFn, ConstructFn, FreeNodeFn, SetPairFn, SetRotationFn, SetTripleFn, SingletonFn,
};
use super::data::{CellKey, PlaneRecord};
use super::raw::{
    read_f32_at, read_i32_at, read_ptr, read_ptr_at, read_u8_at, read_u32_at, write_ptr_at,
    write_u8_at, write_u32_at,
};
use super::runtime_generate::{self, Generation};

/// `NiRefObject::DeleteThis` at one vtable slot.
type DeleteThisFn = unsafe extern "thiscall" fn(*mut c_void);

/// Bounded rebuilds after a cell/scene change. The first frame can run before
/// the cell's references and their 3D are attached, so the runtime retries a
/// few times and only rebuilds when the generated plane set actually changes.
const SETTLE_RETRIES: usize = 5;
/// Frames between settle rebuilds.
const SETTLE_INTERVAL_FRAMES: usize = 20;
/// Consecutive identical settle passes required before the window stops early.
const SETTLE_STABLE_PASSES: usize = 2;
/// Frames between checks that our tracked planes are still in the engine list.
/// The engine can clear the occluder list on cell unload without changing the
/// cell identity, which would otherwise leave the cell with no planes.
const PRESENCE_INTERVAL_FRAMES: usize = 30;
/// Frames between cache saves (about 30 seconds at 60 fps).
const CACHE_SAVE_INTERVAL_FRAMES: usize = 1800;

struct EngineFns {
    alloc: AllocFn,
    construct: ConstructFn,
    set_size: SetPairFn,
    set_position: SetTripleFn,
    set_rotation: SetRotationFn,
    append: AppendFn,
    free_node: FreeNodeFn,
    singleton: SingletonFn,
}

impl EngineFns {
    fn resolve() -> Self {
        // Safety: `verify_contracts` checked every exact byte signature for
        // these fixed addresses against the supported executable before this
        // call. Each signature also establishes the calling convention.
        unsafe {
            Self {
                alloc: FnPtr::from_address_unchecked(ALLOC).as_fn(),
                construct: FnPtr::from_address_unchecked(CONSTRUCT).as_fn(),
                set_size: FnPtr::from_address_unchecked(SET_SIZE).as_fn(),
                set_position: FnPtr::from_address_unchecked(SET_POSITION).as_fn(),
                set_rotation: FnPtr::from_address_unchecked(SET_ROTATION).as_fn(),
                append: FnPtr::from_address_unchecked(APPEND).as_fn(),
                free_node: FnPtr::from_address_unchecked(FREE_NODE).as_fn(),
                singleton: FnPtr::from_address_unchecked(SINGLETON).as_fn(),
            }
        }
    }
}

/// Increment the object's `NiRefObject` count at `+4`.
///
/// The engine's `0x0040F6E0` is a plain `InterlockedIncrement` of this field,
/// and several performance mods replace that function in place with an inlined
/// `lock xadd` form. Managing the documented field directly keeps the feature
/// independent of whichever equivalent form is installed.
pub(super) unsafe fn retain_plane(plane: *mut c_void) {
    let counter = unsafe { &*((plane as *const u8).add(REFCOUNT_OFFSET) as *const AtomicI32) };
    counter.fetch_add(1, Ordering::AcqRel);
}

/// Decrement the object's `NiRefObject` count and destroy it at zero.
///
/// Mirrors the engine's `0x00401970`: decrement `+4`, and on the transition to
/// zero call the object's `DeleteThis` virtual (`vtable+4`), which runs the
/// scalar deleting destructor. This avoids the commonly patched release entry.
pub(super) unsafe fn release_plane(plane: *mut c_void) {
    let counter = unsafe { &*((plane as *const u8).add(REFCOUNT_OFFSET) as *const AtomicI32) };
    if counter.fetch_sub(1, Ordering::AcqRel) == 1 {
        unsafe { delete_this(plane) };
    }
}

unsafe fn delete_this(object: *mut c_void) {
    let vtable = unsafe { read_ptr(object as usize) };
    if vtable.is_null() {
        return;
    }
    let entry = unsafe { read_ptr_at(vtable, VTABLE_DELETE_THIS) };
    if entry.is_null() {
        return;
    }
    // Safety: `vtable+4` is the object's `DeleteThis` slot, a thiscall
    // function taking only the object pointer.
    let Ok(function) = (unsafe { FnPtr::<DeleteThisFn>::from_raw(entry) }) else {
        return;
    };
    unsafe { function.as_fn()(object) };
}

/// Convert a full-extent record size to the native `+0x14/+0x18` fields.
///
/// `0x00C35C10` builds the native corners as `position +/- sizeX * localX +/-
/// sizeY * localZ`, so those fields are half-extents. `PlaneRecord` stores full
/// rectangle width/height; the runtime generator uses that full-extent
/// representation.
pub(super) fn native_size(full: [f32; 2]) -> [f32; 2] {
    [full[0] * 0.5, full[1] * 0.5]
}

/// One injected plane we own, with the quantized key used to reuse it across
/// settle passes instead of removing and recreating the whole list.
#[derive(Clone, Copy, Debug)]
struct TrackedPlane {
    pointer: usize,
    key: u64,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static MAX_PER_CELL: AtomicUsize = AtomicUsize::new(1);
static RESET_PENDING: AtomicBool = AtomicBool::new(false);
static FNS: OnceLock<EngineFns> = OnceLock::new();
static TRACKED: Mutex<Vec<TrackedPlane>> = Mutex::new(Vec::new());
/// Number of tracked planes, so the per-frame presence path can skip the lock
/// and the engine list walk entirely when there is nothing to maintain.
static TRACKED_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Last engine-admitted plane count, so the presence diagnostic logs only when
/// the active set changes instead of every interval.
static LAST_ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// Throttle for the per-frame module-cost warning.
static FRAME_COST_COOLDOWN: AtomicUsize = AtomicUsize::new(0);
/// A frame that spends this long in the occlusion module is worth reporting.
const FRAME_COST_WARN_US: u64 = 2_000;
/// Frames between module-cost warnings (about 5 seconds at 60 fps).
const FRAME_COST_COOLDOWN_FRAMES: usize = 300;
static CURRENT_SCENE_GRAPH: AtomicUsize = AtomicUsize::new(0);
/// Cell pointer for the common case. The identity hash is only recomputed when
/// the pointer changes, so the frame path never hashes in steady state.
static CURRENT_CELL_PTR: AtomicUsize = AtomicUsize::new(0);
static CURRENT_CELL_KEY: AtomicU64 = AtomicU64::new(0);
static LAST_SIGNATURE: AtomicU64 = AtomicU64::new(0);
static SETTLE_RETRIES_LEFT: AtomicUsize = AtomicUsize::new(0);
static SETTLE_COUNTDOWN: AtomicUsize = AtomicUsize::new(0);
/// Set when a plane allocation failed, so the settle window keeps retrying
/// instead of treating a short set as stable.
static INCOMPLETE: AtomicBool = AtomicBool::new(false);
/// Candidate target awaiting confirmation. Rapid cell-boundary flapping would
/// otherwise remove and rebuild the whole plane set every few frames.
static PENDING_SCENE: AtomicUsize = AtomicUsize::new(0);
static PENDING_KEY: AtomicU64 = AtomicU64::new(0);
static PENDING_STREAK: AtomicUsize = AtomicUsize::new(0);
/// Consecutive frames a new cell target must persist before its planes replace
/// the current set. About 60 ms at 60 fps: enough to reject a seam flip-flop
/// while keeping the stale-plane window short.
pub(super) const TARGET_STABLE_FRAMES: usize = 4;
/// Defensive bound on the loaded-grid size. `0x004BA490` bounds both axes with
/// `gridCellArray + 0xC`; the engine's default exterior grid is 5.
const MAX_GRID_DIMENSION: i32 = 64;
/// Frames between checks that the cached neighborhood still matches the loaded
/// grid. A mismatch rebuilds it, so planes are never kept for a cell the engine
/// has unloaded. This path only reads the grid array and the persistent cache;
/// it never walks a neighbor cell's meshes.
const NEIGHBOR_VALIDATE_FRAMES: usize = 60;
/// The loaded-cell grid radius. `0` is the old player-cell-only behavior.
static GRID_RADIUS: AtomicUsize = AtomicUsize::new(0);
/// One cell in the current neighborhood.
///
/// `distance` is the Chebyshev cell distance from the player's cell and only
/// orders the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NeighborCell {
    key: CellKey,
    distance: i32,
}

/// The union of the player's cell and the loaded exterior neighbors.
///
/// `planes` holds the records already available in memory: the freshly generated
/// or cached center plus the **cached** neighbor sets. A neighbor without a
/// complete cache entry is simply absent; it is never generated from the
/// neighbor's live meshes on a frame path. Each cell is generated once, when it
/// is the player's own cell, and reused by key from the persistent cache
/// afterwards.
struct Neighborhood {
    center: CellKey,
    worldspace: usize,
    cells: Vec<NeighborCell>,
    planes: HashMap<CellKey, Vec<PlaneRecord>>,
}

static NEIGHBORHOOD: Mutex<Option<Neighborhood>> = Mutex::new(None);
static NEIGHBOR_VALIDATE_COUNTDOWN: AtomicUsize = AtomicUsize::new(NEIGHBOR_VALIDATE_FRAMES);
/// In-flight resumable generation for the current cell.
///
/// A cell's full mesh walk is larger than one frame's budget (a release build
/// measured 20-32 ms for the Fairfax exterior cells), so the walk is advanced a
/// fixed slice per frame instead of blocking the frame thread. `GENERATION_ACTIVE`
/// lets the frame path advance it every frame rather than only on the settle
/// interval.
static GENERATION: Mutex<Option<Generation>> = Mutex::new(None);
static GENERATION_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Cell pointer a pending generation was started for, so the frame path can
/// advance it while `CURRENT_CELL_KEY` still names the previous cell.
static GENERATION_CELL: AtomicUsize = AtomicUsize::new(0);
/// Consecutive settle passes that produced the same set. The window stops once
/// this reaches `SETTLE_STABLE_PASSES`, so the common case costs two extra
/// walks instead of all five while still allowing one more pass for late 3D.
static STABLE_PASSES: AtomicUsize = AtomicUsize::new(0);
static PRESENCE_COUNTDOWN: AtomicUsize = AtomicUsize::new(PRESENCE_INTERVAL_FRAMES);
static SAVE_COUNTDOWN: AtomicUsize = AtomicUsize::new(CACHE_SAVE_INTERVAL_FRAMES);
static CACHE: OnceLock<Mutex<PlaneCache>> = OnceLock::new();
static CACHE_PATH: OnceLock<String> = OnceLock::new();
/// Debug mode: keeps the last injected set observable and logs it.
static DEBUG: AtomicBool = AtomicBool::new(false);
static LAST_PLANES: Mutex<Vec<PlaneRecord>> = Mutex::new(Vec::new());
static LAST_OBSERVER: Mutex<[f32; 3]> = Mutex::new([0.0; 3]);
/// Floats per debug plane: position(3) + half-size(2) + normal/tangent/
/// bitangent(9).
const DEBUG_PLANE_FLOATS: usize = 14;
/// Header floats: magic, version, count, observer(3).
const DEBUG_HEADER_FLOATS: usize = 6;
/// Exactly representable `f32` magic (0x504F).
const DEBUG_MAGIC: f32 = 20559.0;

/// Record configuration at startup. No file, allocation or engine access
/// occurs here; the feature activates only after `DeferredInit`.
pub(super) fn configure(
    enabled: bool,
    max_per_cell: u16,
    grid_radius: u8,
    cache_path: &str,
    debug: bool,
) {
    ENABLED.store(enabled, Ordering::Release);
    MAX_PER_CELL.store(usize::from(max_per_cell.max(1)), Ordering::Release);
    GRID_RADIUS.store(usize::from(grid_radius.min(2)), Ordering::Release);
    DEBUG.store(debug, Ordering::Release);
    let _ = CACHE_PATH.set(cache_path.to_string());
    if enabled {
        log::info!("[OCCLUSION_PLANES] Prepared; activation at DeferredInit");
    } else {
        log::info!("[OCCLUSION_PLANES] Disabled by configuration");
    }
}

/// Route one core event id to the occlusion-plane lifecycle.
pub(super) fn observe_event(kind: u32) {
    if kind == crate::events::DEFERRED_INIT {
        activate();
        return;
    }
    if !READY.load(Ordering::Acquire) {
        return;
    }
    match kind {
        crate::events::ON_FRAME_PRESENT => frame_tick(),
        crate::events::PRE_LOAD_GAME
        | crate::events::NEW_GAME
        | crate::events::EXIT_TO_MAIN_MENU => {
            RESET_PENDING.store(true, Ordering::Release);
            save_cache();
        }
        _ => {}
    }
}

fn activate() {
    if !ENABLED.load(Ordering::Acquire) || READY.load(Ordering::Acquire) {
        return;
    }
    if let Err(error) = verify_contracts() {
        log::error!("[OCCLUSION_PLANES] Native contract unavailable; feature disabled: {error:#}");
        return;
    }
    let _ = FNS.set(EngineFns::resolve());
    let max = MAX_PER_CELL.load(Ordering::Acquire);
    // Load the persistent plane cache. Its signature binds it to the exact
    // active plugin list, so a mod install/uninstall/update discards it.
    let cache_path = CACHE_PATH.get().map(String::as_str).unwrap_or_default();
    let mod_signature = cache::current_mod_signature();
    let signature = cache::config_signature(mod_signature, max);
    // A zero mod signature means the mod list could not be read; do not reuse a
    // cache whose provenance cannot be checked.
    let cache = if mod_signature == 0 {
        PlaneCache::empty(signature)
    } else {
        PlaneCache::load(cache_path, signature)
    };
    let cached_cells = cache.cell_count();
    let _ = CACHE.set(Mutex::new(cache));
    READY.store(true, Ordering::Release);
    log::info!(
        "[OCCLUSION_PLANES] Active; planes are generated at runtime, grid radius={}, \
         cache cells={cached_cells}, mod signature={signature:016x}",
        GRID_RADIUS.load(Ordering::Acquire)
    );
}

fn verify_contracts() -> anyhow::Result<()> {
    let mut failures: Vec<String> = Vec::new();
    for signature in SIGNATURES {
        if let Err(error) = signature.verify() {
            failures.push(format!("{}: {error}", signature.name()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{}", failures.join("; ")))
    }
}

/// Measure the per-frame module cost. A steady frame only compares atomics; the
/// warning exists so a future regression cannot hide behind the feature.
fn frame_tick() {
    let started = Instant::now();
    frame_tick_inner();
    let elapsed_us = started.elapsed().as_micros() as u64;
    if elapsed_us > FRAME_COST_WARN_US {
        log_frame_cost(elapsed_us);
    }
}

/// Warn at most once per `FRAME_COST_COOLDOWN_FRAMES` when one frame's module
/// work crosses the threshold.
fn log_frame_cost(elapsed_us: u64) {
    if FRAME_COST_COOLDOWN.load(Ordering::Relaxed) > 0 {
        FRAME_COST_COOLDOWN.fetch_sub(1, Ordering::Relaxed);
        return;
    }
    FRAME_COST_COOLDOWN.store(FRAME_COST_COOLDOWN_FRAMES, Ordering::Relaxed);
    log::warn!("[OCCLUSION_PLANES] frame work {elapsed_us} us");
}

fn frame_tick_inner() {
    let pending = RESET_PENDING.swap(false, Ordering::AcqRel);
    let Some(fns) = FNS.get() else {
        restore_pending(pending);
        return;
    };
    // Safety: every read is a volatile pointer/word read on the event thread;
    // null is checked before the next dereference. The engine state is read-only
    // here and the module only writes its own planes and list nodes.
    unsafe {
        let player = read_ptr(PLAYER_PTR);
        if player.is_null() {
            restore_pending(pending);
            return;
        }
        let cell = read_ptr_at(player, super::contract::REFR_PARENT_CELL);
        if cell.is_null() {
            restore_pending(pending);
            return;
        }
        let owner = (fns.singleton)(0);
        if owner.is_null() {
            restore_pending(pending);
            return;
        }
        let scene_graph = read_ptr_at(owner, OWNER_SCENE_GRAPH);
        if scene_graph.is_null() {
            restore_pending(pending);
            return;
        }
        let scene = scene_graph as usize;
        let cell_ptr = cell as usize;
        if pending {
            clear_pending_target();
            // A load/new/exit can retire the scene the neighborhood was built
            // from. Drop its per-cell records and let this frame rebuild them.
            NEIGHBORHOOD.lock().take();
            // A resumable generation walks engine memory; a load/new/exit can
            // unload the cell under it, so abandon it.
            *GENERATION.lock() = None;
            GENERATION_ACTIVE.store(false, Ordering::Release);
        }
        // A resumable cell generation is in flight: advance it every frame (not
        // only on the settle interval) so the plane set appears as soon as
        // possible while each frame pays only the fixed work budget. The target
        // is the generation's own cell, because `CURRENT_*` still names the
        // previous cell until the walk completes and the set is installed; a
        // `same_target` check would otherwise restart the walk every few frames.
        if !pending && GENERATION_ACTIVE.load(Ordering::Acquire) {
            if GENERATION_CELL.load(Ordering::Acquire) == cell_ptr {
                let observer = read_observer(owner);
                let _ = reconcile(fns, scene_graph, cell, observer, false);
                tick_cache_save();
                return;
            }
            // The player left the cell whose walk was in flight; drop it.
            *GENERATION.lock() = None;
            GENERATION_ACTIVE.store(false, Ordering::Release);
        }
        // Fast path: the scene and cell pointers are unchanged, so no hashing
        // or key read happens on a normal frame. Only a pointer change pays for
        // the identity hash, which also catches a reused cell pointer that now
        // names a different cell.
        let fast_same = CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene
            && CURRENT_CELL_PTR.load(Ordering::Acquire) == cell_ptr;
        let candidate_key = if fast_same {
            CURRENT_CELL_KEY.load(Ordering::Acquire)
        } else {
            cell_key_signature(&cell_key(cell))
        };
        let same_target = fast_same
            || (CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene
                && CURRENT_CELL_KEY.load(Ordering::Acquire) == candidate_key);
        if same_target {
            if !fast_same {
                CURRENT_CELL_PTR.store(cell_ptr, Ordering::Release);
            }
            clear_pending_target();
        }
        let settle_left = SETTLE_RETRIES_LEFT.load(Ordering::Acquire);
        if !pending && same_target {
            if settle_left == 0 {
                // The engine can clear the occluder list on cell unload without
                // changing the cell identity. Check periodically that our planes
                // are still present and re-append them from the cache if not.
                // With no tracked planes there is nothing to maintain, so the
                // whole path stays idle.
                if presence_due() {
                    let total = TRACKED_COUNT.load(Ordering::Acquire);
                    if total == 0 {
                        if LAST_ACTIVE.swap(0, Ordering::AcqRel) != 0 {
                            log::debug!("[OCCLUSION_PLANES] presence tracked=0 present=0 active=0");
                        }
                    } else {
                        let (total, present, active) = tracked_status(scene_graph);
                        if present < total {
                            let observer = read_observer(owner);
                            let settle_needed = reconcile(fns, scene_graph, cell, observer, true);
                            schedule_settle(settle_needed);
                        }
                        let previous = LAST_ACTIVE.swap(active, Ordering::AcqRel);
                        // Log only when planes start or stop being admitted, so
                        // camera motion cannot turn this into per-frame spam.
                        if (previous == 0) != (active == 0) {
                            log::debug!(
                                "[OCCLUSION_PLANES] presence tracked={total} present={present} \
                                 active={active}"
                            );
                        }
                    }
                }
                refresh_neighbors(fns, scene_graph, cell, read_observer(owner));
                tick_cache_save();
                return;
            }
            // Settle retry: regenerate only when the interval elapses. The
            // rebuild itself is skipped when the generated set is unchanged.
            let countdown = SETTLE_COUNTDOWN.load(Ordering::Acquire);
            if countdown > 1 {
                SETTLE_COUNTDOWN.store(countdown - 1, Ordering::Release);
                return;
            }
            let observer = read_observer(owner);
            let keep_settling = reconcile(fns, scene_graph, cell, observer, false);
            if keep_settling {
                SETTLE_RETRIES_LEFT.store(settle_left.saturating_sub(1), Ordering::Release);
                SETTLE_COUNTDOWN.store(SETTLE_INTERVAL_FRAMES, Ordering::Release);
            } else {
                // The set stopped changing; skip the remaining regenerations.
                SETTLE_RETRIES_LEFT.store(0, Ordering::Release);
                SETTLE_COUNTDOWN.store(0, Ordering::Release);
            }
            return;
        }
        if !pending {
            // A different target must persist for a few frames before it
            // replaces the current planes. Cell seams can otherwise alternate
            // between two cells every few frames and make the occluder set
            // flicker, which shows up as scenery popping.
            if !confirm_target(scene, candidate_key) {
                tick_cache_save();
                return;
            }
        }
        // A confirmed new target (or an explicit reset) always rebuilds. A
        // cache hit is a complete set and needs no settle window.
        let observer = read_observer(owner);
        let settle_needed = reconcile(fns, scene_graph, cell, observer, true);
        schedule_settle(settle_needed);
        tick_cache_save();
    }
}

/// Forget any target waiting for confirmation.
fn clear_pending_target() {
    if PENDING_SCENE.load(Ordering::Relaxed) == 0 {
        return;
    }
    PENDING_SCENE.store(0, Ordering::Release);
    PENDING_KEY.store(0, Ordering::Release);
    PENDING_STREAK.store(0, Ordering::Release);
}

/// True once `(scene, key)` has been seen for `TARGET_STABLE_FRAMES` in a row.
/// A different candidate resets the streak, so a rapid seam alternation never
/// confirms.
fn confirm_target(scene: usize, key: u64) -> bool {
    let (confirmed, pending_scene, pending_key, streak) = target_confirmation(
        PENDING_SCENE.load(Ordering::Acquire),
        PENDING_KEY.load(Ordering::Acquire),
        PENDING_STREAK.load(Ordering::Acquire),
        scene,
        key,
    );
    PENDING_SCENE.store(pending_scene, Ordering::Release);
    PENDING_KEY.store(pending_key, Ordering::Release);
    PENDING_STREAK.store(streak, Ordering::Release);
    confirmed
}

/// Pure confirmation step: returns `(confirmed, pending_scene, pending_key,
/// streak)` for the next frame.
pub(super) fn target_confirmation(
    pending_scene: usize,
    pending_key: u64,
    streak: usize,
    scene: usize,
    key: u64,
) -> (bool, usize, u64, usize) {
    if pending_scene != scene || pending_key != key {
        return (false, scene, key, 1);
    }
    let streak = streak.saturating_add(1);
    (streak >= TARGET_STABLE_FRAMES, scene, key, streak)
}

/// Decrement the presence-check countdown; `true` when a check is due.
fn presence_due() -> bool {
    let remaining = PRESENCE_COUNTDOWN.load(Ordering::Acquire);
    if remaining > 0 {
        PRESENCE_COUNTDOWN.store(remaining - 1, Ordering::Release);
        return false;
    }
    PRESENCE_COUNTDOWN.store(PRESENCE_INTERVAL_FRAMES, Ordering::Release);
    true
}

/// Snapshot of the tracked set: `(total, present, active)`. `present` counts
/// tracked planes whose node is still linked; `active` counts the linked planes
/// the engine admitted for the current camera (`+0x40 == 1`).
///
/// The engine list is walked once and each plane's admission state recorded, so
/// the cost is linear in the list length instead of one full list walk per
/// tracked plane (the previous quadratic shape grew with the injected cap).
unsafe fn tracked_status(scene_graph: *mut c_void) -> (usize, usize, usize) {
    let tracked = TRACKED.lock();
    let total = tracked.len();
    if total == 0 {
        return (0, 0, 0);
    }
    let wanted: HashSet<usize> = tracked.iter().map(|item| item.pointer).collect();
    let list = unsafe { (scene_graph as *mut u8).add(LIST_OFFSET) as *mut c_void };
    let mut linked: HashMap<usize, bool> = HashMap::with_capacity(wanted.len());
    let mut node = unsafe { read_ptr_at(list, LIST_HEAD) };
    while !node.is_null() {
        let next = unsafe { read_ptr_at(node, NODE_NEXT) };
        let plane = unsafe { read_ptr_at(node, NODE_PLANE) } as usize;
        if wanted.contains(&plane) {
            let active = unsafe { read_u32_at(plane as *mut c_void, PLANE_ACTIVE_OFFSET) } == 1;
            linked.insert(plane, active);
        }
        node = next;
    }
    let present = tracked
        .iter()
        .filter(|item| linked.contains_key(&item.pointer))
        .count();
    let active = tracked
        .iter()
        .filter(|item| linked.get(&item.pointer) == Some(&true))
        .count();
    (total, present, active)
}

/// Start or skip the settle window depending on whether the plane set is
/// complete (cache hit) or freshly generated.
fn schedule_settle(needed: bool) {
    if needed {
        SETTLE_RETRIES_LEFT.store(SETTLE_RETRIES, Ordering::Release);
        SETTLE_COUNTDOWN.store(SETTLE_INTERVAL_FRAMES, Ordering::Release);
    } else {
        SETTLE_RETRIES_LEFT.store(0, Ordering::Release);
        SETTLE_COUNTDOWN.store(0, Ordering::Release);
    }
}

/// Decrement the cache-save countdown and flush a dirty cache when due.
fn tick_cache_save() {
    let remaining = SAVE_COUNTDOWN.load(Ordering::Acquire);
    if remaining > 0 {
        SAVE_COUNTDOWN.store(remaining - 1, Ordering::Release);
        return;
    }
    SAVE_COUNTDOWN.store(CACHE_SAVE_INTERVAL_FRAMES, Ordering::Release);
    save_cache();
}

/// Persist the cache when it changed. Called on a debounce and on
/// load/new/exit, never on a per-frame hot path.
fn save_cache() {
    let (Some(cache), Some(path)) = (CACHE.get(), CACHE_PATH.get()) else {
        return;
    };
    let (snapshot, cells) = {
        let mut guard = cache.lock();
        let cells = guard.cell_count();
        (guard.take_snapshot(), cells)
    };
    let Some(bytes) = snapshot else {
        return;
    };
    match cache::PlaneCache::write_snapshot(path, &bytes, 0) {
        Ok(()) => log::debug!("[OCCLUSION_PLANES] cache saved cells={cells}"),
        Err(error) => {
            // Restore the dirty flag so the failed write is retried on the next
            // debounce instead of losing the generated set.
            cache.lock().mark_dirty();
            log::warn!("[OCCLUSION_PLANES] cache save failed: {error}");
        }
    }
}

/// Hash a cell identity so a reused cell pointer still reads as a new cell.
///
/// FxHash instead of SipHash: this runs on the frame path when the cell or
/// scene pointer changes, and the key is a few small integers.
fn cell_key_signature(key: &CellKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::default();
    key.hash(&mut hasher);
    hasher.finish()
}

/// Order-independent fingerprint of one cell's plane records, used to decide
/// whether a settle pass produced the same set.
///
/// The position/size fields are quantized so sub-unit transform jitter from the
/// engine settling does not defeat stability. The per-plane keys are sorted
/// before hashing because the generator can emit the same planes in a different
/// order: the engine may re-link a cell's reference list while geometry streams
/// in, and the score sort is stable, so candidates with equal scores keep that
/// list order. An order-sensitive hash therefore reported a change on every
/// pass even when the aggregate scan statistics were byte-identical (observed
/// 2026-10-18: six full regenerations per first visit while every
/// `refs/nodes/geoms/faces/mesh_area/rect_area` value matched). Sorting the keys
/// makes the fingerprint independent of emission order while still detecting
/// any added, removed or moved plane.
pub(super) fn plane_signature(planes: &[PlaneRecord]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut keys: Vec<u64> = planes.iter().map(plane_key).collect();
    keys.sort_unstable();
    let mut hasher = rustc_hash::FxHasher::default();
    keys.hash(&mut hasher);
    hasher.finish()
}

/// Quantized fingerprint of one plane. The same key means the plane is close
/// enough that an existing native object can be reused across a settle pass.
pub(super) fn plane_key(plane: &PlaneRecord) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::default();
    for value in plane.position {
        ((value * 4.0).round() as i32).hash(&mut hasher);
    }
    for value in plane.size {
        ((value * 4.0).round() as i32).hash(&mut hasher);
    }
    for value in plane.rotation {
        ((value * 256.0).round() as i32).hash(&mut hasher);
    }
    plane.priority.hash(&mut hasher);
    plane.source_form_id.hash(&mut hasher);
    // Coverage decides the native side flag, so a change must force a recreate
    // instead of reusing the existing plane. Quantize it so sub-percent
    // generation jitter cannot churn the native list.
    ((plane.coverage * 64.0).round() as i32).hash(&mut hasher);
    hasher.finish()
}

/// Observer/player world position, or `None` when the field is not finite.
unsafe fn read_observer(owner: *mut c_void) -> Option<[f32; 3]> {
    let position = [
        unsafe { read_f32_at(owner, OWNER_POSITION) },
        unsafe { read_f32_at(owner, OWNER_POSITION + 4) },
        unsafe { read_f32_at(owner, OWNER_POSITION + 8) },
    ];
    position
        .iter()
        .all(|value| value.is_finite())
        .then_some(position)
}

fn restore_pending(pending: bool) {
    if pending {
        RESET_PENDING.store(true, Ordering::Release);
    }
}

/// A complete cached plane set, converted to runtime records.
///
/// An incomplete entry (written before its settle window finished) is not
/// trusted, exactly as before: the cell is regenerated instead.
fn complete_cached(key: &CellKey) -> Option<(Vec<PlaneRecord>, usize)> {
    let cache = CACHE.get()?;
    let guard = cache.lock();
    let entry = guard.get(key)?;
    entry
        .complete
        .then(|| (cached_to_records(&entry.planes), entry.planes.len()))
}

/// Live `GridCellArray` pointers read from the `TES` singleton.
struct GridInfo {
    cells: *mut c_void,
    size: i32,
    world_x: i32,
    world_y: i32,
}

/// Read the engine's loaded grid through the `TES` singleton.
///
/// `0x0084E3A0` returns `*(gridCellArray + 0xC)` and `0x004BA490` indexes
/// `gridCells[gridSize * x + y]` at `+0x10`. The engine's exterior visibility
/// pass (`0x0045B070`) uses the same getter for every slot of the whole grid,
/// so a plane generated from a neighbor cell is a valid occluder for the same
/// scene graph.
unsafe fn read_grid() -> Option<GridInfo> {
    let tes = unsafe { read_ptr(TES_SINGLETON) };
    if tes.is_null() {
        return None;
    }
    let grid = unsafe { read_ptr_at(tes, TES_GRID_CELL_ARRAY) };
    if grid.is_null() {
        return None;
    }
    let size = unsafe { read_i32_at(grid, GRID_SIZE) };
    if size <= 0 || size > MAX_GRID_DIMENSION {
        return None;
    }
    let cells = unsafe { read_ptr_at(grid, GRID_CELLS) };
    if cells.is_null() {
        return None;
    }
    Some(GridInfo {
        cells,
        size,
        world_x: unsafe { read_i32_at(grid, GRID_WORLD_X) },
        world_y: unsafe { read_i32_at(grid, GRID_WORLD_Y) },
    })
}

/// Read one grid slot exactly as `0x004BA490` does.
unsafe fn grid_cell_at(grid: &GridInfo, x: i32, y: i32) -> Option<*mut c_void> {
    if x < 0 || y < 0 || x >= grid.size || y >= grid.size {
        return None;
    }
    let index = grid.size as usize * x as usize + y as usize;
    let cell = unsafe { read_ptr_at(grid.cells, index * 4) };
    (!cell.is_null()).then_some(cell)
}

/// Chebyshev grid distance used to bound the neighborhood.
pub(super) fn grid_distance(a: (i32, i32), b: (i32, i32)) -> i32 {
    (a.0 - b.0).abs().max((a.1 - b.1).abs())
}

fn exterior_coords(key: &CellKey) -> Option<(i32, i32)> {
    match key {
        CellKey::Exterior { x, y, .. } => Some((*x, *y)),
        CellKey::Interior { .. } => None,
    }
}

/// Decode the current loaded grid into the neighborhood list.
unsafe fn neighborhood_cells(cell: *mut c_void, radius: usize) -> (Vec<NeighborCell>, usize) {
    let center_key = unsafe { cell_key(cell) };
    let worldspace = unsafe { read_ptr_at(cell, CELL_WORLDSPACE) };
    let mut cells = vec![NeighborCell {
        key: center_key,
        distance: 0,
    }];
    let interior = unsafe { read_u8_at(cell, CELL_INTERIOR_FLAG) } & CELL_INTERIOR_MASK != 0;
    if interior || radius == 0 || worldspace.is_null() {
        return (cells, worldspace as usize);
    }
    let Some(grid) = (unsafe { read_grid() }) else {
        return (cells, worldspace as usize);
    };
    // Filter against the player cell's own coordinates, not the grid's cached
    // world position: the two match for a normal exterior, and the cell key is
    // the identity the rest of the module already uses.
    let center_point = exterior_coords(&center_key).unwrap_or((grid.world_x, grid.world_y));
    for x in 0..grid.size {
        for y in 0..grid.size {
            let Some(neighbor) = (unsafe { grid_cell_at(&grid, x, y) }) else {
                continue;
            };
            if neighbor == cell {
                continue;
            }
            if unsafe { read_u8_at(neighbor, CELL_INTERIOR_FLAG) } & CELL_INTERIOR_MASK != 0 {
                continue;
            }
            // A grid slot can be reused while the engine reloads; only accept a
            // cell that still belongs to the same worldspace.
            if unsafe { read_ptr_at(neighbor, CELL_WORLDSPACE) } != worldspace {
                continue;
            }
            let key = unsafe { cell_key(neighbor) };
            let Some(point) = exterior_coords(&key) else {
                continue;
            };
            let distance = grid_distance(center_point, point);
            if distance > radius as i32 {
                continue;
            }
            if cells.iter().any(|existing| existing.key == key) {
                continue;
            }
            cells.push(NeighborCell { key, distance });
        }
    }
    cells.sort_by_key(|item| (item.distance, exterior_coords(&item.key).unwrap_or((0, 0))));
    (cells, worldspace as usize)
}

/// Rebuild the neighborhood description for the current center cell.
///
/// This path is **cache only**: a neighbor contributes planes only when it has a
/// complete persistent-cache entry, i.e. it was generated and settled while it
/// was the player's own cell. No neighbor mesh walk ever runs here, so the
/// per-frame and cell-crossing paths add no generation work. The center cell's
/// records are preserved across the rebuild and refreshed by `reconcile`.
///
/// Returns `true` when the neighborhood changed.
fn refresh_neighborhood(cell: *mut c_void, key: &CellKey, radius: usize) -> bool {
    let (cells, worldspace) = unsafe { neighborhood_cells(cell, radius) };
    let mut guard = NEIGHBORHOOD.lock();
    if let Some(neighborhood) = guard.as_ref()
        && neighborhood.center == *key
        && neighborhood.worldspace == worldspace
        && neighborhood.cells == cells
    {
        return false;
    }
    let old = guard.take();
    let mut planes: HashMap<CellKey, Vec<PlaneRecord>> = HashMap::new();
    if let Some(records) = old
        .as_ref()
        .and_then(|neighborhood| neighborhood.planes.get(key))
        .cloned()
    {
        planes.insert(*key, records);
    }
    for item in &cells {
        if item.key == *key {
            continue;
        }
        if let Some(records) = old
            .as_ref()
            .and_then(|neighborhood| neighborhood.planes.get(&item.key))
            .cloned()
        {
            planes.insert(item.key, records);
        } else if let Some((records, _)) = complete_cached(&item.key) {
            planes.insert(item.key, records);
        }
    }
    *guard = Some(Neighborhood {
        center: *key,
        worldspace,
        cells,
        planes,
    });
    true
}

/// Decrement the neighbor validation countdown; `true` when a check is due.
fn neighbor_validate_due() -> bool {
    let remaining = NEIGHBOR_VALIDATE_COUNTDOWN.load(Ordering::Acquire);
    if remaining > 0 {
        NEIGHBOR_VALIDATE_COUNTDOWN.store(remaining - 1, Ordering::Release);
        return false;
    }
    NEIGHBOR_VALIDATE_COUNTDOWN.store(NEIGHBOR_VALIDATE_FRAMES, Ordering::Release);
    true
}

/// Periodically re-check the loaded grid and reload the cached neighbor sets.
///
/// This runs at most once every `NEIGHBOR_VALIDATE_FRAMES` frames. It reads the
/// grid array and the persistent cache only; it never walks a neighbor cell's
/// meshes. It drops planes for cells that left the grid and picks up a neighbor
/// whose cache entry became complete while the player was elsewhere.
fn refresh_neighbors(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    cell: *mut c_void,
    observer: Option<[f32; 3]>,
) {
    // The default configuration has no neighbors, so the frame path is a single
    // atomic load and return.
    let radius = GRID_RADIUS.load(Ordering::Acquire);
    if radius == 0 {
        return;
    }
    if !neighbor_validate_due() {
        return;
    }
    let center_key = unsafe { cell_key(cell) };
    {
        let guard = NEIGHBORHOOD.lock();
        let Some(neighborhood) = guard.as_ref() else {
            return;
        };
        if neighborhood.center != center_key {
            return;
        }
        if neighborhood.worldspace != 0
            && unsafe { read_ptr_at(cell, CELL_WORLDSPACE) as usize } != neighborhood.worldspace
        {
            drop(guard);
            NEIGHBORHOOD.lock().take();
            return;
        }
    }
    if refresh_neighborhood(cell, &center_key, radius) {
        let _ = unsafe { apply_union(fns, scene_graph, observer) };
    }
}

/// Score and cap the union of all per-cell records, then diff and inject it.
unsafe fn apply_union(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    observer: Option<[f32; 3]>,
) -> UnionReport {
    let (candidates, cells) = {
        let guard = NEIGHBORHOOD.lock();
        let Some(neighborhood) = guard.as_ref() else {
            return UnionReport::default();
        };
        let mut candidates: Vec<(f32, PlaneRecord)> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        for planes in neighborhood.planes.values() {
            for plane in planes {
                // Two cells can only produce the same rectangle if a reference
                // was duplicated; dedupe so the diff cannot create a duplicate
                // native plane for one key.
                if seen.insert(plane_key(plane)) {
                    candidates.push((plane.size[0] * plane.size[1], *plane));
                }
            }
        }
        (candidates, neighborhood.cells.len())
    };
    let candidate_count = candidates.len();
    // Per-cell generation already merged coplanar rectangles. Do not repeat the
    // quadratic merge on the whole union: with nine cells the group would be
    // several times larger, and the extra merge cost would land on the frame
    // path. The union only dedupes, scores and caps.
    let selection =
        runtime_generate::select_planes(candidates, observer, MAX_PER_CELL.load(Ordering::Acquire));
    let selected = selection.planes.len();
    let two_sided = selection
        .planes
        .iter()
        .filter(|plane| plane.coverage >= runtime_generate::TWO_SIDED_COVERAGE)
        .count();
    let injected = unsafe { inject(fns, scene_graph, &selection.planes) };
    store_debug_snapshot(&selection.planes, observer);
    UnionReport {
        selected,
        candidates: candidate_count,
        cells,
        two_sided,
        injected,
    }
}

/// Diagnostics and injection result for one union refresh.
#[derive(Default, Clone, Copy, Debug)]
struct UnionReport {
    selected: usize,
    candidates: usize,
    cells: usize,
    two_sided: usize,
    injected: InjectResult,
}

/// Result of diffing the desired plane set against the tracked native planes.
#[derive(Default, Clone, Copy, Debug)]
struct InjectResult {
    created: usize,
    reused: usize,
    removed: usize,
    complete: bool,
}

/// Diff the desired set against the tracked set and update only the nodes that
/// changed. A reused plane keeps its native object and list node, so a settle
/// pass or a cell crossing cannot make the whole occluder set blink.
unsafe fn inject(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    planes: &[PlaneRecord],
) -> InjectResult {
    let mut tracked = TRACKED.lock();
    let previous_scene = CURRENT_SCENE_GRAPH.load(Ordering::Acquire);
    let same_scene = previous_scene != 0 && previous_scene == scene_graph as usize;
    let list = if same_scene {
        unsafe { (previous_scene as *mut u8).add(LIST_OFFSET) as *mut c_void }
    } else {
        core::ptr::null_mut()
    };
    // One list walk maps each linked plane to its node, so the diff does not
    // walk the list once per tracked plane and again per removed plane (that
    // shape grew with the injected cap). A missing node means the engine
    // cleared the list without changing the scene identity, so our retained
    // reference is released and the diff below recreates that plane. A replaced
    // scene graph means the old list is gone; release every retained reference
    // without dereferencing retired nodes.
    let linked = if same_scene {
        unsafe { linked_nodes(list) }
    } else {
        HashMap::new()
    };
    let previous_count = tracked.len();
    let mut old: Vec<(TrackedPlane, *mut c_void)> = Vec::with_capacity(previous_count);
    for item in tracked.drain(..) {
        if let Some(&node) = linked.get(&item.pointer) {
            old.push((item, node));
        } else {
            unsafe { release_plane(item.pointer as *mut c_void) };
        }
    }
    let mut by_key: HashMap<u64, Vec<usize>> = HashMap::with_capacity(old.len());
    for (index, (item, _)) in old.iter().enumerate() {
        by_key.entry(item.key).or_default().push(index);
    }
    let mut used = vec![false; old.len()];
    let mut next: Vec<TrackedPlane> = Vec::with_capacity(planes.len());
    let mut injected: Vec<PlaneRecord> = Vec::with_capacity(planes.len());
    let mut created = 0usize;
    for record in planes {
        let key = plane_key(record);
        if let Some(index) = by_key.get_mut(&key).and_then(Vec::pop) {
            used[index] = true;
            next.push(old[index].0);
            injected.push(*record);
        } else if let Some(plane) = unsafe { create_plane(fns, record) } {
            unsafe { (fns.append)(scene_graph, plane) };
            next.push(TrackedPlane {
                pointer: plane as usize,
                key,
            });
            injected.push(*record);
            created += 1;
        }
    }
    for (index, (item, node)) in old.iter().enumerate() {
        if used[index] {
            continue;
        }
        if !node.is_null() {
            unsafe { unlink(fns, list, *node) };
        }
        unsafe { release_plane(item.pointer as *mut c_void) };
    }
    let reused = next.len().saturating_sub(created);
    let removed = previous_count.saturating_sub(reused);
    let complete = injected.len() == planes.len();
    if !complete {
        log::warn!(
            "[OCCLUSION_PLANES] injected {}/{} planes; retrying",
            injected.len(),
            planes.len()
        );
    }
    *tracked = next;
    TRACKED_COUNT.store(tracked.len(), Ordering::Release);
    InjectResult {
        created,
        reused,
        removed,
        complete,
    }
}

/// Returns `true` when the freshly generated set should run a settle window.
/// A cache hit is a complete set and needs none.
unsafe fn reconcile(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    cell: *mut c_void,
    observer: Option<[f32; 3]>,
    force: bool,
) -> bool {
    let key = unsafe { cell_key(cell) };
    let key_signature = cell_key_signature(&key);
    let max = MAX_PER_CELL.load(Ordering::Acquire);
    if force {
        STABLE_PASSES.store(0, Ordering::Release);
    }
    // The union includes the loaded exterior neighbors the engine also renders.
    // Neighbors contribute only their complete persistent-cache sets, so this
    // adds no mesh walk to the frame or cell-crossing path.
    let _ = refresh_neighborhood(cell, &key, GRID_RADIUS.load(Ordering::Acquire));

    // A forced pass re-uses a complete cached entry when it has this cell, so a
    // revisited cell skips the mesh walk. A settle retry always regenerates so
    // the final set is complete, and it refreshes the cache entry.
    let mut settle_needed = false;
    let mut from_cache = false;
    let mut generate_ms = 0.0f32;
    let mut render_ready = false;
    let mut planes: Vec<PlaneRecord> = Vec::new();
    let mut raw = 0usize;
    if force && let Some((records, count)) = complete_cached(&key) {
        from_cache = true;
        planes = records;
        raw = count;
        // Drop any in-flight generation for another target; this cache hit is
        // the complete set.
        *GENERATION.lock() = None;
        GENERATION_ACTIVE.store(false, Ordering::Release);
    }
    if !from_cache {
        // A target change must not leave the previous cell's rectangles in the
        // engine list while the new set is being assembled: a stale rectangle
        // could cull visible geometry of the new cell. Drop them once, while
        // the resumable walk runs over several frames.
        if force && CURRENT_CELL_KEY.load(Ordering::Acquire) != key_signature {
            let _ = unsafe { inject(fns, scene_graph, &[]) };
        }
        // Advance the resumable walk by one frame's work budget. A new target
        // (or a forced pass) restarts it; a settle retry continues the same
        // walk. The set is installed only when the whole reference list has
        // been walked, so no frame pays the full cell cost.
        let outcome = {
            let mut guard = GENERATION.lock();
            let restart = force
                || guard
                    .as_ref()
                    .is_none_or(|generation| generation.cell() != cell);
            if restart {
                *guard = Some(Generation::new(cell, max, observer));
                GENERATION_CELL.store(cell as usize, Ordering::Release);
            }
            let generation = guard.as_mut().expect("generation was just inserted");
            if unsafe { generation.advance() } {
                Some(guard.take().expect("generation is present"))
            } else {
                None
            }
        };
        let Some(finished) = outcome else {
            // The cell is still being walked. Keep the settle window alive so
            // the next frame continues it; the caller does not inject yet.
            GENERATION_ACTIVE.store(true, Ordering::Release);
            return true;
        };
        GENERATION_ACTIVE.store(false, Ordering::Release);
        let (generated_planes, generated_raw, ready, generation_ms) = finished.finish();
        generate_ms = generation_ms;
        render_ready = ready;
        planes = generated_planes;
        raw = generated_raw;
        store_in_cache(&key, &planes, false);
        settle_needed = true;
    }
    // Keep the union source current even when no native plane is re-created.
    if let Some(neighborhood) = NEIGHBORHOOD.lock().as_mut() {
        neighborhood.planes.insert(key, planes.clone());
    }
    let signature = plane_signature(&planes);
    // The set is stable when the same target produced the same signature again.
    // Only a stable set is cached, so an incomplete first pass is never reused
    // on a later visit and a settle retry with an unchanged set keeps the
    // existing planes instead of rebuilding.
    let same_target = CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene_graph as usize
        && CURRENT_CELL_KEY.load(Ordering::Acquire) == key_signature;
    let stable = !INCOMPLETE.load(Ordering::Acquire)
        && same_target
        && LAST_SIGNATURE.load(Ordering::Acquire) == signature;
    if stable {
        let passes = STABLE_PASSES.fetch_add(1, Ordering::AcqRel) + 1;
        // The set did not change. A presence-driven force pass re-appends it
        // below; a settle pass stops once enough identical passes were seen.
        // When every reference already has an attached render node, no more 3D
        // can appear, so one identical pass is enough.
        let stable_passes_needed = if render_ready {
            1
        } else {
            SETTLE_STABLE_PASSES
        };
        settle_needed = false;
        if !force && passes >= stable_passes_needed {
            mark_cache_complete(&key);
            return false;
        }
        if !force {
            return true;
        }
    } else {
        STABLE_PASSES.store(0, Ordering::Release);
    }
    let report = unsafe { apply_union(fns, scene_graph, observer) };
    if !report.injected.complete {
        // An allocation failed; keep the bounded settle window alive so the
        // missing plane is retried instead of being silently absent.
        INCOMPLETE.store(true, Ordering::Release);
        settle_needed = true;
    } else {
        INCOMPLETE.store(false, Ordering::Release);
    }
    if !settle_needed {
        mark_cache_complete(&key);
    }
    CURRENT_SCENE_GRAPH.store(scene_graph as usize, Ordering::Release);
    CURRENT_CELL_PTR.store(cell as usize, Ordering::Release);
    CURRENT_CELL_KEY.store(key_signature, Ordering::Release);
    LAST_SIGNATURE.store(signature, Ordering::Release);
    if log::log_enabled!(log::Level::Debug) {
        let (observer_x, observer_y, observer_z) = observer
            .map(|position| (position[0], position[1], position[2]))
            .unwrap_or((0.0, 0.0, 0.0));
        let (neighbor_cells, neighbor_planes) =
            NEIGHBORHOOD.lock().as_ref().map_or((0, 0), |neighborhood| {
                let cells = neighborhood
                    .planes
                    .keys()
                    .filter(|neighbor| **neighbor != key)
                    .count();
                let planes = neighborhood
                    .planes
                    .iter()
                    .filter(|(neighbor, _)| **neighbor != key)
                    .map(|(_, planes)| planes.len())
                    .sum();
                (cells, planes)
            });
        log::debug!(
            "[OCCLUSION_PLANES] cell key={} cells={} neighbors={}/{} candidates={} selected={} \
             center={} raw={} injected={} reused={} removed={} cap={} two_sided={} \
             cached={} complete={} gen_ms={:.1} obs=[{:.0},{:.0},{:.0}]",
            cell_key_log(&key),
            report.cells,
            neighbor_cells,
            neighbor_planes,
            report.candidates,
            report.selected,
            planes.len(),
            raw,
            report.injected.created,
            report.injected.reused,
            report.injected.removed,
            max,
            report.two_sided,
            from_cache,
            !settle_needed,
            generate_ms,
            observer_x,
            observer_y,
            observer_z,
        );
    }
    settle_needed
}

/// Convert a cached plane back into the runtime record.
fn cached_to_records(cached: &[CachedPlane]) -> Vec<PlaneRecord> {
    cached
        .iter()
        .map(|plane| PlaneRecord {
            position: plane.position,
            size: plane.size,
            rotation: plane.rotation,
            priority: plane.priority,
            source_form_id: plane.source_form_id,
            coverage: plane.coverage,
        })
        .collect()
}

/// Convert a generated plane into a cache entry.
fn record_to_cached(record: &PlaneRecord) -> CachedPlane {
    CachedPlane {
        position: record.position,
        size: record.size,
        rotation: record.rotation,
        priority: record.priority,
        source_form_id: record.source_form_id,
        coverage: record.coverage,
    }
}

/// Toggle the occluder debug view and report the summary for the requesting
/// host adapter.
pub(super) fn debug_toggle() -> String {
    let enabled = !DEBUG.load(Ordering::Acquire);
    DEBUG.store(enabled, Ordering::Release);
    if enabled {
        // Force a rebuild on the next frame so the snapshot is populated
        // immediately instead of waiting for the next cell change.
        RESET_PENDING.store(true, Ordering::Release);
        format!(
            "[OCCLUSION_PLANES] debug on; {} plane(s) available for the overlay",
            LAST_PLANES.lock().len()
        )
    } else {
        "[OCCLUSION_PLANES] debug off".to_string()
    }
}

/// Fill a caller-owned float buffer with the current debug frame.
///
/// Layout: `[magic, version, count, observer x, y, z]`, then `count` planes of
/// `[position(3), half-size(2), normal(3), tangent(3), bitangent(3)]`. Returns
/// the number of floats needed; writes at most `capacity`.
pub(super) unsafe fn debug_write(out: *mut f32, capacity: usize) -> i32 {
    let planes = LAST_PLANES.lock();
    let needed = DEBUG_HEADER_FLOATS + planes.len() * DEBUG_PLANE_FLOATS;
    if out.is_null() || capacity == 0 {
        return needed as i32;
    }
    let observer = *LAST_OBSERVER.lock();
    let write = |index: usize, value: f32| {
        if index < capacity {
            unsafe { *out.add(index) = value };
        }
    };
    write(0, DEBUG_MAGIC);
    write(1, 1.0);
    write(2, planes.len() as f32);
    write(3, observer[0]);
    write(4, observer[1]);
    write(5, observer[2]);
    for (plane_index, plane) in planes.iter().enumerate() {
        let base = DEBUG_HEADER_FLOATS + plane_index * DEBUG_PLANE_FLOATS;
        for (axis, value) in plane.position.iter().enumerate() {
            write(base + axis, *value);
        }
        let half = native_size(plane.size);
        write(base + 3, half[0]);
        write(base + 4, half[1]);
        let matrix = plane.rotation;
        for row in 0..3 {
            write(base + 5 + row, matrix[row * 3 + 1]);
            write(base + 8 + row, matrix[row * 3]);
            write(base + 11 + row, matrix[row * 3 + 2]);
        }
    }
    needed as i32
}

/// Store the last injected set and observer while debug mode is on.
fn store_debug_snapshot(planes: &[PlaneRecord], observer: Option<[f32; 3]>) {
    if !DEBUG.load(Ordering::Acquire) {
        return;
    }
    *LAST_PLANES.lock() = planes.to_vec();
    if let Some(observer) = observer {
        *LAST_OBSERVER.lock() = observer;
    }
}

/// Store the latest generated set for a cell so a revisit can re-append it
/// without re-walking the meshes. `complete` is false until the settle window
/// sees two identical passes; an incomplete entry is regenerated on a revisit.
fn store_in_cache(key: &CellKey, planes: &[PlaneRecord], complete: bool) {
    let Some(cache) = CACHE.get() else {
        return;
    };
    let cached: Vec<CachedPlane> = planes.iter().map(record_to_cached).collect();
    cache.lock().insert(*key, cached, complete);
}

/// Mark a cached entry complete once the settle window has ended.
fn mark_cache_complete(key: &CellKey) {
    if let Some(cache) = CACHE.get() {
        cache.lock().mark_complete(key);
    }
}

unsafe fn create_plane(fns: &EngineFns, record: &PlaneRecord) -> Option<*mut c_void> {
    let raw = unsafe { (fns.alloc)(PLANE_SIZE) };
    if raw.is_null() {
        return None;
    }
    let plane = unsafe { (fns.construct)(raw) };
    if plane.is_null() {
        return None;
    }
    // Retain immediately so a concurrent engine retirement path never sees a
    // zero count on our object.
    unsafe { retain_plane(plane) };
    let size = native_size(record.size);
    unsafe {
        (fns.set_size)(plane, size.as_ptr());
        (fns.set_position)(plane, record.position.as_ptr());
        (fns.set_rotation)(plane, record.rotation.as_ptr());
        // The engine's authored `BSOcclusionPlane` constructor leaves `+0xEA`
        // set, which makes `0x00C358A0` a two-sided window: a solid face
        // occludes the camera-through-rectangle pyramid from both sides. Only a
        // face whose support rectangle nearly fills its vertex hull is trusted
        // as solid enough for that; an irregular or partly open face stays
        // one-sided, so `0x00C358A0` runs the engine's camera-side test and the
        // plane is active only from its outward side.
        let two_sided = record.coverage >= runtime_generate::TWO_SIDED_COVERAGE;
        write_u8_at(plane, PLANE_SIDE_FLAG, u8::from(two_sided));
    }
    Some(plane)
}

/// Map every plane pointer in the occluder list to its list node with one walk.
///
/// The diff needs each tracked plane's node; looking it up per plane walked the
/// list once per tracked plane (and again per removed plane), which grew
/// quadratically with the injected cap.
unsafe fn linked_nodes(list: *mut c_void) -> HashMap<usize, *mut c_void> {
    let mut linked: HashMap<usize, *mut c_void> = HashMap::new();
    let mut node = unsafe { read_ptr_at(list, LIST_HEAD) };
    while !node.is_null() {
        let next = unsafe { read_ptr_at(node, NODE_NEXT) };
        let plane = unsafe { read_ptr_at(node, NODE_PLANE) } as usize;
        if plane != 0 {
            linked.insert(plane, node);
        }
        node = next;
    }
    linked
}

unsafe fn unlink(fns: &EngineFns, list: *mut c_void, node: *mut c_void) {
    let previous = unsafe { read_ptr_at(node, NODE_PREV) };
    let next = unsafe { read_ptr_at(node, NODE_NEXT) };
    unsafe {
        if previous.is_null() {
            write_ptr_at(list, LIST_HEAD, next);
        } else {
            write_ptr_at(previous, NODE_NEXT, next);
        }
        if next.is_null() {
            write_ptr_at(list, LIST_TAIL, previous);
        } else {
            write_ptr_at(next, NODE_PREV, previous);
        }
        let count = read_u32_at(list, LIST_COUNT);
        write_u32_at(list, LIST_COUNT, count.saturating_sub(1));
        (fns.free_node)(list, node);
    }
}

unsafe fn cell_key(cell: *mut c_void) -> CellKey {
    let interior = unsafe { read_u8_at(cell, CELL_INTERIOR_FLAG) } & CELL_INTERIOR_MASK != 0;
    if interior {
        return CellKey::Interior {
            form_id: unsafe { read_u32_at(cell, CELL_FORM_ID) },
        };
    }
    // `cell + 0x48` is a `CellCoordinates*`; the grid values live in the
    // pointed structure, not in the two cell fields. A null worldspace or
    // coords pointer during a load is kept as a stable zero so the key does
    // not alternate while the cell streams in.
    let worldspace = unsafe { read_ptr_at(cell, CELL_WORLDSPACE) };
    let worldspace_id = if worldspace.is_null() {
        0
    } else {
        unsafe { read_u32_at(worldspace, TESFORM_REF_ID) }
    };
    let coords = unsafe { read_ptr_at(cell, CELL_EXTERIOR_COORDS) };
    let (x, y) = if coords.is_null() {
        (0, 0)
    } else {
        (unsafe { read_i32_at(coords, COORDS_X) }, unsafe {
            read_i32_at(coords, COORDS_Y)
        })
    };
    CellKey::Exterior {
        worldspace: worldspace_id,
        x,
        y,
    }
}

/// Compact cell identity for the debug log.
fn cell_key_log(key: &CellKey) -> String {
    match key {
        CellKey::Interior { form_id } => format!("interior:{form_id:08X}"),
        CellKey::Exterior { worldspace, x, y } => format!("exterior:{worldspace:08X}:{x}:{y}"),
    }
}
