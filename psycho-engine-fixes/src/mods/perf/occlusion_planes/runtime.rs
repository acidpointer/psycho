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

use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use libpsycho::ffi::fnptr::FnPtr;
use parking_lot::Mutex;

use super::cache::{self, CachedPlane, PlaneCache};
use super::contract::{
    ALLOC, APPEND, CELL_EXTERIOR_COORDS, CELL_FORM_ID, CELL_INTERIOR_FLAG, CELL_INTERIOR_MASK,
    CELL_WORLDSPACE, CONSTRUCT, COORDS_X, COORDS_Y, FREE_NODE, LIST_COUNT, LIST_HEAD, LIST_OFFSET,
    LIST_TAIL, NODE_NEXT, NODE_PLANE, NODE_PREV, OWNER_POSITION, OWNER_SCENE_GRAPH,
    PLANE_ACTIVE_OFFSET, PLANE_SIDE_FLAG, PLANE_SIZE, PLAYER_PTR, REFCOUNT_OFFSET, SET_POSITION,
    SET_ROTATION, SET_SIZE, SIGNATURES, SINGLETON, TESFORM_REF_ID, VTABLE_DELETE_THIS,
};
use super::contract::{
    AllocFn, AppendFn, ConstructFn, FreeNodeFn, SetPairFn, SetRotationFn, SetTripleFn, SingletonFn,
};
use super::data::{CellKey, PlaneRecord};
use super::raw::{
    read_f32_at, read_i32_at, read_ptr, read_ptr_at, read_u8_at, read_u32_at, write_ptr_at,
    write_u8_at, write_u32_at,
};
use super::runtime_generate;

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
pub(super) fn configure(enabled: bool, max_per_cell: u16, cache_path: &str, debug: bool) {
    ENABLED.store(enabled, Ordering::Release);
    MAX_PER_CELL.store(usize::from(max_per_cell.max(1)), Ordering::Release);
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
        "[OCCLUSION_PLANES] Active; planes are generated at runtime, cache cells={cached_cells}, \
         mod signature={signature:016x}"
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
unsafe fn tracked_status(scene_graph: *mut c_void) -> (usize, usize, usize) {
    let tracked = TRACKED.lock();
    let total = tracked.len();
    if total == 0 {
        return (0, 0, 0);
    }
    let list = unsafe { (scene_graph as *mut u8).add(LIST_OFFSET) as *mut c_void };
    let mut present = 0usize;
    let mut active = 0usize;
    for item in tracked.iter() {
        let Some(node) = (unsafe { find_node(list, item.pointer) }) else {
            continue;
        };
        present += 1;
        let plane = unsafe { read_ptr_at(node, NODE_PLANE) };
        if !plane.is_null() && unsafe { read_u32_at(plane, PLANE_ACTIVE_OFFSET) } == 1 {
            active += 1;
        }
    }
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
    // A forced pass re-uses a complete cached entry when it has this cell, so a
    // revisited cell skips the mesh walk. A settle retry always regenerates so
    // the final set is complete, and it refreshes the cache entry.
    let mut settle_needed = false;
    let mut from_cache = false;
    let mut generate_ms = 0.0f32;
    let mut render_ready = false;
    let (planes, raw): (Vec<PlaneRecord>, usize) = if force {
        // Convert under the lock so a cache hit costs one plane allocation
        // instead of a temporary cached-plane vector plus the records. An
        // incomplete entry is treated as a miss so a set cached before its
        // settle window finished is regenerated.
        let cached = CACHE.get().and_then(|cache| {
            let guard = cache.lock();
            guard.get(&key).and_then(|entry| {
                entry
                    .complete
                    .then(|| (cached_to_records(&entry.planes), entry.planes.len()))
            })
        });
        match cached {
            Some((records, count)) => {
                from_cache = true;
                (records, count)
            }
            None => {
                let started = Instant::now();
                let (planes, raw, ready) = runtime_generate::generate(cell, max, observer);
                generate_ms = started.elapsed().as_secs_f32() * 1000.0;
                render_ready = ready;
                store_in_cache(&key, &planes, false);
                settle_needed = true;
                (planes, raw)
            }
        }
    } else {
        // A settle retry keeps settling until the generated set is stable, and
        // refreshes the cache so the latest set is always reusable on a revisit.
        let started = Instant::now();
        let (planes, raw, ready) = runtime_generate::generate(cell, max, observer);
        generate_ms = started.elapsed().as_secs_f32() * 1000.0;
        render_ready = ready;
        store_in_cache(&key, &planes, false);
        settle_needed = true;
        (planes, raw)
    };
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
    let mut tracked = TRACKED.lock();
    let previous_scene = CURRENT_SCENE_GRAPH.load(Ordering::Acquire);
    let same_scene = previous_scene != 0 && previous_scene == scene_graph as usize;
    let list = if same_scene {
        unsafe { (previous_scene as *mut u8).add(LIST_OFFSET) as *mut c_void }
    } else {
        core::ptr::null_mut()
    };
    // Keep only tracked planes whose node is still in the current list. A
    // missing node means the engine cleared the list without changing the
    // scene identity, so our retained reference is released and the diff below
    // recreates that plane. A replaced scene graph means the old list is gone;
    // release every retained reference without dereferencing retired nodes.
    let previous_count = tracked.len();
    let mut old: Vec<TrackedPlane> = Vec::with_capacity(previous_count);
    for item in tracked.drain(..) {
        if same_scene && unsafe { find_node(list, item.pointer) }.is_some() {
            old.push(item);
        } else {
            unsafe { release_plane(item.pointer as *mut c_void) };
        }
    }
    // Reuse unchanged native planes across settle passes. Recreating the whole
    // list on every pass changes culling for one frame and is visible as
    // popping while a cell's geometry is still streaming in.
    let mut by_key: HashMap<u64, Vec<usize>> = HashMap::with_capacity(old.len());
    for (index, item) in old.iter().enumerate() {
        by_key.entry(item.key).or_default().push(index);
    }
    let mut used = vec![false; old.len()];
    let mut next: Vec<TrackedPlane> = Vec::with_capacity(planes.len());
    let mut injected: Vec<PlaneRecord> = Vec::with_capacity(planes.len());
    let mut created = 0usize;
    for record in &planes {
        let key = plane_key(record);
        if let Some(index) = by_key.get_mut(&key).and_then(Vec::pop) {
            used[index] = true;
            next.push(old[index]);
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
    for (index, item) in old.iter().enumerate() {
        if used[index] {
            continue;
        }
        if same_scene && let Some(node) = unsafe { find_node(list, item.pointer) } {
            unsafe { unlink(fns, list, node) };
        }
        unsafe { release_plane(item.pointer as *mut c_void) };
    }
    let reused = next.len().saturating_sub(created);
    let removed = previous_count.saturating_sub(reused);
    // How many injected planes kept the engine's two-sided window. The next
    // playtest can compare this with the engine-admitted `active` count.
    let two_sided = injected
        .iter()
        .filter(|plane| plane.coverage >= runtime_generate::TWO_SIDED_COVERAGE)
        .count();
    if injected.len() < planes.len() {
        // An allocation failed; keep the bounded settle window alive so the
        // missing plane is retried instead of being silently absent.
        INCOMPLETE.store(true, Ordering::Release);
        log::warn!(
            "[OCCLUSION_PLANES] injected {}/{} planes; retrying",
            injected.len(),
            planes.len()
        );
        settle_needed = true;
    } else {
        INCOMPLETE.store(false, Ordering::Release);
    }
    if !settle_needed {
        mark_cache_complete(&key);
    }
    *tracked = next;
    TRACKED_COUNT.store(tracked.len(), Ordering::Release);
    CURRENT_SCENE_GRAPH.store(scene_graph as usize, Ordering::Release);
    CURRENT_CELL_PTR.store(cell as usize, Ordering::Release);
    CURRENT_CELL_KEY.store(key_signature, Ordering::Release);
    LAST_SIGNATURE.store(signature, Ordering::Release);
    if log::log_enabled!(log::Level::Debug) {
        let (observer_x, observer_y, observer_z) = observer
            .map(|position| (position[0], position[1], position[2]))
            .unwrap_or((0.0, 0.0, 0.0));
        log::debug!(
            "[OCCLUSION_PLANES] cell key={} candidates={} raw={} injected={} reused={} \
             removed={} cap={} two_sided={} cached={} complete={} gen_ms={:.1} \
             obs=[{:.0},{:.0},{:.0}]",
            cell_key_log(&key),
            planes.len(),
            raw,
            created,
            reused,
            removed,
            max,
            two_sided,
            from_cache,
            !settle_needed,
            generate_ms,
            observer_x,
            observer_y,
            observer_z,
        );
    }
    store_debug_snapshot(&injected, observer);
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

unsafe fn find_node(list: *mut c_void, plane: usize) -> Option<*mut c_void> {
    let mut node = unsafe { read_ptr_at(list, LIST_HEAD) };
    while !node.is_null() {
        let next = unsafe { read_ptr_at(node, NODE_NEXT) };
        let data = unsafe { read_ptr_at(node, NODE_PLANE) };
        if data as usize == plane {
            return Some(node);
        }
        node = next;
    }
    None
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
