//! Native `BSOcclusionPlane` lifecycle for runtime-generated and override data.
//!
//! Planes are created through the engine's own authored `XOCP` path, retained
//! once, appended to the scene-graph occluder list, and removed and released
//! when the cell or scene graph changes. Created planes are one-sided: the
//! constructor's two-sided flag is cleared so `0x00C358A0` activates a plane
//! only while the camera is on its outward side. All work runs on the xNVSE
//! event thread. The per-frame path compares two atomics and returns
//! immediately on an unchanged cell; allocation, list scans, generation and
//! logging happen only on a transition.
//!
//! A cell's planes come from the optional TOML override when it lists that
//! cell; otherwise the runtime collector derives them from live cell geometry.
//! The module never clears the whole list and never touches an authored plane.
//! A replacement scene graph means the old nodes were already retired by the
//! engine, so the module releases its references without dereferencing the old
//! list. A load/new/exit event defers cleanup to the next frame so the module
//! never scans a list that may be under teardown.

use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

use libpsycho::ffi::fnptr::FnPtr;
use parking_lot::Mutex;

use super::cache::{self, CachedPlane, PlaneCache};
use super::contract::{
    ALLOC, APPEND, BUILD_ROTATION, CELL_EXTERIOR_COORDS, CELL_FORM_ID, CELL_WORLDSPACE, CONSTRUCT,
    COORDS_X, COORDS_Y, FREE_NODE, LIST_COUNT, LIST_HEAD, LIST_OFFSET, LIST_TAIL, NODE_NEXT,
    NODE_PLANE, NODE_PREV, OWNER_POSITION, OWNER_SCENE_GRAPH, PLANE_SIDE_FLAG, PLANE_SIZE,
    PLAYER_PTR, REFCOUNT_OFFSET, SET_POSITION, SET_ROTATION, SET_SIZE, SIGNATURES, SINGLETON,
    TESFORM_REF_ID, VTABLE_DELETE_THIS,
};
use super::contract::{
    AllocFn, AppendFn, BuildRotationFn, ConstructFn, FreeNodeFn, SetPairFn, SetRotationFn,
    SetTripleFn, SingletonFn,
};
use super::data::{CellKey, PlaneRecord, PlaneRotation, PlaneSet};
use super::raw::{
    read_f32_at, read_i32_at, read_ptr, read_ptr_at, read_u32_at, write_ptr_at, write_u8_at,
    write_u32_at,
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
    build_rotation: BuildRotationFn,
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
                build_rotation: FnPtr::from_address_unchecked(BUILD_ROTATION).as_fn(),
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
/// rectangle width/height; the TOML override and runtime generator both use
/// that full-extent representation.
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
static RUNTIME_GENERATE: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static MAX_PER_CELL: AtomicUsize = AtomicUsize::new(1);
static RESET_PENDING: AtomicBool = AtomicBool::new(false);
static DATA: OnceLock<PlaneSet> = OnceLock::new();
static FNS: OnceLock<EngineFns> = OnceLock::new();
static TRACKED: Mutex<Vec<TrackedPlane>> = Mutex::new(Vec::new());
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
    runtime_generate: bool,
    cache_path: &str,
    debug: bool,
) {
    ENABLED.store(enabled, Ordering::Release);
    RUNTIME_GENERATE.store(runtime_generate, Ordering::Release);
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
    // The core config was parsed once at startup and lives for the process, so
    // this borrow is stable and no startup allocation occurs here.
    let path = crate::config::get_config()
        .map(|config| config.performance.occlusion_planes_path.as_str())
        .unwrap_or_default();
    let max = MAX_PER_CELL.load(Ordering::Acquire);
    let data = load_data(path, max);
    let cells = data.cell_count();
    let _ = DATA.set(data);
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
    if !data_is_used() {
        log::info!(
            "[OCCLUSION_PLANES] Active; planes are generated at runtime, cache cells={cached_cells}, \
             mod signature={signature:016x}"
        );
    } else {
        log::info!(
            "[OCCLUSION_PLANES] Active with {cells} override cell(s) from `{path}`, \
             cache cells={cached_cells}, mod signature={signature:016x}"
        );
    }
}

fn data_is_used() -> bool {
    DATA.get().is_some_and(|data| data.cell_count() > 0)
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

fn load_data(path: &str, max_per_cell: usize) -> PlaneSet {
    if path.is_empty() {
        return PlaneSet::empty();
    }
    match std::fs::read_to_string(path) {
        Ok(text) => match PlaneSet::parse(&text, max_per_cell) {
            Ok(set) => set,
            Err(error) => {
                log::error!("[OCCLUSION_PLANES] Override data `{path}` rejected: {error}");
                PlaneSet::empty()
            }
        },
        Err(_) => PlaneSet::empty(),
    }
}

fn frame_tick() {
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
        // Fast path: the scene and cell pointers are unchanged, so no hashing
        // or key read happens on a normal frame. Only a pointer change pays for
        // the identity hash, which also catches a reused cell pointer that now
        // names a different cell.
        let same_target = if CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene
            && CURRENT_CELL_PTR.load(Ordering::Acquire) == cell_ptr
        {
            true
        } else {
            let key = cell_key_signature(&cell_key(cell));
            let same = CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene
                && CURRENT_CELL_KEY.load(Ordering::Acquire) == key;
            if same {
                CURRENT_CELL_PTR.store(cell_ptr, Ordering::Release);
            }
            same
        };
        let settle_left = SETTLE_RETRIES_LEFT.load(Ordering::Acquire);
        if !pending && same_target && settle_left == 0 {
            // The engine can clear the occluder list on cell unload without
            // changing the cell identity. Check periodically that our planes
            // are still present and re-append them from the cache if not.
            if presence_due() && !planes_present(scene_graph) {
                let observer = read_observer(owner);
                let settle_needed = reconcile(fns, scene_graph, cell, observer, true);
                schedule_settle(settle_needed);
            }
            tick_cache_save();
            return;
        }
        let observer = read_observer(owner);
        if pending || !same_target {
            // A new target (or an explicit reset) always rebuilds. A cache hit
            // is a complete set and needs no settle window.
            let settle_needed = reconcile(fns, scene_graph, cell, observer, true);
            schedule_settle(settle_needed);
        } else {
            // Settle retry: regenerate only when the interval elapses. The
            // rebuild itself is skipped when the generated set is unchanged.
            let countdown = SETTLE_COUNTDOWN.load(Ordering::Acquire);
            if countdown > 1 {
                SETTLE_COUNTDOWN.store(countdown - 1, Ordering::Release);
                return;
            }
            let keep_settling = reconcile(fns, scene_graph, cell, observer, false);
            if keep_settling {
                SETTLE_RETRIES_LEFT.store(settle_left.saturating_sub(1), Ordering::Release);
                SETTLE_COUNTDOWN.store(SETTLE_INTERVAL_FRAMES, Ordering::Release);
            } else {
                // The set stopped changing; skip the remaining regenerations.
                SETTLE_RETRIES_LEFT.store(0, Ordering::Release);
                SETTLE_COUNTDOWN.store(0, Ordering::Release);
            }
        }
    }
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

/// True when every tracked plane is still linked in the scene occluder list.
unsafe fn planes_present(scene_graph: *mut c_void) -> bool {
    let tracked = TRACKED.lock();
    if tracked.is_empty() {
        return true;
    }
    let list = unsafe { (scene_graph as *mut u8).add(LIST_OFFSET) as *mut c_void };
    tracked
        .iter()
        .all(|item| unsafe { find_node(list, item.pointer) }.is_some())
}

/// Start or skip the settle window depending on whether the plane set is
/// complete (cache hit or override) or freshly generated.
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
    let mut cache = cache.lock();
    if !cache.is_dirty() {
        return;
    }
    match cache.save(path) {
        Ok(()) => log::debug!(
            "[OCCLUSION_PLANES] cache saved cells={}",
            cache.cell_count()
        ),
        Err(error) => log::warn!("[OCCLUSION_PLANES] cache save failed: {error}"),
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
    match plane.rotation {
        PlaneRotation::Matrix(matrix) => {
            for value in matrix {
                ((value * 256.0).round() as i32).hash(&mut hasher);
            }
        }
        PlaneRotation::AxisAngle { axis, angle } => {
            for value in axis {
                ((value * 256.0).round() as i32).hash(&mut hasher);
            }
            ((angle * 256.0).round() as i32).hash(&mut hasher);
        }
    }
    plane.priority.hash(&mut hasher);
    plane.source_form_id.hash(&mut hasher);
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
/// A cache hit or a hand-authored override is a complete set and needs none.
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
    let override_planes = DATA.get().and_then(|data| data.planes(&key));
    // A per-cell override wins. A forced pass otherwise re-uses the persistent
    // cache when it has this cell, so a revisited cell skips the mesh walk. A
    // settle retry always regenerates so the final set is complete, and it
    // refreshes the cache entry.
    let mut settle_needed = false;
    let mut from_cache = false;
    let (planes, raw): (Vec<PlaneRecord>, usize) = if let Some(override_planes) = override_planes {
        (override_planes.to_vec(), override_planes.len())
    } else if !RUNTIME_GENERATE.load(Ordering::Acquire) {
        (Vec::new(), 0)
    } else if force {
        // Convert under the lock so a cache hit costs one plane allocation
        // instead of a temporary cached-plane vector plus the records.
        let cached = CACHE.get().and_then(|cache| {
            let guard = cache.lock();
            guard
                .get(&key)
                .map(|planes| (cached_to_records(planes), planes.len()))
        });
        match cached {
            Some((records, count)) => {
                from_cache = true;
                (records, count)
            }
            None => {
                let (planes, raw) = runtime_generate::generate(cell, max, observer);
                store_in_cache(&key, &planes);
                settle_needed = true;
                (planes, raw)
            }
        }
    } else {
        // A settle retry keeps settling until two passes agree, and refreshes
        // the cache so the latest set is always reusable on a revisit.
        let (planes, raw) = runtime_generate::generate(cell, max, observer);
        store_in_cache(&key, &planes);
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
        // below; a settle pass stops once enough identical passes were seen,
        // which keeps one extra pass to catch late-attached 3D.
        settle_needed = false;
        if !force && passes >= SETTLE_STABLE_PASSES {
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
    *tracked = next;
    CURRENT_SCENE_GRAPH.store(scene_graph as usize, Ordering::Release);
    CURRENT_CELL_PTR.store(cell as usize, Ordering::Release);
    CURRENT_CELL_KEY.store(key_signature, Ordering::Release);
    LAST_SIGNATURE.store(signature, Ordering::Release);
    if log::log_enabled!(log::Level::Debug) {
        log::debug!(
            "[OCCLUSION_PLANES] cell candidates={} raw={} injected={} reused={} removed={} \
             cap={} cached={}",
            planes.len(),
            raw,
            created,
            reused,
            removed,
            max,
            from_cache,
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
            rotation: PlaneRotation::Matrix(plane.rotation),
            priority: plane.priority,
            source_form_id: plane.source_form_id,
        })
        .collect()
}

/// Convert a generated plane into a cache entry. Only ready matrices are
/// cached; hand-authored axis-angle overrides are not cached.
fn record_to_cached(record: &PlaneRecord) -> Option<CachedPlane> {
    let PlaneRotation::Matrix(rotation) = record.rotation else {
        return None;
    };
    Some(CachedPlane {
        position: record.position,
        size: record.size,
        rotation,
        priority: record.priority,
        source_form_id: record.source_form_id,
    })
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
        let matrix = rotation_matrix(plane.rotation);
        for row in 0..3 {
            write(base + 5 + row, matrix[row * 3 + 1]);
            write(base + 8 + row, matrix[row * 3]);
            write(base + 11 + row, matrix[row * 3 + 2]);
        }
    }
    needed as i32
}

fn rotation_matrix(rotation: PlaneRotation) -> [f32; 9] {
    match rotation {
        PlaneRotation::Matrix(matrix) => matrix,
        PlaneRotation::AxisAngle { axis, angle } => axis_angle_matrix(axis, angle),
    }
}

/// Pure Rodrigues axis-angle matrix, so the debug query never calls the engine
/// from the helper's render thread.
fn axis_angle_matrix(axis: [f32; 3], angle: f32) -> [f32; 9] {
    let length = (axis[0] * axis[0] + axis[1] * axis[1] + axis[2] * axis[2]).sqrt();
    if !length.is_finite() || length <= 0.0 {
        return [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
    }
    let (x, y, z) = (axis[0] / length, axis[1] / length, axis[2] / length);
    let (s, c) = angle.sin_cos();
    let t = 1.0 - c;
    [
        t * x * x + c,
        t * x * y - s * z,
        t * x * z + s * y,
        t * x * y + s * z,
        t * y * y + c,
        t * y * z - s * x,
        t * x * z - s * y,
        t * y * z + s * x,
        t * z * z + c,
    ]
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
/// without re-walking the meshes.
fn store_in_cache(key: &CellKey, planes: &[PlaneRecord]) {
    let Some(cache) = CACHE.get() else {
        return;
    };
    let cached: Vec<CachedPlane> = planes.iter().filter_map(record_to_cached).collect();
    cache.lock().insert(*key, cached);
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
    let matrix = match record.rotation {
        PlaneRotation::Matrix(matrix) => matrix,
        PlaneRotation::AxisAngle { axis, angle } => {
            // The identity case needs no engine call and avoids a degenerate
            // zero-axis request to the axis-angle builder.
            if angle == 0.0 {
                [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
            } else {
                let mut matrix = [0.0f32; 9];
                unsafe {
                    (fns.build_rotation)(matrix.as_mut_ptr(), angle, axis[0], axis[1], axis[2]);
                }
                matrix
            }
        }
    };
    let size = native_size(record.size);
    unsafe {
        (fns.set_size)(plane, size.as_ptr());
        (fns.set_position)(plane, record.position.as_ptr());
        (fns.set_rotation)(plane, matrix.as_ptr());
        // The constructor marks the plane two-sided. Clear that flag after the
        // setters so `0x00C358A0` runs its camera-side test every frame and
        // activates the rectangle only from the face's outward side.
        write_u8_at(plane, PLANE_SIDE_FLAG, 0);
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
    let worldspace = unsafe { read_ptr_at(cell, CELL_WORLDSPACE) };
    if worldspace.is_null() {
        CellKey::Interior {
            form_id: unsafe { read_u32_at(cell, CELL_FORM_ID) },
        }
    } else {
        // `cell + 0x48` is a `CellCoordinates*`; the grid values live in the
        // pointed structure, not in the two cell fields.
        let coords = unsafe { read_ptr_at(cell, CELL_EXTERIOR_COORDS) };
        let (x, y) = if coords.is_null() {
            (0, 0)
        } else {
            (unsafe { read_i32_at(coords, COORDS_X) }, unsafe {
                read_i32_at(coords, COORDS_Y)
            })
        };
        CellKey::Exterior {
            worldspace: unsafe { read_u32_at(worldspace, TESFORM_REF_ID) },
            x,
            y,
        }
    }
}
