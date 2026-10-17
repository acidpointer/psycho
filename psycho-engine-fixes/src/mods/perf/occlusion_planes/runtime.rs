//! Native `BSOcclusionPlane` lifecycle for runtime-generated and override data.
//!
//! Planes are created through the engine's own authored `XOCP` path, retained
//! once, appended to the scene-graph occluder list, and removed and released
//! when the cell or scene graph changes. All work runs on the xNVSE event
//! thread. The per-frame path compares two atomics and returns immediately on
//! an unchanged cell; allocation, list scans, generation and logging happen
//! only on a transition.
//!
//! A cell's planes come from the optional TOML override when it lists that
//! cell; otherwise the runtime collector derives them from live cell geometry.
//! The module never clears the whole list and never touches an authored plane.
//! A replacement scene graph means the old nodes were already retired by the
//! engine, so the module releases its references without dereferencing the old
//! list. A load/new/exit event defers cleanup to the next frame so the module
//! never scans a list that may be under teardown.

use core::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

use libpsycho::ffi::fnptr::FnPtr;
use parking_lot::Mutex;

use super::contract::{
    ALLOC, APPEND, BUILD_ROTATION, CELL_EXTERIOR_COORDS, CELL_FORM_ID, CELL_WORLDSPACE, CONSTRUCT,
    COORDS_X, COORDS_Y, FREE_NODE, LIST_COUNT, LIST_HEAD, LIST_OFFSET, LIST_TAIL, NODE_NEXT,
    NODE_PLANE, NODE_PREV, OWNER_POSITION, OWNER_SCENE_GRAPH, PLANE_SIZE, PLAYER_PTR,
    REFCOUNT_OFFSET, SET_POSITION, SET_ROTATION, SET_SIZE, SIGNATURES, SINGLETON, TESFORM_REF_ID,
    VTABLE_DELETE_THIS,
};
use super::contract::{
    AllocFn, AppendFn, BuildRotationFn, ConstructFn, FreeNodeFn, SetPairFn, SetRotationFn,
    SetTripleFn, SingletonFn,
};
use super::data::{CellKey, PlaneRecord, PlaneRotation, PlaneSet};
use super::raw::{
    read_f32_at, read_i32_at, read_ptr, read_ptr_at, read_u32_at, write_ptr_at, write_u32_at,
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

static ENABLED: AtomicBool = AtomicBool::new(false);
static RUNTIME_GENERATE: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static MAX_PER_CELL: AtomicUsize = AtomicUsize::new(1);
static RESET_PENDING: AtomicBool = AtomicBool::new(false);
static DATA: OnceLock<PlaneSet> = OnceLock::new();
static FNS: OnceLock<EngineFns> = OnceLock::new();
static TRACKED: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static CURRENT_SCENE_GRAPH: AtomicUsize = AtomicUsize::new(0);
static CURRENT_CELL_KEY: AtomicU64 = AtomicU64::new(0);
static LAST_SIGNATURE: AtomicU64 = AtomicU64::new(0);
static SETTLE_RETRIES_LEFT: AtomicUsize = AtomicUsize::new(0);
static SETTLE_COUNTDOWN: AtomicUsize = AtomicUsize::new(0);

/// Record configuration at startup. No file, allocation or engine access
/// occurs here; the feature activates only after `DeferredInit`.
pub(super) fn configure(enabled: bool, max_per_cell: u16, runtime_generate: bool) {
    ENABLED.store(enabled, Ordering::Release);
    RUNTIME_GENERATE.store(runtime_generate, Ordering::Release);
    MAX_PER_CELL.store(usize::from(max_per_cell.max(1)), Ordering::Release);
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
    READY.store(true, Ordering::Release);
    if !data_is_used() {
        log::info!(
            "[OCCLUSION_PLANES] Active; planes are generated at runtime from live cell geometry"
        );
    } else {
        log::info!("[OCCLUSION_PLANES] Active with {cells} override cell(s) from `{path}`");
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
        // A cell pointer can be reused for a different grid cell, so compare
        // the cell identity key, not only the pointer.
        let key = cell_key_signature(&cell_key(cell));
        let same_target = CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene
            && CURRENT_CELL_KEY.load(Ordering::Acquire) == key;
        let settle_left = SETTLE_RETRIES_LEFT.load(Ordering::Acquire);
        if !pending && same_target && settle_left == 0 {
            return;
        }
        let observer = read_observer(owner);
        if pending || !same_target {
            // A new target (or an explicit reset) always rebuilds and restarts
            // the settle window, because the engine list may have been reset.
            reconcile(fns, scene_graph, cell, observer, true);
            SETTLE_RETRIES_LEFT.store(SETTLE_RETRIES, Ordering::Release);
            SETTLE_COUNTDOWN.store(SETTLE_INTERVAL_FRAMES, Ordering::Release);
        } else {
            // Settle retry: regenerate only when the interval elapses. The
            // rebuild itself is skipped when the generated set is unchanged.
            let countdown = SETTLE_COUNTDOWN.load(Ordering::Acquire);
            if countdown > 1 {
                SETTLE_COUNTDOWN.store(countdown - 1, Ordering::Release);
                return;
            }
            reconcile(fns, scene_graph, cell, observer, false);
            SETTLE_RETRIES_LEFT.store(settle_left.saturating_sub(1), Ordering::Release);
            SETTLE_COUNTDOWN.store(SETTLE_INTERVAL_FRAMES, Ordering::Release);
        }
    }
}

/// Hash a cell identity so a reused cell pointer still reads as a new cell.
fn cell_key_signature(key: &CellKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

/// Hash one cell's plane records. Used to skip a settle rebuild when the
/// generated set has not changed.
pub(super) fn plane_signature(planes: &[PlaneRecord]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for plane in planes {
        for value in plane.position {
            value.to_bits().hash(&mut hasher);
        }
        for value in plane.size {
            value.to_bits().hash(&mut hasher);
        }
        match plane.rotation {
            PlaneRotation::Matrix(matrix) => {
                for value in matrix {
                    value.to_bits().hash(&mut hasher);
                }
            }
            PlaneRotation::AxisAngle { axis, angle } => {
                for value in axis {
                    value.to_bits().hash(&mut hasher);
                }
                angle.to_bits().hash(&mut hasher);
            }
        }
        plane.priority.hash(&mut hasher);
    }
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

unsafe fn reconcile(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    cell: *mut c_void,
    observer: Option<[f32; 3]>,
    force: bool,
) {
    let key = unsafe { cell_key(cell) };
    let key_signature = cell_key_signature(&key);
    let max = MAX_PER_CELL.load(Ordering::Acquire);
    // A per-cell override wins; otherwise the runtime collector supplies planes.
    // `raw` is the pre-cap candidate count, so the log distinguishes a
    // cap-limited cell from a detection-limited one.
    let (planes, raw): (Vec<PlaneRecord>, usize) =
        match DATA.get().and_then(|data| data.planes(&key)) {
            Some(override_planes) => (override_planes.to_vec(), override_planes.len()),
            None if RUNTIME_GENERATE.load(Ordering::Acquire) => {
                runtime_generate::generate(cell, max, observer)
            }
            None => (Vec::new(), 0),
        };
    let signature = plane_signature(&planes);
    // A settle retry with the same target and the same generated set keeps the
    // existing planes. A forced pass (new cell/scene or explicit reset) always
    // rebuilds because the engine list may have been reset.
    if !force
        && CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene_graph as usize
        && CURRENT_CELL_KEY.load(Ordering::Acquire) == key_signature
        && LAST_SIGNATURE.load(Ordering::Acquire) == signature
    {
        return;
    }
    let mut tracked = TRACKED.lock();
    let previous_scene = CURRENT_SCENE_GRAPH.load(Ordering::Acquire);
    if previous_scene != 0 && previous_scene == scene_graph as usize {
        let list = unsafe { (previous_scene as *mut u8).add(LIST_OFFSET) as *mut c_void };
        unsafe { remove_tracked(fns, list, &tracked) };
    }
    // A different (or first) scene graph means the old list is gone; release
    // the retained references without dereferencing retired nodes.
    for &plane in tracked.iter() {
        unsafe { release_plane(plane as *mut c_void) };
    }
    tracked.clear();
    let mut created = 0usize;
    for record in &planes {
        let Some(plane) = (unsafe { create_plane(fns, record) }) else {
            continue;
        };
        unsafe { (fns.append)(scene_graph, plane) };
        tracked.push(plane as usize);
        created += 1;
    }
    CURRENT_SCENE_GRAPH.store(scene_graph as usize, Ordering::Release);
    CURRENT_CELL_KEY.store(key_signature, Ordering::Release);
    LAST_SIGNATURE.store(signature, Ordering::Release);
    if log::log_enabled!(log::Level::Debug) {
        log::debug!(
            "[OCCLUSION_PLANES] cell candidates={} raw={} injected={} cap={}",
            planes.len(),
            raw,
            created,
            max,
        );
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
    }
    Some(plane)
}

unsafe fn remove_tracked(fns: &EngineFns, list: *mut c_void, tracked: &[usize]) {
    for &plane in tracked {
        let Some(node) = (unsafe { find_node(list, plane) }) else {
            continue;
        };
        unsafe { unlink(fns, list, node) };
    }
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
