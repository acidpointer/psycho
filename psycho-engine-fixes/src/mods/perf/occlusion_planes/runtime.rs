//! Native `BSOcclusionPlane` lifecycle for runtime-generated planes.
//!
//! Planes are created through the engine's own authored `XOCP` path, retained
//! once, appended to the scene-graph occluder list, and removed and released
//! when the cell or scene graph changes. A plane whose support rectangle nearly
//! fills its vertex hull on a thick (solid-volume) mesh keeps the constructor's
//! two-sided window (`+0xEA = 1`), matching the engine's authored
//! `BSOcclusionPlane`; an irregular, thin-panel or partly open face stays
//! one-sided so `0x00C358A0` activates it only while the camera is on its
//! outward side. Engine work runs only during normal presentation on the
//! DeferredInit main thread. A steady frame checks identity and countdowns;
//! collection is sliced and native list maintenance is periodic or transitional.
//!
//! The runtime collector derives a cell's planes from live cell geometry. A
//! new cell identity must persist for a few frames before it replaces the
//! current set, so cell-seam alternation cannot make the occluders flicker.
//! The module never clears the whole list and never touches an authored plane.
//! One strong graph reference keeps its list alive until our nodes are unlinked
//! and its planes released. Graph selection is never used as a retirement
//! signal. Loading/unknown presentations and load/new/exit events invalidate
//! generation without touching engine memory. The next normal main-thread
//! presentation retires the owned injection even when there is no player/cell.
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
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use libpsycho::ffi::fnptr::FnPtr;
use libpsycho::os::windows::winapi::get_current_thread_id;
use parking_lot::Mutex;

use super::cache::PlaneCache;
use super::contract::{
    ALLOC, APPEND, CELL_EXTERIOR_COORDS, CELL_FORM_ID, CELL_INTERIOR_FLAG, CELL_INTERIOR_MASK,
    CELL_LOCK_ENTER, CELL_LOCK_LEAVE, CELL_WORLDSPACE, CONSTRUCT, COORDS_X, COORDS_Y, FREE_NODE,
    GRID_CELLS, GRID_SIZE, GRID_WORLD_X, GRID_WORLD_Y, LIST_COUNT, LIST_HEAD, LIST_OFFSET,
    LIST_TAIL, NODE_NEXT, NODE_PLANE, NODE_PREV, OWNER_POSITION, OWNER_SCENE_GRAPH,
    PLANE_ACTIVE_OFFSET, PLANE_SIDE_FLAG, PLANE_SIZE, PLAYER_PTR, REFCOUNT_OFFSET, SET_POSITION,
    SET_ROTATION, SET_SIZE, SIGNATURES, SINGLETON, TES_GRID_CELL_ARRAY, TES_SINGLETON,
    TESFORM_REF_ID, VTABLE_DELETE_THIS,
};
use super::contract::{
    AllocFn, AppendFn, CellLockFn, ConstructFn, FreeNodeFn, SetPairFn, SetRotationFn, SetTripleFn,
    SingletonFn,
};
use super::data::{CellKey, PlaneIdentity, PlaneRecord};
use super::raw::{
    read_f32_at, read_i32_at, read_ptr, read_ptr_at, read_u8_at, read_u32_at, write_ptr_at,
    write_u8_at, write_u32_at,
};
use super::runtime_generate::{self, Generation, SourceProof};

/// `NiRefObject::DeleteThis` at one vtable slot.
type DeleteThisFn = unsafe extern "thiscall" fn(*mut c_void);

/// Bounded rebuilds after a cell/scene change. The first frame can run before
/// the cell's references and their 3D are attached, so the runtime retries a
/// few times and only rebuilds when the generated plane set actually changes.
const SETTLE_RETRIES: usize = 5;
/// Frames between settle rebuilds.
const SETTLE_INTERVAL_FRAMES: usize = 20;
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
    cell_lock: CellLockFn,
    cell_unlock: CellLockFn,
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
                cell_lock: FnPtr::from_address_unchecked(CELL_LOCK_ENTER).as_fn(),
                cell_unlock: FnPtr::from_address_unchecked(CELL_LOCK_LEAVE).as_fn(),
            }
        }
    }
}

/// Cell lifetime is supplied by the current normal main-frame owner. The native
/// recursion level excludes reference-list relinking/removal during one slice;
/// it does not claim to synchronize arbitrary scene-graph mutation.
struct CellRefLock<'a> {
    cell: *mut c_void,
    fns: &'a EngineFns,
}

impl<'a> CellRefLock<'a> {
    unsafe fn acquire(cell: *mut c_void, fns: &'a EngineFns) -> Self {
        unsafe { (fns.cell_lock)(cell) };
        Self { cell, fns }
    }
}

impl Drop for CellRefLock<'_> {
    fn drop(&mut self) {
        // SAFETY: acquire owns one recursion level and the main-frame cell
        // remains live until this slice returns.
        unsafe { (self.fns.cell_unlock)(self.cell) };
    }
}

/// Increment the object's `NiRefObject` count at `+4`.
///
/// The engine's `0x0040F6E0` is a plain `InterlockedIncrement` of this field,
/// and several performance mods replace that function in place with an inlined
/// `lock xadd` form. Managing the documented field directly keeps the feature
/// independent of whichever equivalent form is installed.
///
/// # Safety
/// The pointer is an aligned live NiRefObject (plane or BSPortalGraph), held by
/// an existing owner through this acquisition. Its count is initialized at +4.
pub(super) unsafe fn retain_plane(plane: *mut c_void) {
    let counter = unsafe { &*((plane as *const u8).add(REFCOUNT_OFFSET) as *const AtomicI32) };
    counter.fetch_add(1, Ordering::AcqRel);
}

/// Decrement the object's `NiRefObject` count and destroy it at zero.
///
/// Mirrors the engine's `0x00401970`: decrement `+4`, and on the transition to
/// zero call the object's `DeleteThis` virtual (`vtable+4`), which runs the
/// scalar deleting destructor. This avoids the commonly patched release entry.
///
/// # Safety
/// The caller transfers exactly one owned reference. The pointer and vtable
/// remain live until this decrement; no borrowed list membership may outlive it.
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

/// Full cell identity storage, written/read only on admitted main presentation.
/// Separate atomic words keep this static inert before DeferredInit. These are
/// not a cross-thread snapshot API; dashboard counters have their own owner.
struct CellSlot {
    kind: AtomicU32,
    a: AtomicU32,
    b: AtomicU32,
    c: AtomicU32,
}

impl CellSlot {
    const fn new() -> Self {
        Self {
            kind: AtomicU32::new(0),
            a: AtomicU32::new(0),
            b: AtomicU32::new(0),
            c: AtomicU32::new(0),
        }
    }

    fn get(&self) -> Option<CellKey> {
        match self.kind.load(Ordering::Relaxed) {
            1 => Some(CellKey::Interior {
                form_id: self.a.load(Ordering::Relaxed),
            }),
            2 => Some(CellKey::Exterior {
                worldspace: self.a.load(Ordering::Relaxed),
                x: self.b.load(Ordering::Relaxed) as i32,
                y: self.c.load(Ordering::Relaxed) as i32,
            }),
            _ => None,
        }
    }

    fn set(&self, key: Option<CellKey>) {
        let (kind, a, b, c) = match key {
            None => (0, 0, 0, 0),
            Some(CellKey::Interior { form_id }) => (1, form_id, 0, 0),
            Some(CellKey::Exterior { worldspace, x, y }) => (2, worldspace, x as u32, y as u32),
        };
        self.a.store(a, Ordering::Relaxed);
        self.b.store(b, Ordering::Relaxed);
        self.c.store(c, Ordering::Relaxed);
        self.kind.store(kind, Ordering::Relaxed);
    }
}

/// One injected plane we own, with the full descriptor used to reuse it across
/// settle passes instead of removing and recreating the whole list.
#[derive(Clone, Copy, Debug)]
struct TrackedPlane {
    pointer: usize,
    key: PlaneIdentity,
}

/// Own the graph as well as its injected planes. Active selection may change
/// while a cell still owns the old graph. This reference keeps its list live
/// until our nodes are unlinked, after which planes and graph can be released.
struct Injection {
    graph: usize,
    planes: Vec<TrackedPlane>,
}

/// A moved strong graph reference. Declare it outside the publication lock's
/// scope so graph destruction (which releases other scene owners) cannot run
/// while a native publisher waits holding its own engine locks.
struct RetiredGraph(usize);

impl Drop for RetiredGraph {
    fn drop(&mut self) {
        // SAFETY: retirement moved exactly one retained NiRefObject reference
        // here after ending every injector-owned list membership.
        unsafe { release_plane(self.0 as *mut c_void) };
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static MAX_PER_CELL: AtomicUsize = AtomicUsize::new(1);
static RESET_PENDING: AtomicBool = AtomicBool::new(false);
static FNS: OnceLock<EngineFns> = OnceLock::new();
static TRACKED: Mutex<Injection> = Mutex::new(Injection {
    graph: 0,
    planes: Vec::new(),
});
static MAIN_THREAD: AtomicU32 = AtomicU32::new(0);
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
/// Current cell address alongside its freshly checked identity. The address
/// alone cannot distinguish a live cell from reused engine storage.
static CURRENT_CELL_PTR: AtomicUsize = AtomicUsize::new(0);
static CURRENT_CELL_KEY: CellSlot = CellSlot::new();
static LAST_SIGNATURE: Mutex<Vec<PlaneIdentity>> = Mutex::new(Vec::new());
static SETTLE_RETRIES_LEFT: AtomicUsize = AtomicUsize::new(0);
static SETTLE_COUNTDOWN: AtomicUsize = AtomicUsize::new(0);
/// Set when a plane allocation failed, so the settle window keeps retrying
/// instead of treating a short set as stable.
static INCOMPLETE: AtomicBool = AtomicBool::new(false);
/// Geometry requiring later validation; independent of missing native objects.
static RESCAN_PENDING: AtomicBool = AtomicBool::new(false);
/// Desired Rust records survive native allocation failure, including an empty
/// tracked set. No borrowed engine pointer is dereferenced from this state.
static DESIRED: Mutex<Option<(GenerationTarget, Vec<PlaneRecord>)>> = Mutex::new(None);
/// Candidate target awaiting confirmation. Rapid cell-boundary flapping would
/// otherwise remove and rebuild the whole plane set every few frames.
static PENDING_SCENE: AtomicUsize = AtomicUsize::new(0);
static PENDING_KEY: CellSlot = CellSlot::new();
static PENDING_STREAK: AtomicUsize = AtomicUsize::new(0);
/// Consecutive frames a new cell target must persist before its planes replace
/// the current set. About 60 ms at 60 fps: enough to reject a seam flip-flop
/// while keeping the stale-plane window short.
pub(super) const TARGET_STABLE_FRAMES: usize = 4;
/// Defensive bound on the loaded-grid size. `0x004BA490` bounds both axes with
/// `gridCellArray + 0xC`; the engine's default exterior grid is 5.
const MAX_GRID_DIMENSION: i32 = 64;
/// Frames between checks that the cached neighborhood still matches the loaded
/// grid. Removed neighbors leave the union; cached additions require bounded
/// fresh input validation, without rectangle generation.
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
/// `planes` holds the freshly generated center and settled neighbor sets whose
/// complete source input was revalidated. Neighbor validation copies admitted
/// mesh input but never runs coverage or merging. No world placement is loaded
/// from disk.
struct Neighborhood {
    center: CellKey,
    worldspace: usize,
    cells: Vec<NeighborCell>,
    planes: HashMap<CellKey, CellPlanes>,
}

/// Rust-owned cell records with explicit neighbor admission state.
#[derive(Clone)]
struct CellPlanes {
    records: Vec<PlaneRecord>,
    settled: bool,
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
static GENERATION: Mutex<Option<GenerationJob>> = Mutex::new(None);
static GENERATION_ACTIVE: AtomicBool = AtomicBool::new(false);
static SAVE_REQUESTED: AtomicBool = AtomicBool::new(false);
static WORLD_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Addresses are identity tokens only; collection gets the current cell afresh
/// each slice. A load, graph switch or reused cell address cannot resume old work.
#[derive(Clone, Copy, PartialEq, Eq)]
struct GenerationTarget {
    epoch: u64,
    cell: usize,
    key: CellKey,
    graph: usize,
}

struct GenerationJob {
    target: GenerationTarget,
    work: Generation,
    initial: bool,
}

/// Pending collection is not a completed settle attempt.
#[derive(Clone, Copy, Debug)]
enum ReconcileOutcome {
    Pending,
    Finished { initial: bool, settle: bool },
}

impl ReconcileOutcome {
    /// A pending pass cannot spend an attempt or reset the completion timer.
    fn schedule(self, remaining: usize) -> Option<(usize, usize)> {
        match self {
            Self::Pending => None,
            Self::Finished { settle: false, .. } => Some((0, 0)),
            Self::Finished {
                initial: true,
                settle: true,
            } => Some((SETTLE_RETRIES, SETTLE_INTERVAL_FRAMES)),
            Self::Finished {
                initial: false,
                settle: true,
            } => {
                let remaining = remaining.saturating_sub(1);
                Some((
                    remaining,
                    if remaining == 0 {
                        CACHE_SAVE_INTERVAL_FRAMES
                    } else {
                        SETTLE_INTERVAL_FRAMES
                    },
                ))
            }
        }
    }
}

/// Apply a completed pass exactly once regardless of how many frames it took.
fn consume_outcome(outcome: ReconcileOutcome) {
    if let Some((remaining, countdown)) =
        outcome.schedule(SETTLE_RETRIES_LEFT.load(Ordering::Acquire))
    {
        SETTLE_RETRIES_LEFT.store(remaining, Ordering::Release);
        SETTLE_COUNTDOWN.store(countdown, Ordering::Release);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn pending_passes_do_not_spend_settle_attempts() {
        assert_eq!(ReconcileOutcome::Pending.schedule(SETTLE_RETRIES), None);
        let first = ReconcileOutcome::Finished {
            initial: true,
            settle: true,
        };
        assert_eq!(
            first.schedule(0),
            Some((SETTLE_RETRIES, SETTLE_INTERVAL_FRAMES))
        );
        let stable = ReconcileOutcome::Finished {
            initial: false,
            settle: false,
        };
        assert_eq!(stable.schedule(SETTLE_RETRIES), Some((0, 0)));
        let retry = ReconcileOutcome::Finished {
            initial: false,
            settle: true,
        };
        assert_eq!(
            retry.schedule(SETTLE_RETRIES),
            Some((SETTLE_RETRIES - 1, SETTLE_INTERVAL_FRAMES))
        );
        assert_eq!(retry.schedule(1), Some((0, CACHE_SAVE_INTERVAL_FRAMES)));
    }
}

// ---------------------------------------------------------------------------
// Dashboard counters.
//
// Every value is a scalar atomic updated on the event thread and read by the
// helper's background sampling thread, so the dashboard read never locks, walks
// the engine list, or touches engine memory.
// ---------------------------------------------------------------------------

/// Planes currently linked in the engine list (last presence check).
static DASH_PRESENT: AtomicUsize = AtomicUsize::new(0);
/// Linked planes the engine admitted for the current camera (`+0x40 == 1`).
static DASH_ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// Loaded cells with ephemeral world records.
static DASH_CACHED_CELLS: AtomicUsize = AtomicUsize::new(0);
/// Current cell kind: 0 none, 1 interior, 2 exterior.
static DASH_CELL_KIND: AtomicUsize = AtomicUsize::new(0);
/// Interior cell `FormID`, or 0.
static DASH_CELL_FORM_ID: AtomicU32 = AtomicU32::new(0);
/// Exterior cell grid X, or 0.
static DASH_CELL_X: AtomicI32 = AtomicI32::new(0);
/// Exterior cell grid Y, or 0.
static DASH_CELL_Y: AtomicI32 = AtomicI32::new(0);
/// Exterior worldspace `FormID`, or 0.
static DASH_WORLDSPACE: AtomicU32 = AtomicU32::new(0);
/// Completed cell rebuilds this session.
static DASH_REBUILDS: AtomicU64 = AtomicU64::new(0);
/// Wall time of the last completed generation, in milliseconds.
static DASH_LAST_GEN_MS: AtomicU64 = AtomicU64::new(0);
/// Planes created this session.
static DASH_CREATED: AtomicU64 = AtomicU64::new(0);
/// Planes removed this session.
static DASH_REMOVED: AtomicU64 = AtomicU64::new(0);
/// Completed rebuilds that reused at least one local face analysis.
static DASH_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
/// Candidates offered to the last rebuild.
static DASH_LAST_CANDIDATES: AtomicU64 = AtomicU64::new(0);
/// Planes selected by the last rebuild.
static DASH_LAST_SELECTED: AtomicU64 = AtomicU64::new(0);
/// Planes created by the last rebuild.
static DASH_LAST_CREATED: AtomicU64 = AtomicU64::new(0);
/// Planes removed by the last rebuild.
static DASH_LAST_REMOVED: AtomicU64 = AtomicU64::new(0);
/// Whether the last rebuild reused local face analysis.
static DASH_LAST_FROM_CACHE: AtomicBool = AtomicBool::new(false);

/// Plain-data snapshot of the occlusion-plane runtime for the dashboard.
///
/// Fixed-width scalars only, so it copies across the helper/core DLL boundary
/// without any allocation or pointer.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DashboardCounters {
    pub(crate) configured: u64,
    pub(crate) ready: u64,
    pub(crate) generation_running: u64,
    pub(crate) grid_radius: u64,
    pub(crate) max_per_cell: u64,
    pub(crate) tracked: u64,
    pub(crate) active: u64,
    pub(crate) cached_cells: u64,
    pub(crate) cell_kind: u64,
    pub(crate) cell_form_id: u64,
    pub(crate) cell_x: i64,
    pub(crate) cell_y: i64,
    pub(crate) worldspace_form_id: u64,
    pub(crate) rebuilds: u64,
    pub(crate) last_generation_ms: u64,
    pub(crate) planes_created: u64,
    pub(crate) planes_removed: u64,
    pub(crate) cache_hits: u64,
    pub(crate) last_candidates: u64,
    pub(crate) last_selected: u64,
    pub(crate) last_created: u64,
    pub(crate) last_removed: u64,
    pub(crate) last_from_cache: u64,
}

/// Read the occlusion-plane dashboard counters. Called from the helper's
/// sampling thread; it only loads atomics.
pub(crate) fn dashboard_counters() -> DashboardCounters {
    DashboardCounters {
        configured: u64::from(ENABLED.load(Ordering::Relaxed)),
        ready: u64::from(READY.load(Ordering::Relaxed)),
        generation_running: u64::from(GENERATION_ACTIVE.load(Ordering::Relaxed)),
        grid_radius: GRID_RADIUS.load(Ordering::Relaxed) as u64,
        max_per_cell: MAX_PER_CELL.load(Ordering::Relaxed) as u64,
        tracked: TRACKED_COUNT.load(Ordering::Relaxed) as u64,
        active: DASH_ACTIVE.load(Ordering::Relaxed) as u64,
        cached_cells: DASH_CACHED_CELLS.load(Ordering::Relaxed) as u64,
        cell_kind: DASH_CELL_KIND.load(Ordering::Relaxed) as u64,
        cell_form_id: u64::from(DASH_CELL_FORM_ID.load(Ordering::Relaxed)),
        cell_x: i64::from(DASH_CELL_X.load(Ordering::Relaxed)),
        cell_y: i64::from(DASH_CELL_Y.load(Ordering::Relaxed)),
        worldspace_form_id: u64::from(DASH_WORLDSPACE.load(Ordering::Relaxed)),
        rebuilds: DASH_REBUILDS.load(Ordering::Relaxed),
        last_generation_ms: DASH_LAST_GEN_MS.load(Ordering::Relaxed),
        planes_created: DASH_CREATED.load(Ordering::Relaxed),
        planes_removed: DASH_REMOVED.load(Ordering::Relaxed),
        cache_hits: DASH_CACHE_HITS.load(Ordering::Relaxed),
        last_candidates: DASH_LAST_CANDIDATES.load(Ordering::Relaxed),
        last_selected: DASH_LAST_SELECTED.load(Ordering::Relaxed),
        last_created: DASH_LAST_CREATED.load(Ordering::Relaxed),
        last_removed: DASH_LAST_REMOVED.load(Ordering::Relaxed),
        last_from_cache: u64::from(DASH_LAST_FROM_CACHE.load(Ordering::Relaxed)),
    }
}

/// Publish the current cell identity for the dashboard.
fn store_cell_counters(key: &CellKey) {
    match key {
        CellKey::Interior { form_id } => {
            DASH_CELL_KIND.store(1, Ordering::Relaxed);
            DASH_CELL_FORM_ID.store(*form_id, Ordering::Relaxed);
            DASH_CELL_X.store(0, Ordering::Relaxed);
            DASH_CELL_Y.store(0, Ordering::Relaxed);
            DASH_WORLDSPACE.store(0, Ordering::Relaxed);
        }
        CellKey::Exterior { worldspace, x, y } => {
            DASH_CELL_KIND.store(2, Ordering::Relaxed);
            DASH_CELL_FORM_ID.store(0, Ordering::Relaxed);
            DASH_CELL_X.store(*x, Ordering::Relaxed);
            DASH_CELL_Y.store(*y, Ordering::Relaxed);
            DASH_WORLDSPACE.store(*worldspace, Ordering::Relaxed);
        }
    }
}
/// Consecutive settle passes that produced the same set. The window stops once
/// this reaches `SETTLE_STABLE_PASSES`, so the common case costs two extra
/// walks instead of all five while still allowing one more pass for late 3D.
static PRESENCE_COUNTDOWN: AtomicUsize = AtomicUsize::new(PRESENCE_INTERVAL_FRAMES);
static SAVE_COUNTDOWN: AtomicUsize = AtomicUsize::new(CACHE_SAVE_INTERVAL_FRAMES);
static CACHE: OnceLock<Mutex<PlaneCache>> = OnceLock::new();
static CACHE_PATH: OnceLock<String> = OnceLock::new();
/// Whether the verbose per-cell diagnostics are written at debug level.
static DEBUG_LOG: AtomicBool = AtomicBool::new(false);

/// True when the configured verbose occlusion-plane diagnostics are enabled.
///
/// The module logs a lot per cell; the flag keeps the log readable by default
/// while warnings and errors always log.
pub(super) fn debug_log_enabled() -> bool {
    DEBUG_LOG.load(Ordering::Relaxed)
}

/// Record configuration at startup. No file, allocation or engine access
/// occurs here; the feature activates only after `DeferredInit`.
pub(super) fn configure(
    enabled: bool,
    max_per_cell: u16,
    grid_radius: u8,
    cache_path: &str,
    debug_log: bool,
) {
    ENABLED.store(enabled, Ordering::Release);
    MAX_PER_CELL.store(usize::from(max_per_cell.max(1)), Ordering::Release);
    GRID_RADIUS.store(usize::from(grid_radius.min(2)), Ordering::Release);
    DEBUG_LOG.store(debug_log, Ordering::Release);
    let _ = CACHE_PATH.set(cache_path.to_string());
    if enabled {
        log::info!("[OCCLUSION_PLANES] Prepared; activation at DeferredInit");
    } else {
        log::info!("[OCCLUSION_PLANES] Disabled by configuration");
    }
}

/// Route one core event id to the occlusion-plane lifecycle.
pub(super) fn observe_event(kind: u32, frame_phase: i32) {
    if kind == crate::events::DEFERRED_INIT {
        activate();
        return;
    }
    if !READY.load(Ordering::Acquire) {
        return;
    }
    match kind {
        crate::events::ON_FRAME_PRESENT if frame_phase == 0 => frame_tick(),
        crate::events::ON_FRAME_PRESENT => {
            invalidate_world();
        }
        crate::events::PRE_LOAD_GAME
        | crate::events::NEW_GAME
        | crate::events::EXIT_TO_MAIN_MENU => {
            invalidate_world();
            save_cache();
        }
        _ => {}
    }
}

/// Invalidates only Rust work identities. Loading/unknown callbacks never
/// dereference cells, traverse lists or release a native object.
fn invalidate_world() {
    WORLD_EPOCH.fetch_add(1, Ordering::AcqRel);
    RESET_PENDING.store(true, Ordering::Release);
}

fn activate() {
    if !ENABLED.load(Ordering::Acquire) || READY.load(Ordering::Acquire) {
        return;
    }
    if !super::native_list::ready() {
        return;
    }
    if let Err(error) = verify_contracts() {
        log::error!("[OCCLUSION_PLANES] Native contract unavailable; feature disabled: {error:#}");
        return;
    }
    if let Err(error) = super::native_list::publish() {
        log::error!("[OCCLUSION_PLANES] Native publication ownership unavailable: {error:#}");
        return;
    }
    let _ = FNS.set(EngineFns::resolve());
    // Disk data contains local analysis only. Every live hit compares complete
    // mesh input; world placements are ephemeral and require source validation.
    let cache_path = CACHE_PATH.get().map(String::as_str).unwrap_or_default();
    runtime_generate::load_analysis_cache(cache_path);
    let _ = CACHE.set(Mutex::new(PlaneCache::empty()));
    DASH_CACHED_CELLS.store(0, Ordering::Relaxed);
    // xNVSE DeferredInit and normal presentation are main-thread callbacks.
    // A mismatched host invocation cannot enter any native list/mesh operation.
    MAIN_THREAD.store(get_current_thread_id(), Ordering::Release);
    READY.store(true, Ordering::Release);
    log::info!(
        "[OCCLUSION_PLANES] Active; planes are generated at runtime, grid radius={}, \
         content-validated local cache",
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

/// Measure the per-frame module cost. A steady frame checks identity; the
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
        return;
    }
    FRAME_COST_COOLDOWN.store(FRAME_COST_COOLDOWN_FRAMES, Ordering::Relaxed);
    log::warn!("[OCCLUSION_PLANES] frame work {elapsed_us} us");
}

fn frame_tick_inner() {
    if get_current_thread_id() != MAIN_THREAD.load(Ordering::Acquire) {
        invalidate_world();
        return;
    }
    if FRAME_COST_COOLDOWN.load(Ordering::Relaxed) > 0 {
        FRAME_COST_COOLDOWN.fetch_sub(1, Ordering::Relaxed);
    }
    if !super::native_list::publishers_quiescent() {
        return;
    }
    let pending = RESET_PENDING.swap(false, Ordering::AcqRel);
    let Some(fns) = FNS.get() else {
        restore_pending(pending);
        return;
    };
    if pending {
        reset_world(fns);
    }
    // Safety: every read is a volatile pointer/word read on the event thread;
    // null is checked before the next dereference. The engine state is read-only
    // here and the module only writes its own planes and list nodes.
    unsafe {
        let player = read_ptr(PLAYER_PTR);
        if player.is_null() {
            tick_cache_save();
            return;
        }
        let cell = read_ptr_at(player, super::contract::REFR_PARENT_CELL);
        if cell.is_null() {
            tick_cache_save();
            return;
        }
        let owner = (fns.singleton)(0);
        if owner.is_null() {
            return;
        }
        let scene_graph = read_ptr_at(owner, OWNER_SCENE_GRAPH);
        if scene_graph.is_null() {
            return;
        }
        let scene = scene_graph as usize;
        let cell_ptr = cell as usize;
        let key = cell_key(cell);
        let candidate_key = key;
        let generation_target = GenerationTarget {
            epoch: WORLD_EPOCH.load(Ordering::Acquire),
            cell: cell_ptr,
            key,
            graph: scene,
        };
        // A resumable cell generation is in flight: advance it every frame (not
        // only on the settle interval) so the plane set appears as soon as
        // possible while each frame pays only the fixed work budget. The target
        // is the generation's own cell, because `CURRENT_*` still names the
        // previous cell until the walk completes and the set is installed; a
        // `same_target` check would otherwise restart the walk every few frames.
        if !pending && GENERATION_ACTIVE.load(Ordering::Acquire) {
            if GENERATION
                .lock()
                .as_ref()
                .is_some_and(|job| job.target == generation_target)
            {
                let observer = read_observer(owner);
                consume_outcome(reconcile(fns, scene_graph, cell, observer, false));
                return;
            }
            // The player left the cell whose walk was in flight; drop it.
            *GENERATION.lock() = None;
            GENERATION_ACTIVE.store(false, Ordering::Release);
        }
        // Check identity even when the address is unchanged: the engine may
        // reuse cell storage after retirement without changing its address.
        let fast_same = CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene
            && CURRENT_CELL_PTR.load(Ordering::Acquire) == cell_ptr
            && CURRENT_CELL_KEY.get() == Some(candidate_key);
        let same_target = fast_same;
        if same_target {
            clear_pending_target();
        }
        let settle_left = SETTLE_RETRIES_LEFT.load(Ordering::Acquire);
        if !pending && same_target {
            let maintenance_due =
                (settle_left == 0 || INCOMPLETE.load(Ordering::Acquire)) && presence_due();
            if maintenance_due && INCOMPLETE.load(Ordering::Acquire) {
                repair_desired(fns, generation_target);
            }
            if settle_left == 0 && !RESCAN_PENDING.load(Ordering::Acquire) {
                // The engine can clear the occluder list on cell unload without
                // changing the cell identity. Check periodically that our planes
                // are still present and re-append them from the cache if not.
                // With no tracked planes there is nothing to maintain, so the
                // whole path stays idle.
                if maintenance_due {
                    let total = TRACKED_COUNT.load(Ordering::Acquire);
                    if total == 0 {
                        DASH_PRESENT.store(0, Ordering::Relaxed);
                        DASH_ACTIVE.store(0, Ordering::Relaxed);
                        if debug_log_enabled() && LAST_ACTIVE.swap(0, Ordering::AcqRel) != 0 {
                            log::debug!("[OCCLUSION_PLANES] presence tracked=0 present=0 active=0");
                        }
                    } else {
                        let (total, present, active) = tracked_status(scene_graph);
                        if present < total {
                            repair_desired(fns, generation_target);
                        }
                        let previous = LAST_ACTIVE.swap(active, Ordering::AcqRel);
                        // Log only when planes start or stop being admitted, so
                        // camera motion cannot turn this into per-frame spam.
                        if debug_log_enabled() && (previous == 0) != (active == 0) {
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
                if settle_left == 0 {
                    refresh_neighbors(fns, scene_graph, cell, read_observer(owner));
                }
                tick_cache_save();
                return;
            }
            let observer = read_observer(owner);
            consume_outcome(reconcile(fns, scene_graph, cell, observer, false));
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
        // A confirmed new target always captures current sources, even when
        // its local mesh analysis is already cached.
        let observer = read_observer(owner);
        consume_outcome(reconcile(fns, scene_graph, cell, observer, true));
    }
}

/// Forget any target waiting for confirmation.
fn clear_pending_target() {
    if PENDING_SCENE.load(Ordering::Relaxed) == 0 {
        return;
    }
    PENDING_SCENE.store(0, Ordering::Release);
    PENDING_KEY.set(None);
    PENDING_STREAK.store(0, Ordering::Release);
}

/// True once `(scene, key)` has been seen for `TARGET_STABLE_FRAMES` in a row.
/// A different candidate resets the streak, so a rapid seam alternation never
/// confirms.
fn confirm_target(scene: usize, key: CellKey) -> bool {
    let (confirmed, pending_scene, pending_key, streak) = target_confirmation(
        PENDING_SCENE.load(Ordering::Acquire),
        PENDING_KEY.get().unwrap_or(key),
        PENDING_STREAK.load(Ordering::Acquire),
        scene,
        key,
    );
    PENDING_SCENE.store(pending_scene, Ordering::Release);
    PENDING_KEY.set(Some(pending_key));
    PENDING_STREAK.store(streak, Ordering::Release);
    confirmed
}

/// Pure confirmation step: returns `(confirmed, pending_scene, pending_key,
/// streak)` for the next frame.
pub(super) fn target_confirmation<K: Copy + Eq>(
    pending_scene: usize,
    pending_key: K,
    streak: usize,
    scene: usize,
    key: K,
) -> (bool, usize, K, usize) {
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
    let _publication = super::native_list::lock();
    let tracked = TRACKED.lock();
    let total = tracked.planes.len();
    if tracked.graph != scene_graph as usize {
        return (total, 0, 0);
    }
    if total == 0 {
        return (0, 0, 0);
    }
    let mut scratch = MAINTENANCE
        .get_or_init(|| Mutex::new(Maintenance::default()))
        .lock();
    let linked = &mut scratch.presence;
    linked.clear();
    linked.extend(tracked.planes.iter().map(|item| (item.pointer, None)));
    let list = unsafe { (scene_graph as *mut u8).add(LIST_OFFSET) as *mut c_void };
    let mut node = unsafe { read_ptr_at(list, LIST_HEAD) };
    while !node.is_null() {
        let next = unsafe { read_ptr_at(node, NODE_NEXT) };
        let plane = unsafe { read_ptr_at(node, NODE_PLANE) } as usize;
        if let Some(status) = linked.get_mut(&plane) {
            *status = Some(unsafe { read_u32_at(plane as *mut c_void, PLANE_ACTIVE_OFFSET) } == 1);
        }
        node = next;
    }
    let present = linked.values().filter(|value| value.is_some()).count();
    let active = linked
        .values()
        .filter(|value| **value == Some(true))
        .count();
    linked.clear();
    DASH_PRESENT.store(present, Ordering::Relaxed);
    DASH_ACTIVE.store(active, Ordering::Relaxed);
    (total, present, active)
}

/// Request persistence without doing file work in a loading callback.
fn save_cache() {
    SAVE_REQUESTED.store(true, Ordering::Release);
}

/// Progress one bounded persistence unit only between generation passes.
/// Idle frames take atomics only when there is no dirty checkpoint in progress.
fn tick_cache_save() {
    let remaining = SAVE_COUNTDOWN.load(Ordering::Relaxed);
    if remaining > 0 {
        SAVE_COUNTDOWN.store(remaining - 1, Ordering::Relaxed);
    } else {
        SAVE_COUNTDOWN.store(CACHE_SAVE_INTERVAL_FRAMES, Ordering::Relaxed);
        save_cache();
    }
    if GENERATION_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let Some(path) = CACHE_PATH.get() else {
        return;
    };
    let request = SAVE_REQUESTED.swap(false, Ordering::AcqRel);
    if let Err(error) = runtime_generate::save_analysis_cache_step(path, request) {
        log::warn!(
            "[OCCLUSION_PLANES] local analysis checkpoint failed; retry on next checkpoint: {error}"
        );
    }
}

/// Canonical, order-independent plane descriptors for settle equality. Hashes
/// alone cannot establish equality, particularly on the supported 32-bit target.
pub(super) fn plane_signature(planes: &[PlaneRecord]) -> Vec<PlaneIdentity> {
    let mut keys: Vec<_> = planes.iter().map(plane_key).collect();
    keys.sort_unstable();
    keys
}

/// Native reuse identity; the historical name does not imply a hash value.
pub(super) fn plane_key(plane: &PlaneRecord) -> PlaneIdentity {
    plane.identity()
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
/// This updates loaded identities only. Neighbor records are admitted later by
/// bounded source validation. Preserve the center while reconcile refreshes it.
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
    let mut planes: HashMap<CellKey, CellPlanes> = HashMap::new();
    if let Some(records) = old
        .as_ref()
        .and_then(|neighborhood| neighborhood.planes.get(key))
        .cloned()
    {
        planes.insert(*key, records);
    }
    // A new neighborhood does not inherit unvalidated world placements. Keep
    // the center while it is refreshed; neighbors enter after exact live proof.
    let keys: Vec<_> = cells.iter().map(|item| item.key).collect();
    if let Some(cache) = CACHE.get() {
        let mut cache = cache.lock();
        cache.retain(&keys);
        DASH_CACHED_CELLS.store(cache.cell_count(), Ordering::Relaxed);
    }
    *guard = Some(Neighborhood {
        center: *key,
        worldspace,
        cells,
        planes,
    });
    drop(guard);
    NEIGHBOR_WORK.lock().clear();
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

/// One neighbor at a time shares the capture budget with center generation.
/// Native addresses are identity tokens; every slice resolves a loaded grid
/// cell afresh. Proof and queued records are Rust-owned.
struct NeighborValidation {
    owner: GenerationTarget,
    key: CellKey,
    cell: usize,
    expected: Arc<SourceProof>,
    records: Vec<PlaneRecord>,
    work: Generation,
}

struct NeighborWork {
    queue: VecDeque<CellKey>,
    active: Option<NeighborValidation>,
}

impl NeighborWork {
    fn clear(&mut self) {
        self.queue.clear();
        self.active = None;
    }
}

static NEIGHBOR_WORK: Mutex<NeighborWork> = Mutex::new(NeighborWork {
    queue: VecDeque::new(),
    active: None,
});

/// Resolve a neighbor only from the current loaded grid and worldspace.
unsafe fn resolve_neighbor(center: *mut c_void, key: CellKey) -> Option<*mut c_void> {
    let worldspace = unsafe { read_ptr_at(center, CELL_WORLDSPACE) };
    let grid = unsafe { read_grid() }?;
    for x in 0..grid.size {
        for y in 0..grid.size {
            let Some(cell) = (unsafe { grid_cell_at(&grid, x, y) }) else {
                continue;
            };
            if unsafe { read_ptr_at(cell, CELL_WORLDSPACE) } == worldspace
                && unsafe { cell_key(cell) } == key
            {
                return Some(cell);
            }
        }
    }
    None
}

/// Periodically validate cached neighbors, without running coverage or merging
/// on their meshes. Radius zero remains a single atomic load and return.
fn refresh_neighbors(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    cell: *mut c_void,
    observer: Option<[f32; 3]>,
) {
    let radius = GRID_RADIUS.load(Ordering::Acquire);
    if radius == 0 {
        return;
    }
    let center = unsafe { cell_key(cell) };
    let owner = GenerationTarget {
        epoch: WORLD_EPOCH.load(Ordering::Acquire),
        cell: cell as usize,
        key: center,
        graph: scene_graph as usize,
    };
    let due = neighbor_validate_due();
    let mut changed = false;
    if due {
        changed = refresh_neighborhood(cell, &center, radius);
    }
    let mut jobs = NEIGHBOR_WORK.lock();
    if jobs.active.as_ref().is_some_and(|job| job.owner != owner) {
        jobs.clear();
    }
    if due && jobs.active.is_none() && jobs.queue.is_empty() {
        if let Some(neighborhood) = NEIGHBORHOOD.lock().as_ref() {
            jobs.queue.extend(
                neighborhood
                    .cells
                    .iter()
                    .filter(|item| item.key != center)
                    .map(|item| item.key),
            );
        }
    }
    if jobs.active.is_none() {
        while let Some(key) = jobs.queue.pop_front() {
            let cached = CACHE
                .get()
                .and_then(|cache| cache.lock().get(&key).cloned());
            let Some(entry) = cached.filter(|entry| entry.complete) else {
                continue;
            };
            let Some(expected) = entry.proof else {
                continue;
            };
            let Some(neighbor) = (unsafe { resolve_neighbor(cell, key) }) else {
                continue;
            };
            jobs.active = Some(NeighborValidation {
                owner,
                key,
                cell: neighbor as usize,
                expected,
                records: entry.planes,
                work: Generation::new(1, None),
            });
            break;
        }
    }
    if let Some(job) = jobs.active.as_mut() {
        let current = unsafe { resolve_neighbor(cell, job.key) };
        let result = if let Some(current) = current.filter(|ptr| *ptr as usize == job.cell) {
            let _cell_lock = unsafe { CellRefLock::acquire(current, fns) };
            unsafe { job.work.validate_inputs(current) }
        } else {
            Some(None)
        };
        if let Some(proof) = result {
            let valid = proof.is_some_and(|proof| job.expected.matches(&proof));
            if let Some(neighborhood) = NEIGHBORHOOD.lock().as_mut() {
                if valid {
                    let previous = neighborhood.planes.insert(
                        job.key,
                        CellPlanes {
                            records: job.records.clone(),
                            settled: true,
                        },
                    );
                    changed |= previous.is_none_or(|previous| {
                        plane_signature(&previous.records) != plane_signature(&job.records)
                    });
                } else {
                    changed |= neighborhood.planes.remove(&job.key).is_some();
                }
            }
            jobs.active = None;
        }
    }
    drop(jobs);
    if changed {
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
        let mut seen: HashSet<PlaneIdentity> = HashSet::new();
        for cell in &neighborhood.cells {
            let key = cell.key;
            let Some(entry) = neighborhood.planes.get(&key) else {
                continue;
            };
            if key != neighborhood.center && !entry.settled {
                continue;
            }
            for plane in &entry.records {
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
    let player = unsafe { read_ptr(PLAYER_PTR) };
    if !player.is_null() {
        let cell = unsafe { read_ptr_at(player, super::contract::REFR_PARENT_CELL) };
        if !cell.is_null() {
            *DESIRED.lock() = Some((
                GenerationTarget {
                    epoch: WORLD_EPOCH.load(Ordering::Acquire),
                    cell: cell as usize,
                    key: unsafe { cell_key(cell) },
                    graph: scene_graph as usize,
                },
                selection.planes.clone(),
            ));
        }
    }
    INCOMPLETE.store(!injected.complete, Ordering::Release);
    DASH_LAST_CANDIDATES.store(candidate_count as u64, Ordering::Relaxed);
    DASH_LAST_SELECTED.store(selected as u64, Ordering::Relaxed);
    UnionReport {
        selected,
        candidates: candidate_count,
        cells,
        two_sided,
        injected,
    }
}

/// Repair native presence without repeating geometry work. Current identity is
/// supplied afresh by the admitted frame; saved addresses are comparison only.
unsafe fn repair_desired(fns: &EngineFns, target: GenerationTarget) {
    let desired = DESIRED.lock();
    let Some((owner, planes)) = desired.as_ref() else {
        return;
    };
    if *owner != target {
        return;
    }
    let result = unsafe { inject(fns, target.graph as *mut c_void, planes) };
    INCOMPLETE.store(!result.complete, Ordering::Release);
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

/// Reused only on admitted main presentation, under TRACKED. Borrowed native
/// nodes are cleared before releasing the publication lock, including on empty
/// injection. Presence stores only pointers protected by the retained planes.
#[derive(Default)]
struct Maintenance {
    presence: HashMap<usize, Option<bool>>,
    linked: HashMap<usize, usize>,
    old: Vec<(TrackedPlane, usize)>,
    by_key: HashMap<PlaneIdentity, usize>,
    used: Vec<bool>,
    next: Vec<TrackedPlane>,
}

static MAINTENANCE: OnceLock<Mutex<Maintenance>> = OnceLock::new();

/// Diff the desired set against the tracked set and update only the nodes that
/// changed. A reused plane keeps its native object and list node, so a settle
/// pass or a cell crossing cannot make the whole occluder set blink.
unsafe fn inject(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    planes: &[PlaneRecord],
) -> InjectResult {
    let mut _retired_graph = None;
    let mut _empty_graph = None;
    let _publication = super::native_list::lock();
    let mut tracked = TRACKED.lock();
    let previous_count = tracked.planes.len();
    if tracked.graph != scene_graph as usize {
        if !planes.is_empty() {
            // Acquire incoming ownership before releasing an outgoing graph.
            unsafe { retain_plane(scene_graph) };
        }
        // Selection is not destruction. Our graph reference makes the old
        // list safe to unlink even after its cell released its own reference.
        _retired_graph = unsafe { retire_injection(fns, &mut tracked) };
        if !planes.is_empty() {
            tracked.graph = scene_graph as usize;
        }
    }
    let list = if tracked.graph == 0 {
        core::ptr::null_mut()
    } else {
        unsafe { (tracked.graph as *mut u8).add(LIST_OFFSET).cast::<c_void>() }
    };
    let mut scratch = MAINTENANCE
        .get_or_init(|| Mutex::new(Maintenance::default()))
        .lock();
    let Maintenance {
        linked,
        old,
        by_key,
        used,
        next,
        ..
    } = &mut *scratch;
    linked.clear();
    old.clear();
    by_key.clear();
    used.clear();
    next.clear();
    if !list.is_null() {
        let mut node = unsafe { read_ptr_at(list, LIST_HEAD) };
        while !node.is_null() {
            let plane = unsafe { read_ptr_at(node, NODE_PLANE) };
            linked.insert(plane as usize, node as usize);
            node = unsafe { read_ptr_at(node, NODE_NEXT) };
        }
    }
    for item in tracked.planes.drain(..) {
        if let Some(&node) = linked.get(&item.pointer) {
            old.push((item, node));
        } else {
            unsafe { release_plane(item.pointer as *mut c_void) };
        }
    }
    for (index, (item, _)) in old.iter().enumerate() {
        by_key.insert(item.key, index);
    }
    used.resize(old.len(), false);
    let mut created = 0usize;
    for record in planes {
        let key = plane_key(record);
        if let Some(index) = by_key.remove(&key) {
            used[index] = true;
            next.push(old[index].0);
        } else if let Some(plane) = unsafe { create_plane(fns, record) } {
            unsafe { (fns.append)(scene_graph, plane) };
            next.push(TrackedPlane {
                pointer: plane as usize,
                key,
            });
            created += 1;
        }
    }
    for (index, (item, node)) in old.iter().enumerate() {
        if used[index] {
            continue;
        }
        if *node != 0 {
            unsafe { unlink(fns, list, *node as *mut c_void) };
        }
        unsafe { release_plane(item.pointer as *mut c_void) };
    }
    let reused = next.len().saturating_sub(created);
    let removed = previous_count.saturating_sub(reused);
    let complete = next.len() == planes.len();
    if !complete && !INCOMPLETE.load(Ordering::Acquire) {
        log::warn!(
            "[OCCLUSION_PLANES] injected {}/{} planes; retrying",
            next.len(),
            planes.len()
        );
    }
    std::mem::swap(&mut tracked.planes, next);
    // End all scratch borrowing before native publication becomes available.
    linked.clear();
    old.clear();
    by_key.clear();
    used.clear();
    next.clear();
    if tracked.planes.is_empty() && tracked.graph != 0 {
        let graph = core::mem::replace(&mut tracked.graph, 0);
        // Release the graph after the publication guard has dropped.
        _empty_graph = Some(RetiredGraph(graph));
    }
    TRACKED_COUNT.store(tracked.planes.len(), Ordering::Release);
    DASH_PRESENT.store(tracked.planes.len(), Ordering::Relaxed);
    DASH_LAST_CREATED.store(created as u64, Ordering::Relaxed);
    DASH_LAST_REMOVED.store(removed as u64, Ordering::Relaxed);
    DASH_CREATED.fetch_add(created as u64, Ordering::Relaxed);
    DASH_REMOVED.fetch_add(removed as u64, Ordering::Relaxed);
    InjectResult {
        created,
        reused,
        removed,
        complete,
    }
}

/// End every borrowed list membership before releasing its strong plane owner,
/// then release the graph last. Main presentation excludes native readers;
/// the publication lock excludes both native append callers. No unowned old
/// graph address is dereferenced.
unsafe fn retire_injection(fns: &EngineFns, injection: &mut Injection) -> Option<RetiredGraph> {
    if injection.graph == 0 {
        return None;
    }
    let graph = injection.graph as *mut c_void;
    let list = unsafe { graph.cast::<u8>().add(LIST_OFFSET).cast::<c_void>() };
    let linked = unsafe { linked_nodes(list) };
    for item in injection.planes.drain(..) {
        if let Some(&node) = linked.get(&item.pointer) {
            unsafe { unlink(fns, list, node) };
        }
        unsafe { release_plane(item.pointer as *mut c_void) };
    }
    injection.graph = 0;
    Some(RetiredGraph(graph as usize))
}

/// Cancel world-local work and end the old graph's injection before any player
/// or cell lookup. Normal menu presentation can have no player/cell at all.
fn reset_world(fns: &EngineFns) {
    clear_pending_target();
    NEIGHBORHOOD.lock().take();
    NEIGHBOR_WORK.lock().clear();
    if let Some(cache) = CACHE.get() {
        cache.lock().clear();
    }
    DASH_CACHED_CELLS.store(0, Ordering::Relaxed);
    *GENERATION.lock() = None;
    GENERATION_ACTIVE.store(false, Ordering::Release);
    let retired_graph = {
        let _publication = super::native_list::lock();
        let mut tracked = TRACKED.lock();
        let removed = tracked.planes.len();
        // SAFETY: only a normal main-thread presentation calls reset_world.
        // The tracked graph is strongly owned until retirement returns.
        let graph = unsafe { retire_injection(fns, &mut tracked) };
        DASH_REMOVED.fetch_add(removed as u64, Ordering::Relaxed);
        graph
    };
    drop(retired_graph);
    TRACKED_COUNT.store(0, Ordering::Release);
    DASH_PRESENT.store(0, Ordering::Relaxed);
    DASH_ACTIVE.store(0, Ordering::Relaxed);
    CURRENT_SCENE_GRAPH.store(0, Ordering::Release);
    CURRENT_CELL_PTR.store(0, Ordering::Release);
    CURRENT_CELL_KEY.set(None);
    LAST_SIGNATURE.lock().clear();
    SETTLE_RETRIES_LEFT.store(0, Ordering::Release);
    SETTLE_COUNTDOWN.store(0, Ordering::Release);
    INCOMPLETE.store(false, Ordering::Release);
    RESCAN_PENDING.store(false, Ordering::Release);
    DESIRED.lock().take();
}

/// Advance one generation pass and distinguish pending work from completion.
unsafe fn reconcile(
    fns: &EngineFns,
    scene_graph: *mut c_void,
    cell: *mut c_void,
    observer: Option<[f32; 3]>,
    force: bool,
) -> ReconcileOutcome {
    let key = unsafe { cell_key(cell) };
    let target = GenerationTarget {
        epoch: WORLD_EPOCH.load(Ordering::Acquire),
        cell: cell as usize,
        key,
        graph: scene_graph as usize,
    };
    store_cell_counters(&key);
    let key_signature = key;
    let max = MAX_PER_CELL.load(Ordering::Acquire);
    if force {
        // A graph/cell transition cannot carry a previously validated neighbor
        // set into a fresh target without checking its sources again.
        NEIGHBORHOOD.lock().take();
    }
    // The union includes the loaded exterior neighbors the engine also renders.
    // Neighbors contribute only after fresh validation of their settled source
    // input. This description refresh performs no coverage work.
    if force || NEIGHBORHOOD.lock().as_ref().is_none_or(|n| n.center != key) {
        let _ = refresh_neighborhood(cell, &key, GRID_RADIUS.load(Ordering::Acquire));
    }

    // Always resolve live sources on cell entry. Local content analysis is
    // reusable, but old world positions have no authority over a new visit.
    let settle_needed = true;
    let initial;
    let from_cache;
    let generate_ms;
    let render_ready;
    let planes;
    let raw;
    NEIGHBOR_WORK.lock().clear();
    {
        // A target change must not leave the previous cell's rectangles in the
        // engine list while the new set is being assembled: a stale rectangle
        // could cull visible geometry of the new cell. Drop them once, while
        // the resumable walk runs over several frames.
        if force
            && (CURRENT_CELL_KEY.get() != Some(key_signature)
                || CURRENT_CELL_PTR.load(Ordering::Acquire) != cell as usize
                || CURRENT_SCENE_GRAPH.load(Ordering::Acquire) != scene_graph as usize)
        {
            let _ = unsafe { inject(fns, scene_graph, &[]) };
        }
        // Advance the resumable walk by one frame's work budget. A new target
        // (or a forced pass) restarts it; a settle retry continues the same
        // walk. The set is installed only when the whole reference list has
        // been walked, so no frame pays the full cell cost.
        let outcome = {
            let mut guard = GENERATION.lock();
            let restart = force || guard.as_ref().is_none_or(|job| job.target != target);
            if restart {
                *guard = Some(GenerationJob {
                    target,
                    work: Generation::new(max, observer),
                    initial: force,
                });
            }
            // restart inserts whenever empty; this guard excludes removal.
            let generation = guard.as_mut().expect("generation was just inserted");
            // SAFETY: current main-frame cell, not the saved identity token.
            // Keep one native CellRefLock level through the complete slice.
            let slice_started = Instant::now();
            {
                let _cell_lock = unsafe { CellRefLock::acquire(cell, fns) };
                generation.work.account_lock_wait(slice_started.elapsed());
                unsafe { generation.work.capture(cell) };
            }
            let done = generation.work.advance(slice_started);
            if target.epoch != WORLD_EPOCH.load(Ordering::Acquire) {
                *guard = None;
                GENERATION_ACTIVE.store(false, Ordering::Release);
                return ReconcileOutcome::Pending;
            }
            if done {
                // No mutation removed the job while this guard was held.
                Some(guard.take().expect("generation is present"))
            } else {
                None
            }
        };
        let Some(mut finished) = outcome else {
            // The cell is still being walked. Keep the settle window alive so
            // the next frame continues it; the caller does not inject yet.
            GENERATION_ACTIVE.store(true, Ordering::Release);
            return ReconcileOutcome::Pending;
        };
        GENERATION_ACTIVE.store(false, Ordering::Release);
        initial = finished.initial;
        let proof = finished.work.source_proof();
        from_cache = finished.work.used_analysis();
        let (generated_planes, generated_raw, ready, generation_ms) = finished.work.finish();
        generate_ms = generation_ms;
        DASH_REBUILDS.fetch_add(1, Ordering::Relaxed);
        DASH_LAST_GEN_MS.store(generation_ms.round() as u64, Ordering::Relaxed);
        DASH_LAST_FROM_CACHE.store(from_cache, Ordering::Relaxed);
        if from_cache {
            DASH_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        }
        render_ready = ready;
        planes = generated_planes;
        raw = generated_raw;
        store_in_cache(&key, &planes, proof);
    }
    // Keep the union source current even when no native plane is re-created.
    if let Some(neighborhood) = NEIGHBORHOOD.lock().as_mut() {
        neighborhood.planes.insert(
            key,
            CellPlanes {
                records: planes.clone(),
                settled: false,
            },
        );
    }
    let signature = plane_signature(&planes);
    // The set is stable when the same target produced the same signature again.
    // Only a stable set is cached, so an incomplete first pass is never reused
    // on a later visit and a settle retry with an unchanged set keeps the
    // existing planes instead of rebuilding.
    let same_target = CURRENT_SCENE_GRAPH.load(Ordering::Acquire) == scene_graph as usize
        && CURRENT_CELL_KEY.get() == Some(key_signature);
    let stable = same_target && *LAST_SIGNATURE.lock() == signature;
    if stable {
        // Equality with the previous completed pass is already two observed
        // sets. Missing eligible data or truncated scans remain retryable.
        if !initial && render_ready {
            mark_cache_complete(&key);
            RESCAN_PENDING.store(false, Ordering::Release);
            if debug_log_enabled() {
                log::debug!(
                    "[OCCLUSION_PLANES] settled key={} complete=true",
                    cell_key_log(&key)
                );
            }
            return ReconcileOutcome::Finished {
                initial,
                settle: false,
            };
        }
        if !initial {
            RESCAN_PENDING.store(true, Ordering::Release);
            return ReconcileOutcome::Finished {
                initial,
                settle: true,
            };
        }
    }
    let report = unsafe { apply_union(fns, scene_graph, observer) };
    if !report.injected.complete {
        // An allocation failed; keep the bounded settle window alive so the
        // missing plane is retried instead of being silently absent.
        INCOMPLETE.store(true, Ordering::Release);
    } else {
        INCOMPLETE.store(false, Ordering::Release);
    }
    CURRENT_SCENE_GRAPH.store(scene_graph as usize, Ordering::Release);
    CURRENT_CELL_PTR.store(cell as usize, Ordering::Release);
    CURRENT_CELL_KEY.set(Some(key_signature));
    *LAST_SIGNATURE.lock() = signature;
    if debug_log_enabled() {
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
                    .map(|(_, planes)| planes.records.len())
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
    RESCAN_PENDING.store(settle_needed, Ordering::Release);
    ReconcileOutcome::Finished {
        initial,
        settle: settle_needed,
    }
}

/// Keep only loaded-neighborhood placements; proof is weak, non-persistent and
/// must be revalidated against fresh native input before neighbor admission.
fn store_in_cache(key: &CellKey, planes: &[PlaneRecord], proof: Option<Arc<SourceProof>>) {
    let Some(cache) = CACHE.get() else {
        return;
    };
    let mut guard = cache.lock();
    guard.insert(*key, planes.to_vec(), proof);
    DASH_CACHED_CELLS.store(guard.cell_count(), Ordering::Relaxed);
}

/// Mark a cached entry complete once the settle window has ended.
fn mark_cache_complete(key: &CellKey) {
    if let Some(entry) = NEIGHBORHOOD
        .lock()
        .as_mut()
        .and_then(|n| n.planes.get_mut(key))
    {
        entry.settled = true;
    }
    if let Some(cache) = CACHE.get() {
        cache.lock().mark_complete(key);
    }
}

unsafe fn create_plane(fns: &EngineFns, record: &PlaneRecord) -> Option<*mut c_void> {
    if !record.valid_native() {
        return None;
    }
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
        let two_sided = record.two_sided();
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
