//! Worker-backed radio path queries and hot-path attribution.
//!
//! The periodic scan consumes a complete prior distance generation while one
//! opaque mode-0 provider generation is recomputed on the engine's native
//! tasklet workers. Endpoint locations are prepared and released on the game
//! thread, and unknown providers retain the cooperative main-thread fallback.
//! The exact disposition-3 door-policy bypass remains an optional fast path.

use std::{
    cell::{Cell, RefCell, UnsafeCell},
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, ensure};
use libc::c_void;
use parking_lot::Mutex;

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction},
        memory::read_bytes,
        patch::module_address,
        winapi::{ThreadPriority, lower_current_thread_priority_scoped, replace_call},
    },
};

use crate::mods::diagnostics;

const PERIODIC_RADIO_SCAN_CALL_ADDR: usize = 0x00833D86;
const RADIO_SIGNAL_SCAN_ADDR: usize = 0x004FF1A0;
const MODE0_RADIO_DISTANCE_CALL_ADDR: usize = 0x004FF397;
const MODE0_RADIO_DISTANCE_ADDR: usize = 0x006D4EB0;
const PATHING_LOCATION_INIT_ADDR: usize = 0x006DCD70;
const PATHING_LOCATION_DESTROY_ADDR: usize = 0x004FF7E0;
const LOOKUP_FORM_BY_ID_ADDR: usize = 0x004839C0;
const PATH_FAILURE_DISTANCE_ADDR: usize = 0x01016970;
const LOADING_FLAG_ADDR: usize = 0x011DEA2B;
const TASKLET_MANAGER_ADDR: usize = 0x00B00A00;
const TASKLET_GROUP_CREATE_ADDR: usize = 0x00B00A80;
const TASKLET_GROUP_ACTIVATE_ADDR: usize = 0x00B00AE0;
const TASKLET_SUBMIT_ADDR: usize = 0x00B00B40;
const TASKLET_GROUP_CLOSE_ADDR: usize = 0x00B00BC0;
const TASKLET_GROUP_WAIT_ADDR: usize = 0x00B02920;
const TASKLET_PRIORITY_ENQUEUE_ADDR: usize = 0x00B02159;
const TASKLET_PRIORITY_DISPATCH_ADDR: usize = 0x00B024C7;
const TASKLET_GROUP_LAYOUT_ADDR: usize = 0x00B02833;
const TASKLET_GROUP_PRIORITY_OFFSET: usize = 0x30;
const TASKLET_GROUP_SUBMITTED_OFFSET: usize = 0x34;
const TASKLET_GROUP_COMPLETED_OFFSET: usize = 0x38;
const TASKLET_LOWEST_QUEUE_PRIORITY: u32 = 0x3F;
const BSTASKLET_VTABLE: usize = 0x0106C5D8;
const PATH_QUERY_ADDR: usize = 0x006D4D20;
const PATH_TRAVERSAL_ADDR: usize = 0x006F3FB0;
const STATION_MODE_ADDR: usize = 0x0056B210;
const RADIO_QUERY_VTABLE: usize = 0x0106D8FC;
const TELEPORT_DOOR_PROVIDER_SLOT: usize = 0x0106D900;
const DOOR_ACCESSIBILITY_ADDR: usize = 0x00502450;
const VANILLA_PROVIDER_ADDR: usize = 0x006F36D0;
const VANILLA_POLICY_SETUP_ADDR: usize = 0x00501D20;
const VANILLA_POLICY_CLEANUP_ADDR: usize = 0x00501E50;
const VANILLA_DISPOSITION_ADMISSION_OFFSET: usize = 0x72;
const VANILLA_POLICY_SETUP_CALL_OFFSET: usize = 0x1A9;
const VANILLA_ACCESSIBILITY_CALL_OFFSET: usize = 0x1CA;
const VANILLA_ACCESSIBILITY_RESULT_OFFSET: usize = 0x1CF;
const VANILLA_DISPOSITION_BRANCH_OFFSET: usize = 0x1E7;
const VANILLA_MIN_USE_BRANCH_OFFSET: usize = 0x22B;
const VANILLA_POLICY_CLEANUP_CALL_OFFSETS: [usize; 3] = [0x221, 0x307, 0x412];
const STEWIE_POLICY_SETUP_CALL_OFFSET: usize = 0x12B;
const STEWIE_POLICY_BLOCK_OFFSET: usize = 0x118;
const STEWIE_ACCESSIBILITY_CALL_OFFSET: usize = 0x140;
const STEWIE_ACCESSIBILITY_RESULT_OFFSET: usize = 0x153;
const STEWIE_DISPOSITION_BRANCH_OFFSET: usize = 0x174;
const STEWIE_MIN_USE_BRANCH_OFFSET: usize = 0x199;
const STEWIE_LOCK_CLEANUP_OFFSET: usize = 0x2C4;
const PRIORITY_BUCKET_COUNT: usize = 20;
const SLOW_SCAN_US: u64 = 5_000;
const SCAN_REPORT_MS: u32 = 1_000;
const FRAME_EVENT_TIMEOUT_MS: u32 = 1_000;
const FALLBACK_REPORT_DELAY_MS: u32 = 2_000;
const DEFAULT_SCAN_CADENCE_MS: u32 = 250;
const MIN_SCAN_CADENCE_MS: u32 = 16;
const MAX_SCAN_CADENCE_MS: u32 = 500;
const MAX_COOPERATIVE_QUERIES: usize = 512;
const TASKLET_QUERIES_PER_SUBMISSION: usize = 1;

const MODE0_CALL_PREFIX_SIGNATURE: &[u8] = &[0x8B, 0x85, 0x3C, 0xFE, 0xFF, 0xFF, 0x50, 0xE8];
const MODE0_CALL_SUFFIX_SIGNATURE: &[u8] = &[0x83, 0xC4, 0x14, 0xD9, 0x5D, 0xEC];
const LOOKUP_FORM_BY_ID_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x51, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x83, 0x3D, 0xC0, 0x54, 0x1C,
    0x01, 0x00,
];
const TASKLET_MANAGER_SIGNATURE: &[u8] =
    &[0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x9E, 0x38, 0xF2, 0x00];
const TASKLET_GROUP_CREATE_SIGNATURE: &[u8] =
    &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x89, 0x4D, 0xEC];
const TASKLET_GROUP_ACTIVATE_SIGNATURE: &[u8] =
    &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x89, 0x4D, 0xF0];
const TASKLET_SUBMIT_SIGNATURE: &[u8] = &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x1C, 0x89, 0x4D, 0xE8];
const TASKLET_GROUP_CLOSE_SIGNATURE: &[u8] =
    &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x89, 0x4D, 0xF0];
const TASKLET_GROUP_WAIT_SIGNATURE: &[u8] = &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x89, 0x4D, 0xF8];
const TASKLET_PRIORITY_ENQUEUE_SIGNATURE: &[u8] = &[
    0x8B, 0x45, 0x08, 0x8B, 0x48, 0x08, 0x89, 0x4D, 0xF0, 0x8B, 0x55, 0xF0, 0x8B, 0x42, 0x30, 0x89,
    0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x40, 0x72, 0x07, 0xC7, 0x45, 0xFC, 0x3F, 0x00, 0x00, 0x00, 0x8B,
    0x4D, 0xFC, 0x8B, 0x55, 0xE8, 0x83, 0x7C, 0x8A, 0x6C, 0x00,
];
const TASKLET_PRIORITY_DISPATCH_SIGNATURE: &[u8] = &[
    0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xDC, 0x83, 0xC0, 0x6C, 0x89, 0x45, 0xF0,
    0xEB, 0x12, 0x8B, 0x4D, 0xF4, 0x83, 0xC1, 0x01, 0x89, 0x4D, 0xF4, 0x8B, 0x55, 0xF0, 0x83, 0xC2,
    0x04, 0x89, 0x55, 0xF0, 0x83, 0x7D, 0xF4, 0x40, 0x73, 0x26, 0x8B, 0x45, 0xF0, 0x8B, 0x08,
];
const TASKLET_GROUP_LAYOUT_SIGNATURE: &[u8] = &[
    0x8B, 0x45, 0xF4, 0xC6, 0x40, 0x2E, 0x00, 0x8B, 0x4D, 0xF4, 0xC7, 0x41, 0x30, 0x00, 0x00, 0x00,
    0x00, 0x8B, 0x55, 0xF4, 0xC7, 0x42, 0x34, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xF4, 0xC7, 0x40,
];

const VANILLA_PROVIDER_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xA8, 0x6B, 0xF0, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x81, 0xEC, 0x84, 0x00, 0x00, 0x00,
];
const VANILLA_DISPOSITION_ADMISSION_SIGNATURE: &[u8] = &[
    0x8B, 0x45, 0x80, 0x83, 0xB8, 0xB4, 0x20, 0x00, 0x00, 0x01, 0x74, 0x1C, 0x8B, 0x4D, 0x80, 0x83,
    0xB9, 0xB4, 0x20, 0x00, 0x00, 0x03, 0x74, 0x10, 0x8B, 0x55, 0x80, 0x83, 0xBA, 0xA0, 0x20, 0x00,
    0x00, 0x00,
];
const VANILLA_ACCESSIBILITY_RESULT_SIGNATURE: &[u8] = &[
    0x88, 0x45, 0xCF, 0xD9, 0xEE, 0xD9, 0x5D, 0xEC, 0x0F, 0xB6, 0x4D, 0xCF, 0x85, 0xC9, 0x74, 0x08,
    0x0F, 0xB6, 0x55, 0xDF, 0x85, 0xD2, 0x74, 0x44,
];
const VANILLA_DISPOSITION_BRANCH_SIGNATURE: &[u8] = &[
    0x8B, 0x45, 0x80, 0x8B, 0x88, 0xB4, 0x20, 0x00, 0x00, 0x89, 0x8D, 0x74, 0xFF, 0xFF, 0xFF, 0x83,
    0xBD, 0x74, 0xFF, 0xFF, 0xFF, 0x00, 0x74, 0x18, 0x83, 0xBD, 0x74, 0xFF, 0xFF, 0xFF, 0x02, 0x74,
    0x04, 0xEB, 0x21,
];
const VANILLA_MIN_USE_BRANCH_SIGNATURE: &[u8] = &[
    0x8B, 0x4D, 0xE8, 0xE8, 0x2D, 0xBB, 0x0B, 0x00, 0x8B, 0xC8, 0xE8, 0xF6, 0x46, 0xE2, 0xFF, 0x0F,
    0xB6, 0xD0, 0x85, 0xD2, 0x74, 0x15, 0x8B, 0x45, 0x80, 0x83, 0xB8, 0xB4, 0x20, 0x00, 0x00, 0x03,
    0x74, 0x09,
];
const VANILLA_POLICY_SETUP_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x3B, 0xB2, 0xF0, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x83, 0xEC, 0x18,
];
const VANILLA_POLICY_CLEANUP_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x89, 0x4D, 0xF8, 0x8B, 0x45, 0xF8, 0x83, 0x78, 0x08, 0x00,
    0x74, 0x15, 0x8B, 0x4D, 0xF8, 0x8B, 0x51, 0x08, 0x89, 0x55, 0xFC, 0x8B, 0x45, 0xFC, 0x50,
];
const STEWIE_PROVIDER_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x34, 0x53, 0x56, 0x57, 0x8B, 0xF9, 0x8B, 0x4D,
    0x08,
];
const STEWIE_POLICY_BLOCK_SIGNATURE: &[u8] = &[
    0x8B, 0x4C, 0x24, 0x18, 0x33, 0xD2, 0x51, 0x8D, 0x4C, 0x24, 0x2C, 0xC7, 0x44, 0x24, 0x34, 0x00,
    0x00, 0x00, 0x00, 0xE8,
];
const STEWIE_ACCESSIBILITY_CALL_SIGNATURE: &[u8] = &[
    0xF3, 0x0F, 0x11, 0x44, 0x24, 0x24, 0xFF, 0xB7, 0xA0, 0x20, 0x00, 0x00, 0xB8, 0x50, 0x24, 0x50,
    0x00, 0xFF, 0xD0,
];
const STEWIE_ACCESSIBILITY_RESULT_SIGNATURE: &[u8] = &[
    0x84, 0xC0, 0x74, 0x07, 0x80, 0x7C, 0x24, 0x13, 0x00, 0x74, 0x23, 0x8B, 0x87, 0xB4, 0x20, 0x00,
    0x00, 0x85, 0xC0, 0x0F, 0x84, 0x58, 0x01, 0x00, 0x00,
];
const STEWIE_DISPOSITION_BRANCH_SIGNATURE: &[u8] = &[
    0x83, 0xF8, 0x02, 0x75, 0x10, 0xF3, 0x0F, 0x11, 0x44, 0x24, 0x1C, 0xEB, 0x08,
];
const STEWIE_MIN_USE_BRANCH_SIGNATURE: &[u8] = &[
    0xA8, 0x01, 0x74, 0x0F, 0x83, 0xBF, 0xB4, 0x20, 0x00, 0x00, 0x03, 0x74, 0x06, 0xF3, 0x0F, 0x11,
    0x44, 0x24, 0x1C,
];
const STEWIE_LOCK_CLEANUP_SIGNATURE: &[u8] = &[
    0x8B, 0x44, 0x24, 0x30, 0x85, 0xC0, 0x74, 0x0D, 0x50, 0xB9, 0x38, 0x62, 0x1F, 0x01, 0xB8, 0x60,
    0x40, 0xAA, 0x00, 0xFF, 0xD0,
];
const STEWIE_POLICY_SETUP_SIGNATURE: &[u8] = &[
    0x53, 0x55, 0x8B, 0x6C, 0x24, 0x0C, 0xBA, 0x20, 0x02, 0x41, 0x00, 0x56, 0x57, 0x8B, 0xF9, 0x33,
    0xF6, 0x8B, 0x45, 0x40,
];
const DOOR_ACCESSIBILITY_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x89, 0x4D, 0xF4, 0xC6, 0x45, 0xFF, 0x00, 0xC7, 0x45, 0xF8,
    0x00, 0x00, 0x00, 0x00,
];

type RadioSignalScanFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type Mode0RadioDistanceFn =
    unsafe extern "C" fn(*mut PathingLocation, *mut PathingLocation, f32, *mut c_void, u32) -> f32;
type PathingLocationInitFn =
    unsafe extern "thiscall" fn(*mut PathingLocation, *mut c_void) -> *mut PathingLocation;
type PathingLocationDestroyFn = unsafe extern "thiscall" fn(*mut PathingLocation);
type LookupFormByIdFn = unsafe extern "C" fn(u32) -> *mut c_void;
type TaskletManagerFn = unsafe extern "C" fn() -> *mut c_void;
type TaskletGroupCreateFn = unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void) -> u8;
type TaskletGroupActivateFn = unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void) -> u8;
type TaskletSubmitFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void, *mut TaskletHandle, u8) -> u8;
type TaskletGroupCloseFn = unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void) -> u8;
type TaskletGroupWaitFn = unsafe extern "thiscall" fn(*mut c_void, u32);
type PathQueryFn = unsafe extern "C" fn(usize, usize, *mut c_void, u32, u32, u32, u32) -> u8;
type PathTraversalFn = unsafe extern "fastcall" fn(*mut c_void) -> usize;
type StationModeFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;
type DoorPolicySetupFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
type DoorAccessibilityFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut u8) -> u8;

static PATH_QUERY_HOOK: LazyLock<InlineHookContainer<PathQueryFn>> =
    LazyLock::new(InlineHookContainer::new);
static PATH_TRAVERSAL_HOOK: LazyLock<InlineHookContainer<PathTraversalFn>> =
    LazyLock::new(InlineHookContainer::new);
static STATION_MODE_HOOK: LazyLock<InlineHookContainer<StationModeFn>> =
    LazyLock::new(InlineHookContainer::new);
static DOOR_POLICY_SETUP_HOOK: LazyLock<InlineHookContainer<DoorPolicySetupFn>> =
    LazyLock::new(InlineHookContainer::new);
static DOOR_ACCESSIBILITY_HOOK: LazyLock<InlineHookContainer<DoorAccessibilityFn>> =
    LazyLock::new(InlineHookContainer::new);
static SCAN_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static POLICY_INSTALL_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static COOPERATIVE_CAPACITY_EXCEEDED: AtomicBool = AtomicBool::new(false);
static RADIO_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static FRAME_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static LAST_FRAME_EVENT_MS: AtomicU32 = AtomicU32::new(0);
static DEFERRED_INIT_MS: AtomicU32 = AtomicU32::new(0);
static COOPERATIVE_FALLBACK_REPORTED: AtomicBool = AtomicBool::new(false);
static COOPERATIVE_COLLECTION_REPORTED: AtomicBool = AtomicBool::new(false);
static COOPERATIVE_PUBLICATION_REPORTED: AtomicBool = AtomicBool::new(false);
static TASKLET_BACKEND_AVAILABLE: AtomicBool = AtomicBool::new(false);
static TASKLET_BACKEND_FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);
static TASKLET_PRIORITY_FAILED: AtomicBool = AtomicBool::new(false);
static RADIO_DEFERRED_READY: AtomicBool = AtomicBool::new(false);
static TASKLET_BATCH_ABORTED: AtomicBool = AtomicBool::new(false);
static TASKLET_WORKER_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static TASKLET_PROVIDER: AtomicUsize = AtomicUsize::new(0);
static COOPERATIVE_TIMED_JOBS: AtomicU32 = AtomicU32::new(0);
static COOPERATIVE_TIMED_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static COOPERATIVE_TIMED_MAX_US: AtomicU64 = AtomicU64::new(0);
static TASKLET_PREP_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static TASKLET_PREP_MAX_US: AtomicU64 = AtomicU64::new(0);
static COOPERATIVE_COLLECTION_MS: AtomicU32 = AtomicU32::new(0);
static LAST_RADIO_SCAN_MS: AtomicU32 = AtomicU32::new(0);
static QUERY_PIPELINE: LazyLock<Mutex<QueryPipeline>> =
    LazyLock::new(|| Mutex::new(QueryPipeline::new()));
static TASKLET_BACKEND: LazyLock<Mutex<TaskletBackend>> =
    LazyLock::new(|| Mutex::new(TaskletBackend::new()));

#[repr(C, align(4))]
struct PathingLocation {
    bytes: [u8; 0x28],
}

impl PathingLocation {
    const fn uninit_storage() -> Self {
        Self { bytes: [0; 0x28] }
    }
}

#[repr(C)]
struct TaskletVtable {
    finish: unsafe extern "thiscall" fn(*mut EngineTasklet),
    ready: unsafe extern "thiscall" fn(*mut EngineTasklet) -> u8,
    execute: unsafe extern "thiscall" fn(*mut EngineTasklet),
    reserved: unsafe extern "thiscall" fn(*mut EngineTasklet),
}

#[repr(C)]
struct EngineTasklet {
    // BSWin32TaskletManager reads these fields directly while the group owns
    // the task; keep the verified 0x18-byte FalloutNV.exe layout exact.
    vtable: *const TaskletVtable,
    requeue: u8,
    _pad_05: [u8; 3],
    group: *mut c_void,
    check_ready: u8,
    _pad_0d: [u8; 3],
    claimed: u32,
    next: *mut EngineTasklet,
}

#[repr(C)]
struct TaskletHandle {
    vtable: usize,
    task: *mut EngineTasklet,
}

#[repr(C)]
struct PreparedQuery {
    work: QueryWork,
    station: PathingLocation,
    current: PathingLocation,
    distance: f32,
    initialized: bool,
}

impl PreparedQuery {
    const fn empty() -> Self {
        Self {
            work: QueryWork {
                generation: 0,
                index: 0,
                request: QueryRequest {
                    key: QueryKey {
                        station_form_id: 0,
                        current_ref_form_id: 0,
                        radius_bits: 0,
                    },
                    radius: 0.0,
                },
            },
            station: PathingLocation::uninit_storage(),
            current: PathingLocation::uninit_storage(),
            distance: 0.0,
            initialized: false,
        }
    }
}

#[repr(C)]
struct PreparedBatch {
    count: usize,
    queries: [PreparedQuery; TASKLET_QUERIES_PER_SUBMISSION],
}

impl PreparedBatch {
    const fn new() -> Self {
        Self {
            count: 0,
            queries: [const { PreparedQuery::empty() }; TASKLET_QUERIES_PER_SUBMISSION],
        }
    }
}

#[repr(C)]
struct RadioTasklet {
    engine: EngineTasklet,
    batch: PreparedBatch,
}

impl RadioTasklet {
    const fn new() -> Self {
        Self {
            engine: EngineTasklet {
                vtable: &RADIO_TASKLET_VTABLE,
                requeue: 0,
                _pad_05: [0; 3],
                group: core::ptr::null_mut(),
                check_ready: 1,
                _pad_0d: [0; 3],
                claimed: 0,
                next: core::ptr::null_mut(),
            },
            batch: PreparedBatch::new(),
        }
    }
}

struct SharedRadioTasklet(UnsafeCell<RadioTasklet>);

// The game thread alone prepares and destroys the batch outside an active
// group. The tasklet worker owns it until the native group's completed count
// reaches its submitted count and the nonblocking group wait transfers
// ownership back.
unsafe impl Send for SharedRadioTasklet {}
unsafe impl Sync for SharedRadioTasklet {}

static RADIO_TASKLET_VTABLE: TaskletVtable = TaskletVtable {
    finish: radio_tasklet_finish,
    ready: radio_tasklet_ready,
    execute: radio_tasklet_execute,
    reserved: radio_tasklet_finish,
};
static RADIO_TASKLET: LazyLock<Box<SharedRadioTasklet>> =
    LazyLock::new(|| Box::new(SharedRadioTasklet(UnsafeCell::new(RadioTasklet::new()))));

struct TaskletBackend {
    group: usize,
    group_active: bool,
    group_closed: bool,
    in_flight: bool,
}

impl TaskletBackend {
    const fn new() -> Self {
        Self {
            group: 0,
            group_active: false,
            group_closed: false,
            in_flight: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct QueryKey {
    station_form_id: u32,
    current_ref_form_id: u32,
    radius_bits: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct QueryRequest {
    key: QueryKey,
    radius: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct PublishedResult {
    key: QueryKey,
    distance: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PipelineState {
    #[default]
    Idle,
    Collecting,
    Executing,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct QueryWork {
    generation: u32,
    index: usize,
    request: QueryRequest,
}

struct QueryPipeline {
    state: PipelineState,
    generation: u32,
    published_count: usize,
    build_count: usize,
    next_index: usize,
    completed_count: usize,
    collection_failed: bool,
    scan_cadence_ms: u32,
    next_job_due_ms: u32,
    job_spacing_ms: u32,
    published: [PublishedResult; MAX_COOPERATIVE_QUERIES],
    requests: [QueryRequest; MAX_COOPERATIVE_QUERIES],
    results: [PublishedResult; MAX_COOPERATIVE_QUERIES],
}

impl QueryPipeline {
    fn new() -> Self {
        Self {
            state: PipelineState::Idle,
            generation: 0,
            published_count: 0,
            build_count: 0,
            next_index: 0,
            completed_count: 0,
            collection_failed: false,
            scan_cadence_ms: DEFAULT_SCAN_CADENCE_MS,
            next_job_due_ms: 0,
            job_spacing_ms: 0,
            published: [PublishedResult::default(); MAX_COOPERATIVE_QUERIES],
            requests: [QueryRequest::default(); MAX_COOPERATIVE_QUERIES],
            results: [PublishedResult::default(); MAX_COOPERATIVE_QUERIES],
        }
    }

    fn begin_scan(&mut self, now_ms: u32, scan_cadence_ms: u32) {
        if self.state != PipelineState::Idle {
            return;
        }

        self.generation = self.generation.wrapping_add(1).max(1);
        self.state = PipelineState::Collecting;
        self.build_count = 0;
        self.next_index = 0;
        self.completed_count = 0;
        self.collection_failed = false;
        self.scan_cadence_ms = scan_cadence_ms;
        self.next_job_due_ms = now_ms;
        self.job_spacing_ms = 0;
    }

    fn end_scan(&mut self) -> bool {
        if self.state != PipelineState::Collecting {
            return false;
        }
        if self.collection_failed {
            self.state = PipelineState::Idle;
            self.build_count = 0;
            return false;
        }
        if self.build_count == 0 {
            self.published_count = 0;
            self.state = PipelineState::Idle;
            return false;
        }

        self.job_spacing_ms = (self.scan_cadence_ms / self.build_count as u32).max(1);
        self.state = PipelineState::Executing;
        true
    }

    fn observe_query(&mut self, request: QueryRequest) -> Option<f32> {
        let published = self.lookup_published(request.key);
        if self.state != PipelineState::Collecting {
            return published;
        }

        if self.requests[..self.build_count]
            .iter()
            .any(|candidate| candidate.key == request.key)
        {
            return published;
        }
        if self.build_count == MAX_COOPERATIVE_QUERIES {
            self.collection_failed = true;
            return published;
        }

        self.requests[self.build_count] = request;
        self.build_count += 1;
        published
    }

    fn take_next(&mut self, now_ms: u32) -> Option<QueryWork> {
        if self.state != PipelineState::Executing
            || self.next_index == self.build_count
            || !tick_reached(now_ms, self.next_job_due_ms)
        {
            return None;
        }

        let index = self.next_index;
        self.next_index += 1;
        self.next_job_due_ms = self.next_job_due_ms.wrapping_add(self.job_spacing_ms);
        Some(QueryWork {
            generation: self.generation,
            index,
            request: self.requests[index],
        })
    }

    fn complete(&mut self, work: QueryWork, distance: Option<f32>) -> bool {
        if self.state != PipelineState::Executing
            || work.generation != self.generation
            || work.index != self.completed_count
            || work.index >= self.build_count
        {
            return false;
        }

        let Some(distance) = distance else {
            self.abort_build();
            return false;
        };
        self.results[work.index] = PublishedResult {
            key: work.request.key,
            distance,
        };
        self.completed_count += 1;
        if self.completed_count != self.build_count {
            return false;
        }

        self.published[..self.build_count].copy_from_slice(&self.results[..self.build_count]);
        self.published_count = self.build_count;
        self.state = PipelineState::Idle;
        self.build_count = 0;
        true
    }

    fn reset(&mut self) {
        self.state = PipelineState::Idle;
        self.published_count = 0;
        self.build_count = 0;
        self.next_index = 0;
        self.completed_count = 0;
        self.collection_failed = false;
        self.next_job_due_ms = 0;
        self.job_spacing_ms = 0;
    }

    fn abort_build(&mut self) {
        self.state = PipelineState::Idle;
        self.build_count = 0;
        self.next_index = 0;
        self.completed_count = 0;
        self.collection_failed = false;
        self.next_job_due_ms = 0;
        self.job_spacing_ms = 0;
    }

    fn lookup_published(&self, key: QueryKey) -> Option<f32> {
        self.published[..self.published_count]
            .iter()
            .find(|candidate| candidate.key == key)
            .map(|candidate| candidate.distance)
    }
}

#[derive(Clone, Copy, Default)]
struct Timing {
    calls: u32,
    total_us: u64,
    max_us: u64,
}

impl Timing {
    fn record(&mut self, elapsed_us: Option<u64>) {
        self.calls = self.calls.saturating_add(1);
        let Some(elapsed_us) = elapsed_us else {
            return;
        };
        self.total_us = self.total_us.saturating_add(elapsed_us);
        self.max_us = self.max_us.max(elapsed_us);
    }

    fn merge(&mut self, other: Self) {
        self.calls = self.calls.saturating_add(other.calls);
        self.total_us = self.total_us.saturating_add(other.total_us);
        self.max_us = self.max_us.max(other.max_us);
    }
}

#[derive(Clone, Copy)]
struct ScanStats {
    mode_queries: [Timing; 3],
    other_queries: Timing,
    traversals: Timing,
    station_modes: [u32; 5],
    other_station_modes: u32,
    mode0_traversals: u32,
    expected_query_vtable: u32,
    queue_empty_before_traversal: u32,
    source_missing: u32,
    source_first: u32,
    source_goal_match: u32,
    source_parent_null: u32,
    result_null: u32,
    result_source: u32,
    result_other: u32,
    policy_queries: u32,
    policy_setup_bypasses: u32,
    policy_access_bypasses: u32,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            mode_queries: [Timing::default(); 3],
            other_queries: Timing::default(),
            traversals: Timing::default(),
            station_modes: [0; 5],
            other_station_modes: 0,
            mode0_traversals: 0,
            expected_query_vtable: 0,
            queue_empty_before_traversal: 0,
            source_missing: 0,
            source_first: 0,
            source_goal_match: 0,
            source_parent_null: 0,
            result_null: 0,
            result_source: 0,
            result_other: 0,
            policy_queries: 0,
            policy_setup_bypasses: 0,
            policy_access_bypasses: 0,
        }
    }
}

impl ScanStats {
    fn merge(&mut self, other: Self) {
        for (timing, other) in self.mode_queries.iter_mut().zip(other.mode_queries) {
            timing.merge(other);
        }
        self.other_queries.merge(other.other_queries);
        self.traversals.merge(other.traversals);
        for (count, other) in self.station_modes.iter_mut().zip(other.station_modes) {
            *count = count.saturating_add(other);
        }
        self.other_station_modes = self
            .other_station_modes
            .saturating_add(other.other_station_modes);
        self.mode0_traversals = self.mode0_traversals.saturating_add(other.mode0_traversals);
        self.expected_query_vtable = self
            .expected_query_vtable
            .saturating_add(other.expected_query_vtable);
        self.queue_empty_before_traversal = self
            .queue_empty_before_traversal
            .saturating_add(other.queue_empty_before_traversal);
        self.source_missing = self.source_missing.saturating_add(other.source_missing);
        self.source_first = self.source_first.saturating_add(other.source_first);
        self.source_goal_match = self
            .source_goal_match
            .saturating_add(other.source_goal_match);
        self.source_parent_null = self
            .source_parent_null
            .saturating_add(other.source_parent_null);
        self.result_null = self.result_null.saturating_add(other.result_null);
        self.result_source = self.result_source.saturating_add(other.result_source);
        self.result_other = self.result_other.saturating_add(other.result_other);
        self.policy_queries = self.policy_queries.saturating_add(other.policy_queries);
        self.policy_setup_bypasses = self
            .policy_setup_bypasses
            .saturating_add(other.policy_setup_bypasses);
        self.policy_access_bypasses = self
            .policy_access_bypasses
            .saturating_add(other.policy_access_bypasses);
    }
}

#[derive(Clone, Copy, Default)]
struct ScanAggregate {
    slow_scans: u32,
    total_us: u64,
    max_us: u64,
    residual_us: u64,
    residual_max_us: u64,
    stats: ScanStats,
}

#[derive(Default)]
struct ScanReporter {
    aggregate: ScanAggregate,
    last_report_ms: Option<u32>,
}

impl ScanReporter {
    fn observe(
        &mut self,
        now_ms: u32,
        slow_sample: Option<(u64, u64, ScanStats)>,
    ) -> Option<ScanAggregate> {
        if let Some((elapsed_us, residual_us, stats)) = slow_sample {
            self.aggregate.slow_scans = self.aggregate.slow_scans.saturating_add(1);
            self.aggregate.total_us = self.aggregate.total_us.saturating_add(elapsed_us);
            self.aggregate.max_us = self.aggregate.max_us.max(elapsed_us);
            self.aggregate.residual_us = self.aggregate.residual_us.saturating_add(residual_us);
            self.aggregate.residual_max_us = self.aggregate.residual_max_us.max(residual_us);
            self.aggregate.stats.merge(stats);
        }

        if self.aggregate.slow_scans == 0 {
            return None;
        }

        let Some(last_report_ms) = self.last_report_ms else {
            self.last_report_ms = Some(now_ms);
            return None;
        };
        if now_ms.wrapping_sub(last_report_ms) < SCAN_REPORT_MS {
            return None;
        }

        self.last_report_ms = Some(now_ms);
        Some(std::mem::take(&mut self.aggregate))
    }
}

#[derive(Default)]
struct RadioScanState {
    stats: ScanStats,
    reporter: ScanReporter,
}

thread_local! {
    static RADIO_SCAN_DEPTH: Cell<u32> = const { Cell::new(0) };
    static COOPERATIVE_SCAN_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static POLICY_BYPASS_DEPTH: Cell<u32> = const { Cell::new(0) };
    static PENDING_POLICY_ACCESS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static RADIO_SCAN_STATE: RefCell<RadioScanState> = RefCell::new(RadioScanState::default());
}

struct RadioScanScope {
    outermost: bool,
    cooperative: bool,
}

impl RadioScanScope {
    fn enter(now_ms: u32, scan_cadence_ms: u32) -> Self {
        let outermost = RADIO_SCAN_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_add(1));
            current == 0
        });
        if outermost {
            RADIO_SCAN_STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.stats = ScanStats::default();
            });
        }

        let loading = game_is_loading();
        let cooperative = outermost && cooperative_scheduler_available() && !loading;
        if cooperative {
            QUERY_PIPELINE.lock().begin_scan(now_ms, scan_cadence_ms);
            COOPERATIVE_SCAN_ACTIVE.with(|active| active.set(true));
        } else if outermost {
            QUERY_PIPELINE.lock().reset();
            if !loading {
                report_cooperative_fallback_once();
            }
        }
        Self {
            outermost,
            cooperative,
        }
    }
}

impl Drop for RadioScanScope {
    fn drop(&mut self) {
        RADIO_SCAN_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
        if self.outermost {
            if self.cooperative {
                QUERY_PIPELINE.lock().end_scan();
                COOPERATIVE_SCAN_ACTIVE.with(|active| active.set(false));
            }
            PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
        }
    }
}

struct RadioPathQueryScope;

impl RadioPathQueryScope {
    fn enter() -> Self {
        RADIO_SCAN_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for RadioPathQueryScope {
    fn drop(&mut self) {
        RADIO_SCAN_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
    }
}

struct DoorPolicyBypassScope {
    active: bool,
}

impl DoorPolicyBypassScope {
    unsafe fn enter(query: *const u8) -> Self {
        let active = unsafe { is_exact_radio_policy_query(query) };
        if active {
            POLICY_BYPASS_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
            PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
            with_active_stats(|stats| {
                stats.policy_queries = stats.policy_queries.saturating_add(1);
            });
        }
        Self { active }
    }
}

impl Drop for DoorPolicyBypassScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
        POLICY_BYPASS_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub fn install_radio_scan_fix() -> anyhow::Result<()> {
    verify_rel_call(PERIODIC_RADIO_SCAN_CALL_ADDR, RADIO_SIGNAL_SCAN_ADDR)?;
    verify_rel_call(MODE0_RADIO_DISTANCE_CALL_ADDR, MODE0_RADIO_DISTANCE_ADDR)?;
    verify_signature(
        MODE0_RADIO_DISTANCE_CALL_ADDR - 7,
        MODE0_CALL_PREFIX_SIGNATURE,
        "mode-0 radio distance call prefix",
    )?;
    verify_signature(
        MODE0_RADIO_DISTANCE_CALL_ADDR + 5,
        MODE0_CALL_SUFFIX_SIGNATURE,
        "mode-0 radio distance call suffix",
    )?;
    verify_signature(
        LOOKUP_FORM_BY_ID_ADDR,
        LOOKUP_FORM_BY_ID_SIGNATURE,
        "loaded FormID resolver",
    )?;
    unsafe {
        replace_call(
            MODE0_RADIO_DISTANCE_CALL_ADDR as *mut c_void,
            cooperative_distance_entry as *mut c_void,
        )?;
        replace_call(
            PERIODIC_RADIO_SCAN_CALL_ADDR as *mut c_void,
            hook_periodic_radio_signal_scan as *mut c_void,
        )?;
    }

    log::info!(
        "[RADIO] Radio query generation bridge active: scan=0x{:08X} query=0x{:08X} capacity={}",
        PERIODIC_RADIO_SCAN_CALL_ADDR,
        MODE0_RADIO_DISTANCE_CALL_ADDR,
        MAX_COOPERATIVE_QUERIES,
    );

    let profiling = diagnostics::hitch_profiling_enabled();

    unsafe {
        PATH_TRAVERSAL_HOOK.init(
            "radio_path_traversal_policy_scope",
            PATH_TRAVERSAL_ADDR as *mut c_void,
            hook_path_traversal,
        )?;
        if profiling {
            PATH_QUERY_HOOK.init(
                "radio_path_query_profile",
                PATH_QUERY_ADDR as *mut c_void,
                hook_path_query,
            )?;
            STATION_MODE_HOOK.init(
                "radio_station_mode_profile",
                STATION_MODE_ADDR as *mut c_void,
                hook_station_mode,
            )?;
        }
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&PATH_TRAVERSAL_HOOK)?;
    if profiling {
        transaction.enable_inline(&PATH_QUERY_HOOK)?;
        transaction.enable_inline(&STATION_MODE_HOOK)?;
    }
    transaction.commit();

    if profiling {
        log::info!(
            "[RADIO] Scan hot-path profiling active: modes=0x{:08X} query=0x{:08X} traversal=0x{:08X}",
            STATION_MODE_ADDR,
            PATH_QUERY_ADDR,
            PATH_TRAVERSAL_ADDR,
        );
    }
    Ok(())
}

pub(crate) fn observe_event(kind: u32) {
    if kind == crate::events::ON_FRAME_PRESENT {
        observe_frame_present();
        return;
    }
    if is_world_lifetime_event(kind) {
        if !world_lifetime_barrier_ready(kind, RADIO_DEFERRED_READY.load(Ordering::Acquire)) {
            return;
        }
        if TASKLET_BACKEND_AVAILABLE.load(Ordering::Acquire) {
            quiesce_tasklet_queries();
        }
        QUERY_PIPELINE.lock().reset();
        return;
    }
    if kind != crate::events::DEFERRED_INIT || POLICY_INSTALL_ATTEMPTED.swap(true, Ordering::AcqRel)
    {
        return;
    }
    DEFERRED_INIT_MS.store(
        libpsycho::os::windows::winapi::get_tick_count(),
        Ordering::Release,
    );

    if let Err(error) = enable_tasklet_backend() {
        log::warn!(
            "[RADIO] Native tasklet radio queries unavailable; cooperative main-thread fallback retained: {error:#}"
        );
    }
    if let Err(error) = install_door_policy_bypass_hooks() {
        log::warn!(
            "[RADIO] Dead door-policy bypass unavailable; original provider retained: {error:#}"
        );
    }
    RADIO_DEFERRED_READY.store(true, Ordering::Release);
}

fn is_world_lifetime_event(kind: u32) -> bool {
    matches!(
        kind,
        crate::events::PRE_LOAD_GAME | crate::events::EXIT_TO_MAIN_MENU | crate::events::NEW_GAME
    )
}

fn world_lifetime_barrier_ready(kind: u32, deferred_ready: bool) -> bool {
    deferred_ready && is_world_lifetime_event(kind)
}

fn install_door_policy_bypass_hooks() -> anyhow::Result<()> {
    let provider = unsafe { read_u32(TELEPORT_DOOR_PROVIDER_SLOT as *const u8, 0) } as usize;
    let provider_label =
        module_address(provider).unwrap_or_else(|| format!("unknown!0x{provider:08X}"));
    let setup_target = resolve_policy_setup_target(provider, &provider_label)?;
    verify_signature(
        DOOR_ACCESSIBILITY_ADDR,
        DOOR_ACCESSIBILITY_SIGNATURE,
        "game teleport-door accessibility predicate",
    )?;

    unsafe {
        DOOR_POLICY_SETUP_HOOK.init(
            "radio_dead_door_policy_setup",
            setup_target as *mut c_void,
            hook_door_policy_setup,
        )?;
        DOOR_ACCESSIBILITY_HOOK.init(
            "radio_dead_door_accessibility",
            DOOR_ACCESSIBILITY_ADDR as *mut c_void,
            hook_door_accessibility,
        )?;
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&DOOR_POLICY_SETUP_HOOK)?;
    transaction.enable_inline(&DOOR_ACCESSIBILITY_HOOK)?;
    transaction.commit();

    log::info!(
        "[RADIO] Exact mode-0 dead door-policy bypass active: provider={} setup={} accessibility=0x{:08X}",
        provider_label,
        module_address(setup_target).unwrap_or_else(|| format!("unknown!0x{setup_target:08X}")),
        DOOR_ACCESSIBILITY_ADDR,
    );
    Ok(())
}

fn resolve_policy_setup_target(provider: usize, provider_label: &str) -> anyhow::Result<usize> {
    if provider == VANILLA_PROVIDER_ADDR {
        verify_vanilla_policy_provider()?;
        return Ok(VANILLA_POLICY_SETUP_ADDR);
    }

    ensure!(
        module_name(provider)
            .is_some_and(|name| name.eq_ignore_ascii_case("nvse_stewie_tweaks.dll")),
        "unsupported teleport-door provider {provider_label}"
    );
    verify_stewie_policy_provider(provider)
}

fn verify_vanilla_policy_provider() -> anyhow::Result<()> {
    verify_signature(
        VANILLA_PROVIDER_ADDR,
        VANILLA_PROVIDER_SIGNATURE,
        "vanilla TeleportDoorSearch provider",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_DISPOSITION_ADMISSION_OFFSET,
        VANILLA_DISPOSITION_ADMISSION_SIGNATURE,
        "vanilla disposition admission branch",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_ACCESSIBILITY_RESULT_OFFSET,
        VANILLA_ACCESSIBILITY_RESULT_SIGNATURE,
        "vanilla accessibility result branch",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_DISPOSITION_BRANCH_OFFSET,
        VANILLA_DISPOSITION_BRANCH_SIGNATURE,
        "vanilla disposition penalty branch",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_MIN_USE_BRANCH_OFFSET,
        VANILLA_MIN_USE_BRANCH_SIGNATURE,
        "vanilla minimum-use penalty branch",
    )?;
    verify_call_target(
        VANILLA_PROVIDER_ADDR + VANILLA_POLICY_SETUP_CALL_OFFSET,
        VANILLA_POLICY_SETUP_ADDR,
        "vanilla door-policy setup call",
    )?;
    verify_call_target(
        VANILLA_PROVIDER_ADDR + VANILLA_ACCESSIBILITY_CALL_OFFSET,
        DOOR_ACCESSIBILITY_ADDR,
        "vanilla accessibility call",
    )?;
    for offset in VANILLA_POLICY_CLEANUP_CALL_OFFSETS {
        verify_call_target(
            VANILLA_PROVIDER_ADDR + offset,
            VANILLA_POLICY_CLEANUP_ADDR,
            "vanilla temporary policy cleanup call",
        )?;
    }
    verify_signature(
        VANILLA_POLICY_SETUP_ADDR,
        VANILLA_POLICY_SETUP_SIGNATURE,
        "vanilla TeleportDoorData setup",
    )?;
    verify_signature(
        VANILLA_POLICY_CLEANUP_ADDR,
        VANILLA_POLICY_CLEANUP_SIGNATURE,
        "vanilla TeleportDoorData cleanup",
    )?;
    Ok(())
}

fn verify_stewie_policy_provider(provider: usize) -> anyhow::Result<usize> {
    verify_signature(
        provider,
        STEWIE_PROVIDER_SIGNATURE,
        "Stewie TeleportDoorSearch provider",
    )?;
    verify_signature(
        provider + STEWIE_POLICY_BLOCK_OFFSET,
        STEWIE_POLICY_BLOCK_SIGNATURE,
        "Stewie door-policy block",
    )?;
    verify_signature(
        provider + STEWIE_ACCESSIBILITY_CALL_OFFSET,
        STEWIE_ACCESSIBILITY_CALL_SIGNATURE,
        "Stewie accessibility call",
    )?;
    verify_signature(
        provider + STEWIE_ACCESSIBILITY_RESULT_OFFSET,
        STEWIE_ACCESSIBILITY_RESULT_SIGNATURE,
        "Stewie accessibility result branch",
    )?;
    verify_signature(
        provider + STEWIE_DISPOSITION_BRANCH_OFFSET,
        STEWIE_DISPOSITION_BRANCH_SIGNATURE,
        "Stewie disposition penalty branch",
    )?;
    verify_signature(
        provider + STEWIE_MIN_USE_BRANCH_OFFSET,
        STEWIE_MIN_USE_BRANCH_SIGNATURE,
        "Stewie minimum-use penalty branch",
    )?;
    verify_signature(
        provider + STEWIE_LOCK_CLEANUP_OFFSET,
        STEWIE_LOCK_CLEANUP_SIGNATURE,
        "Stewie temporary lock-data cleanup",
    )?;

    let setup_target = relative_call_target(provider + STEWIE_POLICY_SETUP_CALL_OFFSET)
        .context("resolve Stewie door-policy setup call")?;
    ensure!(
        module_name(setup_target)
            .is_some_and(|name| name.eq_ignore_ascii_case("nvse_stewie_tweaks.dll")),
        "unsupported Stewie door-policy setup target {}",
        module_address(setup_target).unwrap_or_else(|| format!("unknown!0x{setup_target:08X}"))
    );
    verify_signature(
        setup_target,
        STEWIE_POLICY_SETUP_SIGNATURE,
        "Stewie TeleportDoorData setup",
    )?;
    Ok(setup_target)
}

fn enable_tasklet_backend() -> anyhow::Result<()> {
    let provider = unsafe { read_u32(TELEPORT_DOOR_PROVIDER_SLOT as *const u8, 0) } as usize;
    let provider_label =
        module_address(provider).unwrap_or_else(|| format!("unknown!0x{provider:08X}"));
    resolve_policy_setup_target(provider, &provider_label)
        .context("verify worker-safe teleport-door provider")?;
    verify_signature(
        DOOR_ACCESSIBILITY_ADDR,
        DOOR_ACCESSIBILITY_SIGNATURE,
        "worker-safe teleport-door accessibility predicate",
    )?;

    verify_signature(
        TASKLET_MANAGER_ADDR,
        TASKLET_MANAGER_SIGNATURE,
        "tasklet manager singleton",
    )?;
    verify_signature(
        TASKLET_GROUP_CREATE_ADDR,
        TASKLET_GROUP_CREATE_SIGNATURE,
        "tasklet group creation wrapper",
    )?;
    verify_signature(
        TASKLET_GROUP_ACTIVATE_ADDR,
        TASKLET_GROUP_ACTIVATE_SIGNATURE,
        "tasklet group activation wrapper",
    )?;
    verify_signature(
        TASKLET_SUBMIT_ADDR,
        TASKLET_SUBMIT_SIGNATURE,
        "tasklet submission wrapper",
    )?;
    verify_signature(
        TASKLET_GROUP_CLOSE_ADDR,
        TASKLET_GROUP_CLOSE_SIGNATURE,
        "tasklet group close wrapper",
    )?;
    verify_signature(
        TASKLET_GROUP_WAIT_ADDR,
        TASKLET_GROUP_WAIT_SIGNATURE,
        "tasklet group completion wait",
    )?;
    verify_signature(
        TASKLET_PRIORITY_ENQUEUE_ADDR,
        TASKLET_PRIORITY_ENQUEUE_SIGNATURE,
        "tasklet priority enqueue buckets",
    )?;
    verify_signature(
        TASKLET_PRIORITY_DISPATCH_ADDR,
        TASKLET_PRIORITY_DISPATCH_SIGNATURE,
        "tasklet ascending-priority dispatcher",
    )?;
    verify_signature(
        TASKLET_GROUP_LAYOUT_ADDR,
        TASKLET_GROUP_LAYOUT_SIGNATURE,
        "tasklet group priority layout",
    )?;

    // Keep tasklet state out of the eagerly mapped DLL image and do not
    // allocate it while xNVSE and other plugins are still loading.
    LazyLock::force(&RADIO_TASKLET);
    TASKLET_PROVIDER.store(provider, Ordering::Release);
    TASKLET_BACKEND_AVAILABLE.store(true, Ordering::Release);
    log::info!(
        "[RADIO] Native tasklet query backend active: provider={} manager=0x{:08X} queue_priority={} worker_priority=below-normal endpoint_ownership=game-thread",
        provider_label,
        TASKLET_MANAGER_ADDR,
        TASKLET_LOWEST_QUEUE_PRIORITY,
    );
    Ok(())
}

unsafe fn tasklet_manager() -> *mut c_void {
    let get_manager =
        unsafe { FnPtr::<TaskletManagerFn>::from_address_unchecked(TASKLET_MANAGER_ADDR) }.as_fn();
    unsafe { get_manager() }
}

unsafe fn ensure_tasklet_group(backend: &mut TaskletBackend) -> anyhow::Result<()> {
    if backend.group != 0 {
        return Ok(());
    }

    let manager = unsafe { tasklet_manager() };
    ensure!(!manager.is_null(), "tasklet manager is null");
    let create =
        unsafe { FnPtr::<TaskletGroupCreateFn>::from_address_unchecked(TASKLET_GROUP_CREATE_ADDR) }
            .as_fn();
    let mut group = core::ptr::null_mut();
    ensure!(
        unsafe { create(manager, &mut group) } != 0 && !group.is_null(),
        "tasklet group creation failed"
    );
    backend.group = group as usize;
    Ok(())
}

unsafe fn set_tasklet_group_priority(group: *mut u8, priority: u32) {
    debug_assert!(!group.is_null());
    debug_assert!(priority <= TASKLET_LOWEST_QUEUE_PRIORITY);
    unsafe {
        core::ptr::write_volatile(
            group.add(TASKLET_GROUP_PRIORITY_OFFSET).cast::<u32>(),
            priority,
        );
    }
}

unsafe fn activate_tasklet_group(backend: &mut TaskletBackend) -> anyhow::Result<()> {
    unsafe { ensure_tasklet_group(backend) }?;
    if backend.group_active {
        return Ok(());
    }

    let manager = unsafe { tasklet_manager() };
    let activate = unsafe {
        FnPtr::<TaskletGroupActivateFn>::from_address_unchecked(TASKLET_GROUP_ACTIVATE_ADDR)
    }
    .as_fn();
    let mut group = backend.group as *mut c_void;
    ensure!(
        unsafe { activate(manager, &mut group) } != 0,
        "tasklet group activation failed"
    );
    ensure!(
        group as usize == backend.group,
        "tasklet group identity changed during activation"
    );
    // The manager scans queue 0 first. Radio work must yield every queue slot
    // to frame-critical engine tasklets even though group construction uses 0.
    unsafe {
        set_tasklet_group_priority(group.cast(), TASKLET_LOWEST_QUEUE_PRIORITY);
    }
    backend.group_active = true;
    backend.group_closed = false;
    Ok(())
}

unsafe fn close_tasklet_group(backend: &mut TaskletBackend) -> bool {
    if !backend.group_active || backend.group_closed {
        return true;
    }

    let manager = unsafe { tasklet_manager() };
    let close =
        unsafe { FnPtr::<TaskletGroupCloseFn>::from_address_unchecked(TASKLET_GROUP_CLOSE_ADDR) }
            .as_fn();
    let mut group = backend.group as *mut c_void;
    let closed = unsafe { close(manager, &mut group) } != 0;
    if closed {
        backend.group_closed = true;
    }
    closed
}

unsafe fn wait_tasklet_group(backend: &mut TaskletBackend) {
    if !backend.group_active {
        return;
    }

    let group = backend.group as *mut c_void;
    let wait =
        unsafe { FnPtr::<TaskletGroupWaitFn>::from_address_unchecked(TASKLET_GROUP_WAIT_ADDR) }
            .as_fn();
    unsafe { wait(group, 0) };
    backend.group_active = false;
    backend.group_closed = false;
    backend.in_flight = false;
}

unsafe fn prepare_tasklet_work(work: QueryWork) -> bool {
    let lookup =
        unsafe { FnPtr::<LookupFormByIdFn>::from_address_unchecked(LOOKUP_FORM_BY_ID_ADDR) }
            .as_fn();
    let init = unsafe {
        FnPtr::<PathingLocationInitFn>::from_address_unchecked(PATHING_LOCATION_INIT_ADDR)
    }
    .as_fn();
    let tasklet = unsafe { &mut *RADIO_TASKLET.0.get() };
    debug_assert_eq!(tasklet.batch.count, 0);
    let station_ref = unsafe { lookup(work.request.key.station_form_id) };
    let current_ref = unsafe { lookup(work.request.key.current_ref_form_id) };
    if station_ref.is_null() || current_ref.is_null() {
        return false;
    }

    let prepared = &mut tasklet.batch.queries[0];
    prepared.work = work;
    unsafe {
        init(&mut prepared.station, station_ref);
        init(&mut prepared.current, current_ref);
    }
    prepared.initialized = true;
    tasklet.batch.count = 1;
    true
}

unsafe fn cleanup_prepared_batch() {
    let tasklet = unsafe { &mut *RADIO_TASKLET.0.get() };
    if tasklet.batch.count == 0 {
        return;
    }

    let destroy = unsafe {
        FnPtr::<PathingLocationDestroyFn>::from_address_unchecked(PATHING_LOCATION_DESTROY_ADDR)
    }
    .as_fn();
    for prepared in &mut tasklet.batch.queries[..tasklet.batch.count] {
        if prepared.initialized {
            unsafe {
                destroy(&mut prepared.station);
                destroy(&mut prepared.current);
            }
            prepared.initialized = false;
        }
    }
    tasklet.batch.count = 0;
}

unsafe fn submit_tasklet_batch(backend: &mut TaskletBackend) -> anyhow::Result<()> {
    let manager = unsafe { tasklet_manager() };
    let submit =
        unsafe { FnPtr::<TaskletSubmitFn>::from_address_unchecked(TASKLET_SUBMIT_ADDR) }.as_fn();
    let tasklet = unsafe { &mut *RADIO_TASKLET.0.get() };
    let mut group = backend.group as *mut c_void;
    let mut handle = TaskletHandle {
        vtable: BSTASKLET_VTABLE,
        task: &mut tasklet.engine,
    };
    TASKLET_BATCH_ABORTED.store(false, Ordering::Release);
    ensure!(
        unsafe { submit(manager, &mut group, &mut handle, 0) } != 0,
        "tasklet submission failed"
    );
    backend.in_flight = true;
    Ok(())
}

fn finish_completed_tasklet(backend: &mut TaskletBackend, now_ms: u32) -> bool {
    if !backend.in_flight {
        return false;
    }
    if !unsafe { close_tasklet_group(backend) } {
        return false;
    }
    if !unsafe { tasklet_group_completion_observed(backend.group as *const u8) } {
        return false;
    }
    unsafe {
        wait_tasklet_group(backend);
    }
    let published = unsafe { publish_prepared_batch() };
    unsafe {
        cleanup_prepared_batch();
    }
    if published {
        report_tasklet_publication(now_ms);
    }
    true
}

unsafe fn tasklet_group_completion_observed(group: *const u8) -> bool {
    if group.is_null() {
        return false;
    }
    let submitted = unsafe {
        core::ptr::read_volatile(group.add(TASKLET_GROUP_SUBMITTED_OFFSET).cast::<u32>())
    };
    let completed = unsafe {
        core::ptr::read_volatile(group.add(TASKLET_GROUP_COMPLETED_OFFSET).cast::<u32>())
    };
    tasklet_group_counts_complete(submitted, completed)
}

fn tasklet_group_counts_complete(submitted: u32, completed: u32) -> bool {
    submitted != 0 && submitted == completed
}

fn schedule_tasklet_generation(now_ms: u32) -> anyhow::Result<()> {
    ensure!(
        !TASKLET_PRIORITY_FAILED.load(Ordering::Acquire),
        "radio tasklet worker priority isolation failed"
    );
    let provider = unsafe { read_u32(TELEPORT_DOOR_PROVIDER_SLOT as *const u8, 0) } as usize;
    ensure!(
        provider == TASKLET_PROVIDER.load(Ordering::Acquire),
        "teleport-door provider changed after tasklet capability verification"
    );
    let mut backend = TASKLET_BACKEND.lock();
    if backend.in_flight {
        finish_completed_tasklet(&mut backend, now_ms);
        if backend.in_flight {
            return Ok(());
        }
    }
    let Some(work) = QUERY_PIPELINE.lock().take_next(now_ms) else {
        return Ok(());
    };

    unsafe { activate_tasklet_group(&mut backend) }?;
    let prep_timer = (!COOPERATIVE_PUBLICATION_REPORTED.load(Ordering::Acquire))
        .then(diagnostics::Stopwatch::start);
    if !unsafe { prepare_tasklet_work(work) } {
        QUERY_PIPELINE.lock().abort_build();
        ensure!(
            unsafe { close_tasklet_group(&mut backend) },
            "empty tasklet group could not be closed"
        );
        unsafe { wait_tasklet_group(&mut backend) };
        return Ok(());
    }
    if let Some(elapsed_us) = prep_timer.and_then(diagnostics::Stopwatch::elapsed_us) {
        TASKLET_PREP_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
        diagnostics::update_max_u64(&TASKLET_PREP_MAX_US, elapsed_us);
    }
    if let Err(error) = unsafe { submit_tasklet_batch(&mut backend) } {
        let _ = unsafe { close_tasklet_group(&mut backend) };
        unsafe {
            wait_tasklet_group(&mut backend);
            cleanup_prepared_batch();
        }
        QUERY_PIPELINE.lock().abort_build();
        return Err(error);
    }
    if !unsafe { close_tasklet_group(&mut backend) } {
        log::error!("[RADIO] Submitted tasklet group could not be closed; completion retry armed");
    }
    Ok(())
}

fn quiesce_tasklet_queries() {
    let mut backend = TASKLET_BACKEND.lock();
    if backend.group_active {
        // World teardown cannot outlive query endpoints. Closing prevents new
        // group work and the native wait joins any callback already running.
        if !unsafe { close_tasklet_group(&mut backend) } {
            log::error!("[RADIO] Tasklet group close failed at world-lifetime barrier");
            return;
        }
        unsafe { wait_tasklet_group(&mut backend) };
    }
    unsafe { cleanup_prepared_batch() };
    QUERY_PIPELINE.lock().abort_build();
}

fn report_tasklet_publication(now_ms: u32) {
    if COOPERATIVE_PUBLICATION_REPORTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let published_count = QUERY_PIPELINE.lock().published_count;
    log::info!(
        "[RADIO] Native paced tasklet generation verified: results={} jobs={} worker_total/max={}/{}us game_thread_prep_total/max={}/{}us latency_ms={:?} worker_thread=0x{:08X}",
        published_count,
        COOPERATIVE_TIMED_JOBS.load(Ordering::Relaxed),
        COOPERATIVE_TIMED_TOTAL_US.load(Ordering::Relaxed),
        COOPERATIVE_TIMED_MAX_US.load(Ordering::Relaxed),
        TASKLET_PREP_TOTAL_US.load(Ordering::Relaxed),
        TASKLET_PREP_MAX_US.load(Ordering::Relaxed),
        (COOPERATIVE_COLLECTION_MS.load(Ordering::Acquire) != 0)
            .then(|| now_ms.wrapping_sub(COOPERATIVE_COLLECTION_MS.load(Ordering::Relaxed))),
        TASKLET_WORKER_THREAD_ID.load(Ordering::Acquire),
    );
}

unsafe extern "thiscall" fn radio_tasklet_finish(_tasklet: *mut EngineTasklet) {}

unsafe extern "thiscall" fn radio_tasklet_ready(_tasklet: *mut EngineTasklet) -> u8 {
    1
}

unsafe extern "thiscall" fn radio_tasklet_execute(tasklet: *mut EngineTasklet) {
    TASKLET_WORKER_THREAD_ID.store(
        libpsycho::os::windows::winapi::get_current_thread_id(),
        Ordering::Release,
    );
    // Queue priority orders engine tasklets; OS priority also prevents the
    // running path query from competing equally with the game/render threads.
    let mut priority_guard = match lower_current_thread_priority_scoped(ThreadPriority::BelowNormal)
    {
        Ok(guard) => guard,
        Err(_) => {
            TASKLET_PRIORITY_FAILED.store(true, Ordering::Release);
            TASKLET_BATCH_ABORTED.store(true, Ordering::Release);
            return;
        }
    };
    let tasklet = unsafe { &mut *tasklet.cast::<RadioTasklet>() };
    for prepared in &mut tasklet.batch.queries[..tasklet.batch.count] {
        if game_is_loading() {
            TASKLET_BATCH_ABORTED.store(true, Ordering::Release);
            break;
        }

        let timer = (!COOPERATIVE_PUBLICATION_REPORTED.load(Ordering::Acquire))
            .then(diagnostics::Stopwatch::start);
        let distance = unsafe { execute_prepared_query(prepared) };
        if let Some(elapsed_us) = timer.and_then(diagnostics::Stopwatch::elapsed_us) {
            COOPERATIVE_TIMED_JOBS.fetch_add(1, Ordering::Relaxed);
            COOPERATIVE_TIMED_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
            diagnostics::update_max_u64(&COOPERATIVE_TIMED_MAX_US, elapsed_us);
        }
        prepared.distance = distance;
    }
    if priority_guard.restore().is_err() {
        TASKLET_PRIORITY_FAILED.store(true, Ordering::Release);
        TASKLET_BATCH_ABORTED.store(true, Ordering::Release);
    }
}

unsafe fn publish_prepared_batch() -> bool {
    let tasklet = unsafe { &*RADIO_TASKLET.0.get() };
    let mut pipeline = QUERY_PIPELINE.lock();
    if TASKLET_BATCH_ABORTED.load(Ordering::Acquire) || tasklet.batch.count != 1 {
        pipeline.abort_build();
        return false;
    }
    let prepared = &tasklet.batch.queries[0];
    pipeline.complete(prepared.work, Some(prepared.distance))
}

unsafe fn execute_prepared_query(prepared: &mut PreparedQuery) -> f32 {
    let scope = RadioPathQueryScope::enter();
    let distance = unsafe {
        call_mode0_distance(
            &mut prepared.station,
            &mut prepared.current,
            prepared.work.request.radius,
            core::ptr::null_mut(),
            3,
        )
    };
    drop(scope);
    distance
}

#[unsafe(naked)]
unsafe extern "C" fn cooperative_distance_entry(
    _station: *mut PathingLocation,
    _current_ref: *mut PathingLocation,
    _radius: f32,
    _actor_data: *mut c_void,
    _disposition: u32,
) -> f32 {
    core::arch::naked_asm!(
        "mov eax, esp",
        "push dword ptr [eax + 20]",
        "push dword ptr [eax + 16]",
        "push dword ptr [eax + 12]",
        "push dword ptr [eax + 8]",
        "push dword ptr [eax + 4]",
        "push ebp",
        "call {}",
        "add esp, 24",
        "ret",
        sym cooperative_distance_body,
    );
}

unsafe extern "C" fn cooperative_distance_body(
    caller_ebp: usize,
    station: *mut PathingLocation,
    current_location: *mut PathingLocation,
    radius: f32,
    actor_data: *mut c_void,
    disposition: u32,
) -> f32 {
    if !cooperative_scan_active() || caller_ebp == 0 || !actor_data.is_null() || disposition != 3 {
        return unsafe {
            call_mode0_distance(station, current_location, radius, actor_data, disposition)
        };
    }

    let station_ref =
        unsafe { core::ptr::read_unaligned(caller_ebp.wrapping_sub(0x24) as *const *mut c_void) };
    let current_ref =
        unsafe { core::ptr::read_unaligned(caller_ebp.wrapping_add(8) as *const *mut c_void) };
    let Some(station_form_id) = (unsafe { reference_form_id(station_ref) }) else {
        return unsafe {
            call_mode0_distance(station, current_location, radius, actor_data, disposition)
        };
    };
    let Some(current_ref_form_id) = (unsafe { reference_form_id(current_ref) }) else {
        return unsafe {
            call_mode0_distance(station, current_location, radius, actor_data, disposition)
        };
    };

    let request = QueryRequest {
        key: QueryKey {
            station_form_id,
            current_ref_form_id,
            radius_bits: radius.to_bits(),
        },
        radius,
    };
    let (distance, collection_failed) = {
        let mut pipeline = QUERY_PIPELINE.lock();
        let distance = pipeline.observe_query(request);
        (distance, pipeline.collection_failed)
    };
    if collection_failed && !COOPERATIVE_CAPACITY_EXCEEDED.swap(true, Ordering::AcqRel) {
        COOPERATIVE_SCAN_ACTIVE.with(|active| active.set(false));
        log::error!(
            "[RADIO] Cooperative query capacity exceeded ({}); future scans retain the original synchronous path",
            MAX_COOPERATIVE_QUERIES,
        );
    }
    distance.unwrap_or_else(path_failure_distance)
}

fn observe_frame_present() {
    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    let now_ms = libpsycho::os::windows::winapi::get_tick_count();
    FRAME_THREAD_ID.store(thread_id, Ordering::Release);
    LAST_FRAME_EVENT_MS.store(now_ms, Ordering::Release);

    if RADIO_THREAD_ID.load(Ordering::Acquire) != thread_id {
        return;
    }
    if game_is_loading() {
        if TASKLET_BACKEND_AVAILABLE.load(Ordering::Acquire) {
            quiesce_tasklet_queries();
        }
        QUERY_PIPELINE.lock().reset();
        return;
    }
    if TASKLET_BACKEND_AVAILABLE.load(Ordering::Acquire) {
        match schedule_tasklet_generation(now_ms) {
            Ok(()) => return,
            Err(error) => {
                TASKLET_BACKEND_AVAILABLE.store(false, Ordering::Release);
                quiesce_tasklet_queries();
                if !TASKLET_BACKEND_FAILURE_REPORTED.swap(true, Ordering::AcqRel) {
                    log::error!(
                        "[RADIO] Native tasklet backend failed; cooperative main-thread fallback restored: {error:#}"
                    );
                }
            }
        }
    }

    let Some(work) = QUERY_PIPELINE.lock().take_next(now_ms) else {
        return;
    };
    let timer = (!COOPERATIVE_PUBLICATION_REPORTED.load(Ordering::Acquire))
        .then(diagnostics::Stopwatch::start);
    let distance = unsafe { execute_query_work(work) };
    if let Some(elapsed_us) = timer.and_then(diagnostics::Stopwatch::elapsed_us) {
        COOPERATIVE_TIMED_JOBS.fetch_add(1, Ordering::Relaxed);
        COOPERATIVE_TIMED_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
        diagnostics::update_max_u64(&COOPERATIVE_TIMED_MAX_US, elapsed_us);
    }

    let (published, published_count) = {
        let mut pipeline = QUERY_PIPELINE.lock();
        let published = pipeline.complete(work, distance);
        (published, pipeline.published_count)
    };
    if published && !COOPERATIVE_PUBLICATION_REPORTED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[RADIO] Cooperative generation verified: results={} jobs={} total/max={}/{}us spread_ms={:?} thread=0x{:08X}",
            published_count,
            COOPERATIVE_TIMED_JOBS.load(Ordering::Relaxed),
            COOPERATIVE_TIMED_TOTAL_US.load(Ordering::Relaxed),
            COOPERATIVE_TIMED_MAX_US.load(Ordering::Relaxed),
            (COOPERATIVE_COLLECTION_MS.load(Ordering::Acquire) != 0)
                .then(|| now_ms.wrapping_sub(COOPERATIVE_COLLECTION_MS.load(Ordering::Relaxed))),
            libpsycho::os::windows::winapi::get_current_thread_id(),
        );
    }
}

unsafe fn execute_query_work(work: QueryWork) -> Option<f32> {
    let lookup =
        unsafe { FnPtr::<LookupFormByIdFn>::from_address_unchecked(LOOKUP_FORM_BY_ID_ADDR) }
            .as_fn();
    let station_ref = unsafe { lookup(work.request.key.station_form_id) };
    let current_ref = unsafe { lookup(work.request.key.current_ref_form_id) };
    if station_ref.is_null() || current_ref.is_null() {
        return None;
    }

    let init = unsafe {
        FnPtr::<PathingLocationInitFn>::from_address_unchecked(PATHING_LOCATION_INIT_ADDR)
    }
    .as_fn();
    let destroy = unsafe {
        FnPtr::<PathingLocationDestroyFn>::from_address_unchecked(PATHING_LOCATION_DESTROY_ADDR)
    }
    .as_fn();
    let mut station = PathingLocation::uninit_storage();
    let mut current = PathingLocation::uninit_storage();
    unsafe {
        init(&mut station, station_ref);
        init(&mut current, current_ref);
    }

    let scope = RadioPathQueryScope::enter();
    let distance = unsafe {
        call_mode0_distance(
            &mut station,
            &mut current,
            work.request.radius,
            core::ptr::null_mut(),
            3,
        )
    };
    drop(scope);
    unsafe {
        destroy(&mut station);
        destroy(&mut current);
    }
    Some(distance)
}

unsafe fn call_mode0_distance(
    station: *mut PathingLocation,
    current_ref: *mut PathingLocation,
    radius: f32,
    actor_data: *mut c_void,
    disposition: u32,
) -> f32 {
    let original =
        unsafe { FnPtr::<Mode0RadioDistanceFn>::from_address_unchecked(MODE0_RADIO_DISTANCE_ADDR) }
            .as_fn();
    unsafe { original(station, current_ref, radius, actor_data, disposition) }
}

unsafe fn reference_form_id(reference: *mut c_void) -> Option<u32> {
    if reference.is_null() {
        return None;
    }
    let form_id = unsafe { core::ptr::read_unaligned(reference.cast::<u8>().add(0x0C).cast()) };
    (form_id != 0).then_some(form_id)
}

fn path_failure_distance() -> f32 {
    unsafe { core::ptr::read_volatile(PATH_FAILURE_DISTANCE_ADDR as *const f32) }
}

fn register_radio_thread() {
    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    let _ = RADIO_THREAD_ID.compare_exchange(0, thread_id, Ordering::AcqRel, Ordering::Acquire);
}

fn cooperative_scheduler_available() -> bool {
    if COOPERATIVE_CAPACITY_EXCEEDED.load(Ordering::Acquire) {
        return false;
    }
    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    if RADIO_THREAD_ID.load(Ordering::Acquire) != thread_id
        || FRAME_THREAD_ID.load(Ordering::Acquire) != thread_id
    {
        return false;
    }

    let last_frame_ms = LAST_FRAME_EVENT_MS.load(Ordering::Acquire);
    last_frame_ms != 0
        && libpsycho::os::windows::winapi::get_tick_count().wrapping_sub(last_frame_ms)
            <= FRAME_EVENT_TIMEOUT_MS
}

fn observe_scan_cadence(now_ms: u32) -> u32 {
    let previous_ms = LAST_RADIO_SCAN_MS.swap(now_ms, Ordering::AcqRel);
    let elapsed_ms = (previous_ms != 0).then(|| now_ms.wrapping_sub(previous_ms));
    normalize_scan_cadence(elapsed_ms)
}

fn normalize_scan_cadence(elapsed_ms: Option<u32>) -> u32 {
    elapsed_ms
        .filter(|elapsed_ms| (MIN_SCAN_CADENCE_MS..=MAX_SCAN_CADENCE_MS).contains(elapsed_ms))
        .unwrap_or(DEFAULT_SCAN_CADENCE_MS)
}

fn tick_reached(now_ms: u32, due_ms: u32) -> bool {
    now_ms.wrapping_sub(due_ms) < 0x8000_0000
}

fn report_cooperative_fallback_once() {
    if COOPERATIVE_FALLBACK_REPORTED.load(Ordering::Acquire) {
        return;
    }

    let deferred_init_ms = DEFERRED_INIT_MS.load(Ordering::Acquire);
    if deferred_init_ms == 0 {
        return;
    }
    let now_ms = libpsycho::os::windows::winapi::get_tick_count();
    if now_ms.wrapping_sub(deferred_init_ms) < FALLBACK_REPORT_DELAY_MS {
        return;
    }
    if COOPERATIVE_FALLBACK_REPORTED.swap(true, Ordering::AcqRel) {
        return;
    }

    let radio_thread = RADIO_THREAD_ID.load(Ordering::Acquire);
    let frame_thread = FRAME_THREAD_ID.load(Ordering::Acquire);
    let last_frame_ms = LAST_FRAME_EVENT_MS.load(Ordering::Acquire);
    let frame_age_ms = (last_frame_ms != 0).then(|| now_ms.wrapping_sub(last_frame_ms));
    let reason = cooperative_fallback_reason(
        COOPERATIVE_CAPACITY_EXCEEDED.load(Ordering::Acquire),
        radio_thread,
        frame_thread,
        frame_age_ms,
    );
    log::warn!(
        "[RADIO] Cooperative scheduler fallback: reason={} radio_thread=0x{:08X} frame_thread=0x{:08X} frame_age_ms={:?}",
        reason,
        radio_thread,
        frame_thread,
        frame_age_ms,
    );
}

fn cooperative_fallback_reason(
    capacity_exceeded: bool,
    radio_thread: u32,
    frame_thread: u32,
    frame_age_ms: Option<u32>,
) -> &'static str {
    if capacity_exceeded {
        return "capacity-exceeded";
    }
    if radio_thread == 0 {
        return "radio-thread-missing";
    }
    if frame_thread == 0 || frame_age_ms.is_none() {
        return "frame-event-missing";
    }
    if radio_thread != frame_thread {
        return "thread-mismatch";
    }
    if frame_age_ms.is_some_and(|age_ms| age_ms > FRAME_EVENT_TIMEOUT_MS) {
        return "frame-event-stale";
    }
    "unknown"
}

fn cooperative_scan_active() -> bool {
    COOPERATIVE_SCAN_ACTIVE.with(|active| active.get())
}

fn game_is_loading() -> bool {
    unsafe { core::ptr::read_volatile(LOADING_FLAG_ADDR as *const u8) != 0 }
}

unsafe extern "C" fn hook_periodic_radio_signal_scan(
    current_ref: *mut c_void,
    out_stations: *mut c_void,
    out_meta: *mut c_void,
) {
    register_radio_thread();
    let scan_started_ms = libpsycho::os::windows::winapi::get_tick_count();
    let scan_cadence_ms = observe_scan_cadence(scan_started_ms);
    let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
    let scope = RadioScanScope::enter(scan_started_ms, scan_cadence_ms);
    let first_collection_timer = (scope.cooperative
        && !COOPERATIVE_COLLECTION_REPORTED.load(Ordering::Acquire))
    .then(diagnostics::Stopwatch::start);
    let cooperative = scope.cooperative;
    let scan =
        unsafe { FnPtr::<RadioSignalScanFn>::from_address_unchecked(RADIO_SIGNAL_SCAN_ADDR) }
            .as_fn();
    unsafe { scan(current_ref, out_stations, out_meta) };
    drop(scope);

    if cooperative && !COOPERATIVE_COLLECTION_REPORTED.swap(true, Ordering::AcqRel) {
        let (requests, spacing_ms, state) = {
            let pipeline = QUERY_PIPELINE.lock();
            (
                pipeline.build_count,
                pipeline.job_spacing_ms,
                pipeline.state,
            )
        };
        COOPERATIVE_COLLECTION_MS.store(scan_started_ms, Ordering::Release);
        log::info!(
            "[RADIO] Cooperative collection verified: requests={} cadence/spacing={}/{}ms scan_us={:?} state={:?} thread=0x{:08X}",
            requests,
            scan_cadence_ms,
            spacing_ms,
            first_collection_timer.and_then(diagnostics::Stopwatch::elapsed_us),
            state,
            libpsycho::os::windows::winapi::get_current_thread_id(),
        );
    }

    let Some(elapsed_us) = timer.elapsed_us() else {
        return;
    };
    if !log::log_enabled!(log::Level::Debug) {
        return;
    }

    let slow_sample = (elapsed_us >= SLOW_SCAN_US).then(|| {
        let stats = RADIO_SCAN_STATE.with(|state| state.borrow().stats);
        let residual_us = elapsed_us.saturating_sub(
            stats
                .mode_queries
                .iter()
                .map(|timing| timing.total_us)
                .sum(),
        );
        SCAN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        (elapsed_us, residual_us, stats)
    });
    let Some(aggregate) = RADIO_SCAN_STATE.with(|state| {
        state.borrow_mut().reporter.observe(
            libpsycho::os::windows::winapi::get_tick_count(),
            slow_sample,
        )
    }) else {
        return;
    };
    let sequence = SCAN_SEQUENCE.load(Ordering::Relaxed);
    let stats = aggregate.stats;
    log::debug!(
        "[RADIO_SCAN] seq={} slow={} total_avg/max={}/{}us station_modes={}/{}/{}/{}/{}+{} query0={}/{}/{} query1={}/{}/{} query2={}/{}/{} other={}/{}/{} traversal={}/{}/{} branch=m0:{}/vtable:{}/empty:{}/missing:{}/first:{}/goal:{}/parent0:{}/result0:{}/source:{}/other:{} policy=query:{}/setup:{}/access:{} residual_avg/max={}/{}us",
        sequence,
        aggregate.slow_scans,
        aggregate.total_us / u64::from(aggregate.slow_scans.max(1)),
        aggregate.max_us,
        stats.station_modes[0],
        stats.station_modes[1],
        stats.station_modes[2],
        stats.station_modes[3],
        stats.station_modes[4],
        stats.other_station_modes,
        stats.mode_queries[0].calls,
        stats.mode_queries[0].total_us,
        stats.mode_queries[0].max_us,
        stats.mode_queries[1].calls,
        stats.mode_queries[1].total_us,
        stats.mode_queries[1].max_us,
        stats.mode_queries[2].calls,
        stats.mode_queries[2].total_us,
        stats.mode_queries[2].max_us,
        stats.other_queries.calls,
        stats.other_queries.total_us,
        stats.other_queries.max_us,
        stats.traversals.calls,
        stats.traversals.total_us,
        stats.traversals.max_us,
        stats.mode0_traversals,
        stats.expected_query_vtable,
        stats.queue_empty_before_traversal,
        stats.source_missing,
        stats.source_first,
        stats.source_goal_match,
        stats.source_parent_null,
        stats.result_null,
        stats.result_source,
        stats.result_other,
        stats.policy_queries,
        stats.policy_setup_bypasses,
        stats.policy_access_bypasses,
        aggregate.residual_us / u64::from(aggregate.slow_scans.max(1)),
        aggregate.residual_max_us,
    );
}

unsafe extern "C" fn hook_path_query(
    from: usize,
    to: usize,
    result: *mut c_void,
    mode: u32,
    max_cost: u32,
    filter: u32,
    behavior: u32,
) -> u8 {
    let Ok(original) = PATH_QUERY_HOOK.original() else {
        return 0;
    };
    if !radio_scan_active() {
        return unsafe { original(from, to, result, mode, max_cost, filter, behavior) };
    }

    let timer = diagnostics::Stopwatch::start();
    let result_value = unsafe { original(from, to, result, mode, max_cost, filter, behavior) };
    let elapsed_us = timer.elapsed_us();
    with_active_stats(|stats| {
        if let Some(timing) = stats.mode_queries.get_mut(mode as usize) {
            timing.record(elapsed_us);
        } else {
            stats.other_queries.record(elapsed_us);
        }
    });
    result_value
}

unsafe extern "fastcall" fn hook_path_traversal(query: *mut c_void) -> usize {
    let Ok(original) = PATH_TRAVERSAL_HOOK.original() else {
        return 0;
    };
    if !radio_scan_active() {
        return unsafe { original(query) };
    }

    let policy_scope = unsafe { DoorPolicyBypassScope::enter(query.cast()) };
    if !diagnostics::hitch_profiling_enabled() {
        let result = unsafe { original(query) };
        drop(policy_scope);
        return result;
    }

    let probe = unsafe { TraversalProbe::capture(query.cast()) };
    let timer = diagnostics::Stopwatch::start();
    let result = unsafe { original(query) };
    drop(policy_scope);
    let elapsed_us = timer.elapsed_us();
    with_active_stats(|stats| {
        stats.traversals.record(elapsed_us);
        probe.record(result, stats);
    });
    result
}

#[derive(Clone, Copy, Default)]
struct TraversalProbe {
    mode0: bool,
    expected_vtable: bool,
    queue_empty: bool,
    source: usize,
    source_first: bool,
    source_goal_match: bool,
    source_parent_null: bool,
}

impl TraversalProbe {
    unsafe fn capture(query: *const u8) -> Self {
        if query.is_null() {
            return Self::default();
        }

        let mode = unsafe { read_u32(query, 0x2098) };
        if mode != 0 {
            return Self::default();
        }

        let source = unsafe { read_u32(query, 0x2050) } as usize;
        let first_queued = unsafe { first_queued_node(query) };
        let source_goal_match = source != 0
            && unsafe { core::ptr::read_unaligned((source + 0x08) as *const u8) }
                == unsafe { core::ptr::read_unaligned(query.add(0x208C)) }
            && unsafe { core::ptr::read_unaligned((source + 0x0C) as *const u32) }
                == unsafe { read_u32(query, 0x2090) }
            && unsafe { core::ptr::read_unaligned((source + 0x10) as *const u32) }
                == unsafe { read_u32(query, 0x2094) };

        Self {
            mode0: true,
            expected_vtable: unsafe { read_u32(query, 0) } as usize == RADIO_QUERY_VTABLE,
            queue_empty: first_queued == 0,
            source,
            source_first: source != 0 && first_queued == source,
            source_goal_match,
            source_parent_null: source != 0
                && unsafe { core::ptr::read_unaligned((source + 0x24) as *const u32) } == 0,
        }
    }

    fn record(self, result: usize, stats: &mut ScanStats) {
        if !self.mode0 {
            return;
        }

        stats.mode0_traversals = stats.mode0_traversals.saturating_add(1);
        stats.expected_query_vtable = stats
            .expected_query_vtable
            .saturating_add(u32::from(self.expected_vtable));
        stats.queue_empty_before_traversal = stats
            .queue_empty_before_traversal
            .saturating_add(u32::from(self.queue_empty));
        stats.source_missing = stats
            .source_missing
            .saturating_add(u32::from(self.source == 0));
        stats.source_first = stats
            .source_first
            .saturating_add(u32::from(self.source_first));
        stats.source_goal_match = stats
            .source_goal_match
            .saturating_add(u32::from(self.source_goal_match));
        stats.source_parent_null = stats
            .source_parent_null
            .saturating_add(u32::from(self.source_parent_null));
        if result == 0 {
            stats.result_null = stats.result_null.saturating_add(1);
        } else if result == self.source {
            stats.result_source = stats.result_source.saturating_add(1);
        } else {
            stats.result_other = stats.result_other.saturating_add(1);
        }
    }
}

unsafe extern "fastcall" fn hook_door_policy_setup(
    data: *mut c_void,
    edx: *mut c_void,
    door: *mut c_void,
) {
    let Ok(original) = DOOR_POLICY_SETUP_HOOK.original() else {
        return;
    };
    if !policy_bypass_active() || data.is_null() || door.is_null() {
        unsafe { original(data, edx, door) };
        return;
    }

    unsafe { core::ptr::write_unaligned(data.cast::<u8>().add(0x08).cast::<usize>(), 0) };
    PENDING_POLICY_ACCESS.with(|pending| pending.set((data as usize, door as usize)));
    with_active_stats(|stats| {
        stats.policy_setup_bypasses = stats.policy_setup_bypasses.saturating_add(1);
    });
}

unsafe extern "thiscall" fn hook_door_accessibility(
    data: *mut c_void,
    actor_data: *mut c_void,
    door: *mut c_void,
    out_flag: *mut u8,
) -> u8 {
    let Ok(original) = DOOR_ACCESSIBILITY_HOOK.original() else {
        return 0;
    };

    let expected = (data as usize, door as usize);
    let paired = policy_bypass_active()
        && actor_data.is_null()
        && !out_flag.is_null()
        && PENDING_POLICY_ACCESS.with(|pending| pending.get() == expected);
    if !paired {
        return unsafe { original(data, actor_data, door, out_flag) };
    }

    PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
    unsafe { out_flag.write(0) };
    with_active_stats(|stats| {
        stats.policy_access_bypasses = stats.policy_access_bypasses.saturating_add(1);
    });
    1
}

unsafe extern "fastcall" fn hook_station_mode(station: *mut c_void) -> u32 {
    let Ok(original) = STATION_MODE_HOOK.original() else {
        return 0;
    };
    let mode = unsafe { original(station) };
    if radio_scan_active() {
        with_active_stats(|stats| {
            if let Some(count) = stats.station_modes.get_mut(mode as usize) {
                *count = count.saturating_add(1);
            } else {
                stats.other_station_modes = stats.other_station_modes.saturating_add(1);
            }
        });
    }
    mode
}

fn radio_scan_active() -> bool {
    RADIO_SCAN_DEPTH.with(|depth| depth.get() != 0)
}

fn policy_bypass_active() -> bool {
    POLICY_BYPASS_DEPTH.with(|depth| depth.get() != 0)
}

unsafe fn is_exact_radio_policy_query(query: *const u8) -> bool {
    !query.is_null()
        && radio_scan_active()
        && unsafe { read_u32(query, 0) } as usize == RADIO_QUERY_VTABLE
        && unsafe { read_u32(query, 0x2098) } == 0
        && unsafe { read_u32(query, 0x20A0) } == 0
        && unsafe { read_u32(query, 0x20B4) } == 3
}

fn with_active_stats(f: impl FnOnce(&mut ScanStats)) {
    RADIO_SCAN_STATE.with(|state| {
        if let Ok(mut state) = state.try_borrow_mut() {
            f(&mut state.stats)
        }
    });
}

fn relative_call_target(call_addr: usize) -> anyhow::Result<usize> {
    let bytes = read_bytes(call_addr as *const c_void, 5)?;
    ensure!(
        bytes[0] == 0xE8,
        "expected CALL at 0x{call_addr:08X}, found opcode 0x{:02X}",
        bytes[0]
    );
    let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    Ok(call_addr
        .wrapping_add(5)
        .wrapping_add_signed(displacement as isize))
}

fn verify_call_target(call_addr: usize, expected_target: usize, label: &str) -> anyhow::Result<()> {
    let observed_target = relative_call_target(call_addr)?;
    ensure!(
        observed_target == expected_target,
        "{label} mismatch at 0x{call_addr:08X}: expected 0x{expected_target:08X}, found 0x{observed_target:08X}"
    );
    Ok(())
}

fn verify_signature(address: usize, expected: &[u8], label: &str) -> anyhow::Result<()> {
    let observed = read_bytes(address as *const c_void, expected.len())?;
    ensure!(
        observed == expected,
        "{label} signature mismatch at 0x{address:08X}: expected {expected:02X?}, found {observed:02X?}"
    );
    Ok(())
}

fn module_name(address: usize) -> Option<String> {
    module_address(address).and_then(|label| label.split_once('!').map(|item| item.0.to_owned()))
}

unsafe fn first_queued_node(query: *const u8) -> usize {
    for bucket in 0..PRIORITY_BUCKET_COUNT {
        let node = unsafe { read_u32(query, 0x1FF8 + bucket * 4) } as usize;
        if node != 0 {
            return node;
        }
    }
    0
}

unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(base.add(offset).cast()) }
}

fn verify_rel_call(call_addr: usize, expected_target: usize) -> anyhow::Result<()> {
    let opcode = unsafe { core::ptr::read_volatile(call_addr as *const u8) };
    if opcode != 0xE8 {
        return Err(anyhow::anyhow!(
            "callsite mismatch at 0x{call_addr:08X}: expected CALL opcode 0xE8, found 0x{opcode:02X}"
        ));
    }

    let displacement = unsafe { core::ptr::read_unaligned((call_addr + 1) as *const i32) };
    let observed_target = call_addr
        .wrapping_add(5)
        .wrapping_add_signed(displacement as isize);
    if observed_target != expected_target {
        return Err(anyhow::anyhow!(
            "callsite mismatch at 0x{call_addr:08X}: expected target 0x{expected_target:08X}, found 0x{observed_target:08X}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(station_form_id: u32, radius: f32) -> QueryRequest {
        QueryRequest {
            key: QueryKey {
                station_form_id,
                current_ref_form_id: 0x14,
                radius_bits: radius.to_bits(),
            },
            radius,
        }
    }

    #[test]
    fn cooperative_generation_is_published_only_when_complete() {
        let mut pipeline = QueryPipeline::new();
        let first = request(0x0100_0001, 10_000.0);
        let second = request(0x0100_0002, 20_000.0);

        pipeline.begin_scan(1_000, 250);
        assert_eq!(pipeline.observe_query(first), None);
        assert_eq!(pipeline.observe_query(second), None);
        assert!(pipeline.end_scan());

        let first_work = pipeline.take_next(1_000).expect("first frame work");
        assert!(!pipeline.complete(first_work, Some(1_500.0)));
        assert_eq!(pipeline.lookup_published(first.key), None);
        assert_eq!(pipeline.lookup_published(second.key), None);

        let second_work = pipeline.take_next(1_125).expect("second frame work");
        assert!(pipeline.complete(second_work, Some(2_500.0)));
        assert_eq!(pipeline.lookup_published(first.key), Some(1_500.0));
        assert_eq!(pipeline.lookup_published(second.key), Some(2_500.0));
    }

    #[test]
    fn failed_generation_preserves_the_last_complete_snapshot() {
        let mut pipeline = QueryPipeline::new();
        let old = request(0x0100_0001, 10_000.0);

        pipeline.begin_scan(1_000, 250);
        pipeline.observe_query(old);
        pipeline.end_scan();
        let work = pipeline.take_next(1_000).expect("seed work");
        assert!(pipeline.complete(work, Some(1_500.0)));

        pipeline.begin_scan(2_000, 250);
        assert_eq!(pipeline.observe_query(old), Some(1_500.0));
        let added = request(0x0100_0002, 20_000.0);
        assert_eq!(pipeline.observe_query(added), None);
        pipeline.end_scan();
        let work = pipeline.take_next(2_000).expect("failed work");
        assert!(!pipeline.complete(work, None));

        assert_eq!(pipeline.lookup_published(old.key), Some(1_500.0));
        assert_eq!(pipeline.lookup_published(added.key), None);
    }

    #[test]
    fn duplicate_queries_share_one_frame_job() {
        let mut pipeline = QueryPipeline::new();
        let request = request(0x0100_0001, 10_000.0);

        pipeline.begin_scan(1_000, 250);
        pipeline.observe_query(request);
        pipeline.observe_query(request);
        assert_eq!(pipeline.build_count, 1);
        pipeline.end_scan();
        let work = pipeline.take_next(1_000).expect("deduplicated work");
        assert!(pipeline.complete(work, Some(1_500.0)));
        assert!(pipeline.take_next(1_001).is_none());
    }

    #[test]
    fn cooperative_jobs_are_evenly_released_across_the_scan_cadence() {
        let mut pipeline = QueryPipeline::new();
        let first = request(0x0100_0001, 10_000.0);
        let second = request(0x0100_0002, 20_000.0);
        let third = request(0x0100_0003, 30_000.0);

        pipeline.begin_scan(1_000, 240);
        pipeline.observe_query(first);
        pipeline.observe_query(second);
        pipeline.observe_query(third);
        assert!(pipeline.end_scan());
        assert_eq!(pipeline.job_spacing_ms, 80);

        let work = pipeline.take_next(1_000).expect("first paced work");
        assert!(!pipeline.complete(work, Some(1_000.0)));
        assert!(pipeline.take_next(1_079).is_none());

        let work = pipeline.take_next(1_080).expect("second paced work");
        assert!(!pipeline.complete(work, Some(2_000.0)));
        assert!(pipeline.take_next(1_159).is_none());

        let work = pipeline.take_next(1_160).expect("third paced work");
        assert!(pipeline.complete(work, Some(3_000.0)));
    }

    #[test]
    fn delayed_frames_catch_up_without_releasing_more_than_one_job_per_call() {
        let mut pipeline = QueryPipeline::new();
        pipeline.begin_scan(1_000, 200);
        for form_id in 1..=4 {
            pipeline.observe_query(request(form_id, 10_000.0));
        }
        assert!(pipeline.end_scan());
        assert_eq!(pipeline.job_spacing_ms, 50);

        let first = pipeline.take_next(1_000).expect("first work");
        assert_eq!(first.index, 0);
        assert!(!pipeline.complete(first, Some(1_000.0)));

        let second = pipeline.take_next(1_125).expect("delayed second work");
        assert_eq!(second.index, 1);
        assert!(!pipeline.complete(second, Some(2_000.0)));

        let third = pipeline.take_next(1_140).expect("catch-up third work");
        assert_eq!(third.index, 2);
    }

    #[test]
    fn worker_queries_follow_the_same_serial_cadence_as_the_fallback() {
        let mut pipeline = QueryPipeline::new();
        pipeline.begin_scan(1_000, 240);
        for form_id in 1..=3 {
            pipeline.observe_query(request(form_id, 10_000.0));
        }
        assert!(pipeline.end_scan());

        let first = pipeline.take_next(1_000).expect("first worker job");
        assert!(pipeline.take_next(1_079).is_none());
        assert!(!pipeline.complete(first, Some(1_000.0)));

        let second = pipeline.take_next(1_080).expect("second worker job");
        assert!(pipeline.take_next(1_159).is_none());
        assert!(!pipeline.complete(second, Some(2_000.0)));

        let third = pipeline.take_next(1_160).expect("third worker job");
        assert_eq!(first.generation, second.generation);
        assert_eq!(second.generation, third.generation);
        assert_eq!([first.index, second.index, third.index], [0, 1, 2]);
        assert!(pipeline.complete(third, Some(3_000.0)));
        assert_eq!(pipeline.lookup_published(first.request.key), Some(1_000.0));
        assert_eq!(pipeline.lookup_published(second.request.key), Some(2_000.0));
        assert_eq!(pipeline.lookup_published(third.request.key), Some(3_000.0));
    }

    #[test]
    fn scan_cadence_rejects_startup_and_loading_gaps() {
        assert_eq!(normalize_scan_cadence(None), DEFAULT_SCAN_CADENCE_MS);
        assert_eq!(normalize_scan_cadence(Some(15)), DEFAULT_SCAN_CADENCE_MS);
        assert_eq!(normalize_scan_cadence(Some(250)), 250);
        assert_eq!(
            normalize_scan_cadence(Some(MAX_SCAN_CADENCE_MS + 1)),
            DEFAULT_SCAN_CADENCE_MS
        );
    }

    #[test]
    fn pathing_location_layout_matches_the_engine_contract() {
        assert_eq!(core::mem::size_of::<PathingLocation>(), 0x28);
        assert_eq!(core::mem::align_of::<PathingLocation>(), 4);
    }

    #[test]
    fn tasklet_layout_matches_the_engine_queue_contract() {
        assert_eq!(core::mem::size_of::<EngineTasklet>(), 0x18);
        assert_eq!(core::mem::align_of::<EngineTasklet>(), 4);
        assert_eq!(core::mem::offset_of!(EngineTasklet, group), 0x08);
        assert_eq!(core::mem::offset_of!(EngineTasklet, check_ready), 0x0C);
        assert_eq!(core::mem::offset_of!(EngineTasklet, claimed), 0x10);
        assert_eq!(core::mem::offset_of!(EngineTasklet, next), 0x14);
        assert_eq!(core::mem::size_of::<TaskletHandle>(), 0x08);
        assert_eq!(core::mem::offset_of!(RadioTasklet, engine), 0);
        assert_eq!(core::mem::offset_of!(RadioTasklet, batch), 0x18);
        assert_eq!(core::mem::size_of::<PreparedQuery>(), 0x70);
        assert_eq!(core::mem::size_of::<PreparedBatch>(), 0x74);
        assert_eq!(core::mem::size_of::<RadioTasklet>(), 0x8C);
    }

    #[test]
    fn radio_tasklet_group_uses_the_dispatchers_lowest_priority_bucket() {
        let mut group = [0u8; 0x3C];
        unsafe {
            set_tasklet_group_priority(group.as_mut_ptr(), TASKLET_LOWEST_QUEUE_PRIORITY);
        }
        assert_eq!(
            unsafe {
                core::ptr::read_unaligned(
                    group
                        .as_ptr()
                        .add(TASKLET_GROUP_PRIORITY_OFFSET)
                        .cast::<u32>(),
                )
            },
            0x3F
        );
    }

    #[test]
    fn radio_worker_priority_change_is_restorable() {
        let mut guard = lower_current_thread_priority_scoped(ThreadPriority::BelowNormal)
            .expect("lower current test-thread priority");
        guard
            .restore()
            .expect("restore current test-thread priority");
    }

    #[test]
    fn tasklet_callback_return_is_not_native_group_completion() {
        assert!(!tasklet_group_counts_complete(1, 0));
        assert!(tasklet_group_counts_complete(1, 1));
        assert!(!tasklet_group_counts_complete(0, 0));
    }

    #[test]
    fn tasklet_storage_is_not_embedded_in_the_eager_dll_image() {
        assert!(
            core::mem::size_of_val(&RADIO_TASKLET) <= 2 * core::mem::size_of::<usize>(),
            "tasklet state must be allocated only after DeferredInit"
        );
    }

    #[test]
    fn world_lifetime_barrier_remains_dormant_before_deferred_init() {
        assert!(!world_lifetime_barrier_ready(
            crate::events::PRE_LOAD_GAME,
            false
        ));
        assert!(world_lifetime_barrier_ready(
            crate::events::PRE_LOAD_GAME,
            true
        ));
    }

    #[test]
    fn slow_scan_reports_are_aggregated_to_one_second_windows() {
        let mut reporter = ScanReporter::default();
        let mut first = ScanStats::default();
        first.mode_queries[0] = Timing {
            calls: 2,
            total_us: 3_000,
            max_us: 2_000,
        };
        assert!(reporter.observe(100, Some((6_000, 3_000, first))).is_none());

        let mut second = ScanStats::default();
        second.mode_queries[0] = Timing {
            calls: 1,
            total_us: 2_000,
            max_us: 2_000,
        };
        assert!(
            reporter
                .observe(900, Some((7_000, 5_000, second)))
                .is_none()
        );

        let report = reporter
            .observe(1_100, None)
            .expect("one report after a complete window");
        assert_eq!(report.slow_scans, 2);
        assert_eq!(report.total_us, 13_000);
        assert_eq!(report.max_us, 7_000);
        assert_eq!(report.residual_us, 8_000);
        assert_eq!(report.stats.mode_queries[0].calls, 3);
        assert_eq!(report.stats.mode_queries[0].total_us, 5_000);
    }

    #[test]
    fn cooperative_fallback_reason_preserves_the_first_failed_guard() {
        assert_eq!(
            cooperative_fallback_reason(true, 1, 1, Some(0)),
            "capacity-exceeded"
        );
        assert_eq!(
            cooperative_fallback_reason(false, 0, 1, Some(0)),
            "radio-thread-missing"
        );
        assert_eq!(
            cooperative_fallback_reason(false, 1, 0, None),
            "frame-event-missing"
        );
        assert_eq!(
            cooperative_fallback_reason(false, 1, 2, Some(0)),
            "thread-mismatch"
        );
        assert_eq!(
            cooperative_fallback_reason(false, 1, 1, Some(FRAME_EVENT_TIMEOUT_MS + 1)),
            "frame-event-stale"
        );
        assert_eq!(
            cooperative_fallback_reason(false, 1, 1, Some(FRAME_EVENT_TIMEOUT_MS)),
            "unknown"
        );
    }
}
