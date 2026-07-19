//! Static vertex-buffer allocation and lifetime repair.
//!
//! Terrain workers can enter NiStaticGeometryGroup concurrently. Its block
//! map, free list, chip pool, and COM lifetime have no native synchronization.
//! The engine also treats any non-null NiVBChip as allocation success even
//! when `NiVBChip + 0x08` contains no Direct3D vertex buffer.

use std::{
    ffi::c_void,
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use libpsycho::os::windows::{hook::transaction::ModificationTransaction, patch::OwnedCodePatch};
use parking_lot::ReentrantMutex;

use crate::mods::diagnostics::should_log_power_of_two;

use super::super::statics;

const STATIC_GEOMETRY_GROUP_VTABLE: usize = 0x010F_0FD4;
const GEOMETRY_GROUP_OFFSET: usize = 0x08;
const STREAM_COUNT_OFFSET: usize = 0x20;
const STREAM_CHIPS_OFFSET: usize = 0x28;
const CHIP_VERTEX_BUFFER_OFFSET: usize = 0x08;

const NULL_CHIP_GUARD_ORIGINAL: [u8; 5] = [0x8B, 0xC8, 0x8B, 0x41, 0x0C];
const CALL_MASK: [u8; 5] = [0xFF, 0x00, 0x00, 0x00, 0x00];
const VALID_CALL_0: [u8; 5] = [0xE8, 0x08, 0x17, 0x02, 0x00];
const VALID_CALL_1: [u8; 5] = [0xE8, 0xA8, 0xCE, 0x01, 0x00];
const VALID_CALL_2: [u8; 5] = [0xE8, 0x1D, 0xC5, 0x01, 0x00];
const VALID_CALL_3: [u8; 5] = [0xE8, 0xD5, 0xC3, 0x01, 0x00];
const VALID_CALL_4: [u8; 5] = [0xE8, 0xD5, 0xA1, 0x01, 0x00];
const VALID_CALL_5: [u8; 5] = [0xE8, 0xCF, 0x23, 0x01, 0x00];

static STATIC_LIFETIME_LOCK: LazyLock<ReentrantMutex<()>> =
    LazyLock::new(|| ReentrantMutex::new(()));
static INSTALLED: AtomicBool = AtomicBool::new(false);
static STREAM_TRANSACTIONS: AtomicU64 = AtomicU64::new(0);
static STATIC_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static STATIC_RETIREMENTS: AtomicU64 = AtomicU64::new(0);
static NULL_ALLOCATION_FAILURES: AtomicU64 = AtomicU64::new(0);
static INVALID_PUBLICATIONS: AtomicU64 = AtomicU64::new(0);

static NULL_CHIP_GUARD_JUMP: LazyLock<[u8; 5]> = LazyLock::new(|| {
    let displacement = (static_geometry_null_chip_guard as *const () as usize)
        .wrapping_sub(statics::STATIC_GEOMETRY_NULL_CHIP_GUARD_ADDR + 5)
        as i32;
    let mut replacement = [0u8; 5];
    replacement[0] = 0xE9;
    replacement[1..].copy_from_slice(&displacement.to_le_bytes());
    replacement
});

static NULL_CHIP_GUARD_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    OwnedCodePatch::new(
        "static_geometry_null_chip_guard",
        statics::STATIC_GEOMETRY_NULL_CHIP_GUARD_ADDR,
        &NULL_CHIP_GUARD_ORIGINAL,
        &*NULL_CHIP_GUARD_JUMP,
    )
});

static VALIDITY_PATCHES: [OwnedCodePatch; 6] = [
    OwnedCodePatch::masked(
        "geometry_all_stream_valid_0",
        statics::GEOMETRY_CHIP_VALID_CALL_ADDRS[0],
        &VALID_CALL_0,
        &CALL_MASK,
        &VALID_CALL_0,
    ),
    OwnedCodePatch::masked(
        "geometry_all_stream_valid_1",
        statics::GEOMETRY_CHIP_VALID_CALL_ADDRS[1],
        &VALID_CALL_1,
        &CALL_MASK,
        &VALID_CALL_1,
    ),
    OwnedCodePatch::masked(
        "geometry_all_stream_valid_2",
        statics::GEOMETRY_CHIP_VALID_CALL_ADDRS[2],
        &VALID_CALL_2,
        &CALL_MASK,
        &VALID_CALL_2,
    ),
    OwnedCodePatch::masked(
        "geometry_all_stream_valid_3",
        statics::GEOMETRY_CHIP_VALID_CALL_ADDRS[3],
        &VALID_CALL_3,
        &CALL_MASK,
        &VALID_CALL_3,
    ),
    OwnedCodePatch::masked(
        "geometry_all_stream_valid_4",
        statics::GEOMETRY_CHIP_VALID_CALL_ADDRS[4],
        &VALID_CALL_4,
        &CALL_MASK,
        &VALID_CALL_4,
    ),
    OwnedCodePatch::masked(
        "geometry_all_stream_valid_5",
        statics::GEOMETRY_CHIP_VALID_CALL_ADDRS[5],
        &VALID_CALL_5,
        &CALL_MASK,
        &VALID_CALL_5,
    ),
];

#[derive(Clone, Copy)]
pub(in crate::mods::engine_fixes) struct Snapshot {
    pub installed: bool,
    pub stream_transactions: u64,
    pub static_allocations: u64,
    pub static_retirements: u64,
    pub null_allocation_failures: u64,
    pub invalid_publications: u64,
}

pub(super) fn install() -> anyhow::Result<()> {
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    unsafe {
        statics::GEOMETRY_STREAM_ALLOCATE_HOOK.init(
            "geometry_stream_allocation_validation",
            statics::GEOMETRY_STREAM_ALLOCATE_ADDR as *mut c_void,
            hook_geometry_stream_allocate,
        )?;
        statics::STATIC_GEOMETRY_ALLOCATE_HOOK.init(
            "static_geometry_allocation_serialization",
            statics::STATIC_GEOMETRY_ALLOCATE_ADDR as *mut c_void,
            hook_static_geometry_allocate,
        )?;
        statics::STATIC_GEOMETRY_RETIRE_HOOK.init(
            "static_geometry_retirement_serialization",
            statics::STATIC_GEOMETRY_RETIRE_ADDR as *mut c_void,
            hook_static_geometry_retire,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::GEOMETRY_STREAM_ALLOCATE_HOOK)?;
    transaction.enable_inline(&statics::STATIC_GEOMETRY_ALLOCATE_HOOK)?;
    transaction.enable_inline(&statics::STATIC_GEOMETRY_RETIRE_HOOK)?;
    transaction.apply_patch(&NULL_CHIP_GUARD_PATCH)?;
    for patch in &VALIDITY_PATCHES {
        transaction.apply_patch(patch)?;
    }
    transaction.commit();

    INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[LOD] Static vertex-buffer lifetime serialized; null allocation unwind and 6 all-stream validity calls installed"
    );
    Ok(())
}

unsafe extern "stdcall" fn hook_geometry_stream_allocate(geometry: *mut c_void, stream: u32) -> u8 {
    let original = match statics::GEOMETRY_STREAM_ALLOCATE_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[LOD] Geometry stream allocation trampoline missing: {error:?}");
            return 0;
        }
    };

    if !is_static_geometry(geometry) {
        return unsafe { original(geometry, stream) };
    }

    let _guard = STATIC_LIFETIME_LOCK.lock();
    STREAM_TRANSACTIONS.fetch_add(1, Ordering::Relaxed);
    let allocated = unsafe { original(geometry, stream) };
    if allocated == 0 || stream_chip_is_valid(geometry, stream) {
        return allocated;
    }

    let count = INVALID_PUBLICATIONS.fetch_add(1, Ordering::Relaxed) + 1;
    unsafe { retire_static_stream(geometry, stream) };
    if should_log_power_of_two(count) {
        log::warn!(
            "[LOD] Rejected static VB chip without a Direct3D buffer geometry=0x{:08X} stream={} count={count}",
            geometry as usize,
            stream,
        );
    }
    0
}

unsafe extern "thiscall" fn hook_static_geometry_allocate(
    group: *mut c_void,
    geometry: *mut c_void,
    stream: u32,
) -> *mut c_void {
    let original = match statics::STATIC_GEOMETRY_ALLOCATE_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[LOD] Static geometry allocation trampoline missing: {error:?}");
            return ptr::null_mut();
        }
    };

    let _guard = STATIC_LIFETIME_LOCK.lock();
    STATIC_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    unsafe { original(group, geometry, stream) }
}

unsafe extern "thiscall" fn hook_static_geometry_retire(
    group: *mut c_void,
    geometry: *mut c_void,
    stream: u32,
) {
    let original = match statics::STATIC_GEOMETRY_RETIRE_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[LOD] Static geometry retirement trampoline missing: {error:?}");
            return;
        }
    };

    let _guard = STATIC_LIFETIME_LOCK.lock();
    STATIC_RETIREMENTS.fetch_add(1, Ordering::Relaxed);
    unsafe { original(group, geometry, stream) };
}

fn is_static_geometry(geometry: *mut c_void) -> bool {
    let Some(group) = read_pointer(geometry, GEOMETRY_GROUP_OFFSET) else {
        return false;
    };
    read_pointer(group, 0).is_some_and(|vtable| vtable as usize == STATIC_GEOMETRY_GROUP_VTABLE)
}

fn stream_chip_is_valid(geometry: *mut c_void, stream: u32) -> bool {
    let Some(stream_count) = read_u32(geometry, STREAM_COUNT_OFFSET) else {
        return false;
    };
    if stream >= stream_count {
        return false;
    }
    let Some(chips) = read_pointer(geometry, STREAM_CHIPS_OFFSET) else {
        return false;
    };
    let chip = unsafe { ptr::read_unaligned(chips.cast::<*mut c_void>().add(stream as usize)) };
    read_pointer(chip, CHIP_VERTEX_BUFFER_OFFSET).is_some()
}

unsafe fn retire_static_stream(geometry: *mut c_void, stream: u32) {
    let Some(group) = read_pointer(geometry, GEOMETRY_GROUP_OFFSET) else {
        return;
    };
    let Ok(original) = statics::STATIC_GEOMETRY_RETIRE_HOOK.original() else {
        return;
    };
    STATIC_RETIREMENTS.fetch_add(1, Ordering::Relaxed);
    unsafe { original(group, geometry, stream) };
}

fn read_u32(base: *mut c_void, offset: usize) -> Option<u32> {
    if base.is_null() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned(base.cast::<u8>().add(offset).cast::<u32>()) })
}

fn read_pointer(base: *mut c_void, offset: usize) -> Option<*mut c_void> {
    if base.is_null() {
        return None;
    }
    let value = unsafe { ptr::read_unaligned(base.cast::<u8>().add(offset).cast::<*mut c_void>()) };
    (!value.is_null()).then_some(value)
}

#[unsafe(naked)]
unsafe extern "C" fn static_geometry_null_chip_guard() {
    core::arch::naked_asm!(
        "test eax, eax",
        "jz 2f",
        "mov ecx, eax",
        "mov eax, [ecx + 0xc]",
        "mov edx, {resume}",
        "jmp edx",
        "2:",
        "pushad",
        "call {observe}",
        "popad",
        "pop edi",
        "pop esi",
        "pop ebp",
        "xor eax, eax",
        "pop ebx",
        "add esp, 8",
        "ret 8",
        resume = const statics::STATIC_GEOMETRY_NULL_CHIP_RESUME_ADDR,
        observe = sym observe_null_static_allocation,
    );
}

extern "C" fn observe_null_static_allocation() {
    NULL_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub(in crate::mods::engine_fixes) fn snapshot() -> Snapshot {
    Snapshot {
        installed: INSTALLED.load(Ordering::Acquire),
        stream_transactions: STREAM_TRANSACTIONS.load(Ordering::Relaxed),
        static_allocations: STATIC_ALLOCATIONS.load(Ordering::Relaxed),
        static_retirements: STATIC_RETIREMENTS.load(Ordering::Relaxed),
        null_allocation_failures: NULL_ALLOCATION_FAILURES.load(Ordering::Relaxed),
        invalid_publications: INVALID_PUBLICATIONS.load(Ordering::Relaxed),
    }
}
