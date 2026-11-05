//! Native admission for camera-scoped rectangles. Two inert pre-CRT bridges
//! always chain their captured providers. DeferredInit allocates a bounded atomic
//! lookup table and enables filtering. Only our additional planes have entries;
//! authored and legacy provider results are preserved in normal visibility.
//!
//! Main presentation follows synchronous native visibility readers. The existing
//! publication lock excludes native append writers while the table is replaced.
//! Atomic fields and a sequence check also fail closed on an overlapping read;
//! no reader dereferences a cached plane address or allocates/locks/logs.
use super::{
    data::CameraBounds,
    raw::{read_f32_at, read_u8_at},
};
use anyhow::{Result, ensure};
use core::ffi::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{callsite::Rel32CallHookContainer, transaction::ModificationTransaction},
        memory::read_bytes,
        patch::CodeSignature,
    },
};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

type AdmissionFn = unsafe extern "thiscall" fn(*mut c_void, f32, f32, f32) -> u8;
type CameraFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
const CALL: usize = 0x00B5_AD8C;
const CAMERA_CALL: usize = 0x0086_EBF5;
const CAMERA_BEFORE: &[u8] = &[0x83, 0xC4, 0x04, 0x8B, 0xC8];
const CAMERA_AFTER: &[u8] = &[0x83, 0x7D, 0xF4, 0, 0x74, 0x08];
const BEFORE: &[u8] = &[0x89, 0x50, 0x04, 0x89, 0x48, 0x08, 0x8B, 0xCE];
const AFTER: &[u8] = &[0x22, 0xD8, 0xBA, 0, 0, 0, 0];

static HOOK: Rel32CallHookContainer<AdmissionFn> = Rel32CallHookContainer::new();
static PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static CAMERA_HOOK: Rel32CallHookContainer<CameraFn> = Rel32CallHookContainer::new();
static CAMERA_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SAMPLE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SAMPLE_EPOCH: AtomicU64 = AtomicU64::new(0);
static PERSPECTIVE: AtomicBool = AtomicBool::new(false);
static SAMPLE: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static READY: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static REFRESH: AtomicBool = AtomicBool::new(false);
static EPOCH: AtomicU64 = AtomicU64::new(1);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static SLOTS: OnceLock<Box<[Slot]>> = OnceLock::new();
static REFERENCE: AtomicBool = AtomicBool::new(false);
static REFERENCE_EPOCH: AtomicU64 = AtomicU64::new(0);
static REFERENCE_MIN: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static REFERENCE_MAX: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

struct Slot {
    pointer: AtomicUsize,
    min: [AtomicU32; 3],
    max: [AtomicU32; 3],
    epoch: AtomicU64,
}
impl Slot {
    fn empty() -> Self {
        Self {
            pointer: AtomicUsize::new(0),
            min: [const { AtomicU32::new(0) }; 3],
            max: [const { AtomicU32::new(0) }; 3],
            epoch: AtomicU64::new(0),
        }
    }
}

/// Prepare the unique native thiscall(plane, cameraXYZ), AL result, RET 12.
/// Failure leaves the legacy extractor usable and this extension inactive.
pub(super) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "camera admission requires the pre-CRT barrier"
    );
    CodeSignature::new("occlusion camera arguments", CALL - BEFORE.len(), BEFORE).verify()?;
    CodeSignature::new("occlusion camera continuation", CALL + 5, AFTER).verify()?;
    CodeSignature::new(
        "occlusion camera owner",
        CAMERA_CALL - CAMERA_BEFORE.len(),
        CAMERA_BEFORE,
    )
    .verify()?;
    CodeSignature::new(
        "occlusion camera argument",
        0x0086_EBE5,
        &[0x8B, 0x55, 0xC8, 0x52],
    )
    .verify()?;
    CodeSignature::new(
        "occlusion camera update continuation",
        CAMERA_CALL + 5,
        CAMERA_AFTER,
    )
    .verify()?;
    // SAFETY: exact caller bytes and the sole callee's RET 12 establish ABI.
    unsafe { HOOK.init("occlusion_camera_admission", CALL as *mut c_void, admission) }?;
    PROVIDER.store(HOOK.original()? as *mut c_void, Ordering::Release);
    // SAFETY: the main-frame caller pushes one live NiCamera pointer and the
    // native provider is thiscall(owner, camera), void, RET 4.
    unsafe {
        CAMERA_HOOK.init(
            "occlusion_camera_capture",
            CAMERA_CALL as *mut c_void,
            capture_camera,
        )
    }?;
    CAMERA_PROVIDER.store(CAMERA_HOOK.original()? as *mut c_void, Ordering::Release);
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&HOOK)?;
    transaction.enable_callsite(&CAMERA_HOOK)?;
    transaction.commit();
    READY.store(true, Ordering::Release);
    Ok(())
}

/// Allocate metadata only at DeferredInit, then verify ownership and activate
/// without executable writes. Capacity is the existing shared native cap.
pub(super) fn publish(capacity: usize) -> Result<()> {
    ensure!(
        READY.load(Ordering::Acquire),
        "camera admission was not prepared"
    );
    for (call, bridge) in [
        (CALL, admission as *const () as usize),
        (CAMERA_CALL, capture_camera as *const () as usize),
    ] {
        let displacement = bridge.wrapping_sub(call + 5) as u32;
        let mut expected = [0xE8, 0, 0, 0, 0];
        expected[1..].copy_from_slice(&displacement.to_le_bytes());
        ensure!(
            read_bytes(call as *const c_void, 5)? == expected,
            "camera caller ownership changed at 0x{call:08X}"
        );
    }
    let _ = SLOTS.set(
        (0..capacity)
            .map(|_| Slot::empty())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    ACTIVE.store(true, Ordering::Release);
    Ok(())
}

pub(super) fn epoch() -> Option<u64> {
    ACTIVE
        .load(Ordering::Acquire)
        .then(|| EPOCH.load(Ordering::SeqCst))
}

pub(super) fn has_scoped() -> bool {
    COUNT.load(Ordering::Acquire) != 0
}

/// World callbacks only revoke Rust certificates; no native access is needed.
pub(super) fn invalidate() {
    EPOCH.fetch_add(1, Ordering::SeqCst);
    PERSPECTIVE.store(false, Ordering::Release);
    REFERENCE.store(false, Ordering::Release);
}
pub(super) fn take_refresh() -> bool {
    if REFRESH.swap(false, Ordering::AcqRel) {
        return true;
    }
    if !REFERENCE.load(Ordering::Acquire) {
        return false;
    }
    let bounds = CameraBounds {
        min: std::array::from_fn(|i| REFERENCE_MIN[i].load(Ordering::Relaxed)),
        max: std::array::from_fn(|i| REFERENCE_MAX[i].load(Ordering::Relaxed)),
        epoch: REFERENCE_EPOCH.load(Ordering::Relaxed),
    };
    camera().is_some_and(|(camera, epoch)| epoch == bounds.epoch && !bounds.contains(camera))
}
pub(super) fn request_refresh() {
    REFRESH.store(true, Ordering::Release);
}
pub(super) fn acknowledge_refresh() {
    REFRESH.store(false, Ordering::Release);
}

/// With spare capacity but no additional planes, movement by one minimum face
/// extent retries extraction. Rotation alone does not need a rebuild. This
/// prevents a permanent empty result for an earlier unproductive viewpoint.
pub(super) fn record_reference(reference: Option<([f32; 3], u64)>) {
    REFERENCE.store(false, Ordering::Release);
    let Some((camera, epoch)) = reference else {
        return;
    };
    let extent = super::runtime_generate::minimum_face_extent();
    let Some(bounds) = CameraBounds::new(camera.map(|v| v - extent), camera.map(|v| v + extent))
    else {
        return;
    };
    for i in 0..3 {
        REFERENCE_MIN[i].store(bounds.min[i], Ordering::Relaxed);
        REFERENCE_MAX[i].store(bounds.max[i], Ordering::Relaxed);
    }
    REFERENCE_EPOCH.store(epoch, Ordering::Relaxed);
    REFERENCE.store(true, Ordering::Release);
}

/// Actual camera copied at the main visibility call, even with an empty plane
/// list. Never use NiPoint3::ZERO or a player/observer approximation. No engine
/// pointer or camera lifetime is carried into owned generation.
pub(super) fn camera() -> Option<([f32; 3], u64)> {
    let epoch = epoch()?;
    let sequence = SAMPLE_SEQUENCE.load(Ordering::SeqCst);
    if sequence & 1 != 0 || SAMPLE_EPOCH.load(Ordering::Acquire) != epoch {
        return None;
    }
    let point = std::array::from_fn(|i| f32::from_bits(SAMPLE[i].load(Ordering::Relaxed)));
    (sequence == SAMPLE_SEQUENCE.load(Ordering::SeqCst) && EPOCH.load(Ordering::SeqCst) == epoch)
        .then_some((point, epoch))
}

unsafe extern "thiscall" fn capture_camera(owner: *mut c_void, camera: *mut c_void) {
    let pointer = CAMERA_PROVIDER.load(Ordering::Acquire);
    // SAFETY: both predecessors are published before either bridge is enabled.
    let provider = unsafe { FnPtr::<CameraFn>::from_address_unchecked(pointer as usize).as_fn() };
    if ACTIVE.load(Ordering::Acquire) {
        let epoch = EPOCH.load(Ordering::SeqCst);
        let previous = SAMPLE_EPOCH.load(Ordering::Relaxed);
        SAMPLE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        // B5AC90 passes camera+DC as NiFrustum; its +18 orthographic byte
        // selects a parallel projection. The additional certificate is for a
        // perspective viewpoint only. Legacy/authored planes are unaffected.
        let perspective = !camera.is_null() && unsafe { read_u8_at(camera, 0xF4) } == 0;
        PERSPECTIVE.store(perspective, Ordering::Release);
        let mut valid = perspective;
        if valid {
            for (i, slot) in SAMPLE.iter().enumerate() {
                // SAFETY: this caller owns its NiCamera through the synchronous
                // provider call. B5AC90 reads exactly these three offsets.
                let bits =
                    unsafe { read_f32_at(camera, super::contract::WORLD_TRANSLATION + i * 4) }
                        .to_bits();
                valid &= bits & 0x7f800000 != 0x7f800000;
                slot.store(bits, Ordering::Relaxed);
            }
        }
        SAMPLE_EPOCH.store(if valid { epoch } else { 0 }, Ordering::Release);
        SAMPLE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        if valid && previous != epoch {
            request_refresh();
        }
    }
    unsafe { provider(owner, camera) };
}

/// Hold across the complete native list diff/retirement under publication lock.
/// A reader that unexpectedly overlaps this main-frame mutation rejects culling.
pub(super) struct Update;
pub(super) fn update() -> Update {
    SEQUENCE.fetch_add(1, Ordering::SeqCst);
    Update
}
impl Update {
    /// Input is sorted by pointer and contains only strongly tracked objects.
    /// No native address is dereferenced. Metadata is visible before the write
    /// interval ends; old entries remain protected until their nodes are gone.
    pub(super) fn replace(&self, input: &[(usize, CameraBounds)]) {
        let Some(slots) = SLOTS.get() else {
            return;
        };
        // create_plane admits additional records only while this guard is active
        // and the selected set never exceeds the capacity allocated at publish.
        if input.len() > slots.len() {
            COUNT.store(usize::MAX, Ordering::SeqCst);
            return;
        }
        for (slot, (pointer, bounds)) in slots.iter().zip(input) {
            slot.pointer.store(*pointer, Ordering::SeqCst);
            for i in 0..3 {
                slot.min[i].store(bounds.min[i], Ordering::SeqCst);
                slot.max[i].store(bounds.max[i], Ordering::SeqCst);
            }
            slot.epoch.store(bounds.epoch, Ordering::SeqCst);
        }
        COUNT.store(input.len(), Ordering::SeqCst);
    }
}
impl Drop for Update {
    fn drop(&mut self) {
        SEQUENCE.fetch_add(1, Ordering::SeqCst);
    }
}

/// Pure admission boundary shared by the native bridge and offline regressions.
/// Preserve all provider result bits; zero is the only additional rejection.
pub(super) fn filter(result: u8, bounds: &CameraBounds, epoch: u64, camera: [f32; 3]) -> u8 {
    if bounds.epoch == epoch && bounds.contains(camera) {
        result
    } else {
        0
    }
}

unsafe extern "thiscall" fn admission(plane: *mut c_void, x: f32, y: f32, z: f32) -> u8 {
    let pointer = PROVIDER.load(Ordering::Acquire);
    // SAFETY: provider is published before any reachable bridge, including
    // rollback survivors, and has exactly the verified native ABI.
    let provider =
        unsafe { FnPtr::<AdmissionFn>::from_address_unchecked(pointer as usize).as_fn() };
    let result = unsafe { provider(plane, x, y, z) };
    if !ACTIVE.load(Ordering::Acquire) {
        return result;
    }
    let sequence = SEQUENCE.load(Ordering::SeqCst);
    if sequence & 1 != 0 {
        return 0;
    }
    let count = COUNT.load(Ordering::SeqCst);
    if count == 0 {
        return if SEQUENCE.load(Ordering::SeqCst) == sequence {
            result
        } else {
            0
        };
    }
    let Some(slots) = SLOTS.get() else {
        return 0;
    };
    if count > slots.len() {
        return 0;
    }
    let mut lo = 0;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let key = slots[mid].pointer.load(Ordering::SeqCst);
        if key < plane as usize {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut answer = result;
    if lo < count && slots[lo].pointer.load(Ordering::SeqCst) == plane as usize {
        let slot = &slots[lo];
        let bounds = CameraBounds {
            min: std::array::from_fn(|i| slot.min[i].load(Ordering::SeqCst)),
            max: std::array::from_fn(|i| slot.max[i].load(Ordering::SeqCst)),
            epoch: slot.epoch.load(Ordering::SeqCst),
        };
        // These are the NiCamera world-position arguments of this visibility
        // pass. The preceding clip test's zero-vector arguments are unused.
        answer = if PERSPECTIVE.load(Ordering::Acquire) {
            filter(result, &bounds, EPOCH.load(Ordering::SeqCst), [x, y, z])
        } else {
            0
        };
        if answer == 0 && result != 0 {
            REFRESH.store(true, Ordering::Release);
        }
    }
    if SEQUENCE.load(Ordering::SeqCst) != sequence {
        0
    } else {
        answer
    }
}
