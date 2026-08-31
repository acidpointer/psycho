//! Allocation-failure containment at proven FalloutNV consumers.
//!
//! The game's two zero-allocation providers write through unchecked allocation
//! results. A separate `NiPixelData` constructor publishes a NULL backing
//! allocation through object fields before the affected caller invokes the
//! image converter. The replacement providers preserve successful allocation
//! behavior, while the converter boundary maps that incomplete object to the
//! caller's native false-result cleanup path.
//!
//! Installation is one transaction. Exact executable fingerprints establish
//! the native contract, pointer-slot hooks refuse foreign predecessors, and an
//! owned code patch makes partial installation rollback-safe.

use std::sync::{
    LazyLock, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use anyhow::{Context, ensure};
use libc::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        guarded_memory::{
            ThreadLocalSlot, prepare_current_process_memory_reader, read_current_process_memory,
        },
        hook::{pointer::PointerSlotHookContainer, transaction::ModificationTransaction},
        patch::OwnedCodePatch,
    },
};

use super::patching::verify_bytes;

const GAME_HEAP_ADDR: usize = 0x011F6238;
const GAME_HEAP_ALLOC_ADDR: usize = 0x00AA3E40;

const ZERO_ALLOC_SLOT_1: usize = 0x010A252C;
const ZERO_ALLOC_SLOT_2: usize = 0x010A2538;
const ZERO_ALLOC_ORIGINAL_1: usize = 0x00AA2240;
const ZERO_ALLOC_ORIGINAL_2: usize = 0x00AA2370;

const PIXEL_CONVERT_BLOCK_ADDR: usize = 0x00A7A412;
const PIXEL_CONVERT_CALL_ADDR: usize = PIXEL_CONVERT_BLOCK_ADDR + 6;
const PIXEL_DATA_BACKING_OFFSET: usize = 0x50;
const PIXEL_CONVERT_ORIGINAL: &[u8] = &[
    0x8B, 0x03, // mov eax, [ebx]
    0x8B, 0x50, 0x30, // mov edx, [eax+0x30]
    0x6A, 0xFF, // push -1
    0x56, // push esi
    0x55, // push ebp
    0x8B, 0xCB, // mov ecx, ebx
    0xFF, 0xD2, // call edx
];

const DESTINATION_ALLOC_CALL_ADDR: usize = 0x00A7A3DA;
const DESTINATION_ALLOC_CALL: &[u8] = &[0xE8, 0x01, 0x70, 0x02, 0x00];
const PIXEL_DATA_CTOR_CALL_ADDR: usize = 0x00A7A403;
const PIXEL_DATA_CTOR_CALL: &[u8] = &[0xE8, 0x88, 0x1D, 0x00, 0x00];
const PIXEL_CONVERT_RESULT_BRANCH_ADDR: usize = 0x00A7A425;
const PIXEL_CONVERT_RESULT_BRANCH: &[u8] = &[0x84, 0xC0, 0x74, 0x59];
const PIXEL_DATA_CTOR_ADDR: usize = 0x00A7C190;
const PIXEL_DATA_ALLOC_CALL_ADDR: usize = 0x00A7C331;
const PIXEL_DATA_ALLOC_CALL: &[u8] = &[0xE8, 0xDA, 0x2C, 0x01, 0x00];
const PIXEL_DATA_ALLOC_ADDR: usize = 0x00A8F010;
const PIXEL_DATA_ALLOCATION_ADDR: usize = 0x00A8F031;
const PIXEL_DATA_ALLOCATION: &[u8] = &[
    0x51, // push ecx (allocation size)
    0xE8, 0x39, 0x20, 0x01, 0x00, // call 0x00AA1070
    0x89, 0x46, 0x50, // mov [esi+0x50], eax
    0x03, 0xC7, // add eax, edi
    0x89, 0x46, 0x54, // mov [esi+0x54], eax
    0x8D, 0x04, 0x98, // lea eax, [eax+ebx*4]
    0x83, 0xC4, 0x04, // add esp, 4
    0x8D, 0x14, 0x98, // lea edx, [eax+ebx*4]
    0x5F, // pop edi
    0x89, 0x46, 0x58, // mov [esi+0x58], eax
    0x89, 0x56, 0x5C, // mov [esi+0x5c], edx
];

type GameHeapAllocFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> *mut c_void;
type ZeroAllocFn = unsafe extern "thiscall" fn(
    *mut c_void,
    *const u32,
    *const u8,
    u32,
    u32,
    u32,
    u32,
    u32,
) -> *mut c_void;
type PixelDataCtorFn =
    unsafe extern "thiscall" fn(*mut c_void, u32, u32, *mut c_void, u32, i32) -> *mut c_void;
type PixelConvertFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, i32) -> u8;

static ZERO_ALLOC_HOOK_1: PointerSlotHookContainer<ZeroAllocFn> = PointerSlotHookContainer::new();
static ZERO_ALLOC_HOOK_2: PointerSlotHookContainer<ZeroAllocFn> = PointerSlotHookContainer::new();
static PIXEL_DATA_CTOR_PATCH_REPLACEMENT: LazyLock<[u8; PIXEL_DATA_CTOR_CALL.len()]> =
    LazyLock::new(|| {
        relative_call_replacement(
            PIXEL_DATA_CTOR_CALL_ADDR,
            hook_pixel_data_ctor as *const () as usize,
        )
    });
static PIXEL_DATA_CTOR_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    OwnedCodePatch::new(
        "NiPixelData scoped constructor guard",
        PIXEL_DATA_CTOR_CALL_ADDR,
        PIXEL_DATA_CTOR_CALL,
        PIXEL_DATA_CTOR_PATCH_REPLACEMENT.as_slice(),
    )
});
static PIXEL_DATA_ALLOC_PATCH_REPLACEMENT: LazyLock<[u8; PIXEL_DATA_ALLOC_CALL.len()]> =
    LazyLock::new(|| {
        relative_call_replacement(
            PIXEL_DATA_ALLOC_CALL_ADDR,
            pixel_data_allocation_bridge as *const () as usize,
        )
    });
static PIXEL_DATA_ALLOC_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    OwnedCodePatch::new(
        "NiPixelData allocation-result bridge",
        PIXEL_DATA_ALLOC_CALL_ADDR,
        PIXEL_DATA_ALLOC_CALL,
        PIXEL_DATA_ALLOC_PATCH_REPLACEMENT.as_slice(),
    )
});
static PIXEL_CONVERT_PATCH_REPLACEMENT: LazyLock<[u8; PIXEL_CONVERT_ORIGINAL.len()]> =
    LazyLock::new(|| pixel_convert_replacement(hook_pixel_convert as *const () as usize));
static PIXEL_CONVERT_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    let replacement: &'static [u8] = PIXEL_CONVERT_PATCH_REPLACEMENT.as_slice();
    OwnedCodePatch::new(
        "NiPixelData allocation-failure guard",
        PIXEL_CONVERT_BLOCK_ADDR,
        PIXEL_CONVERT_ORIGINAL,
        replacement,
    )
});

static INSTALLED: AtomicBool = AtomicBool::new(false);
static CONSTRUCTION_SCOPE_HEALTHY: AtomicBool = AtomicBool::new(false);
static CONSTRUCTION_SCOPE_SLOT: OnceLock<ThreadLocalSlot> = OnceLock::new();
static NULL_RETURNS: AtomicU64 = AtomicU64::new(0);
static CONVERSION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static LAST_REJECTION: AtomicU64 = AtomicU64::new(0);

struct PixelConstructionScope {
    slot: ThreadLocalSlot,
    previous: *mut c_void,
}

impl PixelConstructionScope {
    fn enter(destination: *mut c_void) -> Option<Self> {
        if !CONSTRUCTION_SCOPE_HEALTHY.load(Ordering::Acquire) {
            return None;
        }
        let slot = *CONSTRUCTION_SCOPE_SLOT.get()?;
        let previous = slot.get();
        if slot.set(destination).is_err() {
            CONSTRUCTION_SCOPE_HEALTHY.store(false, Ordering::Release);
            return None;
        }
        Some(Self { slot, previous })
    }
}

impl Drop for PixelConstructionScope {
    fn drop(&mut self) {
        if self.slot.set(self.previous).is_err() {
            // A stale destination can never remain an admission capability.
            CONSTRUCTION_SCOPE_HEALTHY.store(false, Ordering::Release);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum RejectionReason {
    None = 0,
    NullDestination = 1,
    AddressOverflow = 2,
    UnreadableDestination = 3,
    MissingBackingAllocation = 4,
}

impl RejectionReason {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::NullDestination => "null destination",
            Self::AddressOverflow => "destination overflow",
            Self::UnreadableDestination => "unreadable destination",
            Self::MissingBackingAllocation => "missing backing allocation",
        }
    }

    fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::NullDestination,
            2 => Self::AddressOverflow,
            3 => Self::UnreadableDestination,
            4 => Self::MissingBackingAllocation,
            _ => Self::None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DiagnosticSnapshot {
    pub installed: bool,
    pub callsite_owned: bool,
    pub null_returns: u64,
    pub conversion_rejections: u64,
    pub last_destination: u32,
    pub last_reason: &'static str,
}

/// Install the allocation providers and their proven downstream containment.
pub fn install_allocation_failure_guards() -> anyhow::Result<()> {
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    prepare_current_process_memory_reader().context("prepare NiPixelData destination reader")?;
    verify_native_contract()?;
    prepare_zero_alloc_hook(
        &ZERO_ALLOC_HOOK_1,
        "zero-allocation provider 1",
        ZERO_ALLOC_SLOT_1,
        ZERO_ALLOC_ORIGINAL_1,
        hook_zero_alloc_1,
    )?;
    prepare_zero_alloc_hook(
        &ZERO_ALLOC_HOOK_2,
        "zero-allocation provider 2",
        ZERO_ALLOC_SLOT_2,
        ZERO_ALLOC_ORIGINAL_2,
        hook_zero_alloc_2,
    )?;
    let scope_slot = ThreadLocalSlot::allocate().context("allocate NiPixelData scope slot")?;
    CONSTRUCTION_SCOPE_SLOT
        .set(scope_slot)
        .map_err(|_| anyhow::anyhow!("NiPixelData scope slot is already initialized"))?;

    let mut transaction = ModificationTransaction::new();
    transaction.apply_patch(&PIXEL_CONVERT_PATCH)?;
    transaction.apply_patch(&PIXEL_DATA_ALLOC_PATCH)?;
    transaction.apply_patch(&PIXEL_DATA_CTOR_PATCH)?;
    transaction.enable_pointer(&ZERO_ALLOC_HOOK_1)?;
    transaction.enable_pointer(&ZERO_ALLOC_HOOK_2)?;
    transaction.commit();
    CONSTRUCTION_SCOPE_HEALTHY.store(true, Ordering::Release);
    INSTALLED.store(true, Ordering::Release);
    Ok(())
}

fn verify_native_contract() -> anyhow::Result<()> {
    unsafe {
        verify_bytes(DESTINATION_ALLOC_CALL_ADDR, DESTINATION_ALLOC_CALL)?;
        verify_bytes(
            PIXEL_CONVERT_RESULT_BRANCH_ADDR,
            PIXEL_CONVERT_RESULT_BRANCH,
        )?;
        verify_bytes(PIXEL_DATA_ALLOCATION_ADDR, PIXEL_DATA_ALLOCATION)?;
    }
    PIXEL_DATA_CTOR_PATCH.verify()?;
    PIXEL_DATA_ALLOC_PATCH.verify()?;
    PIXEL_CONVERT_PATCH.verify()?;
    Ok(())
}

fn prepare_zero_alloc_hook(
    hook: &'static PointerSlotHookContainer<ZeroAllocFn>,
    name: &'static str,
    slot: usize,
    expected: usize,
    detour: ZeroAllocFn,
) -> anyhow::Result<()> {
    if !hook.is_initialized() {
        unsafe { hook.init(name, slot as *mut *mut c_void, detour) }
            .with_context(|| format!("prepare zero-allocation slot 0x{slot:08X}"))?;
    }
    let predecessor = hook.predecessor_address()?;
    ensure!(
        predecessor == expected,
        "zero-allocation slot 0x{slot:08X} target mismatch: expected 0x{expected:08X}, found 0x{predecessor:08X}"
    );
    Ok(())
}

fn pixel_convert_replacement(target: usize) -> [u8; PIXEL_CONVERT_ORIGINAL.len()] {
    let displacement = target.wrapping_sub(PIXEL_CONVERT_CALL_ADDR + 5) as u32;
    let mut replacement = [0x90; PIXEL_CONVERT_ORIGINAL.len()];
    replacement[..7].copy_from_slice(&[0x6A, 0xFF, 0x56, 0x55, 0x8B, 0xCB, 0xE8]);
    replacement[7..11].copy_from_slice(&displacement.to_le_bytes());
    replacement
}

fn relative_call_replacement(address: usize, target: usize) -> [u8; 5] {
    let mut replacement = [0u8; 5];
    replacement[0] = 0xE8;
    replacement[1..5].copy_from_slice(&(target.wrapping_sub(address + 5) as u32).to_le_bytes());
    replacement
}

unsafe extern "thiscall" fn hook_pixel_data_ctor(
    destination: *mut c_void,
    width: u32,
    height: u32,
    pixel_format: *mut c_void,
    mip_count: u32,
    faces: i32,
) -> *mut c_void {
    let constructor =
        unsafe { FnPtr::<PixelDataCtorFn>::from_address_unchecked(PIXEL_DATA_CTOR_ADDR) };
    let Some(_scope) = PixelConstructionScope::enter(destination) else {
        // If the process-lifetime TLS capability is unavailable, preserve the
        // native call instead of rejecting an otherwise valid construction.
        return unsafe {
            constructor.as_fn()(destination, width, height, pixel_format, mip_count, faces)
        };
    };
    unsafe { constructor.as_fn()(destination, width, height, pixel_format, mip_count, faces) }
}

extern "C" fn guarded_pixel_construction_destination() -> *mut c_void {
    if !CONSTRUCTION_SCOPE_HEALTHY.load(Ordering::Acquire) {
        return std::ptr::null_mut();
    }
    CONSTRUCTION_SCOPE_SLOT
        .get()
        .map_or(std::ptr::null_mut(), |slot| slot.get())
}

#[unsafe(naked)]
unsafe extern "thiscall" fn pixel_data_allocation_bridge(
    _destination: *mut c_void,
    _mip_count: u32,
    _faces: u32,
    _payload_size: u32,
) -> *mut c_void {
    core::arch::naked_asm!(
        // Re-push the three original arguments. The repeated offset advances
        // to the preceding argument after each push.
        "push dword ptr [esp + 0x0c]",
        "push dword ptr [esp + 0x0c]",
        "push dword ptr [esp + 0x0c]",
        "mov eax, {allocation}",
        "call eax",
        "mov eax, [ebp + 0x50]",
        "test eax, eax",
        "jnz 2f",
        // The shared constructor has other native callers. Only the exact
        // caller wrapper publishes this per-thread scope, so their behavior
        // remains unchanged on allocation failure.
        "pushad",
        "call {scope_destination}",
        "cmp eax, ebp",
        "jne 1f",
        "popad",
        // Discard this bridge's return and three original arguments, then
        // execute the constructor's proven epilogue without marking the
        // incomplete object initialized.
        "add esp, 0x10",
        "pop edi",
        "pop esi",
        "mov eax, ebp",
        "pop ebp",
        "pop ebx",
        "add esp, 0xc4",
        "ret 0x14",
        "1:",
        "popad",
        "2:",
        "ret 0x0c",
        allocation = const PIXEL_DATA_ALLOC_ADDR,
        scope_destination = sym guarded_pixel_construction_destination,
    );
}

unsafe extern "thiscall" fn hook_pixel_convert(
    converter: *mut c_void,
    destination: *mut c_void,
    source: *mut c_void,
    mip_level: i32,
) -> u8 {
    if let Err(reason) = validate_pixel_destination(destination) {
        record_conversion_rejection(destination, reason);
        return 0;
    }

    // SAFETY: the exact replaced instructions load converter[0] and vtable
    // slot 0x30 immediately before this call. The guard changes only the
    // incomplete-destination result; admitted inputs dispatch the provider
    // currently installed in that same native slot with the original ABI and
    // arguments. Provider identity and all other inputs remain native policy.
    let vtable = unsafe { converter.cast::<*const c_void>().read() };
    let provider = unsafe {
        vtable
            .cast::<u8>()
            .add(0x30)
            .cast::<usize>()
            .read_unaligned()
    };
    let provider = unsafe { FnPtr::<PixelConvertFn>::from_address_unchecked(provider) };
    unsafe { provider.as_fn()(converter, destination, source, mip_level) }
}

fn validate_pixel_destination(destination: *mut c_void) -> Result<(), RejectionReason> {
    let address = destination as usize;
    if address == 0 {
        return Err(RejectionReason::NullDestination);
    }
    let backing_field = address
        .checked_add(PIXEL_DATA_BACKING_OFFSET)
        .ok_or(RejectionReason::AddressOverflow)?;
    let mut bytes = [0u8; size_of::<u32>()];
    read_current_process_memory(backing_field, &mut bytes)
        .map_err(|_| RejectionReason::UnreadableDestination)?;
    if u32::from_ne_bytes(bytes) == 0 {
        return Err(RejectionReason::MissingBackingAllocation);
    }
    Ok(())
}

fn record_conversion_rejection(destination: *mut c_void, reason: RejectionReason) {
    let destination = destination as usize as u32;
    LAST_REJECTION.store(
        (u64::from(destination) << 32) | u64::from(reason as u32),
        Ordering::Release,
    );
    let n = CONVERSION_REJECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[OOM] NiPixelData conversion rejected total={} destination=0x{:08X} reason={} result=false",
            n,
            destination,
            reason.name(),
        );
    }
}

unsafe extern "thiscall" fn hook_zero_alloc_1(
    _this: *mut c_void,
    size_ptr: *const u32,
    alignment_ptr: *const u8,
    mode: u32,
    _arg4: u32,
    _arg5: u32,
    _arg6: u32,
    _arg7: u32,
) -> *mut c_void {
    unsafe { zero_alloc(size_ptr, alignment_ptr, mode, 7) }
}

unsafe extern "thiscall" fn hook_zero_alloc_2(
    _this: *mut c_void,
    size_ptr: *const u32,
    alignment_ptr: *const u8,
    mode: u32,
    _arg4: u32,
    _arg5: u32,
    _arg6: u32,
    _arg7: u32,
) -> *mut c_void {
    unsafe { zero_alloc(size_ptr, alignment_ptr, mode, 13) }
}

unsafe fn zero_alloc(
    size_ptr: *const u32,
    alignment_ptr: *const u8,
    mode: u32,
    aligned_mode: u32,
) -> *mut c_void {
    let size = unsafe { core::ptr::read_unaligned(size_ptr) } as usize;
    let allocation = if mode == aligned_mode {
        let alignment = unsafe { core::ptr::read_unaligned(alignment_ptr) };
        let base = unsafe { game_heap_alloc(size.wrapping_add(alignment as usize)) };
        if base.is_null() {
            base
        } else {
            let marker = alignment.wrapping_sub(alignment.wrapping_sub(1) & (base as usize as u8));
            let aligned = unsafe { base.cast::<u8>().add(marker as usize) };
            unsafe { aligned.sub(1).write(marker) };
            aligned.cast()
        }
    } else {
        unsafe { game_heap_alloc(size) }
    };

    if allocation.is_null() {
        log_null_return(size, mode, aligned_mode);
        return allocation;
    }
    if size != 0 {
        unsafe { core::ptr::write_bytes(allocation.cast::<u8>(), 0, size) };
    }
    allocation
}

unsafe fn game_heap_alloc(size: usize) -> *mut c_void {
    let alloc = unsafe { FnPtr::<GameHeapAllocFn>::from_address_unchecked(GAME_HEAP_ALLOC_ADDR) };
    unsafe { alloc.as_fn()(GAME_HEAP_ADDR as *mut c_void, size) }
}

fn log_null_return(size: usize, mode: u32, aligned_mode: u32) {
    let n = NULL_RETURNS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[OOM] zero-allocation consumer returned NULL total={} size={} mode={} aligned_mode={}",
            n,
            size,
            mode,
            aligned_mode,
        );
    }
}

pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    let callsite_owned = patch_is_owned(
        PIXEL_DATA_CTOR_CALL_ADDR,
        PIXEL_DATA_CTOR_PATCH_REPLACEMENT.as_slice(),
    ) && patch_is_owned(
        PIXEL_DATA_ALLOC_CALL_ADDR,
        PIXEL_DATA_ALLOC_PATCH_REPLACEMENT.as_slice(),
    ) && patch_is_owned(
        PIXEL_CONVERT_BLOCK_ADDR,
        PIXEL_CONVERT_PATCH_REPLACEMENT.as_slice(),
    );
    let last = LAST_REJECTION.load(Ordering::Acquire);
    let reason = RejectionReason::from_raw(last as u32);
    DiagnosticSnapshot {
        installed: INSTALLED.load(Ordering::Acquire),
        callsite_owned,
        null_returns: NULL_RETURNS.load(Ordering::Relaxed),
        conversion_rejections: CONVERSION_REJECTIONS.load(Ordering::Relaxed),
        last_destination: (last >> 32) as u32,
        last_reason: reason.name(),
    }
}

fn patch_is_owned(address: usize, expected: &[u8]) -> bool {
    let mut observed = vec![0u8; expected.len()];
    read_current_process_memory(address, &mut observed).is_ok_and(|()| observed == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_admission_requires_only_a_readable_nonnull_backing_field() {
        prepare_current_process_memory_reader().unwrap();
        assert_eq!(
            validate_pixel_destination(std::ptr::null_mut()),
            Err(RejectionReason::NullDestination),
        );
        assert_eq!(
            validate_pixel_destination((usize::MAX - PIXEL_DATA_BACKING_OFFSET + 1) as *mut c_void),
            Err(RejectionReason::AddressOverflow),
        );

        let mut destination = [0u32; 0x74 / size_of::<u32>()];
        assert_eq!(
            validate_pixel_destination(destination.as_mut_ptr().cast()),
            Err(RejectionReason::MissingBackingAllocation),
        );
        let mut backing = 0u8;
        destination[PIXEL_DATA_BACKING_OFFSET / size_of::<u32>()] =
            (&mut backing as *mut u8) as usize as u32;
        assert_eq!(
            validate_pixel_destination(destination.as_mut_ptr().cast()),
            Ok(()),
        );
    }

    #[test]
    fn construction_scope_is_thread_local_and_restores_nested_destinations() {
        let slot = ThreadLocalSlot::allocate().unwrap();
        CONSTRUCTION_SCOPE_SLOT.set(slot).unwrap();
        CONSTRUCTION_SCOPE_HEALTHY.store(true, Ordering::Release);
        let mut outer_destination = 0u8;
        let mut inner_destination = 0u8;

        let outer = PixelConstructionScope::enter((&mut outer_destination as *mut u8).cast())
            .expect("enter outer construction scope");
        assert_eq!(
            guarded_pixel_construction_destination(),
            (&mut outer_destination as *mut u8).cast(),
        );
        {
            let _inner = PixelConstructionScope::enter((&mut inner_destination as *mut u8).cast())
                .expect("enter inner construction scope");
            assert_eq!(
                guarded_pixel_construction_destination(),
                (&mut inner_destination as *mut u8).cast(),
            );
        }
        assert_eq!(
            guarded_pixel_construction_destination(),
            (&mut outer_destination as *mut u8).cast(),
        );
        assert_eq!(
            std::thread::spawn(|| guarded_pixel_construction_destination() as usize)
                .join()
                .unwrap(),
            0,
        );

        drop(outer);
        assert!(guarded_pixel_construction_destination().is_null());
    }
}
