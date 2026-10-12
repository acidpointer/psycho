//! Combine room/shared-root membership lookup and absent-key insertion.
//!
//! Native accumulator admission already holds its +0x200 critical section.
//! For the exact pure native hash/equality providers, this replacement walks
//! the existing +0x1B4 map once, then enters the original absent-insertion tail.
//! Existing byte payloads, output writes, clear interval, node pool, callbacks,
//! head reload and count publication retain their native contracts. Unknown
//! providers or changed required code use the original lookup and insertion.
//!
//! All pointers are borrowed within one native locked operation; no cache,
//! auxiliary index, new lock, TLS, allocation or diagnostics enter the search.
//! Live integer checks compare 232 required code bytes per lookup, so the
//! removed collision work is not an unconditional net performance guarantee.
//! These checks do not synchronize concurrent executable-code writers.
//!
//! Core activation verifies the complete outer body and generic/provider
//! contracts at the quiescent pre-CRT barrier. Both logical interventions share
//! one contiguous owned write, preventing separately installed CALL/skip states.
//! Cold patch storage lives until exit; there is no event or teardown work.
//! Evidence, ABI and qualification limits are in
//! `docs/fnv_location_performance_static_audit.md`.

use core::{arch::naked_asm, ffi::c_void};
use std::sync::OnceLock;

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::{CodeSignature, OwnedCodePatch},
};

use super::lighting_contract::{branch, word};

const LOOKUP_ADDRESS: usize = 0x00B63170;
const INSERT_ADDRESS: usize = 0x00A5D320;
const HASH_ADDRESS: u32 = 0x00A63840;
const EQUALITY_ADDRESS: u32 = 0x00E92590;
const OUTER_ADDRESS: usize = 0x00B63B10;
const CALL_ADDRESS: usize = 0x00B63B35;
const OUTER: &[u8] = include_bytes!("scene_signatures/root_admission.bin");
// The CALL, unchanged MOV BL,AL and conditional-insertion window are contiguous.
// One 21-byte write owns the entire change, rather than two partial states.
const ORIGINAL_WINDOW: &[u8] = OUTER.split_at(0x25).1.split_at(21).0;
static REPLACEMENT: OnceLock<[u8; 21]> = OnceLock::new();
static PATCH: OnceLock<OwnedCodePatch> = OnceLock::new();

const LOOKUP: &[u8; 81] = include_bytes!("scene_signatures/lookup.bin");
const INSERT: &[u8; 121] = include_bytes!("scene_signatures/insert.bin");
const HASH: &[u8; 14] = include_bytes!("scene_signatures/hash.bin");
const EQUALITY: &[u8; 16] = include_bytes!("scene_signatures/equality.bin");
const CONTRACTS: [CodeSignature; 4] = [
    CodeSignature::new("Room admission lookup", LOOKUP_ADDRESS, LOOKUP),
    CodeSignature::new("Room admission insertion", INSERT_ADDRESS, INSERT),
    CodeSignature::new("Room admission hash", HASH_ADDRESS as usize, HASH),
    CodeSignature::new(
        "Room admission equality",
        EQUALITY_ADDRESS as usize,
        EQUALITY,
    ),
];

type Lookup = unsafe extern "thiscall" fn(*mut c_void, u32, *mut u8) -> u8;
type Insert = unsafe extern "thiscall" fn(*mut c_void, u32, u32);

/// Install the room-admission replacement during core pre-CRT activation.
///
/// Requires quiescent native code and unfinished core initialization. Preflights
/// the complete outer body outside the owned window and all generic/provider
/// bytes before writing. An exact existing replacement acquires no ownership.
/// Errors retain native code or trigger ownership-aware rollback; foreign
/// writes are never restored over. Successful code/storage remain until exit.
/// Does not read engine objects or introduce gameplay lifecycle work.
pub(crate) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "Room admission installation requires core activation at the pre-CRT barrier"
    );
    for contract in CONTRACTS {
        contract.verify()?;
    }
    CodeSignature::new(
        "Room admission frame",
        OUTER_ADDRESS,
        OUTER.split_at(0x25).0,
    )
    .verify()?;
    CodeSignature::new(
        "Room admission unlock/return",
        0x00B63B4A,
        OUTER.split_at(0x3A).1,
    )
    .verify()?;

    let replacement = REPLACEMENT.get_or_init(|| {
        let mut bytes = [0x90; 21];
        bytes[..5].copy_from_slice(&branch(
            0xE8,
            CALL_ADDRESS,
            find_or_insert as *const () as usize,
        ));
        // Keep the outer membership result in BL, then resume original unlock.
        bytes[5..7].copy_from_slice(&[0x8A, 0xD8]);
        bytes[7..12].copy_from_slice(&[0xE9, 0x09, 0x00, 0x00, 0x00]);
        bytes
    });
    let patch = PATCH.get_or_init(|| {
        OwnedCodePatch::new(
            "Room admission find-or-insert",
            CALL_ADDRESS,
            ORIGINAL_WINDOW,
            replacement,
        )
    });
    patch.verify()?;
    let mut transaction = ModificationTransaction::new();
    if let Err(error) = transaction.apply_patch(patch) {
        log::error!(
            "[SCENE_ROOT_ADMISSION] Admission installation failed; rolling back owned write: {error}"
        );
        return Err(error.into());
    }
    transaction.commit();
    log::debug!("[SCENE_ROOT_ADMISSION] Qualified admission window at 0x{CALL_ADDRESS:08X}");
    log::info!(
        "[SCENE_ROOT_ADMISSION] Single-search room admission installed with native fallback"
    );
    Ok(())
}

/// Execute native lookup and conditional insertion without bypassing providers.
///
/// # Safety
/// Caller owns the same locked, live map, key and output-byte storage required
/// by the original lookup. The supported FNV mapping remains loaded. The generic
/// entries are untouched by this feature, so any installed entry/body provider
/// executes with its original receiver and stack arguments. No panic or Rust
/// unwinding is introduced; native failure behavior remains native.
#[inline]
unsafe fn native_lookup_and_insert(map: *mut c_void, identity: u32, output: *mut u8) -> u8 {
    // Safety: binary proof establishes both thiscall signatures and RET 8;
    // fixed entries remain callable even when their installed bodies differ.
    let lookup: Lookup = unsafe { core::mem::transmute(LOOKUP_ADDRESS) };
    let insert: Insert = unsafe { core::mem::transmute(INSERT_ADDRESS) };
    let found = unsafe { lookup(map, identity, output) };
    if found == 0 {
        unsafe { insert(map, identity, 1) };
    }
    found
}

/// Complete membership lookup and optional insertion with the native lookup ABI.
///
/// # Safety
/// Called only from the verified `0x00B63B10` window while its accumulator lock
/// is held. Map/vtable/bucket/node storage is live, initialized and DWORD-aligned
/// under the original valid-map preconditions. Nodes have next/key/value at
/// +0/+4/+8; the payload and output are bytes. The output argument points to
/// the outer method's writable key slot after its key was saved in EBP.
/// Executable providers must not be concurrently rewritten during the call.
/// No engine reference or node pointer is retained beyond this operation.
unsafe extern "thiscall" fn find_or_insert(map: *mut c_void, identity: u32, output: *mut u8) -> u8 {
    let address = map as usize;
    // Safety: original lookup reads these same vtable slots on a valid map.
    let vtable = unsafe { word(address, 0) } as usize;
    if unsafe { word(vtable, 4) } != HASH_ADDRESS
        || unsafe { word(vtable, 8) } != EQUALITY_ADDRESS
        || !unsafe {
            native_code_matches(LOOKUP_ADDRESS, LOOKUP)
                && native_code_matches(INSERT_ADDRESS, INSERT)
                && native_code_matches(HASH_ADDRESS as usize, HASH)
                && native_code_matches(EQUALITY_ADDRESS as usize, EQUALITY)
        }
    {
        return unsafe { native_lookup_and_insert(map, identity, output) };
    }

    let count = unsafe { word(address, 4) };
    // Unsupported arithmetic retains native behavior rather than introducing
    // division or indexing panics at the FFI boundary.
    let Some(bucket) = identity.checked_rem(count) else {
        return unsafe { native_lookup_and_insert(map, identity, output) };
    };
    let Some(offset) = (bucket as usize).checked_mul(4) else {
        return unsafe { native_lookup_and_insert(map, identity, output) };
    };
    let buckets = unsafe { word(address, 8) } as usize;
    let mut node = unsafe { word(buckets, offset) } as usize;
    while node != 0 {
        if unsafe { word(node, 4) } == identity {
            // Safety: native nodes carry one byte at +8, and the original hit
            // writes exactly that byte to this live output slot, including zero.
            unsafe { output.write((node.wrapping_add(8) as *const u8).read()) };
            return 1;
        }
        node = unsafe { word(node, 0) } as usize;
    }

    // Safety: the single pure-provider search found no key under the existing
    // lock. Bucket/key/value and the adapter's frame match the native absent
    // continuation. Native callbacks, allocation and publication remain there.
    unsafe { insert_absent(map, bucket, identity, 1) };
    0
}

/// Compare one complete, fixed native provider without mutable overlay policy.
///
/// # Safety
/// Installation must have validated the entire DWORD-aligned executable range,
/// which stays mapped for process lifetime. The only production lengths are
/// 81/121/14/16 bytes, so loop arithmetic is bounded. Volatile reads observe
/// later byte changes but do not synchronize concurrent executable writes.
#[inline(always)]
unsafe fn native_code_matches<const LENGTH: usize>(
    address: usize,
    expected: &[u8; LENGTH],
) -> bool {
    // These ranges never acquire overlays or alternative bodies. Keeping their
    // checker local avoids the lighting checker's unused OnceLock/alternative
    // branches and runtime alignment/length discovery on every map lookup.
    let mut offset = 0;
    while offset + 4 <= LENGTH {
        let value = u32::from_le_bytes([
            expected[offset],
            expected[offset + 1],
            expected[offset + 2],
            expected[offset + 3],
        ]);
        if unsafe { (address.wrapping_add(offset) as *const u32).read_volatile() } != value {
            return false;
        }
        offset += 4;
    }
    while offset < LENGTH {
        if unsafe { (address.wrapping_add(offset) as *const u8).read_volatile() }
            != expected[offset]
        {
            return false;
        }
        offset += 1;
    }
    true
}

/// Enter the original absent-insertion tail with its exact saved-register frame.
///
/// # Safety
/// ECX is the locked native map, EDX its already computed valid bucket; the
/// stack supplies key and DWORD value (native stores only its low byte).
/// The complete insertion body must have passed live capability admission.
/// The tail invokes original virtual acquisition/payload callbacks, reloads
/// the bucket head, increments count, restores four registers and executes RET 8.
#[unsafe(naked)]
unsafe extern "fastcall" fn insert_absent(
    map: *mut c_void,
    bucket: u32,
    identity: u32,
    value: u32,
) {
    naked_asm!(
        "push ebx",
        "mov ebx, [esp+8]",
        "push ebp",
        "mov ebp, edx",
        "push esi",
        "mov esi, ecx",
        "push edi",
        "xor edi, edi",
        // EAX is overwritten by the tail before its first native callback.
        "mov eax, 0x00A5D358",
        "jmp eax",
    );
}
