//! Radio-only expansion at the game's neighbor-dispatch instruction.
//!
//! Installation owns five game bytes at pre-CRT; DeferredInit only publishes a
//! verified, immutable code capability. Each scan revalidates it without heap
//! allocation. Unknown/changed providers chain the actual incoming vtable. No
//! provider DLL is modified and no engine pointer/result survives its query.
//!
//! The admitted expansion preserves candidate enumeration, native node/queue
//! ownership, geometry callbacks, scalar SSE arithmetic, and output ordering.
//! Only the proven unused policy temporary lifetime is omitted. Captured helper
//! code has the normal xNVSE plugin lifetime (load through DeInit); concurrent
//! code rewriting/unloading during a native call is not supported by the engine.
//! See docs/radio_scan_hitch_evidence.md and the provider-dispatch binary audit.

use anyhow::ensure;
use libc::c_void;
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction, patch::OwnedCodePatch, winapi::virtual_query,
};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

#[path = "provider_contract.rs"]
mod contract;

const DISPATCH: usize = 0x006F40D0;
const ORIGINAL_DISPATCH: &[u8; 5] = &[0x8B, 0x42, 0x04, 0xFF, 0xD0];
static PATCH_BYTES: OnceLock<[u8; 5]> = OnceLock::new();
static PATCH: OnceLock<OwnedCodePatch> = OnceLock::new();
static CAPABILITY: OnceLock<Bindings> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);

/// Immutable code addresses admitted from one complete provider contract.
/// No station, door, node, array, or query pointer is retained here.
#[derive(Clone, Copy)]
pub(super) struct Bindings {
    provider: usize,
    setup: usize,
    enumerate: usize,
    sqrt: usize,
    penalty: usize,
    zero: usize,
}

/// Install a dormant dispatch bridge at the core's quiescent pre-CRT boundary.
/// Failure leaves the prior game instruction, using ownership-aware rollback.
pub(super) fn install() -> anyhow::Result<()> {
    let bytes = PATCH_BYTES.get_or_init(|| {
        let mut bytes = [0xE8, 0, 0, 0, 0];
        // x86 rel32 arithmetic is modulo 2^32, including high DLL mappings.
        let displacement = (dispatch as *const () as usize).wrapping_sub(DISPATCH + 5) as u32;
        bytes[1..].copy_from_slice(&displacement.to_le_bytes());
        bytes
    });
    let patch = PATCH.get_or_init(|| {
        OwnedCodePatch::new(
            "radio_neighbor_dispatch",
            DISPATCH,
            ORIGINAL_DISPATCH,
            bytes,
        )
    });
    let mut transaction = ModificationTransaction::new();
    transaction.apply_patch(patch)?;
    transaction.commit();
    INSTALLED.store(true, Ordering::Release);
    Ok(())
}

/// Admit an optional capability once after plugin loading. No code is written.
/// A mismatch retains complete dynamic provider execution, with no result cache.
pub(super) fn publish() -> anyhow::Result<()> {
    ensure!(dispatch_owned(), "radio dispatch no longer owned");
    // SAFETY: the supported executable's query vtable is process-lifetime data.
    let target = unsafe { (super::RADIO_QUERY_VTABLE as *const usize).add(1).read() };
    if target == super::VANILLA_PROVIDER_ADDR {
        return Ok(());
    }
    let bindings = discover(target).ok_or_else(|| {
        anyhow::anyhow!("provider contract unrecognized; original expansion retained")
    })?;
    ensure!(
        CAPABILITY.set(bindings).is_ok(),
        "radio capability already published"
    );
    READY.store(true, Ordering::Release);
    log::info!("[RADIO] Verified radio expansion active at game-owned dispatch");
    Ok(())
}

/// Revalidate the published contract once per outer synchronous scan.
/// Bounded code reads/page queries allocate no buffers and retain no engine data.
pub(super) fn for_scan() -> Option<Bindings> {
    if !READY.load(Ordering::Acquire) || !dispatch_owned() {
        return None;
    }
    let bindings = *CAPABILITY.get()?;
    // SAFETY: process-lifetime native vtable; changing slots declines admission.
    let current = unsafe { (super::RADIO_QUERY_VTABLE as *const usize).add(1).read() };
    if current != bindings.provider {
        return None;
    }
    let observed = discover(current)?;
    if observed.setup != bindings.setup
        || observed.enumerate != bindings.enumerate
        || observed.sqrt != bindings.sqrt
        || observed.penalty != bindings.penalty
        || observed.zero != bindings.zero
    {
        return None;
    }
    Some(bindings)
}

fn dispatch_owned() -> bool {
    // SAFETY: fixed supported-executable dispatch instruction, mapped for life.
    INSTALLED.load(Ordering::Acquire)
        && PATCH_BYTES
            .get()
            .is_some_and(|expected| unsafe { game_bytes_equal(DISPATCH, expected) })
}

/// Compare bytes at a proven process-lifetime game code address, without I/O,
/// allocation, diagnostics, or page probes.
///
/// # Safety
/// The complete range must be mapped/readable and stable during the comparison.
pub(super) unsafe fn game_bytes_equal(address: usize, expected: &[u8]) -> bool {
    // SAFETY: callers use fixed, audited mapped game instruction ranges. Code
    // writes occur only at lifecycle boundaries, never concurrently with scans.
    unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) == expected }
}

/// Compare a game-owned rel32 call against its expected target without allocation.
///
/// # Safety
/// The complete five-byte range must be mapped/readable and stable for this call.
pub(super) unsafe fn game_call_matches(address: usize, target: usize) -> bool {
    // SAFETY: as for game_bytes_equal; all callers pass known five-byte callsites.
    unsafe {
        let instruction = address as *const u8;
        instruction.read() == 0xE8
            && address
                .wrapping_add(5)
                .wrapping_add(instruction.add(1).cast::<u32>().read_unaligned() as usize)
                == target
    }
}

// A page query proves mapping/protection, not lifetime. The latter comes from
// the installed provider and xNVSE's load-to-DeInit ownership contract.
fn mapped(address: usize, size: usize, executable: bool) -> bool {
    let Some(end) = address.checked_add(size) else {
        return false;
    };
    if address == 0 || size == 0 {
        return false;
    }
    let mut cursor = address;
    while cursor < end {
        let Ok(region) = virtual_query(cursor as *mut c_void) else {
            return false;
        };
        if !region.is_accessible() || (executable && !region.is_executable()) {
            return false;
        }
        let Some(next) = (region.base_address as usize).checked_add(region.region_size) else {
            return false;
        };
        if next <= cursor {
            return false;
        }
        cursor = next.min(end);
    }
    true
}

fn discover(provider: usize) -> Option<Bindings> {
    if !mapped(provider, contract::PROVIDER.len(), true) {
        return None;
    }
    // SAFETY: mapped range and normal installed-provider code lifetime. Only the
    // enumerated relocation/call operands are variable; all branches are exact.
    let code =
        unsafe { std::slice::from_raw_parts(provider as *const u8, contract::PROVIDER.len()) };
    const VARIABLE: [usize; 6] = [0x3A, 0x12C, 0x170, 0x185, 0x1FB, 0x20D];
    // Compare contiguous significant spans so scan admission is seven bounded
    // byte comparisons, not a mask search for every instruction byte.
    let mut first = 0;
    for operand in VARIABLE {
        if code[first..operand] != contract::PROVIDER[first..operand] {
            return None;
        }
        first = operand + 4;
    }
    if code[first..] != contract::PROVIDER[first..] {
        return None;
    }
    let word = |offset: usize| -> u32 {
        // All offsets below are fixed four-byte operands inside the proven body.
        u32::from_le_bytes([
            code[offset],
            code[offset + 1],
            code[offset + 2],
            code[offset + 3],
        ])
    };
    let relative = |offset: usize| {
        provider
            .wrapping_add(offset + 5)
            .wrapping_add(word(offset + 1) as usize)
    };
    let bindings = Bindings {
        provider,
        enumerate: relative(0x39),
        setup: relative(0x12B),
        sqrt: relative(0x1FA),
        penalty: word(0x170) as usize,
        zero: word(0x20D) as usize,
    };
    if word(0x185) as usize != bindings.penalty
        || !mapped(bindings.setup, contract::SETUP.len(), true)
        || !mapped(bindings.enumerate, 1, true)
        || !mapped(bindings.sqrt, 1, true)
        || !mapped(bindings.penalty, 4, false)
        || !mapped(bindings.zero, 4, false)
    {
        return None;
    }
    // SAFETY: each range was validated above and has the same plugin lifetime.
    unsafe {
        if std::slice::from_raw_parts(bindings.setup as *const u8, contract::SETUP.len())
            != contract::SETUP
            || (bindings.penalty as *const u32).read_unaligned() != 0x48C80000
            || (bindings.zero as *const u32).read_unaligned() != 0
        {
            return None;
        }
    }
    Some(bindings)
}

// This is the physical ABI of the replaced MOV/CALL pair, including incoming
// EDX. Fastcall also gives the native two-stack-argument RET 8 contract.
#[unsafe(naked)]
unsafe extern "fastcall" fn dispatch(
    _query: *mut u8,
    _vtable: usize,
    _node: *mut u8,
    _output: *mut u8,
) -> u8 {
    core::arch::naked_asm!(
        "cmp edx, {vtable}",
        "jne 2f",
        "cmp byte ptr [{ready}], 0",
        "je 2f",
        "push ebp",
        "mov ebp, esp",
        "and esp, -16",
        "push dword ptr [ebp + 12]",
        "push dword ptr [ebp + 8]",
        "push edx",
        "push ecx",
        "call {body}",
        "mov esp, ebp",
        "pop ebp",
        "ret 8",
        "2:",
        "mov eax, [edx + 4]",
        "jmp eax",
        vtable = const super::RADIO_QUERY_VTABLE,
        ready = sym READY,
        body = sym dispatch_body,
    );
}

unsafe extern "C" fn dispatch_body(
    query: *mut u8,
    vtable: usize,
    node: *mut u8,
    output: *mut u8,
) -> u8 {
    // SAFETY: original MOV/CALL inputs; vtable and query are alive for this call.
    let target = unsafe { (vtable as *const usize).add(1).read() };
    let context = super::RADIO_SCAN_CONTEXT.with(std::cell::Cell::get);
    if let Some(bindings) = context.provider
        && context.depth != 0
        && target == bindings.provider
        && unsafe { super::radio_query_fields_match(query) }
    {
        // SAFETY: exact live query/compiled-provider contract; no outputs yet
        // changed, and the native caller retains every object until return.
        return unsafe { expand(query, node, output, bindings) };
    }
    type Provider = unsafe extern "fastcall" fn(*mut u8, usize, *mut u8, *mut u8) -> u8;
    // SAFETY: chain the exact dynamic target with unchanged ECX/EDX/stack args.
    let original: Provider = unsafe { std::mem::transmute(target) };
    unsafe { original(query, vtable, node, output) }
}

/// Read one native field without creating an aliasing Rust reference.
/// The caller proves the object/offset readable and alive for this operation.
unsafe fn field<T: Copy>(object: *const u8, offset: usize) -> T {
    unsafe { object.add(offset).cast::<T>().read_unaligned() }
}

/// Write one native field while preserving engine ownership and native aliasing.
/// The caller proves the field writable and no conflicting engine access.
unsafe fn store<T>(object: *mut u8, offset: usize, value: T) {
    unsafe { object.add(offset).cast::<T>().write_unaligned(value) }
}

/// Expand one node under the verified provider's valid-native-object contract.
/// Query, node and output belong exclusively to the synchronous native search.
/// Door/cell/extra pointers have the same lifetime/locking preconditions as the
/// retained enumerator and original provider. No new Rust references are made;
/// required virtual calls and native container operations retain their ABIs.
unsafe fn expand(query: *mut u8, node: *mut u8, output: *mut u8, bindings: Bindings) -> u8 {
    type Enumerate = unsafe extern "fastcall" fn(*mut u8, usize, *mut u8);
    type Lookup = unsafe extern "thiscall" fn(*mut u8, u32) -> *mut u8;
    type GetCell = unsafe extern "thiscall" fn(*mut u8) -> *mut u8;
    type GetPosition = unsafe extern "thiscall" fn(*mut u8) -> *const u8;
    // Cost is passed as its exact f32 bits in a four-byte stack slot. This avoids
    // an extra x87 load/store (and possible NaN conversion) in the Rust ABI.
    type GetNode = unsafe extern "thiscall" fn(*mut u8, *mut u8, u32, *mut *mut u8) -> u32;
    type Append = unsafe extern "thiscall" fn(*mut u8, *const *mut u8) -> u32;
    // SAFETY: the caller supplies the proven native ownership/layout/ABI contract
    // above. Keep all raw object operations confined to this engine boundary.
    unsafe {
        let enumerate: Enumerate = std::mem::transmute(bindings.enumerate);
        let lookup: Lookup = std::mem::transmute(0x00410220usize);
        let get_node: GetNode = std::mem::transmute(0x006F3E30usize);
        let append: Append = std::mem::transmute(0x007CB2E0usize);
        store(query, 0x20AC, 0u32);
        if field::<u8>(node, 8) != 0 {
            let world = field::<*mut u8>(node, 0xC);
            let cell = field::<*mut u8>(world, 0x34);
            if !cell.is_null() {
                enumerate(cell, 0, query.add(0x20A4));
            }
        } else {
            enumerate(field(node, 0x10), 0, query.add(0x20A4));
        }
        let mut index = 0u32;
        while index < field::<u32>(query, 0x20AC) {
            let candidates = field::<*mut *mut u8>(query, 0x20A8);
            let door = candidates.add(index as usize).read();
            index += 1;
            if field::<u32>(door, 8) & (1 << 11) != 0 {
                continue;
            }
            let extra = lookup(door.add(0x44), 0x2B);
            let teleport = field::<*mut u8>(extra, 0xC);
            let linked = field::<*mut u8>(teleport, 0);
            let mut world = std::ptr::null_mut::<u8>();
            if !linked.is_null() {
                let mut cell = field::<*mut u8>(linked, 0x40);
                if cell.is_null() {
                    let child = linked.add(0x18);
                    let table = field::<*const u8>(child, 0);
                    let get_cell: GetCell = std::mem::transmute(field::<usize>(table, 0));
                    cell = get_cell(child);
                }
                if !cell.is_null() && field::<u8>(cell, 0x24) & 1 == 0 {
                    world = field(cell, 0xC0);
                }
            }
            let key = if !world.is_null() {
                world
            } else {
                // The child-cell virtual call above may change reference state.
                // Match the provider's post-callback reread of the linked door.
                let current_linked = field::<*mut u8>(teleport, 0);
                if current_linked.is_null() {
                    std::ptr::null_mut()
                } else {
                    field(current_linked, 0x40)
                }
            };
            match field::<u32>(query, 0x2098) {
                1 if !world.is_null() && world != field::<*mut u8>(query, 0x205C) => continue,
                2 if !world.is_null() => continue,
                _ => {}
            }
            // Discarded setup/access/free are the only omitted operations.
            // Minimum-use penalties remain effective for disposition 1.
            let base = field::<*const u8>(door, 0x20);
            let penalty = if field::<u8>(base, 0x84) & 8 != 0 && field::<u32>(query, 0x20B4) != 3 {
                0x48C80000u32
            } else {
                0u32
            };
            let table = field::<*const u8>(door, 0);
            let get_position: GetPosition = std::mem::transmute(field::<usize>(table, 0x1F4));
            let position = get_position(door);
            let source = if field::<u32>(node, 0x24) != 0 {
                node.add(0x18)
            } else {
                query.add(0x2068)
            };
            let mut cost = 0u32;
            if edge_cost(
                query,
                node,
                source,
                position,
                penalty,
                bindings.sqrt,
                &mut cost,
            ) == 0
            {
                continue;
            }
            let mut next = std::ptr::null_mut();
            match get_node(query, key, cost, &mut next) {
                0 => {
                    store(next, 8, u8::from(!world.is_null()));
                    store(next, 0xC, world);
                    store(
                        next,
                        0x10,
                        if world.is_null() {
                            key
                        } else {
                            std::ptr::null_mut::<u8>()
                        },
                    );
                    store(next, 4, 0x3F800000u32);
                }
                1 => {}
                _ => continue,
            }
            store(next, 0x14, door);
            // Copy the exact payload bits; no float arithmetic/conversions here.
            store(next, 0x18, field::<u64>(teleport, 4));
            store(next, 0x20, field::<u32>(teleport, 0xC));
            append(output, &next);
        }
    }
    1
}

/// Exact scalar SSE edge-cost and radius predicate from the admitted provider.
/// Pointers obey `expand`'s lifetime contract; the captured helper takes/returns
/// XMM0. The stack is realigned before calling it. Preserve unordered branches,
/// operation order and post-helper node/max-cost reads; output is written only
/// on the accepted branch. No Rust float ABI or optimizer changes the sequence.
#[unsafe(naked)]
unsafe extern "C" fn edge_cost(
    _query: *const u8,
    _node: *const u8,
    _source: *const u8,
    _position: *const u8,
    _penalty_bits: u32,
    _sqrt: usize,
    _output: *mut u32,
) -> u32 {
    core::arch::naked_asm!(
        "push ebp",
        "mov ebp, esp",
        "and esp, -16",
        "sub esp, 16",
        "mov dword ptr [esp], 0",
        "mov edx, [ebp + 16]",
        "mov eax, [ebp + 20]",
        "movss xmm2, [edx]",
        "movss xmm0, [edx + 4]",
        "subss xmm0, [eax + 4]",
        "subss xmm2, [eax]",
        "movss xmm1, [edx + 8]",
        "subss xmm1, [eax + 8]",
        "mulss xmm0, xmm0",
        "mulss xmm2, xmm2",
        "mulss xmm1, xmm1",
        "addss xmm0, xmm2",
        "addss xmm0, xmm1",
        "call dword ptr [ebp + 28]",
        "mov edx, [ebp + 8]",
        "movss xmm2, [edx + 0x209C]",
        "movaps xmm1, xmm0",
        "ucomiss xmm2, [esp]",
        "lahf",
        "test ah, 0x44",
        "mov eax, [ebp + 12]",
        "jnp 2f",
        "addss xmm0, [eax]",
        "comiss xmm2, xmm0",
        "jb 3f",
        "2:",
        "addss xmm1, [eax]",
        "addss xmm1, [ebp + 24]",
        "mov eax, [ebp + 32]",
        "movss [eax], xmm1",
        "mov eax, 1",
        "jmp 4f",
        "3:",
        "xor eax, eax",
        "4:",
        "mov esp, ebp",
        "pop ebp",
        "ret",
    );
}
