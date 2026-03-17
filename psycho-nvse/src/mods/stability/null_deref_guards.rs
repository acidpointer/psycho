//! Null Pointer Dereference Guards
//!
//! FNV has several tiny getter functions that blindly dereference their `this`
//! pointer without null checks. When other code passes a stale/freed pointer
//! (common during rapid cell transitions), these getters crash.
//!
//! We use inline hooks where possible (resilient to other plugins overwriting
//! the same function), and direct byte patches for simple cases unlikely to
//! be modified.
//!
//! ## FUN_0044ddc0 - AI path node getter (byte patch)
//! Simple *(ECX+8) getter. Patched inline with CMP ECX/JB guard.
//!
//! ## FUN_0040fe80 - Bit flag checker (inline hook)
//! Checks bit N in a bitfield at this+8. Crashes when this=2 (garbage from
//! unloaded actor 3D data). Uses inline hook because jip_nvse or other plugins
//! may overwrite raw byte patches at this address.
//!
//! ## FUN_00a6df40 - HAVOK matrix decomposition (inline hook)
//! Crashes when ragdoll bone transform pointer is in the null page.

use std::sync::LazyLock;

use libc::c_void;
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    winapi::patch_bytes,
};

// ---------------------------------------------------------------------------
// FUN_004182b0 - 3D data flag getter wrapper (inline hook)
// ---------------------------------------------------------------------------

// No Rust hooks for the 0x0040FE96 crash chain - pure assembly patches only.
// Previous Rust inline hooks at FUN_004182B0 and FUN_00569140 appeared in the
// crash stack but failed to prevent the crash, suggesting a calling convention
// issue with extern "fastcall"/"thiscall" on i686-pc-windows-gnu where ECX
// isn't properly read by the Rust hook function.

// ---------------------------------------------------------------------------
// FUN_00a6df40 - Matrix-to-quaternion decomposition (HAVOK physics)
// ---------------------------------------------------------------------------

/// FUN_00a6df40: __thiscall(this=output_quat, param_1=input_3x3_matrix)
/// Called from HAVOK ragdoll bone processing (FUN_00c79680) during NPC loading.
/// Crashes when param_1 = 0x34 (NULL bone struct + 0x34 offset).
const MATRIX_DECOMP_ADDR: usize = 0x00A6DF40;

type MatrixDecompFn = unsafe extern "thiscall" fn(this: *mut c_void, matrix: *const f32);

static MATRIX_DECOMP_HOOK: LazyLock<InlineHookContainer<MatrixDecompFn>> =
    LazyLock::new(InlineHookContainer::new);

/// # Safety
/// Called by the game engine via the inline hook trampoline.
unsafe extern "thiscall" fn hook_matrix_decomp(this: *mut c_void, matrix: *const f32) {
    if (matrix as usize) < 0x10000 {
        let out = this as *mut f32;
        unsafe {
            *out = 0.0;
            *out.add(1) = 0.0;
            *out.add(2) = 0.0;
            *out.add(3) = 1.0;
        }
        return;
    }

    match MATRIX_DECOMP_HOOK.original() {
        Ok(original) => unsafe { original(this, matrix) },
        Err(err) => {
            log::error!("Matrix decomp: failed to call original: {:?}", err);
        }
    }
}

// ---------------------------------------------------------------------------
// Null Object for safe guard returns
// ---------------------------------------------------------------------------

/// Static zeroed memory block used as a "null object" for guard returns.
/// Instead of returning 0 (which causes fall-chain crashes when callers
/// do `&null->field`), guards return a pointer to this block.
///
/// All reads from this block return 0 (fields, vtable, next pointers),
/// which safely terminates linked list walks AND prevents callers from
/// crashing when they compute offsets from the returned pointer.
///
/// Size: 1024 bytes covers any reasonable struct field access
/// (BSExtraData, TESObjectREFR, NiNode etc. are all < 1KB).
static NULL_OBJECT: [u8; 1024] = [0u8; 1024];

/// Get the address of the null object as a u32 for use in raw asm patches.
fn null_object_addr() -> u32 {
    NULL_OBJECT.as_ptr() as u32
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install null dereference guards on crash-prone functions.
pub fn install_null_deref_guards() -> anyhow::Result<()> {
    // FUN_0044ddc0: __fastcall getter that returns *(ECX + 8)
    //
    // OLD guard returned 0 → callers did &null->field → fall-chain crash.
    // NEW guard returns pointer to NULL_OBJECT (all-zeros static block).
    // - Linked list walk: [null_obj+8] = 0 → terminates loop ✓
    // - Object field access: [null_obj+N] = 0 → safe read ✓
    // - Pointer arithmetic: &null_obj->fieldC = valid_addr → no crash ✓
    let null_addr = null_object_addr();
    let b0 = (null_addr & 0xFF) as u8;
    let b1 = ((null_addr >> 8) & 0xFF) as u8;
    let b2 = ((null_addr >> 16) & 0xFF) as u8;
    let b3 = ((null_addr >> 24) & 0xFF) as u8;

    // 17 bytes exactly (matches original function size).
    // Guard path returns &NULL_OBJECT instead of 0 to prevent fall-chain.
    //
    //   CMP ECX, 0x10000           6 bytes (0-5)
    //   JNB normal                 2 bytes (6-7)  → offset 14
    //   MOV EAX, &NULL_OBJECT      5 bytes (8-12)
    //   RET                        1 byte  (13)
    //   normal: MOV EAX, [ECX+8]   3 bytes (14-16)
    //   (falls through to next byte which is the original function's
    //    MOV ESP,EBP at 0x0044DDD1 — but we have our own RET below)
    //
    // Wait - no room for RET after normal path in 17 bytes.
    // 6+2+5+1+3 = 17, no byte left for RET.
    // Solution: reuse the guard RET. JNB jumps to offset 12 (MOV EAX,[ECX+8])
    // and MOV EAX,[ECX+8] falls into the same RET at offset 15.
    //
    //   CMP ECX, 0x10000           6 bytes (0-5)
    //   JNB +4                     2 bytes (6-7)  → offset 12
    //   MOV EAX, &NULL_OBJECT      5 bytes (8-12)
    //   --- JNB lands here ---
    //   Wait, that doesn't work: JNB+4 from offset 8 = offset 12 which is
    //   the last byte of MOV EAX imm32. Wrong.
    //
    // Correct layout: normal path first, guard path second, share RET.
    //
    //   CMP ECX, 0x10000           6 bytes (0-5)
    //   JB guard                   2 bytes (6-7)  → offset 12
    //   MOV EAX, [ECX+8]           3 bytes (8-10)
    //   RET                        1 byte  (11)
    //   guard: MOV EAX, &NULL_OBJ  5 bytes (12-16)
    //   (no room for RET — BUT offset 11's RET is at a fixed address.
    //    We can JMP back to it... no, that needs more bytes.)
    //
    // The only way to fit in 17 bytes: use a code cave for the guard path.
    // Normal path stays inline (fast), guard path JMPs to cave (cold).
    //
    //   CMP ECX, 0x10000           6 bytes
    //   JB cave                    2 bytes (short jump if cave is close)
    //
    // Cave can't be a short jump (< 128 bytes) — cave is far away.
    // Need 6-byte JB (0F 82 rel32)? No, that's 6 bytes for the JB alone.
    //   6 (CMP) + 6 (JB rel32) + 3 (MOV EAX,[ECX+8]) + 1 (RET) = 16 bytes.
    //   +1 NOP = 17. This fits!

    drop(null_addr); drop(b0); drop(b1); drop(b2); drop(b3); // recalculate after cave

    // Allocate cave for guard return path
    let cave = libpsycho::os::windows::winapi::virtual_alloc_rwx(32)?;

    let cave_addr = cave as usize;
    let null_addr = null_object_addr();

    // Cave: MOV EAX, &NULL_OBJECT; RET
    let cave_bytes: [u8; 6] = [
        0xB8,
        (null_addr & 0xFF) as u8,
        ((null_addr >> 8) & 0xFF) as u8,
        ((null_addr >> 16) & 0xFF) as u8,
        ((null_addr >> 24) & 0xFF) as u8,
        0xC3,
    ];
    unsafe {
        std::ptr::copy_nonoverlapping(cave_bytes.as_ptr(), cave as *mut u8, cave_bytes.len());
    }

    // Patch: CMP + JB rel32 to cave + MOV EAX,[ECX+8] + RET + NOP
    let jb_addr: u32 = 0x0044DDC0 + 6 + 6; // after CMP(6) + JB(6)
    let jb_disp = (cave_addr as u32).wrapping_sub(jb_addr);

    #[rustfmt::skip]
    let patched_getter: [u8; 17] = [
        // CMP ECX, 0x10000                     (6 bytes, offset 0-5)
        0x81, 0xF9, 0x00, 0x00, 0x01, 0x00,
        // JB rel32 (cave)                      (6 bytes, offset 6-11)
        0x0F, 0x82,
        (jb_disp & 0xFF) as u8,
        ((jb_disp >> 8) & 0xFF) as u8,
        ((jb_disp >> 16) & 0xFF) as u8,
        ((jb_disp >> 24) & 0xFF) as u8,
        // MOV EAX, [ECX+8]                     (3 bytes, offset 12-14)
        0x8B, 0x41, 0x08,
        // RET                                  (1 byte, offset 15)
        0xC3,
        // NOP padding                          (1 byte, offset 16)
        0x90,
    ];

    match unsafe { patch_bytes(0x0044DDC0 as *mut c_void, &patched_getter) } {
        Ok(_) => log::info!(
            "[STABILITY] Guard at 0x0044DDC0 (null object at 0x{:08X})",
            null_addr
        ),
        Err(e) => log::error!("[STABILITY] FAILED 0x0044DDC0: {:?}", e),
    }

    // FUN_00569140: Pure assembly replacement (no Rust hooks).
    // Original: calls FUN_005d43c0(ECX) which returns ECX+0x44, then FUN_004182b0.
    // Guarded: compute ECX+0x44, check if result < 0x10000 (null page wrap),
    // tail-call FUN_004182b0 if valid, return 0 if not.
    // 20 bytes of code + 12 bytes INT3 padding = 32 bytes total.
    //
    //   LEA EAX, [ECX+0x44]       ; compute param_1 + 0x44
    //   CMP EAX, 0x10000          ; would it access null page?
    //   JB  return_zero           ; yes -> skip
    //   MOV ECX, EAX              ; pass result as this to FUN_004182b0
    //   JMP 0x004182B0            ; tail-call (preserves caller's return addr)
    //   return_zero:
    //   XOR EAX, EAX              ; return 0
    //   RET
    #[rustfmt::skip]
    let patched_bridge: [u8; 32] = [
        0x8D, 0x41, 0x44,                     // LEA EAX, [ECX+0x44]
        0x3D, 0x00, 0x00, 0x01, 0x00,         // CMP EAX, 0x10000
        0x72, 0x07,                            // JB +7 (to XOR EAX,EAX)
        0x8B, 0xC8,                            // MOV ECX, EAX
        0xE9, 0x5F, 0xF1, 0xEA, 0xFF,         // JMP 0x004182B0 (rel32)
        0x33, 0xC0,                            // XOR EAX, EAX
        0xC3,                                  // RET
        // INT3 padding
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    ];

    match unsafe { patch_bytes(0x00569140 as *mut c_void, &patched_bridge) } {
        Ok(_) => log::info!("[STABILITY] Guard at 0x00569140 (bridge, raw asm)"),
        Err(e) => log::error!("[STABILITY] FAILED 0x00569140: {:?}", e),
    }

    // NOTE: FUN_004182B0 is NOT guarded. It has 500+ callers across the engine
    // including rendering code. A blanket ECX < 0x10000 guard incorrectly
    // returns 0 for callers that pass small valid values (indices, enums),
    // corrupting rendering state and causing heap-address jumps.
    // The FUN_00569140 guard above handles the specific ExtraTeleport crash path.

    // FUN_00a6df40: HAVOK matrix decomposition - INLINE HOOK
    MATRIX_DECOMP_HOOK.init(
        "matrix_decomp_guard",
        MATRIX_DECOMP_ADDR as *mut c_void,
        hook_matrix_decomp,
    )?;
    MATRIX_DECOMP_HOOK.enable()?;

    log::info!("[STABILITY] Guard at 0x00A6DF40 (HAVOK matrix decomp, inline hook)");

    // FUN_00868850+0x33F: Queue vtable crash guard (code cave).
    //
    // At 0x00868B8F, the per-frame queue processor dereferences a
    // TESObjectREFR* from queue 0x11de874 and calls vtable[0x100].
    // If the ref is stale (cell unloaded), the vtable read crashes.
    //
    // Original sequence (16 bytes, 0x00868B8F-0x00868B9E):
    //   8B 45 D4        MOV EAX, [EBP-0x2C]     ; load ref
    //   8B 10           MOV EDX, [EAX]           ; vtable ptr (CRASH)
    //   8B 4D D4        MOV ECX, [EBP-0x2C]     ; this = ref
    //   8B 82 00010000  MOV EAX, [EDX+0x100]    ; vtable slot
    //   FF D0           CALL EAX                 ; call
    //
    // Fix: patch a 5-byte JMP at 0x00868B8F to a code cave that
    // validates the ref pointer before dereferencing its vtable.
    // If ref < 0x10000, skip to 0x00868BBE (past both vtable calls).
    install_queue_vtable_guard()?;
    log::info!("[STABILITY] Guard at 0x00868B8F (queue vtable, code cave)");

    Ok(())
}

/// Install a code cave guard for the queue vtable dereference at 0x00868B8F.
fn install_queue_vtable_guard() -> anyhow::Result<()> {
    use libpsycho::os::windows::winapi::{patch_bytes, virtual_alloc_rwx};

    // Allocate a code cave
    let cave = virtual_alloc_rwx(64)?;

    let cave_addr = cave as usize;

    // Code cave layout (34 bytes):
    //
    // offset  0: MOV EAX, [EBP-0x2C]     ; load ref from local
    // offset  3: CMP EAX, 0x10000        ; null page check
    // offset  8: JB skip                 ; if stale/null, skip vtable call
    // offset 10: MOV EDX, [EAX]          ; vtable ptr (safe - ref validated)
    // offset 12: MOV ECX, [EBP-0x2C]     ; this = ref for vtable call
    // offset 15: MOV EAX, [EDX+0x100]    ; vtable slot
    // offset 21: CALL EAX                ; call vtable function
    // offset 23: JMP return_normal       ; -> 0x00868B9F
    // offset 28: skip:
    //            MOV [EBP-0x2C], 0       ; zero out ref so downstream null
    //                                    ;   checks at 0x00868BCE catch it
    // offset 35: XOR EAX, EAX            ; return 0 (not an actor)
    // offset 37: JMP skip_continue       ; -> 0x00868BBE (null check catches zeroed ref)
    //
    // Why skip goes to 0x00868BBE not 0x00868B9F:
    // At 0x00868B9F, the code falls through to FUN_00564d80([EBP-0x2C]).
    // If [EBP-0x2C]=0 (our zeroed ref), that function may crash on NULL.
    // At 0x00868BBE, the code loads [EBP-0x2C] into [EBP-0x40] and does
    // CMP [EBP-0x40],0 / JZ 0x00868BE4 which safely skips everything.

    let return_addr: u32 = 0x00868B9F;
    let skip_continue: u32 = 0x00868BBE;

    #[rustfmt::skip]
    let mut cave_code: [u8; 48] = [
        // offset 0: MOV EAX, [EBP-0x2C]
        0x8B, 0x45, 0xD4,
        // offset 3: CMP EAX, 0x10000
        0x3D, 0x00, 0x00, 0x01, 0x00,
        // offset 8: JB skip (skip label at offset 28, rel = 28-10 = 18 = 0x12)
        0x72, 0x12,
        // offset 10: MOV EDX, [EAX]
        0x8B, 0x10,
        // offset 12: MOV ECX, [EBP-0x2C]
        0x8B, 0x4D, 0xD4,
        // offset 15: MOV EAX, [EDX+0x100]
        0x8B, 0x82, 0x00, 0x01, 0x00, 0x00,
        // offset 21: CALL EAX
        0xFF, 0xD0,
        // offset 23: JMP return_normal (fixup at indices 24-27)
        0xE9, 0x00, 0x00, 0x00, 0x00,
        // offset 28: skip:
        // MOV dword ptr [EBP-0x2C], 0   (C7 45 D4 00 00 00 00)
        0xC7, 0x45, 0xD4, 0x00, 0x00, 0x00, 0x00,
        // offset 35: XOR EAX, EAX
        0x33, 0xC0,
        // offset 37: JMP return_normal (fixup at indices 38-41)
        0xE9, 0x00, 0x00, 0x00, 0x00,
        // padding
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    ];

    // Fixup JMP at offset 23 -> return_addr
    let after_jmp1 = (cave_addr + 28) as u32;
    let disp1 = return_addr.wrapping_sub(after_jmp1);
    cave_code[24] = (disp1 & 0xFF) as u8;
    cave_code[25] = ((disp1 >> 8) & 0xFF) as u8;
    cave_code[26] = ((disp1 >> 16) & 0xFF) as u8;
    cave_code[27] = ((disp1 >> 24) & 0xFF) as u8;

    // Fixup JMP at offset 37 -> skip_continue (0x00868BBE)
    let after_jmp2 = (cave_addr + 42) as u32;
    let disp2 = skip_continue.wrapping_sub(after_jmp2);
    cave_code[38] = (disp2 & 0xFF) as u8;
    cave_code[39] = ((disp2 >> 8) & 0xFF) as u8;
    cave_code[40] = ((disp2 >> 16) & 0xFF) as u8;
    cave_code[41] = ((disp2 >> 24) & 0xFF) as u8;

    // Write code cave
    unsafe {
        std::ptr::copy_nonoverlapping(cave_code.as_ptr(), cave as *mut u8, cave_code.len());
    }

    // Patch JMP at 0x00868B8F (5 bytes) + NOP remaining bytes up to 0x00868B9F
    // Original: 16 bytes from 0x00868B8F to 0x00868B9E
    // Patched:  5 byte JMP + 11 byte NOP
    let patch_addr: u32 = 0x00868B8F;
    let jmp_target = cave_addr as u32;
    let jmp_disp = jmp_target.wrapping_sub(patch_addr + 5);

    #[rustfmt::skip]
    let patch: [u8; 16] = [
        0xE9,
        (jmp_disp & 0xFF) as u8,
        ((jmp_disp >> 8) & 0xFF) as u8,
        ((jmp_disp >> 16) & 0xFF) as u8,
        ((jmp_disp >> 24) & 0xFF) as u8,
        // NOP sled (11 bytes)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90,
    ];

    unsafe {
        patch_bytes(patch_addr as *mut c_void, &patch)?;
    }

    log::debug!(
        "[STABILITY] Queue vtable cave at 0x{:08X}, patch at 0x{:08X}",
        cave_addr,
        patch_addr
    );

    Ok(())
}
