//! Null Pointer Dereference Guards
//!
//! FNV has several tiny getter functions that blindly dereference their `this`
//! pointer without null checks. When other code passes a stale/freed pointer
//! (common during rapid cell transitions), these getters crash.
//!
//! We patch these getters to check if ECX (the __fastcall `this` pointer)
//! points to unmapped memory (< 0x10000 - the Windows null page guard region).
//! If so, return 0 instead of crashing.
//!
//! ## FUN_0044ddc0 - AI path node getter
//!
//! Original (17 bytes):
//!   PUSH EBP / MOV EBP,ESP / PUSH ECX / MOV [EBP-4],ECX
//!   MOV EAX,[EBP-4] / MOV EAX,[EAX+8] / MOV ESP,EBP / POP EBP / RET
//!
//! Patched (15 bytes + 2 NOP):
//!   CMP ECX, 0x10000      ; valid pointer?
//!   JB  return_zero        ; if not, return 0
//!   MOV EAX, [ECX+0x8]    ; normal path
//!   RET
//!   XOR EAX, EAX           ; return_zero: return 0
//!   RET
//!   NOP; NOP               ; padding

use std::sync::LazyLock;

use libc::c_void;
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    winapi::patch_bytes,
};

// ---------------------------------------------------------------------------
// FUN_00a6df40 - Matrix-to-quaternion decomposition (HAVOK physics)
// ---------------------------------------------------------------------------

/// FUN_00a6df40: __thiscall(this=output_quat, param_1=input_3x3_matrix)
/// Called from HAVOK ragdoll bone processing (FUN_00c79680) during NPC loading.
/// Crashes when param_1 = 0x34 (NULL bone struct + 0x34 offset) because
/// the NPC's ragdoll physics data isn't fully initialized during queue processing.
const MATRIX_DECOMP_ADDR: usize = 0x00A6DF40;

type MatrixDecompFn = unsafe extern "thiscall" fn(this: *mut c_void, matrix: *const f32);

static MATRIX_DECOMP_HOOK: LazyLock<InlineHookContainer<MatrixDecompFn>> =
    LazyLock::new(InlineHookContainer::new);

/// Guard: if the matrix pointer is in the null page, write an identity
/// quaternion (0,0,0,1) to the output and return without crashing.
///
/// # Safety
/// Called by the game engine via the inline hook trampoline.
unsafe extern "thiscall" fn hook_matrix_decomp(this: *mut c_void, matrix: *const f32) {
    if (matrix as usize) < 0x10000 {
        // Write identity quaternion to output (w=1, x=y=z=0)
        let out = this as *mut f32;
        unsafe {
            *out = 0.0;            // x or scale
            *out.add(1) = 0.0;     // y
            *out.add(2) = 0.0;     // z
            *out.add(3) = 1.0;     // w (identity)
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

/// Install null dereference guards on crash-prone getter functions.
pub fn install_null_deref_guards() -> anyhow::Result<()> {
    // FUN_0044ddc0: __fastcall getter that returns *(ECX + 8)
    // Crashes when ECX is null/stale (e.g., 0x8 from null->field propagation)
    //
    // New code:
    //   0044DDC0: 81 F9 00 00 01 00  CMP ECX, 0x10000
    //   0044DDC6: 72 04              JB +4 (-> return_zero)
    //   0044DDC8: 8B 41 08           MOV EAX, [ECX+8]
    //   0044DDCB: C3                 RET
    //   0044DDCC: 33 C0              XOR EAX, EAX
    //   0044DDCE: C3                 RET
    //   0044DDCF: 90                 NOP
    //   0044DDD0: 90                 NOP
    #[rustfmt::skip]
    let patched_getter: [u8; 17] = [
        0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, // CMP ECX, 0x10000
        0x72, 0x04,                           // JB +4 (to XOR EAX,EAX)
        0x8B, 0x41, 0x08,                     // MOV EAX, [ECX+8]
        0xC3,                                 // RET
        0x33, 0xC0,                           // XOR EAX, EAX
        0xC3,                                 // RET
        0x90, 0x90,                           // NOP padding
    ];

    unsafe {
        patch_bytes(0x0044DDC0 as *mut c_void, &patched_getter)?;
    }

    log::info!(
        "[STABILITY] Null deref guard installed at 0x0044DDC0 (AI path getter)"
    );

    // FUN_0040fe80: __thiscall bit flag checker
    // Checks bit 'param' in a bitfield at this+8.
    // Called from scene graph processing (FUN_00569140 -> FUN_004182b0 -> FUN_00410220)
    // during actor init in FUN_00970d50.
    //
    // Crash: When an actor's 3D data is not yet loaded (e.g., creature in an
    // unloaded cell), FUN_005d43c0 returns a garbage pointer (value 2).
    // This garbage becomes 'this' in FUN_0040fe80, which tries to read
    // *(byte*)(2 + (param>>3) + 8) -> access violation in the null page.
    //
    // Our sleep patches change loading timing, exposing this race condition
    // on certain mod configurations (TTW + Smashed Patch with Vault34 refs).
    //
    // Fix: Guard the function entry - if this < 0x10000, return false.
    // Original function: 87 bytes. Replacement: 49 bytes + 38 NOP padding.
    //
    // Original logic (thiscall: ECX=this, [ESP+4]=byte param):
    //   idx = param >> 3;
    //   if (idx < 0x15) return (*(byte*)(this + idx + 8) & (1 << (param & 7))) != 0;
    //   return false;
    //
    // Guarded replacement:
    //   if (this < 0x10000) return false;  // NEW: null page guard
    //   idx = param >> 3;
    //   if (idx < 0x15) return (*(byte*)(this + idx + 8) & (1 << (param & 7))) != 0;
    //   return false;
    #[rustfmt::skip]
    let patched_bitcheck: [u8; 87] = [
        // Guard: CMP ECX, 0x10000 / JB return_zero
        0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, // CMP ECX, 0x10000
        0x72, 0x24,                           // JB +36 (to return_zero at offset 44)
        // MOVZX EAX, byte ptr [ESP+4]        ; param_1
        0x0F, 0xB6, 0x44, 0x24, 0x04,
        // MOV EDX, EAX
        0x8B, 0xD0,
        // SHR EDX, 3                         ; idx = param >> 3
        0xC1, 0xEA, 0x03,
        // CMP EDX, 0x15                      ; if (idx >= 0x15)
        0x83, 0xFA, 0x15,
        // JAE return_zero
        0x73, 0x15,                           // JAE +21 (to return_zero at offset 44)
        // AND EAX, 7                         ; bit = param & 7
        0x83, 0xE0, 0x07,
        // ADD EDX, ECX                       ; addr = this + idx
        0x03, 0xD1,
        // MOVZX ECX, byte ptr [EDX+8]        ; byte_val = *(byte*)(this + idx + 8)
        0x0F, 0xB6, 0x4A, 0x08,
        // BT ECX, EAX                        ; test bit 'bit' of byte_val
        0x0F, 0xA3, 0xC1,
        // SETB AL                            ; AL = carry flag = tested bit
        0x0F, 0x92, 0xC0,
        // MOVZX EAX, AL                      ; zero-extend result
        0x0F, 0xB6, 0xC0,
        // RET 4                              ; return (thiscall, 1 stack param)
        0xC2, 0x04, 0x00,
        // return_zero: (offset 44)
        0x33, 0xC0,                           // XOR EAX, EAX
        0xC2, 0x04, 0x00,                     // RET 4
        // NOP padding (38 bytes)
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    ];

    unsafe {
        patch_bytes(0x0040FE80 as *mut c_void, &patched_bitcheck)?;
    }

    log::info!(
        "[STABILITY] Null deref guard installed at 0x0040FE80 (bit flag checker)"
    );

    // FUN_00a6df40: matrix-to-quaternion decomposition in HAVOK ragdoll processing.
    // Crashes when a ragdoll bone struct is NULL, producing param_1 = 0x34
    // (NULL + bone transform offset). Uses inline hook to check param_1
    // and return identity quaternion if invalid.
    MATRIX_DECOMP_HOOK.init(
        "matrix_decomp_guard",
        MATRIX_DECOMP_ADDR as *mut c_void,
        hook_matrix_decomp,
    )?;
    MATRIX_DECOMP_HOOK.enable()?;

    log::info!(
        "[STABILITY] Null deref guard installed at 0x00A6DF40 (HAVOK matrix decomp)"
    );

    Ok(())
}
