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
// Public API
// ---------------------------------------------------------------------------

/// Install null dereference guards on crash-prone functions.
pub fn install_null_deref_guards() -> anyhow::Result<()> {
    // FUN_0044ddc0: __fastcall getter that returns *(ECX + 8)
    // Simple byte patch - this function is unlikely to be hooked by other plugins.
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

    match unsafe { patch_bytes(0x0044DDC0 as *mut c_void, &patched_getter) } {
        Ok(_) => log::info!("[STABILITY] Guard at 0x0044DDC0 (AI path getter)"),
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

    Ok(())
}
