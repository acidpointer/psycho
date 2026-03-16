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

use libc::c_void;
use libpsycho::os::windows::winapi::patch_bytes;

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

    Ok(())
}
