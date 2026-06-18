//! Fallout NV engine-side contracts required by native PBR.
//!
//! Keep raw addresses and global engine patches here. Shader code can only be
//! stable when the engine supplies the same pass constants that NVR relies on.

use std::{
    ffi::c_void,
    mem::size_of,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use libpsycho::os::windows::memory::validate_memory_range;

const SLS_VERTEX_CONSTANT_FLAGS_ADDR: usize = 0x011FCC80;
const SLS_EYE_POSITION_FIRST_ROW: usize = 88;
const SLS_EYE_POSITION_LAST_ROW_EXCLUSIVE: usize = 561;
const SLS_EYE_POSITION_FLAG: u32 = 1 << 10;
const EYE_POSITION_REFRESH_INTERVAL_FRAMES: u32 = 240;

static EYE_POSITION_CONTRACT_READY: AtomicBool = AtomicBool::new(false);
static EYE_POSITION_REFRESH_FRAME: AtomicU32 = AtomicU32::new(0);

/// Recreates NVR's `ShadowLightShader::EnableEyePositionForAllPasses`.
///
/// OMV replacement vertex shaders read `EyePosition` from `c16`. Vanilla does
/// not guarantee that all SLS rows upload that constant, so the replacement can
/// flicker with camera movement unless this bit is forced for every row.
pub(super) fn enable_eye_position_for_all_sls_passes() -> bool {
    let Some(first_row) = sls_eye_position_first_row() else {
        EYE_POSITION_CONTRACT_READY.store(false, Ordering::Release);
        return false;
    };

    let row_count = SLS_EYE_POSITION_LAST_ROW_EXCLUSIVE - SLS_EYE_POSITION_FIRST_ROW;
    let byte_len = row_count * size_of::<u32>();
    if validate_memory_range(first_row.cast::<c_void>(), byte_len).is_err() {
        EYE_POSITION_CONTRACT_READY.store(false, Ordering::Release);
        return false;
    }

    unsafe {
        for row in 0..row_count {
            let flags = first_row.add(row);
            flags.write(flags.read() | SLS_EYE_POSITION_FLAG);
        }
    }

    EYE_POSITION_CONTRACT_READY.store(true, Ordering::Release);
    true
}

pub(super) fn service_eye_position_contract() {
    let frame = EYE_POSITION_REFRESH_FRAME.fetch_add(1, Ordering::Relaxed);
    if frame == 0
        || frame % EYE_POSITION_REFRESH_INTERVAL_FRAMES == 0
        || !eye_position_contract_ready()
    {
        enable_eye_position_for_all_sls_passes();
    }
}

pub(super) fn eye_position_contract_ready() -> bool {
    if !EYE_POSITION_CONTRACT_READY.load(Ordering::Acquire) {
        return false;
    }

    let Some(first_row) = sls_eye_position_first_row() else {
        return false;
    };
    let row_count = SLS_EYE_POSITION_LAST_ROW_EXCLUSIVE - SLS_EYE_POSITION_FIRST_ROW;
    let byte_len = row_count * size_of::<u32>();
    if validate_memory_range(first_row.cast::<c_void>(), byte_len).is_err() {
        return false;
    }

    unsafe {
        for row in 0..row_count {
            if first_row.add(row).read() & SLS_EYE_POSITION_FLAG == 0 {
                return false;
            }
        }
    }

    true
}

fn sls_eye_position_first_row() -> Option<*mut u32> {
    let first = SLS_VERTEX_CONSTANT_FLAGS_ADDR
        .checked_add(SLS_EYE_POSITION_FIRST_ROW.checked_mul(size_of::<u32>())?)?;
    Some(first as *mut u32)
}
