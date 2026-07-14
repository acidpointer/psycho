//! Engine-side contracts required before visible object PBR can be enabled.
//!
//! Keep raw addresses and global engine patches here. Shader code can only be
//! stable when the engine supplies the same pass constants and shader package
//! lifetime behavior that NVR relies on.

use std::{
    ffi::c_void,
    mem::size_of,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use libpsycho::os::windows::{
    memory::{validate_memory_range, with_writable_memory},
    winapi::patch_bytes,
};

use super::shader_registry::ShaderStage;

const SLS_VERTEX_CONSTANT_FLAGS_ADDR: usize = 0x011FCC80;
const SLS_EYE_POSITION_FIRST_ROW: usize = 88;
const SLS_EYE_POSITION_LAST_ROW_EXCLUSIVE: usize = 561;
const SLS_EYE_POSITION_FLAG: u32 = 1 << 10;
const EYE_POSITION_REFRESH_INTERVAL_FRAMES: u32 = 240;

const SHADER_PACKAGE_CURRENT_ADDR: usize = 0x011F91C0;
const SHADER_PACKAGE_MAX_ADDR: usize = 0x011F91BC;
const NVR_SHADER_PACKAGE_SLS2: u32 = 7;
const SHADER_PACKAGE_LIFETIME_BRANCH_ADDR: usize = 0x00B575AA;
const SHADER_PACKAGE_LIFETIME_VANILLA_JZ: u8 = 0x74;
const SHADER_PACKAGE_LIFETIME_NVR_JNZ: u8 = 0x75;

const CURRENT_PASS_GLOBAL_ADDR: usize = 0x0126F74C;
const PASS_PIXEL_SHADER_OFFSET: usize = 0x44;
const PASS_VERTEX_SHADER_OFFSET: usize = 0x5C;
const CURRENT_GEOMETRY_SLOT_ADDR: usize = 0x011F91E0;
const CURRENT_DRAW_SELECTOR_OFFSET: usize = 0xC0;
const SELECTOR_STATE_OFFSET: usize = 0xA8;
const SELECTOR_ACTIVE_LAYER_COUNT_OFFSET: usize = 0xC8;
const SELECTOR_PASS_ENTRY_LIST_OFFSET: usize = 0x3C;
const PASS_ENTRY_POINTER_ARRAY_OFFSET: usize = 0x04;
const PASS_ENTRY_ACTIVE_COUNT_OFFSET: usize = 0x10;
const PASS_ENTRY_ROW_OFFSET: usize = 0x04;
const PASS_ENTRY_LAYER_OFFSET: usize = 0x0B;
const MAX_PASS_ENTRY_SCAN: usize = 24;
const NID3D_PIXEL_SHADER_VTABLE_ADDR: usize = 0x010EF7D4;
const NID3D_VERTEX_SHADER_VTABLE_ADDR: usize = 0x010EF87C;
const PIXEL_SHADER_NATIVE_HANDLE_OFFSET: usize = 0x2C;
const VERTEX_SHADER_NATIVE_HANDLE_OFFSET: usize = 0x34;
const SHADER_PROGRAM_BACKUP_HANDLE_OFFSET: usize = 0x1C;

static TERRAIN_CONTRACT_AVAILABLE: AtomicBool = AtomicBool::new(false);
static EYE_POSITION_CONTRACT_READY: AtomicBool = AtomicBool::new(false);
static SHADER_PACKAGE_LIFETIME_READY: AtomicBool = AtomicBool::new(false);
static EYE_POSITION_REFRESH_FRAME: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ObjectDrawRejectReason {
    CloseTerrainMaterial,
    TerrainZeroResource,
    TerrainLightResource,
    TerrainHelper,
    MissingD3DState,
    MissingShaderRecord,
    MissingTableIdentity,
    TableIdentityMismatch,
    TerrainTableSlot,
    EnvMapTableSlot,
    UnsupportedObjectPair,
    MissingReplacementResource,
    HandleStateMismatch,
    MissingSampler,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ObjectDrawRejection {
    pub(super) reason: ObjectDrawRejectReason,
    pub(super) row: u16,
    pub(super) selector: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DrawSnapshot {
    pub(super) selector: usize,
    pub(super) selector_state: u32,
    pub(super) active_layer_count: u32,
    pub(super) pass_entry_list: usize,
    pub(super) scanned_entries: u32,
    pub(super) rejection: Option<ObjectDrawRejection>,
}

pub(super) fn install_core_contracts() {
    enable_eye_position_for_all_sls_passes();
    enable_shader_package_lifetime_contract();
    force_nvr_shader_package();
}

pub(super) fn set_terrain_contract_available(available: bool) {
    TERRAIN_CONTRACT_AVAILABLE.store(available, Ordering::Release);
}

pub(super) fn terrain_contract_available() -> bool {
    TERRAIN_CONTRACT_AVAILABLE.load(Ordering::Acquire)
}

pub(super) fn shader_package_lifetime_ready() -> bool {
    SHADER_PACKAGE_LIFETIME_READY.load(Ordering::Acquire)
}

pub(super) fn eye_position_ready() -> bool {
    eye_position_contract_ready()
}

pub(super) fn service_frame() {
    force_nvr_shader_package();
    service_eye_position_contract();
    if !shader_package_lifetime_ready() {
        enable_shader_package_lifetime_contract();
    }
}

pub(super) fn current_pass_shaders() -> Option<(*mut c_void, *mut c_void)> {
    let pass = read_ptr(CURRENT_PASS_GLOBAL_ADDR as *const c_void)?;
    let pixel = read_ptr_offset(pass, PASS_PIXEL_SHADER_OFFSET)?;
    let vertex = read_ptr_offset(pass, PASS_VERTEX_SHADER_OFFSET)?;
    Some((vertex, pixel))
}

pub(super) fn current_draw_selector_address_fast() -> usize {
    // Hot SetTexture telemetry path. The global addresses are fixed engine
    // state; avoid VirtualQuery per texture bind and fall back to zero on nulls.
    const MIN_ENGINE_PTR: usize = 0x10000;

    let draw_slot = unsafe { (CURRENT_GEOMETRY_SLOT_ADDR as *const usize).read() };
    if draw_slot < MIN_ENGINE_PTR {
        return 0;
    }

    let geometry = unsafe { (draw_slot as *const usize).read() };
    if geometry < MIN_ENGINE_PTR {
        return 0;
    }

    unsafe { (geometry.wrapping_add(CURRENT_DRAW_SELECTOR_OFFSET) as *const usize).read() }
}

pub(super) fn current_draw_snapshot() -> DrawSnapshot {
    let selector = current_draw_selector().map_or(0, |ptr| ptr as usize);
    if selector == 0 {
        return DrawSnapshot {
            selector: 0,
            selector_state: 0,
            active_layer_count: 0,
            pass_entry_list: 0,
            scanned_entries: 0,
            rejection: None,
        };
    }

    let selector_ptr = selector as *mut c_void;
    let selector_state = read_u32_offset(selector_ptr, SELECTOR_STATE_OFFSET).unwrap_or(0);
    let active_layer_count =
        read_u32_offset(selector_ptr, SELECTOR_ACTIVE_LAYER_COUNT_OFFSET).unwrap_or(0);
    let pass_entry_list = read_ptr_offset(selector_ptr, SELECTOR_PASS_ENTRY_LIST_OFFSET)
        .map_or(0, |ptr| ptr as usize);
    let (scanned_entries, rejection) = scan_pass_entries_for_object_rejection(
        selector,
        selector_state,
        pass_entry_list,
        active_layer_count,
    );

    DrawSnapshot {
        selector,
        selector_state,
        active_layer_count,
        pass_entry_list,
        scanned_entries,
        rejection,
    }
}

pub(super) fn shader_handle(shader: *mut c_void, stage: ShaderStage) -> Option<*mut c_void> {
    let expected_vtable = shader_vtable(stage);
    let handle_offset = shader_handle_offset(stage);
    read_shader_handle(shader, expected_vtable, handle_offset).or_else(|| {
        read_shader_handle(shader, expected_vtable, SHADER_PROGRAM_BACKUP_HANDLE_OFFSET)
    })
}

pub(super) fn write_shader_handle(
    shader: *mut c_void,
    stage: ShaderStage,
    handle: *mut c_void,
) -> bool {
    let slot = offset_ptr(shader, shader_handle_offset(stage));
    if slot.is_null() || handle.is_null() {
        return false;
    }
    if !readable_range(slot.cast_const(), size_of::<usize>()) {
        return false;
    }

    unsafe {
        with_writable_memory(slot, size_of::<usize>(), || {
            (slot as *mut usize).write(handle as usize);
        })
        .is_ok()
    }
}

fn enable_eye_position_for_all_sls_passes() -> bool {
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

fn service_eye_position_contract() {
    let frame = EYE_POSITION_REFRESH_FRAME.fetch_add(1, Ordering::Relaxed);
    if frame == 0
        || frame % EYE_POSITION_REFRESH_INTERVAL_FRAMES == 0
        || !eye_position_contract_ready()
    {
        enable_eye_position_for_all_sls_passes();
    }
}

fn eye_position_contract_ready() -> bool {
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

fn enable_shader_package_lifetime_contract() -> bool {
    let addr = SHADER_PACKAGE_LIFETIME_BRANCH_ADDR as *mut c_void;
    if validate_memory_range(addr.cast_const(), 1).is_err() {
        SHADER_PACKAGE_LIFETIME_READY.store(false, Ordering::Release);
        return false;
    }

    let current = unsafe { (addr as *const u8).read() };
    if current == SHADER_PACKAGE_LIFETIME_NVR_JNZ {
        SHADER_PACKAGE_LIFETIME_READY.store(true, Ordering::Release);
        return true;
    }
    if current != SHADER_PACKAGE_LIFETIME_VANILLA_JZ {
        SHADER_PACKAGE_LIFETIME_READY.store(false, Ordering::Release);
        log::warn!(
            "[PBR] Shader package lifetime branch at 0x{SHADER_PACKAGE_LIFETIME_BRANCH_ADDR:08X} has unexpected opcode 0x{current:02X}"
        );
        return false;
    }

    match unsafe { patch_bytes(addr, &[SHADER_PACKAGE_LIFETIME_NVR_JNZ]) } {
        Ok(()) => {
            SHADER_PACKAGE_LIFETIME_READY.store(true, Ordering::Release);
            log::info!(
                "[PBR] Shader package lifetime branch patched at 0x{SHADER_PACKAGE_LIFETIME_BRANCH_ADDR:08X}"
            );
            true
        }
        Err(err) => {
            SHADER_PACKAGE_LIFETIME_READY.store(false, Ordering::Release);
            log::warn!("[PBR] Shader package lifetime patch failed: {err}");
            false
        }
    }
}

fn force_nvr_shader_package() {
    write_u32(SHADER_PACKAGE_CURRENT_ADDR, NVR_SHADER_PACKAGE_SLS2);
    write_u32(SHADER_PACKAGE_MAX_ADDR, NVR_SHADER_PACKAGE_SLS2);
}

fn current_draw_selector() -> Option<*mut c_void> {
    let draw_slot = read_ptr(CURRENT_GEOMETRY_SLOT_ADDR as *const c_void)?;
    let geometry = read_ptr(draw_slot.cast_const())?;
    read_ptr_offset(geometry, CURRENT_DRAW_SELECTOR_OFFSET)
}

fn scan_pass_entries_for_object_rejection(
    selector: usize,
    selector_state: u32,
    pass_entry_list: usize,
    active_layer_count: u32,
) -> (u32, Option<ObjectDrawRejection>) {
    if pass_entry_list == 0 {
        return (0, None);
    }

    let Some(entry_array) = read_ptr_offset(
        pass_entry_list as *mut c_void,
        PASS_ENTRY_POINTER_ARRAY_OFFSET,
    ) else {
        return (0, None);
    };
    let active_count = read_u32_offset(
        pass_entry_list as *mut c_void,
        PASS_ENTRY_ACTIVE_COUNT_OFFSET,
    )
    .unwrap_or(0)
    .min(MAX_PASS_ENTRY_SCAN as u32);

    let mut scanned = 0u32;
    for index in 0..active_count as usize {
        let Some(entry) = read_ptr_offset(entry_array, index * size_of::<usize>()) else {
            continue;
        };
        scanned += 1;

        let row = read_u16_offset(entry, PASS_ENTRY_ROW_OFFSET).unwrap_or(0);
        let layer = read_u8_offset(entry, PASS_ENTRY_LAYER_OFFSET).unwrap_or(0);
        if let Some(reason) =
            classify_object_draw_blocker(row, layer, selector_state, active_layer_count)
        {
            return (
                scanned,
                Some(ObjectDrawRejection {
                    reason,
                    row,
                    selector,
                }),
            );
        }
    }

    (scanned, None)
}

fn classify_object_draw_blocker(
    row: u16,
    layer: u8,
    selector_state: u32,
    active_layer_count: u32,
) -> Option<ObjectDrawRejectReason> {
    if matches!(row, 0x1F2..=0x1F5) && layer != 0 && u32::from(layer) <= active_layer_count.max(1) {
        return Some(ObjectDrawRejectReason::CloseTerrainMaterial);
    }
    if matches!(row, 0x14A..=0x152) {
        return Some(ObjectDrawRejectReason::TerrainZeroResource);
    }
    if matches!(row, 0x1F7..=0x230) {
        return Some(ObjectDrawRejectReason::TerrainLightResource);
    }
    if selector_state == 9 && matches!(row, 0x10..=0x13 | 0x62 | 0x63) {
        return Some(ObjectDrawRejectReason::TerrainHelper);
    }

    None
}

fn sls_eye_position_first_row() -> Option<*mut u32> {
    let first = SLS_VERTEX_CONSTANT_FLAGS_ADDR
        .checked_add(SLS_EYE_POSITION_FIRST_ROW.checked_mul(size_of::<u32>())?)?;
    Some(first as *mut u32)
}

fn read_shader_handle(
    shader: *mut c_void,
    expected_vtable: usize,
    handle_offset: usize,
) -> Option<*mut c_void> {
    let vtable = read_ptr(shader.cast_const())?;
    if vtable as usize != expected_vtable {
        return None;
    }

    read_ptr_offset(shader, handle_offset)
}

fn shader_vtable(stage: ShaderStage) -> usize {
    match stage {
        ShaderStage::Vertex => NID3D_VERTEX_SHADER_VTABLE_ADDR,
        ShaderStage::Pixel => NID3D_PIXEL_SHADER_VTABLE_ADDR,
    }
}

fn shader_handle_offset(stage: ShaderStage) -> usize {
    match stage {
        ShaderStage::Vertex => VERTEX_SHADER_NATIVE_HANDLE_OFFSET,
        ShaderStage::Pixel => PIXEL_SHADER_NATIVE_HANDLE_OFFSET,
    }
}

fn write_u32(address: usize, value: u32) -> bool {
    let ptr = address as *mut c_void;
    if !readable_range(ptr.cast_const(), size_of::<u32>()) {
        return false;
    }

    unsafe {
        with_writable_memory(ptr, size_of::<u32>(), || {
            (ptr as *mut u32).write(value);
        })
        .is_ok()
    }
}

fn read_ptr(address: *const c_void) -> Option<*mut c_void> {
    if !readable_range(address, size_of::<usize>()) {
        return None;
    }

    Some(unsafe { (address as *const usize).read() as *mut c_void })
}

fn read_ptr_offset(base: *mut c_void, offset: usize) -> Option<*mut c_void> {
    let ptr = offset_ptr(base, offset);
    if ptr.is_null() {
        return None;
    }
    read_ptr(ptr.cast_const())
}

fn read_u32_offset(base: *mut c_void, offset: usize) -> Option<u32> {
    let ptr = offset_ptr(base, offset);
    if ptr.is_null() || !readable_range(ptr.cast_const(), size_of::<u32>()) {
        return None;
    }

    Some(unsafe { (ptr as *const u32).read() })
}

fn read_u16_offset(base: *mut c_void, offset: usize) -> Option<u16> {
    let ptr = offset_ptr(base, offset);
    if ptr.is_null() || !readable_range(ptr.cast_const(), size_of::<u16>()) {
        return None;
    }

    Some(unsafe { (ptr as *const u16).read() })
}

fn read_u8_offset(base: *mut c_void, offset: usize) -> Option<u8> {
    let ptr = offset_ptr(base, offset);
    if ptr.is_null() || !readable_range(ptr.cast_const(), size_of::<u8>()) {
        return None;
    }

    Some(unsafe { (ptr as *const u8).read() })
}

fn offset_ptr(base: *mut c_void, offset: usize) -> *mut c_void {
    if base.is_null() {
        return std::ptr::null_mut();
    }
    (base as usize).wrapping_add(offset) as *mut c_void
}

fn readable_range(address: *const c_void, size: usize) -> bool {
    !address.is_null() && size != 0 && validate_memory_range(address, size).is_ok()
}
