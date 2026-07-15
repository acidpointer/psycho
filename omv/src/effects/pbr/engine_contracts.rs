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
const SLS_PIXEL_CONSTANT_FLAGS_ADDR: usize = 0x011FC0A0;
const SLS_LAST_DISPATCHED_PASS_ROW_EXCLUSIVE: u32 = 0x252;
const SLS_EYE_POSITION_FIRST_ROW: usize = 88;
const SLS_EYE_POSITION_LAST_ROW_EXCLUSIVE: usize = 561;
const SLS_FOG_FLAGS: u32 = (1 << 8) | (1 << 9);
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
const GEOMETRY_NAME_OFFSET: usize = 0x08;
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

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DrawSnapshot {
    pub(super) geometry: usize,
    pub(super) pass: usize,
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
    EYE_POSITION_CONTRACT_READY.load(Ordering::Acquire)
}

pub(super) fn eye_position_ready_for_pass(pass_index: u32) -> bool {
    if !eye_position_ready() {
        return false;
    }
    let Ok(row) = usize::try_from(pass_index) else {
        return false;
    };
    if !(SLS_EYE_POSITION_FIRST_ROW..SLS_EYE_POSITION_LAST_ROW_EXCLUSIVE).contains(&row) {
        return false;
    }

    let Some(first_row) = sls_eye_position_first_row() else {
        return false;
    };
    unsafe { first_row.add(row - SLS_EYE_POSITION_FIRST_ROW).read() & SLS_EYE_POSITION_FLAG != 0 }
}

pub(super) fn enable_fog_for_pass(pass_index: u32) -> bool {
    if !eye_position_ready() {
        return false;
    }
    let Ok(row) = usize::try_from(pass_index) else {
        return false;
    };
    if !(SLS_EYE_POSITION_FIRST_ROW..SLS_EYE_POSITION_LAST_ROW_EXCLUSIVE).contains(&row) {
        return false;
    }

    let Some(first_row) = sls_eye_position_first_row() else {
        return false;
    };
    let flags = unsafe { first_row.add(row - SLS_EYE_POSITION_FIRST_ROW) };
    unsafe { flags.write(flags.read() | SLS_FOG_FLAGS) };
    true
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

pub(super) fn pass_constant_flags(pass_index: u32) -> Option<(u32, u32)> {
    if pass_index >= SLS_LAST_DISPATCHED_PASS_ROW_EXCLUSIVE {
        return None;
    }

    let offset = usize::try_from(pass_index)
        .ok()?
        .checked_mul(size_of::<u32>())?;
    let vertex = read_u32(SLS_VERTEX_CONSTANT_FLAGS_ADDR.checked_add(offset)? as *const c_void)?;
    let pixel = read_u32(SLS_PIXEL_CONSTANT_FLAGS_ADDR.checked_add(offset)? as *const c_void)?;
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

pub(super) fn current_draw_snapshot(pass_index: u32) -> DrawSnapshot {
    let geometry = current_geometry().map_or(0, |ptr| ptr as usize);
    let pass = read_ptr(CURRENT_PASS_GLOBAL_ADDR as *const c_void).map_or(0, |ptr| ptr as usize);
    let selector = if geometry == 0 {
        0
    } else {
        read_ptr_offset(geometry as *mut c_void, CURRENT_DRAW_SELECTOR_OFFSET)
            .map_or(0, |ptr| ptr as usize)
    };
    if selector == 0 {
        return DrawSnapshot {
            geometry,
            pass,
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
        pass_index,
    );

    DrawSnapshot {
        geometry,
        pass,
        selector,
        selector_state,
        active_layer_count,
        pass_entry_list,
        scanned_entries,
        rejection,
    }
}

pub(super) fn current_object_draw_rejection(pass_index: u32) -> Option<ObjectDrawRejection> {
    let active_row = u16::try_from(pass_index).ok()?;
    if let Some(reason) = classify_active_object_pass_blocker(active_row, 0) {
        return Some(ObjectDrawRejection {
            reason,
            row: active_row,
            selector: 0,
        });
    }

    if matches!(active_row, 0x10..=0x13 | 0x62 | 0x63 | 0x93 | 0x94) {
        return current_draw_snapshot(pass_index).rejection;
    }

    None
}

pub(super) fn geometry_name(geometry: usize) -> Option<String> {
    const MAX_NAME_BYTES: usize = 96;

    let name = read_ptr_offset(geometry as *mut c_void, GEOMETRY_NAME_OFFSET)?;
    let mut bytes = Vec::with_capacity(32);
    for index in 0..MAX_NAME_BYTES {
        let byte_ptr = offset_ptr(name, index);
        let byte = read_u8(byte_ptr.cast_const())?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    if bytes.is_empty() {
        return None;
    }

    Some(String::from_utf8_lossy(&bytes).into_owned())
}

pub(super) fn shader_handle(shader: *mut c_void, stage: ShaderStage) -> Option<*mut c_void> {
    let expected_vtable = shader_vtable(stage);
    let handle_offset = shader_handle_offset(stage);
    read_shader_handle(shader, expected_vtable, handle_offset).or_else(|| {
        read_shader_handle(shader, expected_vtable, SHADER_PROGRAM_BACKUP_HANDLE_OFFSET)
    })
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
        || !EYE_POSITION_CONTRACT_READY.load(Ordering::Acquire)
    {
        enable_eye_position_for_all_sls_passes();
    }
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

fn current_geometry() -> Option<*mut c_void> {
    let draw_slot = read_ptr(CURRENT_GEOMETRY_SLOT_ADDR as *const c_void)?;
    read_ptr(draw_slot.cast_const())
}

fn scan_pass_entries_for_object_rejection(
    selector: usize,
    selector_state: u32,
    pass_entry_list: usize,
    active_layer_count: u32,
    pass_index: u32,
) -> (u32, Option<ObjectDrawRejection>) {
    let Ok(active_row) = u16::try_from(pass_index) else {
        return (0, None);
    };

    if let Some(reason) = classify_active_object_pass_blocker(active_row, selector_state) {
        return (
            0,
            Some(ObjectDrawRejection {
                reason,
                row: active_row,
                selector,
            }),
        );
    }

    if !matches!(active_row, 0x93 | 0x94) || pass_entry_list == 0 {
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
        if matches!(row, 0x1F2..=0x1F5) && layer != 0 && u32::from(layer) <= active_layer_count {
            return (
                scanned,
                Some(ObjectDrawRejection {
                    reason: ObjectDrawRejectReason::CloseTerrainMaterial,
                    row,
                    selector,
                }),
            );
        }
    }

    (scanned, None)
}

fn classify_active_object_pass_blocker(
    row: u16,
    selector_state: u32,
) -> Option<ObjectDrawRejectReason> {
    if matches!(row, 0x1F2..=0x1F5) {
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

fn read_u32(address: *const c_void) -> Option<u32> {
    if !readable_range(address, size_of::<u32>()) {
        return None;
    }
    Some(unsafe { address.cast::<u32>().read() })
}

fn read_u8(address: *const c_void) -> Option<u8> {
    if !readable_range(address, size_of::<u8>()) {
        return None;
    }
    Some(unsafe { address.cast::<u8>().read() })
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
    const MIN_USER_ADDRESS: usize = 0x1_0000;

    address as usize >= MIN_USER_ADDRESS
        && size != 0
        && validate_memory_range(address, size).is_ok()
}
