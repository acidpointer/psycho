//! Side-table shader records.
//!
//! NVR stores extra shader records inside extended native shader objects. OMV
//! keeps wrapper metadata in a fixed side table keyed by the native wrapper
//! pointer, avoiding native allocation-size patches.

use std::{
    array,
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use super::{engine_contracts, shader_registry::ShaderStage};

const RECORD_COUNT: usize = 512;
const PROBE_COUNT: usize = 8;
const STAGE_NONE: u32 = 0;
const STAGE_VERTEX: u32 = 1;
const STAGE_PIXEL: u32 = 2;
const TEMPLATE_NONE: u32 = u32::MAX;
pub(super) const TABLE_UNKNOWN: u32 = 0;

static TABLE: LazyLock<ShaderRecordTable> = LazyLock::new(ShaderRecordTable::new);
static IDENTITY_READY: AtomicBool = AtomicBool::new(false);
static CAPTURED_RECORDS: AtomicU32 = AtomicU32::new(0);
static ADOPTED_RECORDS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug)]
pub(super) struct ShaderRecordSnapshot {
    pub(super) shader: *mut c_void,
    pub(super) stage: ShaderStage,
    pub(super) original_handle: *mut c_void,
    pub(super) current_handle: *mut c_void,
    pub(super) template_id: u16,
    pub(super) table_id: u32,
    pub(super) table_index: u32,
}

struct ShaderRecordTable {
    records: [ShaderRecord; RECORD_COUNT],
}

struct ShaderRecord {
    shader: AtomicUsize,
    stage: AtomicU32,
    original_handle: AtomicUsize,
    current_handle: AtomicUsize,
    template_id: AtomicU32,
    table_id: AtomicU32,
    table_index: AtomicU32,
}

impl ShaderRecordTable {
    fn new() -> Self {
        Self {
            records: array::from_fn(|_| ShaderRecord::new()),
        }
    }

    fn clear(&self) {
        for record in &self.records {
            record.shader.store(0, Ordering::Release);
            record.stage.store(STAGE_NONE, Ordering::Release);
            record.original_handle.store(0, Ordering::Release);
            record.current_handle.store(0, Ordering::Release);
            record.template_id.store(TEMPLATE_NONE, Ordering::Release);
            record.table_id.store(TABLE_UNKNOWN, Ordering::Release);
            record.table_index.store(u32::MAX, Ordering::Release);
        }
    }

    fn find(&self, shader: *mut c_void) -> Option<ShaderRecordSnapshot> {
        let key = shader as usize;
        if key == 0 {
            return None;
        }

        let index = self.find_index(key)?;
        self.records[index].snapshot()
    }

    fn store(
        &self,
        shader: *mut c_void,
        stage: ShaderStage,
        original_handle: *mut c_void,
        template_id: u16,
        table_id: u32,
        table_index: u32,
        adopted: bool,
    ) -> Option<ShaderRecordSnapshot> {
        let key = shader as usize;
        let original_handle = original_handle as usize;
        if key == 0 || original_handle == 0 {
            return None;
        }

        let index = self
            .find_index(key)
            .unwrap_or_else(|| self.write_index(key));
        let record = &self.records[index];
        record.shader.store(0, Ordering::Release);
        record.stage.store(stage_to_u32(stage), Ordering::Release);
        record
            .original_handle
            .store(original_handle, Ordering::Release);
        record
            .current_handle
            .store(original_handle, Ordering::Release);
        record
            .template_id
            .store(template_id as u32, Ordering::Release);
        record.table_id.store(table_id, Ordering::Release);
        record.table_index.store(table_index, Ordering::Release);
        record.shader.store(key, Ordering::Release);

        IDENTITY_READY.store(true, Ordering::Release);
        CAPTURED_RECORDS.fetch_add(1, Ordering::Relaxed);
        if adopted {
            ADOPTED_RECORDS.fetch_add(1, Ordering::Relaxed);
        }

        record.snapshot()
    }

    fn set_current(&self, shader: *mut c_void, handle: *mut c_void) {
        let key = shader as usize;
        if key == 0 {
            return;
        }
        let Some(index) = self.find_index(key) else {
            return;
        };

        self.records[index]
            .current_handle
            .store(handle as usize, Ordering::Release);
    }

    fn set_table_slot(&self, shader: *mut c_void, table_id: u32, table_index: u32) {
        let key = shader as usize;
        if key == 0 || table_id == TABLE_UNKNOWN {
            return;
        }
        let Some(index) = self.find_index(key) else {
            return;
        };

        self.records[index]
            .table_id
            .store(table_id, Ordering::Release);
        self.records[index]
            .table_index
            .store(table_index, Ordering::Release);
    }

    fn active_record_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.snapshot().is_some())
            .count()
    }

    fn recorded_template_count(&self) -> usize {
        let mut seen = [false; RECORD_COUNT];
        for record in &self.records {
            let Some(snapshot) = record.snapshot() else {
                continue;
            };
            let index = snapshot.template_id as usize;
            if index < seen.len() {
                seen[index] = true;
            }
        }

        seen.into_iter().filter(|value| *value).count()
    }

    fn find_index(&self, shader: usize) -> Option<usize> {
        let base = hash_slot(shader);
        for offset in 0..PROBE_COUNT {
            let index = (base + offset) % RECORD_COUNT;
            if self.records[index].shader.load(Ordering::Acquire) == shader {
                return Some(index);
            }
        }
        None
    }

    fn write_index(&self, shader: usize) -> usize {
        let base = hash_slot(shader);
        for offset in 0..PROBE_COUNT {
            let index = (base + offset) % RECORD_COUNT;
            if self.records[index].shader.load(Ordering::Acquire) == 0 {
                return index;
            }
        }
        base
    }
}

impl ShaderRecord {
    fn new() -> Self {
        Self {
            shader: AtomicUsize::new(0),
            stage: AtomicU32::new(STAGE_NONE),
            original_handle: AtomicUsize::new(0),
            current_handle: AtomicUsize::new(0),
            template_id: AtomicU32::new(TEMPLATE_NONE),
            table_id: AtomicU32::new(TABLE_UNKNOWN),
            table_index: AtomicU32::new(u32::MAX),
        }
    }

    fn snapshot(&self) -> Option<ShaderRecordSnapshot> {
        let stage = match self.stage.load(Ordering::Acquire) {
            STAGE_VERTEX => ShaderStage::Vertex,
            STAGE_PIXEL => ShaderStage::Pixel,
            _ => return None,
        };
        let template_id = self.template_id.load(Ordering::Acquire);
        if template_id == TEMPLATE_NONE {
            return None;
        }

        Some(ShaderRecordSnapshot {
            shader: self.shader.load(Ordering::Acquire) as *mut c_void,
            stage,
            original_handle: self.original_handle.load(Ordering::Acquire) as *mut c_void,
            current_handle: self.current_handle.load(Ordering::Acquire) as *mut c_void,
            template_id: template_id as u16,
            table_id: self.table_id.load(Ordering::Acquire),
            table_index: self.table_index.load(Ordering::Acquire),
        })
    }
}

pub(super) fn store_created(
    shader: *mut c_void,
    stage: ShaderStage,
    original_handle: *mut c_void,
    template_id: u16,
    table_id: u32,
    table_index: u32,
) -> Option<ShaderRecordSnapshot> {
    TABLE.store(
        shader,
        stage,
        original_handle,
        template_id,
        table_id,
        table_index,
        false,
    )
}

pub(super) fn adopt_existing(
    shader: *mut c_void,
    stage: ShaderStage,
    template_id: u16,
    table_id: u32,
    table_index: u32,
) -> Option<ShaderRecordSnapshot> {
    if let Some(snapshot) = TABLE.find(shader) {
        if snapshot.table_id == TABLE_UNKNOWN {
            TABLE.set_table_slot(shader, table_id, table_index);
            return TABLE.find(shader);
        }
        return None;
    }
    let original_handle = engine_contracts::shader_handle(shader, stage)?;
    TABLE.store(
        shader,
        stage,
        original_handle,
        template_id,
        table_id,
        table_index,
        true,
    )
}

pub(super) fn find(shader: *mut c_void) -> Option<ShaderRecordSnapshot> {
    TABLE.find(shader)
}

pub(super) fn set_current(shader: *mut c_void, handle: *mut c_void) {
    TABLE.set_current(shader, handle);
}

pub(super) fn set_table_slot(shader: *mut c_void, table_id: u32, table_index: u32) {
    TABLE.set_table_slot(shader, table_id, table_index);
}

pub(super) fn restore(snapshot: ShaderRecordSnapshot) -> bool {
    if engine_contracts::write_shader_handle(
        snapshot.shader,
        snapshot.stage,
        snapshot.original_handle,
    ) {
        TABLE.set_current(snapshot.shader, snapshot.original_handle);
        true
    } else {
        false
    }
}

pub(super) fn restore_all_mutated() -> u32 {
    let mut restored = 0u32;
    for record in &TABLE.records {
        let Some(snapshot) = record.snapshot() else {
            continue;
        };
        if snapshot.current_handle == snapshot.original_handle {
            continue;
        }

        let Some(actual_handle) = engine_contracts::shader_handle(snapshot.shader, snapshot.stage)
        else {
            continue;
        };
        if actual_handle == snapshot.original_handle {
            TABLE.set_current(snapshot.shader, snapshot.original_handle);
            continue;
        }
        if actual_handle != snapshot.current_handle {
            continue;
        }
        if restore(snapshot) {
            restored += 1;
        }
    }
    restored
}

pub(super) fn identity_ready() -> bool {
    IDENTITY_READY.load(Ordering::Acquire)
}

pub(super) fn captured_records() -> u32 {
    CAPTURED_RECORDS.load(Ordering::Acquire)
}

pub(super) fn adopted_records() -> u32 {
    ADOPTED_RECORDS.load(Ordering::Acquire)
}

pub(super) fn active_record_count() -> usize {
    TABLE.active_record_count()
}

pub(super) fn recorded_template_count() -> usize {
    TABLE.recorded_template_count()
}

pub(super) fn reset() {
    TABLE.clear();
    IDENTITY_READY.store(false, Ordering::Release);
    CAPTURED_RECORDS.store(0, Ordering::Release);
    ADOPTED_RECORDS.store(0, Ordering::Release);
}

fn hash_slot(shader: usize) -> usize {
    (shader >> 4) % RECORD_COUNT
}

fn stage_to_u32(stage: ShaderStage) -> u32 {
    match stage {
        ShaderStage::Vertex => STAGE_VERTEX,
        ShaderStage::Pixel => STAGE_PIXEL,
    }
}
