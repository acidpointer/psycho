//! Shared ABI between `psycho_engine_fixes.dll` and its helper plugin.

pub const PSYCHO_ENGINE_FIXES_DLL: &str = "psycho_engine_fixes.dll";
pub const PSYCHO_ENGINE_FIXES_GET_API: &str = "PsychoEngineFixes_GetApi";
pub const PSYCHO_ENGINE_FIXES_GET_STATE: &str = "PsychoEngineFixes_GetState";

pub const PSYCHO_MAGIC: u32 = 0x4843_5950; // PSYH
pub const PSYCHO_API_VERSION: u32 = 4;
pub const PSYCHO_MAX_CHUNKS: usize = 8;

pub const PSYCHO_CHUNK_RESERVED: u32 = 1;
pub const PSYCHO_CHUNK_TOP_DOWN: u32 = 2;
pub const PSYCHO_CHUNK_CLAIMED: u32 = 4;

pub const PSYCHO_STATE_READY: u32 = 1;
pub const PSYCHO_STATE_PARTIAL: u32 = 2;

pub const PSYCHO_EVENT_DEFERRED_INIT: u32 = 1;
pub const PSYCHO_EVENT_PRE_LOAD_GAME: u32 = 2;
pub const PSYCHO_EVENT_LOAD_GAME: u32 = 3;
pub const PSYCHO_EVENT_POST_LOAD_GAME: u32 = 4;
pub const PSYCHO_EVENT_MAIN_GAME_LOOP: u32 = 5;
pub const PSYCHO_EVENT_ON_FRAME_PRESENT: u32 = 6;

pub const PSYCHO_COMMAND_MEM: u32 = 1;
pub const PSYCHO_COMMAND_MEM_MB: u32 = 2;
pub const PSYCHO_COMMAND_MEM_BYTES: u32 = 3;
pub const PSYCHO_COMMAND_SCRAP_HEAP: u32 = 4;
pub const PSYCHO_COMMAND_MEM_HUD: u32 = 5;
pub const PSYCHO_COMMAND_QUARANTINE: u32 = 6;
pub const PSYCHO_COMMAND_CELL_UNLOAD: u32 = 7;

pub const PSYCHO_COMMAND_HAS_RESULT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PsychoReservedChunk {
    pub base: usize,
    pub size: usize,
    pub flags: u32,
    pub reserved: u32,
}

impl PsychoReservedChunk {
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            flags: 0,
            reserved: 0,
        }
    }
}

#[repr(C)]
pub struct PsychoState {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub flags: u32,
    pub chunk_count: u32,
    pub total_reserved: usize,
    pub last_error: u32,
    pub chunks: [PsychoReservedChunk; PSYCHO_MAX_CHUNKS],
}

impl PsychoState {
    pub const fn new() -> Self {
        Self {
            magic: PSYCHO_MAGIC,
            version: PSYCHO_API_VERSION,
            size: size_of::<Self>() as u32,
            flags: 0,
            chunk_count: 0,
            total_reserved: 0,
            last_error: 0,
            chunks: [PsychoReservedChunk::empty(); PSYCHO_MAX_CHUNKS],
        }
    }
}

impl Default for PsychoState {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PsychoClaim {
    pub base: usize,
    pub size: usize,
    pub index: u32,
    pub flags: u32,
}

impl PsychoClaim {
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            index: u32::MAX,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PsychoEvent {
    pub kind: u32,
    pub data: *const u8,
    pub data_len: usize,
    pub bool_value: i32,
}

#[repr(C)]
pub struct PsychoCommandOutput {
    pub text: *mut u8,
    pub text_len: usize,
    pub written: usize,
    pub result: f64,
    pub flags: u32,
}

pub type PsychoGetStateFn = unsafe extern "system" fn() -> *const PsychoState;
pub type PsychoClaimChunkFn =
    unsafe extern "system" fn(min_size: usize, align: usize, out: *mut PsychoClaim) -> i32;
pub type PsychoNotifyFn = unsafe extern "system" fn(event: *const PsychoEvent) -> i32;
pub type PsychoCommandFn =
    unsafe extern "system" fn(command: u32, output: *mut PsychoCommandOutput) -> i32;
pub type PsychoGetApiFn = unsafe extern "system" fn() -> *const PsychoApi;

#[repr(C)]
pub struct PsychoApi {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub get_state: Option<PsychoGetStateFn>,
    pub claim_chunk: Option<PsychoClaimChunkFn>,
    pub notify: Option<PsychoNotifyFn>,
    pub command: Option<PsychoCommandFn>,
    pub reserved: [usize; 7],
}

impl PsychoApi {
    pub const fn new(
        get_state: PsychoGetStateFn,
        claim_chunk: PsychoClaimChunkFn,
        notify: PsychoNotifyFn,
        command: PsychoCommandFn,
    ) -> Self {
        Self {
            magic: PSYCHO_MAGIC,
            version: PSYCHO_API_VERSION,
            size: size_of::<Self>() as u32,
            get_state: Some(get_state),
            claim_chunk: Some(claim_chunk),
            notify: Some(notify),
            command: Some(command),
            reserved: [0; 7],
        }
    }
}
