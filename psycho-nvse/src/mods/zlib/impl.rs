//! High-performance zlib replacement with dual-path decompression
//!
//! Replaces the game's stock zlib 1.2.1 with flate2/zlib-rs. Two separate paths:
//! - TESFile (ESP/ESM forms): always one-shot, no streaming overhead
//! - BSA (archives): one-shot first (~93%), streaming fallback for the rest
//!
//! Buffer cap removal at 0xAFC58C lets BSA entries decompress in one shot.
//! Thread-local decompressors avoid per-call allocation.
//!
//! Based on ideas from:  https://github.com/WallSoGB/Fallout-zlibUpdate
//! and FastDecompressNV: https://github.com/1001Bits/FastDecompress/tree/main/FalloutNewVegas


// TODO: Research and fix:
// BSA decompress failed: deflate decompression error: invalid code -- missing end-of-block
// BSA decompress failed: deflate decompression error: invalid code -- missing end-of-block


use std::cell::{Cell, UnsafeCell};

use flate2::{Decompress, FlushDecompress, Status};
use libc::c_void;
use libnvse::api::interface::NVSEInterface;
use libpsycho::os::windows::winapi::{patch_memory_nop, replace_call, safe_write_8, safe_write_16};

// zlib return codes
const Z_OK: i32 = 0;
const Z_STREAM_END: i32 = 1;
const Z_DATA_ERROR: i32 = -3;

// zlib flush modes (from the game's inflate calls)
const Z_SYNC_FLUSH: i32 = 2;
const Z_FINISH: i32 = 4;

/// Skip zlib header and adler32 checksum verification.
/// true = raw deflate mode (faster, no checksum overhead on every output byte).
/// false = full zlib mode (safer, verifies adler32 integrity).
const SKIP_ADLER32: bool = true;

/// Zlib header size (CMF + FLG bytes).
const ZLIB_HEADER_SIZE: u32 = 2;
/// Zlib trailer size (adler32 checksum).
const ZLIB_TRAILER_SIZE: u32 = 4;
/// Total overhead bytes in zlib format that we bypass in raw mode.
const ZLIB_OVERHEAD: u32 = ZLIB_HEADER_SIZE + ZLIB_TRAILER_SIZE;

/// Increased alloc size for the game's z_stream-adjacent buffer.
/// Kept for safety even though we don't populate the internal state.
const ZLIB_ALLOC_SIZE: u16 = 0x1C08;

// ============================================================================
// Game's z_stream layout (32-bit, 56 bytes)
// ============================================================================

#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: u32,
    total_in: u32,
    next_out: *mut u8,
    avail_out: u32,
    total_out: u32,
    msg: *const u8,
    state: *mut c_void, // sentinel: 0x1 = TES, 0x2 = BSA
    zalloc: *mut c_void,
    zfree: *mut c_void,
    opaque: *mut c_void,
    data_type: i32,
    adler: u32,
    reserved: u32,
}

// ============================================================================
// Fallout: New Vegas Runtime Addresses
// ============================================================================

// TESFile (ESP/ESM form records)
const GAME_TES_INFLATE_INIT: usize = 0x4742AC;
const GAME_TES_INFLATE: usize = 0x47434F;
const GAME_TES_INFLATE_END: [usize; 4] = [0x4742CA, 0x474388, 0x4743D5, 0x474419];

// BSA (CompressedArchiveFile)
const GAME_BSA_INFLATE_INIT: usize = 0xAFC537;
const GAME_BSA_INFLATE: usize = 0xAFC1F4;
const GAME_BSA_INFLATE_END: [usize; 3] = [0xAFC00E, 0xAFC21B, 0xAFC552];

const GAME_ALLOC_SIZE_ADDR: usize = 0xAFC4A2;

/// BSA buffer cap: 8 bytes at 0xAFC58C (CMP + JAE that caps to 128KB)
const GAME_BSA_BUFFER_CAP_ADDR: usize = 0xAFC58C;
const GAME_BSA_BUFFER_CAP_SIZE: usize = 8;

// ============================================================================
// GECK Editor Addresses
// ============================================================================

const EDITOR_INFLATE_INIT_EX_ADDRS: [usize; 2] = [0x4E32D8, 0xB552D8];
const EDITOR_INFLATE_ADDRS: [usize; 2] = [0x4E3350, 0xB52E98];
const EDITOR_INFLATE_END_ADDRS: [usize; 7] = [
    0x4E32E9, 0x4E33DC, 0x4E3387, 0x4E3376, 0xB52D82, 0xB52EF4, 0xB552EB,
];
const EDITOR_ALLOC_SIZE_ADDR: usize = 0xB55284;
const EDITOR_TESNPC_COMPRESSION_ADDR: usize = 0x57A448;
const EDITOR_TESLAND_COMPRESSION_ADDR: usize = 0x61912D;

// ============================================================================
// Thread-local decompressor state
// ============================================================================

thread_local! {
    // UnsafeCell because these are accessed from extern "C" FFI hooks.
    // thread_local guarantees single-thread access, so no data race.
    // SKIP_ADLER32=true: raw deflate (no header/checksum overhead).
    // SKIP_ADLER32=false: full zlib mode (header parsed, adler32 verified).
    static TES_DECOMPRESS: UnsafeCell<Decompress> = UnsafeCell::new(Decompress::new(!SKIP_ADLER32));
    static BSA_DECOMPRESS: UnsafeCell<Decompress> = UnsafeCell::new(Decompress::new(!SKIP_ADLER32));

    // whether BSA is still attempting one-shot or fell back to streaming
    static BSA_ONESHOT: Cell<bool> = const { Cell::new(true) };
}

// ============================================================================
// z_stream field update helper
// ============================================================================

#[inline]
unsafe fn update_zstream(strm: *mut ZStream, d: &Decompress, before_in: u64, before_out: u64) {
    let consumed = (d.total_in() - before_in) as u32;
    let produced = (d.total_out() - before_out) as u32;

    let s = unsafe { &mut *strm };
    s.next_in = unsafe { s.next_in.add(consumed as usize) };
    s.avail_in -= consumed;
    s.total_in += consumed;
    s.next_out = unsafe { s.next_out.add(produced as usize) };
    s.avail_out -= produced;
    s.total_out += produced;
}

// ============================================================================
// TESFile hooks -- always one-shot
// ============================================================================

unsafe extern "C" fn hook_tesfile_inflate_init(
    strm: *mut ZStream,
    _version: *const u8,
    _stream_size: i32,
) -> i32 {
    let s = unsafe { &mut *strm };
    s.state = std::ptr::dangling_mut::<c_void>();
    s.total_in = 0;
    s.total_out = 0;
    s.msg = std::ptr::null();

    TES_DECOMPRESS.with(|cell| {
        let d = unsafe { &mut *cell.get() };
        d.reset(!SKIP_ADLER32);
    });

    Z_OK
}

unsafe extern "C" fn hook_tesfile_inflate(strm: *mut ZStream, _flush: i32) -> i32 {
    let s = unsafe { &mut *strm };

    if s.next_in.is_null() || s.next_out.is_null() || s.avail_in == 0 || s.avail_out == 0 {
        return Z_DATA_ERROR;
    }

    // raw deflate: skip zlib header, exclude trailer from input length.
    // zlib mode: pass everything through, flate2 handles header+checksum.
    let (input_ptr, input_len) = if SKIP_ADLER32 {
        if s.avail_in <= ZLIB_HEADER_SIZE {
            return Z_DATA_ERROR;
        }
        (
            unsafe { s.next_in.add(ZLIB_HEADER_SIZE as usize) },
            s.avail_in - ZLIB_OVERHEAD,
        )
    } else {
        (s.next_in, s.avail_in)
    };

    TES_DECOMPRESS.with(|cell| {
        let d = unsafe { &mut *cell.get() };
        let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };
        let output = unsafe { std::slice::from_raw_parts_mut(s.next_out, s.avail_out as usize) };

        let before_in = d.total_in();
        let before_out = d.total_out();
        match d.decompress(input, output, FlushDecompress::Finish) {
            Ok(Status::StreamEnd) => {
                unsafe { update_zstream(strm, d, before_in, before_out) };
                if SKIP_ADLER32 {
                    // fixup: game expects total_in to cover the full zlib stream
                    s.next_in = unsafe { s.next_in.add(s.avail_in as usize) };
                    s.total_in += ZLIB_OVERHEAD;
                    s.avail_in = 0;
                }
                Z_STREAM_END
            }
            Ok(_) => {
                unsafe { update_zstream(strm, d, before_in, before_out) };
                log::warn!(
                    "[ZLIB] TESFile one-shot incomplete, avail_in={}, avail_out={}",
                    s.avail_in,
                    s.avail_out
                );
                Z_OK
            }
            Err(e) => {
                log::error!("[ZLIB] TESFile decompress failed: {}", e);
                Z_DATA_ERROR
            }
        }
    })
}

unsafe extern "C" fn hook_tesfile_inflate_end(strm: *mut ZStream) -> i32 {
    unsafe { (*strm).state = std::ptr::null_mut() };
    Z_OK
}

// ============================================================================
// BSA hooks -- one-shot with streaming fallback
// ============================================================================

unsafe extern "C" fn hook_bsa_inflate_init(
    strm: *mut ZStream,
    _version: *const u8,
    _stream_size: i32,
) -> i32 {
    let s = unsafe { &mut *strm };
    s.state = 0x2usize as *mut c_void;
    s.total_in = 0;
    s.total_out = 0;
    s.msg = std::ptr::null();

    BSA_DECOMPRESS.with(|cell| {
        let d = unsafe { &mut *cell.get() };
        d.reset(!SKIP_ADLER32);
    });
    BSA_ONESHOT.with(|flag| flag.set(true));

    Z_OK
}

unsafe extern "C" fn hook_bsa_inflate(strm: *mut ZStream, flush: i32) -> i32 {
    let s = unsafe { &mut *strm };

    if s.next_in.is_null() || s.next_out.is_null() {
        return Z_DATA_ERROR;
    }

    let is_first = BSA_ONESHOT.with(|f| f.get());

    // raw deflate: skip header on first call, strip trailer from length.
    // zlib mode: pass everything through unchanged.
    let (input_ptr, input_len) = if SKIP_ADLER32 && is_first && s.avail_in > ZLIB_HEADER_SIZE {
        (
            unsafe { s.next_in.add(ZLIB_HEADER_SIZE as usize) },
            s.avail_in - ZLIB_OVERHEAD,
        )
    } else {
        (s.next_in, s.avail_in)
    };

    BSA_DECOMPRESS.with(|cell| {
        let d = unsafe { &mut *cell.get() };
        let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };
        let output = unsafe { std::slice::from_raw_parts_mut(s.next_out, s.avail_out as usize) };

        let before_in = d.total_in();
        let before_out = d.total_out();

        // first call: try one-shot with Finish.
        // if it completes, great. if not, state is preserved for streaming.
        let flush_mode = if is_first {
            FlushDecompress::Finish
        } else {
            match flush {
                Z_FINISH => FlushDecompress::Finish,
                Z_SYNC_FLUSH => FlushDecompress::Sync,
                _ => FlushDecompress::None,
            }
        };

        match d.decompress(input, output, flush_mode) {
            Ok(Status::StreamEnd) => {
                unsafe { update_zstream(strm, d, before_in, before_out) };
                if SKIP_ADLER32 && is_first {
                    s.next_in = unsafe { s.next_in.add(s.avail_in as usize) };
                    s.total_in += ZLIB_OVERHEAD;
                    s.avail_in = 0;
                }
                Z_STREAM_END
            }
            Ok(Status::Ok | Status::BufError) => {
                unsafe { update_zstream(strm, d, before_in, before_out) };
                if is_first {
                    BSA_ONESHOT.with(|f| f.set(false));
                    if SKIP_ADLER32 {
                        s.total_in += ZLIB_HEADER_SIZE;
                    }
                }
                Z_OK
            }
            Err(e) => {
                log::error!("[ZLIB] BSA decompress failed: {}", e);
                Z_DATA_ERROR
            }
        }
    })
}

unsafe extern "C" fn hook_bsa_inflate_end(strm: *mut ZStream) -> i32 {
    unsafe { (*strm).state = std::ptr::null_mut() };
    Z_OK
}

// ============================================================================
// Editor hooks -- simple streaming (not perf critical)
// ============================================================================

unsafe extern "C" fn hook_editor_inflate_init(
    strm: *mut ZStream,
    _version: *const u8,
    _stream_size: i32,
) -> i32 {
    let s = unsafe { &mut *strm };
    s.state = std::ptr::dangling_mut::<c_void>();
    s.total_in = 0;
    s.total_out = 0;
    s.msg = std::ptr::null();

    TES_DECOMPRESS.with(|cell| {
        let d = unsafe { &mut *cell.get() };
        d.reset(true);
    });

    Z_OK
}

unsafe extern "C" fn hook_editor_inflate(strm: *mut ZStream, flush: i32) -> i32 {
    let s = unsafe { &mut *strm };

    if s.next_in.is_null() || s.next_out.is_null() {
        return Z_DATA_ERROR;
    }

    TES_DECOMPRESS.with(|cell| {
        let d = unsafe { &mut *cell.get() };
        let input = unsafe { std::slice::from_raw_parts(s.next_in, s.avail_in as usize) };
        let output = unsafe { std::slice::from_raw_parts_mut(s.next_out, s.avail_out as usize) };

        let before_in = d.total_in();
        let before_out = d.total_out();

        let flush_mode = match flush {
            Z_FINISH => FlushDecompress::Finish,
            Z_SYNC_FLUSH => FlushDecompress::Sync,
            _ => FlushDecompress::None,
        };

        match d.decompress(input, output, flush_mode) {
            Ok(Status::StreamEnd) => {
                unsafe { update_zstream(strm, d, before_in, before_out) };
                Z_STREAM_END
            }
            Ok(_) => {
                unsafe { update_zstream(strm, d, before_in, before_out) };
                Z_OK
            }
            Err(e) => {
                log::error!("[ZLIB] Editor decompress failed: {}", e);
                Z_DATA_ERROR
            }
        }
    })
}

unsafe extern "C" fn hook_editor_inflate_end(strm: *mut ZStream) -> i32 {
    unsafe { (*strm).state = std::ptr::null_mut() };
    Z_OK
}

// ============================================================================
// Installation
// ============================================================================

fn install_game_hooks() -> anyhow::Result<()> {
    log::info!("[ZLIB] Installing dual-path decompression (flate2/zlib-rs)");

    // -- TESFile path: one-shot --
    unsafe {
        replace_call(
            GAME_TES_INFLATE_INIT as *mut c_void,
            hook_tesfile_inflate_init as *mut c_void,
        )?;
        replace_call(
            GAME_TES_INFLATE as *mut c_void,
            hook_tesfile_inflate as *mut c_void,
        )?;
        for addr in GAME_TES_INFLATE_END {
            replace_call(addr as *mut c_void, hook_tesfile_inflate_end as *mut c_void)?;
        }
    }

    // -- BSA path: one-shot + streaming fallback --
    unsafe {
        replace_call(
            GAME_BSA_INFLATE_INIT as *mut c_void,
            hook_bsa_inflate_init as *mut c_void,
        )?;
        replace_call(
            GAME_BSA_INFLATE as *mut c_void,
            hook_bsa_inflate as *mut c_void,
        )?;
        for addr in GAME_BSA_INFLATE_END {
            replace_call(addr as *mut c_void, hook_bsa_inflate_end as *mut c_void)?;
        }
    }

    // -- Buffer cap removal: NOP 8 bytes at 0xAFC58C --
    // removes 128KB limit on BSA decompression buffers so one-shot
    // succeeds for ~93% of entries instead of needing chunked streaming
    unsafe {
        patch_memory_nop(
            GAME_BSA_BUFFER_CAP_ADDR as *mut c_void,
            GAME_BSA_BUFFER_CAP_SIZE,
        )?;
    }

    // alloc size patch (safety margin for game's z_stream-adjacent buffer)
    safe_write_16(GAME_ALLOC_SIZE_ADDR as *mut c_void, ZLIB_ALLOC_SIZE)?;

    log::info!("[ZLIB] All patches installed (TES one-shot + BSA hybrid + buffer cap removed)");
    Ok(())
}

fn install_editor_hooks() -> anyhow::Result<()> {
    log::info!("[ZLIB] Installing editor zlib patches (flate2/zlib-rs)");

    for addr in EDITOR_INFLATE_INIT_EX_ADDRS {
        unsafe {
            replace_call(addr as *mut c_void, hook_editor_inflate_init as *mut c_void)?;
        }
    }
    for addr in EDITOR_INFLATE_ADDRS {
        unsafe {
            replace_call(addr as *mut c_void, hook_editor_inflate as *mut c_void)?;
        }
    }
    for addr in EDITOR_INFLATE_END_ADDRS {
        unsafe {
            replace_call(addr as *mut c_void, hook_editor_inflate_end as *mut c_void)?;
        }
    }

    safe_write_16(EDITOR_ALLOC_SIZE_ADDR as *mut c_void, ZLIB_ALLOC_SIZE)?;

    // disable compression for TESNPC records
    unsafe {
        patch_memory_nop(EDITOR_TESNPC_COMPRESSION_ADDR as *mut c_void, 5)?;
        safe_write_8(EDITOR_TESNPC_COMPRESSION_ADDR as *mut c_void, 0x00)?;
    }

    // disable compression for TESObjectLAND records
    unsafe {
        patch_memory_nop(EDITOR_TESLAND_COMPRESSION_ADDR as *mut c_void, 5)?;
    }

    log::info!("[ZLIB] Editor patches installed");
    Ok(())
}

pub fn install_zlib_hooks(nvse: &NVSEInterface) -> anyhow::Result<()> {
    if nvse.is_editor() {
        install_editor_hooks()
    } else {
        install_game_hooks()
    }
}
