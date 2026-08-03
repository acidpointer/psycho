//! High-throughput zlib replacement for Fallout: New Vegas.
//!
//! The engine exposes two different decompression contracts through the same
//! zlib ABI. `TESFile` provides a complete compressed record and destination in
//! one call, so it uses a reusable thread-local libdeflate decoder. Archive
//! reads retain one `z_stream` across bounded output and compressed-input
//! refills. They first try libdeflate without changing public stream state; a
//! miss materializes a fallible zlib-rs decoder directly in that `z_stream`.
//! Continuation state therefore follows the archive object across interleaved
//! streams and sequential worker handoffs.
//!
//! The low-level zlib-rs API is intentional. Its initializer reports allocation
//! failure as `Z_MEM_ERROR`, updates all public zlib cursor/checksum fields, and
//! avoids the extra allocation and wrapper calls required by a boxed flate2
//! decoder. The archive constructor preloads `state` with vanilla's 0x1BA8-byte
//! inline state area while leaving `zalloc` and `zfree` null. That storage does
//! not match zlib-rs's layout or capacity, so the fallback clears the borrowed
//! pointer and lets zlib-rs install its checked Rust allocator.
//!
//! Callsite installation verifies every original zlib target before writing and
//! applies the connected init/inflate/end set transactionally. The native 128
//! KiB archive output cap remains in place because an unbounded complete-entry
//! allocation is unsafe in FNV's 32-bit address space. See
//! `docs/zlib_stream_ownership.md` for executable evidence and performance
//! boundaries.

use std::{
    cell::RefCell,
    ffi::{CStr, c_void},
    ptr::NonNull,
};

use anyhow::{Context, ensure};
use libc::c_void as libc_void;
use libdeflate_sys::{
    libdeflate_alloc_decompressor, libdeflate_decompressor, libdeflate_free_decompressor,
    libdeflate_zlib_decompress_ex,
};
use libpsycho::os::windows::{memory::read_bytes, winapi::patch_bytes};
use zlib_rs::{
    InflateConfig, InflateFlush, ReturnCode,
    c_api::z_stream as BackendZStream,
    inflate::{self, InflateStream},
};

const LIBDEFLATE_SUCCESS: u32 = libdeflate_sys::libdeflate_result_LIBDEFLATE_SUCCESS;
const LIBDEFLATE_BAD_DATA: u32 = libdeflate_sys::libdeflate_result_LIBDEFLATE_BAD_DATA;
const LIBDEFLATE_SHORT_OUTPUT: u32 = libdeflate_sys::libdeflate_result_LIBDEFLATE_SHORT_OUTPUT;
const LIBDEFLATE_INSUFFICIENT_SPACE: u32 =
    libdeflate_sys::libdeflate_result_LIBDEFLATE_INSUFFICIENT_SPACE;

const Z_OK: i32 = ReturnCode::Ok as i32;
const Z_STREAM_END: i32 = ReturnCode::StreamEnd as i32;
const Z_STREAM_ERROR: i32 = ReturnCode::StreamError as i32;
const Z_DATA_ERROR: i32 = ReturnCode::DataError as i32;
const Z_MEM_ERROR: i32 = ReturnCode::MemError as i32;
const Z_BUF_ERROR: i32 = ReturnCode::BufError as i32;
const Z_VERSION_ERROR: i32 = ReturnCode::VersionError as i32;

#[cfg(test)]
const Z_SYNC_FLUSH: i32 = InflateFlush::SyncFlush as i32;
#[cfg(test)]
const Z_FINISH: i32 = InflateFlush::Finish as i32;

/// Identifies a TES stream initialized by the complete-buffer hooks.
const TES_STREAM_MAGIC: u32 = u32::from_le_bytes(*b"PSTZ");

/// Identifies an archive stream initialized by the hybrid hooks.
const ARCHIVE_STREAM_MAGIC: u32 = u32::from_le_bytes(*b"PSAZ");

/// Non-null marker used until an archive actually needs streaming state.
///
/// libdeflate hits never allocate a zlib-rs decoder. A real zlib-rs state is at
/// least allocator-aligned and can therefore never equal this value.
const PENDING_STREAM_STATE: usize = 1;

/// Default and preserved FNV archive output capacity.
///
/// When the first `avail_out` equals this value, the entry may be larger than
/// the buffer and libdeflate cannot prove completion. Skipping the speculative
/// pass avoids decoding the first 128 KiB twice on every capped large entry.
const NATIVE_ARCHIVE_OUTPUT_CAP: u32 = 0x20000;

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
    msg: *mut u8,
    state: *mut c_void,
    zalloc: *mut c_void,
    zfree: *mut c_void,
    opaque: *mut c_void,
    data_type: i32,
    adler: u32,
    reserved: u32,
}

// The direct backend cast below is valid only for the supported 32-bit Windows
// ABI. Keep this as a compile-time contract instead of relying solely on a test.
const _: () = {
    assert!(std::mem::size_of::<ZStream>() == 56);
    assert!(std::mem::size_of::<ZStream>() == std::mem::size_of::<BackendZStream>());
    assert!(std::mem::align_of::<ZStream>() == std::mem::align_of::<BackendZStream>());
    assert!(
        std::mem::offset_of!(ZStream, next_in) == std::mem::offset_of!(BackendZStream, next_in)
    );
    assert!(
        std::mem::offset_of!(ZStream, avail_in) == std::mem::offset_of!(BackendZStream, avail_in)
    );
    assert!(
        std::mem::offset_of!(ZStream, total_in) == std::mem::offset_of!(BackendZStream, total_in)
    );
    assert!(
        std::mem::offset_of!(ZStream, next_out) == std::mem::offset_of!(BackendZStream, next_out)
    );
    assert!(
        std::mem::offset_of!(ZStream, avail_out) == std::mem::offset_of!(BackendZStream, avail_out)
    );
    assert!(
        std::mem::offset_of!(ZStream, total_out) == std::mem::offset_of!(BackendZStream, total_out)
    );
    assert!(std::mem::offset_of!(ZStream, msg) == std::mem::offset_of!(BackendZStream, msg));
    assert!(std::mem::offset_of!(ZStream, state) == std::mem::offset_of!(BackendZStream, state));
    assert!(std::mem::offset_of!(ZStream, zalloc) == std::mem::offset_of!(BackendZStream, zalloc));
    assert!(std::mem::offset_of!(ZStream, zfree) == std::mem::offset_of!(BackendZStream, zfree));
    assert!(std::mem::offset_of!(ZStream, opaque) == std::mem::offset_of!(BackendZStream, opaque));
    assert!(
        std::mem::offset_of!(ZStream, data_type) == std::mem::offset_of!(BackendZStream, data_type)
    );
    assert!(std::mem::offset_of!(ZStream, adler) == std::mem::offset_of!(BackendZStream, adler));
    assert!(
        std::mem::offset_of!(ZStream, reserved) == std::mem::offset_of!(BackendZStream, reserved)
    );
};

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

/// Owns one fallibly allocated libdeflate decoder.
struct LibdeflateDecoder(NonNull<libdeflate_decompressor>);

impl LibdeflateDecoder {
    /// Allocate a decoder, preserving libdeflate's null-on-OOM contract.
    #[inline]
    fn new() -> Option<Self> {
        NonNull::new(unsafe { libdeflate_alloc_decompressor() }).map(Self)
    }

    /// Decode one complete zlib member and report exact cursor movement.
    #[inline]
    fn decompress_zlib(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<OneShotProgress, OneShotError> {
        let mut consumed = 0usize;
        let mut produced = 0usize;
        let result = unsafe {
            libdeflate_zlib_decompress_ex(
                self.0.as_ptr(),
                input.as_ptr().cast::<libc_void>(),
                input.len(),
                output.as_mut_ptr().cast::<libc_void>(),
                output.len(),
                &mut consumed,
                &mut produced,
            )
        };

        match result {
            LIBDEFLATE_SUCCESS if consumed <= input.len() && produced <= output.len() => {
                Ok(OneShotProgress {
                    consumed: consumed as u32,
                    produced: produced as u32,
                })
            }
            // Both sizes originate from u32 z_stream fields on the supported
            // target. Reject impossible library progress defensively before it
            // can underflow an engine-visible cursor.
            LIBDEFLATE_SUCCESS => Err(OneShotError::BadData),
            LIBDEFLATE_INSUFFICIENT_SPACE => Err(OneShotError::InsufficientSpace),
            LIBDEFLATE_SHORT_OUTPUT => Err(OneShotError::ShortOutput),
            LIBDEFLATE_BAD_DATA => Err(OneShotError::BadData),
            _ => Err(OneShotError::BadData),
        }
    }
}

impl Drop for LibdeflateDecoder {
    fn drop(&mut self) {
        unsafe { libdeflate_free_decompressor(self.0.as_ptr()) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OneShotProgress {
    consumed: u32,
    produced: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OneShotError {
    OutOfMemory,
    BadData,
    ShortOutput,
    InsufficientSpace,
}

thread_local! {
    // RefCell::try_borrow_mut makes same-thread recursive entry explicit. A
    // recursive call receives a temporary decoder rather than aliasing the
    // decoder already active in the outer hook.
    static ONESHOT_DECODER: RefCell<Option<LibdeflateDecoder>> = const { RefCell::new(None) };
}

/// Run a complete-buffer decode with thread-local reuse and fallible recursion.
#[inline]
fn decompress_one_shot(input: &[u8], output: &mut [u8]) -> Result<OneShotProgress, OneShotError> {
    let result = ONESHOT_DECODER.try_with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return decompress_with_temporary_decoder(input, output);
        };
        if slot.is_none() {
            *slot = LibdeflateDecoder::new();
        }
        slot.as_mut()
            .ok_or(OneShotError::OutOfMemory)?
            .decompress_zlib(input, output)
    });

    // A hook reached during TLS destruction cannot reuse that TLS slot. A
    // temporary checked allocation preserves behavior without panicking across
    // the C ABI.
    result.unwrap_or_else(|_| decompress_with_temporary_decoder(input, output))
}

fn decompress_with_temporary_decoder(
    input: &[u8],
    output: &mut [u8],
) -> Result<OneShotProgress, OneShotError> {
    LibdeflateDecoder::new()
        .ok_or(OneShotError::OutOfMemory)?
        .decompress_zlib(input, output)
}

/// Validate the ABI values supplied to zlib's `inflateInit_` entrypoint.
unsafe fn validate_init_args(version: *const u8, stream_size: i32) -> i32 {
    if version.is_null()
        || stream_size != std::mem::size_of::<ZStream>() as i32
        || unsafe { *version } != b'1'
    {
        Z_VERSION_ERROR
    } else {
        Z_OK
    }
}

/// Initialize public fields shared by the TES and archive proxy states.
fn initialize_public_stream(s: &mut ZStream, magic: u32) {
    s.state = PENDING_STREAM_STATE as *mut c_void;
    s.total_in = 0;
    s.total_out = 0;
    s.msg = std::ptr::null_mut();
    s.data_type = 2; // Z_UNKNOWN
    s.adler = 1;
    s.reserved = magic;
}

/// Return complete input/output slices only when their pointers are valid.
#[inline]
unsafe fn complete_buffers<'a>(s: &'a mut ZStream) -> Result<(&'a [u8], &'a mut [u8]), i32> {
    if s.next_in.is_null() || s.next_out.is_null() || s.avail_in == 0 || s.avail_out == 0 {
        return Err(Z_STREAM_ERROR);
    }

    Ok((
        unsafe { std::slice::from_raw_parts(s.next_in, s.avail_in as usize) },
        unsafe { std::slice::from_raw_parts_mut(s.next_out, s.avail_out as usize) },
    ))
}

/// Apply libdeflate's exact progress to the engine-visible zlib cursor.
#[inline]
unsafe fn apply_one_shot_progress(s: &mut ZStream, progress: OneShotProgress) {
    if progress.consumed != 0 {
        s.next_in = unsafe { s.next_in.add(progress.consumed as usize) };
    }
    s.avail_in -= progress.consumed;
    s.total_in = s.total_in.wrapping_add(progress.consumed);

    if progress.produced != 0 {
        s.next_out = unsafe { s.next_out.add(progress.produced as usize) };
    }
    s.avail_out -= progress.produced;
    s.total_out = s.total_out.wrapping_add(progress.produced);
}

/// Read the verified Adler-32 trailer without rescanning decompressed output.
#[inline]
fn zlib_trailer_adler(input: &[u8], consumed: u32) -> Option<u32> {
    let end = consumed as usize;
    let trailer = input.get(end.checked_sub(4)?..end)?;
    Some(u32::from_be_bytes(trailer.try_into().ok()?))
}

/// Reinterpret the engine's proven 56-byte ABI as zlib-rs's public stream.
#[inline]
unsafe fn backend_stream(s: &mut ZStream) -> &mut BackendZStream {
    unsafe { &mut *(s as *mut ZStream).cast::<BackendZStream>() }
}

/// Materialize a fallible zlib-rs decoder after a libdeflate miss.
unsafe fn initialize_streaming_decoder(s: &mut ZStream) -> ReturnCode {
    unsafe {
        initialize_streaming_decoder_with(s, |backend| {
            inflate::init(backend, InflateConfig { window_bits: 15 })
        })
    }
}

/// Dependency-injected initializer used to prove allocation-failure behavior.
unsafe fn initialize_streaming_decoder_with(
    s: &mut ZStream,
    initialize: impl FnOnce(&mut BackendZStream) -> ReturnCode,
) -> ReturnCode {
    // FNV passes a preinitialized pointer to the 0x1BA8-byte inline tail of the
    // archive's outer block. Stock inflate treats that state as borrowed and
    // records the ownership decision in reserved. zlib-rs instead allocates a
    // single differently aligned state/window block, so retaining the vanilla
    // pointer would reinterpret unrelated storage and corrupt the archive.
    s.state = std::ptr::null_mut();
    s.zalloc = std::ptr::null_mut();
    s.zfree = std::ptr::null_mut();
    s.opaque = std::ptr::null_mut();

    let backend = unsafe { backend_stream(s) };
    initialize(backend)
}

/// Prevent the native archive loop from spinning on an impossible no-progress return.
#[inline]
fn normalize_archive_result(
    result: ReturnCode,
    before_in: u32,
    before_out: u32,
    after_in: u32,
    after_out: u32,
) -> ReturnCode {
    if result == ReturnCode::BufError
        && before_in != 0
        && before_out != 0
        && after_in == before_in
        && after_out == before_out
    {
        ReturnCode::DataError
    } else {
        result
    }
}

/// Run one streaming step using state stored directly in this `z_stream`.
unsafe fn decompress_owned_stream(strm: *mut ZStream, flush: i32) -> i32 {
    let Some(s) = (unsafe { strm.as_mut() }) else {
        return Z_STREAM_ERROR;
    };
    if s.reserved != ARCHIVE_STREAM_MAGIC {
        return Z_STREAM_ERROR;
    }
    if s.state as usize == PENDING_STREAM_STATE {
        let initialized = unsafe { initialize_streaming_decoder(s) };
        if initialized != ReturnCode::Ok {
            return initialized as i32;
        }
    }
    if s.state.is_null() {
        return Z_STREAM_ERROR;
    }

    let Ok(flush) = InflateFlush::try_from(flush) else {
        return Z_STREAM_ERROR;
    };
    let before_in = s.avail_in;
    let before_out = s.avail_out;
    let backend = unsafe { backend_stream(s) };
    let backend_ptr = backend as *mut BackendZStream;
    let Some(stream) = (unsafe { InflateStream::from_stream_mut(backend) }) else {
        return Z_STREAM_ERROR;
    };
    let mut result = unsafe { inflate::inflate(stream, flush) };
    let backend = unsafe { &mut *backend_ptr };

    // FNV's archive loop does not treat Z_BUF_ERROR as fatal. Returning it when
    // both buffers remain usable and no cursor moved would spin forever, so an
    // impossible valid-stream state is promoted to a data error.
    let normalized = normalize_archive_result(
        result,
        before_in,
        before_out,
        backend.avail_in,
        backend.avail_out,
    );
    if normalized != result {
        backend.msg = c"Psycho zlib decoder made no progress".as_ptr().cast_mut();
    }
    result = normalized;

    if matches!(result, ReturnCode::DataError | ReturnCode::MemError) {
        let message = if backend.msg.is_null() {
            result.error_message().cast_mut()
        } else {
            backend.msg
        };
        let message = unsafe { CStr::from_ptr(message) }.to_string_lossy();
        log::error!("[ZLIB] BSA decompress failed: {message}");
    }

    result as i32
}

/// End a pending, completed-one-shot, failed-init, or active archive stream.
unsafe fn release_stream_decoder(strm: *mut ZStream) -> i32 {
    let Some(s) = (unsafe { strm.as_mut() }) else {
        return Z_STREAM_ERROR;
    };
    if s.reserved != ARCHIVE_STREAM_MAGIC {
        return Z_STREAM_ERROR;
    }

    if !s.state.is_null() && s.state as usize != PENDING_STREAM_STATE {
        let backend = unsafe { backend_stream(s) };
        let Some(stream) = (unsafe { InflateStream::from_stream_mut(backend) }) else {
            return Z_STREAM_ERROR;
        };
        inflate::end(stream);
    }

    s.state = std::ptr::null_mut();
    s.reserved = 0;
    Z_OK
}

// ============================================================================
// TESFile hooks -- always one-shot
// ============================================================================

unsafe extern "C" fn hook_tesfile_inflate_init(
    strm: *mut ZStream,
    version: *const u8,
    stream_size: i32,
) -> i32 {
    let validation = unsafe { validate_init_args(version, stream_size) };
    if validation != Z_OK {
        return validation;
    }
    let Some(s) = (unsafe { strm.as_mut() }) else {
        return Z_STREAM_ERROR;
    };
    initialize_public_stream(s, TES_STREAM_MAGIC);
    Z_OK
}

unsafe extern "C" fn hook_tesfile_inflate(strm: *mut ZStream, _flush: i32) -> i32 {
    let Some(s) = (unsafe { strm.as_mut() }) else {
        return Z_STREAM_ERROR;
    };

    if s.reserved != TES_STREAM_MAGIC || s.state as usize != PENDING_STREAM_STATE {
        return Z_STREAM_ERROR;
    }

    let (result, adler) = {
        let (input, output) = match unsafe { complete_buffers(s) } {
            Ok(buffers) => buffers,
            Err(code) => return code,
        };
        let result = decompress_one_shot(input, output);
        let adler = result
            .ok()
            .and_then(|progress| zlib_trailer_adler(input, progress.consumed));
        (result, adler)
    };

    match result {
        Ok(progress) => {
            unsafe { apply_one_shot_progress(s, progress) };
            if let Some(adler) = adler {
                s.adler = adler;
            }
            Z_STREAM_END
        }
        Err(OneShotError::OutOfMemory) => Z_MEM_ERROR,
        Err(OneShotError::InsufficientSpace) => Z_BUF_ERROR,
        Err(OneShotError::BadData | OneShotError::ShortOutput) => Z_DATA_ERROR,
    }
}

unsafe extern "C" fn hook_tesfile_inflate_end(strm: *mut ZStream) -> i32 {
    let Some(s) = (unsafe { strm.as_mut() }) else {
        return Z_STREAM_ERROR;
    };
    if s.reserved != TES_STREAM_MAGIC {
        return Z_STREAM_ERROR;
    }
    s.state = std::ptr::null_mut();
    s.reserved = 0;
    Z_OK
}

// ============================================================================
// BSA hooks -- persistent streaming state
// ============================================================================

unsafe extern "C" fn hook_bsa_inflate_init(
    strm: *mut ZStream,
    version: *const u8,
    stream_size: i32,
) -> i32 {
    let validation = unsafe { validate_init_args(version, stream_size) };
    if validation != Z_OK {
        return validation;
    }
    let Some(s) = (unsafe { strm.as_mut() }) else {
        return Z_STREAM_ERROR;
    };
    initialize_public_stream(s, ARCHIVE_STREAM_MAGIC);
    Z_OK
}

unsafe extern "C" fn hook_bsa_inflate(strm: *mut ZStream, flush: i32) -> i32 {
    let Some(s) = (unsafe { strm.as_mut() }) else {
        return Z_STREAM_ERROR;
    };
    if s.reserved != ARCHIVE_STREAM_MAGIC {
        return Z_STREAM_ERROR;
    }

    // Only a pristine pending stream may use libdeflate. A failed attempt does
    // not move public cursors; zlib-rs then overwrites any undefined output from
    // the failed complete-buffer operation while decoding from byte zero.
    if s.state as usize == PENDING_STREAM_STATE
        && s.total_in == 0
        && s.total_out == 0
        && s.avail_out < NATIVE_ARCHIVE_OUTPUT_CAP
    {
        let (result, adler) = {
            let (input, output) = match unsafe { complete_buffers(s) } {
                Ok(buffers) => buffers,
                Err(code) => return code,
            };
            let result = decompress_one_shot(input, output);
            let adler = result
                .ok()
                .and_then(|progress| zlib_trailer_adler(input, progress.consumed));
            (result, adler)
        };
        if let Ok(progress) = result {
            unsafe { apply_one_shot_progress(s, progress) };
            if let Some(adler) = adler {
                s.adler = adler;
            }
            return Z_STREAM_END;
        }
    }

    unsafe { decompress_owned_stream(strm, flush) }
}

unsafe extern "C" fn hook_bsa_inflate_end(strm: *mut ZStream) -> i32 {
    unsafe { release_stream_decoder(strm) }
}

// ============================================================================
// Installation
// ============================================================================

const STOCK_INFLATE_INIT: usize = 0x00B43FE0;
const STOCK_INFLATE: usize = 0x00B44000;
const STOCK_INFLATE_END: usize = 0x00B45DB0;

#[derive(Clone, Copy)]
struct CallPatch {
    address: usize,
    expected_target: usize,
    replacement: usize,
    label: &'static str,
}

/// Encode one complete x86 near-CALL instruction.
fn encode_relative_call(source: usize, target: usize) -> [u8; 5] {
    let displacement = target.wrapping_sub(source.wrapping_add(5)) as u32;
    let mut bytes = [0u8; 5];
    bytes[0] = 0xE8;
    bytes[1..].copy_from_slice(&displacement.to_le_bytes());
    bytes
}

/// Decode and validate one x86 near-CALL target from a five-byte snapshot.
fn relative_call_target(source: usize, bytes: &[u8]) -> anyhow::Result<usize> {
    ensure!(
        bytes.len() == 5,
        "CALL snapshot must contain exactly five bytes"
    );
    ensure!(
        bytes[0] == 0xE8,
        "expected CALL at 0x{source:08X}, found opcode 0x{:02X}",
        bytes[0]
    );
    let displacement = i32::from_le_bytes(bytes[1..5].try_into().expect("fixed CALL width"));
    Ok(source
        .wrapping_add(5)
        .wrapping_add_signed(displacement as isize))
}

/// Verify, apply, and if necessary roll back a connected callsite patch set.
fn replace_calls_transactionally(patches: &[CallPatch]) -> anyhow::Result<()> {
    replace_calls_transactionally_with(
        patches,
        |address| read_bytes(address as *const c_void, 5).map_err(anyhow::Error::from),
        |address, bytes| {
            unsafe { patch_bytes(address as *mut c_void, bytes) }.map_err(anyhow::Error::from)
        },
    )
}

/// Injectable transaction core used by rollback regression tests.
fn replace_calls_transactionally_with(
    patches: &[CallPatch],
    mut read: impl FnMut(usize) -> anyhow::Result<Vec<u8>>,
    mut write: impl FnMut(usize, &[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let originals = patches
        .iter()
        .map(|patch| {
            let bytes = read(patch.address)
                .with_context(|| format!("read {} at 0x{:08X}", patch.label, patch.address))?;
            let observed = relative_call_target(patch.address, &bytes)?;
            ensure!(
                observed == patch.expected_target,
                "{} target mismatch at 0x{:08X}: expected 0x{:08X}, found 0x{observed:08X}",
                patch.label,
                patch.address,
                patch.expected_target
            );
            Ok(bytes)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    for (index, patch) in patches.iter().enumerate() {
        let replacement = encode_relative_call(patch.address, patch.replacement);
        if let Err(error) = write(patch.address, &replacement) {
            let mut rollback_failures = Vec::new();
            for rollback_index in (0..=index).rev() {
                if let Err(rollback_error) = write(
                    patches[rollback_index].address,
                    originals[rollback_index].as_slice(),
                ) {
                    rollback_failures.push(format!(
                        "0x{:08X}: {rollback_error}",
                        patches[rollback_index].address
                    ));
                }
            }

            if rollback_failures.is_empty() {
                return Err(error).with_context(|| {
                    format!(
                        "replace {} at 0x{:08X}; all writes rolled back",
                        patch.label, patch.address
                    )
                });
            }
            return Err(anyhow::anyhow!(
                "replace {} at 0x{:08X}: {error}; rollback failures: {}",
                patch.label,
                patch.address,
                rollback_failures.join(", ")
            ));
        }
    }

    Ok(())
}

fn install_game_hooks() -> anyhow::Result<()> {
    log::info!("[ZLIB] Installing libdeflate/zlib-rs decompression hooks");

    let mut patches = Vec::with_capacity(11);
    patches.push(CallPatch {
        address: GAME_TES_INFLATE_INIT,
        expected_target: STOCK_INFLATE_INIT,
        replacement: hook_tesfile_inflate_init as *const () as usize,
        label: "TES inflateInit_",
    });
    patches.push(CallPatch {
        address: GAME_TES_INFLATE,
        expected_target: STOCK_INFLATE,
        replacement: hook_tesfile_inflate as *const () as usize,
        label: "TES inflate",
    });
    patches.extend(GAME_TES_INFLATE_END.map(|address| CallPatch {
        address,
        expected_target: STOCK_INFLATE_END,
        replacement: hook_tesfile_inflate_end as *const () as usize,
        label: "TES inflateEnd",
    }));
    patches.push(CallPatch {
        address: GAME_BSA_INFLATE_INIT,
        expected_target: STOCK_INFLATE_INIT,
        replacement: hook_bsa_inflate_init as *const () as usize,
        label: "BSA inflateInit_",
    });
    patches.push(CallPatch {
        address: GAME_BSA_INFLATE,
        expected_target: STOCK_INFLATE,
        replacement: hook_bsa_inflate as *const () as usize,
        label: "BSA inflate",
    });
    patches.extend(GAME_BSA_INFLATE_END.map(|address| CallPatch {
        address,
        expected_target: STOCK_INFLATE_END,
        replacement: hook_bsa_inflate_end as *const () as usize,
        label: "BSA inflateEnd",
    }));

    replace_calls_transactionally(&patches)?;

    // Do not alter the engine's 0x1BE0 outer allocation or 128 KiB output cap.
    // zlib-rs state uses its own fallible allocation only after a libdeflate
    // miss, while the cap prevents a single archive entry from demanding an
    // unbounded contiguous buffer in FNV's 32-bit address space.
    log::info!("[ZLIB] Hooks installed (libdeflate one-shot + per-stream zlib-rs fallback)");
    Ok(())
}

/// Install the verified FNV zlib replacement callsites.
///
/// Installation must run once during the pre-CRT core startup phase, before
/// `TESFile` or `CompressedArchiveFile` can create a redirected stream. GECK is
/// intentionally excluded: the repository has no editor executable identity or
/// static callsite proof, and its previously listed addresses were unreachable
/// from core startup.
///
/// # Errors
///
/// Returns an error before writing if any callsite is not an original call to
/// FNV's audited zlib entrypoint. A write failure restores every instruction
/// snapshot; rollback failures are included in the returned error.
pub fn install_zlib_hooks() -> anyhow::Result<()> {
    install_game_hooks()
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell as TestRefCell},
        collections::BTreeMap,
        io::Write,
    };

    use flate2::{Compression, write::ZlibEncoder};

    use super::*;

    const ZLIB_VERSION: &[u8] = b"1.2.1\0";

    /// Owns every allocation referenced by the embedded raw `ZStream`.
    struct TestStream {
        compressed: Vec<u8>,
        output: Vec<u8>,
        input_limit: usize,
        stream: ZStream,
    }

    // SAFETY: the vectors own stable heap allocations and the test moves the
    // complete owner between threads only after joining the previous user. No
    // hook call can overlap that move or another call for the same stream.
    unsafe impl Send for TestStream {}

    impl TestStream {
        /// Create and initialize a BSA-style stream with spare output room for
        /// consuming the trailer after the final payload byte is produced.
        fn new_bsa(payload: &[u8]) -> Self {
            Self::new_bsa_with_input_limit(payload, usize::MAX)
        }

        /// Create a stream whose compressed input is refilled in bounded chunks.
        fn new_bsa_with_input_limit(payload: &[u8], input_limit: usize) -> Self {
            let compressed = compress(payload);
            let mut output = vec![0; payload.len() + 64];
            let mut stream = empty_stream();
            stream.next_in = compressed.as_ptr();
            stream.avail_in = compressed.len().min(input_limit) as u32;
            stream.next_out = output.as_mut_ptr();
            stream.avail_out = output.len() as u32;

            let mut owned = Self {
                compressed,
                output,
                input_limit,
                stream,
            };
            assert_eq!(
                unsafe {
                    hook_bsa_inflate_init(
                        &mut owned.stream,
                        ZLIB_VERSION.as_ptr(),
                        std::mem::size_of::<ZStream>() as i32,
                    )
                },
                Z_OK
            );
            owned
        }

        /// Supply a fresh bounded output window, matching the archive reader's
        /// repeated refill/decompress loop.
        fn step(&mut self, output_limit: usize) -> i32 {
            if self.stream.avail_in == 0 && (self.stream.total_in as usize) < self.compressed.len()
            {
                let consumed = self.stream.total_in as usize;
                let remaining = self.compressed.len() - consumed;
                self.stream.next_in = unsafe { self.compressed.as_ptr().add(consumed) };
                self.stream.avail_in = remaining.min(self.input_limit) as u32;
            }

            let produced = self.stream.total_out as usize;
            let remaining = self.output.len() - produced;
            assert!(
                remaining > 0,
                "decoder exhausted the test output allocation"
            );

            self.stream.next_out = unsafe { self.output.as_mut_ptr().add(produced) };
            self.stream.avail_out = remaining.min(output_limit) as u32;
            unsafe { hook_bsa_inflate(&mut self.stream, Z_SYNC_FLUSH) }
        }

        /// Continue bounded decompression until the stream terminates.
        fn complete(&mut self, output_limit: usize) {
            for _ in 0..10_000 {
                match self.step(output_limit) {
                    Z_STREAM_END => return,
                    Z_OK | Z_BUF_ERROR => {}
                    code => panic!("inflate failed with {code}"),
                }
            }
            panic!("inflate did not terminate");
        }

        /// Return only bytes reported through the public zlib cursor.
        fn produced(&self) -> &[u8] {
            &self.output[..self.stream.total_out as usize]
        }

        /// Release the replacement decoder through the same hook as the game.
        fn end(&mut self) -> i32 {
            unsafe { hook_bsa_inflate_end(&mut self.stream) }
        }
    }

    impl Drop for TestStream {
        fn drop(&mut self) {
            if self.stream.reserved == ARCHIVE_STREAM_MAGIC {
                let _ = self.end();
            }
        }
    }

    fn empty_stream() -> ZStream {
        ZStream {
            next_in: std::ptr::null(),
            avail_in: 0,
            total_in: 0,
            next_out: std::ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: std::ptr::null_mut(),
            state: std::ptr::null_mut(),
            zalloc: std::ptr::null_mut(),
            zfree: std::ptr::null_mut(),
            opaque: std::ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        }
    }

    fn compress(payload: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn payload(seed: u32, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|index| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state as u8) ^ (index as u8).wrapping_mul(31)
            })
            .collect()
    }

    /// Exercise zlib-rs's real null-on-allocation-failure branch.
    unsafe extern "C" fn fail_zalloc(_opaque: *mut c_void, _items: u32, _size: u32) -> *mut c_void {
        std::ptr::null_mut()
    }

    unsafe extern "C" fn fail_zfree(_opaque: *mut c_void, _allocation: *mut c_void) {}

    #[test]
    fn zstream_layout_matches_32_bit_game_abi() {
        assert_eq!(std::mem::size_of::<ZStream>(), 56);
        assert_eq!(
            std::mem::size_of::<ZStream>(),
            std::mem::size_of::<BackendZStream>()
        );
        assert_eq!(
            std::mem::align_of::<ZStream>(),
            std::mem::align_of::<BackendZStream>()
        );
        assert_eq!(std::mem::offset_of!(ZStream, state), 0x1C);
        assert_eq!(std::mem::offset_of!(ZStream, reserved), 0x34);
    }

    #[test]
    fn inflate_init_validates_version_and_stream_size_before_mutation() {
        let mut stream = empty_stream();
        let unsupported = b"2.0.0\0";

        assert_eq!(
            unsafe { hook_bsa_inflate_init(&mut stream, std::ptr::null(), 56) },
            Z_VERSION_ERROR
        );
        assert_eq!(stream.reserved, 0);
        assert_eq!(
            unsafe { hook_bsa_inflate_init(&mut stream, unsupported.as_ptr(), 56) },
            Z_VERSION_ERROR
        );
        assert_eq!(
            unsafe { hook_bsa_inflate_init(&mut stream, ZLIB_VERSION.as_ptr(), 55) },
            Z_VERSION_ERROR
        );
        assert_eq!(stream.reserved, 0);
    }

    #[test]
    fn fixed_external_zlib_member_uses_libdeflate_complete_path() {
        // Standard zlib member for "hello". Keeping fixed bytes avoids testing
        // a decoder only against streams emitted by the same Rust backend.
        let compressed = [
            0x78, 0x9C, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00, 0x06, 0x2C, 0x02, 0x15,
        ];
        let mut output = [0u8; 5];

        assert_eq!(
            decompress_one_shot(&compressed, &mut output),
            Ok(OneShotProgress {
                consumed: compressed.len() as u32,
                produced: output.len() as u32,
            })
        );
        assert_eq!(&output, b"hello");
    }

    #[test]
    fn complete_bsa_member_avoids_streaming_allocation() {
        let expected = payload(0x1020_3040, 12_345);
        let mut stream = TestStream::new_bsa(&expected);
        let output_limit = stream.output.len();

        assert_eq!(stream.step(output_limit), Z_STREAM_END);
        assert_eq!(stream.stream.state as usize, PENDING_STREAM_STATE);
        assert_eq!(stream.produced(), expected);
        assert_eq!(
            stream.stream.adler,
            u32::from_be_bytes(
                stream.compressed[stream.compressed.len() - 4..]
                    .try_into()
                    .unwrap()
            )
        );
        assert_eq!(stream.end(), Z_OK);
    }

    #[test]
    fn capped_large_bsa_member_skips_guaranteed_one_shot_miss() {
        let expected = payload(0x5566_AABB, NATIVE_ARCHIVE_OUTPUT_CAP as usize + 65_537);
        let mut stream = TestStream::new_bsa(&expected);

        assert_ne!(
            stream.step(NATIVE_ARCHIVE_OUTPUT_CAP as usize),
            Z_STREAM_END
        );
        assert_ne!(stream.stream.state as usize, PENDING_STREAM_STATE);
        stream.complete(NATIVE_ARCHIVE_OUTPUT_CAP as usize);
        assert_eq!(stream.produced(), expected);
        assert_eq!(stream.end(), Z_OK);
    }

    #[test]
    fn streaming_init_reports_memory_failure_without_panicking() {
        let mut stream = empty_stream();
        initialize_public_stream(&mut stream, ARCHIVE_STREAM_MAGIC);

        let result = unsafe {
            initialize_streaming_decoder_with(&mut stream, |backend| {
                backend.zalloc = Some(fail_zalloc);
                backend.zfree = Some(fail_zfree);
                inflate::init(backend, InflateConfig { window_bits: 15 })
            })
        };

        assert_eq!(result, ReturnCode::MemError);
        assert!(stream.state.is_null());
        assert_eq!(stream.reserved, ARCHIVE_STREAM_MAGIC);
        assert_eq!(unsafe { hook_bsa_inflate_end(&mut stream) }, Z_OK);
    }

    #[test]
    fn incremental_compressed_input_refills_preserve_stream_state() {
        let expected = payload(0x7654_3210, 48_123);
        let mut stream = TestStream::new_bsa_with_input_limit(&expected, 17);

        stream.complete(131);

        assert_eq!(stream.produced(), expected);
        assert_eq!(stream.stream.total_in as usize, stream.compressed.len());
        assert_eq!(stream.end(), Z_OK);
    }

    #[test]
    fn native_archive_no_progress_case_is_promoted_to_data_error() {
        assert_eq!(
            normalize_archive_result(ReturnCode::BufError, 12, 34, 12, 34),
            ReturnCode::DataError
        );
        assert_eq!(
            normalize_archive_result(ReturnCode::BufError, 12, 34, 0, 34),
            ReturnCode::BufError
        );
        assert_eq!(
            normalize_archive_result(ReturnCode::BufError, 0, 34, 0, 34),
            ReturnCode::BufError
        );
    }

    #[test]
    fn persistent_decoder_can_cross_threads_sequentially() {
        let expected = payload(0x1357_2468, 24_000);
        let mut stream = TestStream::new_bsa(&expected);
        assert_ne!(stream.step(113), Z_STREAM_END);

        let (mut stream, actual) = std::thread::spawn(move || {
            stream.complete(113);
            let actual = stream.produced().to_vec();
            (stream, actual)
        })
        .join()
        .unwrap();

        assert_eq!(actual, expected);
        assert_eq!(stream.stream.total_in as usize, stream.compressed.len());
        assert_eq!(stream.end(), Z_OK);
    }

    #[test]
    fn interleaved_bsa_streams_keep_independent_state() {
        let expected_a = payload(0xA5A5_5A5A, 31_337);
        let expected_b = payload(0xC001_C0DE, 27_019);
        let mut stream_a = TestStream::new_bsa(&expected_a);
        let mut stream_b = TestStream::new_bsa(&expected_b);

        assert_eq!(stream_a.stream.state as usize, PENDING_STREAM_STATE);
        assert_eq!(stream_b.stream.state as usize, PENDING_STREAM_STATE);
        assert_ne!(stream_a.step(127), Z_STREAM_END);
        assert_ne!(stream_b.step(89), Z_STREAM_END);
        assert_ne!(stream_a.stream.state, stream_b.stream.state);
        let mut done_a = false;
        let mut done_b = false;
        for _ in 0..10_000 {
            if !done_a {
                done_a = stream_a.step(127) == Z_STREAM_END;
            }
            if !done_b {
                done_b = stream_b.step(89) == Z_STREAM_END;
            }
            if done_a && done_b {
                break;
            }
        }

        assert!(done_a && done_b);
        assert_eq!(stream_a.produced(), expected_a);
        assert_eq!(stream_b.produced(), expected_b);
        assert_eq!(stream_a.end(), Z_OK);
        assert_eq!(stream_b.end(), Z_OK);
    }

    #[test]
    fn tes_decoder_resets_at_each_complete_operation() {
        let expected_a = payload(0x1122_3344, 4_321);
        let expected_b = payload(0x5566_7788, 5_678);
        let compressed_a = compress(&expected_a);
        let compressed_b = compress(&expected_b);
        let mut output_a = vec![0; expected_a.len()];
        let mut output_b = vec![0; expected_b.len()];
        let mut stream_a = empty_stream();
        let mut stream_b = empty_stream();

        for (stream, input, output) in [
            (&mut stream_a, &compressed_a, &mut output_a),
            (&mut stream_b, &compressed_b, &mut output_b),
        ] {
            stream.next_in = input.as_ptr();
            stream.avail_in = input.len() as u32;
            stream.next_out = output.as_mut_ptr();
            stream.avail_out = output.len() as u32;
            assert_eq!(
                unsafe {
                    hook_tesfile_inflate_init(
                        stream,
                        ZLIB_VERSION.as_ptr(),
                        std::mem::size_of::<ZStream>() as i32,
                    )
                },
                Z_OK
            );
        }

        // Both init calls happen first. Resetting TLS in init would leave the
        // second operation dependent on the first operation's completed state.
        assert_eq!(
            unsafe { hook_tesfile_inflate(&mut stream_a, 0) },
            Z_STREAM_END
        );
        assert_eq!(
            unsafe { hook_tesfile_inflate(&mut stream_b, 0) },
            Z_STREAM_END
        );
        assert_eq!(output_a, expected_a);
        assert_eq!(output_b, expected_b);
        assert_eq!(unsafe { hook_tesfile_inflate_end(&mut stream_a) }, Z_OK);
        assert_eq!(unsafe { hook_tesfile_inflate_end(&mut stream_b) }, Z_OK);
    }

    #[test]
    fn checksum_corruption_is_rejected() {
        let expected = payload(0xDEAD_BEEF, 8_192);
        let mut stream = TestStream::new_bsa(&expected);
        let trailer = stream.compressed.last_mut().unwrap();
        *trailer ^= 0xFF;

        assert_eq!(
            unsafe { hook_bsa_inflate(&mut stream.stream, Z_FINISH) },
            Z_DATA_ERROR
        );
        assert_eq!(stream.end(), Z_OK);
    }

    #[test]
    fn repeated_inflate_end_does_not_double_drop_state() {
        let mut stream = TestStream::new_bsa(b"persistent stream ownership");
        assert_eq!(stream.end(), Z_OK);
        assert_eq!(stream.end(), Z_STREAM_ERROR);
        assert!(stream.stream.state.is_null());
        assert_eq!(stream.stream.reserved, 0);
    }

    #[test]
    fn call_encoding_round_trips_forward_and_backward_targets() {
        for (source, target) in [(0x1000, 0x7654_3210), (0x7654_3210, 0x1000)] {
            let bytes = encode_relative_call(source, target);
            assert_eq!(relative_call_target(source, &bytes).unwrap(), target);
        }
    }

    #[test]
    fn transaction_rejects_target_mismatch_before_any_write() {
        let patches = [CallPatch {
            address: 0x1000,
            expected_target: 0x2000,
            replacement: 0x3000,
            label: "test CALL",
        }];
        let writes = Cell::new(0usize);

        let result = replace_calls_transactionally_with(
            &patches,
            |_| Ok(encode_relative_call(0x1000, 0x2222).to_vec()),
            |_, _| {
                writes.set(writes.get() + 1);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn transaction_rolls_back_every_prior_call_after_write_failure() {
        let patches = [
            CallPatch {
                address: 0x1000,
                expected_target: 0x4000,
                replacement: 0x6000,
                label: "first test CALL",
            },
            CallPatch {
                address: 0x2000,
                expected_target: 0x5000,
                replacement: 0x7000,
                label: "second test CALL",
            },
        ];
        let originals = BTreeMap::from([
            (0x1000, encode_relative_call(0x1000, 0x4000).to_vec()),
            (0x2000, encode_relative_call(0x2000, 0x5000).to_vec()),
        ]);
        let memory = TestRefCell::new(originals.clone());
        let failed_once = Cell::new(false);

        let result = replace_calls_transactionally_with(
            &patches,
            |address| Ok(memory.borrow().get(&address).unwrap().clone()),
            |address, bytes| {
                if address == 0x2000 && !failed_once.replace(true) {
                    anyhow::bail!("injected write failure");
                }
                memory.borrow_mut().insert(address, bytes.to_vec());
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(*memory.borrow(), originals);
    }
}
