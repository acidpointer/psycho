//! Safe wrapper for the NVSE serialization (co-save) interface.
//!
//! Allows plugins to persist custom data alongside game saves. Data is stored
//! in a separate file from the main .ess save to prevent compatibility issues.
//!
//! # Overview
//!
//! The co-save system uses typed, versioned records. Each plugin writes records
//! identified by a 4-byte type tag and a version number. On load, records are
//! returned in the order they were written.
//!
//! # Usage
//!
//! ```no_run
//! // Register save/load callbacks during plugin load
//! serialization.set_save_callback(plugin_handle, my_save_handler)?;
//! serialization.set_load_callback(plugin_handle, my_load_handler)?;
//! serialization.set_new_game_callback(plugin_handle, my_new_game_handler)?;
//!
//! // In your save callback:
//! serialization.write_record(b"DATA", 1, &my_data)?;
//!
//! // In your load callback:
//! while let Some(record) = serialization.next_record()? {
//!     match &record.record_type {
//!         b"DATA" => {
//!             let mut buf = vec![0u8; record.length as usize];
//!             serialization.read_data(&mut buf)?;
//!         }
//!         _ => {}
//!     }
//! }
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use closure_ffi::BareFn;
use thiserror::Error;

use crate::NVSESerializationInterface as NVSESerializationInterfaceFFI;

/// Type alias for the raw event callback signature used by NVSE serialization.
type RawEventCallback = unsafe extern "C" fn(reserved: *mut libc::c_void);

#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("NVSESerializationInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("SetSaveCallback function pointer is NULL")]
    SetSaveCallbackIsNull,

    #[error("SetLoadCallback function pointer is NULL")]
    SetLoadCallbackIsNull,

    #[error("SetNewGameCallback function pointer is NULL")]
    SetNewGameCallbackIsNull,

    #[error("WriteRecord function pointer is NULL")]
    WriteRecordIsNull,

    #[error("WriteRecord failed")]
    WriteFailed,

    #[error("OpenRecord function pointer is NULL")]
    OpenRecordIsNull,

    #[error("OpenRecord failed")]
    OpenFailed,

    #[error("WriteRecordData function pointer is NULL")]
    WriteRecordDataIsNull,

    #[error("GetNextRecordInfo function pointer is NULL")]
    GetNextRecordInfoIsNull,

    #[error("ReadRecordData function pointer is NULL")]
    ReadRecordDataIsNull,

    #[error("ResolveRefID function pointer is NULL")]
    ResolveRefIDIsNull,

    #[error("RefID {0:#010X} could not be resolved (owning mod may be unloaded)")]
    RefIdUnresolved(u32),
}

pub type SerializationResult<T> = Result<T, SerializationError>;

/// Information about a record returned by `next_record()`.
#[derive(Debug, Clone)]
pub struct RecordInfo {
    /// 4-byte record type tag (e.g. b"DATA").
    pub record_type: [u8; 4],
    /// Version of this record (for backwards-compatible loading).
    pub version: u32,
    /// Length of the record data in bytes.
    pub length: u32,
}

/// Safe wrapper around NVSESerializationInterface.
///
/// Provides methods for:
/// - Registering save/load/new-game callbacks
/// - Writing typed, versioned records during save
/// - Reading records during load
/// - Resolving RefIDs that may change between saves
pub struct Serialization<'a> {
    ptr: NonNull<NVSESerializationInterfaceFFI>,
    /// Stored closures to prevent them from being dropped.
    _save_cb: Option<BareFn<'a, RawEventCallback>>,
    _load_cb: Option<BareFn<'a, RawEventCallback>>,
    _new_game_cb: Option<BareFn<'a, RawEventCallback>>,
    _preload_cb: Option<BareFn<'a, RawEventCallback>>,
}

impl<'a> Serialization<'a> {
    /// Create a Serialization wrapper from a raw FFI pointer.
    pub fn from_raw(
        raw: *mut NVSESerializationInterfaceFFI,
    ) -> SerializationResult<Self> {
        let ptr = NonNull::new(raw).ok_or(SerializationError::InterfaceIsNull)?;
        Ok(Self {
            ptr,
            _save_cb: None,
            _load_cb: None,
            _new_game_cb: None,
            _preload_cb: None,
        })
    }

    /// Register a callback invoked when the game is saved.
    ///
    /// Inside the callback, use `write_record()` or `open_record()` +
    /// `write_record_data()` to persist your plugin's data.
    ///
    /// Can only be set once. Returns an error if already registered.
    pub fn set_save_callback<F: Fn() + 'a>(
        &mut self,
        plugin_handle: u32,
        cb: F,
    ) -> SerializationResult<()> {
        if self._save_cb.is_some() {
            log::warn!("Save callback already registered, ignoring duplicate");
            return Ok(());
        }

        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetSaveCallback
            .ok_or(SerializationError::SetSaveCallbackIsNull)?;

        let bare = BareFn::new(move |_: *mut libc::c_void| cb());
        unsafe { set_fn(plugin_handle, Some(bare.bare())) };
        self._save_cb = Some(bare);

        Ok(())
    }

    /// Register a callback invoked when a save is loaded.
    ///
    /// Inside the callback, use `next_record()` and `read_data()` to
    /// restore your plugin's data.
    ///
    /// Can only be set once. Returns an error if already registered.
    pub fn set_load_callback<F: Fn() + 'a>(
        &mut self,
        plugin_handle: u32,
        cb: F,
    ) -> SerializationResult<()> {
        if self._load_cb.is_some() {
            log::warn!("Load callback already registered, ignoring duplicate");
            return Ok(());
        }

        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetLoadCallback
            .ok_or(SerializationError::SetLoadCallbackIsNull)?;

        let bare = BareFn::new(move |_: *mut libc::c_void| cb());
        unsafe { set_fn(plugin_handle, Some(bare.bare())) };
        self._load_cb = Some(bare);

        Ok(())
    }

    /// Register a callback invoked when a new game is started.
    ///
    /// Use this to reset all internal data structures.
    ///
    /// Can only be set once. Returns an error if already registered.
    pub fn set_new_game_callback<F: Fn() + 'a>(
        &mut self,
        plugin_handle: u32,
        cb: F,
    ) -> SerializationResult<()> {
        if self._new_game_cb.is_some() {
            log::warn!("NewGame callback already registered, ignoring duplicate");
            return Ok(());
        }

        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetNewGameCallback
            .ok_or(SerializationError::SetNewGameCallbackIsNull)?;

        let bare = BareFn::new(move |_: *mut libc::c_void| cb());
        unsafe { set_fn(plugin_handle, Some(bare.bare())) };
        self._new_game_cb = Some(bare);

        Ok(())
    }

    /// Register a pre-load callback (invoked before the save is loaded).
    ///
    /// Only register this if you genuinely need to modify objects before
    /// the game loads them. It requires NVSE to parse the co-save twice.
    ///
    /// Can only be set once.
    pub fn set_preload_callback<F: Fn() + 'a>(
        &mut self,
        plugin_handle: u32,
        cb: F,
    ) -> SerializationResult<()> {
        if self._preload_cb.is_some() {
            log::warn!("Preload callback already registered, ignoring duplicate");
            return Ok(());
        }

        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetPreLoadCallback
            .ok_or(SerializationError::SetLoadCallbackIsNull)?;

        let bare = BareFn::new(move |_: *mut libc::c_void| cb());
        unsafe { set_fn(plugin_handle, Some(bare.bare())) };
        self._preload_cb = Some(bare);

        Ok(())
    }

    // -- Writing (use in save callback) --

    /// Write a complete record in one call.
    ///
    /// `record_type` is a 4-byte tag (e.g. `b"DATA"`).
    /// For more complex records, use `open_record()` + `write_data()`.
    pub fn write_record(
        &self,
        record_type: &[u8; 4],
        version: u32,
        data: &[u8],
    ) -> SerializationResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let write_fn = iface
            .WriteRecord
            .ok_or(SerializationError::WriteRecordIsNull)?;

        let type_u32 = u32::from_le_bytes(*record_type);
        let success = unsafe {
            write_fn(
                type_u32,
                version,
                data.as_ptr() as *const libc::c_void,
                data.len() as u32,
            )
        };

        if success {
            Ok(())
        } else {
            Err(SerializationError::WriteFailed)
        }
    }

    /// Open a new record for streaming writes.
    ///
    /// After calling this, use `write_data()` to append data.
    /// The record is automatically closed when `open_record()` is called
    /// again or the save callback returns.
    pub fn open_record(
        &self,
        record_type: &[u8; 4],
        version: u32,
    ) -> SerializationResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let open_fn = iface
            .OpenRecord
            .ok_or(SerializationError::OpenRecordIsNull)?;

        let type_u32 = u32::from_le_bytes(*record_type);
        let success = unsafe { open_fn(type_u32, version) };

        if success {
            Ok(())
        } else {
            Err(SerializationError::OpenFailed)
        }
    }

    /// Write data to the currently open record.
    pub fn write_data(&self, data: &[u8]) -> SerializationResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let write_fn = iface
            .WriteRecordData
            .ok_or(SerializationError::WriteRecordDataIsNull)?;

        let success =
            unsafe { write_fn(data.as_ptr() as *const libc::c_void, data.len() as u32) };

        if success {
            Ok(())
        } else {
            Err(SerializationError::WriteFailed)
        }
    }

    // -- Reading (use in load callback) --

    /// Move to the next record and return its info.
    ///
    /// Returns `Ok(None)` when there are no more records.
    pub fn next_record(&self) -> SerializationResult<Option<RecordInfo>> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_next = iface
            .GetNextRecordInfo
            .ok_or(SerializationError::GetNextRecordInfoIsNull)?;

        let mut type_u32: u32 = 0;
        let mut version: u32 = 0;
        let mut length: u32 = 0;

        let found = unsafe { get_next(&mut type_u32, &mut version, &mut length) };

        if found {
            Ok(Some(RecordInfo {
                record_type: type_u32.to_le_bytes(),
                version,
                length,
            }))
        } else {
            Ok(None)
        }
    }

    /// Read data from the current record into the provided buffer.
    ///
    /// Returns the number of bytes actually read. If this is less than
    /// `buf.len()`, you attempted to read past the end of the record.
    pub fn read_data(&self, buf: &mut [u8]) -> SerializationResult<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let read_fn = iface
            .ReadRecordData
            .ok_or(SerializationError::ReadRecordDataIsNull)?;

        let bytes_read =
            unsafe { read_fn(buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };

        Ok(bytes_read)
    }

    /// Peek at record data without advancing the read position.
    ///
    /// Returns the number of bytes actually read.
    pub fn peek_data(&self, buf: &mut [u8]) -> SerializationResult<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let peek_fn = iface
            .PeekRecordData
            .ok_or(SerializationError::ReadRecordDataIsNull)?;

        let bytes_read =
            unsafe { peek_fn(buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };

        Ok(bytes_read)
    }

    /// Skip N bytes in the current record.
    pub fn skip(&self, bytes: u32) -> SerializationResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        if let Some(skip_fn) = iface.SkipNBytes {
            unsafe { skip_fn(bytes) };
        }
        Ok(())
    }

    // -- Utilities --

    /// Resolve a RefID from a save file to the current load order.
    ///
    /// The upper 8 bits of a RefID encode the owning mod's load order index,
    /// which can change between sessions. This function maps the saved RefID
    /// to the correct current value.
    ///
    /// Returns an error if the owning mod is no longer loaded.
    pub fn resolve_ref_id(&self, saved_ref_id: u32) -> SerializationResult<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let resolve_fn = iface
            .ResolveRefID
            .ok_or(SerializationError::ResolveRefIDIsNull)?;

        let mut resolved: u32 = 0;
        let success = unsafe { resolve_fn(saved_ref_id, &mut resolved) };

        if success {
            Ok(resolved)
        } else {
            Err(SerializationError::RefIdUnresolved(saved_ref_id))
        }
    }

    /// Get the path of the last loaded save file.
    ///
    /// Returns None if no save has been loaded yet or the path is unavailable.
    pub fn save_path(&self) -> Option<&str> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_path = iface.GetSavePath?;

        let ptr = unsafe { get_path() };
        if ptr.is_null() {
            return None;
        }

        let cstr = unsafe { CStr::from_ptr(ptr) };
        cstr.to_str().ok()
    }
}
