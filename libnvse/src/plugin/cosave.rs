//! Typed co-save serialization for the high-level API.
//!
//! Provides `SaveWriter` and `LoadReader` that work with standard Rust
//! types instead of raw byte buffers.

/// Writes plugin data during a save callback.
///
/// Wraps the low-level serialization interface with convenient methods
/// for writing Rust types.
///
/// # Example
///
/// ```no_run
/// fn on_save(writer: &SaveWriter) {
///     writer.write(b"CONF", 1, |w| {
///         w.write_u32(my_config.threshold)?;
///         w.write_bool(my_config.enabled)?;
///         w.write_string(&my_config.name)?;
///         Ok(())
///     })?;
/// }
/// ```
pub struct SaveWriter<'a> {
    ser: &'a crate::api::serialization::Serialization<'a>,
}

impl<'a> SaveWriter<'a> {
    pub(crate) fn new(ser: &'a crate::api::serialization::Serialization<'a>) -> Self {
        Self { ser }
    }

    /// Write a complete record with a builder callback.
    ///
    /// Opens a record, calls your writer function, then the record
    /// is automatically closed.
    pub fn write<F>(&self, tag: &[u8; 4], version: u32, f: F) -> Result<(), SaveError>
    where
        F: FnOnce(&RecordWriter<'_>) -> Result<(), SaveError>,
    {
        self.ser.open_record(tag, version)?;
        let writer = RecordWriter { ser: self.ser };
        f(&writer)
    }

    /// Write a complete record from a byte slice (simple case).
    pub fn write_bytes(
        &self,
        tag: &[u8; 4],
        version: u32,
        data: &[u8],
    ) -> Result<(), SaveError> {
        self.ser.write_record(tag, version, data)?;
        Ok(())
    }
}

/// Writes individual fields within an open record.
pub struct RecordWriter<'a> {
    ser: &'a crate::api::serialization::Serialization<'a>,
}

impl RecordWriter<'_> {
    /// Write raw bytes.
    pub fn write_raw(&self, data: &[u8]) -> Result<(), SaveError> {
        self.ser.write_data(data)?;
        Ok(())
    }

    /// Write a u8.
    pub fn write_u8(&self, val: u8) -> Result<(), SaveError> {
        self.write_raw(&[val])
    }

    /// Write a u16 (little-endian).
    pub fn write_u16(&self, val: u16) -> Result<(), SaveError> {
        self.write_raw(&val.to_le_bytes())
    }

    /// Write a u32 (little-endian).
    pub fn write_u32(&self, val: u32) -> Result<(), SaveError> {
        self.write_raw(&val.to_le_bytes())
    }

    /// Write a u64 (little-endian).
    pub fn write_u64(&self, val: u64) -> Result<(), SaveError> {
        self.write_raw(&val.to_le_bytes())
    }

    /// Write an i32 (little-endian).
    pub fn write_i32(&self, val: i32) -> Result<(), SaveError> {
        self.write_raw(&val.to_le_bytes())
    }

    /// Write an f32 (little-endian).
    pub fn write_f32(&self, val: f32) -> Result<(), SaveError> {
        self.write_raw(&val.to_le_bytes())
    }

    /// Write an f64 (little-endian).
    pub fn write_f64(&self, val: f64) -> Result<(), SaveError> {
        self.write_raw(&val.to_le_bytes())
    }

    /// Write a bool (1 byte: 0 or 1).
    pub fn write_bool(&self, val: bool) -> Result<(), SaveError> {
        self.write_u8(if val { 1 } else { 0 })
    }

    /// Write a length-prefixed string (u32 length + UTF-8 bytes).
    pub fn write_string(&self, val: &str) -> Result<(), SaveError> {
        let bytes = val.as_bytes();
        self.write_u32(bytes.len() as u32)?;
        self.write_raw(bytes)
    }

    /// Write a FormId (as u32).
    pub fn write_form_id(&self, id: super::types::FormId) -> Result<(), SaveError> {
        self.write_u32(id.raw())
    }
}

/// Reads plugin data during a load callback.
///
/// # Example
///
/// ```no_run
/// fn on_load(reader: &mut LoadReader) {
///     while let Some(record) = reader.next_record()? {
///         match &record.tag {
///             b"CONF" => {
///                 let threshold = reader.read_u32()?;
///                 let enabled = reader.read_bool()?;
///                 let name = reader.read_string()?;
///             }
///             _ => reader.skip(record.length)?,
///         }
///     }
/// }
/// ```
pub struct LoadReader<'a> {
    ser: &'a crate::api::serialization::Serialization<'a>,
}

impl<'a> LoadReader<'a> {
    pub(crate) fn new(ser: &'a crate::api::serialization::Serialization<'a>) -> Self {
        Self { ser }
    }

    /// Advance to the next record.
    ///
    /// Returns `Ok(None)` when all records have been read.
    pub fn next_record(&self) -> Result<Option<Record>, SaveError> {
        match self.ser.next_record()? {
            Some(info) => Ok(Some(Record {
                tag: info.record_type,
                version: info.version,
                length: info.length,
            })),
            None => Ok(None),
        }
    }

    /// Read raw bytes into a new Vec.
    pub fn read_bytes(&self, count: u32) -> Result<Vec<u8>, SaveError> {
        let mut buf = vec![0u8; count as usize];
        let read = self.ser.read_data(&mut buf)?;
        buf.truncate(read as usize);
        Ok(buf)
    }

    /// Read a u8.
    pub fn read_u8(&self) -> Result<u8, SaveError> {
        let mut buf = [0u8; 1];
        self.ser.read_data(&mut buf)?;
        Ok(buf[0])
    }

    /// Read a u16 (little-endian).
    pub fn read_u16(&self) -> Result<u16, SaveError> {
        let mut buf = [0u8; 2];
        self.ser.read_data(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Read a u32 (little-endian).
    pub fn read_u32(&self) -> Result<u32, SaveError> {
        let mut buf = [0u8; 4];
        self.ser.read_data(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a u64 (little-endian).
    pub fn read_u64(&self) -> Result<u64, SaveError> {
        let mut buf = [0u8; 8];
        self.ser.read_data(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read an i32 (little-endian).
    pub fn read_i32(&self) -> Result<i32, SaveError> {
        let mut buf = [0u8; 4];
        self.ser.read_data(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    /// Read an f32 (little-endian).
    pub fn read_f32(&self) -> Result<f32, SaveError> {
        let mut buf = [0u8; 4];
        self.ser.read_data(&mut buf)?;
        Ok(f32::from_le_bytes(buf))
    }

    /// Read an f64 (little-endian).
    pub fn read_f64(&self) -> Result<f64, SaveError> {
        let mut buf = [0u8; 8];
        self.ser.read_data(&mut buf)?;
        Ok(f64::from_le_bytes(buf))
    }

    /// Read a bool (1 byte: nonzero = true).
    pub fn read_bool(&self) -> Result<bool, SaveError> {
        Ok(self.read_u8()? != 0)
    }

    /// Read a length-prefixed string (u32 length + UTF-8 bytes).
    pub fn read_string(&self) -> Result<String, SaveError> {
        let len = self.read_u32()?;
        if len > 1_048_576 {
            // Sanity check: reject strings > 1MB
            return Err(SaveError::DataCorrupted(format!(
                "String length {} exceeds 1MB limit",
                len
            )));
        }
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes).map_err(|_| SaveError::InvalidUtf8)
    }

    /// Read a FormId (u32) and resolve it to the current load order.
    pub fn read_form_id(&self) -> Result<super::types::FormId, SaveError> {
        let raw = self.read_u32()?;
        let resolved = self.ser.resolve_ref_id(raw)?;
        Ok(super::types::FormId::new(resolved))
    }

    /// Read a raw FormId without load-order resolution.
    ///
    /// Only use this for IDs that don't come from plugin forms
    /// (e.g., dynamically created runtime refs).
    pub fn read_form_id_raw(&self) -> Result<super::types::FormId, SaveError> {
        let raw = self.read_u32()?;
        Ok(super::types::FormId::new(raw))
    }

    /// Skip bytes in the current record.
    pub fn skip(&self, count: u32) -> Result<(), SaveError> {
        self.ser.skip(count)?;
        Ok(())
    }
}

/// Metadata for a single record in a co-save file.
#[derive(Debug, Clone)]
pub struct Record {
    /// 4-byte type tag (e.g. `b"DATA"`).
    pub tag: [u8; 4],
    /// Record format version.
    pub version: u32,
    /// Length of record data in bytes.
    pub length: u32,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during save/load operations.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] crate::api::serialization::SerializationError),

    #[error("Save data appears corrupted: {0}")]
    DataCorrupted(String),

    #[error("String data is not valid UTF-8")]
    InvalidUtf8,
}
