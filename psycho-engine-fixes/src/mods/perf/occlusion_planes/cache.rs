//! Persistent cache of generated occlusion planes.
//!
//! Generating planes walks a cell's meshes and triangles, which is the most
//! expensive part of the feature. This cache keeps verified planes keyed by
//! cell so a revisited cell can re-append them without regenerating.
//!
//! The header carries a hash of the active plugin list. If a mod is installed,
//! removed, reordered or updated, the signature changes and the whole cache is
//! discarded, so planes generated for a different load order are never reused.
//! Every plane also stores the `TESForm::refID` of the base form it came from,
//! which binds it to its source plugin for diagnostics and selective
//! invalidation.

use std::collections::HashMap;
use std::fs;
use std::hash::BuildHasherDefault;
use std::path::Path;

use rustc_hash::FxHasher;

type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

use super::contract::{
    DATA_HANDLER_MOD_LIST, DATA_HANDLER_PTR, MOD_INFO_FILE_SIZE_HIGH, MOD_INFO_FILE_SIZE_LOW,
    MOD_INFO_MAX, MOD_INFO_NAME, MOD_INFO_NAME_CAPACITY, TLIST_DATA, TLIST_NEXT,
};
use super::data::CellKey;
use super::raw::{read_ptr, read_ptr_at, read_u8_at, read_u32_at};

const MAGIC: [u8; 4] = *b"PSOC";
/// Cache schema and generator semantics version. Bump it whenever the
/// generated plane set would change for the same meshes, so an updated DLL
/// never reuses planes produced by older extraction logic.
const FORMAT_VERSION: u32 = 9;
/// magic + version + signature; the entry count is read by `Reader`.
const HEADER_LEN: usize = 4 + 4 + 8;
/// position(12) + size(8) + rotation(36) + priority(1) + source(4) + coverage(4)
const PLANE_LEN: usize = 3 * 4 + 2 * 4 + 9 * 4 + 1 + 4 + 4;
/// Sanity bound for a cached plane list, so a corrupt file cannot allocate
/// without limit.
const MAX_PLANES_PER_CELL: usize = 4096;
const MAX_CELLS: usize = 1 << 16;

/// One cached occlusion plane.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CachedPlane {
    pub(super) position: [f32; 3],
    pub(super) size: [f32; 2],
    pub(super) rotation: [f32; 9],
    pub(super) priority: u8,
    pub(super) source_form_id: u32,
    pub(super) coverage: f32,
}

/// Cached planes for one cell plus whether generation settled.
///
/// An entry written before the settle window finished is marked incomplete and
/// is regenerated on the next visit instead of being trusted as a complete set.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct CacheEntry {
    pub(super) planes: Vec<CachedPlane>,
    pub(super) complete: bool,
}

/// Cached planes keyed by cell identity, plus the plugin-list signature they
/// were generated under.
pub(super) struct PlaneCache {
    signature: u64,
    cells: FxHashMap<CellKey, CacheEntry>,
    dirty: bool,
}

impl PlaneCache {
    pub(super) fn empty(signature: u64) -> Self {
        Self {
            signature,
            cells: FxHashMap::default(),
            dirty: false,
        }
    }

    pub(super) fn cell_count(&self) -> usize {
        self.cells.len()
    }

    pub(super) fn get(&self, key: &CellKey) -> Option<&CacheEntry> {
        self.cells.get(key)
    }

    pub(super) fn insert(&mut self, key: CellKey, planes: Vec<CachedPlane>, complete: bool) {
        self.cells.insert(key, CacheEntry { planes, complete });
        self.dirty = true;
    }

    /// Mark an existing entry complete. No-op when the entry is absent.
    pub(super) fn mark_complete(&mut self, key: &CellKey) {
        if let Some(entry) = self.cells.get_mut(key)
            && !entry.complete
        {
            entry.complete = true;
            self.dirty = true;
        }
    }

    /// Re-mark the cache dirty after a snapshot failed to persist, so the next
    /// debounce retries the write instead of silently dropping it.
    pub(super) fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Take the serialized cache and clear the dirty flag. Returns `None` when
    /// there is nothing new to write. The caller owns the bytes.
    pub(super) fn take_snapshot(&mut self) -> Option<Vec<u8>> {
        if !self.dirty {
            return None;
        }
        self.dirty = false;
        Some(self.serialize())
    }

    /// Write a snapshot through a temporary file so a crash cannot leave a
    /// half-written cache behind. `seq` keeps concurrent writers from sharing
    /// the same temporary name.
    pub(super) fn write_snapshot(path: &str, bytes: &[u8], seq: u64) -> std::io::Result<()> {
        if path.is_empty() {
            return Ok(());
        }
        let temporary = format!("{path}.{seq}.tmp");
        fs::write(&temporary, bytes)?;
        let result = fs::rename(&temporary, Path::new(path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Load a cache file. Any magic, version, signature or parse mismatch
    /// yields an empty cache for the current signature.
    pub(super) fn load(path: &str, signature: u64) -> Self {
        if path.is_empty() {
            return Self::empty(signature);
        }
        let Ok(bytes) = fs::read(path) else {
            return Self::empty(signature);
        };
        Self::deserialize(&bytes, signature).unwrap_or_else(|| Self::empty(signature))
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.cells.len() * (32 + PLANE_LEN));
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.signature.to_le_bytes());
        out.extend_from_slice(&(self.cells.len() as u32).to_le_bytes());
        for (key, entry) in &self.cells {
            match key {
                CellKey::Interior { form_id } => {
                    out.push(0);
                    out.extend_from_slice(&form_id.to_le_bytes());
                }
                CellKey::Exterior { worldspace, x, y } => {
                    out.push(1);
                    out.extend_from_slice(&worldspace.to_le_bytes());
                    out.extend_from_slice(&x.to_le_bytes());
                    out.extend_from_slice(&y.to_le_bytes());
                }
            }
            out.push(u8::from(entry.complete));
            out.extend_from_slice(&(entry.planes.len() as u32).to_le_bytes());
            for plane in &entry.planes {
                for value in plane.position {
                    out.extend_from_slice(&value.to_le_bytes());
                }
                for value in plane.size {
                    out.extend_from_slice(&value.to_le_bytes());
                }
                for value in plane.rotation {
                    out.extend_from_slice(&value.to_le_bytes());
                }
                out.push(plane.priority);
                out.extend_from_slice(&plane.source_form_id.to_le_bytes());
                out.extend_from_slice(&plane.coverage.to_le_bytes());
            }
        }
        out
    }

    fn deserialize(bytes: &[u8], signature: u64) -> Option<Self> {
        if bytes.len() < HEADER_LEN + 4 || bytes[0..4] != MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        if version != FORMAT_VERSION {
            return None;
        }
        let file_signature = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        if file_signature != signature {
            return None;
        }
        let mut reader = Reader {
            bytes,
            offset: HEADER_LEN,
        };
        let count = reader.u32()? as usize;
        if count > MAX_CELLS {
            return None;
        }
        let mut cells: FxHashMap<CellKey, CacheEntry> =
            FxHashMap::with_capacity_and_hasher(count.min(4096), Default::default());
        for _ in 0..count {
            let kind = reader.u8()?;
            let key = match kind {
                0 => CellKey::Interior {
                    form_id: reader.u32()?,
                },
                1 => CellKey::Exterior {
                    worldspace: reader.u32()?,
                    x: reader.i32()?,
                    y: reader.i32()?,
                },
                _ => return None,
            };
            let complete = reader.u8()? != 0;
            let plane_count = reader.u32()? as usize;
            if plane_count > MAX_PLANES_PER_CELL {
                return None;
            }
            let mut planes = Vec::with_capacity(plane_count);
            for _ in 0..plane_count {
                let position = [reader.f32()?, reader.f32()?, reader.f32()?];
                let size = [reader.f32()?, reader.f32()?];
                let mut rotation = [0.0f32; 9];
                for value in rotation.iter_mut() {
                    *value = reader.f32()?;
                }
                let priority = reader.u8()?;
                let source_form_id = reader.u32()?;
                let coverage = reader.f32()?;
                planes.push(CachedPlane {
                    position,
                    size,
                    rotation,
                    priority,
                    source_form_id,
                    coverage,
                });
            }
            cells.insert(key, CacheEntry { planes, complete });
        }
        Some(Self {
            signature,
            cells,
            dirty: false,
        })
    }
}

/// Bounds-checked little-endian reader.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Option<&[u8]> {
        let end = self.offset.checked_add(count)?;
        let slice = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|value| value as i32)
    }

    fn f32(&mut self) -> Option<f32> {
        self.u32().map(f32::from_bits)
    }
}

/// Hash the active plugin list (order, names and size hints). A different hash
/// means a different load order or mod content, so the cache is discarded.
pub(super) fn current_mod_signature() -> u64 {
    // Safety: `DataHandler` is created before `DeferredInit`; every read is a
    // bounded volatile read of the engine's own mod list.
    let handler = unsafe { read_ptr(DATA_HANDLER_PTR) };
    if handler.is_null() {
        return 0;
    }
    let list = unsafe { (handler as *mut u8).add(DATA_HANDLER_MOD_LIST) as *mut core::ffi::c_void };
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut node = list;
    let mut count = 0usize;
    loop {
        let info = unsafe { read_ptr_at(node, TLIST_DATA) };
        let next = unsafe { read_ptr_at(node, TLIST_NEXT) };
        if !info.is_null() {
            hash = hash_name(hash, info);
            // Hash the file size from the embedded WIN32_FIND_DATA so an
            // in-place mod update changes the signature, not only a rename.
            hash = mix(hash, unsafe { read_u32_at(info, MOD_INFO_FILE_SIZE_LOW) });
            hash = mix(hash, unsafe { read_u32_at(info, MOD_INFO_FILE_SIZE_HIGH) });
            count += 1;
        }
        if next.is_null() || count > MOD_INFO_MAX {
            break;
        }
        node = next;
    }
    mix(hash, count as u32)
}

fn hash_name(mut hash: u64, info: *mut core::ffi::c_void) -> u64 {
    for index in 0..MOD_INFO_NAME_CAPACITY.saturating_sub(1) {
        let byte = unsafe { read_u8_at(info, MOD_INFO_NAME + index) };
        if byte == 0 {
            break;
        }
        hash = mix(hash, u32::from(byte));
    }
    hash
}

/// Fold generation-affecting configuration into the cache signature, so
/// changing the per-cell cap discards cached sets generated under the old cap.
pub(super) fn config_signature(base: u64, max_per_cell: usize) -> u64 {
    let hash = mix(base, max_per_cell as u32);
    let generation = super::runtime_generate::generation_signature();
    let mut hash = hash;
    for byte in generation.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn mix(mut hash: u64, value: u32) -> u64 {
    for byte in value.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plane(x: f32) -> CachedPlane {
        CachedPlane {
            position: [x, 1.0, 2.0],
            size: [10.0, 20.0],
            rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            priority: 200,
            source_form_id: 0x000A_1234,
            coverage: 0.75,
        }
    }

    #[test]
    fn cache_round_trip_preserves_planes_and_rejects_other_signatures() {
        let interior = CellKey::Interior { form_id: 0x1234 };
        let exterior = CellKey::Exterior {
            worldspace: 0x3C,
            x: -3,
            y: -12,
        };
        let mut cache = PlaneCache::empty(0xDEAD_BEEF);
        cache.insert(interior, vec![plane(1.0)], true);
        cache.insert(exterior, vec![plane(2.0), plane(3.0)], false);
        let bytes = cache.serialize();
        let decoded = PlaneCache::deserialize(&bytes, 0xDEAD_BEEF).expect("same signature");
        assert_eq!(decoded.get(&interior).unwrap().planes, &[plane(1.0)]);
        assert!(decoded.get(&interior).unwrap().complete);
        assert_eq!(decoded.get(&exterior).unwrap().planes.len(), 2);
        assert!(!decoded.get(&exterior).unwrap().complete);
        assert!(
            PlaneCache::deserialize(&bytes, 0x1111).is_none(),
            "a different plugin signature must discard the cache"
        );
    }

    #[test]
    fn cache_rejects_corrupt_input() {
        assert!(PlaneCache::deserialize(b"nope", 0).is_none());
        let mut cache = PlaneCache::empty(7);
        cache.insert(CellKey::Interior { form_id: 1 }, vec![plane(1.0)], true);
        let mut bytes = cache.serialize();
        bytes.truncate(bytes.len() - 3);
        assert!(
            PlaneCache::deserialize(&bytes, 7).is_none(),
            "a truncated file must be rejected"
        );
    }
}
