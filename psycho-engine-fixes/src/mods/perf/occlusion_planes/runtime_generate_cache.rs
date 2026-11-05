//! Content-validated local mesh analysis. Native capture supplies owned finite
//! vertex/index values; every hit checks the complete input after hash lookup.
//! No native address, world transform, material decision or source FormID is
//! cached here. Snapshots and retained surfaces share the owner's existing
//! vertex/triangle budget. Only the main-frame generator acquires this pool.
use super::*;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io::{self, Read};

#[path = "runtime_generate_cache_io.rs"]
mod io_writer;
use io_writer::{CacheWriter, Checkpoint};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};

/// Local support/coverage result, independent of instance transform and scale.
#[derive(Clone, Copy)]
pub(super) enum LocalFace {
    Unsupported,
    Opening,
    Rectangle {
        center_u: f32,
        center_v: f32,
        half_u: f32,
        half_v: f32,
        coverage: f32,
    },
}

#[derive(Default)]
struct Accounting {
    vertices: AtomicUsize,
    triangles: AtomicUsize,
}

/// Shared immutable input with lazily computed local face footprints.
pub(super) struct Surface {
    pub(super) local: Aabb,
    pub(super) vertices: Box<[[f32; 3]]>,
    pub(super) triangles: Box<[[u16; 3]]>,
    pub(super) faces: [OnceLock<LocalFace>; 6],
    /// Separate tiny token lets world provenance retain a weak identity without
    /// keeping the much larger Surface allocation after decoded data is evicted.
    pub(super) identity: Arc<()>,
    fingerprint: u64,
    accounting: Arc<Accounting>,
}

impl Drop for Surface {
    fn drop(&mut self) {
        self.accounting
            .vertices
            .fetch_sub(self.vertices.len(), Ordering::Relaxed);
        self.accounting
            .triangles
            .fetch_sub(self.triangles.len(), Ordering::Relaxed);
    }
}

/// Hashing accelerates lookup only. Complete input equality below is mandatory.
fn fingerprint(vertices: &[[f32; 3]], triangles: &[[u16; 3]]) -> u64 {
    use std::hash::Hasher;
    // This is only a resident lookup accelerator, not the persisted checksum
    // or semantic identity. Native-width arithmetic avoids a serial 64-bit
    // multiply for every coordinate/index on the supported 32-bit target.
    let mut hash = rustc_hash::FxHasher::default();
    hash.write_usize(vertices.len());
    hash.write_usize(triangles.len());
    for value in vertices.iter().flatten() {
        hash.write_u32(value.to_bits());
    }
    for value in triangles.iter().flatten() {
        hash.write_u16(*value);
    }
    hash.finish()
}

/// Resident LRU entries are expendable; active snapshots retain their inputs.
/// Aggregate allocation accounting includes entries already evicted from LRU
/// while still owned by a snapshot. Metadata count uses the existing reference
/// limit; eviction affects reuse, never geometry admission or emitted coverage.
pub(super) struct SurfacePool {
    entries: VecDeque<Arc<Surface>>,
    accounting: Arc<Accounting>,
}

impl SurfacePool {
    /// Empty residency with accounting shared by every retained snapshot.
    pub(super) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            accounting: Arc::new(Accounting::default()),
        }
    }

    /// Intern complete admitted input or return None if strong owners prevent
    /// admission within the shared limits. The caller still owns its input.
    pub(super) fn capture(
        &mut self,
        local: Aabb,
        vertices: &[[f32; 3]],
        triangles: &[[u16; 3]],
    ) -> Option<Arc<Surface>> {
        let hash = fingerprint(vertices, triangles);
        if let Some(index) = self.entries.iter().position(|entry| {
            entry.fingerprint == hash
                && entry.vertices.len() == vertices.len()
                && entry.triangles.as_ref() == triangles
                && entry
                    .vertices
                    .iter()
                    .flatten()
                    .zip(vertices.iter().flatten())
                    .all(|(a, b)| a.to_bits() == b.to_bits())
        }) {
            // position was found in this owned deque with no intervening mutation.
            let entry = self.entries.remove(index)?;
            self.entries.push_front(entry.clone());
            return Some(entry);
        }
        if vertices.len() > VERTEX_BUDGET || triangles.len() > TRIANGLE_BUDGET {
            return None;
        }
        loop {
            let fits = self.accounting.vertices.load(Ordering::Relaxed)
                <= VERTEX_BUDGET - vertices.len()
                && self.accounting.triangles.load(Ordering::Relaxed)
                    <= TRIANGLE_BUDGET - triangles.len();
            if fits && self.entries.len() < MAX_REFS {
                break;
            }
            // Production owns one generation; its admitted input fits the same
            // budgets. Old cache entries have no other strong owner. A caller
            // retaining additional jobs must retry rather than exceed the cap.
            drop(self.entries.pop_back()?);
        }
        self.accounting
            .vertices
            .fetch_add(vertices.len(), Ordering::Relaxed);
        self.accounting
            .triangles
            .fetch_add(triangles.len(), Ordering::Relaxed);
        let entry = Arc::new(Surface {
            local,
            vertices: vertices.into(),
            triangles: triangles.into(),
            faces: std::array::from_fn(|_| OnceLock::new()),
            identity: Arc::new(()),
            fingerprint: hash,
            accounting: self.accounting.clone(),
        });
        self.entries.push_front(entry.clone());
        mark_dirty();
        Some(entry)
    }
}

static POOL: OnceLock<Mutex<SurfacePool>> = OnceLock::new();

/// First touched during admitted capture, after DeferredInit. Returned input
/// is Rust-owned; the pool lock is released before coverage analysis runs.
pub(super) fn capture(
    local: Aabb,
    vertices: &[[f32; 3]],
    triangles: &[[u16; 3]],
) -> Option<Arc<Surface>> {
    POOL.get_or_init(|| Mutex::new(SurfacePool::new()))
        .lock()
        .capture(local, vertices, triangles)
}

// Cache revision 11 stores content-validated local analysis, not world-space
// placements. Old PSOC versions are deliberately rejected at the same path.
const VERSION: u32 = 11;
const HEADER: usize = 20;
const MAX_FILE: usize =
    HEADER + VERTEX_BUDGET * 12 + TRIANGLE_BUDGET * 6 + MAX_REFS * (8 + 1 + 6 * 21 + 8);
static DIRTY: AtomicBool = AtomicBool::new(false);
static REVISION: AtomicU64 = AtomicU64::new(0);
static WRITING: AtomicBool = AtomicBool::new(false);
static SAVE: Mutex<Option<SaveWork>> = Mutex::new(None);
static IO_WRITER: OnceLock<Option<CacheWriter>> = OnceLock::new();

/// Mark a newly computed local footprint for eventual persistence.
pub(super) fn mark_dirty() {
    REVISION.fetch_add(1, Ordering::Relaxed);
    DIRTY.store(true, Ordering::Release);
}

fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// Bounds come from the actual local input, without an invented tolerance.
/// A runtime footprint that cannot be represented within these finite bounds
/// is simply recomputed after reload; it must not poison the whole checkpoint.
fn valid_face(face: usize, local: &Aabb, footprint: &LocalFace) -> bool {
    match *footprint {
        LocalFace::Unsupported | LocalFace::Opening => true,
        LocalFace::Rectangle {
            center_u,
            center_v,
            half_u,
            half_v,
            coverage,
        } => {
            let a = (face / 2 + 1) % 3;
            let b = (face / 2 + 2) % 3;
            [center_u, center_v, half_u, half_v, coverage]
                .iter()
                .all(|v| v.is_finite())
                && half_u > 0.0
                && half_v > 0.0
                && (0.0..=1.0).contains(&coverage)
                && center_u - half_u >= local.min[a]
                && center_u + half_u <= local.max[a]
                && center_v - half_v >= local.min[b]
                && center_v + half_v <= local.max[b]
        }
    }
}

fn encode(entry: &Surface) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(8 + entry.vertices.len() * 12 + entry.triangles.len() * 6 + 135);
    out.extend_from_slice(&(entry.vertices.len() as u32).to_le_bytes());
    out.extend_from_slice(&(entry.triangles.len() as u32).to_le_bytes());
    for value in entry.vertices.iter().flatten() {
        out.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    for value in entry.triangles.iter().flatten() {
        out.extend_from_slice(&value.to_le_bytes());
    }
    let faces: [Option<&LocalFace>; 6] = std::array::from_fn(|i| {
        entry.faces[i]
            .get()
            .filter(|f| valid_face(i, &entry.local, f))
    });
    let mask = faces
        .iter()
        .enumerate()
        .fold(0u8, |m, (i, f)| m | (u8::from(f.is_some()) << i));
    out.push(mask);
    for face in faces {
        match face {
            None => {}
            Some(LocalFace::Unsupported) => out.push(0),
            Some(LocalFace::Opening) => out.push(1),
            Some(LocalFace::Rectangle {
                center_u,
                center_v,
                half_u,
                half_v,
                coverage,
            }) => {
                out.push(2);
                for value in [center_u, center_v, half_u, half_v, coverage] {
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
    }
    let digest = checksum(&out);
    out.extend_from_slice(&digest.to_le_bytes());
    out
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid local occlusion cache")
}

struct Input<R> {
    reader: R,
    bytes: Vec<u8>,
}
impl<R: Read> Input<R> {
    fn take<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut value = [0; N];
        self.reader.read_exact(&mut value)?;
        self.bytes.extend_from_slice(&value);
        Ok(value)
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn float(&mut self) -> io::Result<f32> {
        let value = f32::from_bits(self.u32()?);
        if value.is_finite() {
            Ok(value)
        } else {
            Err(invalid())
        }
    }
}

/// Decode through a bounded streaming reader. Metadata limits and aggregate
/// input counts are checked before arrays are allocated. A hash checks record
/// integrity only; live geometry still requires complete input equality.
fn decode<R: Read>(reader: R) -> io::Result<SurfacePool> {
    let mut input = Input {
        reader,
        bytes: Vec::new(),
    };
    if &input.take::<4>()? != b"PSOC" || input.u32()? != VERSION {
        return Err(invalid());
    }
    if u64::from_le_bytes(input.take()?) != generation_signature() {
        return Err(invalid());
    }
    let count = input.u32()? as usize;
    if count > MAX_REFS {
        return Err(invalid());
    }
    let mut pool = SurfacePool::new();
    let (mut vertices_total, mut triangles_total) = (0usize, 0usize);
    for _ in 0..count {
        input.bytes.clear();
        let vc = input.u32()? as usize;
        let tc = input.u32()? as usize;
        if vc == 0 || vc > MAX_VERTICES_PER_MESH || tc == 0 || tc > MAX_TRIANGLES_PER_MESH {
            return Err(invalid());
        }
        vertices_total = vertices_total.checked_add(vc).ok_or_else(invalid)?;
        triangles_total = triangles_total.checked_add(tc).ok_or_else(invalid)?;
        if vertices_total > VERTEX_BUDGET || triangles_total > TRIANGLE_BUDGET {
            return Err(invalid());
        }
        let mut vertices = Vec::with_capacity(vc);
        for _ in 0..vc {
            vertices.push([input.float()?, input.float()?, input.float()?]);
        }
        let mut triangles = Vec::with_capacity(tc);
        for _ in 0..tc {
            let t = [
                u16::from_le_bytes(input.take()?),
                u16::from_le_bytes(input.take()?),
                u16::from_le_bytes(input.take()?),
            ];
            if t.iter().any(|i| usize::from(*i) >= vc) {
                return Err(invalid());
            }
            triangles.push(t);
        }
        let mask = input.take::<1>()?[0];
        if mask & !0x3f != 0 {
            return Err(invalid());
        }
        let faces: [OnceLock<LocalFace>; 6] = std::array::from_fn(|_| OnceLock::new());
        let local = finite_aabb_of(&vertices);
        for (i, slot) in faces.iter().enumerate() {
            if mask & (1 << i) == 0 {
                continue;
            }
            let face = match input.take::<1>()?[0] {
                0 => LocalFace::Unsupported,
                1 => LocalFace::Opening,
                2 => {
                    let (center_u, center_v, half_u, half_v, coverage) = (
                        input.float()?,
                        input.float()?,
                        input.float()?,
                        input.float()?,
                        input.float()?,
                    );
                    LocalFace::Rectangle {
                        center_u,
                        center_v,
                        half_u,
                        half_v,
                        coverage,
                    }
                }
                _ => return Err(invalid()),
            };
            if !valid_face(i, &local, &face) {
                return Err(invalid());
            }
            let _ = slot.set(face);
        }
        let digest = checksum(&input.bytes);
        if u64::from_le_bytes(input.take()?) != digest {
            return Err(invalid());
        }
        // Move decoded arrays into ownership without temporarily duplicating a
        // full record beside the bounded decoded pool. Aggregate counts above
        // include duplicate records too; none can evade the budget by interning.
        let fingerprint = fingerprint(&vertices, &triangles);
        pool.accounting
            .vertices
            .fetch_add(vertices.len(), Ordering::Relaxed);
        pool.accounting
            .triangles
            .fetch_add(triangles.len(), Ordering::Relaxed);
        pool.entries.push_front(Arc::new(Surface {
            local,
            vertices: vertices.into_boxed_slice(),
            triangles: triangles.into_boxed_slice(),
            faces,
            identity: Arc::new(()),
            fingerprint,
            accounting: pool.accounting.clone(),
        }));
    }
    let mut extra = [0];
    if input.reader.read(&mut extra)? != 0 {
        return Err(invalid());
    }
    Ok(pool)
}

/// Load at DeferredInit, before native capture can create the pool. Invalid or
/// older files are cache misses; no world-space placement is trusted from disk.
pub(super) fn load(path: &str) {
    // Reader and writer share one owned absolute destination. Resolve only at
    // DeferredInit, never during pre-CRT configuration or individual frames.
    let destination = if path.is_empty() {
        None
    } else {
        match std::path::absolute(path) {
            Ok(path) => Some(path),
            Err(error) => {
                log::warn!(
                    "[OCCLUSION_PLANES] Cache path unavailable; analysis stays in memory: {error}"
                );
                None
            }
        }
    };
    let pool = destination
        .as_ref()
        .and_then(|path| std::fs::File::open(path).ok())
        .and_then(|file| {
            if file.metadata().ok()?.len() > MAX_FILE as u64 {
                return None;
            }
            decode(std::io::BufReader::new(file)).ok()
        });
    let _ = POOL.set(Mutex::new(pool.unwrap_or_else(SurfacePool::new)));
    DIRTY.store(false, Ordering::Release);
    let writer = destination
        .as_ref()
        .and_then(|path| match CacheWriter::new(path) {
            Ok(writer) => Some(writer),
            Err(error) => {
                log::warn!(
                    "[OCCLUSION_PLANES] Cache writer unavailable; analysis stays in memory: {error}"
                );
                None
            }
        });
    let _ = IO_WRITER.set(writer);
}

/// Frame-side serialization only. No filesystem operation, worker wait or
/// additional decoded pool occurs here; one bounded record is encoded per call.
struct SaveWork {
    entries: std::vec::IntoIter<Weak<Surface>>,
    bytes: Vec<u8>,
    count: u32,
    revision: u64,
    encoded: bool,
}

impl SaveWork {
    fn new(pool: &SurfacePool) -> io::Result<Self> {
        // Reserve one bounded upper size from resident inputs, avoiding repeated
        // whole-buffer growth/copies on the frame thread. Future face results
        // fit the six-footprint allowance even if computed during preparation.
        let capacity = pool
            .entries
            .iter()
            .try_fold(HEADER, |size, entry| {
                size.checked_add(
                    8 + entry.vertices.len() * 12 + entry.triangles.len() * 6 + 1 + 6 * 21 + 8,
                )
            })
            .filter(|size| *size <= MAX_FILE)
            .ok_or_else(invalid)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        bytes.extend_from_slice(b"PSOC");
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&generation_signature().to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        Ok(Self {
            entries: pool
                .entries
                .iter()
                .map(Arc::downgrade)
                .collect::<Vec<_>>()
                .into_iter(),
            bytes,
            count: 0,
            revision: REVISION.load(Ordering::Relaxed),
            encoded: false,
        })
    }

    fn advance(&mut self) -> io::Result<bool> {
        if self.encoded {
            return Ok(true);
        }
        if let Some(entry) = self.entries.next() {
            if let Some(entry) = entry.upgrade() {
                let record = encode(&entry);
                if self
                    .bytes
                    .len()
                    .checked_add(record.len())
                    .is_none_or(|size| size > MAX_FILE)
                {
                    return Err(invalid());
                }
                self.bytes.extend_from_slice(&record);
                self.count += 1;
            }
            return Ok(false);
        }
        self.bytes[16..20].copy_from_slice(&self.count.to_le_bytes());
        self.encoded = true;
        Ok(true)
    }

    fn finish(self) -> io::Result<Checkpoint> {
        if !self.encoded {
            return Err(invalid());
        }
        Ok(Checkpoint {
            bytes: self.bytes,
            revision: self.revision,
        })
    }
}

/// Prepare on cold requests in idle frames. While the one writer runs, a frame
/// takes atomics only. All create/write/sync/rename/cleanup runs on that worker.
pub(super) fn save_step(path: &str, request: bool) -> io::Result<()> {
    if path.is_empty()
        || (!WRITING.load(Ordering::Acquire) && !(request && DIRTY.load(Ordering::Acquire)))
    {
        return Ok(());
    }
    let writer = IO_WRITER
        .get()
        .and_then(Option::as_ref)
        .ok_or_else(|| io::Error::other("local analysis writer unavailable"))?;
    if writer.busy() {
        return Ok(());
    }
    if let Some(result) = writer.take_result() {
        WRITING.store(false, Ordering::Release);
        if let Some(error) = result.error {
            DIRTY.store(true, Ordering::Release);
            return Err(error);
        }
        if result.revision == REVISION.load(Ordering::Relaxed) {
            DIRTY.store(false, Ordering::Release);
        }
        return Ok(());
    }
    let mut save = SAVE.lock();
    if save.is_none() {
        let Some(pool) = POOL.get() else {
            return Ok(());
        };
        *save = Some(SaveWork::new(&pool.lock())?);
        WRITING.store(true, Ordering::Release);
    }
    let result = save.as_mut().ok_or_else(invalid)?.advance();
    match result {
        Ok(false) => Ok(()),
        Ok(true) => {
            let checkpoint = save.take().ok_or_else(invalid)?.finish()?;
            drop(save);
            if let Err(error) = writer.submit(checkpoint) {
                WRITING.store(false, Ordering::Release);
                DIRTY.store(true, Ordering::Release);
                return Err(error);
            }
            Ok(())
        }
        Err(error) => {
            save.take();
            WRITING.store(false, Ordering::Release);
            DIRTY.store(true, Ordering::Release);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actual() -> (SurfacePool, Arc<Surface>) {
        let (vertices, triangles) = super::super::surface_tests::mesh();
        let mut pool = SurfacePool::new();
        let surface = pool
            .capture(aabb_of(&vertices), &vertices, &triangles)
            .unwrap();
        // Execute the production local analysis, including faces that would be
        // horizontal for one instance but visible after another rigid rotation.
        for face in 0..6 {
            let result = local_face(
                &surface.local,
                &vertices,
                &triangles,
                face,
                &mut Vec::new(),
                &mut Vec::new(),
                &mut Vec::new(),
                &mut CoverageScratch::default(),
            );
            surface.faces[face].set(result).ok().unwrap();
        }
        (pool, surface)
    }

    fn encoded(surface: &Surface) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PSOC");
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&generation_signature().to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&encode(surface));
        bytes
    }

    fn extract(surface: &Surface, world: &WorldTransform, cached: bool) -> Vec<PlaneRecord> {
        let mut planes = Vec::new();
        faces_in_range(
            &surface.local,
            world,
            &surface.vertices,
            &surface.triangles,
            &mut planes,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut Vec::new(),
            &mut CoverageScratch::default(),
            0..6,
            cached.then_some(surface),
        );
        planes.into_iter().map(|(_, plane)| plane).collect()
    }

    #[test]
    fn actual_mesh_analysis_roundtrip_preserves_transformed_planes() {
        let (_pool, surface) = actual();
        let bytes = encoded(&surface);
        let decoded = decode(bytes.as_slice()).unwrap();
        let restored = decoded.entries.front().unwrap();
        assert_eq!(restored.vertices, surface.vertices);
        assert_eq!(restored.triangles, surface.triangles);
        // Axis permutations exercise every local face. Mirroring and scale stay
        // at the instance boundary and must not be baked into cached footprints.
        for rotation in [
            [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            [0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0],
            [0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0],
        ] {
            for scale in [-2.0, -1.0, 1.0, 2.0] {
                let world = WorldTransform {
                    rotation,
                    translation: [2048.0, -4096.0, 128.0],
                    scale,
                };
                let direct = extract(&surface, &world, false);
                let reused = extract(restored, &world, true);
                assert_eq!(
                    super::super::super::runtime::plane_signature(&direct),
                    super::super::super::runtime::plane_signature(&reused)
                );
            }
        }
    }

    #[test]
    fn actual_cache_rejects_legacy_invalid_numeric_index_and_truncated_data() {
        assert!(
            decode(include_bytes!("fixtures/pre_surface_correction.cache").as_slice()).is_err()
        );
        let (_pool, surface) = actual();
        let bytes = encoded(&surface);
        assert!(decode(bytes.as_slice()).is_ok());
        for prefix in [0, HEADER - 1, HEADER + 8, bytes.len() - 1] {
            assert!(decode(&bytes[..prefix]).is_err());
        }
        // Change actual encoded fields; update the checksum so numeric/index
        // validation, rather than the integrity guard, must reject them.
        for (offset, value) in [
            (HEADER + 8, f32::NAN.to_bits()),
            (HEADER + 8, f32::INFINITY.to_bits()),
            (HEADER, (MAX_VERTICES_PER_MESH + 1) as u32),
        ] {
            let mut invalid = bytes.clone();
            invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            let end = invalid.len() - 8;
            let digest = checksum(&invalid[HEADER..end]);
            invalid[end..].copy_from_slice(&digest.to_le_bytes());
            assert!(decode(invalid.as_slice()).is_err());
        }
        let mut invalid = bytes.clone();
        let index = HEADER + 8 + surface.vertices.len() * 12;
        invalid[index..index + 2].copy_from_slice(&(surface.vertices.len() as u16).to_le_bytes());
        let end = invalid.len() - 8;
        let digest = checksum(&invalid[HEADER..end]);
        invalid[end..].copy_from_slice(&digest.to_le_bytes());
        assert!(decode(invalid.as_slice()).is_err());
        let mut invalid = bytes.clone();
        invalid[8] ^= 1;
        assert!(decode(invalid.as_slice()).is_err());
        let mut invalid = bytes;
        invalid.push(0);
        assert!(decode(invalid.as_slice()).is_err());
    }

    #[test]
    fn actual_input_reuse_compares_content_and_budget_includes_evicted_owners() {
        let (mut pool, surface) = actual();
        let same = pool
            .capture(surface.local, &surface.vertices, &surface.triangles)
            .unwrap();
        assert!(Arc::ptr_eq(&surface, &same));
        let mut moved = surface.vertices.to_vec();
        for point in &mut moved {
            point[0] += 128.0;
        }
        let changed = pool
            .capture(aabb_of(&moved), &moved, &surface.triangles)
            .unwrap();
        assert!(!Arc::ptr_eq(&surface, &changed));
        let before = pool.accounting.vertices.load(Ordering::Relaxed);
        pool.entries.clear();
        assert_eq!(pool.accounting.vertices.load(Ordering::Relaxed), before);
        drop(surface);
        drop(same);
        drop(changed);
        assert_eq!(pool.accounting.vertices.load(Ordering::Relaxed), 0);
        assert_eq!(pool.accounting.triangles.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn actual_content_survives_a_lookup_collision() {
        let (mut pool, original) = actual();
        let mut moved = original.vertices.to_vec();
        moved[0][0] += 128.0;
        let triangles = original.triangles.to_vec();
        drop(original);
        // Force a resident hash collision without changing the actual arrays.
        Arc::get_mut(pool.entries.front_mut().unwrap())
            .unwrap()
            .fingerprint = fingerprint(&moved, &triangles);
        let original = pool.entries[0].clone();
        let changed = pool
            .capture(finite_aabb_of(&moved), &moved, &triangles)
            .unwrap();
        assert!(!Arc::ptr_eq(&changed, &original));
        assert!(Arc::ptr_eq(
            &changed,
            &pool.capture(changed.local, &moved, &triangles).unwrap()
        ));
    }

    #[test]
    fn worker_checkpoint_replaces_and_preserves_old_on_failure() {
        use std::os::windows::fs::OpenOptionsExt;
        let (pool, _surface) = actual();
        let directory = std::env::temp_dir().join(format!(
            "psycho-cache-worker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache");
        std::fs::write(&path, b"old").unwrap();
        let writer = CacheWriter::new(&path).unwrap();
        let prepare = || {
            let mut work = SaveWork::new(&pool).unwrap();
            while !work.advance().unwrap() {}
            work.finish().unwrap()
        };
        let wait = || {
            let started = std::time::Instant::now();
            loop {
                if let Some(result) = writer.take_result() {
                    break result;
                }
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "real file writer did not finish"
                );
                std::thread::yield_now();
            }
        };
        writer.submit(prepare()).unwrap();
        assert_eq!(
            writer.submit(prepare()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "a second checkpoint must wait until completion is consumed"
        );
        let result = wait();
        assert!(result.error.is_none());
        assert_ne!(
            result.thread,
            std::thread::current().id(),
            "filesystem work ran on sender thread"
        );
        assert!(decode(std::fs::read(&path).unwrap().as_slice()).is_ok());
        let original = std::fs::read(&path).unwrap();
        // A real exclusive Windows file handle makes atomic replacement fail
        // against the same destination. The writer must preserve old bytes.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        writer.submit(prepare()).unwrap();
        let failed = wait();
        assert!(failed.error.is_some());
        drop(held);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!directory.join("cache.tmp").exists());
        // The same worker remains usable after an actual filesystem failure.
        writer.submit(prepare()).unwrap();
        assert!(wait().error.is_none());
        assert!(decode(std::fs::read(&path).unwrap().as_slice()).is_ok());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    #[ignore = "serial production extraction benchmark with the archived real mesh"]
    fn benchmark_actual_local_analysis_reuse() {
        let (mut pool, surface) = actual();
        let world = WorldTransform {
            rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            translation: [0.0; 3],
            scale: 1.0,
        };
        let runs = 2000;
        let started = std::time::Instant::now();
        for _ in 0..runs {
            std::hint::black_box(extract(&surface, &world, false));
        }
        let direct = started.elapsed().as_secs_f64() * 1e6 / runs as f64;
        let started = std::time::Instant::now();
        for _ in 0..runs {
            let hit = pool
                .capture(surface.local, &surface.vertices, &surface.triangles)
                .unwrap();
            std::hint::black_box(extract(&hit, &world, true));
        }
        let warm = started.elapsed().as_secs_f64() * 1e6 / runs as f64;
        println!("actual mesh direct_us={direct:.3} warm_with_content_validation_us={warm:.3}");
    }
    #[test]
    #[ignore = "investigate a supplied real runtime local-mesh cache"]
    fn captured_cache_matches_direct_surface_analysis() {
        let path = std::env::var("PSYCHO_OCCLUSION_CAPTURE").expect("supplied cache path");
        let file = std::fs::File::open(path).unwrap();
        let pool = decode(std::io::BufReader::new(file)).unwrap();
        let mut vertices = 0;
        let mut triangles = 0;
        let mut planes = 0;
        for (index, surface) in pool.entries.iter().enumerate() {
            vertices += surface.vertices.len();
            triangles += surface.triangles.len();
            for rotation in [
                [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                [0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0],
            ] {
                for scale in [-1.0, 1.0] {
                    let world = WorldTransform {
                        rotation,
                        translation: [0.0; 3],
                        scale,
                    };
                    let direct = extract(surface, &world, false);
                    let cached = extract(surface, &world, true);
                    assert_eq!(
                        super::super::super::runtime::plane_signature(&direct),
                        super::super::super::runtime::plane_signature(&cached),
                        "captured mesh {index}: cached local analysis changed output"
                    );
                    planes += cached.len();
                }
            }
        }
        println!(
            "captured meshes={} vertices={vertices} triangles={triangles} transformed_planes={planes}",
            pool.entries.len()
        );
    }

    /// Execute the production owned scheduler and populated cache with actual
    /// supplied mesh arrays. Identity placement is an offline local workload,
    /// not a reconstruction of the captured scene or its materials.
    #[test]
    #[ignore = "serial complete owned-pipeline benchmark on supplied meshes"]
    fn benchmark_captured_owned_pipeline() {
        let path = std::env::var("PSYCHO_OCCLUSION_CAPTURE").expect("supplied cache path");
        let bytes = std::fs::read(path).unwrap();
        let world = WorldTransform {
            rotation: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            translation: [0.0; 3],
            scale: 1.0,
        };
        let mut expected = None;
        for round in 0..6 {
            let mut pool = decode(bytes.as_slice()).unwrap();
            for surface in &mut pool.entries {
                // Decode owns each entry exclusively before snapshots exist.
                Arc::get_mut(surface).unwrap().faces = std::array::from_fn(|_| OnceLock::new());
            }
            // Cache hits reorder residency; source admission order must remain
            // fixed because coplanar merging preserves its original pair order.
            let input: Vec<_> = pool.entries.iter().cloned().collect();
            for warm in [false, true] {
                let mut generation = Generation::new(128, None);
                generation.done = true;
                generation.stats.refs = pool.entries.len();
                for surface in &input {
                    generation.snapshots.push_back(MeshSnapshot {
                        surface: surface.clone(),
                        world,
                        source_form_id: 0,
                        reference: ReferenceIdentity {
                            form_id: 0,
                            address: 0,
                        },
                        geometry: 0,
                        recorded: true,
                        face: 0,

                        produced: false,
                        sides: Sides::Unknown,
                    });
                }
                let mut slices = Vec::new();
                let started = std::time::Instant::now();
                loop {
                    let frame = std::time::Instant::now();
                    let done = generation.advance(frame);
                    slices.push(frame.elapsed().as_secs_f64() * 1e6);
                    if done {
                        break;
                    }
                }
                let (planes, raw, ready, _) = generation.finish();
                let total_us = started.elapsed().as_secs_f64() * 1e6;
                let signature = super::super::super::runtime::plane_signature(&planes);
                if let Some(expected) = &expected {
                    assert_eq!(&signature, expected);
                } else {
                    expected = Some(signature);
                }
                assert!(ready);
                let advances = slices.len();
                slices.sort_by(f64::total_cmp);
                println!(
                    "owned round={round} warm={warm} meshes={} selected={} raw={raw} total_us={total_us:.2} advances={advances} median_us={:.2} p95_us={:.2} p99_us={:.2} max_us={:.2}",
                    pool.entries.len(),
                    planes.len(),
                    slices[advances / 2],
                    slices[(advances - 1) * 95 / 100],
                    slices[(advances - 1) * 99 / 100],
                    slices[advances - 1]
                );
                // Include populated lookup, exact equality and owned bounds.
                let started = std::time::Instant::now();
                for surface in &input {
                    let hit = pool
                        .capture(
                            finite_aabb_of(&surface.vertices),
                            &surface.vertices,
                            &surface.triangles,
                        )
                        .unwrap();
                    assert!(Arc::ptr_eq(&hit, surface));
                }
                println!(
                    "reuse round={round} warm={warm} meshes={} total_us={:.2}",
                    input.len(),
                    started.elapsed().as_secs_f64() * 1e6
                );
            }
        }
    }

    #[test]
    #[ignore = "compare complete local face output against a supplied offline baseline"]
    fn captured_local_face_baseline() {
        let path = std::env::var("PSYCHO_OCCLUSION_CAPTURE").expect("supplied cache path");
        let pool = decode(std::fs::read(path).unwrap().as_slice()).unwrap();
        let mut result = Vec::new();
        for surface in &pool.entries {
            for face in 0..6 {
                match local_face(
                    &surface.local,
                    &surface.vertices,
                    &surface.triangles,
                    face,
                    &mut Vec::new(),
                    &mut Vec::new(),
                    &mut Vec::new(),
                    &mut CoverageScratch::default(),
                ) {
                    LocalFace::Unsupported => result.push(0),
                    LocalFace::Opening => result.push(1),
                    LocalFace::Rectangle {
                        center_u,
                        center_v,
                        half_u,
                        half_v,
                        coverage,
                    } => {
                        result.push(2);
                        for value in [center_u, center_v, half_u, half_v, coverage] {
                            result.extend_from_slice(&value.to_bits().to_le_bytes());
                        }
                    }
                }
            }
        }
        if let Ok(path) = std::env::var("PSYCHO_OCCLUSION_FACE_OUTPUT") {
            std::fs::write(path, &result).unwrap();
        } else {
            let expected = std::fs::read(
                std::env::var("PSYCHO_OCCLUSION_FACE_EXPECT").expect("baseline path"),
            )
            .unwrap();
            assert_eq!(result.len(), expected.len());
            assert!(
                result == expected,
                "complete local face descriptors changed"
            );
        }
        println!(
            "local faces={} encoded_bytes={}",
            pool.entries.len() * 6,
            result.len()
        );
    }
    #[test]
    fn checkpoint_preparation_does_not_write_on_the_frame_thread() {
        let (pool, _surface) = actual();
        let directory = std::env::temp_dir().join(format!(
            "psycho-cache-prepare-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache");
        let mut preparation = SaveWork::new(&pool).unwrap();
        while !preparation.advance().unwrap() {}
        let wrote_cache = path.exists();
        let wrote_temporary = directory.join("cache.tmp").exists();
        drop(preparation);
        if wrote_cache {
            std::fs::remove_file(&path).unwrap();
        }
        if directory.join("cache.tmp").exists() {
            std::fs::remove_file(directory.join("cache.tmp")).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
        assert!(
            !wrote_cache && !wrote_temporary,
            "frame-side checkpoint preparation performed blocking filesystem work"
        );
    }
}
