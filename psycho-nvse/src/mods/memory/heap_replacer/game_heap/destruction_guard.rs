//! Heap access guard — RwLock synchronization for game heap operations.
//!
//! Two APIs for different lifetimes:
//! - Closure: read(||), write(||), try_write(||), try_read(||)
//! - Guard:   try_read_guard() -> Option<ReadGuard>
//!
//! Guard dropped = lock released. Rust ownership handles the rest.

use parking_lot::RwLock;

static HEAP_GUARD: RwLock<()> = RwLock::new(());

pub type ReadGuard = parking_lot::RwLockReadGuard<'static, ()>;

// ---- Closure API ----

#[inline]
pub fn read<R>(f: impl FnOnce() -> R) -> R {
    let _g = HEAP_GUARD.read();
    f()
}

#[inline]
pub fn write<R>(f: impl FnOnce() -> R) -> R {
    let _g = HEAP_GUARD.write();
    f()
}

#[inline]
pub fn try_write<R>(f: impl FnOnce() -> R) -> Option<R> {
    let _g = HEAP_GUARD.try_write()?;
    Some(f())
}

#[inline]
pub fn try_read<R>(f: impl FnOnce() -> R) -> Option<R> {
    let _g = HEAP_GUARD.try_read()?;
    Some(f())
}

// ---- Guard API ----

#[inline]
pub fn try_read_guard() -> Option<ReadGuard> {
    HEAP_GUARD.try_read()
}
