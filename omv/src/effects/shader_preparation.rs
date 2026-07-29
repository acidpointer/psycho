//! Process-wide coordination for screen-effect shader preparation.
//!
//! Individual effects retain ownership of their immutable bytecode catalogs,
//! failure state, and device-object creation. This module owns only the
//! compiler concurrency contract: any number of preparation workers may be
//! requested, but at most one screen-effect compiler transaction executes at
//! a time. The mutex is acquired exclusively by background workers and is
//! never touched by a render callback.

use std::sync::LazyLock;

use parking_lot::Mutex;

static SCREEN_EFFECT_COMPILER: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Run one background shader preparation transaction serially.
///
/// The caller must already be executing on a worker thread. Holding this lock
/// may include cache I/O and compiler process execution, which are forbidden
/// on OMV render callbacks.
pub(super) fn run_serialized<T>(prepare: impl FnOnce() -> T) -> T {
    let _compiler = SCREEN_EFFECT_COMPILER.lock();
    prepare()
}
