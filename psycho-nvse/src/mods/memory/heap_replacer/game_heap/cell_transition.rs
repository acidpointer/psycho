//! CellTransitionHandler analysis notes.
//!
//! FUN_008774a0 orchestrates object destruction during cell transitions.
//! It was previously hooked to add hkWorld_Lock and loading state counter,
//! but this caused deadlocks:
//!
//! - hkWorld_Lock before calling the original blocks AI threads that need
//!   Havok world access to finish current physics work. FUN_008324e0(0)
//!   inside the original tries to drain AI task queues, but they can't
//!   complete -- deadlock.
//!
//! - The IO dequeue lock blocked BSTaskManagerThread from processing
//!   pending cell load tasks that FUN_00877700 waits for -- deadlock.
//!
//! The original function already handles all synchronization correctly:
//!   FUN_00877700  -- waits for pending cell loads (BSTaskManagerThread)
//!   FUN_008324e0  -- stops Havok simulation, drains AI task queues
//!   FUN_00868d70  -- blocking PDD (all queues), runs AFTER AI drained
//!   FUN_00c459d0  -- blocking async flush
//!
//! No hook is needed. Stale pointer issues are handled by targeted hooks
//! (texture dead set, IO task validation, queued ref HAVOK_DEATH check).
