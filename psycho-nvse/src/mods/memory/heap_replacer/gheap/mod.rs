// Game heap replacement using mimalloc with deferred-free GC.
//
// Replaces the game's SBM pool allocator (FUN_00aa3e40 / FUN_00aa4060)
// with mimalloc. Freed main-thread pointers are held in a pending buffer
// for N frames before actual mi_free runs on a background GC thread.
// This preserves SBM's "freed memory stays readable" contract that the
// game engine relies on.
//
// Worker threads (AI, BST) call mi_free directly -- their freed objects
// are refcount-gated and have no cross-thread stale readers.
//
// Design:
//   alloc  -> mi_malloc_aligned (fast path, no overhead)
//   free   -> main thread: push to pending buffer (~5ns)
//             workers: mi_free directly (~15ns)
//   GC     -> background thread, drains batches older than N frames
//   OOM    -> game's own OOM stages + emergency GC drain

pub mod allocator;
pub mod engine;
pub mod pool;
pub mod game_guard;
pub mod hooks;
pub mod io_task;
pub mod watchdog;
pub mod pdd_hook;
pub mod pressure;
pub mod skeleton_update;
pub mod statics;
pub mod texture_cache;
pub mod types;
