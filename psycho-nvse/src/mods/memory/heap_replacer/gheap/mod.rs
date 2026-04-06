// Game heap replacement using mimalloc with per-thread zombie pools.
//
// Replaces the game's SBM pool allocator (FUN_00aa3e40 / FUN_00aa4060)
// with mimalloc. Every thread gets a thread-local pool that holds freed
// blocks on per-size-class freelists. This preserves SBM's "freed memory
// stays readable" contract -- stale readers find valid zombie data instead
// of recycled garbage.
//
// Design:
//   alloc  -> pool freelist (hit) or mi_malloc_aligned (miss)
//   free   -> pool freelist push (block stays readable)
//   OOM    -> drain own pool + game OOM stages (mutex) + retry

pub mod allocator;
pub mod engine;
pub mod heap_manager;
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
pub mod uaf_bitmap;
pub mod virtual_alloc;
