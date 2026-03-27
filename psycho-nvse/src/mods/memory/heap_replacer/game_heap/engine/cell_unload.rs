// Safe cell unloading wrapper.
//
// Lock ordering matches CellTransitionHandler to prevent deadlocks:
//   Game loading:  IO wait (FUN_00877700) → Havok stop (FUN_008324e0)
//   Our unload:    IO lock → Havok lock (same order)
//
// Sequence:
//   1. AI idle check
//   2. NVSE event suppression (loading counter)
//   3. IO lock (block BST from dequeuing tasks)
//   4. Havok lock (pre_destruction_setup)
//   5. FindCellToUnload loop
//   6. PDD + async flush
//   7. Release Havok (post_destruction_restore)
//   8. Release IO lock
//   9. Restore loading counter

use libc::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::globals;
use super::io_sync;

// ---------------------------------------------------------------------------
// Global stats
// ---------------------------------------------------------------------------

static TOTAL_CELLS_UNLOADED: AtomicUsize = AtomicUsize::new(0);
static TOTAL_BYTES_FREED: AtomicUsize = AtomicUsize::new(0);
static TOTAL_CYCLES: AtomicUsize = AtomicUsize::new(0);

pub fn total_cells_unloaded() -> usize {
	TOTAL_CELLS_UNLOADED.load(Ordering::Relaxed)
}

pub fn total_bytes_freed() -> usize {
	TOTAL_BYTES_FREED.load(Ordering::Relaxed)
}

pub fn total_cycles() -> usize {
	TOTAL_CYCLES.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

pub struct CellUnloadResult {
	pub cells: usize,
	pub commit_before: usize,
	pub commit_after: usize,
	pub freed: usize,
	pub freed_mb: usize,
}

// ---------------------------------------------------------------------------
// Guard — lock order: IO → Havok (matches game's CellTransitionHandler)
// ---------------------------------------------------------------------------

struct CellUnloadGuard {
	manager: *mut c_void,
	state: [u8; 12],
	io_locked: bool,
	cells_unloaded: usize,
}

#[derive(Debug)]
pub enum AcquireError {
	AiActive,
	NoManager,
	SetupFailed,
}

impl CellUnloadGuard {
	fn acquire() -> Result<Self, AcquireError> {
		if super::super::game_guard::is_ai_active() {
			return Err(AcquireError::AiActive);
		}

		let manager = globals::game_manager()
			.ok_or(AcquireError::NoManager)?;

		// 1. Suppress NVSE events.
		let loading_counter = globals::loading_state_counter();
		loading_counter.fetch_add(1, Ordering::AcqRel);

		// 2. IO lock FIRST (same order as CellTransitionHandler).
		// Blocks BST from dequeuing tasks during our cell unload.
		let io_locked = unsafe { io_sync::io_lock_acquire() };

		// 3. Havok lock SECOND.
		let state = match unsafe { globals::pre_destruction_setup() } {
			Some(s) => s,
			None => {
				if io_locked {
					unsafe { io_sync::io_lock_release() };
				}
				loading_counter.fetch_sub(1, Ordering::AcqRel);
				return Err(AcquireError::SetupFailed);
			}
		};

		log::debug!("[CELL_UNLOAD] Guard acquired: IO={}, Havok locked", io_locked);

		Ok(CellUnloadGuard {
			manager,
			state,
			io_locked,
			cells_unloaded: 0,
		})
	}

	fn unload_cells(&mut self, max_cells: usize) -> usize {
		for i in 0..max_cells {
			if globals::is_loading() {
				log::warn!("[CELL_UNLOAD] Aborting: loading started after {} cells", self.cells_unloaded);
				break;
			}
			match unsafe { globals::find_cell_to_unload(self.manager) } {
				Some(true) => {
					self.cells_unloaded += 1;
					log::debug!("[CELL_UNLOAD] Cell {} unloaded", i + 1);
				}
				_ => {
					log::debug!("[CELL_UNLOAD] No more eligible after {}", self.cells_unloaded);
					break;
				}
			}
		}
		self.cells_unloaded
	}

	fn run_cleanup(&mut self) {
		if globals::is_loading() {
			log::warn!("[CELL_UNLOAD] Skipping PDD: loading started");
			return;
		}
		// PDD + async flush. IO lock held to prevent BST from dequeuing
		// tasks that reference objects being destroyed by PDD.
		unsafe { globals::deferred_cleanup_small(self.state[5]) };
		log::debug!("[CELL_UNLOAD] PDD + async flush complete");
	}
}

impl Drop for CellUnloadGuard {
	fn drop(&mut self) {
		// Release in REVERSE order: Havok first, then IO.
		unsafe { globals::post_destruction_restore(&mut self.state) };

		if self.io_locked {
			unsafe { io_sync::io_lock_release() };
		}

		if self.cells_unloaded == 0 {
			globals::loading_state_counter().fetch_sub(1, Ordering::AcqRel);
		}

		log::debug!("[CELL_UNLOAD] Guard released: {} cells", self.cells_unloaded);
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn execute(max_cells: usize) -> Option<CellUnloadResult> {
	let loading = globals::is_loading();

	let mut guard = match CellUnloadGuard::acquire() {
		Ok(g) => g,
		Err(reason) => {
			log::debug!("[CELL_UNLOAD] Skipped: {:?} (loading={})", reason, loading);
			return None;
		}
	};

	let info = libmimalloc::process_info::MiMallocProcessInfo::get();
	let commit_before = info.get_current_commit();
	let quarantine_before = super::super::orchestrator::HeapOrchestrator::quarantine_usage();

	log::info!(
		"[CELL_UNLOAD] Starting: max={}, loading={}, commit={}MB, quarantine={}MB",
		max_cells, loading,
		commit_before / 1024 / 1024,
		quarantine_before / 1024 / 1024,
	);

	let cells = guard.unload_cells(max_cells);

	if cells == 0 {
		log::info!("[CELL_UNLOAD] No eligible cells found");
		return Some(CellUnloadResult {
			cells: 0,
			commit_before,
			commit_after: commit_before,
			freed: 0,
			freed_mb: 0,
		});
	}

	guard.run_cleanup();
	drop(guard);

	let commit_after = info.get_current_commit();
	let quarantine_after = super::super::orchestrator::HeapOrchestrator::quarantine_usage();
	let freed = commit_before.saturating_sub(commit_after);

	TOTAL_CELLS_UNLOADED.fetch_add(cells, Ordering::Relaxed);
	TOTAL_BYTES_FREED.fetch_add(freed, Ordering::Relaxed);
	TOTAL_CYCLES.fetch_add(1, Ordering::Relaxed);

	log::warn!(
		"[CELL_UNLOAD] Done: {} cells, commit {}MB→{}MB (freed {}MB), quarantine {}MB→{}MB, total={}",
		cells,
		commit_before / 1024 / 1024,
		commit_after / 1024 / 1024,
		freed / 1024 / 1024,
		quarantine_before / 1024 / 1024,
		quarantine_after / 1024 / 1024,
		TOTAL_CELLS_UNLOADED.load(Ordering::Relaxed),
	);

	Some(CellUnloadResult {
		cells,
		commit_before,
		commit_after,
		freed,
		freed_mb: freed / 1024 / 1024,
	})
}

// ---------------------------------------------------------------------------
// Deferred request (console command → next on_pre_ai)
// ---------------------------------------------------------------------------

static DEFERRED_REQUEST: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn request_deferred(max_cells: u8) {
	DEFERRED_REQUEST.store(max_cells, Ordering::Release);
	log::info!("[CELL_UNLOAD] Deferred request: {} cells", max_cells);
}

pub fn take_deferred_request() -> usize {
	DEFERRED_REQUEST.swap(0, Ordering::AcqRel) as usize
}

// ---------------------------------------------------------------------------
// Proactive trigger
// ---------------------------------------------------------------------------

pub fn should_unload_proactively() -> usize {
	use super::super::pressure::PressureRelief;

	let pr = match PressureRelief::instance() {
		Some(pr) => pr,
		None => return 0,
	};

	let baseline = pr.baseline_commit();
	if baseline == 0 {
		return 0;
	}

	let info = libmimalloc::process_info::MiMallocProcessInfo::get();
	let commit = info.get_current_commit();
	let growth = commit.saturating_sub(baseline);

	const HIGH: usize = 1000 * 1024 * 1024;
	const CRITICAL: usize = 1200 * 1024 * 1024;

	if growth >= CRITICAL {
		log::warn!(
			"[CELL_UNLOAD] Critical: commit={}MB, growth={}MB — 10 cells",
			commit / 1024 / 1024, growth / 1024 / 1024,
		);
		10
	} else if growth >= HIGH {
		log::info!(
			"[CELL_UNLOAD] Proactive: commit={}MB, growth={}MB — 5 cells",
			commit / 1024 / 1024, growth / 1024 / 1024,
		);
		5
	} else {
		0
	}
}
