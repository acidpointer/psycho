// Safe cell unloading wrapper.
//
// Enforces the complete synchronization protocol via RAII:
//   1. AI threads idle (checked at construction)
//   2. Not loading (checked at construction)
//   3. BST not busy (checked at construction)
//   4. NVSE events suppressed (loading counter incremented)
//   5. Havok world locked (pre_destruction_setup)
//   6. IO dequeue locked during PDD (blocks BSTaskManagerThread)
//   7. All locks released on drop in correct reverse order
//
// Usage:
//   let result = CellUnloadGuard::execute(20);
//   if let Some(r) = result {
//       log::info!("Unloaded {} cells, freed {}MB", r.cells, r.freed_mb);
//   }

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

/// Total cells unloaded since plugin load.
pub fn total_cells_unloaded() -> usize {
	TOTAL_CELLS_UNLOADED.load(Ordering::Relaxed)
}

/// Total bytes freed by cell unload since plugin load.
pub fn total_bytes_freed() -> usize {
	TOTAL_BYTES_FREED.load(Ordering::Relaxed)
}

/// Total cell unload cycles executed.
pub fn total_cycles() -> usize {
	TOTAL_CYCLES.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// Concrete result from a cell unload operation.
pub struct CellUnloadResult {
	/// Number of cells successfully unloaded.
	pub cells: usize,
	/// Commit before unload (bytes).
	pub commit_before: usize,
	/// Commit after unload + PDD + collect (bytes).
	pub commit_after: usize,
	/// Memory freed (bytes). commit_before - commit_after, saturating.
	pub freed: usize,
	/// Freed in megabytes (for logging convenience).
	pub freed_mb: usize,
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

/// RAII guard that holds all locks needed for safe cell unloading.
///
/// Acquiring:
///   - Checks: AI idle, not loading, BST idle, game manager available
///   - Increments loading state counter (suppresses NVSE events)
///   - Calls pre_destruction_setup (locks Havok, invalidates scene graph)
///
/// Dropping:
///   - Releases IO lock (if acquired)
///   - Calls post_destruction_restore (unlocks Havok)
///   - Decrements loading counter (if no cells were unloaded)
///   - If cells WERE unloaded: counter stays elevated for one frame
struct CellUnloadGuard {
	manager: *mut c_void,
	state: [u8; 12],
	io_locked: bool,
	cells_unloaded: usize,
}

/// Why acquire failed. Logged at DEBUG level.
#[derive(Debug)]
pub enum AcquireError {
	AiActive,
	NoManager,
	SetupFailed,
}

impl CellUnloadGuard {
	/// Try to acquire all locks for cell unloading.
	fn acquire() -> Result<Self, AcquireError> {
		// Only check: AI threads must be idle. FindCellToUnload modifies
		// cell arrays that AI threads read.
		//
		// NO is_loading() check: game's OOM stage 5 unloads during loading.
		// NO is_bst_cell_load_pending() check: BST loads NEW cells while
		// we unload OLD cells (different cells). FindCellToUnload itself
		// checks cell eligibility (FUN_004511e0, FUN_00557090) and skips
		// cells with pending loads.

		if super::super::game_guard::is_ai_active() {
			return Err(AcquireError::AiActive);
		}

		let manager = globals::game_manager()
			.ok_or(AcquireError::NoManager)?;

		// Suppress NVSE PLChangeEvent dispatch.
		let loading_counter = globals::loading_state_counter();
		loading_counter.fetch_add(1, Ordering::AcqRel);

		// Lock Havok world + invalidate scene graph.
		let state = match unsafe { globals::pre_destruction_setup() } {
			Some(s) => s,
			None => {
				loading_counter.fetch_sub(1, Ordering::AcqRel);
				return Err(AcquireError::SetupFailed);
			}
		};

		log::debug!("[CELL_UNLOAD] Guard acquired: Havok locked, NVSE suppressed");

		Ok(CellUnloadGuard {
			manager,
			state,
			io_locked: false,
			cells_unloaded: 0,
		})
	}

	/// Find and unload up to `max_cells` eligible cells.
	fn unload_cells(&mut self, max_cells: usize) -> usize {
		for i in 0..max_cells {
			match unsafe { globals::find_cell_to_unload(self.manager) } {
				Some(true) => {
					self.cells_unloaded += 1;
					log::debug!("[CELL_UNLOAD] Cell {} unloaded", i + 1);
				}
				_ => {
					log::debug!("[CELL_UNLOAD] No more eligible cells after {}", self.cells_unloaded);
					break;
				}
			}
		}
		self.cells_unloaded
	}

	/// Run PDD + async flush under IO lock.
	fn run_cleanup(&mut self) {
		if self.cells_unloaded > 0 && !self.io_locked {
			log::debug!("[CELL_UNLOAD] Acquiring IO lock for PDD...");
			self.io_locked = unsafe { io_sync::io_lock_acquire() };
			if !self.io_locked {
				log::warn!("[CELL_UNLOAD] IO lock acquire failed — PDD without BST sync");
			}
		}

		unsafe { globals::deferred_cleanup_small(self.state[5]) };
		log::debug!("[CELL_UNLOAD] PDD + async flush complete");
	}
}

impl Drop for CellUnloadGuard {
	fn drop(&mut self) {
		if self.io_locked {
			unsafe { io_sync::io_lock_release() };
			log::debug!("[CELL_UNLOAD] IO lock released");
		}

		unsafe { globals::post_destruction_restore(&mut self.state) };
		log::debug!("[CELL_UNLOAD] Havok unlocked, scene graph restored");

		if self.cells_unloaded == 0 {
			globals::loading_state_counter().fetch_sub(1, Ordering::AcqRel);
		}
		// If cells > 0: counter stays elevated.
		// Caller must set pending_counter_decrement for next frame.
	}
}

// ---------------------------------------------------------------------------
// Public API — single entry point
// ---------------------------------------------------------------------------

/// Execute a complete cell unload cycle.
///
/// Acquires all locks, unloads up to `max_cells`, runs PDD, measures
/// memory freed, releases everything. Returns None if preconditions
/// not met (logged at debug level).
///
/// Caller is responsible for:
///   - Being on the main thread
///   - Calling flush_pending_counter_decrement next frame if cells > 0
///   - Optionally flushing quarantine + mi_collect after this returns
///
/// Safe to call speculatively — returns None without side effects
/// if any precondition fails.
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

	// Update global stats.
	TOTAL_CELLS_UNLOADED.fetch_add(cells, Ordering::Relaxed);
	TOTAL_BYTES_FREED.fetch_add(freed, Ordering::Relaxed);
	TOTAL_CYCLES.fetch_add(1, Ordering::Relaxed);

	log::warn!(
		"[CELL_UNLOAD] Done: {} cells, commit {}MB→{}MB (freed {}MB), quarantine {}MB→{}MB, total_cells={}, total_freed={}MB",
		cells,
		commit_before / 1024 / 1024,
		commit_after / 1024 / 1024,
		freed / 1024 / 1024,
		quarantine_before / 1024 / 1024,
		quarantine_after / 1024 / 1024,
		TOTAL_CELLS_UNLOADED.load(Ordering::Relaxed),
		TOTAL_BYTES_FREED.load(Ordering::Relaxed) / 1024 / 1024,
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
// Deferred request (for console command — runs at next on_ai_join)
// ---------------------------------------------------------------------------

static DEFERRED_REQUEST: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Request cell unload at the next safe point (on_ai_join).
/// Used by console commands that can't guarantee AI idle timing.
/// Returns immediately — actual unload happens next frame.
pub fn request_deferred(max_cells: u8) {
	DEFERRED_REQUEST.store(max_cells, Ordering::Release);
	log::info!("[CELL_UNLOAD] Deferred request: {} cells at next AI_JOIN", max_cells);
}

/// Check and consume deferred request. Called from on_ai_join.
/// Returns 0 if no pending request.
pub fn take_deferred_request() -> usize {
	DEFERRED_REQUEST.swap(0, Ordering::AcqRel) as usize
}

// ---------------------------------------------------------------------------
// Proactive trigger — should we unload cells now?
// ---------------------------------------------------------------------------

/// Check if memory pressure warrants proactive cell unloading.
///
/// Uses baseline-relative thresholds from the pressure system:
///   - baseline + 500MB (pressure threshold): unload 5 cells
///   - baseline + 750MB: unload 10 cells
///   - baseline + 1000MB (aggressive threshold): unload 20 cells
///
/// Dynamic — adapts to any mod count. A user with baseline 800MB
/// triggers at 1300MB. A user with baseline 1500MB triggers at 2000MB.
///
/// Returns the recommended max_cells to unload (0 = don't unload).
pub fn should_unload_proactively() -> usize {
	use super::super::pressure::PressureRelief;

	let pr = match PressureRelief::instance() {
		Some(pr) => pr,
		None => return 0,
	};

	let baseline = pr.baseline_commit();
	if baseline == 0 {
		return 0; // not calibrated yet
	}

	let info = libmimalloc::process_info::MiMallocProcessInfo::get();
	let commit = info.get_current_commit();
	let growth = commit.saturating_sub(baseline);

	// Thresholds relative to baseline growth.
	const CELL_UNLOAD_GROWTH: usize = 500 * 1024 * 1024;
	const MODERATE_GROWTH: usize = 750 * 1024 * 1024;
	const AGGRESSIVE_GROWTH: usize = 1000 * 1024 * 1024;

	if growth >= AGGRESSIVE_GROWTH {
		log::warn!(
			"[CELL_UNLOAD] Aggressive: commit={}MB, baseline={}MB, growth={}MB — 20 cells",
			commit / 1024 / 1024, baseline / 1024 / 1024, growth / 1024 / 1024,
		);
		20
	} else if growth >= MODERATE_GROWTH {
		log::info!(
			"[CELL_UNLOAD] Moderate: commit={}MB, growth={}MB — 10 cells",
			commit / 1024 / 1024, growth / 1024 / 1024,
		);
		10
	} else if growth >= CELL_UNLOAD_GROWTH {
		log::info!(
			"[CELL_UNLOAD] Proactive: commit={}MB, growth={}MB — 5 cells",
			commit / 1024 / 1024, growth / 1024 / 1024,
		);
		5
	} else {
		0
	}
}
