//! Hook functions — thin wrappers that delegate to HeapOrchestrator.

use libc::c_void;

use super::engine::globals::{self, PddQueue};
use super::orchestrator::HeapOrchestrator;
use super::statics;

// ---- Game heap alloc/free/msize/realloc ----

pub unsafe extern "thiscall" fn hook_gheap_alloc(
	_this: *mut c_void,
	size: usize,
) -> *mut c_void {
	unsafe { HeapOrchestrator::alloc(size) }
}

pub unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
	unsafe { HeapOrchestrator::free(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_msize(
	_this: *mut c_void,
	ptr: *mut c_void,
) -> usize {
	unsafe { HeapOrchestrator::msize(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_realloc(
	_this: *mut c_void,
	ptr: *mut c_void,
	new_size: usize,
) -> *mut c_void {
	unsafe { HeapOrchestrator::realloc(ptr, new_size) }
}

// ---- Main loop maintenance (post-render, before AI_JOIN) ----

pub unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
	if let Ok(original) = statics::MAIN_LOOP_MAINTENANCE_HOOK.original() {
		unsafe { original(this) };
	}
	unsafe { HeapOrchestrator::on_mid_frame() };
}

// ---- AI thread start/join ----

pub unsafe extern "fastcall" fn hook_ai_thread_start(mgr: *mut c_void) {
	HeapOrchestrator::on_ai_start();
	if let Ok(original) = statics::AI_THREAD_START_HOOK.original() {
		unsafe { original(mgr) };
	}
}

pub unsafe extern "fastcall" fn hook_ai_thread_join(mgr: *mut c_void) {
	if let Ok(original) = statics::AI_THREAD_JOIN_HOOK.original() {
		unsafe { original(mgr) };
	}
	unsafe { HeapOrchestrator::on_ai_join() };
}

// ---- Per-frame queue drain (Phase 7, before AI_START) ----

// Extra rounds of FUN_00868850 when under memory pressure.
const EXTRA_DRAIN_ROUNDS: u32 = 19;
const DIAG_LOG_INTERVAL: u32 = 300;

thread_local! {
	static DIAG_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub unsafe extern "C" fn hook_per_frame_queue_drain() {
	unsafe { HeapOrchestrator::on_pre_ai() };

	if let Ok(original) = statics::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
		unsafe { original() };

		if HeapOrchestrator::is_pressure_active() {
			DIAG_COUNTER.with(|c| {
				let count = c.get().wrapping_add(1);
				c.set(count);
				if count % DIAG_LOG_INTERVAL == 0 {
					log::debug!(
						"[PDD] trigger={} queues: NiNode={} Tex={} Anim={} Gen={} Form={}",
						globals::heap_compact_trigger_value(),
						globals::pdd_queue_count(PddQueue::NiNode),
						globals::pdd_queue_count(PddQueue::Texture),
						globals::pdd_queue_count(PddQueue::Anim),
						globals::pdd_queue_count(PddQueue::Generic),
						globals::pdd_queue_count(PddQueue::Form),
					);
				}
			});

			for _ in 0..EXTRA_DRAIN_ROUNDS {
				if globals::pdd_queue_count(PddQueue::NiNode) == 0 {
					break;
				}
				unsafe { original() };
			}
		}
	}
}
