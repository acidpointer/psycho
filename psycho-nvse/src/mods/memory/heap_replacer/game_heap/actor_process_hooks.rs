// Actor process synchronization hooks.
//
// with_try_read handles main/worker distinction internally.

use libc::c_void;

use super::game_guard;
use super::statics;

pub unsafe extern "thiscall" fn hook_actor_downgrade(
	this: *mut c_void,
	param_1: *mut c_void,
) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::ACTOR_DOWNGRADE_HOOK.original() {
			unsafe { original(this, param_1) };
		}
	});
}

pub unsafe extern "fastcall" fn hook_process_mgr_update(param_1: i32) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::PROCESS_MGR_UPDATE_HOOK.original() {
			unsafe { original(param_1) };
		}
	});
}

pub unsafe extern "fastcall" fn hook_ai_process1(param_1: i32) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::AI_PROCESS1_HOOK.original() {
			unsafe { original(param_1) };
		}
	});
}

pub unsafe extern "fastcall" fn hook_ai_process2(param_1: i32) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::AI_PROCESS2_HOOK.original() {
			unsafe { original(param_1) };
		}
	});
}

pub unsafe extern "thiscall" fn hook_cell_mgmt_update(
	this: *mut c_void,
	param_1: f32,
) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::CELL_MGMT_UPDATE_HOOK.original() {
			unsafe { original(this, param_1) };
		}
	});
}
