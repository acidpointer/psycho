// Havok broadphase synchronization hooks.
//
// with_try_read handles main/worker distinction internally.

use libc::c_void;

use super::game_guard;
use super::statics;

pub unsafe extern "thiscall" fn hook_havok_add_entity(
	this: *mut c_void,
	param_1: i32,
	param_2: i32,
	param_3: i32,
) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::HAVOK_ADD_ENTITY_HOOK.original() {
			unsafe { original(this, param_1, param_2, param_3) };
		}
	});
}

pub unsafe extern "thiscall" fn hook_havok_coll_obj_dtor(
	this: *mut c_void,
	param_1: u8,
) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::HAVOK_COLL_OBJ_DTOR_HOOK.original() {
			unsafe { original(this, param_1) };
		}
	});
}

pub unsafe extern "thiscall" fn hook_havok_raycast(
	this: *mut c_void,
	param_1: *mut c_void,
	param_2: *mut c_void,
	param_3: i32,
	param_4: u32,
	param_5: u32,
) {
	game_guard::with_try_read(|| {
		if let Ok(original) = statics::HAVOK_RAYCAST_HOOK.original() {
			unsafe { original(this, param_1, param_2, param_3, param_4, param_5) };
		}
	});
}
