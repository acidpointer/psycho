#![allow(non_snake_case)]

mod commands;
mod plugininfo;

use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};
use libnvse::plugin::PluginContext;
use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
use libpsycho::os::windows::winapi::{get_module_handle_w, get_proc_address};
use psycho_engine_fixes_api::{
    PSYCHO_API_VERSION, PSYCHO_ENGINE_FIXES_DLL, PSYCHO_ENGINE_FIXES_GET_API,
    PSYCHO_EVENT_DEFERRED_INIT, PSYCHO_EVENT_LOAD_GAME, PSYCHO_EVENT_MAIN_GAME_LOOP,
    PSYCHO_EVENT_ON_FRAME_PRESENT, PSYCHO_EVENT_POST_LOAD_GAME, PSYCHO_EVENT_PRE_LOAD_GAME,
    PSYCHO_MAGIC, PsychoApi, PsychoEvent,
};
use windows::core::BOOL;

static PSYCHO_API: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Preload() -> BOOL {
    true.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    nvse: *const NVSEInterfaceFFI,
    info: *mut PluginInfoFFI,
) -> BOOL {
    if unsafe { nvse.as_ref() }.is_none() {
        return false.into();
    }
    let Some(info) = (unsafe { info.as_mut() }) else {
        return false.into();
    };

    info.name = plugininfo::PLUGIN_NAME.as_ptr();
    info.version = plugininfo::PLUGIN_VERSION;

    true.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> BOOL {
    match helper_load(nvse) {
        Ok(()) => true.into(),
        Err(err) => {
            log::error!("[HELPER] Load failed: {:?}", err);
            false.into()
        }
    }
}

fn helper_load(nvse: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    if unsafe { nvse.as_ref() }.is_none() {
        anyhow::bail!("NVSE interface pointer is NULL");
    }

    let mut ctx = PluginContext::new(nvse, plugininfo::PLUGIN_NAME)?;

    if let Ok(console) = ctx.low_level().query_console() {
        console.set_global();
    }

    ctx.on_message(forward_message)?;

    if let Err(e) = ctx.set_opcode_base(0x3F00) {
        log::error!("[FAIL] set_opcode_base: {}", e);
    } else {
        log::info!("[OK] Opcode base set to 0x3F00");
        commands::register(&mut ctx);
    }

    std::mem::forget(ctx);

    Ok(())
}

pub(crate) fn engine_fixes_api() -> Option<&'static PsychoApi> {
    let current = PSYCHO_API.load(Ordering::Acquire);
    if current != 0 {
        return unsafe { (current as *const PsychoApi).as_ref() };
    }

    // Do not LoadLibrary here. The helper is intentionally late-loaded by
    // xNVSE; the core DLL must already be mapped by psycho-loader.
    let module = get_module_handle_w(Some(PSYCHO_ENGINE_FIXES_DLL)).ok()?;
    let get_api = get_proc_address(module, PSYCHO_ENGINE_FIXES_GET_API).ok()?;
    let get_api: unsafe extern "system" fn() -> *const PsychoApi =
        unsafe { core::mem::transmute(get_api) };
    let api = unsafe { get_api().as_ref() }?;

    if api.magic != PSYCHO_MAGIC || api.version != PSYCHO_API_VERSION {
        return None;
    }

    PSYCHO_API.store(api as *const PsychoApi as usize, Ordering::Release);
    Some(api)
}

fn forward_message(msg: &NVSEMessage) {
    let Some(kind) = event_kind(msg.get_type()) else {
        return;
    };

    let Some(api) = engine_fixes_api() else {
        return;
    };
    let Some(notify) = api.notify else {
        return;
    };

    let path = msg.data_as_path();
    let (data, data_len) = path
        .map(|path| (path.as_ptr(), path.len()))
        .unwrap_or((ptr::null(), 0));
    let bool_value = msg
        .data_as_bool()
        .map(|value| if value { 1 } else { 0 })
        .unwrap_or(-1);

    let event = PsychoEvent {
        kind,
        data,
        data_len,
        bool_value,
    };

    let _ = unsafe { notify(&event) };
}

fn event_kind(kind: NVSEMessageType) -> Option<u32> {
    match kind {
        NVSEMessageType::DeferredInit => Some(PSYCHO_EVENT_DEFERRED_INIT),
        NVSEMessageType::PreLoadGame => Some(PSYCHO_EVENT_PRE_LOAD_GAME),
        NVSEMessageType::LoadGame => Some(PSYCHO_EVENT_LOAD_GAME),
        NVSEMessageType::PostLoadGame => Some(PSYCHO_EVENT_POST_LOAD_GAME),
        NVSEMessageType::MainGameLoop => Some(PSYCHO_EVENT_MAIN_GAME_LOOP),
        NVSEMessageType::OnFramePresent => Some(PSYCHO_EVENT_ON_FRAME_PRESENT),
        _ => None,
    }
}
