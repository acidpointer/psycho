#![allow(non_snake_case)]

//! xNVSE entrypoint for Oh My Vegas graphics.

use core::{ffi::c_void, mem::size_of};
use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};
use libnvse::plugin::PluginContext;
use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
use libpsycho::os::windows::winapi::WinBool;

const PLUGIN_INFO_VERSION: u32 = 1;

/// xNVSE preload callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Preload() -> WinBool {
    true.into()
}

/// xNVSE metadata query callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    nvse: *const NVSEInterfaceFFI,
    info: *mut PluginInfoFFI,
) -> WinBool {
    if unsafe { nvse.as_ref() }.is_none() {
        return false.into();
    }
    let Some(info) = (unsafe { info.as_mut() }) else {
        return false.into();
    };

    info.infoVersion = PLUGIN_INFO_VERSION;
    info.name = crate::plugininfo::PLUGIN_NAME.as_ptr();
    info.version = crate::plugininfo::PLUGIN_VERSION;

    true.into()
}

/// xNVSE load callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> WinBool {
    match plugin_load(nvse) {
        Ok(()) => true.into(),
        Err(err) => {
            eprintln!("omv: Failed to initialize xNVSE plugin: {err:?}");
            false.into()
        }
    }
}

fn plugin_load(nvse: *const NVSEInterfaceFFI) -> anyhow::Result<()> {
    if unsafe { nvse.as_ref() }.is_none() {
        anyhow::bail!("NVSE interface pointer is NULL");
    }

    crate::startup::initialize_for_nvse()?;

    let mut ctx = PluginContext::new(nvse, crate::plugininfo::PLUGIN_NAME)?;
    log::info!(
        "[XNVSE] Loaded as '{}', xNVSE={}, runtime={}",
        crate::plugininfo::PLUGIN_NAME.to_string_lossy(),
        ctx.nvse_version(),
        ctx.runtime_version(),
    );

    ctx.on_message(handle_message)?;

    // PluginContext owns callback thunks passed to xNVSE. Dropping it after
    // Load would leave xNVSE with stale pointers.
    std::mem::forget(ctx);

    Ok(())
}

fn handle_message(msg: &NVSEMessage) {
    match msg.get_type() {
        NVSEMessageType::PostLoad => crate::startup::observe_post_load(),
        NVSEMessageType::PreLoadGame => crate::runtime::prepare_for_game_load(),
        NVSEMessageType::DeferredInit => {
            if let Err(err) = crate::startup::install_deferred_hooks() {
                log::error!("[XNVSE] Deferred graphics hook install failed: {err:#}");
            }
        }
        NVSEMessageType::OnFramePresent => {
            // xNVSE passes `int loadingScreen` by pointer for this message.
            // An absent or malformed payload is treated as loading so OMV can
            // still service resources/UI without applying gameplay fallback
            // effects to an unproven target.
            let (data, data_len) = msg.raw_data();
            let loading_screen = decode_loading_screen(data, data_len).unwrap_or(true);
            crate::hooks::on_frame_present(loading_screen);
        }
        _ => {}
    }
}

fn decode_loading_screen(data: *mut c_void, data_len: u32) -> Option<bool> {
    if data.is_null() || usize::try_from(data_len).ok()? < size_of::<i32>() {
        return None;
    }
    libpsycho::os::windows::memory::validate_memory_range(data.cast_const(), size_of::<i32>())
        .ok()?;
    // The xNVSE payload lives on its dispatcher's stack and is not promised to
    // be Rust-aligned. Copying one i32 is both alignment-safe and bounded by
    // the validated message length.
    Some(unsafe { data.cast::<i32>().read_unaligned() } != 0)
}

#[cfg(test)]
mod tests {
    use super::decode_loading_screen;
    use core::ffi::c_void;

    #[test]
    fn preload_message_releases_workbench_ownership_before_native_load() {
        let source = include_str!("nvse_plugin.rs");
        assert!(
            source.contains(
                "NVSEMessageType::PreLoadGame => crate::runtime::prepare_for_game_load()"
            )
        );
    }

    #[test]
    fn frame_present_decodes_the_pointed_to_unaligned_loading_integer() {
        let mut loading_payload = [0xFFu8, 1, 0, 0, 0, 0xFF];
        let loading = unsafe { loading_payload.as_mut_ptr().add(1) }.cast::<c_void>();
        let mut gameplay_payload = [0xFFu8, 0, 0, 0, 0, 0xFF];
        let gameplay = unsafe { gameplay_payload.as_mut_ptr().add(1) }.cast::<c_void>();
        assert_eq!(decode_loading_screen(loading, 4), Some(true));
        assert_eq!(decode_loading_screen(gameplay, 4), Some(false));
        assert_eq!(decode_loading_screen(loading, 3), None);
        assert_eq!(decode_loading_screen(core::ptr::null_mut(), 4), None);
    }

    #[test]
    fn frame_present_never_uses_pointer_value_boolean_decoding() {
        let source = include_str!("nvse_plugin.rs");
        let arm = source
            .split_once("NVSEMessageType::OnFramePresent")
            .and_then(|(_, tail)| tail.split_once("_ => {}"))
            .map(|(body, _)| body)
            .expect("OnFramePresent arm");
        assert!(arm.contains("decode_loading_screen"));
        assert!(!arm.contains("data_as_bool"));
    }
}
