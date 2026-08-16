#![allow(non_snake_case)]

//! ESP-less xNVSE entrypoint for Atom.
//!
//! Atom's loader-visible work is deliberately small: plugin load acquires the
//! process-lifetime xNVSE services which are legal to request only there, then
//! registers one message callback and retains its callback owner. Configuration
//! loading, native validation, and hook installation remain unreachable until
//! xNVSE dispatches `DeferredInit`.

pub mod ballistics;
pub mod camera;
pub mod config;
pub mod input;

mod plugininfo;
mod runtime;

use libnvse::api::event_manager::EventManager;
use libnvse::api::interface::NVSEInterfaceError;
use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};
use libnvse::api::player_controls::PlayerControls;
use libnvse::plugin::{PluginContext, PluginError};
use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
use std::path::PathBuf;
use thiserror::Error;

/// Fallout: New Vegas 1.4.0.525's packed xNVSE runtime version.
const SUPPORTED_RUNTIME_VERSION: u32 = 0x0400_20D0;

/// Report Atom's stable plugin identity and supported runtime to xNVSE.
///
/// Atom deliberately rejects the editor, no-gore executable, and other
/// runtime versions before any callback can reach fixed engine addresses.
/// Deferred installation additionally validates the exact call contexts, so a
/// same-version executable with a different binary shape fails locally.
///
/// # Safety
///
/// `nvse` and `info` must be the pointers supplied by xNVSE during plugin
/// query. `info` must be writable for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    nvse: *const NVSEInterfaceFFI,
    info: *mut PluginInfoFFI,
) -> bool {
    let Some(nvse) = (unsafe { nvse.as_ref() }) else {
        return false;
    };
    let Some(info) = (unsafe { info.as_mut() }) else {
        return false;
    };

    info.infoVersion = plugininfo::PLUGIN_INFO_VERSION;
    info.name = plugininfo::PLUGIN_NAME.as_ptr();
    info.version = plugininfo::PLUGIN_VERSION;

    nvse.isEditor == 0 && nvse.isNogore == 0 && nvse.runtimeVersion == SUPPORTED_RUNTIME_VERSION
}

/// Register Atom's xNVSE lifecycle listener without starting gameplay work.
///
/// The retained [`PluginContext`] owns the callback thunk registered with
/// xNVSE. Dropping it after this function returned would leave xNVSE with a
/// stale callback pointer, so successful load intentionally gives it process
/// lifetime.
///
/// # Safety
///
/// `nvse` must be the interface pointer supplied by xNVSE during plugin load
/// and must remain valid for the game process lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Load(nvse: *const NVSEInterfaceFFI) -> bool {
    match plugin_load(nvse) {
        Ok(()) => true,
        Err(error) => {
            log::error!("[INIT] xNVSE plugin load failed: {error:#}");
            false
        }
    }
}

#[derive(Debug, Error)]
enum PluginLoadError {
    #[error("NVSE interface is NULL")]
    NullInterface,
    #[error(transparent)]
    Nvse(#[from] PluginError),
}

/// Process-lifetime services acquired while xNVSE identifies Atom as loading.
///
/// xNVSE asserts if `GetPluginHandle` is called from a later lifecycle
/// callback. Keeping the already-created interface wrappers in the registered
/// closure follows the same ownership model as OMV's retained
/// [`PluginContext`] and prevents DeferredInit from reconstructing an xNVSE
/// owner.
struct NvseServices {
    runtime_directory: PathBuf,
    event_manager: Result<EventManager, NVSEInterfaceError>,
    player_controls: Result<PlayerControls, NVSEInterfaceError>,
}

fn plugin_load(nvse: *const NVSEInterfaceFFI) -> Result<(), PluginLoadError> {
    if unsafe { nvse.as_ref() }.is_none() {
        return Err(PluginLoadError::NullInterface);
    }

    let mut context = PluginContext::new(nvse, plugininfo::PLUGIN_NAME)?;
    let services = NvseServices {
        runtime_directory: PathBuf::from(context.game_directory()?),
        event_manager: context.low_level().query_event_manager(),
        player_controls: context
            .low_level()
            .query_player_controls(plugininfo::PLUGIN_NAME),
    };
    context.on_message(move |message| handle_message(message, &services))?;

    // xNVSE owns the registered callback address for the entire session.
    std::mem::forget(context);
    Ok(())
}

fn handle_message(message: &NVSEMessage, services: &NvseServices) {
    match message.get_type() {
        NVSEMessageType::DeferredInit => {
            if let Err(error) = runtime::initialize(
                services.runtime_directory.as_path(),
                services.event_manager.as_ref(),
                services.player_controls.as_ref(),
            ) {
                log::error!("[INIT] Atom is unavailable because DeferredInit failed: {error:#}");
            }
        }
        NVSEMessageType::PreLoadGame
        | NVSEMessageType::NewGame
        | NVSEMessageType::ExitToMainMenu
        | NVSEMessageType::ExitGame
        | NVSEMessageType::ExitGame_Console => {
            ballistics::clear_observations();
            camera::request_reset();
        }
        NVSEMessageType::OnFramePresent => {
            input::finish_frame();
            input::telemetry::mark_present();
            camera::finish_frame();
        }
        _ => {}
    }
}

/// Publish an external native owner for Atom's camera outputs.
///
/// Vehicle and scripted-camera providers may call this C ABI with a stable
/// nonzero token. `active` is `1` to acquire ownership and `0` to release it.
/// The function returns `1` when the request is accepted. While any token is
/// active, Atom performs no camera, movement, facing, or aim writes.
#[unsafe(no_mangle)]
pub extern "C" fn AtomCamera_SetExternalOwner(owner_token: u32, active: u8) -> u8 {
    if active > 1 {
        return 0;
    }
    u8::from(camera::set_external_owner(owner_token, active != 0))
}

#[cfg(test)]
mod tests {
    use super::{NVSEPlugin_Query, SUPPORTED_RUNTIME_VERSION, plugininfo};
    use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};

    fn supported_interface() -> NVSEInterfaceFFI {
        NVSEInterfaceFFI {
            runtimeVersion: SUPPORTED_RUNTIME_VERSION,
            ..NVSEInterfaceFFI::default()
        }
    }

    #[test]
    fn query_publishes_identity_only_for_the_supported_game() {
        let nvse = supported_interface();
        let mut info = PluginInfoFFI::default();

        assert!(unsafe { NVSEPlugin_Query(&nvse, &mut info) });
        assert_eq!(info.infoVersion, plugininfo::PLUGIN_INFO_VERSION);
        assert_eq!(info.name, plugininfo::PLUGIN_NAME.as_ptr());
        assert_eq!(info.version, plugininfo::PLUGIN_VERSION);

        let mut editor = supported_interface();
        editor.isEditor = 1;
        assert!(!unsafe { NVSEPlugin_Query(&editor, &mut info) });

        let mut no_gore = supported_interface();
        no_gore.isNogore = 1;
        assert!(!unsafe { NVSEPlugin_Query(&no_gore, &mut info) });

        let unsupported = NVSEInterfaceFFI::default();
        assert!(!unsafe { NVSEPlugin_Query(&unsupported, &mut info) });
    }

    #[test]
    fn query_rejects_invalid_pointers() {
        let nvse = supported_interface();
        let mut info = PluginInfoFFI::default();

        assert!(!unsafe { NVSEPlugin_Query(std::ptr::null(), &mut info) });
        assert!(!unsafe { NVSEPlugin_Query(&nvse, std::ptr::null_mut()) });
    }
}
