//! High-level, safe API for xNVSE plugin development.
//!
//! This module provides a **zero-unsafe** interface for building Fallout: New
//! Vegas plugins entirely in Rust. All string handling uses standard Rust
//! `String` / `&str`. All game objects are referenced by [`FormId`] instead of
//! raw pointers.
//!
//! # Getting started
//!
//! ```no_run
//! use libnvse::plugin::prelude::*;
//!
//! // 1. Query -- tell NVSE about your plugin
//! #[unsafe(no_mangle)]
//! pub unsafe extern "C" fn NVSEPlugin_Query(
//!     _nvse: *const libnvse::NVSEInterfaceFFI,
//!     info: *mut libnvse::PluginInfoFFI,
//! ) -> bool {
//!     let info = unsafe { &mut *info };
//!     info.name = c"my-rust-plugin".as_ptr();
//!     info.version = 1;
//!     true
//! }
//!
//! // 2. Load -- set up your plugin (all safe code from here)
//! #[unsafe(no_mangle)]
//! pub unsafe extern "C" fn NVSEPlugin_Load(
//!     nvse: *const libnvse::NVSEInterfaceFFI,
//! ) -> bool {
//!     match plugin_main(nvse) {
//!         Ok(()) => true,
//!         Err(e) => { log::error!("Plugin load failed: {}", e); false }
//!     }
//! }
//!
//! // All your plugin logic lives here -- fully safe Rust.
//! fn plugin_main(nvse: *const libnvse::NVSEInterfaceFFI) -> Result<(), PluginError> {
//!     let mut ctx = PluginContext::new(nvse)?;
//!
//!     ctx.on_message(|msg| {
//!         if msg.get_type() == MessageType::DeferredInit {
//!             log::info!("My plugin is ready!");
//!         }
//!     })?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Recipes
//!
//! ## Run console commands
//!
//! The console is the safest way to interact with the game world.
//! Every vanilla and NVSE script command is available.
//!
//! ```no_run
//! fn do_stuff(ctx: &PluginContext) -> Result<(), PluginError> {
//!     let con = ctx.console()?;
//!
//!     // Give the player 100 caps
//!     con.run("player.additem F 100")?;
//!
//!     // Heal the player
//!     con.run("player.restoreav health 999")?;
//!
//!     // Set a global variable
//!     con.run("set MyGlobalVar to 42")?;
//!
//!     // Silently (no console echo)
//!     con.run_silent("set SomeInternalVar to 1")?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Persist data across saves (co-save)
//!
//! ```no_run
//! use std::sync::Mutex;
//!
//! static STATE: Mutex<MyState> = Mutex::new(MyState::default());
//!
//! struct MyState {
//!     kill_count: u32,
//!     player_name: String,
//!     hardcore: bool,
//! }
//!
//! fn setup_cosave(ctx: &mut PluginContext) -> Result<(), PluginError> {
//!     ctx.on_save(|writer| {
//!         let state = STATE.lock().unwrap();
//!         writer.write(b"STAT", 1, |w| {
//!             w.write_u32(state.kill_count)?;
//!             w.write_string(&state.player_name)?;
//!             w.write_bool(state.hardcore)?;
//!             Ok(())
//!         })
//!     })?;
//!
//!     ctx.on_load(|reader| {
//!         let mut state = STATE.lock().unwrap();
//!         while let Some(rec) = reader.next_record()? {
//!             if rec.tag == *b"STAT" {
//!                 state.kill_count = reader.read_u32()?;
//!                 state.player_name = reader.read_string()?;
//!                 state.hardcore = reader.read_bool()?;
//!             } else {
//!                 reader.skip(rec.length)?;
//!             }
//!         }
//!         Ok(())
//!     })?;
//!
//!     ctx.on_new_game(|| {
//!         let mut state = STATE.lock().unwrap();
//!         *state = MyState::default();
//!     })?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## React to game events via messages
//!
//! ```no_run
//! fn setup_messages(ctx: &mut PluginContext) -> Result<(), PluginError> {
//!     ctx.on_message(|msg| {
//!         match msg.get_type() {
//!             MessageType::PostLoad => {
//!                 log::info!("All plugins loaded");
//!             }
//!             MessageType::DeferredInit => {
//!                 log::info!("Game engine ready -- safe to call console");
//!             }
//!             MessageType::LoadGame => {
//!                 if let Some(path) = msg.data_as_path() {
//!                     log::info!("Loading save: {}", path);
//!                 }
//!             }
//!             MessageType::SaveGame => {
//!                 if let Some(path) = msg.data_as_path() {
//!                     log::info!("Saving: {}", path);
//!                 }
//!             }
//!             MessageType::MainGameLoop => {
//!                 // Called every frame -- use sparingly!
//!             }
//!             _ => {}
//!         }
//!     })?;
//!     Ok(())
//! }
//! ```
//!
//! ## Toggle player controls
//!
//! ```no_run
//! fn freeze_player(ctx: &PluginContext) -> Result<(), PluginError> {
//!     let ctrl = ctx.player_controls()?;
//!     ctrl.disable(Controls::MOVEMENT | Controls::JUMPING)?;
//!     // ... later ...
//!     ctrl.enable(Controls::MOVEMENT | Controls::JUMPING)?;
//!     Ok(())
//! }
//! ```
//!
//! ## Show in-game message box
//!
//! ```no_run
//! fn greet(ctx: &PluginContext) -> Result<(), PluginError> {
//!     ctx.message_box("Hello from Rust!", "Cool")?;
//!     Ok(())
//! }
//! ```
//!
//! ## Work with NVSE string variables
//!
//! ```no_run
//! fn string_demo(ctx: &PluginContext) -> Result<(), PluginError> {
//!     let strings = ctx.string_vars()?;
//!
//!     // Create a new string variable
//!     let id = strings.create("Hello from Rust!")?;
//!     log::info!("Created string var with ID {}", id);
//!
//!     // Read it back
//!     let value = strings.get(id)?;
//!     assert_eq!(value, "Hello from Rust!");
//!
//!     // Update it
//!     strings.set(id, "Updated!")?;
//!     Ok(())
//! }
//! ```
//!
//! ## Dispatch messages to other plugins
//!
//! ```no_run
//! fn notify_other_plugins(ctx: &PluginContext) -> Result<(), PluginError> {
//!     // Broadcast to all plugins
//!     ctx.dispatch_message(1000, b"hello", None)?;
//!
//!     // Send to a specific plugin
//!     ctx.dispatch_message(1000, b"hello", Some("OtherPlugin"))?;
//!     Ok(())
//! }
//! ```

pub mod cosave;
pub mod types;

use std::ffi::CStr;

use crate::api::console::{Console, ConsoleError};
use crate::api::interface::{NVSEInterface, NVSEInterfaceError};
use crate::api::message_box::{MessageBox, MessageBoxError};
use crate::api::messaging::{NVSEMessage, NVSEMessagingInterfaceError};
use crate::api::player_controls::{
    ControlFlags, PlayerControls, PlayerControlsError,
};
use crate::api::serialization::SerializationError;
use crate::api::string_var::{StringVarError, StringVars};
use crate::NVSEInterfaceFFI;

use self::cosave::SaveError;
use self::types::FormId;

// ---------------------------------------------------------------------------
// Prelude
// ---------------------------------------------------------------------------

/// Convenient glob import for plugin development.
///
/// ```
/// use libnvse::plugin::prelude::*;
/// ```
pub mod prelude {
    pub use super::cosave::{LoadReader, Record, SaveError, SaveWriter};
    pub use super::types::{ArrayId, FormId, Value};
    pub use super::{PluginContext, PluginError};
    pub use crate::api::command::{CommandContext, Param, ParamType, ReturnType};
    pub use crate::api::hud::Emotion;
    pub use crate::api::messaging::NVSEMessageType as MessageType;
    pub use crate::api::player_controls::ControlFlags as Controls;
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Unified error type for the high-level plugin API.
///
/// Wraps all possible errors from the underlying interfaces into a
/// single type so plugin code can use a single `?` operator.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("NVSE interface error: {0}")]
    Interface(#[from] NVSEInterfaceError),

    #[error("Messaging error: {0}")]
    Messaging(#[from] NVSEMessagingInterfaceError),

    #[error("Console error: {0}")]
    Console(#[from] ConsoleError),

    #[error("Player controls error: {0}")]
    Controls(#[from] PlayerControlsError),

    #[error("String variable error: {0}")]
    StringVar(#[from] StringVarError),

    #[error("Save/Load error: {0}")]
    Save(#[from] SaveError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("Message box error: {0}")]
    MessageBox(#[from] MessageBoxError),

    #[error("HUD error: {0}")]
    Hud(#[from] crate::api::hud::HudError),

    #[error("Command error: {0}")]
    Command(#[from] crate::api::command::CommandError),
}

// ---------------------------------------------------------------------------
// Safe string variable wrapper
// ---------------------------------------------------------------------------

/// Safe string variable interface using standard Rust strings.
///
/// Wraps the low-level `StringVars` interface so callers never deal
/// with C strings or WinAPI conversions.
pub struct StringApi {
    inner: StringVars,
}

impl StringApi {
    fn new(inner: StringVars) -> Self {
        Self { inner }
    }

    /// Get the value of a string variable by its ID.
    pub fn get(&self, id: u32) -> Result<String, PluginError> {
        let s = self.inner.get(id)?;
        Ok(s.to_string())
    }

    /// Set the value of an existing string variable.
    pub fn set(&self, id: u32, value: &str) -> Result<(), PluginError> {
        self.inner.set(id, value)?;
        Ok(())
    }

    /// Create a new string variable with an initial value.
    ///
    /// Returns the integer ID that scripts use to reference this string.
    pub fn create(&self, value: &str) -> Result<u32, PluginError> {
        let id = self.inner.create(value, std::ptr::null_mut())?;
        Ok(id)
    }
}

// ---------------------------------------------------------------------------
// Safe console wrapper
// ---------------------------------------------------------------------------

/// Safe console command interface using Rust strings.
pub struct ConsoleApi {
    inner: Console,
}

impl ConsoleApi {
    fn new(inner: Console) -> Self {
        Self { inner }
    }

    /// Execute a console command.
    ///
    /// Equivalent to typing the command in the in-game console (~).
    ///
    /// # Common commands
    ///
    /// ```no_run
    /// con.run("player.additem F 100")?;          // give 100 caps
    /// con.run("player.setav health 200")?;        // set health to 200
    /// con.run("set MyGlobal to 1")?;              // set a global variable
    /// con.run("player.placeatme A1B2C 1")?;       // spawn an NPC
    /// con.run("player.moveto 123ABC")?;            // teleport
    /// ```
    pub fn run(&self, command: &str) -> Result<(), PluginError> {
        self.inner.run(command)?;
        Ok(())
    }

    /// Execute a console command silently (no console output).
    pub fn run_silent(&self, command: &str) -> Result<(), PluginError> {
        self.inner.run_silent(command)?;
        Ok(())
    }

    /// Execute a console command targeting a specific form by ID.
    ///
    /// Equivalent to clicking a ref in console then typing the command.
    ///
    /// # Example
    ///
    /// ```no_run
    /// // Disable a specific object (hex form ID)
    /// con.run_on(FormId::new(0x123ABC), "disable")?;
    ///
    /// // Kill a specific NPC
    /// con.run_on(some_npc_id, "kill")?;
    /// ```
    pub fn run_on(&self, target: FormId, command: &str) -> Result<(), PluginError> {
        // Use prid (pick ref by ID) then execute on it
        self.inner
            .run_silent(&format!("prid {:X}", target.raw()))?;
        self.inner.run(command)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Safe player controls wrapper
// ---------------------------------------------------------------------------

/// Safe player controls interface.
pub struct ControlsApi {
    inner: PlayerControls,
}

impl ControlsApi {
    fn new(inner: PlayerControls) -> Self {
        Self { inner }
    }

    /// Disable specific player controls.
    ///
    /// Changes are tracked per-plugin and reset on save load.
    pub fn disable(&self, flags: ControlFlags) -> Result<(), PluginError> {
        self.inner.disable(flags)?;
        Ok(())
    }

    /// Re-enable specific player controls.
    pub fn enable(&self, flags: ControlFlags) -> Result<(), PluginError> {
        self.inner.enable(flags)?;
        Ok(())
    }

    /// Check if specific controls are currently disabled (by any source).
    pub fn is_disabled(&self, flags: ControlFlags) -> bool {
        self.inner.is_disabled(flags)
    }
}

// ---------------------------------------------------------------------------
// PluginContext
// ---------------------------------------------------------------------------

/// Main entry point for the high-level plugin API.
///
/// Create one in your `NVSEPlugin_Load` function and use it to register
/// message handlers, co-save callbacks, and access game interfaces.
///
/// # Lifetime
///
/// `PluginContext` should be created once during plugin load. Closures
/// registered through it (message handlers, save/load callbacks) live
/// for the entire game session.
///
/// # Thread safety
///
/// NVSE is single-threaded. All callbacks run on the main game thread.
/// You may use `Mutex`/`RwLock` for your own state if you spawn threads,
/// but NVSE interface calls must happen on the main thread.
pub struct PluginContext {
    inner: NVSEInterface<'static>,
    /// Plugin name for player controls per-mod tracking.
    plugin_name: &'static CStr,
    /// Serialization interface -- must be kept alive for the entire game
    /// session because it owns the BareFn closures that NVSE calls back.
    serialization: Option<crate::api::serialization::Serialization<'static>>,
    /// Command builder -- keeps leaked strings and param arrays alive.
    commands: Option<crate::api::command::CommandBuilder>,
}

impl PluginContext {
    /// Initialize the plugin context from the raw NVSE interface pointer.
    ///
    /// Call this once at the start of `NVSEPlugin_Load`.
    ///
    /// `plugin_name` is used to identify your plugin for per-mod control
    /// tracking. Must be a `&'static CStr` (use `c"my-plugin"`).
    pub fn new(
        nvse_ptr: *const NVSEInterfaceFFI,
        plugin_name: &'static CStr,
    ) -> Result<Self, PluginError> {
        let inner = NVSEInterface::from_raw(nvse_ptr)?;
        Ok(Self {
            inner,
            plugin_name,
            serialization: None,
            commands: None,
        })
    }

    // -- Version info -------------------------------------------------------

    /// Get the xNVSE version string.
    pub fn nvse_version(&self) -> String {
        format!("{}", self.inner.nvse_version())
    }

    /// Get the game runtime version string.
    pub fn runtime_version(&self) -> String {
        format!("{}", self.inner.runtime_version())
    }

    /// Check if running inside the GECK editor (not the game).
    pub fn is_editor(&self) -> bool {
        self.inner.is_editor()
    }

    /// Get the game's installation directory.
    pub fn game_directory(&self) -> Result<String, PluginError> {
        Ok(self.inner.runtime_directory()?.to_string())
    }

    /// Get the raw plugin handle (for advanced low-level use).
    pub fn plugin_handle(&self) -> u32 {
        self.inner.get_plugin_handle().get_handle()
    }

    // -- Messaging ----------------------------------------------------------

    /// Register a handler for NVSE system messages.
    ///
    /// Your callback is invoked on the main thread for every NVSE event:
    /// game loads, saves, new games, main loop ticks, etc.
    ///
    /// See [`NVSEMessageType`](crate::api::messaging::NVSEMessageType) for
    /// all message types.
    pub fn on_message<F>(&mut self, cb: F) -> Result<(), PluginError>
    where
        F: Fn(&NVSEMessage) + 'static,
    {
        self.inner
            .messaging_interface_mut()
            .register_listener("NVSE", cb)?;
        Ok(())
    }

    /// Register a handler for messages from a specific plugin.
    pub fn on_plugin_message<F>(&mut self, sender: &str, cb: F) -> Result<(), PluginError>
    where
        F: Fn(&NVSEMessage) + 'static,
    {
        self.inner
            .messaging_interface_mut()
            .register_listener(sender, cb)?;
        Ok(())
    }

    /// Dispatch a message to other plugins.
    ///
    /// - `message_type` - Your plugin-defined message type ID
    /// - `data` - Raw bytes (receiver must know the format)
    /// - `receiver` - Target plugin name, or None to broadcast
    pub fn dispatch_message(
        &self,
        message_type: u32,
        data: &[u8],
        receiver: Option<&str>,
    ) -> Result<bool, PluginError> {
        let result = self
            .inner
            .messaging_interface_ref()
            .dispatch(message_type, data, receiver)?;
        Ok(result)
    }

    // -- Console ------------------------------------------------------------

    /// Get the safe console interface.
    pub fn console(&self) -> Result<ConsoleApi, PluginError> {
        let inner = self.inner.query_console()?;
        Ok(ConsoleApi::new(inner))
    }

    // -- Commands -----------------------------------------------------------

    /// Lazily initialize the command builder.
    fn commands_mut(
        &mut self,
    ) -> Result<&mut crate::api::command::CommandBuilder, PluginError> {
        if self.commands.is_none() {
            let builder = self.inner.command_builder()?;
            self.commands = Some(builder);
        }
        Ok(self.commands.as_mut().expect("just initialized"))
    }

    /// Set the opcode base for command registration.
    ///
    /// Must be called before registering any commands.
    /// The base is assigned by the xNVSE team to avoid conflicts.
    pub fn set_opcode_base(&mut self, opcode: u32) -> Result<(), PluginError> {
        self.commands_mut()?.set_opcode_base(opcode)?;
        Ok(())
    }

    /// Register a command. Use `nvse_command!` macro to define the handler.
    ///
    /// ```no_run
    /// use libnvse::nvse_command;
    ///
    /// nvse_command!(MyCmd, cmd, {
    ///     cmd.print("Hello!");
    ///     cmd.set_result(1.0);
    ///     true
    /// });
    ///
    /// ctx.set_opcode_base(0x3000)?;
    /// ctx.register_command("MyCmd", "mc", "Does something",
    ///     false, &[], MY_CMD_EXECUTE)?;
    /// ```
    pub fn register_command(
        &mut self,
        name: &str,
        short_name: &str,
        help: &str,
        needs_ref: bool,
        params: &[crate::api::command::Param],
        execute: crate::Cmd_Execute,
    ) -> Result<(), PluginError> {
        self.commands_mut()?
            .register(name, short_name, help, needs_ref, params, execute)?;
        Ok(())
    }

    // -- Player controls ----------------------------------------------------

    /// Get the safe player controls interface.
    pub fn player_controls(&self) -> Result<ControlsApi, PluginError> {
        let inner = self.inner.query_player_controls(self.plugin_name)?;
        Ok(ControlsApi::new(inner))
    }

    // -- String variables ---------------------------------------------------

    /// Get the safe string variable interface.
    pub fn string_vars(&self) -> Result<StringApi, PluginError> {
        let inner = self.inner.query_string_vars()?;
        Ok(StringApi::new(inner))
    }

    // -- Message box --------------------------------------------------------

    /// Show a simple in-game message box (no custom callback).
    ///
    /// Uses the game's default callback. No ownership concerns.
    pub fn message_box(&self, message: &str, button_text: &str) -> Result<(), PluginError> {
        MessageBox::show_simple(message, button_text)?;
        Ok(())
    }

    /// Show an in-game message box with a custom callback.
    ///
    /// Returns a [`MessageBox`] that owns the callback. You MUST keep
    /// the returned value alive until the player clicks the button.
    ///
    /// ```no_run
    /// let _dialog = ctx.message_box_with_callback("Save?", "Yes", || {
    ///     log::info!("Player said yes");
    /// })?;
    /// // _dialog must stay alive until the player clicks
    /// ```
    pub fn message_box_with_callback<F: Fn() + 'static>(
        &self,
        message: &str,
        button_text: &str,
        on_click: F,
    ) -> Result<MessageBox<'static>, PluginError> {
        Ok(MessageBox::show(message, button_text, on_click)?)
    }

    // -- HUD notifications ---------------------------------------------------

    /// Show a corner notification with the default Vault Boy face.
    ///
    /// These are the small auto-dismissing messages in the top-left corner.
    /// Fire-and-forget, no ownership concerns.
    pub fn hud_message(&self, message: &str) -> Result<(), PluginError> {
        crate::api::hud::hud_message(message)?;
        Ok(())
    }

    /// Show a corner notification with a specific emotion and duration.
    pub fn hud_message_with(
        &self,
        message: &str,
        emotion: crate::api::hud::Emotion,
        duration: f32,
    ) -> Result<(), PluginError> {
        crate::api::hud::hud_message_with(message, emotion, duration)?;
        Ok(())
    }

    // -- Co-save (serialization) --------------------------------------------

    /// Lazily initialize and return a mutable reference to the
    /// serialization interface. The instance is kept alive in `self`
    /// so that registered BareFn closures are never freed.
    fn serialization_mut(
        &mut self,
    ) -> Result<&mut crate::api::serialization::Serialization<'static>, PluginError> {
        if self.serialization.is_none() {
            let ser = self.inner.query_serialization()?;
            self.serialization = Some(ser);
        }
        Ok(self.serialization.as_mut().expect("just initialized"))
    }

    /// Register a save callback.
    ///
    /// Called each time the player saves the game. Put your data
    /// persistence logic here.
    pub fn on_save<F>(&mut self, cb: F) -> Result<(), PluginError>
    where
        F: Fn() + 'static,
    {
        let handle = self.inner.get_plugin_handle().get_handle();
        self.serialization_mut()?.set_save_callback(handle, cb)?;
        Ok(())
    }

    /// Register a load callback.
    ///
    /// Called each time the player loads a save. Restore your
    /// persisted state here.
    pub fn on_load<F>(&mut self, cb: F) -> Result<(), PluginError>
    where
        F: Fn() + 'static,
    {
        let handle = self.inner.get_plugin_handle().get_handle();
        self.serialization_mut()?.set_load_callback(handle, cb)?;
        Ok(())
    }

    /// Register a new-game callback.
    ///
    /// Called when the player starts a new game. Use this to reset your
    /// plugin's state to defaults.
    pub fn on_new_game<F>(&mut self, cb: F) -> Result<(), PluginError>
    where
        F: Fn() + 'static,
    {
        let handle = self.inner.get_plugin_handle().get_handle();
        self.serialization_mut()?
            .set_new_game_callback(handle, cb)?;
        Ok(())
    }

    // -- Low-level access (escape hatch) ------------------------------------

    /// Get a reference to the underlying low-level NVSEInterface.
    ///
    /// Use this when you need functionality not yet covered by the
    /// high-level API (e.g., command registration, event manager).
    pub fn low_level(&self) -> &NVSEInterface<'static> {
        &self.inner
    }

    /// Get a mutable reference to the underlying low-level NVSEInterface.
    pub fn low_level_mut(&mut self) -> &mut NVSEInterface<'static> {
        &mut self.inner
    }
}
