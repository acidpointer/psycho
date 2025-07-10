#![allow(non_camel_case_types, dead_code, non_snake_case, unused_imports, non_upper_case_globals)]


/// An unsigned 8-bit integer value
pub type UInt8 = u8;

/// An unsigned 16-bit integer value
pub type UInt16 = u16;

/// An unsigned 32-bit integer value
pub type UInt32 = u32;

/// An unsigned 64-bit integer value
pub type UInt64 = u64;

/// A signed 8-bit integer value
pub type SInt8 = i8;

/// A signed 16-bit integer value
pub type SInt16 = i16;

/// A signed 32-bit integer value
pub type SInt32 = i32;

/// A signed 64-bit integer value
pub type SInt64 = i64;

/// A 32-bit floating point value
pub type Float32 = f32;

/// A 64-bit floating point value
pub type Float64 = f64;

pub type PluginHandle = UInt32;


pub const kPluginHandle_Invalid: UInt32 = 0xFFFFFFFF;


pub const kInterface_Invalid: UInt32 = 0;
pub const kInterface_Messaging: UInt32 = 1;
pub const kInterface_Scaleform: UInt32 = 2;
pub const kInterface_Papyrus: UInt32 = 3;
pub const kInterface_Serialization: UInt32 = 4;
pub const kInterface_Task: UInt32 = 5;
pub const kInterface_Object: UInt32 = 6;
pub const kInterface_Trampoline: UInt32 = 7;
pub const kInterface_Max: UInt32 = 8;


#[repr(C)]
pub struct PluginInfo {
    pub infoVersion: UInt32,

    pub version: UInt32,

    pub name: *const libc::c_char,
}

impl PluginInfo {
    pub const kInfoVersion: UInt32 = 1;
}

/// FFI type for F4SEInterface
/// Source: f4se/PluginAPI.h
#[repr(C)]
pub struct F4SEInterface {
    pub f4seVersion: UInt32,
    pub runtimeVersion: UInt32,
    pub editorVersion: UInt32,
    pub isEditor: UInt32,
    pub QueryInterface: Option<unsafe extern "C" fn (id: UInt32) -> *mut libc::c_void>,

    /// Call during your Query or Load functions to get a PluginHandle uniquely identifying your plugin
    /// invalid if called at any other time, so call it once and save the result
    pub GetPluginHandle: Option<unsafe extern "C" fn() -> PluginHandle>,

    /// Returns the F4SE build's release index
    pub GetReleaseIndex: Option<unsafe extern "C" fn() -> UInt32>,

    /// Minimum F4SE version 0.6.22
    /// returns the plugin info structure for a plugin by name, only valid to be called after PostLoad message
    pub GetPluginInfo: Option<unsafe extern "C" fn(name: *const libc::c_char) -> *const PluginInfo>,
}



///  Messaging API docs
///  Messaging API allows inter-plugin communication at run-time. A plugin may register
///  one callback for each plugin from which it wishes to receive messages, specifying
///  the sender by name in the call to RegisterListener(). RegisterListener returns false
///  if the specified plugin is not loaded, true otherwise. Any messages dispatched by
///  the specified plugin will then be forwarded to the listener as they occur. Passing NULL as 
///  the sender registers the calling plugin as a listener to every loaded plugin.
///  
///  Messages may be dispatched via Dispatch() to either a specific listener (specified
///  by name) or to all listeners (with NULL passed as the receiver). The contents and format of
///  messageData are left up to the sender, and the receiver is responsible for casting the message
///  to the expected type. If no plugins are registered as listeners for the sender, 
///  Dispatch() returns false, otherwise it returns true.
///  
///  Calling RegisterListener() or Dispatch() during plugin load is not advised as the requested plugin
///  may not yet be loaded at that point. Instead, if you wish to register as a listener or dispatch a
///  message immediately after plugin load, use RegisterListener() during load to register to receive
///  messages from F4SE (sender name: "F4SE"). You will then receive a message from F4SE once 
///  all plugins have been loaded, at which point it is safe to establish communications between
///  plugins.
///  
///  Some plugin authors may wish to use strings instead of integers to denote message type. In
///  that case the receiver can pass the address of the string as an integer and require the receiver
///  to cast it back to a char* on receipt.
#[repr(C)]
pub struct F4SEMessagingInterface {
    pub RegisterListener: Option<unsafe extern "C" fn(listener: PluginHandle, sender: *const libc::c_char, handler: F4SEMessagingInterface_EventCallback) -> bool>,
    pub Dispatch: Option<unsafe extern "C" fn(sender: PluginHandle, messageType: UInt32, data: *mut libc::c_void, dataLen: UInt32, receiver: *const libc::c_char)>,
    
    /// Use this to acquire F4SE's internal EventDispatchers so that you can sink to them. Currently none implemented yet
    pub GetEventDispatcher: Option<unsafe extern "C" fn(dispatcherId: UInt32) -> *mut libc::c_void>,
}

impl F4SEMessagingInterface {
    pub const kInterfaceVersion: UInt32 = 1;


    // Messages:

    /// Sent to registered plugins once all plugins have been loaded (no data)
    pub const kMessage_PostLoad: UInt32 = 0;

    /// Sent right after kMessage_PostLoad to facilitate the correct dispatching/registering of messages/listeners
    pub const kMessage_PostPostLoad: UInt32 = 1;

    /// Dispatched immediately before savegame is read by Fallout
    /// dataLen: length of file path, data: char* file path of .ess savegame file
    pub const kMessage_PreLoadGame: UInt32 = 2;

    /// Dispatched after an attempt to load a saved game has finished (the game's LoadGame() routine has returned). 
    /// You will probably want to handle this event if your plugin uses a Preload callback
    /// as there is a chance that after that callback is invoked the game will encounter an error
    /// while loading the saved game (eg. corrupted save) which may require you to reset some of your plugin state.
    /// 
    /// data: bool, true if game successfully loaded, false otherwise
    ///       plugins may register as listeners during the first callback while deferring dispatches until the next
    pub const kMessage_PostLoadGame: UInt32 = 3;

    /// Right before the game is saved
    pub const kMessage_PreSaveGame: UInt32 = 4;

    /// Right after the game is saved
    pub const kMessage_PostSaveGame: UInt32 = 5;

    /// Sent right before deleting the .f4se cosave and the .ess save.
    /// dataLen: length of file path, data: char* file path of .ess savegame file
    pub const kMessage_DeleteGame: UInt32 = 6;

    /// Sent right after game input is loaded, right before the main menu initializes
    pub const kMessage_InputLoaded: UInt32 = 7;

    /// Sent after a new game is created, before the game has loaded (Sends CharGen TESQuest pointer)
    pub const kMessage_NewGame: UInt32 = 8;

    /// Sent after the game has finished loading (only sent once)
    pub const kMessage_GameLoaded: UInt32 = 9;

    /// Sent when the data handler is ready (data is false before loading, true when finished loading)
    pub const kMessage_GameDataReady: UInt32 = 10;
}


#[repr(C)]
pub struct F4SEMessagingInterface_Message {
    pub sender: *const std::ffi::c_char,
    pub r#type: UInt32,
    pub dataLen: UInt32,
    pub data: *mut std::ffi::c_void,
}

pub type F4SEMessagingInterface_EventCallback = Option<unsafe extern "C" fn(msg: *mut F4SEMessagingInterface_Message)>;


#[repr(C)]
pub struct F4SESerializationInterface {
    pub version: UInt32,

    pub SetUniqueID: Option<unsafe extern "C" fn(plugin: PluginHandle, uid: UInt32)>,
    pub SetRevertCallback: Option<unsafe extern "C" fn(plugin: PluginHandle, callback: F4SESerializationInterface_EventCallback)>,
    pub SetSaveCallback: Option<unsafe extern "C" fn(plugin: PluginHandle, callback: F4SESerializationInterface_EventCallback)>,
    pub SetLoadCallback: Option<unsafe extern "C" fn(plugin: PluginHandle, callback: F4SESerializationInterface_EventCallback)>,
    pub SetFormDeleteCallback: Option<unsafe extern "C" fn(plugin: PluginHandle, callback: F4SESerializationInterface_EventCallback)>,

    pub WriteRecord: Option<unsafe extern "C" fn(r#type: UInt32, version: UInt32, buf: *const libc::c_void, length: UInt32) -> bool>,
    pub OpenRecord: Option<unsafe extern "C" fn(r#type: UInt32, version: UInt32) -> bool>,
    pub WriteRecordData: Option<unsafe extern "C" fn(buf: *const libc::c_void, length: UInt32) -> bool>,

    pub GetNextRecordInfo: Option<unsafe extern "C" fn(r#type: *mut UInt32, version: *mut UInt32, length: *mut UInt32) -> bool>,
    pub ReadRecordData: Option<unsafe extern "C" fn(buf: *mut libc::c_void, length: UInt32) -> UInt32>,
    pub ResolveHandle: Option<unsafe extern "C" fn(handle: UInt64, handleOut: *mut UInt64) -> bool>,
    pub ResolveFormId: Option<unsafe extern "C" fn(formId: UInt32, formIdOut: *mut UInt32) -> bool>,
}

pub type F4SESerializationInterface_EventCallback = Option<unsafe extern "C" fn(intfc: *const F4SESerializationInterface)>;

impl F4SESerializationInterface {
    pub const kInterfaceVersion: UInt32 = 1;
}
