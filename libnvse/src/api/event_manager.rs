//! Safe wrapper for the NVSE event manager interface.
//!
//! Allows plugins to:
//! - Register custom event types with typed parameters
//! - Dispatch events to scripts and other plugins
//! - Set native event handlers that respond to game events
//!
//! # Custom events
//!
//! Plugins can define their own events that scripts can listen to:
//!
//! ```no_run
//! use libnvse::api::event_manager::{EventParamType, EventFlags};
//!
//! // Define parameter types (must be 'static - stored permanently)
//! static MY_PARAMS: &[EventParamType] = &[
//!     EventParamType::AnyForm,
//!     EventParamType::String,
//! ];
//!
//! // Register the event
//! events.register_event("MyPlugin:OnSomething", MY_PARAMS, EventFlags::NONE)?;
//!
//! // Later, dispatch it when something happens
//! events.dispatch("MyPlugin:OnSomething", some_ref, some_form_ptr, some_string_ptr)?;
//! ```
//!
//! # Native event handlers
//!
//! ```no_run
//! // Handle an existing game event
//! events.set_native_handler("OnHit", my_on_hit_handler)?;
//! ```

use std::ptr::NonNull;

use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

use crate::{
    NVSEEventManagerInterface as NVSEEventManagerInterfaceFFI,
    NVSEEventManagerInterface_DispatchReturn as DispatchReturnFFI,
    NVSEEventManagerInterface_EventFlags as EventFlagsFFI,
    NVSEEventManagerInterface_NativeEventHandler as NativeEventHandlerFFI,
    NVSEEventManagerInterface_ParamType as ParamTypeFFI, TESObjectREFR,
};

// -- Parameter types --------------------------------------------------------

/// Event parameter types for custom event registration.
///
/// These describe the types of values passed when dispatching an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventParamType {
    Float = 0,
    Int = 1,
    String = 2,
    Array = 3,
    AnyForm = 4,
    Reference = 5,
    BaseForm = 6,
    Invalid = 7,
    Anything = 8,
}

impl EventParamType {
    /// Convert to the FFI representation.
    pub fn to_ffi(self) -> ParamTypeFFI {
        // Safe: the enum values are identical
        unsafe { std::mem::transmute(self as u8) }
    }
}

// -- Event flags ------------------------------------------------------------

bitflags::bitflags! {
    /// Flags controlling event behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EventFlags: u32 {
        /// No special behavior.
        const NONE = 0;
        /// Remove all handlers when a save is loaded.
        const FLUSH_ON_LOAD = 1 << 0;
        /// Parameter types are determined at dispatch time.
        const HAS_UNKNOWN_ARG_TYPES = 1 << 1;
        /// Scripts can dispatch this event (via DispatchEvent).
        const ALLOW_SCRIPT_DISPATCH = 1 << 2;
        /// Combination of HAS_UNKNOWN_ARG_TYPES | ALLOW_SCRIPT_DISPATCH.
        const USER_DEFINED = 0b110;
        /// Report error if no handler returns a result.
        const REPORT_ERROR_IF_NO_RESULT = 1 << 3;
    }
}

// -- Dispatch return --------------------------------------------------------

/// Result of dispatching an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchReturn {
    /// Event name was not recognized.
    UnknownEvent,
    /// A generic error occurred.
    GenericError,
    /// Normal completion - all handlers ran.
    Normal,
    /// A handler requested early termination.
    EarlyBreak,
    /// Dispatch was deferred (thread-safe dispatch from non-main thread).
    Deferred,
}

impl From<DispatchReturnFFI> for DispatchReturn {
    fn from(val: DispatchReturnFFI) -> Self {
        match val {
            DispatchReturnFFI::kRetn_UnknownEvent => Self::UnknownEvent,
            DispatchReturnFFI::kRetn_GenericError => Self::GenericError,
            DispatchReturnFFI::kRetn_Normal => Self::Normal,
            DispatchReturnFFI::kRetn_EarlyBreak => Self::EarlyBreak,
            DispatchReturnFFI::kRetn_Deferred => Self::Deferred,
        }
    }
}

// -- Error ------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum EventManagerError {
    #[error("NVSEEventManagerInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("RegisterEvent function pointer is NULL")]
    RegisterEventIsNull,

    #[error("DispatchEvent function pointer is NULL")]
    DispatchEventIsNull,

    #[error("SetNativeEventHandler function pointer is NULL")]
    SetNativeHandlerIsNull,

    #[error("RemoveNativeEventHandler function pointer is NULL")]
    RemoveNativeHandlerIsNull,

    #[error("Event registration failed for: {0}")]
    RegistrationFailed(String),

    #[error("WinAPI error: {0}")]
    WinapiError(#[from] WinapiError),
}

pub type EventManagerResult<T> = Result<T, EventManagerError>;

// -- Wrapper ----------------------------------------------------------------

/// Safe wrapper around NVSEEventManagerInterface.
///
/// Provides event registration, dispatching, and native handler management.
pub struct EventManager {
    ptr: NonNull<NVSEEventManagerInterfaceFFI>,
}

impl EventManager {
    /// Create an EventManager wrapper from a raw FFI pointer.
    pub fn from_raw(raw: *mut NVSEEventManagerInterfaceFFI) -> EventManagerResult<Self> {
        let ptr = NonNull::new(raw).ok_or(EventManagerError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Register a new custom event type.
    ///
    /// `param_types` must be a static slice - NVSE keeps the pointer permanently.
    /// Convention: prefix event names with your plugin name (e.g. "MyPlugin:OnFoo").
    pub fn register_event(
        &self,
        name: &str,
        param_types: &'static [EventParamType],
        flags: EventFlags,
    ) -> EventManagerResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let register_fn = iface
            .RegisterEvent
            .ok_or(EventManagerError::RegisterEventIsNull)?;

        let win_name = WinString::new(name)?;
        let success = win_name.with_ansi(|name_ptr| unsafe {
            register_fn(
                name_ptr,
                param_types.len() as u8,
                // Safe: EventParamType and ParamTypeFFI have the same repr(u8) layout
                param_types.as_ptr() as *mut ParamTypeFFI,
                // SAFETY: EventFlagsFFI is repr(u32) matching C enum ABI.
                // Combined flag values are valid at ABI level even if not
                // named Rust enum discriminants.
                std::mem::transmute::<u32, EventFlagsFFI>(flags.bits()),
            )
        });

        if success {
            Ok(())
        } else {
            Err(EventManagerError::RegistrationFailed(name.to_string()))
        }
    }

    /// Register a custom event with an alternative name (alias).
    pub fn register_event_with_alias(
        &self,
        name: &str,
        alias: &str,
        param_types: &'static [EventParamType],
        flags: EventFlags,
    ) -> EventManagerResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let register_fn = iface
            .RegisterEventWithAlias
            .ok_or(EventManagerError::RegisterEventIsNull)?;

        let win_name = WinString::new(name)?;
        let win_alias = WinString::new(alias)?;

        let success = win_name.with_ansi(|name_ptr| {
            win_alias.with_ansi(|alias_ptr| unsafe {
                register_fn(
                    name_ptr,
                    alias_ptr,
                    param_types.len() as u8,
                    param_types.as_ptr() as *mut ParamTypeFFI,
                    std::mem::transmute::<u32, EventFlagsFFI>(flags.bits()),
                )
            })
        });

        if success {
            Ok(())
        } else {
            Err(EventManagerError::RegistrationFailed(name.to_string()))
        }
    }

    /// Set a native event handler for an existing event.
    ///
    /// The handler receives the calling reference and a pointer to the
    /// event parameters (layout depends on the event's param types).
    ///
    /// # Safety contract
    ///
    /// The `handler` function pointer must remain valid for the game session.
    /// Use a static/extern function, not a closure.
    pub fn set_native_handler(
        &self,
        event_name: &str,
        handler: NativeEventHandlerFFI,
    ) -> EventManagerResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetNativeEventHandler
            .ok_or(EventManagerError::SetNativeHandlerIsNull)?;

        let win_name = WinString::new(event_name)?;
        let success = win_name.with_ansi(|name_ptr| unsafe { set_fn(name_ptr, handler) });

        if success {
            Ok(())
        } else {
            Err(EventManagerError::RegistrationFailed(
                event_name.to_string(),
            ))
        }
    }

    /// Remove a previously set native event handler.
    pub fn remove_native_handler(
        &self,
        event_name: &str,
        handler: NativeEventHandlerFFI,
    ) -> EventManagerResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let remove_fn = iface
            .RemoveNativeEventHandler
            .ok_or(EventManagerError::RemoveNativeHandlerIsNull)?;

        let win_name = WinString::new(event_name)?;
        win_name.with_ansi(|name_ptr| unsafe { remove_fn(name_ptr, handler) });

        Ok(())
    }

    /// Set a native event handler with a specific priority.
    ///
    /// Higher priority handlers run first. Default priority is 1.
    /// Valid range: -9999 to 9999.
    pub fn set_native_handler_with_priority(
        &self,
        event_name: &str,
        handler: NativeEventHandlerFFI,
        plugin_handle: u32,
        handler_name: &str,
        priority: i32,
    ) -> EventManagerResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetNativeEventHandlerWithPriority
            .ok_or(EventManagerError::SetNativeHandlerIsNull)?;

        let win_event = WinString::new(event_name)?;
        let win_handler = WinString::new(handler_name)?;

        let success = win_event.with_ansi(|event_ptr| {
            win_handler.with_ansi(|handler_ptr| unsafe {
                set_fn(event_ptr, handler, plugin_handle, handler_ptr, priority)
            })
        });

        if success {
            Ok(())
        } else {
            Err(EventManagerError::RegistrationFailed(
                event_name.to_string(),
            ))
        }
    }

    /// Remove a prioritized native event handler.
    ///
    /// Must specify the same priority used when registering.
    /// Returns `Ok(true)` if the handler was found and removed.
    pub fn remove_native_handler_with_priority(
        &self,
        event_name: &str,
        handler: NativeEventHandlerFFI,
        priority: i32,
    ) -> EventManagerResult<bool> {
        let iface = unsafe { self.ptr.as_ref() };
        let remove_fn = iface
            .RemoveNativeEventHandlerWithPriority
            .ok_or(EventManagerError::RemoveNativeHandlerIsNull)?;

        let win_name = WinString::new(event_name)?;
        let success =
            win_name.with_ansi(|name_ptr| unsafe { remove_fn(name_ptr, handler, priority) });

        Ok(success)
    }

    /// Set the return value for the current native event handler.
    ///
    /// Call this inside a native event handler to provide a result
    /// value back to the event dispatcher. If never called, a NULL
    /// element is passed by default.
    pub fn set_handler_result(
        &self,
        value: &mut crate::NVSEArrayVarInterface_Element,
    ) -> EventManagerResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetNativeHandlerFunctionValue
            .ok_or(EventManagerError::SetNativeHandlerIsNull)?;

        unsafe { set_fn(value) };
        Ok(())
    }

    /// Get the raw DispatchEvent function pointer for variadic dispatch.
    ///
    /// Since Rust cannot express C variadic calls through a safe API,
    /// this returns the raw function pointer. The caller is responsible
    /// for passing the correct parameter types matching the event definition.
    ///
    /// # Example (unsafe)
    ///
    /// ```no_run
    /// let dispatch_fn = events.raw_dispatch_fn()?;
    /// let name = WinString::new("MyPlugin:OnFoo")?;
    /// name.with_ansi(|name_ptr| unsafe {
    ///     dispatch_fn(name_ptr, some_ref, arg1, arg2);
    /// });
    /// ```
    pub fn raw_dispatch_fn(
        &self,
    ) -> EventManagerResult<
        unsafe extern "C" fn(eventName: *const i8, thisObj: *mut TESObjectREFR, ...) -> bool,
    > {
        let iface = unsafe { self.ptr.as_ref() };
        iface
            .DispatchEvent
            .ok_or(EventManagerError::DispatchEventIsNull)
    }

    /// Get the raw thread-safe DispatchEvent function pointer.
    ///
    /// If called from a non-main thread, the dispatch is deferred until
    /// the next main-thread tick. The post-callback is invoked after dispatch.
    pub fn raw_dispatch_thread_safe_fn(
        &self,
    ) -> EventManagerResult<
        unsafe extern "C" fn(
            eventName: *const i8,
            postCallback: crate::NVSEEventManagerInterface_PostDispatchCallback,
            thisObj: *mut TESObjectREFR,
            ...
        ) -> bool,
    > {
        let iface = unsafe { self.ptr.as_ref() };
        iface
            .DispatchEventThreadSafe
            .ok_or(EventManagerError::DispatchEventIsNull)
    }
}
