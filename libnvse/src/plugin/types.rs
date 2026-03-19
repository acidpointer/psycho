//! Safe types for the high-level plugin API.
//!
//! These types are designed to be used without any `unsafe` code.
//! They wrap raw game engine concepts in Rust-native abstractions.

use std::fmt;

use crate::{
    NVSEArrayVarInterface_Element as ElementFFI,
    NVSEArrayVarInterface_Element__bindgen_ty_1 as ElementUnion,
    NVSEArrayVarInterface_Element__bindgen_ty_2 as ElementType,
    TESForm,
};

// ---------------------------------------------------------------------------
// FormId
// ---------------------------------------------------------------------------

/// A game form identifier (reference ID).
///
/// Every object in the game world (items, NPCs, quests, globals, etc.) has
/// a unique 32-bit form ID. The upper 8 bits encode the owning plugin's
/// load order index; the lower 24 bits are the local ID within that plugin.
///
/// # Well-known IDs
///
/// - `0x00000007` - PlayerRef (the player character reference)
/// - `0x0000000F` - Gold001 (bottle caps / currency)
/// - `0x00000014` - Player base actor
///
/// # Example
///
/// ```
/// let caps = FormId::new(0xF);
/// let player = FormId::PLAYER_REF;
/// assert_eq!(player.raw(), 0x7);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FormId(u32);

impl FormId {
    /// The player character reference (refID 0x00000007).
    pub const PLAYER_REF: FormId = FormId(0x7);

    /// The player base actor form (refID 0x00000014).
    pub const PLAYER_BASE: FormId = FormId(0x14);

    /// Gold / bottle caps (refID 0x0000000F).
    pub const CAPS: FormId = FormId(0xF);

    /// Null / invalid form.
    pub const NONE: FormId = FormId(0);

    /// Create a FormId from a raw 32-bit reference ID.
    pub const fn new(ref_id: u32) -> Self {
        Self(ref_id)
    }

    /// Get the raw 32-bit reference ID.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Check if this is a valid (non-zero) form ID.
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }

    /// Get the load order index (upper 8 bits).
    ///
    /// - 0x00-0xFD: Regular plugin index
    /// - 0xFE: Light plugin (ESL) range
    /// - 0xFF: Dynamically created at runtime
    pub const fn plugin_index(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// Get the local form ID within the owning plugin (lower 24 bits).
    pub const fn local_id(self) -> u32 {
        self.0 & 0x00FFFFFF
    }

    /// Build a FormId from a plugin index and local ID.
    pub const fn from_parts(plugin_index: u8, local_id: u32) -> Self {
        Self(((plugin_index as u32) << 24) | (local_id & 0x00FFFFFF))
    }

    /// Create from a raw TESForm pointer by reading its refID.
    ///
    /// Returns FormId::NONE if the pointer is null.
    pub(crate) fn from_form_ptr(form: *const TESForm) -> Self {
        if form.is_null() {
            Self::NONE
        } else {
            // SAFETY: We checked for null. TESForm layout is stable and
            // refID is at a fixed offset defined by the game engine.
            Self(unsafe { (*form).refID })
        }
    }

    /// Format as hex string (e.g. "000F" for caps).
    pub fn to_hex(self) -> String {
        format!("{:08X}", self.0)
    }

    /// Format as a console-compatible reference string (e.g. "0xF").
    pub fn to_console_ref(self) -> String {
        format!("{:X}", self.0)
    }
}

impl fmt::Debug for FormId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FormId({:08X})", self.0)
    }
}

impl fmt::Display for FormId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08X}", self.0)
    }
}

impl From<u32> for FormId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<FormId> for u32 {
    fn from(id: FormId) -> u32 {
        id.0
    }
}

// ---------------------------------------------------------------------------
// ArrayId
// ---------------------------------------------------------------------------

/// Opaque identifier for an NVSE array.
///
/// Arrays are managed by NVSE's garbage collector. You do not need to free
/// them, but they may become invalid if the owning script is destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArrayId(pub(crate) u32);

impl ArrayId {
    /// Get the raw internal ID.
    pub fn raw(self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------

/// A safe, owned value that can be stored in NVSE arrays or passed to events.
///
/// Unlike the low-level `ElementFFI`, this type:
/// - Owns its string data (no dangling pointers)
/// - Uses `FormId` instead of raw `*mut TESForm`
/// - Uses `ArrayId` instead of raw array pointers
/// - Requires zero `unsafe` to construct or read
///
/// # Example
///
/// ```
/// let greeting = Value::text("Hello, Courier!");
/// let damage = Value::number(42.0);
/// let target = Value::form(FormId::PLAYER_REF);
///
/// assert_eq!(greeting.as_str(), Some("Hello, Courier!"));
/// assert_eq!(damage.as_f64(), Some(42.0));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// No value / uninitialized.
    None,
    /// Numeric value (all game script numbers are f64).
    Number(f64),
    /// Owned string value.
    Text(String),
    /// Game form reference by ID.
    Form(FormId),
    /// Nested NVSE array reference.
    Array(ArrayId),
}

impl Value {
    // -- Constructors (named for clarity) -----------------------------------

    /// Create a numeric value.
    pub fn number(n: f64) -> Self {
        Self::Number(n)
    }

    /// Create an integer as a numeric value (scripts use f64 for all numbers).
    pub fn int(n: i32) -> Self {
        Self::Number(n as f64)
    }

    /// Create a string value.
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    /// Create a form reference value.
    pub fn form(id: FormId) -> Self {
        Self::Form(id)
    }

    /// Create a form reference from a raw ID.
    pub fn form_id(ref_id: u32) -> Self {
        Self::Form(FormId::new(ref_id))
    }

    // -- Accessors ----------------------------------------------------------

    /// Get the numeric value, if this is a Number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => Option::None,
        }
    }

    /// Get the numeric value as i32, if this is a Number.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::Number(n) => Some(*n as i32),
            _ => Option::None,
        }
    }

    /// Get the string value, if this is Text.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s.as_str()),
            _ => Option::None,
        }
    }

    /// Get the form ID, if this is a Form.
    pub fn as_form_id(&self) -> Option<FormId> {
        match self {
            Self::Form(id) => Some(*id),
            _ => Option::None,
        }
    }

    /// Get the array ID, if this is an Array.
    pub fn as_array_id(&self) -> Option<ArrayId> {
        match self {
            Self::Array(id) => Some(*id),
            _ => Option::None,
        }
    }

    /// Check if this is a None/invalid value.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    // -- FFI conversions (crate-internal) -----------------------------------

    /// Convert from a raw FFI element.
    ///
    /// Strings are copied into owned Strings. Forms are converted to FormId.
    pub(crate) fn from_element_ffi(raw: &ElementFFI) -> Self {
        match raw.type_ {
            1 => {
                // kType_Numeric
                Value::Number(unsafe { raw.__bindgen_anon_1.num })
            }
            2 => {
                // kType_Form
                let form_ptr = unsafe { raw.__bindgen_anon_1.form };
                Value::Form(FormId::from_form_ptr(form_ptr))
            }
            3 => {
                // kType_String
                let ptr = unsafe { raw.__bindgen_anon_1.str_ };
                if ptr.is_null() {
                    Value::Text(String::new())
                } else {
                    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
                    Value::Text(cstr.to_str().unwrap_or("").to_string())
                }
            }
            4 => {
                // kType_Array -- we don't have the array ID directly from
                // the raw pointer, but we can represent it as a handle.
                // The raw pointer is opaque; NVSE manages the lifetime.
                Value::Array(ArrayId(0)) // Placeholder - arrays need lookup
            }
            _ => Value::None,
        }
    }

    /// Convert to a raw FFI element for passing to NVSE.
    ///
    /// IMPORTANT: For Text values, the returned ElementFFI borrows from
    /// `c_string_out`. The caller must keep `c_string_out` alive while
    /// the ElementFFI is in use.
    pub(crate) fn to_element_ffi(
        &self,
        c_string_out: &mut Option<std::ffi::CString>,
    ) -> ElementFFI {
        match self {
            Value::None => ElementFFI::default(),
            Value::Number(n) => ElementFFI {
                __bindgen_anon_1: ElementUnion { num: *n },
                type_: ElementType::kType_Numeric as u8,
            },
            Value::Form(id) => {
                // NVSE expects a TESForm pointer, but we only have a FormId.
                // For the safe API, we store the refID as a numeric and let
                // the caller use the appropriate NVSE function to resolve.
                // Alternatively, we pass NULL and set it via other means.
                // For now: store as numeric (scripts often treat form IDs as numbers).
                ElementFFI {
                    __bindgen_anon_1: ElementUnion {
                        num: id.raw() as f64,
                    },
                    type_: ElementType::kType_Numeric as u8,
                }
            }
            Value::Text(s) => {
                let cstring = std::ffi::CString::new(s.as_str()).unwrap_or_default();
                let ptr = cstring.as_ptr() as *mut i8;
                *c_string_out = Some(cstring);
                ElementFFI {
                    __bindgen_anon_1: ElementUnion { str_: ptr },
                    type_: ElementType::kType_String as u8,
                }
            }
            Value::Array(id) => {
                // Store array ID as numeric for cross-interface compatibility
                ElementFFI {
                    __bindgen_anon_1: ElementUnion {
                        num: id.raw() as f64,
                    },
                    type_: ElementType::kType_Numeric as u8,
                }
            }
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::None => write!(f, "<none>"),
            Value::Number(n) => write!(f, "{}", n),
            Value::Text(s) => write!(f, "{}", s),
            Value::Form(id) => write!(f, "Form({})", id),
            Value::Array(id) => write!(f, "Array({})", id.0),
        }
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Self::Number(n)
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Self::Number(n as f64)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Text(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

impl From<FormId> for Value {
    fn from(id: FormId) -> Self {
        Self::Form(id)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Number(if b { 1.0 } else { 0.0 })
    }
}
