//! Safe wrapper for the NVSE array variable interface.
//!
//! NVSE extends the scripting engine with dynamic arrays, maps, and string maps.
//! This interface lets plugins create and manipulate these data structures,
//! which scripts can then access.
//!
//! # Array types
//!
//! - **Array**: Zero-indexed sequential list (like Vec)
//! - **Map**: Numeric-keyed associative container (f64 keys)
//! - **StringMap**: String-keyed associative container
//!
//! # Element types
//!
//! Array elements can hold: numbers (f64), strings, forms (game objects),
//! or nested arrays. The `Element` enum provides safe conversions.
//!
//! # Usage
//!
//! ```no_run
//! // Create an array and populate it
//! let arr = arrays.create_array(&[
//!     Element::Number(42.0),
//!     Element::String("hello"),
//! ], script_ptr)?;
//!
//! // Query array size
//! let size = arrays.len(arr)?;
//!
//! // Get an element
//! if let Some(elem) = arrays.get(arr, &Element::Number(0.0))? {
//!     match elem {
//!         Element::Number(n) => log::info!("Got number: {}", n),
//!         Element::String(s) => log::info!("Got string: {}", s),
//!         _ => {}
//!     }
//! }
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use thiserror::Error;

use crate::{
    NVSEArrayVarInterface as NVSEArrayVarInterfaceFFI,
    NVSEArrayVarInterface_Array as ArrayFFI,
    NVSEArrayVarInterface_Element as ElementFFI,
    NVSEArrayVarInterface_Element__bindgen_ty_1 as ElementUnion,
    NVSEArrayVarInterface_Element__bindgen_ty_2 as ElementType,
    Script, TESForm,
};

// -- Element ----------------------------------------------------------------

/// A value that can be stored in an NVSE array.
///
/// Elements are the universal value type in NVSE's array system.
/// They can hold numbers, strings, game forms, or nested arrays.
#[derive(Debug)]
pub enum Element<'a> {
    /// Invalid/uninitialized element.
    Invalid,
    /// Numeric value (all script numbers are f64).
    Number(f64),
    /// Game form reference.
    Form(*mut TESForm),
    /// String value (borrowed from NVSE's internal storage).
    String(&'a str),
    /// Nested array handle.
    Array(ArrayHandle),
}

impl<'a> Element<'a> {
    /// Convert from the raw FFI element type.
    ///
    /// # Safety
    /// The raw element must be valid and its type tag must match the union field.
    pub(crate) unsafe fn from_raw(raw: &ElementFFI) -> Self {
        match raw.type_ {
            1 => Element::Number(unsafe { raw.__bindgen_anon_1.num }),  // kType_Numeric
            2 => Element::Form(unsafe { raw.__bindgen_anon_1.form }),   // kType_Form
            3 => {                                                       // kType_String
                let ptr = unsafe { raw.__bindgen_anon_1.str_ };
                if ptr.is_null() {
                    Element::String("")
                } else {
                    let cstr = unsafe { CStr::from_ptr(ptr) };
                    Element::String(cstr.to_str().unwrap_or(""))
                }
            }
            4 => Element::Array(ArrayHandle(unsafe { raw.__bindgen_anon_1.arr })), // kType_Array
            _ => Element::Invalid,
        }
    }

    /// Convert to the raw FFI element type.
    pub(crate) fn to_raw(&self) -> ElementFFI {
        match self {
            Element::Invalid => ElementFFI::default(),
            Element::Number(n) => ElementFFI {
                __bindgen_anon_1: ElementUnion { num: *n },
                type_: ElementType::kType_Numeric as u8,
            },
            Element::Form(f) => ElementFFI {
                __bindgen_anon_1: ElementUnion { form: *f },
                type_: ElementType::kType_Form as u8,
            },
            Element::String(_s) => {
                // WARNING: Cannot safely convert &str to *mut c_char for FFI.
                // Rust &str is NOT null-terminated. Callers must use ElementFFI
                // directly with a properly null-terminated C string pointer.
                // Returning Invalid to prevent buffer overread.
                log::error!("Element::String::to_raw() is not safe -- use ElementFFI directly with a CStr pointer");
                ElementFFI::default()
            }
            Element::Array(h) => ElementFFI {
                __bindgen_anon_1: ElementUnion { arr: h.0 },
                type_: ElementType::kType_Array as u8,
            },
        }
    }

    /// Get the numeric value, if this is a Number element.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Element::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Get the string value, if this is a String element.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Element::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the form pointer, if this is a Form element.
    pub fn as_form(&self) -> Option<*mut TESForm> {
        match self {
            Element::Form(f) => Some(*f),
            _ => None,
        }
    }

    /// Get the array handle, if this is an Array element.
    pub fn as_array(&self) -> Option<ArrayHandle> {
        match self {
            Element::Array(h) => Some(*h),
            _ => None,
        }
    }
}

// -- Array handle -----------------------------------------------------------

/// Opaque handle to an NVSE array.
///
/// This is a lightweight wrapper around a raw pointer. Arrays are managed
/// by NVSE's internal garbage collector - you do not need to free them.
#[derive(Debug, Clone, Copy)]
pub struct ArrayHandle(pub(crate) *mut ArrayFFI);

impl ArrayHandle {
    /// Check if this handle is valid (non-null).
    pub fn is_valid(&self) -> bool {
        !self.0.is_null()
    }

    /// Get the raw pointer (for interop with other interfaces).
    pub fn as_raw(&self) -> *mut ArrayFFI {
        self.0
    }
}

/// The type of container an array handle represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerType {
    /// Zero-indexed sequential array.
    Array,
    /// Numeric-keyed map (f64 keys).
    Map,
    /// String-keyed map.
    StringMap,
    /// Unknown or invalid container.
    Invalid,
}

// -- Errors -----------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ArrayVarError {
    #[error("NVSEArrayVarInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("CreateArray function pointer is NULL")]
    CreateArrayIsNull,

    #[error("CreateMap function pointer is NULL")]
    CreateMapIsNull,

    #[error("CreateStringMap function pointer is NULL")]
    CreateStringMapIsNull,

    #[error("Array creation returned NULL")]
    CreationFailed,

    #[error("GetElement function pointer is NULL")]
    GetElementIsNull,

    #[error("SetElement function pointer is NULL")]
    SetElementIsNull,

    #[error("GetArraySize function pointer is NULL")]
    GetArraySizeIsNull,
}

pub type ArrayVarResult<T> = Result<T, ArrayVarError>;

// -- Wrapper ----------------------------------------------------------------

/// Safe wrapper around NVSEArrayVarInterface.
///
/// Provides methods to create and manipulate NVSE arrays, maps, and string maps.
/// These containers are accessible from both Rust and game scripts.
pub struct ArrayVars {
    ptr: NonNull<NVSEArrayVarInterfaceFFI>,
}

impl ArrayVars {
    /// Create an ArrayVars wrapper from a raw FFI pointer.
    pub fn from_raw(raw: *mut NVSEArrayVarInterfaceFFI) -> ArrayVarResult<Self> {
        let ptr = NonNull::new(raw).ok_or(ArrayVarError::InterfaceIsNull)?;
        Ok(Self { ptr })
    }

    /// Create a new zero-indexed array from a slice of elements.
    ///
    /// `calling_script` ties the array's lifetime to a script. Pass
    /// null for persistent arrays.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn create_array(
        &self,
        data: &[ElementFFI],
        calling_script: *mut Script,
    ) -> ArrayVarResult<ArrayHandle> {
        let iface = unsafe { self.ptr.as_ref() };
        let create_fn = iface
            .CreateArray
            .ok_or(ArrayVarError::CreateArrayIsNull)?;

        let ptr = if data.is_empty() {
            unsafe { create_fn(std::ptr::null(), 0, calling_script) }
        } else {
            unsafe { create_fn(data.as_ptr(), data.len() as u32, calling_script) }
        };

        if ptr.is_null() {
            Err(ArrayVarError::CreationFailed)
        } else {
            Ok(ArrayHandle(ptr))
        }
    }

    /// Create an empty array.
    pub fn create_empty(&self, calling_script: *mut Script) -> ArrayVarResult<ArrayHandle> {
        self.create_array(&[], calling_script)
    }

    /// Create a new numeric-keyed map.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn create_map(
        &self,
        keys: &[f64],
        values: &[ElementFFI],
        calling_script: *mut Script,
    ) -> ArrayVarResult<ArrayHandle> {
        let iface = unsafe { self.ptr.as_ref() };
        let create_fn = iface.CreateMap.ok_or(ArrayVarError::CreateMapIsNull)?;

        let size = keys.len().min(values.len()) as u32;
        let ptr = unsafe {
            create_fn(
                if keys.is_empty() {
                    std::ptr::null()
                } else {
                    keys.as_ptr()
                },
                if values.is_empty() {
                    std::ptr::null()
                } else {
                    values.as_ptr()
                },
                size,
                calling_script,
            )
        };

        if ptr.is_null() {
            Err(ArrayVarError::CreationFailed)
        } else {
            Ok(ArrayHandle(ptr))
        }
    }

    /// Create a new string-keyed map.
    ///
    /// `keys` and `values` must have the same length. Each key is a C string.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn create_string_map(
        &self,
        keys: &[*const i8],
        values: &[ElementFFI],
        calling_script: *mut Script,
    ) -> ArrayVarResult<ArrayHandle> {
        let iface = unsafe { self.ptr.as_ref() };
        let create_fn = iface
            .CreateStringMap
            .ok_or(ArrayVarError::CreateStringMapIsNull)?;

        let size = keys.len().min(values.len()) as u32;
        let ptr = unsafe {
            create_fn(
                if keys.is_empty() {
                    std::ptr::null_mut()
                } else {
                    keys.as_ptr() as *mut *const i8
                },
                if values.is_empty() {
                    std::ptr::null()
                } else {
                    values.as_ptr()
                },
                size,
                calling_script,
            )
        };

        if ptr.is_null() {
            Err(ArrayVarError::CreationFailed)
        } else {
            Ok(ArrayHandle(ptr))
        }
    }

    /// Get the number of elements in an array.
    pub fn len(&self, arr: ArrayHandle) -> ArrayVarResult<u32> {
        let iface = unsafe { self.ptr.as_ref() };
        let size_fn = iface
            .GetArraySize
            .ok_or(ArrayVarError::GetArraySizeIsNull)?;
        Ok(unsafe { size_fn(arr.0) })
    }

    /// Check if an array is empty.
    pub fn is_empty(&self, arr: ArrayHandle) -> ArrayVarResult<bool> {
        Ok(self.len(arr)? == 0)
    }

    /// Get an element by key.
    ///
    /// Returns None if the key is not found.
    pub fn get(&self, arr: ArrayHandle, key: &ElementFFI) -> ArrayVarResult<Option<ElementFFI>> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface
            .GetElement
            .ok_or(ArrayVarError::GetElementIsNull)?;

        let mut out = ElementFFI::default();
        let found = unsafe { get_fn(arr.0, key, &mut out) };

        if found {
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }

    /// Set an element by key.
    pub fn set(
        &self,
        arr: ArrayHandle,
        key: &ElementFFI,
        value: &ElementFFI,
    ) -> ArrayVarResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface
            .SetElement
            .ok_or(ArrayVarError::SetElementIsNull)?;

        unsafe { set_fn(arr.0, key, value) };
        Ok(())
    }

    /// Append an element to a zero-indexed array.
    pub fn append(&self, arr: ArrayHandle, value: &ElementFFI) -> ArrayVarResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let append_fn = iface
            .AppendElement
            .ok_or(ArrayVarError::SetElementIsNull)?;

        unsafe { append_fn(arr.0, value) };
        Ok(())
    }

    /// Check if an array contains a specific key.
    pub fn has_key(&self, arr: ArrayHandle, key: &ElementFFI) -> bool {
        let iface = unsafe { self.ptr.as_ref() };
        match iface.ArrayHasKey {
            Some(f) => unsafe { f(arr.0, key) },
            None => false,
        }
    }

    /// Get the container type of an array handle.
    pub fn container_type(&self, arr: ArrayHandle) -> ContainerType {
        let iface = unsafe { self.ptr.as_ref() };
        match iface.GetContainerType {
            Some(f) => {
                let raw = unsafe { f(arr.0) };
                match raw {
                    0 => ContainerType::Array,
                    1 => ContainerType::Map,
                    2 => ContainerType::StringMap,
                    _ => ContainerType::Invalid,
                }
            }
            None => ContainerType::Invalid,
        }
    }

    /// Look up an array by its internal ID.
    pub fn lookup_by_id(&self, id: u32) -> Option<ArrayHandle> {
        let iface = unsafe { self.ptr.as_ref() };
        let lookup_fn = iface.LookupArrayByID?;
        let ptr = unsafe { lookup_fn(id) };
        if ptr.is_null() {
            None
        } else {
            Some(ArrayHandle(ptr))
        }
    }

    /// Assign an array as a command result (for typed commands returning arrays).
    pub fn assign_result(&self, arr: ArrayHandle, result: &mut f64) -> bool {
        let iface = unsafe { self.ptr.as_ref() };
        match iface.AssignCommandResult {
            Some(f) => unsafe { f(arr.0, result) },
            None => false,
        }
    }
}
