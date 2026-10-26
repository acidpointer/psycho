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
//! or nested arrays. [`ArrayElement`] is a value or key passed to
//! [`ArrayVars`]. Elements it returns are [`OwnedElement`]s, which release
//! xNVSE's copy of their string when dropped. `value()` on either reads it
//! as an [`Element`].
//!
//! # Calling script
//!
//! xNVSE derives a new array's owning mod from the calling script, so every
//! `create_*` method needs a [`CallingScript`]. Inside a command handler,
//! [`CommandContext::calling_script`](crate::api::command::CommandContext::calling_script)
//! provides it. New arrays are temporary until a script variable or another
//! array references them, e.g. by returning one with
//! [`ArrayVars::assign_result`].
//!
//! # Usage
//!
//! ```no_run
//! use libnvse::api::array_var::{ArrayElement, ArrayVarResult, ArrayVars};
//! use libnvse::api::command::CommandContext;
//!
//! // Called from an `nvse_command!` body.
//! fn build_stats(arrays: &ArrayVars, cmd: &CommandContext) -> ArrayVarResult<()> {
//!     let Some(script) = cmd.calling_script() else {
//!         return Ok(());
//!     };
//!
//!     // ["courier", 6]
//!     let list = arrays.create_array(
//!         &[ArrayElement::string(c"courier"), ArrayElement::number(6.0)],
//!         script,
//!     )?;
//!
//!     // {"name": "six"}
//!     let map = arrays.create_string_map(
//!         &[c"name"],
//!         &[ArrayElement::string(c"six")],
//!         script,
//!     )?;
//!     if let Some(name) = arrays.get(map, &ArrayElement::string(c"name"))? {
//!         log::info!("name = {:?}", name.value().as_str());
//!     }
//!
//!     // Nest the map and return the list to the script.
//!     arrays.append(list, &ArrayElement::array(map))?;
//!     let mut result = 0.0;
//!     if arrays.assign_result(list, &mut result) {
//!         cmd.set_result(result);
//!     }
//!
//!     let (values, keys) = arrays.get_elements(list)?;
//!     for (key, value) in keys.iter().zip(&values) {
//!         log::info!("{:?} = {:?}", key.value(), value.value());
//!     }
//!     Ok(())
//! }
//! ```

use std::ffi::{CStr, c_char};
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;

use thiserror::Error;

use crate::{
    NVSEArrayVarInterface as NVSEArrayVarInterfaceFFI, NVSEArrayVarInterface_Array as ArrayFFI,
    NVSEArrayVarInterface_Element as ElementFFI,
    NVSEArrayVarInterface_Element__bindgen_ty_1 as ElementUnion,
    NVSEArrayVarInterface_Element__bindgen_ty_2 as ElementType, Script, TESForm,
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
            1 => Element::Number(unsafe { raw.__bindgen_anon_1.num }), // kType_Numeric
            2 => Element::Form(unsafe { raw.__bindgen_anon_1.form }),  // kType_Form
            3 => {
                // kType_String
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

// -- ArrayElement -----------------------------------------------------------

/// One element in xNVSE's `NVSEArrayVarInterface::Element` layout.
///
/// Used for values and keys passed to [`ArrayVars`]; elements it returns are
/// [`OwnedElement`]s. Read the contents with [`value`](Self::value).
///
/// A string element borrows its `CStr` for `'a`; xNVSE copies the text when
/// it stores or looks up the element, so the borrow only has to cover the
/// call.
#[repr(transparent)]
pub struct ArrayElement<'a> {
    /// `repr(transparent)` keeps the exact ABI of the xNVSE element so a
    /// slice of `ArrayElement` can be passed where xNVSE expects an
    /// `Element*` array.
    raw: ElementFFI,
    _text: PhantomData<&'a CStr>,
}

impl<'a> ArrayElement<'a> {
    fn from_ffi(raw: ElementFFI) -> Self {
        Self {
            raw,
            _text: PhantomData,
        }
    }

    /// An invalid (empty) element.
    pub fn invalid() -> Self {
        Self::from_ffi(ElementFFI::default())
    }

    /// A numeric element.
    pub fn number(value: f64) -> Self {
        Self::from_ffi(ElementFFI {
            __bindgen_anon_1: ElementUnion { num: value },
            type_: ElementType::kType_Numeric as u8,
        })
    }

    /// A form element. xNVSE stores the form's ID; a null form stores ID 0.
    pub fn form(form: *mut TESForm) -> Self {
        Self::from_ffi(ElementFFI {
            __bindgen_anon_1: ElementUnion { form },
            type_: ElementType::kType_Form as u8,
        })
    }

    /// A string element that borrows `text` for the element's lifetime.
    pub fn string(text: &'a CStr) -> Self {
        Self::from_ffi(ElementFFI {
            // xNVSE only reads through this pointer; it never writes.
            __bindgen_anon_1: ElementUnion {
                str_: text.as_ptr().cast_mut(),
            },
            type_: ElementType::kType_String as u8,
        })
    }

    /// A nested-array element.
    pub fn array(array: ArrayHandle) -> Self {
        Self::from_ffi(ElementFFI {
            __bindgen_anon_1: ElementUnion { arr: array.0 },
            type_: ElementType::kType_Array as u8,
        })
    }

    /// Read the element's type and value.
    ///
    /// Strings that are not valid UTF-8 read as an empty string.
    pub fn value(&self) -> Element<'_> {
        // SAFETY: every constructor writes the union field that matches its
        // type tag, and a string pointer is a `CStr` borrowed for `'a`. An
        // `OwnedElement` viewed through `as_element` keeps its string alive
        // for the borrow.
        unsafe { Element::from_raw(&self.raw) }
    }

    fn as_ffi(&self) -> &ElementFFI {
        &self.raw
    }
}

impl Default for ArrayElement<'_> {
    fn default() -> Self {
        Self::invalid()
    }
}

impl fmt::Debug for ArrayElement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ArrayElement").field(&self.value()).finish()
    }
}

// -- OwnedElement -----------------------------------------------------------

/// Game `FormHeap_Free` in FalloutNV.exe 1.4.0.525: `void __cdecl(void*)`,
/// forwarding to the game heap's free (0x00AA4060), which ignores null.
/// It is the free that pairs with `FormHeap_Allocate` (0x00401000), which
/// xNVSE's `CopyCString` uses for the strings it returns. xNVSE uses the
/// same address in its runtime build, and the array and script interfaces
/// exist only in that build. Evidence: `analysis/ghidra/output/memory/deep_io_lifecycle.txt`
/// ("CommonDelete @ 0x00401030") and xNVSE `GameAPI.cpp`.
const FORM_HEAP_FREE: usize = 0x0040_1030;

/// An element xNVSE returned to the caller.
///
/// xNVSE gives the caller its own heap copy of a string element's text.
/// This type owns that copy and returns it to the game heap on drop, so it
/// is neither `Clone` nor `Copy`. Read it with [`value`](Self::value), or
/// pass it back to [`ArrayVars`] through [`as_element`](Self::as_element).
#[repr(transparent)]
pub struct OwnedElement {
    /// Same layout as `ArrayElement`, so a `Vec<OwnedElement>` can be the
    /// output buffer for `GetElements` and a reference can be viewed as an
    /// `ArrayElement`.
    raw: ElementFFI,
}

impl OwnedElement {
    /// An invalid element for xNVSE to overwrite. It owns nothing, and
    /// xNVSE's assignment only frees an existing value of string type.
    pub(crate) fn empty() -> Self {
        Self {
            raw: ElementFFI::default(),
        }
    }

    /// Read the element's type and value.
    ///
    /// Strings that are not valid UTF-8 read as an empty string.
    pub fn value(&self) -> Element<'_> {
        self.as_element().value()
    }

    /// Output slot for an xNVSE call that fills a result element.
    pub(crate) fn as_mut_ffi(&mut self) -> *mut ElementFFI {
        &mut self.raw
    }

    /// View this element as an input for [`ArrayVars`], e.g. to reuse a
    /// returned key. The string stays owned by `self`.
    pub fn as_element(&self) -> &ArrayElement<'_> {
        // SAFETY: both types are `repr(transparent)` over `ElementFFI`, and
        // the borrow keeps the owned string alive for the view's lifetime.
        unsafe { &*(self as *const Self).cast::<ArrayElement<'_>>() }
    }
}

impl Drop for OwnedElement {
    fn drop(&mut self) {
        if self.raw.type_ != ElementType::kType_String as u8 {
            return;
        }
        // SAFETY: the tag says the union holds `str_`.
        let text = unsafe { self.raw.__bindgen_anon_1.str_ };
        if text.is_null() {
            return;
        }
        // SAFETY: an `OwnedElement` is only filled by xNVSE's GetElement,
        // GetElements, or CallFunction, which assign string elements a
        // `CopyCString` copy from `FormHeap_Allocate`. The copy is freed exactly once because
        // this type cannot be cloned. See `FORM_HEAP_FREE` for the address.
        unsafe {
            let form_heap_free: unsafe extern "C" fn(*mut std::ffi::c_void) =
                std::mem::transmute(FORM_HEAP_FREE);
            form_heap_free(text.cast());
        }
    }
}

impl fmt::Debug for OwnedElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OwnedElement").field(&self.value()).finish()
    }
}

// -- Calling script ---------------------------------------------------------

/// The script that is creating an array.
///
/// xNVSE dereferences it to assign the new array's owning mod, so it must be
/// a live script. Obtain one from
/// [`CommandContext::calling_script`](crate::api::command::CommandContext::calling_script);
/// the borrow keeps it from outliving the command call.
#[derive(Debug, Clone, Copy)]
pub struct CallingScript<'a> {
    ptr: NonNull<Script>,
    _call: PhantomData<&'a Script>,
}

impl CallingScript<'_> {
    /// Wrap a script pointer obtained outside a command handler.
    ///
    /// # Safety
    /// `script` must point to a live engine `Script` for the whole lifetime
    /// of the returned value.
    pub unsafe fn from_raw(script: NonNull<Script>) -> Self {
        Self {
            ptr: script,
            _call: PhantomData,
        }
    }

    fn as_ptr(self) -> *mut Script {
        self.ptr.as_ptr()
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

    #[error("{keys} keys but {values} values")]
    LengthMismatch { keys: usize, values: usize },
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

    /// Create a new zero-indexed array holding `data` in order.
    ///
    /// The array is temporary until a script variable or another array
    /// references it.
    pub fn create_array(
        &self,
        data: &[ArrayElement<'_>],
        calling_script: CallingScript<'_>,
    ) -> ArrayVarResult<ArrayHandle> {
        let iface = unsafe { self.ptr.as_ref() };
        let create_fn = iface.CreateArray.ok_or(ArrayVarError::CreateArrayIsNull)?;

        // SAFETY: `ArrayElement` is `repr(transparent)` over the xNVSE
        // element, xNVSE reads exactly `size` elements, and the calling
        // script is live for this call.
        let ptr = unsafe {
            create_fn(
                elements_ptr(data),
                data.len() as u32,
                calling_script.as_ptr(),
            )
        };
        handle_or_failed(ptr)
    }

    /// Create an empty zero-indexed array.
    pub fn create_empty(&self, calling_script: CallingScript<'_>) -> ArrayVarResult<ArrayHandle> {
        self.create_array(&[], calling_script)
    }

    /// Create a numeric-keyed map with `values[i]` stored at `keys[i]`.
    ///
    /// Returns [`ArrayVarError::LengthMismatch`] unless both slices have the
    /// same length.
    pub fn create_map(
        &self,
        keys: &[f64],
        values: &[ArrayElement<'_>],
        calling_script: CallingScript<'_>,
    ) -> ArrayVarResult<ArrayHandle> {
        check_lengths(keys.len(), values.len())?;
        let iface = unsafe { self.ptr.as_ref() };
        let create_fn = iface.CreateMap.ok_or(ArrayVarError::CreateMapIsNull)?;

        // SAFETY: both slices hold `size` items, see `create_array`.
        let ptr = unsafe {
            create_fn(
                if keys.is_empty() {
                    std::ptr::null()
                } else {
                    keys.as_ptr()
                },
                elements_ptr(values),
                values.len() as u32,
                calling_script.as_ptr(),
            )
        };
        handle_or_failed(ptr)
    }

    /// Create a string-keyed map with `values[i]` stored at `keys[i]`.
    ///
    /// xNVSE copies the keys. Returns [`ArrayVarError::LengthMismatch`]
    /// unless both slices have the same length.
    pub fn create_string_map(
        &self,
        keys: &[&CStr],
        values: &[ArrayElement<'_>],
        calling_script: CallingScript<'_>,
    ) -> ArrayVarResult<ArrayHandle> {
        check_lengths(keys.len(), values.len())?;
        let iface = unsafe { self.ptr.as_ref() };
        let create_fn = iface
            .CreateStringMap
            .ok_or(ArrayVarError::CreateStringMapIsNull)?;

        // `&CStr` is not guaranteed to be a thin pointer, so build the
        // `const char*` array xNVSE expects. Map creation is not a hot path.
        let mut key_ptrs: Vec<*const c_char> = keys.iter().map(|key| key.as_ptr()).collect();
        // SAFETY: both arrays hold `size` items whose strings outlive the
        // call, see `create_array`.
        let ptr = unsafe {
            create_fn(
                if key_ptrs.is_empty() {
                    std::ptr::null_mut()
                } else {
                    key_ptrs.as_mut_ptr()
                },
                elements_ptr(values),
                values.len() as u32,
                calling_script.as_ptr(),
            )
        };
        handle_or_failed(ptr)
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

    /// Get the element stored at `key`.
    ///
    /// `key` must be a number for arrays and maps, or a string for string
    /// maps. Returns `None` if the key is absent or has the wrong type.
    pub fn get(
        &self,
        arr: ArrayHandle,
        key: &ArrayElement<'_>,
    ) -> ArrayVarResult<Option<OwnedElement>> {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetElement.ok_or(ArrayVarError::GetElementIsNull)?;

        // Owned before the call, so a string xNVSE writes is freed on every
        // path.
        let mut out = OwnedElement::empty();
        let found = unsafe { get_fn(arr.0, key.as_ffi(), &mut out.raw) };

        Ok(found.then_some(out))
    }

    /// Store `value` at `key`. xNVSE ignores keys that are neither numbers
    /// nor strings.
    pub fn set(
        &self,
        arr: ArrayHandle,
        key: &ArrayElement<'_>,
        value: &ArrayElement<'_>,
    ) -> ArrayVarResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let set_fn = iface.SetElement.ok_or(ArrayVarError::SetElementIsNull)?;

        unsafe { set_fn(arr.0, key.as_ffi(), value.as_ffi()) };
        Ok(())
    }

    /// Append an element to a zero-indexed array. xNVSE ignores maps.
    pub fn append(&self, arr: ArrayHandle, value: &ArrayElement<'_>) -> ArrayVarResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let append_fn = iface.AppendElement.ok_or(ArrayVarError::SetElementIsNull)?;

        unsafe { append_fn(arr.0, value.as_ffi()) };
        Ok(())
    }

    /// Get all elements and keys from an array at once.
    ///
    /// Allocates and returns two Vecs: (values, keys).
    /// For zero-indexed arrays the keys are numeric indices (0.0, 1.0, ...).
    /// For maps the keys match the map's key type.
    ///
    /// Returns empty Vecs if the array is invalid or empty.
    pub fn get_elements(
        &self,
        arr: ArrayHandle,
    ) -> ArrayVarResult<(Vec<OwnedElement>, Vec<OwnedElement>)> {
        let size = self.len(arr)?;
        if size == 0 {
            return Ok((Vec::new(), Vec::new()));
        }

        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = iface.GetElements.ok_or(ArrayVarError::GetElementIsNull)?;

        let mut values: Vec<OwnedElement> = (0..size).map(|_| OwnedElement::empty()).collect();
        let mut keys: Vec<OwnedElement> = (0..size).map(|_| OwnedElement::empty()).collect();

        // SAFETY: both buffers hold `size` initialized elements in the
        // xNVSE layout (`repr(transparent)`), and xNVSE writes one element
        // per array entry.
        let success = unsafe {
            get_fn(
                arr.0,
                values.as_mut_ptr().cast::<ElementFFI>(),
                keys.as_mut_ptr().cast::<ElementFFI>(),
            )
        };

        if success {
            Ok((values, keys))
        } else {
            Ok((Vec::new(), Vec::new()))
        }
    }

    /// Check if an array contains a specific key.
    pub fn has_key(&self, arr: ArrayHandle, key: &ArrayElement<'_>) -> bool {
        let iface = unsafe { self.ptr.as_ref() };
        match iface.ArrayHasKey {
            Some(f) => unsafe { f(arr.0, key.as_ffi()) },
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

/// Pointer to an element slice in the layout xNVSE reads, or null if empty.
fn elements_ptr(elements: &[ArrayElement<'_>]) -> *const ElementFFI {
    if elements.is_empty() {
        std::ptr::null()
    } else {
        elements.as_ptr().cast::<ElementFFI>()
    }
}

fn check_lengths(keys: usize, values: usize) -> ArrayVarResult<()> {
    if keys == values {
        Ok(())
    } else {
        Err(ArrayVarError::LengthMismatch { keys, values })
    }
}

fn handle_or_failed(ptr: *mut ArrayFFI) -> ArrayVarResult<ArrayHandle> {
    if ptr.is_null() {
        Err(ArrayVarError::CreationFailed)
    } else {
        Ok(ArrayHandle(ptr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructed_elements_read_back_their_values() {
        assert_eq!(ArrayElement::number(6.5).value().as_number(), Some(6.5));
        assert_eq!(
            ArrayElement::string(c"courier").value().as_str(),
            Some("courier")
        );

        let form = 0x1000 as *mut TESForm;
        assert_eq!(ArrayElement::form(form).value().as_form(), Some(form));

        let nested = ArrayHandle(0x42 as *mut ArrayFFI);
        let read = ArrayElement::array(nested)
            .value()
            .as_array()
            .map(|h| h.as_raw());
        assert_eq!(read, Some(nested.as_raw()));

        assert!(matches!(ArrayElement::invalid().value(), Element::Invalid));
    }
}
