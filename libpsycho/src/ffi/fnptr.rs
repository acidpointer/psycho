use libc::c_void;
use std::fmt;
use thiserror::Error;

mod private {
    pub trait Sealed {}
}

/// A concrete Rust function-pointer type.
///
/// The implementations are generated only for language function-pointer
/// types. This is the compile-time proof that lets [`FnPtr`] centralize raw
/// address conversion without accepting integers or data pointers as if they
/// were functions.
///
/// This contract follows Retour's `Function` abstraction.
///
/// # Safety
///
/// Implementations must represent a real function-pointer type whose value can
/// be converted to and from `*const ()` without changing its address. The trait
/// is sealed so only the generated language function-pointer implementations
/// can provide that guarantee.
pub unsafe trait Function: private::Sealed + Sized + Copy + Send + Sync + 'static {
    /// Function arguments represented as a tuple.
    type Arguments;

    /// Function return type.
    type Output;

    /// Construct this function-pointer type from an untyped code address.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live function with exactly this signature and
    /// calling convention. A raw address contains no metadata from which Rust
    /// could validate that contract.
    unsafe fn from_ptr(ptr: *const ()) -> Self;

    /// Return the function's untyped code address.
    fn to_ptr(self) -> *const ();
}

macro_rules! impl_functions {
    (@recurse () ($($name:ident : $type:ident),*)) => {
        impl_functions!(@impl_all ($($name : $type),*));
    };
    (@recurse
        ($head_name:ident : $head_type:ident $(, $tail_name:ident : $tail_type:ident)*)
        ($($name:ident : $type:ident),*)) => {
        impl_functions!(@impl_all ($($name : $type),*));
        impl_functions!(@recurse
            ($($tail_name : $tail_type),*)
            ($($name : $type,)* $head_name : $head_type));
    };

    (@impl_all ($($name:ident : $type:ident),*)) => {
        impl_functions!(@impl_pair ($($type),*) (extern "C" fn($($type),*) -> Ret));
        impl_functions!(@impl_pair ($($type),*) (extern "Rust" fn($($type),*) -> Ret));
        impl_functions!(@impl_pair ($($type),*) (extern "system" fn($($type),*) -> Ret));

        #[cfg(target_arch = "x86")]
        impl_functions!(@impl_pair ($($type),*) (extern "cdecl" fn($($type),*) -> Ret));
        #[cfg(target_arch = "x86")]
        impl_functions!(@impl_pair ($($type),*) (extern "fastcall" fn($($type),*) -> Ret));
        #[cfg(target_arch = "x86")]
        impl_functions!(@impl_pair ($($type),*) (extern "stdcall" fn($($type),*) -> Ret));
        #[cfg(target_arch = "x86")]
        impl_functions!(@impl_pair ($($type),*) (extern "thiscall" fn($($type),*) -> Ret));
    };

    (@impl_pair ($($type:ident),*) ($($function_type:tt)*)) => {
        impl_functions!(@impl_one ($($type),*) ($($function_type)*));
        impl_functions!(@impl_one ($($type),*) (unsafe $($function_type)*));
    };

    (@impl_one ($($type:ident),*) ($function_type:ty)) => {
        impl<Ret: 'static, $($type: 'static),*> private::Sealed for $function_type {}

        unsafe impl<Ret: 'static, $($type: 'static),*> Function for $function_type {
            type Arguments = ($($type,)*);
            type Output = Ret;

            #[inline]
            unsafe fn from_ptr(ptr: *const ()) -> Self {
                unsafe { std::mem::transmute(ptr) }
            }

            #[inline]
            fn to_ptr(self) -> *const () {
                self as *const ()
            }
        }
    };

    ($($name:ident : $type:ident),*) => {
        impl_functions!(@recurse ($($name : $type),*) ());
    };
}

// ShowMessageBox is the largest signature currently crossing this boundary.
impl_functions! {
    arg_0: A,
    arg_1: B,
    arg_2: C,
    arg_3: D,
    arg_4: E,
    arg_5: F,
    arg_6: G,
    arg_7: H,
    arg_8: I,
    arg_9: J,
    arg_10: K,
    arg_11: L,
    arg_12: M,
    arg_13: N,
    arg_14: O,
    arg_15: P,
    arg_16: Q,
    arg_17: R,
    arg_18: S
}

#[derive(Debug, Error)]
pub enum FnPtrError {
    #[error("Function pointer is NULL")]
    FunctionPtrIsNull,
}

/// A non-null function pointer whose signature is carried by its type.
#[derive(Clone, Copy)]
pub struct FnPtr<F: Function> {
    function: F,
}

impl<F: Function> FnPtr<F> {
    /// Wrap an already typed function pointer.
    #[inline]
    pub const fn new(function: F) -> Self {
        Self { function }
    }

    /// Import an untyped code address as `F`.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live function with exactly `F`'s signature and
    /// calling convention for every subsequent use of this value.
    #[inline]
    pub unsafe fn from_raw(ptr: *mut c_void) -> Result<Self, FnPtrError> {
        if ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        Ok(Self::new(unsafe { F::from_ptr(ptr.cast_const().cast()) }))
    }

    /// Import a compile-time or otherwise proven non-null code address.
    ///
    /// This is the infallible counterpart to [`Self::from_raw`] for audited
    /// engine addresses. It deliberately performs no runtime check, so callers
    /// must not use it for dynamic exports, hook predecessors, or optional
    /// pointers.
    ///
    /// # Safety
    ///
    /// `address` must be non-zero and point to a live function with exactly
    /// `F`'s signature and calling convention for every use of this value.
    #[inline]
    pub unsafe fn from_address_unchecked(address: usize) -> Self {
        Self::new(unsafe { F::from_ptr(address as *const ()) })
    }

    /// Return the stored typed function pointer.
    #[inline]
    pub fn as_fn(&self) -> F {
        self.function
    }

    /// Return the function's untyped code address.
    #[inline]
    pub fn as_ptr(&self) -> *mut c_void {
        self.function.to_ptr().cast_mut().cast()
    }
}

impl<F: Function> fmt::Debug for FnPtr<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FnPtr")
            .field(&self.as_ptr())
            .finish()
    }
}
