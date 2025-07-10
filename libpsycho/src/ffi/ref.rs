use std::{marker::PhantomData, ptr::NonNull, sync::Arc};

use parking_lot::Mutex;


/// FFIRef<T>
/// 
/// Basic building block for FFI interaction.
/// Use FFIRef when you get raw pointer to some struct and want read-only access.
/// Note: FFIRef<T> is Clone
#[derive(Clone)]
pub struct FFIRef<T> {
    inner: NonNull<T>,
    _phantom: PhantomData<T>,
}

impl<T> FFIRef<T> {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn from_ptr(ffi_ptr: *mut T) -> Option<Self> {
        if ffi_ptr.is_null() {
            return None;
        }
        
        let inner = unsafe { NonNull::new_unchecked(ffi_ptr) };

        Some(Self {
            inner,
            _phantom: PhantomData,
        })
    }
}

impl<T> AsRef<T> for FFIRef<T> {
    /// Return reference to underlying FFI type.
    fn as_ref(&self) -> &T {
        unsafe { self.inner.as_ref() }
    }
}


pub struct FFIRefMut<'a, T> {
    inner: NonNull<T>,
    _phantom: PhantomData<&'a mut T>,
}

impl<'a, T> FFIRefMut<'a, T> {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn from_ptr(ffi_ptr: *mut T) -> Option<Self> {
        if ffi_ptr.is_null() {
            return None;
        }
        
        let inner = unsafe { NonNull::new_unchecked(ffi_ptr) };

        Some(Self {
            inner,
            _phantom: PhantomData,
        })
    }
}

impl<'a, T> AsMut<T> for FFIRefMut<'a, T> {
    /// Return mutable reference to underlying FFI type.
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.inner.as_mut() }
    }
}

impl<'a, T> AsRef<T> for FFIRefMut<'a, T> {
    /// Return reference to underlying FFI type.
    fn as_ref(&self) -> &T {
        unsafe { self.inner.as_ref() }
    }
}

/// FFIRef<T> and FFIRefMut<T> are good, but not thread-safe.
/// SyncFFIRef<T> is thread-safe container for FFI type T.
pub struct SyncFFIRef<T> {
    inner: Arc<Mutex<NonNull<T>>>,
}

impl<T> SyncFFIRef<T> {
    pub fn from_ptr(ffi_ptr: *mut T) -> Option<Self> {
        NonNull::new(ffi_ptr).map(|ptr| {
            Self {
                inner: Arc::new(Mutex::new(ptr))
            }
        })
    }

    pub fn inner(&self) -> Arc<Mutex<NonNull<T>>> {
        self.inner.clone()
    }
}

impl<T> Clone for SyncFFIRef<T> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

// Safety: SyncFFIRef<T> is fully thread safe
unsafe impl<T: Send> Send for SyncFFIRef<T> {}

// Safety: SyncFFIRef<T> is fully thread safe
unsafe impl<T: Sync> Sync for SyncFFIRef<T> {}