use std::marker::PhantomData;

use crate::os::windows::{hook::inline::inlinehook::InlineHook, types::funcs::MallocAlignFn};

use super::traits::Hook;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum HookContainerError { 
    #[error("Container already contains hook")]
    HookAlreadyExist,
}

pub type HookContainerResult<T> = std::result::Result<T, HookContainerError>;


#[derive(Debug)]
pub struct HookContainer<H: Hook<F>, F: Copy + 'static> {
    hook: Option<H>,
    _fntype: PhantomData<F>,
}

impl<H: Hook<F>, F: Copy + 'static> HookContainer<H, F> {
    pub const fn new() -> Self {
        Self {
            hook: None,
            _fntype: PhantomData,
        }
    }

    /// Locks HookContainer with Hook 'H'
    /// Returns error if hook already exist in current hook container.
    pub fn with_hook(&mut self, hook: H) -> HookContainerResult<&mut Self> {
        match self.hook {
            // Here is interesting part, in theory.
            // We not copy value which is in Option. We want only check if some value exist or not.
            Some(_) => {
                return Err(HookContainerError::HookAlreadyExist)
            }

            None => {
                self.hook = Some(hook);
            }
        }

        Ok(self)
    }


    pub fn enable(&self) -> HookContainerResult<()> {
        if let Some(hook) = &self.hook {
            hook.enable();
        }

        Ok(())
    }
}


static HC: HookContainer<InlineHook<MallocAlignFn>, MallocAlignFn> = HookContainer::<InlineHook<MallocAlignFn>, MallocAlignFn>::new();

fn t() {
    HC.enable();
}
