//! Rollback support for installing a related set of runtime modifications.

use super::inline::{InlineHookResult, inlinehook::InlineHookContainer};
use super::replacement::ReplacementHookContainer;
use crate::ffi::fnptr::Function;
use crate::os::windows::patch::{CodePatchResult, OwnedCodePatch};

/// Collects successful hook and code-patch activations until commit.
///
/// Dropping an uncommitted transaction runs restorations in reverse order.
/// Rollback is best-effort and ownership-aware: bytes changed by another
/// component are reported and never overwritten. This type does not suspend
/// other threads and therefore does not make process-memory writes atomic.
#[must_use = "an uncommitted modification transaction rolls itself back"]
pub struct ModificationTransaction {
    rollbacks: Vec<Box<dyn FnOnce()>>,
    committed: bool,
}

impl ModificationTransaction {
    /// Start an empty transaction. It rolls back unless [`Self::commit`] runs.
    pub fn new() -> Self {
        Self {
            rollbacks: Vec::new(),
            committed: false,
        }
    }

    /// Enables a prepared inline hook and records its inverse operation.
    pub fn enable_inline<T: Function>(
        &mut self,
        hook: &'static InlineHookContainer<T>,
    ) -> InlineHookResult<()> {
        if let Err(error) = hook.enable() {
            if hook.is_enabled()
                && let Err(rollback_error) = hook.disable()
            {
                log::error!(
                    "Hook activation failed and immediate rollback also failed: {}",
                    rollback_error
                );
                // Keep ownership in the transaction so dropping it makes one
                // final restoration attempt. A caller must not commit after an
                // optional activation error while this hook remains enabled.
                self.rollbacks.push(Box::new(move || {
                    if let Err(error) = hook.disable() {
                        log::error!("Inline-hook rollback lost ownership: {}", error);
                    }
                }));
            }
            return Err(error);
        }

        self.rollbacks.push(Box::new(move || {
            if let Err(error) = hook.disable() {
                log::error!("Inline-hook rollback lost ownership: {}", error);
            }
        }));
        Ok(())
    }

    /// Enables a prepared provider replacement and records its inverse.
    pub fn enable_replacement<T: Function>(
        &mut self,
        hook: &'static ReplacementHookContainer<T>,
    ) -> InlineHookResult<()> {
        if let Err(error) = hook.enable() {
            if hook.is_enabled()
                && let Err(rollback_error) = hook.disable()
            {
                log::error!(
                    "Replacement-hook activation failed and immediate rollback also failed: {}",
                    rollback_error
                );
                self.rollbacks.push(Box::new(move || {
                    if let Err(error) = hook.disable() {
                        log::error!("Replacement-hook rollback lost ownership: {}", error);
                    }
                }));
            }
            return Err(error);
        }

        self.rollbacks.push(Box::new(move || {
            if let Err(error) = hook.disable() {
                log::error!("Replacement-hook rollback lost ownership: {}", error);
            }
        }));
        Ok(())
    }

    /// Applies an owned code patch and records its inverse operation.
    pub fn apply_patch(&mut self, patch: &'static OwnedCodePatch) -> CodePatchResult<()> {
        let Some(applied) = patch.apply()? else {
            return Ok(());
        };
        self.rollbacks.push(Box::new(move || {
            if let Err(error) = applied.restore() {
                log::error!("Code-patch rollback lost ownership: {}", error);
            }
        }));
        Ok(())
    }

    /// Keep every recorded modification active and discard its inverse actions.
    pub fn commit(mut self) {
        self.committed = true;
        self.rollbacks.clear();
    }
}

impl Default for ModificationTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ModificationTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        log::warn!("Rolling back incomplete runtime-modification transaction");
        while let Some(rollback) = self.rollbacks.pop() {
            rollback();
        }
    }
}
