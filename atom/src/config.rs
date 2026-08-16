//! Unified, read-only Atom configuration.
//!
//! MCM Extender owns `Atom.ini`. Atom reads that file once per deferred load
//! or menu-close event, lets each subsystem deserialize its recognized keys,
//! and publishes independent immutable snapshots. Unknown sections and keys
//! remain tolerated so installed and future modules can share one file.

use thiserror::Error;

use crate::ballistics::{BallisticsConfig, BallisticsConfigError};
use crate::camera::third_person::{ThirdPersonConfig, ThirdPersonConfigError};
use crate::camera::{FirstPersonConfig, FirstPersonConfigError};
use crate::input::{ConfigError as InputConfigError, InputConfig};

/// Complete configuration snapshot consumed by Atom's native modules.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AtomConfig {
    input: InputConfig,
    ballistics: BallisticsConfig,
    first_person: FirstPersonConfig,
    third_person: ThirdPersonConfig,
}

impl AtomConfig {
    /// Deserialize every recognized Atom setting from one INI document.
    ///
    /// The subsystem parsers intentionally inspect the same immutable text.
    /// This keeps persistence ownership with MCM Extender and avoids coupling
    /// otherwise independent publication formats.
    pub fn from_ini(text: &str) -> Result<Self, AtomConfigError> {
        Ok(Self {
            input: InputConfig::from_ini(text)?,
            ballistics: BallisticsConfig::from_ini(text)?,
            first_person: FirstPersonConfig::from_ini(text)?,
            third_person: ThirdPersonConfig::from_ini(text)?,
        })
    }

    /// Return the input subsystem snapshot.
    #[inline]
    pub const fn input(self) -> InputConfig {
        self.input
    }

    /// Return the ballistics observation snapshot.
    #[inline]
    pub const fn ballistics(self) -> BallisticsConfig {
        self.ballistics
    }

    /// Return the first-person presentation snapshot.
    #[inline]
    pub const fn first_person(self) -> FirstPersonConfig {
        self.first_person
    }

    /// Return the third-person follow and locomotion snapshot.
    #[inline]
    pub const fn third_person(self) -> ThirdPersonConfig {
        self.third_person
    }
}

/// Failure to deserialize a recognized Atom setting.
#[derive(Debug, Error)]
pub enum AtomConfigError {
    /// The input configuration was invalid.
    #[error(transparent)]
    Input(#[from] InputConfigError),
    /// The ballistics configuration was invalid.
    #[error(transparent)]
    Ballistics(#[from] BallisticsConfigError),
    /// The first-person configuration was invalid.
    #[error(transparent)]
    FirstPerson(#[from] FirstPersonConfigError),
    /// The third-person configuration was invalid.
    #[error(transparent)]
    ThirdPerson(#[from] ThirdPersonConfigError),
}
