//! Helpers for a 32-bit packed version format: 8-bit major, 8-bit minor,
//! 12-bit build, and 4-bit subversion.

#[inline]
pub const fn pack_version_with_subversion(
    major: u32,
    minor: u32,
    build: u32,
    subversion: u32,
) -> u32 {
    ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | ((build & 0xFFF) << 4) | (subversion & 0xF)
}

#[inline]
pub const fn pack_version(major: u32, minor: u32, build: u32) -> u32 {
    pack_version_with_subversion(major, minor, build, 0)
}

#[inline]
pub const fn unpack_version_major(version: u32) -> u32 {
    (version & 0xFF00_0000) >> 24
}

#[inline]
pub const fn unpack_version_minor(version: u32) -> u32 {
    (version & 0x00FF_0000) >> 16
}

#[inline]
pub const fn unpack_version_build(version: u32) -> u32 {
    (version & 0x0000_FFF0) >> 4
}

#[inline]
pub const fn unpack_version_subversion(version: u32) -> u32 {
    version & 0x0000_000F
}

/// A value encoded in the library's 8/8/12/4 packed version format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PackedVersion {
    major: u32,
    minor: u32,
    build: u32,
    subversion: u32,
    version: u32,
}

impl std::fmt::Display for PackedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.subversion > 0 {
            write!(
                f,
                "{}.{}.{}.{}",
                self.major, self.minor, self.build, self.subversion
            )
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.build)
        }
    }
}

impl PackedVersion {
    pub const fn new(major: u32, minor: u32, build: u32, subversion: u32) -> Self {
        Self {
            major,
            minor,
            build,
            subversion,
            version: pack_version_with_subversion(major, minor, build, subversion),
        }
    }

    /// Decode a 32-bit value in the 8/8/12/4 packed version format.
    pub const fn from_u32(version: u32) -> Self {
        Self {
            major: unpack_version_major(version),
            minor: unpack_version_minor(version),
            build: unpack_version_build(version),
            subversion: unpack_version_subversion(version),
            version,
        }
    }

    /// Return the packed 32-bit representation.
    pub const fn as_u32(&self) -> u32 {
        self.version
    }

    pub const fn major(&self) -> u32 {
        self.major
    }

    pub const fn minor(&self) -> u32 {
        self.minor
    }

    pub const fn build(&self) -> u32 {
        self.build
    }

    pub const fn subversion(&self) -> u32 {
        self.subversion
    }
}
