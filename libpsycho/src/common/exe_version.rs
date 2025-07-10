//! Abstractions for executable versioning


// Macro equivalents as Rust functions
#[inline]
pub const fn make_exe_version_ex(major: u32, minor: u32, build: u32, sub: u32) -> u32 {
    ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | ((build & 0xFFF) << 4) | (sub & 0xF)
}

#[inline]
pub const fn make_exe_version(major: u32, minor: u32, build: u32) -> u32 {
    make_exe_version_ex(major, minor, build, 0)
}

// Getter functions
#[inline]
pub const fn get_exe_version_major(version: u32) -> u32 {
    (version & 0xFF000000) >> 24
}

#[inline]
pub const fn get_exe_version_minor(version: u32) -> u32 {
    (version & 0x00FF0000) >> 16
}

#[inline]
pub const fn get_exe_version_build(version: u32) -> u32 {
    (version & 0x0000FFF0) >> 4
}

#[inline]
pub const fn get_exe_version_sub(version: u32) -> u32 {
    version & 0x0000000F
}


/// ExeVersion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExeVersion {
    major: u32,
    minor: u32,
    build: u32,
    sub: u32,

    version: u32,
}

impl std::fmt::Display for ExeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.sub > 0 {
            // sub almost always will be zero
            write!(f, "{}.{}.{}.{}", self.major, self.minor, self.build, self.sub)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.build)
        }
    }
}

impl ExeVersion {
    pub fn new(major: u32, minor: u32, build: u32, sub: u32) -> Self {
        let version = make_exe_version_ex(major, minor, build, sub);

        Self {
            major,
            minor,
            version,
            build,
            sub,
        }
    }

    /// Deconstruct packed version number (type u32)
    pub fn from_u32(version: u32) -> Self {
        let major = get_exe_version_major(version);
        let minor = get_exe_version_minor(version);
        let build = get_exe_version_build(version);
        let sub = get_exe_version_sub(version);

        Self {
            major,
            minor,
            version,
            build,
            sub,
        }    
    }

    /// Return packed version number
    /// Version packing work similar to F4SE logic.
    /// Can be safely used in interaction with C++ codebase.
    pub fn get_version_packed(&self) -> u32 {
        self.version
    }

    pub fn get_major(&self) -> u32 {
        self.major
    }

    pub fn get_minor(&self) -> u32 {
        self.minor
    }

    pub fn get_build(&self) -> u32 {
        self.build
    }

    pub fn get_sub(&self) -> u32 {
        self.sub
    }
}
