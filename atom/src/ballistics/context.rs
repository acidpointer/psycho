//! Immutable values captured at the authoritative native launch seam.
//!
//! Context values contain numeric correlation tokens only. Raw engine
//! pointers are never retained as Rust references and are never dereferenced
//! after the native callback that supplied them returns.

/// Broad origin of one native-authorized projectile launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SourceKind {
    /// The current player singleton launched the projectile.
    Player = 0,
    /// A non-player actor launched the projectile.
    Actor = 1,
    /// Native launch context did not contain an actor.
    Unknown = 2,
}

impl SourceKind {
    pub(crate) const COUNT: usize = 3;
}

/// Capability class derived only from live projectile behavior and links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProjectileCapability {
    /// Discrete MissileProjectile-family round with native physical flight.
    DiscretePhysical = 0,
    /// Discrete MissileProjectile-family round using native hitscan policy.
    DiscreteHitscan = 1,
    /// MissileProjectile-family round with explosion behavior or data.
    ExplosiveMissile = 2,
    /// Grenade, mine, placed, or thrown projectile family.
    GrenadeOrThrown = 3,
    /// Beam projectile family.
    Beam = 4,
    /// Flame projectile family.
    Flame = 5,
    /// Continuous-beam projectile family.
    ContinuousBeam = 6,
    /// Missing, contradictory, or unsupported projectile data.
    Unknown = 7,
}

impl ProjectileCapability {
    pub(crate) const COUNT: usize = 8;
}

/// Stable, pointer-free description of the projectile form seen at launch.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ProjectileProfile {
    form_token: u32,
    type_bits: u32,
    flags: u16,
    gravity: f32,
    speed: f32,
    range: f32,
    has_explosion: bool,
}

impl ProjectileProfile {
    /// Construct a profile from live form values.
    ///
    /// `form_token` is the numeric address used only for telemetry
    /// correlation. No API may turn it back into a retained Rust reference.
    pub const fn new(
        form_token: u32,
        type_bits: u32,
        flags: u16,
        gravity: f32,
        speed: f32,
        range: f32,
        has_explosion: bool,
    ) -> Self {
        Self {
            form_token,
            type_bits,
            flags,
            gravity,
            speed,
            range,
            has_explosion,
        }
    }

    /// Return the opaque form correlation token.
    pub const fn form_token(self) -> u32 {
        self.form_token
    }

    /// Return the native projectile-family bits.
    pub const fn type_bits(self) -> u32 {
        self.type_bits
    }

    /// Return native projectile record flags.
    pub const fn flags(self) -> u16 {
        self.flags
    }

    /// Return native projectile gravity.
    pub const fn gravity(self) -> f32 {
        self.gravity
    }

    /// Return native projectile speed.
    pub const fn speed(self) -> f32 {
        self.speed
    }

    /// Return native projectile range.
    pub const fn range(self) -> f32 {
        self.range
    }

    /// Return whether the projectile has explosion behavior or a linked form.
    pub const fn has_explosion(self) -> bool {
        self.has_explosion
    }
}

/// Pointer-free snapshot of one native-authorized launch.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ShotContext {
    sequence: u32,
    source_kind: SourceKind,
    source_token: u32,
    weapon_token: u32,
    projectile: ProjectileProfile,
    capability: ProjectileCapability,
    position: [f32; 3],
    rotation: [f32; 2],
    always_hit: bool,
    ignore_gravity: bool,
    has_live_target: bool,
}

impl ShotContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        sequence: u32,
        source_kind: SourceKind,
        source_token: u32,
        weapon_token: u32,
        projectile: ProjectileProfile,
        capability: ProjectileCapability,
        position: [f32; 3],
        rotation: [f32; 2],
        always_hit: bool,
        ignore_gravity: bool,
        has_live_target: bool,
    ) -> Self {
        Self {
            sequence,
            source_kind,
            source_token,
            weapon_token,
            projectile,
            capability,
            position,
            rotation,
            always_hit,
            ignore_gravity,
            has_live_target,
        }
    }

    /// Return the wrapping process-local launch sequence.
    pub const fn sequence(self) -> u32 {
        self.sequence
    }

    /// Return the launcher's broad runtime kind.
    pub const fn source_kind(self) -> SourceKind {
        self.source_kind
    }

    /// Return the opaque source correlation token.
    pub const fn source_token(self) -> u32 {
        self.source_token
    }

    /// Return the opaque source-weapon correlation token.
    pub const fn weapon_token(self) -> u32 {
        self.weapon_token
    }

    /// Return the immutable projectile-form profile.
    pub const fn projectile(self) -> ProjectileProfile {
        self.projectile
    }

    /// Return the launch-time capability classification.
    pub const fn capability(self) -> ProjectileCapability {
        self.capability
    }

    /// Return the native launch position.
    pub const fn position(self) -> [f32; 3] {
        self.position
    }

    /// Return native Z/X launch rotation.
    pub const fn rotation(self) -> [f32; 2] {
        self.rotation
    }

    /// Return native always-hit launch policy.
    pub const fn always_hit(self) -> bool {
        self.always_hit
    }

    /// Return native ignore-gravity launch policy.
    pub const fn ignore_gravity(self) -> bool {
        self.ignore_gravity
    }

    /// Return whether native launch supplied a live target.
    pub const fn has_live_target(self) -> bool {
        self.has_live_target
    }
}
