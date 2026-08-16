//! Audited Fallout: New Vegas 1.4.0.525 ballistics ABI.
//!
//! Addresses and layouts in this module are valid only for the executable
//! accepted by Atom's plugin query. Caller fingerprints are validated again
//! immediately before deferred hook installation.

use core::ffi::c_void;

use super::{ProjectileCapability, ProjectileProfile, SourceKind};

pub(crate) const COUNT_CALLSITE: usize = 0x0052_4413;
pub(crate) const COUNT_TARGET: usize = 0x0052_5B20;
pub(crate) const LAUNCH_CALLSITE: usize = 0x0052_45BD;
pub(crate) const LAUNCH_TARGET: usize = 0x009B_CA60;
pub(crate) const HIT_BUILD_CALLSITE: usize = 0x009C_1E61;
pub(crate) const HIT_BUILD_TARGET: usize = 0x009B_5650;
pub(crate) const HIT_COMMIT_CALLSITE: usize = 0x009C_1E96;
pub(crate) const HIT_COMMIT_TARGET: usize = 0x0089_A760;
pub(crate) const COLLISION_CALLSITE: usize = 0x009C_2058;
pub(crate) const COLLISION_TARGET: usize = 0x009C_20E0;
pub(crate) const MISSILE_UPDATE_SLOT: usize = 0x0108_FD54;
pub(crate) const MISSILE_UPDATE_TARGET: usize = 0x009B_8030;
pub(crate) const HITSCAN_POLICY_CALLSITE: usize = 0x009B_7D08;
pub(crate) const HITSCAN_POLICY_TARGET: usize = 0x009A_7F80;

const PLAYER_SINGLETON: usize = 0x011D_EA3C;
const PROJECTILE_TYPE_MASK: u32 = 0x001F_0000;
const TYPE_MISSILE: u32 = 0x0001_0000;
const TYPE_GRENADE: u32 = 0x0002_0000;
const TYPE_BEAM: u32 = 0x0004_0000;
const TYPE_FLAME: u32 = 0x0008_0000;
const TYPE_CONTINUOUS_BEAM: u32 = 0x0010_0000;
const FLAG_HITSCAN: u16 = 1 << 0;
const FLAG_EXPLOSION: u16 = 1 << 1;
const RUNTIME_FLAG_HITSCAN: u32 = 0x2000;
const RUNTIME_FLAG_PHYSICAL: u32 = 0x8000;
const EFFECTIVE_SPEED_TARGET: usize = 0x0096_69C0;

/// Three-component Gamebryo position passed by value in the spawn ABI.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct NiPoint3 {
    pub(crate) x: f32,
    pub(crate) y: f32,
    pub(crate) z: f32,
}

#[repr(C)]
struct ProjectileFormView {
    prefix: [u8; 0x60],
    flags: u16,
    projectile_type: u16,
    gravity: f32,
    speed: f32,
    range: f32,
    lights_and_tracer: [u8; 0x14],
    explosion: *mut c_void,
}

/// Read-only fields whose offsets are shared by every runtime Projectile.
///
/// The padding is intentional: it makes the audited layout executable in
/// offset tests and keeps hook code from scattering unchecked byte arithmetic.
/// Atom reads this view only while a native callback owns the live object.
#[repr(C)]
struct ProjectileRuntimeView {
    prefix: [u8; 0x30],
    position: NiPoint3,
    before_impact_list: [u8; 0x4C],
    impact_list_head: *mut c_void,
    impact_list_tail: *mut c_void,
    has_impacted: u8,
    before_flags: [u8; 0x37],
    flags: u32,
    power: f32,
    speed_multiplier: f32,
    range: f32,
    age: f32,
    damage: f32,
    before_condition: [u8; 0x14],
    weapon_condition: f32,
    source_weapon: *mut c_void,
    source: *mut c_void,
    live_target: *mut c_void,
    direction: NiPoint3,
    distance_travelled: f32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeFlightPath {
    Hitscan,
    Physical,
    Ambiguous,
}

/// Exact state of FNV's two launch-policy marker bits on a live projectile.
///
/// These markers are sampled as compatibility evidence, not used to decide
/// which path Atom requested. Other runtime owners can retain both bits after
/// the engine's initializer has consumed the scoped policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimePolicyMarkers {
    HitscanOnly,
    PhysicalOnly,
    Both,
    Neither,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ProjectileRuntimeSample {
    pub(crate) position: [f32; 3],
    pub(crate) impact_list_empty: bool,
    pub(crate) has_impacted: bool,
    pub(crate) flags: u32,
    pub(crate) power: f32,
    pub(crate) speed_multiplier: f32,
    pub(crate) range: f32,
    pub(crate) age: f32,
    pub(crate) damage: f32,
    pub(crate) weapon_condition: f32,
    pub(crate) source_weapon_token: u32,
    pub(crate) source_token: u32,
    pub(crate) direction: [f32; 3],
    pub(crate) distance_travelled: f32,
}

impl ProjectileRuntimeSample {
    pub(crate) fn policy_markers(self) -> RuntimePolicyMarkers {
        runtime_policy_markers(self.flags)
    }

    pub(crate) fn is_finite(self) -> bool {
        self.position.into_iter().all(f32::is_finite)
            && self.direction.into_iter().all(f32::is_finite)
            && [
                self.power,
                self.speed_multiplier,
                self.range,
                self.age,
                self.damage,
                self.weapon_condition,
                self.distance_travelled,
            ]
            .into_iter()
            .all(f32::is_finite)
    }
}

#[cfg(test)]
fn runtime_flight_path(flags: u32) -> RuntimeFlightPath {
    match runtime_policy_markers(flags) {
        RuntimePolicyMarkers::HitscanOnly => RuntimeFlightPath::Hitscan,
        RuntimePolicyMarkers::PhysicalOnly => RuntimeFlightPath::Physical,
        RuntimePolicyMarkers::Both | RuntimePolicyMarkers::Neither => RuntimeFlightPath::Ambiguous,
    }
}

fn runtime_policy_markers(flags: u32) -> RuntimePolicyMarkers {
    match (
        flags & RUNTIME_FLAG_HITSCAN != 0,
        flags & RUNTIME_FLAG_PHYSICAL != 0,
    ) {
        (true, false) => RuntimePolicyMarkers::HitscanOnly,
        (false, true) => RuntimePolicyMarkers::PhysicalOnly,
        (true, true) => RuntimePolicyMarkers::Both,
        (false, false) => RuntimePolicyMarkers::Neither,
    }
}

pub(crate) type CountFn = unsafe extern "thiscall" fn(*mut c_void, u8, u8, *mut c_void) -> u8;

pub(crate) type LaunchFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    NiPoint3,
    f32,
    f32,
    *mut c_void,
    *mut c_void,
    u32,
    u32,
    f32,
    f32,
    *mut c_void,
) -> *mut c_void;

pub(crate) type HitBuildFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void);

pub(crate) type HitCommitFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

pub(crate) type CollisionFn = unsafe extern "thiscall" fn(
    *mut c_void,
    *mut c_void,
    *const NiPoint3,
    *const NiPoint3,
    *mut c_void,
    u32,
);

pub(crate) type MissileUpdateFn = unsafe extern "thiscall" fn(*mut c_void, f32);

pub(crate) type HitscanPolicyFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;

type EffectiveSpeedFn = unsafe extern "thiscall" fn(*mut c_void) -> f32;

/// Classify a pointer-free projectile profile by native capabilities.
pub fn classify_profile(profile: ProjectileProfile) -> ProjectileCapability {
    match profile.type_bits() & PROJECTILE_TYPE_MASK {
        TYPE_MISSILE if profile.has_explosion() => ProjectileCapability::ExplosiveMissile,
        TYPE_MISSILE if profile.flags() & FLAG_HITSCAN != 0 => {
            ProjectileCapability::DiscreteHitscan
        }
        TYPE_MISSILE => ProjectileCapability::DiscretePhysical,
        TYPE_GRENADE => ProjectileCapability::GrenadeOrThrown,
        TYPE_BEAM => ProjectileCapability::Beam,
        TYPE_FLAME => ProjectileCapability::Flame,
        TYPE_CONTINUOUS_BEAM => ProjectileCapability::ContinuousBeam,
        _ => ProjectileCapability::Unknown,
    }
}

pub(crate) unsafe fn profile(projectile: *mut c_void) -> ProjectileProfile {
    let projectile = projectile.cast::<ProjectileFormView>();
    let Some(projectile) = (unsafe { projectile.as_ref() }) else {
        return ProjectileProfile::default();
    };
    ProjectileProfile::new(
        projectile as *const ProjectileFormView as usize as u32,
        u32::from(projectile.projectile_type) << 16,
        projectile.flags,
        projectile.gravity,
        projectile.speed,
        projectile.range,
        projectile.flags & FLAG_EXPLOSION != 0 || !projectile.explosion.is_null(),
    )
}

pub(crate) unsafe fn source_kind(source: *mut c_void) -> SourceKind {
    if source.is_null() {
        return SourceKind::Unknown;
    }
    // The singleton slot is executable-version-validated before hooks open.
    let player = unsafe { (PLAYER_SINGLETON as *const *mut c_void).read() };
    if source == player {
        SourceKind::Player
    } else {
        SourceKind::Actor
    }
}

pub(crate) unsafe fn runtime_sample(projectile: *mut c_void) -> Option<ProjectileRuntimeSample> {
    let projectile = unsafe { projectile.cast::<ProjectileRuntimeView>().as_ref() }?;
    Some(ProjectileRuntimeSample {
        position: [
            projectile.position.x,
            projectile.position.y,
            projectile.position.z,
        ],
        impact_list_empty: projectile.impact_list_head.is_null(),
        has_impacted: projectile.has_impacted != 0,
        flags: projectile.flags,
        power: projectile.power,
        speed_multiplier: projectile.speed_multiplier,
        range: projectile.range,
        age: projectile.age,
        damage: projectile.damage,
        weapon_condition: projectile.weapon_condition,
        source_weapon_token: projectile.source_weapon as usize as u32,
        source_token: projectile.source as usize as u32,
        direction: [
            projectile.direction.x,
            projectile.direction.y,
            projectile.direction.z,
        ],
        distance_travelled: projectile.distance_travelled,
    })
}

pub(crate) unsafe fn effective_speed(projectile: *mut c_void) -> f32 {
    let function: EffectiveSpeedFn = unsafe { core::mem::transmute(EFFECTIVE_SPEED_TARGET) };
    unsafe { function(projectile) }
}

pub(crate) fn native_count() -> CountFn {
    unsafe { core::mem::transmute(COUNT_TARGET) }
}

pub(crate) fn native_launch() -> LaunchFn {
    unsafe { core::mem::transmute(LAUNCH_TARGET) }
}

pub(crate) fn native_hit_build() -> HitBuildFn {
    unsafe { core::mem::transmute(HIT_BUILD_TARGET) }
}

pub(crate) fn native_hit_commit() -> HitCommitFn {
    unsafe { core::mem::transmute(HIT_COMMIT_TARGET) }
}

pub(crate) fn native_collision() -> CollisionFn {
    unsafe { core::mem::transmute(COLLISION_TARGET) }
}

pub(crate) fn native_missile_update() -> MissileUpdateFn {
    unsafe { core::mem::transmute(MISSILE_UPDATE_TARGET) }
}

pub(crate) fn native_hitscan_policy() -> HitscanPolicyFn {
    unsafe { core::mem::transmute(HITSCAN_POLICY_TARGET) }
}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use super::{
        NiPoint3, ProjectileFormView, ProjectileRuntimeView, RuntimeFlightPath,
        RuntimePolicyMarkers, runtime_flight_path, runtime_policy_markers,
    };

    #[test]
    fn audited_projectile_form_offsets_match_xnvse_layout() {
        assert_eq!(size_of::<NiPoint3>(), 0x0C);
        assert_eq!(offset_of!(ProjectileFormView, flags), 0x60);
        assert_eq!(offset_of!(ProjectileFormView, projectile_type), 0x62);
        assert_eq!(offset_of!(ProjectileFormView, gravity), 0x64);
        assert_eq!(offset_of!(ProjectileFormView, speed), 0x68);
        assert_eq!(offset_of!(ProjectileFormView, range), 0x6C);
        assert_eq!(offset_of!(ProjectileFormView, explosion), 0x84);
    }

    #[test]
    fn audited_runtime_projectile_offsets_match_native_update_layout() {
        assert_eq!(offset_of!(ProjectileRuntimeView, position), 0x30);
        assert_eq!(offset_of!(ProjectileRuntimeView, impact_list_head), 0x88);
        assert_eq!(offset_of!(ProjectileRuntimeView, has_impacted), 0x90);
        assert_eq!(offset_of!(ProjectileRuntimeView, flags), 0xC8);
        assert_eq!(offset_of!(ProjectileRuntimeView, power), 0xCC);
        assert_eq!(offset_of!(ProjectileRuntimeView, speed_multiplier), 0xD0);
        assert_eq!(offset_of!(ProjectileRuntimeView, range), 0xD4);
        assert_eq!(offset_of!(ProjectileRuntimeView, age), 0xD8);
        assert_eq!(offset_of!(ProjectileRuntimeView, damage), 0xDC);
        assert_eq!(offset_of!(ProjectileRuntimeView, weapon_condition), 0xF4);
        assert_eq!(offset_of!(ProjectileRuntimeView, source_weapon), 0xF8);
        assert_eq!(offset_of!(ProjectileRuntimeView, source), 0xFC);
        assert_eq!(offset_of!(ProjectileRuntimeView, direction), 0x104);
        assert_eq!(offset_of!(ProjectileRuntimeView, distance_travelled), 0x110);
    }

    #[test]
    fn runtime_path_requires_one_complete_native_policy() {
        assert_eq!(runtime_flight_path(0x2000), RuntimeFlightPath::Hitscan);
        assert_eq!(runtime_flight_path(0x8000), RuntimeFlightPath::Physical);
        assert_eq!(runtime_flight_path(0), RuntimeFlightPath::Ambiguous);
        assert_eq!(
            runtime_flight_path(0x2000 | 0x8000),
            RuntimeFlightPath::Ambiguous
        );
    }

    #[test]
    fn runtime_policy_markers_preserve_coexisting_and_absent_states() {
        assert_eq!(
            runtime_policy_markers(0x2000),
            RuntimePolicyMarkers::HitscanOnly
        );
        assert_eq!(
            runtime_policy_markers(0x8000),
            RuntimePolicyMarkers::PhysicalOnly
        );
        assert_eq!(runtime_policy_markers(0xA000), RuntimePolicyMarkers::Both);
        assert_eq!(runtime_policy_markers(0), RuntimePolicyMarkers::Neither);
    }
}
