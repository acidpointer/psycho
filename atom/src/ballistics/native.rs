//! Audited Fallout: New Vegas 1.4.0.525 ballistics ABI.
//!
//! Addresses and layouts in this module are valid only for the executable
//! accepted by Atom's plugin query. Caller fingerprints are validated again
//! immediately before deferred hook installation.

use core::ffi::c_void;

use libpsycho::os::windows::memory::{MemoryError, read_bytes, validate_memory_access};
use thiserror::Error;

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
pub(crate) const COMMON_IMPACT_CALLSITE: usize = 0x009B_8BD8;
pub(crate) const COMMON_IMPACT_TARGET: usize = 0x009C_1B70;
pub(crate) const MISSILE_UPDATE_SLOT: usize = 0x0108_FD54;
pub(crate) const MISSILE_UPDATE_TARGET: usize = 0x009B_8030;
pub(crate) const MOVEMENT_STEP_CALLSITE_A: usize = 0x009B_83E5;
pub(crate) const MOVEMENT_STEP_CALLSITE_B: usize = 0x009B_847C;
pub(crate) const MOVEMENT_STEP_TARGET: usize = 0x009B_F300;
pub(crate) const HITSCAN_POLICY_CALLSITE: usize = 0x009B_7D08;
pub(crate) const HITSCAN_POLICY_TARGET: usize = 0x009A_7F80;
pub(crate) const MUZZLE_FLASH_CALLSITE: usize = 0x009B_DCA2;
pub(crate) const MUZZLE_FLASH_TARGET: usize = 0x009C_2FF0;

const TES_SINGLETON: usize = 0x011D_EA10;
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
const RAYCAST_TARGET: usize = 0x0045_8440;
const PROJECTILE_TERMINATE_TARGET: usize = 0x009B_C8F0;
const VATS_CAMERA_DATA: usize = 0x011F_2250;
const VATS_MODE_OFFSET: usize = 0x08;
const MIN_ENGINE_POINTER: usize = 0x1_0000;
const MAX_IMPACT_SCAN_NODES: usize = 8;
const HAVOK_UNITS_PER_GAME_UNIT: f32 = f32::from_bits(0x3E12_4DD2);

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

#[repr(C)]
struct ImpactDataView {
    target: *mut c_void,
    point: NiPoint3,
    normal: NiPoint3,
    rigid_body: *mut c_void,
    raw_material: u32,
    hit_location: u32,
    marker: u8,
    ready: u8,
    tail: [u8; 6],
}

#[repr(C)]
struct ImpactListNode {
    data: *mut ImpactDataView,
    next: *mut ImpactListNode,
}

/// FNV's 32-bit Havok world-ray input and output record.
#[repr(C, align(16))]
struct RayCastData {
    position_start: [f32; 4],
    position_end: [f32; 4],
    byte_20: u8,
    padding_21: [u8; 3],
    layer_type: u8,
    filter_flags: u8,
    group: u16,
    unknown_28: [u32; 6],
    fraction: f32,
    unknown_44: [u32; 15],
    collision_body: u32,
    unknown_84: [u32; 3],
    hit_normal: [f32; 4],
    unknown_a0: [u32; 3],
    byte_ac: u8,
    padding_ad: [u8; 3],
}

impl RayCastData {
    fn new(start: [f32; 3], end: [f32; 3], group: u16) -> Self {
        let to_havok = |point: [f32; 3]| {
            [
                point[0] * HAVOK_UNITS_PER_GAME_UNIT,
                point[1] * HAVOK_UNITS_PER_GAME_UNIT,
                point[2] * HAVOK_UNITS_PER_GAME_UNIT,
                0.0,
            ]
        };
        let mut data = Self {
            position_start: to_havok(start),
            position_end: to_havok(end),
            byte_20: 0,
            padding_21: [0; 3],
            layer_type: 6,
            filter_flags: 0,
            group,
            unknown_28: [0; 6],
            fraction: 1.0,
            unknown_44: [0; 15],
            collision_body: 0,
            unknown_84: [0; 3],
            hit_normal: [0.0; 4],
            unknown_a0: [0; 3],
            byte_ac: 0,
            padding_ad: [0; 3],
        };
        data.unknown_44[0] = u32::MAX;
        data.unknown_44[3] = u32::MAX;
        data
    }
}

/// Read-only fields whose offsets are shared by every runtime Projectile.
///
/// The padding is intentional: it makes the audited layout executable in
/// offset tests and keeps hook code from scattering unchecked byte arithmetic.
/// Atom reads this view only while a native callback owns the live object.
#[repr(C)]
struct ProjectileRuntimeView {
    prefix: [u8; 0x20],
    base_form: *mut c_void,
    rotation_x: f32,
    rotation_y: f32,
    rotation_z: f32,
    position: NiPoint3,
    before_parent_cell: [u8; 0x04],
    parent_cell: *mut c_void,
    before_impact_list: [u8; 0x44],
    impact_list: ImpactListNode,
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
    before_flight_target: [u8; 0x2C],
    flight_target: *mut c_void,
    rock_it_entry: *mut c_void,
    before_impact_result: [u8; 0x08],
    impact_result: u32,
}

/// Value-only copy of one ready native impact record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ImpactRecordSample {
    pub(crate) target_token: u32,
    pub(crate) point: [f32; 3],
    pub(crate) normal: [f32; 3],
    pub(crate) raw_material: u32,
}

impl ImpactRecordSample {
    pub(crate) fn is_finite(self) -> bool {
        self.point.into_iter().all(f32::is_finite) && self.normal.into_iter().all(f32::is_finite)
    }
}

/// Bounded view of the ready records owned by one native impact traversal.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct ImpactListSample {
    pub(crate) first_ready: Option<ImpactRecordSample>,
    pub(crate) ready_count: u8,
    pub(crate) traversal_truncated: bool,
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
    pub(crate) base_form_token: u32,
    pub(crate) parent_cell_token: u32,
    /// Native reference yaw and pitch. Ordinary Missile movement consumes
    /// these values before refreshing `direction` with the completed step.
    pub(crate) rotation: [f32; 2],
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
    pub(crate) live_target_token: u32,
    pub(crate) direction: [f32; 3],
    pub(crate) distance_travelled: f32,
    pub(crate) flight_target_token: u32,
    pub(crate) rock_it_entry_token: u32,
    pub(crate) impact_result: u32,
}

impl ProjectileRuntimeSample {
    pub(crate) fn policy_markers(self) -> RuntimePolicyMarkers {
        runtime_policy_markers(self.flags)
    }

    pub(crate) fn is_finite(self) -> bool {
        self.rotation.into_iter().all(f32::is_finite)
            && self.position.into_iter().all(f32::is_finite)
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

pub(crate) type CommonImpactFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;

pub(crate) type MissileUpdateFn = unsafe extern "thiscall" fn(*mut c_void, f32);

pub(crate) type MovementStepFn = unsafe extern "thiscall" fn(*mut c_void, f32);

pub(crate) type HitscanPolicyFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;

pub(crate) type MuzzleFlashFn = unsafe extern "thiscall" fn(*mut c_void);

/// Failure of an admission-time check on a helper Atom calls directly at
/// runtime.
#[derive(Debug, Error)]
pub enum HelperContractError {
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error("runtime helper entry is unavailable: {} at 0x{address:08X}", helper.label())]
    EntryUnavailable { helper: HelperKind, address: usize },
}

/// Identity of one helper Atom invokes directly by fixed address at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperKind {
    /// BGSProjectile-derived effective speed `0x009669C0`.
    EffectiveSpeed,
    /// Havok world-ray wrapper `0x00458440`.
    ClearanceRaycast,
    /// Projectile terminal path `0x009BC8F0`.
    ProjectileTerminate,
    /// Canonical ranged launch `0x009BCA60`.
    ProjectileLaunch,
}

impl HelperKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::EffectiveSpeed => "effective speed",
            Self::ClearanceRaycast => "clearance raycast",
            Self::ProjectileTerminate => "projectile terminate",
            Self::ProjectileLaunch => "projectile launch",
        }
    }

    pub(crate) const fn target(self) -> usize {
        match self {
            Self::EffectiveSpeed => EFFECTIVE_SPEED_TARGET,
            Self::ClearanceRaycast => RAYCAST_TARGET,
            Self::ProjectileTerminate => PROJECTILE_TERMINATE_TARGET,
            Self::ProjectileLaunch => LAUNCH_TARGET,
        }
    }
}

/// All four directly-called helpers, in stable diagnostic order.
const HELPER_KINDS: [HelperKind; 4] = [
    HelperKind::EffectiveSpeed,
    HelperKind::ClearanceRaycast,
    HelperKind::ProjectileTerminate,
    HelperKind::ProjectileLaunch,
];

/// One interior-body window that differs from the researched binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HelperFinding {
    pub(crate) kind: HelperKind,
    pub(crate) address: usize,
}

/// Diagnostic result of comparing every interior-body window at admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HelperScan {
    /// First differing window per helper kind; `None` while it matches.
    pub(crate) findings: [Option<HelperFinding>; HELPER_KINDS.len()],
    /// Windows that differ from the researched binary.
    pub(crate) differing: usize,
    /// Windows actually compared (unreadable windows are unverifiable, not
    /// differing, and are skipped).
    pub(crate) checked: usize,
}

impl HelperScan {
    const CLEAN: Self = Self {
        findings: [None; HELPER_KINDS.len()],
        differing: 0,
        checked: 0,
    };

    /// Human-readable summary of the differing helpers, if any.
    pub(crate) fn summary(&self) -> Option<String> {
        let names: Vec<String> = self
            .findings
            .iter()
            .flatten()
            .map(|finding| format!("{} @ 0x{:08X}", finding.kind.label(), finding.address))
            .collect();
        (!names.is_empty()).then(|| names.join(", "))
    }
}

/// Interior-body and epilogue evidence for every directly-called helper.
///
/// These windows are **diagnostic only**: they name which helper a third-party
/// patcher touched. They never disable anything. Admission gates on entry
/// readiness alone ([`validate_helper_entries`]); ecosystem patchers either
/// hook entries with ABI-preserving jumps or edit instructions in place, and
/// both remain safe to call through.
///
/// Each window starts beyond offset +0x09 so a compatible earlier owner's
/// complete entry jump never reports as a difference. Evidence:
/// `analysis/radare2/output/perf/fnv_ballistics_runtime_helper_contract.txt`.
pub(crate) struct HelperWindow {
    pub(crate) kind: HelperKind,
    pub(crate) offset: usize,
    pub(crate) bytes: &'static [u8],
}

impl HelperWindow {
    pub(crate) const fn address(&self) -> usize {
        self.kind.target() + self.offset
    }

    pub(crate) fn matches(&self, actual: &[u8]) -> bool {
        actual == self.bytes
    }
}

pub(crate) const RUNTIME_HELPER_WINDOWS: &[HelperWindow] = &[
    // BGSProjectile-derived effective speed 0x009669C0.
    HelperWindow {
        kind: HelperKind::EffectiveSpeed,
        offset: 0x14,
        bytes: &[
            0x8B, 0x4D, 0xFC, 0x51, 0xD9, 0x81, 0xCC, 0x00, 0x00, 0x00, 0xD9, 0x1C, 0x24,
        ],
    },
    HelperWindow {
        kind: HelperKind::EffectiveSpeed,
        offset: 0x39,
        bytes: &[0x83, 0xC4, 0x0C, 0x8B, 0xE5, 0x5D, 0xC3],
    },
    // Havok world-ray wrapper 0x00458440.
    HelperWindow {
        kind: HelperKind::ClearanceRaycast,
        offset: 0x09,
        bytes: &[0x0F, 0xB6, 0x45, 0x0C, 0x85, 0xC0],
    },
    HelperWindow {
        kind: HelperKind::ClearanceRaycast,
        offset: 0x22,
        bytes: &[0xB9, 0xCC, 0x63, 0x1C, 0x01, 0xE8, 0x64, 0x50, 0xFE, 0xFF],
    },
    HelperWindow {
        kind: HelperKind::ClearanceRaycast,
        offset: 0x81,
        bytes: &[0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00],
    },
    // Projectile terminal path 0x009BC8F0.
    HelperWindow {
        kind: HelperKind::ProjectileTerminate,
        offset: 0x21,
        bytes: &[
            0x81, 0xC1, 0x88, 0x00, 0x00, 0x00, 0xE8, 0xB4, 0x8D, 0xE6, 0xFF,
        ],
    },
    HelperWindow {
        kind: HelperKind::ProjectileTerminate,
        offset: 0x15A,
        bytes: &[0x8B, 0x90, 0xC4, 0x00, 0x00, 0x00, 0xFF, 0xD2],
    },
    HelperWindow {
        kind: HelperKind::ProjectileTerminate,
        offset: 0x16C,
        bytes: &[0x8B, 0xE5, 0x5D, 0xC3],
    },
    // Canonical ranged launch 0x009BCA60.
    HelperWindow {
        kind: HelperKind::ProjectileLaunch,
        offset: 0x2A,
        bytes: &[
            0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x45, 0xF3, 0x01,
        ],
    },
    HelperWindow {
        kind: HelperKind::ProjectileLaunch,
        offset: 0x4D,
        bytes: &[0x81, 0xBD, 0x20, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x04, 0x00],
    },
    HelperWindow {
        kind: HelperKind::ProjectileLaunch,
        offset: 0xAC3,
        bytes: &[
            0x64, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x59, 0x5F, 0x5E, 0x8B, 0xE5, 0x5D, 0xC3,
        ],
    },
];

/// Validate that every directly-called helper entry is mapped executable
/// memory.
///
/// This is the complete call-safety precondition Atom can prove: invoking an
/// unmapped or non-executable address would crash regardless of who owns the
/// body. Body ownership is deliberately not an admission condition; see
/// [`scan_helper_bodies`] for the diagnostic counterpart.
pub fn validate_helper_entries() -> Result<(), HelperContractError> {
    for kind in HELPER_KINDS {
        let address = kind.target();
        validate_memory_access(address as *mut c_void).map_err(|_| {
            HelperContractError::EntryUnavailable {
                helper: kind,
                address,
            }
        })?;
    }
    Ok(())
}

/// Compare every interior-body window against the researched binary.
///
/// Purely diagnostic: differences are reported to the user and recorded in
/// logs, never used to disable capability. Unreadable windows are counted as
/// unchecked rather than differing.
pub(crate) fn scan_helper_bodies() -> HelperScan {
    let mut scan = HelperScan::CLEAN;
    for window in RUNTIME_HELPER_WINDOWS {
        let Ok(actual) = read_bytes(window.address() as *const c_void, window.bytes.len()) else {
            continue;
        };
        scan.checked += 1;
        if !window.matches(&actual) && scan.differing < scan.findings.len() {
            let slot = HELPER_KINDS
                .iter()
                .position(|kind| *kind == window.kind)
                .unwrap_or_default();
            if scan.findings[slot].is_none() {
                scan.findings[slot] = Some(HelperFinding {
                    kind: window.kind,
                    address: window.address(),
                });
            }
            scan.differing += 1;
        }
    }
    scan
}

type EffectiveSpeedFn = unsafe extern "thiscall" fn(*mut c_void) -> f32;

type RayCastFn = unsafe extern "thiscall" fn(*mut c_void, *mut RayCastData, u32) -> *mut c_void;

type ProjectileTerminateFn = unsafe extern "thiscall" fn(*mut c_void);

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
        base_form_token: projectile.base_form as usize as u32,
        parent_cell_token: projectile.parent_cell as usize as u32,
        rotation: [projectile.rotation_z, projectile.rotation_x],
        position: [
            projectile.position.x,
            projectile.position.y,
            projectile.position.z,
        ],
        impact_list_empty: projectile.impact_list.data.is_null(),
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
        live_target_token: projectile.live_target as usize as u32,
        direction: [
            projectile.direction.x,
            projectile.direction.y,
            projectile.direction.z,
        ],
        distance_travelled: projectile.distance_travelled,
        flight_target_token: projectile.flight_target as usize as u32,
        rock_it_entry_token: projectile.rock_it_entry as usize as u32,
        impact_result: projectile.impact_result,
    })
}

/// Snapshot at most two ready impact records from the callback-owned list.
///
/// # Safety
///
/// `projectile` must be the live object supplied to the synchronous native
/// ProcessImpacts callback. Its embedded list and every traversed node must
/// remain engine-owned and valid for the duration of this call. No pointer is
/// retained in the returned value.
pub(crate) unsafe fn impact_list_sample(projectile: *mut c_void) -> Option<ImpactListSample> {
    let projectile = unsafe { projectile.cast::<ProjectileRuntimeView>().as_ref() }?;
    let mut sample = ImpactListSample::default();
    let mut node = &projectile.impact_list as *const ImpactListNode;

    for _ in 0..MAX_IMPACT_SCAN_NODES {
        let current = unsafe { node.as_ref() }?;
        if let Some(data) = unsafe { current.data.as_ref() }
            && data.ready != 0
        {
            sample.ready_count = sample.ready_count.saturating_add(1);
            if sample.first_ready.is_none() {
                sample.first_ready = Some(ImpactRecordSample {
                    target_token: data.target as usize as u32,
                    point: [data.point.x, data.point.y, data.point.z],
                    normal: [data.normal.x, data.normal.y, data.normal.z],
                    raw_material: data.raw_material,
                });
            }
            if sample.ready_count >= 2 {
                return Some(sample);
            }
        }

        if current.next.is_null() {
            return Some(sample);
        }
        node = current.next;
    }

    sample.traversal_truncated = true;
    Some(sample)
}

/// Return whether FNV's live VATS camera state is active.
pub(crate) unsafe fn vats_active() -> bool {
    unsafe { core::ptr::read_unaligned((VATS_CAMERA_DATA + VATS_MODE_OFFSET) as *const u32) != 0 }
}

/// Ask FNV's collision world whether the complete outbound child segment is usable.
///
/// This reproduces the working comparison mod's `RayCastCoords` contract:
/// player collision group, layer 6, a 1024-unit ray, and a loaded endpoint when
/// the query returns no obstruction. The child origin is admitted only when
/// the first obstruction lies strictly beyond 32 units.
///
/// # Safety
///
/// The supported executable must be active at its normal gameplay lifecycle.
/// The validated TES/player singleton chains and `0x00458440` ABI must match
/// the executable contract.
pub(crate) unsafe fn outbound_clearance_available(path: super::ricochet::ChildSpawnPath) -> bool {
    let Some(tes) = (unsafe { read_global_pointer(TES_SINGLETON) }) else {
        return false;
    };
    let Some(group) = (unsafe { player_collision_group() }) else {
        return false;
    };
    let mut ray = RayCastData::new(path.ray_start(), path.ray_end(), group);
    let raycast: RayCastFn = unsafe { core::mem::transmute(RAYCAST_TARGET) };
    let hit = unsafe { raycast(tes, &mut ray, 1) };
    if !ray.fraction.is_finite() || !(0.0..=1.0).contains(&ray.fraction) {
        return false;
    }
    if hit.is_null() && !unsafe { ray_endpoint_is_loaded(tes, path.ray_end()) } {
        return false;
    }
    ray.fraction * super::ricochet::RICOCHET_TRACE_UNITS
        > super::ricochet::RICOCHET_SPAWN_CLEARANCE_UNITS
}

/// Exact invariant that prevented publication of a freshly spawned child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ChildInitializationError {
    InvalidInput = 0,
    SampleUnavailable = 1,
    BaseForm = 2,
    ParentCell = 3,
    SourceWeapon = 4,
    Source = 5,
    LiveTarget = 6,
    ImpactList = 7,
    Impacted = 8,
    RockIt = 9,
    ImpactResult = 10,
    InvalidEnergy = 11,
    PublishedSampleUnavailable = 12,
    PostWriteMismatch = 13,
}

impl ChildInitializationError {
    pub(crate) const COUNT: usize = 14;
}

/// Transfer only audited scalar flight state into a freshly spawned child.
///
/// Native launch owns the new object's references, impact list, flags, render
/// state, and auxiliary pointers. Atom retains the original round's live
/// energy/range progression without copying native ownership state.
///
/// # Safety
///
/// `child` must be the non-null return from the synchronous native spawn call
/// and must not alias the still-live parent. `parent` must be a sample captured
/// from that parent in the same common-impact callback.
pub(crate) unsafe fn initialize_ricochet_child(
    child: *mut c_void,
    parent: ProjectileRuntimeSample,
    speed_retention: f32,
    damage_retention: f32,
) -> Result<ProjectileRuntimeSample, ChildInitializationError> {
    if (child as usize) < MIN_ENGINE_POINTER
        || !speed_retention.is_finite()
        || !damage_retention.is_finite()
    {
        return Err(ChildInitializationError::InvalidInput);
    }
    let before =
        unsafe { runtime_sample(child) }.ok_or(ChildInitializationError::SampleUnavailable)?;
    if before.base_form_token != parent.base_form_token {
        return Err(ChildInitializationError::BaseForm);
    }
    if before.parent_cell_token != parent.parent_cell_token {
        return Err(ChildInitializationError::ParentCell);
    }
    if before.source_weapon_token != parent.source_weapon_token {
        return Err(ChildInitializationError::SourceWeapon);
    }
    if before.source_token != parent.source_token {
        return Err(ChildInitializationError::Source);
    }
    if before.live_target_token != 0 {
        return Err(ChildInitializationError::LiveTarget);
    }
    if !before.impact_list_empty {
        return Err(ChildInitializationError::ImpactList);
    }
    if before.has_impacted {
        return Err(ChildInitializationError::Impacted);
    }
    if before.rock_it_entry_token != 0 {
        return Err(ChildInitializationError::RockIt);
    }
    if before.impact_result != 0 {
        return Err(ChildInitializationError::ImpactResult);
    }
    let speed_multiplier = parent.speed_multiplier * speed_retention;
    let damage = parent.damage * damage_retention;
    if !speed_multiplier.is_finite()
        || speed_multiplier <= 0.0
        || !damage.is_finite()
        || damage <= 0.0
    {
        return Err(ChildInitializationError::InvalidEnergy);
    }

    let child = unsafe { &mut *child.cast::<ProjectileRuntimeView>() };
    child.power = parent.power;
    child.speed_multiplier = speed_multiplier;
    child.range = parent.range;
    child.age = parent.age;
    child.damage = damage;
    child.weapon_condition = parent.weapon_condition;
    child.distance_travelled = parent.distance_travelled;

    let published = unsafe { runtime_sample(child as *mut ProjectileRuntimeView as *mut c_void) }
        .ok_or(ChildInitializationError::PublishedSampleUnavailable)?;
    (published.power.to_bits() == parent.power.to_bits()
        && published.speed_multiplier.to_bits() == speed_multiplier.to_bits()
        && published.range.to_bits() == parent.range.to_bits()
        && published.age.to_bits() == parent.age.to_bits()
        && published.damage.to_bits() == damage.to_bits()
        && published.weapon_condition.to_bits() == parent.weapon_condition.to_bits()
        && published.distance_travelled.to_bits() == parent.distance_travelled.to_bits())
    .then_some(published)
    .ok_or(ChildInitializationError::PostWriteMismatch)
}

/// End a failed synthetic child through the projectile's native terminal path.
///
/// # Safety
///
/// `projectile` must be a live projectile returned by `0x009BCA60` that Atom
/// cannot publish. The function must be called at most once for that object.
pub(crate) unsafe fn terminate_projectile(projectile: *mut c_void) {
    let terminate: ProjectileTerminateFn =
        unsafe { core::mem::transmute(PROJECTILE_TERMINATE_TARGET) };
    unsafe { terminate(projectile) };
}

/// Read the base form token needed to scope synthetic muzzle suppression.
///
/// # Safety
///
/// `projectile` must be the live projectile passed by the native muzzle call.
pub(crate) unsafe fn runtime_base_form_token(projectile: *mut c_void) -> u32 {
    unsafe { projectile.cast::<ProjectileRuntimeView>().as_ref() }
        .map(|projectile| projectile.base_form as usize as u32)
        .unwrap_or(0)
}

unsafe fn player_collision_group() -> Option<u16> {
    let player = unsafe { read_global_pointer(PLAYER_SINGLETON) }?;
    let process = unsafe { read_pointer(player, 0x68) }?;
    let controller = unsafe { read_pointer(process, 0x138) }?;
    let phantom = unsafe { read_pointer(controller, 0x594) }?;
    let world_object = unsafe { read_pointer(phantom, 0x08) }?;
    let filter_info =
        unsafe { core::ptr::read_unaligned((world_object as *const u8).add(0x2C).cast::<u32>()) };
    Some((filter_info >> 16) as u16)
}

unsafe fn ray_endpoint_is_loaded(tes: *mut c_void, endpoint: [f32; 3]) -> bool {
    if unsafe { read_pointer(tes, 0x34) }.is_some() {
        return true;
    }
    let Some(grid) = (unsafe { read_pointer(tes, 0x08) }) else {
        return false;
    };
    let grid = grid as *const u8;
    let origin_x = unsafe { core::ptr::read_unaligned(grid.add(0x04).cast::<i32>()) };
    let origin_y = unsafe { core::ptr::read_unaligned(grid.add(0x08).cast::<i32>()) };
    let grid_size = unsafe { core::ptr::read_unaligned(grid.add(0x0C).cast::<u32>()) };
    let cells = unsafe { core::ptr::read_unaligned(grid.add(0x10).cast::<*const u32>()) };
    if grid_size == 0 || grid_size > 31 || (cells as usize) < MIN_ENGINE_POINTER {
        return false;
    }
    let Some(cell_x) = world_cell_coordinate(endpoint[0]) else {
        return false;
    };
    let Some(cell_y) = world_cell_coordinate(endpoint[1]) else {
        return false;
    };
    let Some(index) = loaded_grid_index(grid_size, origin_x, origin_y, cell_x, cell_y) else {
        return false;
    };
    unsafe { core::ptr::read_unaligned(cells.add(index)) != 0 }
}

fn loaded_grid_index(
    grid_size: u32,
    origin_x: i32,
    origin_y: i32,
    cell_x: i32,
    cell_y: i32,
) -> Option<usize> {
    if grid_size == 0 || grid_size > 31 {
        return None;
    }
    let half = i64::from(grid_size >> 1);
    let x = i64::from(cell_x) - i64::from(origin_x) + half;
    let y = i64::from(cell_y) - i64::from(origin_y) + half;
    if x < 0 || y < 0 || x >= i64::from(grid_size) || y >= i64::from(grid_size) {
        return None;
    }
    let index = u32::try_from(x)
        .ok()?
        .checked_mul(grid_size)?
        .checked_add(u32::try_from(y).ok()?)?;
    usize::try_from(index).ok()
}

fn world_cell_coordinate(value: f32) -> Option<i32> {
    if !value.is_finite() || value < i32::MIN as f32 || value > i32::MAX as f32 {
        return None;
    }
    Some((value.trunc() as i32) >> 12)
}

unsafe fn read_global_pointer(address: usize) -> Option<*mut c_void> {
    let value = unsafe { core::ptr::read_unaligned(address as *const *mut c_void) };
    ((value as usize) >= MIN_ENGINE_POINTER).then_some(value)
}

unsafe fn read_pointer(owner: *mut c_void, offset: usize) -> Option<*mut c_void> {
    if (owner as usize) < MIN_ENGINE_POINTER {
        return None;
    }
    let value = unsafe {
        core::ptr::read_unaligned((owner as *const u8).add(offset).cast::<*mut c_void>())
    };
    ((value as usize) >= MIN_ENGINE_POINTER).then_some(value)
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

pub(crate) fn native_common_impacts() -> CommonImpactFn {
    unsafe { core::mem::transmute(COMMON_IMPACT_TARGET) }
}

pub(crate) fn native_missile_update() -> MissileUpdateFn {
    unsafe { core::mem::transmute(MISSILE_UPDATE_TARGET) }
}

pub(crate) fn native_movement_step() -> MovementStepFn {
    unsafe { core::mem::transmute(MOVEMENT_STEP_TARGET) }
}

pub(crate) fn native_hitscan_policy() -> HitscanPolicyFn {
    unsafe { core::mem::transmute(HITSCAN_POLICY_TARGET) }
}

pub(crate) fn native_muzzle_flash() -> MuzzleFlashFn {
    unsafe { core::mem::transmute(MUZZLE_FLASH_TARGET) }
}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use super::{
        HELPER_KINDS, HelperKind, ImpactDataView, ImpactListNode, NiPoint3, ProjectileFormView,
        ProjectileRuntimeView, RUNTIME_HELPER_WINDOWS, RayCastData, RuntimeFlightPath,
        RuntimePolicyMarkers, loaded_grid_index, runtime_flight_path, runtime_policy_markers,
        world_cell_coordinate,
    };

    /// Ledger section that pins every window's exact bytes.
    const LEDGER_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../analysis/radare2/output/perf/fnv_ballistics_runtime_helper_contract.txt"
    );

    #[test]
    fn helper_windows_match_the_evidence_ledger_byte_for_byte() {
        let ledger = std::fs::read_to_string(LEDGER_PATH).expect("helper contract ledger");
        let mut matched = 0;
        for line in ledger.lines() {
            let Some((address_text, bytes_text)) = line.split_once(" len ") else {
                continue;
            };
            let Some((length_text, hex_text)) = bytes_text.split_once(": ") else {
                continue;
            };
            let address = usize::from_str_radix(address_text.trim().trim_start_matches("0x"), 16)
                .expect("ledger address");
            let _ = length_text;
            for window in RUNTIME_HELPER_WINDOWS {
                if window.address() != address {
                    continue;
                }
                let expected_len = window.bytes.len();
                assert_eq!(
                    hex_text.len(),
                    expected_len * 2,
                    "ledger length drift at 0x{address:08X}"
                );
                for (index, byte) in window.bytes.iter().enumerate() {
                    let parsed = u8::from_str_radix(
                        hex_text.get(index * 2..index * 2 + 2).expect("hex pair"),
                        16,
                    )
                    .expect("ledger hex byte");
                    assert_eq!(
                        *byte,
                        parsed,
                        "window {:#x} byte {index} drifted from the ledger",
                        window.address()
                    );
                }
                matched += 1;
            }
        }
        assert_eq!(
            matched,
            RUNTIME_HELPER_WINDOWS.len(),
            "every window must be pinned by a ledger line"
        );
    }

    #[test]
    fn helper_labels_are_distinct_and_cover_all_targets() {
        let mut labels: Vec<&str> = HELPER_KINDS.map(HelperKind::label).to_vec();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count);
        for kind in HELPER_KINDS {
            assert!(!kind.label().is_empty());
            assert!(kind.target() >= 0x400_000);
        }
    }

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
        assert_eq!(offset_of!(ProjectileRuntimeView, base_form), 0x20);
        assert_eq!(offset_of!(ProjectileRuntimeView, rotation_x), 0x24);
        assert_eq!(offset_of!(ProjectileRuntimeView, rotation_y), 0x28);
        assert_eq!(offset_of!(ProjectileRuntimeView, rotation_z), 0x2C);
        assert_eq!(offset_of!(ProjectileRuntimeView, position), 0x30);
        assert_eq!(offset_of!(ProjectileRuntimeView, parent_cell), 0x40);
        assert_eq!(offset_of!(ProjectileRuntimeView, impact_list), 0x88);
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
        assert_eq!(offset_of!(ProjectileRuntimeView, flight_target), 0x140);
        assert_eq!(offset_of!(ProjectileRuntimeView, rock_it_entry), 0x144);
        assert_eq!(offset_of!(ProjectileRuntimeView, impact_result), 0x150);
    }

    #[test]
    fn audited_impact_and_raycast_layouts_match_native_traversal() {
        assert_eq!(size_of::<ImpactListNode>(), 0x08);
        assert_eq!(offset_of!(ImpactListNode, data), 0x00);
        assert_eq!(offset_of!(ImpactListNode, next), 0x04);
        assert_eq!(size_of::<ImpactDataView>(), 0x30);
        assert_eq!(offset_of!(ImpactDataView, target), 0x00);
        assert_eq!(offset_of!(ImpactDataView, point), 0x04);
        assert_eq!(offset_of!(ImpactDataView, normal), 0x10);
        assert_eq!(offset_of!(ImpactDataView, rigid_body), 0x1C);
        assert_eq!(offset_of!(ImpactDataView, raw_material), 0x20);
        assert_eq!(offset_of!(ImpactDataView, hit_location), 0x24);
        assert_eq!(offset_of!(ImpactDataView, marker), 0x28);
        assert_eq!(offset_of!(ImpactDataView, ready), 0x29);
        assert_eq!(size_of::<RayCastData>(), 0xB0);
        assert_eq!(offset_of!(RayCastData, position_start), 0x00);
        assert_eq!(offset_of!(RayCastData, position_end), 0x10);
        assert_eq!(offset_of!(RayCastData, layer_type), 0x24);
        assert_eq!(offset_of!(RayCastData, group), 0x26);
        assert_eq!(offset_of!(RayCastData, fraction), 0x40);
        assert_eq!(offset_of!(RayCastData, collision_body), 0x80);
        assert_eq!(offset_of!(RayCastData, hit_normal), 0x90);
        assert_eq!(offset_of!(RayCastData, byte_ac), 0xAC);
    }

    #[test]
    fn loaded_grid_coordinates_and_index_stay_inside_the_runtime_array() {
        assert_eq!(world_cell_coordinate(0.0), Some(0));
        assert_eq!(world_cell_coordinate(4095.9), Some(0));
        assert_eq!(world_cell_coordinate(4096.0), Some(1));
        assert_eq!(world_cell_coordinate(-1.0), Some(-1));
        assert_eq!(world_cell_coordinate(f32::NAN), None);

        assert_eq!(loaded_grid_index(5, 10, 20, 10, 20), Some(12));
        assert_eq!(loaded_grid_index(5, 10, 20, 8, 18), Some(0));
        assert_eq!(loaded_grid_index(5, 10, 20, 12, 22), Some(24));
        assert_eq!(loaded_grid_index(5, 10, 20, 13, 20), None);
        assert_eq!(loaded_grid_index(7, 10, 20, 13, 23), Some(48));
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
