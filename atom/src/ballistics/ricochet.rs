//! Deterministic, engine-independent ricochet contact classification.
//!
//! This module owns only the proven FNV material map, finite incidence
//! geometry, and value-only energy attenuation needed by Ballistics. It also
//! derives the finite segment used by the native clearance query and
//! child-projectile launch. It never reads engine memory, retains a native
//! pointer, performs a collision query, or mutates projectile state. Unknown
//! material and invalid geometry fail closed so callers retain native terminal
//! behavior.

use super::RicochetEnergyConfig;

/// Number of canonical material slots in a live `BGSImpactDataSet`.
pub(super) const CANONICAL_MATERIAL_COUNT: usize = 10;

/// Number of hard-material classes admitted to diagnostics.
pub(super) const HARD_MATERIAL_COUNT: usize = 3;

const RAW_MATERIAL_MAP: [u8; 32] = [
    0, 7, 1, 3, 2, 4, 6, 6, 8, 5, 0, 4, 5, 4, 4, 4, 9, 9, 1, 0, 4, 4, 9, 9, 3, 9, 4, 4, 9, 9, 5, 5,
];

/// Distance moved behind the completed contact before testing the new path.
pub(crate) const RICOCHET_BACKTRACK_UNITS: f32 = 2.0;

/// Clear distance required before a child projectile may be launched.
pub(crate) const RICOCHET_SPAWN_CLEARANCE_UNITS: f32 = 32.0;

/// Native ray length used to prove the outbound segment is loaded and clear.
pub(crate) const RICOCHET_TRACE_UNITS: f32 = 1024.0;

/// Comparison-implementation default below which a child is not continued.
pub(crate) const MIN_RICOCHET_EFFECTIVE_SPEED: f32 = 6400.0;

/// Comparison-implementation default below which a child is not continued.
pub(crate) const MIN_RICOCHET_DAMAGE: f32 = 6.0;

/// FNV's canonical impact-data material slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum CanonicalMaterial {
    Stone = 0,
    Dirt = 1,
    Grass = 2,
    Glass = 3,
    Metal = 4,
    Wood = 5,
    Organic = 6,
    Cloth = 7,
    Water = 8,
    HollowMetal = 9,
}

/// Hard surface admitted to ricochet diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum HardMaterial {
    Stone = 0,
    Metal = 1,
    HollowMetal = 2,
}

#[derive(Clone, Copy)]
struct MaterialPolicy {
    attenuation_saturation_degrees: f32,
    minimum_speed_ratio: f32,
}

impl CanonicalMaterial {
    const fn policy(self) -> MaterialPolicy {
        match self {
            CanonicalMaterial::Metal => MaterialPolicy {
                attenuation_saturation_degrees: 20.0,
                minimum_speed_ratio: 0.55 / 0.75,
            },
            CanonicalMaterial::HollowMetal => MaterialPolicy {
                attenuation_saturation_degrees: 18.0,
                minimum_speed_ratio: 0.50 / 0.68,
            },
            CanonicalMaterial::Stone
            | CanonicalMaterial::Dirt
            | CanonicalMaterial::Grass
            | CanonicalMaterial::Glass
            | CanonicalMaterial::Wood
            | CanonicalMaterial::Organic
            | CanonicalMaterial::Cloth
            | CanonicalMaterial::Water => MaterialPolicy {
                attenuation_saturation_degrees: 12.0,
                minimum_speed_ratio: 0.45 / 0.60,
            },
        }
    }
}

/// Finite incidence result measured from the contacted surface plane.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Incidence {
    grazing_degrees: f32,
    oriented_normal: [f32; 3],
}

impl Incidence {
    /// Return zero for tangent travel and 90 for a head-on contact.
    pub(super) const fn grazing_degrees(self) -> f32 {
        self.grazing_degrees
    }

    pub(super) const fn oriented_normal(self) -> [f32; 3] {
        self.oriented_normal
    }
}

/// Why incidence geometry could not be classified safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GeometryError {
    NonFinite,
    Degenerate,
}

/// Why a hard contact retained native terminal behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseError {
    UnsupportedMaterial,
    MaterialDisabled,
    InvalidGeometry,
    InvalidEnergy,
}

/// Energy floor crossed by the next reflected child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnergyDepletion {
    Speed,
    Damage,
    SpeedAndDamage,
}

/// Live and predicted value-only energy state for one continuation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ContinuationEnergy {
    current_effective_speed: f32,
    current_damage: f32,
    next_effective_speed: f32,
    next_damage: f32,
}

/// Complete value-only response for one admitted hard-surface contact.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct RicochetPlan {
    material: CanonicalMaterial,
    grazing_degrees: f32,
    reflected_vector: [f32; 3],
    oriented_normal: [f32; 3],
    launch_rotation: [f32; 2],
    speed_retention: f32,
    damage_retention: f32,
    energy: ContinuationEnergy,
}

/// Finite world-space segment used to validate and launch one ricochet child.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ChildSpawnPath {
    ray_start: [f32; 3],
    ray_end: [f32; 3],
    spawn_origin: [f32; 3],
}

impl ChildSpawnPath {
    pub(crate) const fn ray_start(self) -> [f32; 3] {
        self.ray_start
    }

    pub(crate) const fn ray_end(self) -> [f32; 3] {
        self.ray_end
    }

    pub(crate) const fn spawn_origin(self) -> [f32; 3] {
        self.spawn_origin
    }
}

impl RicochetPlan {
    pub(super) const fn material(self) -> CanonicalMaterial {
        self.material
    }

    pub(crate) const fn grazing_degrees(self) -> f32 {
        self.grazing_degrees
    }

    /// Return the reflected cached direction with its incoming magnitude.
    pub(crate) const fn reflected_vector(self) -> [f32; 3] {
        self.reflected_vector
    }

    /// Return the unit contact normal oriented against incoming travel.
    pub(crate) const fn oriented_normal(self) -> [f32; 3] {
        self.oriented_normal
    }

    /// Return FNV's native launch yaw and pitch for the reflected direction.
    pub(crate) const fn launch_rotation(self) -> [f32; 2] {
        self.launch_rotation
    }

    /// Return the multiplier for the projectile's live speed multiplier.
    pub(crate) const fn speed_retention(self) -> f32 {
        self.speed_retention
    }

    /// Return the multiplier for the projectile's live damage.
    pub(crate) const fn damage_retention(self) -> f32 {
        self.damage_retention
    }

    pub(crate) const fn energy(self) -> ContinuationEnergy {
        self.energy
    }
}

impl ContinuationEnergy {
    pub(crate) const fn current_effective_speed(self) -> f32 {
        self.current_effective_speed
    }

    pub(crate) const fn current_damage(self) -> f32 {
        self.current_damage
    }

    pub(crate) const fn next_effective_speed(self) -> f32 {
        self.next_effective_speed
    }

    pub(crate) const fn next_damage(self) -> f32 {
        self.next_damage
    }

    /// Return why the predicted child cannot retain a gameplay ricochet.
    pub(crate) fn depletion(self) -> Option<EnergyDepletion> {
        let speed = self.next_effective_speed < MIN_RICOCHET_EFFECTIVE_SPEED;
        let damage = self.next_damage < MIN_RICOCHET_DAMAGE;
        match (speed, damage) {
            (false, false) => None,
            (true, false) => Some(EnergyDepletion::Speed),
            (false, true) => Some(EnergyDepletion::Damage),
            (true, true) => Some(EnergyDepletion::SpeedAndDamage),
        }
    }
}

/// Generation-owned parent contact retained for child follow-up telemetry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ContactSignature {
    pub(crate) target_token: u32,
    pub(crate) point: [f32; 3],
    pub(crate) oriented_normal: [f32; 3],
    pub(crate) raw_material: u32,
    pub(crate) distance_travelled: f32,
}

/// Live values from a later contact of a published ricochet child.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FollowupSample {
    pub(crate) target_token: u32,
    pub(crate) point: [f32; 3],
    pub(crate) raw_material: u32,
    pub(crate) distance_travelled: f32,
    pub(crate) direction: [f32; 3],
}

/// Value-only evidence describing the first contact after a continuation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FollowupContact {
    pub(crate) same_target: bool,
    pub(crate) same_material: bool,
    pub(crate) distance_progress: Option<f32>,
    pub(crate) point_separation: Option<f32>,
    pub(crate) outward_dot: Option<f32>,
}

impl FollowupContact {
    /// Return whether native movement proves that this child left its prior surface.
    pub(crate) fn proves_outward_progress(self) -> bool {
        self.outward_dot.is_some_and(|value| value > f32::EPSILON)
            && self
                .distance_progress
                .is_some_and(|value| value > f32::EPSILON)
            && self
                .point_separation
                .is_some_and(|value| value > f32::EPSILON)
    }
}

/// Result of the first native movement update after Atom publishes a bounce.
///
/// The cached Projectile direction is the executable-proven completed-step
/// displacement at `+0x104`. Position displacement is retained independently
/// so runtime evidence can expose disagreement between the two native views.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FirstStepEvidence {
    pub(crate) outcome: FirstStepOutcome,
    pub(crate) expected_error_degrees: Option<f32>,
    pub(crate) position_error_degrees: Option<f32>,
}

/// Behavior-neutral classification of one observed post-bounce native step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstStepOutcome {
    Outward,
    NonOutward,
    Stationary,
    Invalid,
}

impl ContactSignature {
    /// Compare a later contact with the continued contact without changing policy.
    pub(crate) fn followup_contact(self, sample: FollowupSample) -> FollowupContact {
        let distance_progress = (sample.distance_travelled - self.distance_travelled)
            .is_finite()
            .then_some(sample.distance_travelled - self.distance_travelled);
        let point_separation = finite_length(subtract(sample.point, self.point));
        let outward_dot = normalize(sample.direction)
            .ok()
            .map(|direction| dot(direction, self.oriented_normal))
            .filter(|value| value.is_finite());
        FollowupContact {
            same_target: self.target_token == sample.target_token,
            same_material: self.raw_material == sample.raw_material,
            distance_progress,
            point_separation,
            outward_dot,
        }
    }
}

/// Reconstruct FNV's local-`+Y` forward vector from reference yaw and pitch.
///
/// The convention is proven by `0x00A59400`, `0x009C6330`, and the ordinary
/// Missile movement path recorded in the executable contract.
pub(crate) fn direction_from_rotation(rotation: [f32; 2]) -> Option<[f32; 3]> {
    let [yaw, pitch] = rotation;
    if !yaw.is_finite() || !pitch.is_finite() {
        return None;
    }
    let pitch_cosine = pitch.cos();
    normalize([
        yaw.sin() * pitch_cosine,
        yaw.cos() * pitch_cosine,
        -pitch.sin(),
    ])
    .ok()
}

/// Return the finite angular error between two directions in degrees.
pub(crate) fn direction_error_degrees(expected: [f32; 3], actual: [f32; 3]) -> Option<f32> {
    let expected = normalize(expected).ok()?;
    let actual = normalize(actual).ok()?;
    let cross = cross(expected, actual);
    let sine = dot(cross, cross).sqrt();
    let cosine = dot(expected, actual).clamp(-1.0, 1.0);
    let error = sine.atan2(cosine).to_degrees();
    error.is_finite().then_some(error)
}

/// Classify the actual first native movement after a published reflection.
pub(crate) fn first_step_evidence(
    expected: [f32; 3],
    oriented_normal: [f32; 3],
    pre_position: [f32; 3],
    post_position: [f32; 3],
    completed_step: [f32; 3],
) -> FirstStepEvidence {
    let position_delta = subtract(post_position, pre_position);
    let expected_error_degrees = direction_error_degrees(expected, completed_step);
    let position_error_degrees = direction_error_degrees(expected, position_delta);
    let completed_step = normalize(completed_step);
    let normal = normalize(oriented_normal);
    let outcome = match (completed_step, normal) {
        (Ok(completed_step), Ok(normal)) => {
            let outward_dot = dot(completed_step, normal);
            if outward_dot > f32::EPSILON {
                FirstStepOutcome::Outward
            } else {
                FirstStepOutcome::NonOutward
            }
        }
        (Err(GeometryError::Degenerate), _) => FirstStepOutcome::Stationary,
        _ => FirstStepOutcome::Invalid,
    };
    FirstStepEvidence {
        outcome,
        expected_error_degrees,
        position_error_degrees,
    }
}

/// Map a raw Havok material to the canonical live impact-data slot.
///
/// FNV visually defaults values above 31 to metal. Gameplay policy must not
/// inherit that fallback because an unknown material is not evidence of a
/// hard surface.
pub(super) fn canonical_material(raw_material: u32) -> Option<CanonicalMaterial> {
    let slot = *RAW_MATERIAL_MAP.get(raw_material as usize)?;
    Some(match slot {
        0 => CanonicalMaterial::Stone,
        1 => CanonicalMaterial::Dirt,
        2 => CanonicalMaterial::Grass,
        3 => CanonicalMaterial::Glass,
        4 => CanonicalMaterial::Metal,
        5 => CanonicalMaterial::Wood,
        6 => CanonicalMaterial::Organic,
        7 => CanonicalMaterial::Cloth,
        8 => CanonicalMaterial::Water,
        9 => CanonicalMaterial::HollowMetal,
        _ => return None,
    })
}

/// Convert a canonical material to a hard diagnostic class.
pub(super) const fn hard_material(material: CanonicalMaterial) -> Option<HardMaterial> {
    match material {
        CanonicalMaterial::Stone => Some(HardMaterial::Stone),
        CanonicalMaterial::Metal => Some(HardMaterial::Metal),
        CanonicalMaterial::HollowMetal => Some(HardMaterial::HollowMetal),
        _ => None,
    }
}

/// Evaluate finite incidence using the actual incoming vector and contact normal.
///
/// Normal orientation is corrected before measuring the angle so equivalent
/// collision-provider conventions produce the same result.
pub(super) fn incidence(incoming: [f32; 3], normal: [f32; 3]) -> Result<Incidence, GeometryError> {
    let incoming = normalize(incoming)?;
    let mut normal = normalize(normal)?;
    if dot(incoming, normal) > 0.0 {
        normal = [-normal[0], -normal[1], -normal[2]];
    }
    let normal_cosine = (-dot(incoming, normal)).clamp(0.0, 1.0);
    if !normal_cosine.is_finite() {
        return Err(GeometryError::NonFinite);
    }
    let grazing_degrees = normal_cosine.asin().to_degrees();
    if !grazing_degrees.is_finite() {
        return Err(GeometryError::NonFinite);
    }
    Ok(Incidence {
        grazing_degrees,
        oriented_normal: normal,
    })
}

/// Build the deterministic continuation response for one known live contact.
pub(crate) fn response(
    raw_material: u32,
    configured_energy: RicochetEnergyConfig,
    incoming: [f32; 3],
    normal: [f32; 3],
    effective_speed: f32,
    speed_multiplier: f32,
    damage: f32,
) -> Result<RicochetPlan, ResponseError> {
    let material = canonical_material(raw_material).ok_or(ResponseError::UnsupportedMaterial)?;
    let grazing_energy = f32::from(configured_energy.percentages()[material as usize]) * 0.01;
    if grazing_energy == 0.0 {
        return Err(ResponseError::MaterialDisabled);
    }
    if !effective_speed.is_finite()
        || effective_speed <= 0.0
        || !speed_multiplier.is_finite()
        || speed_multiplier <= 0.0
        || !damage.is_finite()
        || damage <= 0.0
    {
        return Err(ResponseError::InvalidEnergy);
    }

    let incoming_magnitude = magnitude(incoming).map_err(|_| ResponseError::InvalidGeometry)?;
    let incoming_unit = scale(incoming, incoming_magnitude.recip());
    let incidence = incidence(incoming, normal).map_err(|_| ResponseError::InvalidGeometry)?;
    let policy = material.policy();
    // The setting controls grazing energy. Scaling the accepted minimum/max
    // speed ratio preserves each material's angle response while ensuring the
    // squared speed multiplier remains the configured damage/energy proxy.
    let maximum_speed_retention = grazing_energy.sqrt();
    let minimum_speed_retention = maximum_speed_retention * policy.minimum_speed_ratio;

    let reflected_unit = normalize(subtract(
        incoming_unit,
        scale(
            incidence.oriented_normal(),
            2.0 * dot(incoming_unit, incidence.oriented_normal()),
        ),
    ))
    .map_err(|_| ResponseError::InvalidGeometry)?;
    let launch_rotation =
        rotation_from_direction(reflected_unit).ok_or(ResponseError::InvalidGeometry)?;
    let depth =
        (incidence.grazing_degrees() / policy.attenuation_saturation_degrees).clamp(0.0, 1.0);
    let speed_retention =
        maximum_speed_retention + (minimum_speed_retention - maximum_speed_retention) * depth;
    let damage_retention = speed_retention * speed_retention;
    let reflected_vector = scale(reflected_unit, incoming_magnitude);
    let next_speed_multiplier = speed_multiplier * speed_retention;
    let next_effective_speed = effective_speed * speed_retention;
    let next_damage = damage * damage_retention;
    if !reflected_vector.into_iter().all(f32::is_finite)
        || !speed_retention.is_finite()
        || !damage_retention.is_finite()
        || !next_speed_multiplier.is_finite()
        || next_speed_multiplier <= 0.0
        || !next_effective_speed.is_finite()
        || next_effective_speed <= 0.0
        || !next_damage.is_finite()
        || next_damage <= 0.0
    {
        return Err(ResponseError::InvalidEnergy);
    }

    Ok(RicochetPlan {
        material,
        grazing_degrees: incidence.grazing_degrees(),
        reflected_vector,
        oriented_normal: incidence.oriented_normal(),
        launch_rotation,
        speed_retention,
        damage_retention,
        energy: ContinuationEnergy {
            current_effective_speed: effective_speed,
            current_damage: damage,
            next_effective_speed,
            next_damage,
        },
    })
}

/// Derive the comparison-mod-proven backtracked ray and clear child origin.
pub(crate) fn child_spawn_path(
    contact_position: [f32; 3],
    incoming: [f32; 3],
    reflected: [f32; 3],
) -> Result<ChildSpawnPath, GeometryError> {
    if !contact_position.into_iter().all(f32::is_finite) {
        return Err(GeometryError::NonFinite);
    }
    let incoming = normalize(incoming)?;
    let reflected = normalize(reflected)?;
    let ray_start = subtract(contact_position, scale(incoming, RICOCHET_BACKTRACK_UNITS));
    let ray_end = add(ray_start, scale(reflected, RICOCHET_TRACE_UNITS));
    let spawn_origin = add(ray_start, scale(reflected, RICOCHET_SPAWN_CLEARANCE_UNITS));
    if ray_start
        .into_iter()
        .chain(ray_end)
        .chain(spawn_origin)
        .all(f32::is_finite)
    {
        Ok(ChildSpawnPath {
            ray_start,
            ray_end,
            spawn_origin,
        })
    } else {
        Err(GeometryError::NonFinite)
    }
}

fn normalize(value: [f32; 3]) -> Result<[f32; 3], GeometryError> {
    if !value.into_iter().all(f32::is_finite) {
        return Err(GeometryError::NonFinite);
    }
    let magnitude_squared = dot(value, value);
    if !magnitude_squared.is_finite() {
        return Err(GeometryError::NonFinite);
    }
    if magnitude_squared <= f32::EPSILON {
        return Err(GeometryError::Degenerate);
    }
    let inverse = magnitude_squared.sqrt().recip();
    let normalized = [value[0] * inverse, value[1] * inverse, value[2] * inverse];
    if normalized.into_iter().all(f32::is_finite) {
        Ok(normalized)
    } else {
        Err(GeometryError::NonFinite)
    }
}

fn magnitude(value: [f32; 3]) -> Result<f32, GeometryError> {
    if !value.into_iter().all(f32::is_finite) {
        return Err(GeometryError::NonFinite);
    }
    let magnitude_squared = dot(value, value);
    if !magnitude_squared.is_finite() {
        return Err(GeometryError::NonFinite);
    }
    if magnitude_squared <= f32::EPSILON {
        return Err(GeometryError::Degenerate);
    }
    let magnitude = magnitude_squared.sqrt();
    if magnitude.is_finite() {
        Ok(magnitude)
    } else {
        Err(GeometryError::NonFinite)
    }
}

fn finite_length(value: [f32; 3]) -> Option<f32> {
    if !value.into_iter().all(f32::is_finite) {
        return None;
    }
    let squared = dot(value, value);
    let length = squared.sqrt();
    (squared.is_finite() && length.is_finite()).then_some(length)
}

fn rotation_from_direction(direction: [f32; 3]) -> Option<[f32; 2]> {
    let direction = normalize(direction).ok()?;
    let yaw = direction[0].atan2(direction[1]);
    let pitch = (-direction[2]).clamp(-1.0, 1.0).asin();
    (yaw.is_finite() && pitch.is_finite()).then_some([yaw, pitch])
}

fn cross(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    [
        left[1] * right[2] - left[2] * right[1],
        left[2] * right[0] - left[0] * right[2],
        left[0] * right[1] - left[1] * right[0],
    ]
}

fn subtract(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    [left[0] - right[0], left[1] - right[1], left[2] - right[2]]
}

fn add(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    [left[0] + right[0], left[1] + right[1], left[2] + right[2]]
}

fn scale(value: [f32; 3], factor: f32) -> [f32; 3] {
    [value[0] * factor, value[1] * factor, value[2] * factor]
}

fn dot(left: [f32; 3], right: [f32; 3]) -> f32 {
    left.into_iter().zip(right).map(|(a, b)| a * b).sum()
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalMaterial, EnergyDepletion, FirstStepOutcome, ResponseError, RicochetPlan,
        canonical_material, child_spawn_path, direction_error_degrees, direction_from_rotation,
        first_step_evidence, response as configured_response,
    };
    use crate::ballistics::RicochetEnergyConfig;

    fn response(
        raw_material: u32,
        incoming: [f32; 3],
        normal: [f32; 3],
        effective_speed: f32,
        speed_multiplier: f32,
        damage: f32,
    ) -> Result<RicochetPlan, ResponseError> {
        configured_response(
            raw_material,
            RicochetEnergyConfig::default(),
            incoming,
            normal,
            effective_speed,
            speed_multiplier,
            damage,
        )
    }

    #[test]
    fn material_map_and_unknown_fallback_follow_the_native_contract() {
        let expected = [
            0_u8, 7, 1, 3, 2, 4, 6, 6, 8, 5, 0, 4, 5, 4, 4, 4, 9, 9, 1, 0, 4, 4, 9, 9, 3, 9, 4, 4,
            9, 9, 5, 5,
        ];
        for (raw, expected) in expected.into_iter().enumerate() {
            assert_eq!(canonical_material(raw as u32).unwrap() as u8, expected);
        }
        assert_eq!(canonical_material(32), None);
        assert_eq!(canonical_material(u32::MAX), None);
        assert_eq!(canonical_material(4), Some(CanonicalMaterial::Grass));
    }

    #[test]
    fn admitted_metal_contact_reflects_local_y_and_attenuates_live_values() {
        let plan = response(5, [1.0, -0.1, 0.0], [0.0, 1.0, 0.0], 1000.0, 1.0, 50.0).unwrap();
        let reflected = plan.reflected_vector();
        assert!(reflected[0] > 0.0 && reflected[1] > 0.0);
        let rotation = plan.launch_rotation();
        assert!(
            direction_error_degrees(reflected, direction_from_rotation(rotation).unwrap()).unwrap()
                < 0.001
        );
        assert!((0.55..=0.75).contains(&plan.speed_retention()));
        assert!(
            (plan.damage_retention() - plan.speed_retention() * plan.speed_retention()).abs()
                < 0.000_001
        );
    }

    #[test]
    fn native_rotation_round_trip_preserves_the_reflected_direction() {
        let plan = response(5, [1.0, -0.1, 0.2], [0.0, 1.0, 0.0], 1000.0, 1.0, 50.0).unwrap();
        let direction = plan.reflected_vector();
        let reconstructed = direction_from_rotation(plan.launch_rotation()).unwrap();
        assert!(direction_error_degrees(direction, reconstructed).unwrap() < 0.001);
    }

    #[test]
    fn child_spawn_path_clears_the_completed_contact_before_native_launch() {
        let position = [10.0, 20.0, 30.0];
        let incoming = [1.0, -0.1, 0.0];
        let reflected = response(5, incoming, [0.0, 1.0, 0.0], 1000.0, 1.0, 50.0)
            .unwrap()
            .reflected_vector();
        let path = child_spawn_path(position, incoming, reflected).unwrap();

        let incoming_offset = [
            path.ray_start()[0] - position[0],
            path.ray_start()[1] - position[1],
            path.ray_start()[2] - position[2],
        ];
        let outbound_offset = [
            path.spawn_origin()[0] - path.ray_start()[0],
            path.spawn_origin()[1] - path.ray_start()[1],
            path.spawn_origin()[2] - path.ray_start()[2],
        ];
        let trace_offset = [
            path.ray_end()[0] - path.ray_start()[0],
            path.ray_end()[1] - path.ray_start()[1],
            path.ray_end()[2] - path.ray_start()[2],
        ];

        assert!((super::finite_length(incoming_offset).unwrap() - 2.0).abs() < 0.001);
        assert!(super::dot(incoming_offset, incoming) < 0.0);
        assert!((super::finite_length(outbound_offset).unwrap() - 32.0).abs() < 0.001);
        assert!(super::dot(outbound_offset, reflected) > 0.0);
        assert!((super::finite_length(trace_offset).unwrap() - 1024.0).abs() < 0.01);
    }

    #[test]
    fn first_step_evidence_distinguishes_outward_and_unreflected_travel() {
        let outward = first_step_evidence(
            [1.0, 0.1, 0.0],
            [0.0, 1.0, 0.0],
            [0.0; 3],
            [1.0, 0.1, 0.0],
            [1.0, 0.1, 0.0],
        );
        assert_eq!(outward.outcome, FirstStepOutcome::Outward);
        assert!(outward.expected_error_degrees.unwrap() < 0.001);

        let unreflected = first_step_evidence(
            [1.0, 0.1, 0.0],
            [0.0, 1.0, 0.0],
            [0.0; 3],
            [1.0, -0.1, 0.0],
            [1.0, -0.1, 0.0],
        );
        assert_eq!(unreflected.outcome, FirstStepOutcome::NonOutward);
        assert!(unreflected.expected_error_degrees.unwrap() > 10.0);
    }

    #[test]
    fn every_known_material_covers_the_full_finite_angle_range() {
        let energy = RicochetEnergyConfig::from_percentages([75; 10]);
        for raw in 0..32 {
            for expected_grazing_degrees in [0.0_f32, 12.0, 45.0, 89.999, 90.0] {
                let radians = expected_grazing_degrees.to_radians();
                let plan = configured_response(
                    raw,
                    energy,
                    [radians.cos(), -radians.sin(), 0.0],
                    [0.0, 1.0, 0.0],
                    20_000.0,
                    1.0,
                    50.0,
                )
                .unwrap();
                assert!(
                    (plan.grazing_degrees() - expected_grazing_degrees).abs() < 0.001,
                    "raw material {raw} measured {} instead of {expected_grazing_degrees}",
                    plan.grazing_degrees(),
                );
                assert!((0.0..=0.75_f32.sqrt()).contains(&plan.speed_retention()));
                assert!((0.0..=0.75).contains(&plan.damage_retention()));
            }
        }

        let stone_limit = 12.0_f32.to_radians();
        let at_limit = [stone_limit.cos(), -stone_limit.sin(), 0.0];
        assert!(response(0, at_limit, [0.0, 1.0, 0.0], 1.0, 1.0, 1.0).is_ok());
        let outside = 12.01_f32.to_radians();
        assert!(
            response(
                0,
                [outside.cos(), -outside.sin(), 0.0],
                [0.0, 1.0, 0.0],
                1.0,
                1.0,
                1.0,
            )
            .is_ok()
        );
        assert_eq!(
            configured_response(32, energy, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], 1.0, 1.0, 1.0,),
            Err(ResponseError::UnsupportedMaterial)
        );
        assert_eq!(
            response(5, [0.0; 3], [0.0, 1.0, 0.0], 1.0, 1.0, 1.0),
            Err(ResponseError::InvalidGeometry)
        );
        assert_eq!(
            response(5, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], 0.0, 1.0, 1.0),
            Err(ResponseError::InvalidEnergy)
        );
        assert_eq!(
            response(1, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], 1.0, 1.0, 1.0),
            Err(ResponseError::MaterialDisabled)
        );
    }

    #[test]
    fn configured_percentages_follow_canonical_material_slots() {
        let energy = RicochetEnergyConfig::from_percentages([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let representatives = [0_u32, 2, 4, 3, 5, 9, 6, 1, 8, 16];

        for (slot, raw_material) in representatives.into_iter().enumerate() {
            let plan = configured_response(
                raw_material,
                energy,
                [1.0, 0.0, 0.0],
                [0.0, 1.0, 0.0],
                20_000.0,
                1.0,
                50.0,
            )
            .unwrap();
            let expected_energy = (slot + 1) as f32 * 0.01;
            assert!((plan.damage_retention() - expected_energy).abs() < 0.000_001);
        }
    }

    #[test]
    fn default_non_hard_materials_do_not_share_one_energy_fallback() {
        let dirt = response(2, [1.0, -0.1, 0.0], [0.0, 1.0, 0.0], 20_000.0, 1.0, 50.0).unwrap();
        let wood = response(9, [1.0, -0.1, 0.0], [0.0, 1.0, 0.0], 20_000.0, 1.0, 50.0).unwrap();

        assert_ne!(dirt.damage_retention(), wood.damage_retention());
    }

    #[test]
    fn configured_percentage_controls_grazing_energy_and_angle_loss() {
        let energy = RicochetEnergyConfig::from_percentages([75; 10]);
        let grazing = configured_response(
            5,
            energy,
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            20_000.0,
            1.0,
            50.0,
        )
        .unwrap();
        let head_on = configured_response(
            5,
            energy,
            [0.0, -1.0, 0.0],
            [0.0, 1.0, 0.0],
            20_000.0,
            1.0,
            50.0,
        )
        .unwrap();

        assert!((grazing.damage_retention() - 0.75).abs() < 0.000_001);
        assert!((grazing.speed_retention() - 0.75_f32.sqrt()).abs() < 0.000_001);
        assert!(head_on.damage_retention() < grazing.damage_retention());
    }

    #[test]
    fn predicted_child_energy_controls_continuation_without_a_bounce_cap() {
        let favorable = response(5, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], 20_000.0, 1.0, 50.0).unwrap();
        assert_eq!(favorable.energy().depletion(), None);
        assert!((favorable.energy().next_effective_speed() - 14_966.63).abs() < 0.01);
        assert!((favorable.energy().next_damage() - 28.0).abs() < 0.001);

        let speed_depleted =
            response(5, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], 8_000.0, 1.0, 50.0).unwrap();
        assert_eq!(
            speed_depleted.energy().depletion(),
            Some(EnergyDepletion::Speed)
        );

        let damage_depleted =
            response(5, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], 20_000.0, 1.0, 10.0).unwrap();
        assert_eq!(
            damage_depleted.energy().depletion(),
            Some(EnergyDepletion::Damage)
        );

        let both = response(5, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], 8_000.0, 1.0, 10.0).unwrap();
        assert_eq!(
            both.energy().depletion(),
            Some(EnergyDepletion::SpeedAndDamage)
        );
    }

    #[test]
    fn stronger_live_rounds_produce_longer_energy_depleting_chains() {
        fn chain_depth(mut speed: f32, mut damage: f32) -> u32 {
            let mut depth = 0;
            loop {
                let plan =
                    response(5, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0], speed, 1.0, damage).unwrap();
                if plan.energy().depletion().is_some() {
                    return depth;
                }
                depth += 1;
                speed = plan.energy().next_effective_speed();
                damage = plan.energy().next_damage();
            }
        }

        assert_eq!(chain_depth(100_000.0, 20.0), 2);
        assert_eq!(chain_depth(100_000.0, 50.0), 3);
        assert_eq!(chain_depth(100_000.0, 100.0), 4);
    }

    #[test]
    fn maximum_configured_energy_still_reaches_a_terminal_floor() {
        let energy = RicochetEnergyConfig::from_percentages([75; 10]);
        let mut speed = 100_000.0;
        let mut damage = 1_000.0;
        for depth in 0..128 {
            let plan = configured_response(
                5,
                energy,
                [1.0, 0.0, 0.0],
                [0.0, 1.0, 0.0],
                speed,
                1.0,
                damage,
            )
            .unwrap();
            if plan.energy().depletion().is_some() {
                assert!(depth > 0);
                return;
            }
            speed = plan.energy().next_effective_speed();
            damage = plan.energy().next_damage();
        }
        panic!("bounded retained energy must reach a terminal floor");
    }
}
