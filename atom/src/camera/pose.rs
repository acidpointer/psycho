//! Camera-local additive pose math.
//!
//! FNV stores `NiMatrix33` in row-major memory, while its local forward, up,
//! and right axes are matrix columns 0, 1, and 2. Poses in this module use
//! that native basis directly: translation is `[forward, up, right]` and
//! rotation is `[roll_about_forward, yaw_about_up, pitch_about_right]`.

/// Zero-centered translation and rotation applied to a native camera basis.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CameraPose {
    translation: [f32; 3],
    rotation: [f32; 3],
}

impl CameraPose {
    /// An exact identity pose which causes no native camera write.
    pub const IDENTITY: Self = Self {
        translation: [0.0; 3],
        rotation: [0.0; 3],
    };

    /// Construct a camera-local pose.
    ///
    /// Translation is `[forward, up, right]` in game units. Rotation is
    /// `[roll, yaw, pitch]` in radians around those respective local axes.
    pub const fn new(translation: [f32; 3], rotation: [f32; 3]) -> Self {
        Self {
            translation,
            rotation,
        }
    }

    /// Return camera-local `[forward, up, right]` translation in game units.
    pub const fn translation(self) -> [f32; 3] {
        self.translation
    }

    /// Return local `[roll, yaw, pitch]` rotation in radians.
    pub const fn rotation(self) -> [f32; 3] {
        self.rotation
    }

    /// Return whether this pose is exactly the native identity.
    pub fn is_identity(self) -> bool {
        self.translation.into_iter().all(|value| value == 0.0)
            && self.rotation.into_iter().all(|value| value == 0.0)
    }

    pub(super) fn finite(self) -> bool {
        self.translation
            .into_iter()
            .chain(self.rotation)
            .all(f32::is_finite)
    }
}

/// A native world-space camera transform.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CameraTransform {
    /// Native row-major rotation whose columns are forward, up, and right.
    pub rotation: [[f32; 3]; 3],
    /// Native absolute world translation.
    pub translation: [f32; 3],
}

impl CameraTransform {
    /// Construct a transform from the exact native fields.
    pub const fn new(rotation: [[f32; 3]; 3], translation: [f32; 3]) -> Self {
        Self {
            rotation,
            translation,
        }
    }

    /// Return whether every component is finite.
    pub fn is_finite(self) -> bool {
        self.rotation
            .into_iter()
            .flatten()
            .chain(self.translation)
            .all(f32::is_finite)
    }
}

/// Compose one additive local pose onto a native world transform.
///
/// This follows the engine's column-basis convention. The base is never
/// reconstructed from Euler angles, so externally supplied camera roll and
/// iron-sight smoothing remain intact. `None` is returned before any native
/// write when either input contains a non-finite component.
pub fn compose_transform(base: CameraTransform, pose: CameraPose) -> Option<CameraTransform> {
    if !base.is_finite() || !pose.finite() {
        return None;
    }

    let [forward, up, right] = pose.translation;
    let mut translation = base.translation;
    for (axis, value) in translation.iter_mut().enumerate() {
        *value += base.rotation[axis][0] * forward
            + base.rotation[axis][1] * up
            + base.rotation[axis][2] * right;
    }

    let [roll, yaw, pitch] = pose.rotation;
    let (sin_roll, cos_roll) = roll.sin_cos();
    let (sin_yaw, cos_yaw) = yaw.sin_cos();
    let (sin_pitch, cos_pitch) = pitch.sin_cos();
    let roll_matrix = [
        [1.0, 0.0, 0.0],
        [0.0, cos_roll, -sin_roll],
        [0.0, sin_roll, cos_roll],
    ];
    let yaw_matrix = [
        [cos_yaw, 0.0, sin_yaw],
        [0.0, 1.0, 0.0],
        [-sin_yaw, 0.0, cos_yaw],
    ];
    let pitch_matrix = [
        [cos_pitch, -sin_pitch, 0.0],
        [sin_pitch, cos_pitch, 0.0],
        [0.0, 0.0, 1.0],
    ];
    let local = multiply3(multiply3(yaw_matrix, pitch_matrix), roll_matrix);
    let rotation = multiply3(base.rotation, local);
    let result = CameraTransform {
        rotation,
        translation,
    };
    result.is_finite().then_some(result)
}

fn multiply3(left: [[f32; 3]; 3], right: [[f32; 3]; 3]) -> [[f32; 3]; 3] {
    let mut result = [[0.0; 3]; 3];
    for row in 0..3 {
        for column in 0..3 {
            result[row][column] = left[row][0] * right[0][column]
                + left[row][1] * right[1][column]
                + left[row][2] * right[2][column];
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{CameraPose, CameraTransform, compose_transform};

    const IDENTITY: CameraTransform = CameraTransform::new(
        [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
        [10.0, 20.0, 30.0],
    );

    #[test]
    fn native_columns_map_local_translation_to_world_space() {
        let quarter_turn = CameraTransform::new(
            [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]],
            [10.0, 20.0, 30.0],
        );
        let transformed =
            compose_transform(quarter_turn, CameraPose::new([2.0, 3.0, 4.0], [0.0; 3]))
                .expect("finite transform");

        assert_eq!(transformed.translation, [7.0, 22.0, 34.0]);
    }

    #[test]
    fn identity_pose_preserves_every_native_float() {
        assert_eq!(
            compose_transform(IDENTITY, CameraPose::IDENTITY),
            Some(IDENTITY)
        );
    }

    #[test]
    fn forward_axis_roll_preserves_the_native_center_direction() {
        let transformed = compose_transform(IDENTITY, CameraPose::new([0.0; 3], [0.006, 0.0, 0.0]))
            .expect("finite roll");

        assert_eq!(
            transformed.rotation.map(|row| row[0]),
            IDENTITY.rotation.map(|row| row[0])
        );
        assert_eq!(transformed.translation, IDENTITY.translation);
    }

    #[test]
    fn non_finite_pose_is_rejected_before_composition() {
        assert!(
            compose_transform(IDENTITY, CameraPose::new([f32::NAN, 0.0, 0.0], [0.0; 3])).is_none()
        );
    }
}
