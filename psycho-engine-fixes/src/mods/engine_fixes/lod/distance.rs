//! Distance calculations for native terrain, object, and tree demand.
//!
//! The LOD hooks supply camera coordinates, native block centers, and the
//! block's world size. This module owns no engine pointers or persistent state.
//! Invalid or overflowing geometry returns no extension, preserving native
//! demand. Calculation is allocation-free and runs only outside native demand.

/// Return camera-to-block distance, or `None` for invalid geometry.
///
/// `center` is the node's native center, not its minimum corner. Coordinates
/// and size use engine world units. The result is nonnegative;
/// this function has no side effects, synchronization, or panic path.
pub(super) fn distance_to_block(camera: [f32; 2], center: [f32; 2], size: f32) -> Option<f32> {
    if camera
        .into_iter()
        .chain(center)
        .any(|value| !value.is_finite())
        || !size.is_finite()
        || size <= 0.0
    {
        return None;
    }
    // Native 0x006FE830 subtracts half the size before testing square bounds.
    let half = size * 0.5;
    let minimum = [center[0] - half, center[1] - half];
    let maximum = [center[0] + half, center[1] + half];
    if minimum
        .into_iter()
        .chain(maximum)
        .any(|value| !value.is_finite())
    {
        return None;
    }
    let dx = axis_distance(camera[0], minimum[0], maximum[0]);
    let dy = axis_distance(camera[1], minimum[1], maximum[1]);
    let distance = (dx * dx + dy * dy).sqrt();
    distance.is_finite().then_some(distance)
}

fn axis_distance(point: f32, minimum: f32, maximum: f32) -> f32 {
    if point <= minimum {
        minimum - point
    } else if maximum < point {
        point - maximum
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::distance_to_block;

    #[test]
    fn cell_origin_is_inside_the_native_centered_block() {
        // Native constructor 0x006FD210 stores cell_origin + size / 2.
        // For level one at cell (0, 0), the center is (2048, 2048).
        assert_eq!(
            distance_to_block([0.0, 0.0], [2048.0, 2048.0], 4096.0),
            Some(0.0)
        );
    }

    #[test]
    fn distance_uses_the_nearest_edge_or_corner() {
        assert_eq!(
            distance_to_block([-3.0, -4.0], [2048.0, 2048.0], 4096.0),
            Some(5.0)
        );
        assert_eq!(
            distance_to_block([4099.0, 2048.0], [2048.0, 2048.0], 4096.0),
            Some(3.0)
        );
        assert_eq!(
            distance_to_block([3.0, 4.0], [-2048.0, -2048.0], 4096.0),
            Some(5.0)
        );
    }

    #[test]
    fn invalid_geometry_preserves_native_demand() {
        assert_eq!(distance_to_block([0.0; 2], [0.0; 2], 0.0), None);
        assert_eq!(distance_to_block([f32::NAN, 0.0], [0.0; 2], 4096.0), None);
        assert_eq!(
            distance_to_block([f32::MAX; 2], [-f32::MAX; 2], 4096.0),
            None
        );
    }
}
