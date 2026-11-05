//! Conservative numeric envelope of the native axis-aligned window.
//!
//! C35C10 builds its corners. A699D0/53D1A0 form each plane from an axis edge
//! and the camera, normalize with a common positive scale, then store n.dot(p).
//! Their binary32 rounding is included before exact source coverage is tested.
//! This does not change the caller's x87 or SSE state, or mirror a native
//! culling test. It bounds construction error, including directed rounding.
use super::PlaneRecord;

use super::super::exact::exact64;

/// Directed conversion without depending on MXCSR rounding or FTZ. All input
/// arithmetic is finite binary64; oversized output becomes infinity and the
/// enclosing certificate rejects it.
fn outward32(value: f64, upper: bool) -> f32 {
    let bits = value.to_bits();
    let negative = bits >> 63 != 0;
    let exponent = ((bits >> 52) & 2047) as i32 - 1023;
    let mantissa = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    let (floor, remainder) = if bits & 0x7fffffffffffffff == 0 {
        (0, false)
    } else if exponent > 127 {
        (0x7f7fffff, true)
    } else if exponent >= -126 {
        (
            (((exponent + 127) as u32) << 23) | ((mantissa >> 29) as u32 & 0x7fffff),
            mantissa & ((1 << 29) - 1) != 0,
        )
    } else if exponent >= -149 {
        let shift = (-exponent - 97) as u32;
        (
            (mantissa >> shift) as u32,
            mantissa & ((1u64 << shift) - 1) != 0,
        )
    } else {
        (0, true)
    };
    let ceil = floor + u32::from(remainder);
    let body = if upper != negative { ceil } else { floor };
    f32::from_bits(body | if negative { 0x80000000 } else { 0 })
}

pub(super) fn midpoint(a: f32, b: f32) -> f32 {
    outward32((exact64(a) + exact64(b)) * 0.5, false)
}

fn add(a: f64, b: f64) -> f64 {
    (a + b).next_up()
}
fn mul(a: f64, b: f64) -> f64 {
    (a * b).next_up()
}
fn div(a: f64, b: f64) -> f64 {
    (a / b).next_up()
}
fn difference(a: f64, b: f64) -> f64 {
    (a - b).abs().next_up()
}
fn gamma(rounds: f64) -> f64 {
    let error = rounds * f64::from(f32::EPSILON);
    div(error, 1.0 - error)
}

/// One corner addition is enclosed by its neighboring binary32 values. Reject
/// collapsed native rectangles before native normalization can see a zero edge.
pub(super) fn corners(plane: &PlaneRecord) -> Option<[[f32; 3]; 8]> {
    if !plane.valid_native() {
        return None;
    }
    // This proof applies only to a signed permutation, never an approximate
    // orthonormal matrix. No oblique legacy face enters this path.
    for i in 0..3 {
        if (0..3)
            .filter(|&j| plane.rotation[i * 3 + j].abs() == 1.0)
            .count()
            != 1
            || (0..3)
                .filter(|&j| plane.rotation[j * 3 + i].abs() == 1.0)
                .count()
                != 1
        {
            return None;
        }
    }
    if plane.rotation.iter().any(|v| *v != 0.0 && v.abs() != 1.0) {
        return None;
    }
    let axis = (0..3).find(|&i| plane.rotation[i * 3 + 1] != 0.0)?;
    let raw = [(-0.5, -0.5), (0.5, -0.5), (-0.5, 0.5), (0.5, 0.5)].map(|(x, z)| {
        std::array::from_fn::<_, 3, _>(|i| {
            plane.position[i]
                + x * plane.size[0] * plane.rotation[i * 3]
                + z * plane.size[1] * plane.rotation[i * 3 + 2]
        })
    });
    let min: [f32; 3] =
        std::array::from_fn(|i| raw.iter().map(|p| p[i]).fold(f32::INFINITY, f32::min));
    let max: [f32; 3] =
        std::array::from_fn(|i| raw.iter().map(|p| p[i]).fold(f32::NEG_INFINITY, f32::max));
    for i in 0..3 {
        if i != axis
            && super::super::data::coordinate_key(min[i].next_up())?
                >= super::super::data::coordinate_key(max[i].next_down())?
        {
            return None;
        }
    }
    let min = min.map(f32::next_down);
    let max = max.map(f32::next_up);
    let points: [[f32; 3]; 8] = std::array::from_fn(|bits| {
        std::array::from_fn(|i| if bits & (1 << i) == 0 { min[i] } else { max[i] })
    });
    points
        .iter()
        .flatten()
        .all(|v| v.is_finite())
        .then_some(points)
}

/// Bound the native frustum by a wider rectangle closer to the camera.
/// At depths beyond that rectangle, each native side halfspace lies inside
/// its corresponding widened camera ray halfspace. Source certification of
/// this entire envelope therefore includes native plane-construction error.
pub(super) fn enclose(
    raw: [[f32; 3]; 8],
    axis: usize,
    camera_min: [f32; 3],
    camera_max: [f32; 3],
    positive: bool,
) -> Option<[[f32; 3]; 4]> {
    let lo: [f64; 3] = std::array::from_fn(|i| {
        raw.iter()
            .map(|p| exact64(p[i]))
            .fold(f64::INFINITY, f64::min)
    });
    let hi: [f64; 3] = std::array::from_fn(|i| {
        raw.iter()
            .map(|p| exact64(p[i]))
            .fold(f64::NEG_INFINITY, f64::max)
    });
    let cmin = camera_min.map(exact64);
    let cmax = camera_max.map(exact64);
    let distance = (if positive {
        lo[axis] - cmax[axis]
    } else {
        cmin[axis] - hi[axis]
    })
    .next_down();
    if !distance.is_finite() || distance <= 0.0 {
        return None;
    }
    let axis_abs = lo[axis].abs().max(hi[axis].abs());
    // The axis face has one nonzero normal component. Its stored dot product
    // has at most a multiply and a binary32 store's rounding. The normalized
    // component exceeds 1/2; 2*MIN_POSITIVE also covers underflow/flush.
    let depth = add(
        mul(gamma(2.0), axis_abs),
        2.0 * f64::from(f32::MIN_POSITIVE),
    );
    let near = if positive {
        outward32((lo[axis] - depth).next_down(), false)
    } else {
        outward32((hi[axis] + depth).next_up(), true)
    };
    let mut min = [0.0f32; 3];
    let mut max = [0.0f32; 3];
    min[axis] = near;
    max[axis] = near;
    for i in 0..3 {
        if i == axis {
            continue;
        }
        let delta = [
            difference(lo[i], cmin[i]),
            difference(lo[i], cmax[i]),
            difference(hi[i], cmin[i]),
            difference(hi[i], cmax[i]),
        ]
        .into_iter()
        .fold(0.0f64, f64::max);
        let world = lo[i].abs().max(hi[i].abs());
        // Edge-axis subtraction, product and normalized-component store each
        // have at most two rounds (x87 operation plus f32 store). Three such
        // pairs per component give gamma_12 for their ratio. Dot's two
        // nonzero terms give gamma_3. The common normalization factor cancels.
        let ratio = mul(add(1.0, gamma(12.0)), div(delta, distance));
        let slope = mul(gamma(12.0), delta);
        let constant = mul(gamma(3.0), add(world, mul(ratio, axis_abs)));
        let underflow = mul(
            24.0 * f64::from(f32::MIN_POSITIVE),
            mul(
                add(1.0, ratio),
                add(1.0, add(axis_abs, add(world, add(distance, delta)))),
            ),
        );
        let expansion = add(add(slope, constant), add(mul(ratio, depth), underflow));
        min[i] = outward32((lo[i] - expansion).next_down(), false);
        max[i] = outward32((hi[i] + expansion).next_up(), true);
    }
    let points: [[f32; 3]; 4] = std::array::from_fn(|bits| {
        std::array::from_fn(|i| {
            if i == axis {
                near
            } else {
                let bit = if i == (axis + 1) % 3 { 0 } else { 1 };
                if bits & (1 << bit) == 0 {
                    min[i]
                } else {
                    max[i]
                }
            }
        })
    });
    points
        .iter()
        .flatten()
        .all(|v| v.is_finite())
        .then_some(points)
}

#[cfg(test)]
pub(super) fn conversion_probe(value: f32) -> (u64, u32, u32) {
    let double = exact64(value);
    (
        double.to_bits(),
        outward32(double, false).to_bits(),
        outward32(double, true).to_bits(),
    )
}
