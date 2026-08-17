//! Linear third-person mouse-wheel distance conversion.
//!
//! FNV scales each wheel sample by the current desired camera distance and by
//! separate live in/out multipliers. That makes far-camera notches much larger
//! than near-camera notches. This module converts the sample before FNV sees it
//! so the existing native formula produces a constant distance step. It does
//! not own the desired distance, realized collision distance, POV transition,
//! or any camera setting.

/// Convert one raw FNV wheel sample into a linear desired-distance step.
///
/// `raw_delta` uses DirectInput wheel units, where a conventional notch is
/// `120`. `desired_distance` and `native_multiplier` must be the live values
/// FNV will consume for this sample. `step` is the requested world-unit change
/// per notch. `residual` retains fractional native wheel units across samples,
/// which prevents high-resolution wheels from losing small deltas.
///
/// The function returns `None` and clears `residual` when any input violates
/// the finite positive-distance contract or when the transformed result cannot
/// fit in an `i32`. Callers should pass the original delta to native code in
/// that case.
pub fn linear_zoom_delta(
    raw_delta: i32,
    desired_distance: f32,
    native_multiplier: f32,
    step: f32,
    residual: &mut f64,
) -> Option<i32> {
    if raw_delta == 0 {
        return Some(0);
    }
    if !desired_distance.is_finite()
        || desired_distance <= 0.0
        || !native_multiplier.is_finite()
        || native_multiplier <= 0.0
        || !step.is_finite()
        || step <= 0.0
        || !residual.is_finite()
        || residual.abs() >= 1.0
    {
        *residual = 0.0;
        return None;
    }

    // Native computes:
    //   distance -= raw / 120 * distance * multiplier
    // Supplying raw * step / (distance * multiplier) therefore reduces that
    // expression to a constant raw / 120 * step without bypassing native
    // clamps, POV handling, or endpoint construction.
    let transformed = f64::from(raw_delta) * f64::from(step)
        / (f64::from(desired_distance) * f64::from(native_multiplier))
        + *residual;
    if !transformed.is_finite()
        || transformed < f64::from(i32::MIN)
        || transformed > f64::from(i32::MAX)
    {
        *residual = 0.0;
        return None;
    }

    // Nearest-integer quantization minimizes the error of each native sample.
    // Carrying the signed remainder makes the sequence unbiased over time and
    // makes an immediate opposite wheel sample cancel exactly.
    // Avoid the CRT `round` symbol: changing final-DLL imports would expand
    // Atom's pre-Deferred startup footprint for a hot-path quantizer that can
    // be expressed directly. Rust's float-to-int conversion truncates after
    // the sign-aware half-unit bias and saturates at the already-checked i32
    // bounds.
    let integral = if transformed >= 0.0 {
        (transformed + 0.5) as i32
    } else {
        (transformed - 0.5) as i32
    };
    *residual = transformed - f64::from(integral);
    Some(integral)
}

#[cfg(test)]
mod tests {
    use super::linear_zoom_delta;

    #[test]
    fn invalid_contract_falls_back_and_clears_fractional_state() {
        let mut residual = 0.75;
        assert_eq!(linear_zoom_delta(120, 60.0, 0.0, 2.0, &mut residual), None);
        assert_eq!(residual, 0.0);
    }
}
