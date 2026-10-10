// Shared display-referred contrast and highlight shoulder, prepended by the
// production shader catalog. This is an authored output look, not an HDR
// radiance reconstruction. Black and display midpoint 0.5 are fixed; contrast
// expands on both sides of that midpoint. A rational shoulder approaches white
// without folding at high strength. Value and slope agree at both joins.
float DisplayToneScale(float luminance, float amount, float reserve, float toeCurvature) {
    // Amount, reserve, and curvature are prepared per response update (or by
    // the CPU for
    // fixed mode), keeping strength policy out of full-resolution shading.
    // Relief vanishes with its first derivative at the midpoint, retaining the
    // contrast slope while keeping low-end texture above the former deep toe.
    float toeDistance = max(1.0f - 2.0f * luminance, 0.0f);
    float toeScale = rcp(1.0f + toeDistance * (amount - toeCurvature * toeDistance));
    float ramp = luminance + amount * (luminance - 0.5f);
    float over = max(ramp - (1.0f - reserve), 0.0f);
    // Evaluate the shoulder toward its white asymptote directly. Subtracting
    // two large ramp values loses enough precision to reverse 8-bit steps.
    float mapped = min(ramp, 1.0f - reserve * reserve / max(reserve + over, 0.000001f));
    return luminance <= 0.5f ? toeScale : mapped / luminance;
}
