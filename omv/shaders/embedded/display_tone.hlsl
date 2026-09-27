// Shared display-referred contrast and highlight shoulder, prepended by the
// production shader catalog. This is an authored output look, not an HDR
// radiance reconstruction. Black and display midpoint 0.5 are fixed; contrast
// expands on both sides of that midpoint. A rational shoulder approaches white
// without folding at high strength. Value and slope agree at both joins.
float DisplayToneScale(float luminance, float slope, float reserve) {
    // slope and reserve are prepared per response update (or by the CPU for
    // fixed mode), keeping strength policy out of full-resolution shading.
    float toeScale = rcp(slope + (1.0f - slope) * 2.0f * min(luminance, 0.5f));
    float ramp = 0.5f + slope * (luminance - 0.5f);
    float over = max(ramp - (1.0f - reserve), 0.0f);
    float mapped = ramp - over * over / max(reserve + over, 0.000001f);
    return luminance <= 0.5f ? toeScale : mapped / luminance;
}
