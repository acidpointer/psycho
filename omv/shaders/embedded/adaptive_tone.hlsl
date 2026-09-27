// Display-referred metering, temporal adaptation, and response-curve generation.
//
// Fallout's native image-space pipeline has already mapped the scene into a
// display range. OMV therefore models exposure as a temporary contrast between
// the current view and a slowly adapted reference. Automatic tone uses a
// separate over-range signal for shoulder headroom, never sky occupancy for
// global contrast. The meter passes own spatial integration. The small output
// curve keeps temporal and nonlinear work out of full-resolution composition.

sampler2D SceneColor : register(s0);
sampler2D PreviousResponse : register(s1);

// x = accumulated update seconds, y = symmetric transient range EV,
// z = adaptation-speed scalar, w = previous response valid.
float4 AdaptData0 : register(c0);
// x = auto exposure enabled, y = tone mode (0 off, 1 fixed, 2 automatic),
// z = tone strength, w = inverse response width.
float4 AdaptData1 : register(c1);
static const float MinimumMeterLuma = 1.0f / 1024.0f;
static const float ExposureDeadbandEv = 0.035f;
static const float ExposureDeadbandFadeEv = 0.12f;
static const float BrightAdaptHalfLifeSeconds = 0.52f;
static const float DarkAdaptHalfLifeSeconds = 1.05f;
static const float ExposureResponseHalfLifeSeconds = 0.14f;
static const float ToneRiseHalfLifeSeconds = 0.22f;
static const float ToneFallHalfLifeSeconds = 0.72f;
static const float DisplayGamma = 2.2f;
static const float ResponseCurveMaxLuma = 4.0f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float AdaptValue(
    float current,
    float target,
    float frameSeconds,
    float speedScale,
    float halfLifeSeconds
) {
    float alpha = 1.0f - exp2(-frameSeconds * speedScale / halfLifeSeconds);
    return lerp(current, target, saturate(alpha));
}

float4 Main(PixelInput input) : COLOR0 {
    float4 previous = tex2Dlod(PreviousResponse, float4(0.5f * AdaptData1.w, 0.5f, 0.0f, 0.0f));
    // Valid metered log luminance is never positive. G=+1 is the black/loading
    // sentinel, while AdaptData0.w separately describes CPU render continuity.
    bool temporalStateValid = AdaptData0.w > 0.5f && previous.g <= 0.5f;
    // A single half-float log anchor stalls at slow adaptation speeds: the
    // update becomes smaller than its ULP. G of texel 1 stores a fine residual
    // while all other G texels store the coarse part. R remains the same curve.
    float fine = tex2Dlod(PreviousResponse, float4(1.5f * AdaptData1.w, 0.5f, 0.0f, 0.0f)).g;
    previous.g += temporalStateValid ? fine : 0.0f;
    // The meter/reduction passes already integrate the 64x64 stratified grid.
    // RG contain weighted log luminance and weight; B is the brightest sampled
    // scene/Bloom channel. Read shared statistics once per response texel.
    float4 meter = tex2Dlod(SceneColor, float4(0.5f, 0.5f, 0.0f, 0.0f));
    float exposureLogSum = meter.r;
    float exposureWeight = meter.g;

    bool validMeter = exposureWeight > 0.0001f;
    float meteredMean = validMeter
        ? exposureLogSum / exposureWeight
        : (temporalStateValid ? previous.g : 1.0f);
    float frameSeconds = clamp(AdaptData0.x, 1.0f / 240.0f, 1.0f / 20.0f);
    float speedScale = clamp(AdaptData0.z, 0.10f, 4.0f);
    float adaptedLog = temporalStateValid ? previous.g : meteredMean;
    float exposureEv = temporalStateValid ? previous.b : 0.0f;
    float toneActivity = temporalStateValid ? previous.a : 0.0f;

    if (validMeter && temporalStateValid) {
        float adaptationHalfLife = meteredMean > adaptedLog
            ? BrightAdaptHalfLifeSeconds
            : DarkAdaptHalfLifeSeconds;
        adaptedLog = AdaptValue(
            adaptedLog,
            meteredMean,
            frameSeconds,
            speedScale,
            adaptationHalfLife
        );

        float exposureDelta = (meteredMean - adaptedLog) * DisplayGamma;
        float deadband = Smooth01(
            (abs(exposureDelta) - ExposureDeadbandEv) / ExposureDeadbandFadeEv
        );
        float targetExposure = AdaptData1.x > 0.5f
            ? clamp(exposureDelta * deadband, -AdaptData0.y, AdaptData0.y)
            : 0.0f;
        // With tone off there is no shoulder to preserve over-white detail.
        // Bound positive gain by sampled headroom instead of clipping the sky.
        if (AdaptData1.y < 0.5f) {
            float headroomEv = max(-DisplayGamma * log2(max(meter.b, MinimumMeterLuma)), 0.0f);
            targetExposure = min(targetExposure, headroomEv);
        }
        exposureEv = AdaptData1.x > 0.5f
            ? AdaptValue(
                exposureEv,
                targetExposure,
                frameSeconds,
                speedScale,
                ExposureResponseHalfLifeSeconds
            )
            : 0.0f;

        // Ordinary sky occupancy must not change contrast. Only actual
        // over-range light asks for extra shoulder headroom; tone contrast is
        // always controlled by the user's strength, independently of coverage.
        float exposedPeak = meter.b * exp2(exposureEv / DisplayGamma);
        float targetTone = AdaptData1.y > 1.5f
            ? Smooth01(exposedPeak - 1.0f)
            : 0.0f;
        float toneHalfLife = targetTone > toneActivity
            ? ToneRiseHalfLifeSeconds
            : ToneFallHalfLifeSeconds;
        toneActivity = AdaptData1.y > 1.5f
            ? AdaptValue(toneActivity, targetTone, frameSeconds, speedScale, toneHalfLife)
            : 0.0f;
    } else {
        exposureEv = AdaptData1.x > 0.5f ? exposureEv : 0.0f;
        toneActivity = AdaptData1.y > 1.5f ? toneActivity : 0.0f;
    }

    // Exposure is an approximate display-linear stop, not a gain applied to
    // already encoded RGB. Both fixed and automatic modes use the same curve.
    float exposureScale = exp2(exposureEv / DisplayGamma);
    float curveLuma = input.uv.x * ResponseCurveMaxLuma;
    float toneStrength = AdaptData1.y > 0.5f ? AdaptData1.z : 0.0f;
    float amount = toneStrength / (1.0f + toneStrength);
    float slope = 1.0f + amount;
    float reserve = amount * 0.25f * (1.0f + saturate(toneActivity) * 0.5f);
    float toneScale = toneStrength > 0.0f
        ? DisplayToneScale(curveLuma * exposureScale, slope, reserve)
        : 1.0f;
    float responseScale = exposureScale * toneScale;
    // Multiples of 1/64 are exact FP16 throughout the metered [-10, 0] range.
    // The residual is below 1/64 and retains the small increments separately.
    float coarseLog = floor(adaptedLog * 64.0f) / 64.0f;
    bool fineTexel = input.uv.x > AdaptData1.w && input.uv.x < 2.0f * AdaptData1.w;
    float storedLog = fineTexel ? adaptedLog - coarseLog : coarseLog;
    return float4(responseScale, storedLog, exposureEv, toneActivity);
}
