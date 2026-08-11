// Display-referred metering, temporal adaptation, and response-curve generation.
//
// Fallout's native image-space pipeline has already mapped the scene into a
// display range. OMV therefore models exposure as a temporary contrast between
// the current view and a slowly adapted reference. Automatic tone uses a
// separate upper-tail signal: exposure must suppress isolated bright outliers,
// while tone mapping must deliberately see the lamps, clouds, signs, and Bloom
// which need highlight compression. The small output curve keeps all expensive
// temporal and nonlinear work out of the full-resolution compose pass.

sampler2D SceneColor : register(s0);
sampler2D PreviousResponse : register(s1);
sampler2D BloomTexture : register(s4);

// x = accumulated update seconds, y = symmetric transient range EV,
// z = adaptation-speed scalar, w = previous response valid.
float4 AdaptData0 : register(c0);
// x = auto exposure enabled, y = automatic tone enabled,
// z = tone strength, w = reserved.
float4 AdaptData1 : register(c1);
// x = reserved, y = Bloom contributes to the frame,
// z = Bloom intensity, w = Bloom exposure bias.
float4 AdaptData2 : register(c2);
// x = Bloom blend shoulder, y = Bloom saturation,
// z = Bloom warmth, w = Bloom shadow lift.
float4 AdaptData3 : register(c3);

static const float3 LumaFactors = float3(0.2126f, 0.7152f, 0.0722f);
static const float3 WarmTint = float3(1.08f, 1.02f, 0.90f);
static const float3 CoolTint = float3(0.94f, 0.99f, 1.08f);
static const float MinimumMeterLuma = 1.0f / 1024.0f;
static const float BlackStart = 1.0f / 255.0f;
static const float BlackEnd = 4.0f / 255.0f;
static const float MeterWinsorRangeEv = 2.5f;
static const float ExposureDeadbandEv = 0.035f;
static const float ExposureDeadbandFadeEv = 0.12f;
static const float BrightAdaptHalfLifeSeconds = 0.52f;
static const float DarkAdaptHalfLifeSeconds = 1.05f;
static const float ExposureResponseHalfLifeSeconds = 0.14f;
static const float ToneRiseHalfLifeSeconds = 0.22f;
static const float ToneFallHalfLifeSeconds = 0.72f;
static const float DisplayGamma = 2.2f;
static const float ToneWhitePointSquared = 6.25f;
static const float ToneMinimumActivityScale = 0.70f;
static const float ToneMaximumActivityScale = 1.30f;
static const float ResponseCurveMaxLuma = 4.0f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float Luma(float3 color) {
    return dot(color, LumaFactors);
}

float SpatialWeight(float2 sampleUv) {
    float2 centered = sampleUv * 2.0f - 1.0f;
    return lerp(1.0f, 0.40f, saturate(dot(centered, centered) * 0.5f));
}

float MeterWeight(float luminance, float2 sampleUv) {
    float blackWeight = Smooth01((luminance - BlackStart) / (BlackEnd - BlackStart));
    return blackWeight * SpatialWeight(sampleUv);
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

float3 ApplySaturation(float3 color, float amount) {
    float luminance = Luma(color);
    return lerp(luminance.xxx, color, max(amount, 0.0f));
}

float3 ApplyWarmth(float3 color, float warmth) {
    warmth = clamp(warmth, -1.0f, 1.0f);
    float3 tint = warmth >= 0.0f
        ? lerp(1.0f.xxx, WarmTint, warmth)
        : lerp(1.0f.xxx, CoolTint, -warmth);
    return color * tint;
}

float3 ComposeBloom(float3 base, float3 bloomContribution, float shoulder) {
    float3 additive = base + bloomContribution * (1.0f - base * (0.25f + shoulder * 0.55f));
    float3 screen = 1.0f - (1.0f - saturate(base)) * (1.0f - saturate(bloomContribution));
    return lerp(additive, screen, shoulder * 0.70f);
}

float4 Main(PixelInput input) : COLOR0 {
    float4 previous = tex2Dlod(PreviousResponse, float4(input.uv, 0.0f, 0.0f));
    // Valid metered log luminance is never positive. G=+1 is the black/loading
    // sentinel, while AdaptData0.w separately describes CPU render continuity.
    bool temporalStateValid = AdaptData0.w > 0.5f && previous.g <= 0.5f;
    float exposureLogSum = 0.0f;
    float exposureWeight = 0.0f;
    float highlightSum = 0.0f;
    float highlightWeight = 0.0f;
    float highlightMaximum = 0.0f;

    // A stable 4x4 grid is enough for a global view transition because each
    // read is bilinear and the response changes far more slowly than camera
    // motion. Clamping each log sample around the prior temporal anchor bounds
    // isolated UI/sky extremes without the second 32-sample pass which used to
    // be repeated for every response texel. Unlike rejection, winsorization
    // still lets a genuine whole-screen transition move the anchor.
    [loop]
    for (int y = 0; y < 4; ++y) {
        [loop]
        for (int x = 0; x < 4; ++x) {
            float2 sampleUv = (float2(x, y) + 0.5f.xx) * 0.25f;
            float3 scene = max(
                tex2Dlod(SceneColor, float4(sampleUv, 0.0f, 0.0f)).rgb,
                0.0f.xxx
            );
            float luminance = saturate(Luma(scene));
            float weight = MeterWeight(luminance, sampleUv);
            float logLuminance = clamp(log2(max(luminance, MinimumMeterLuma)), -10.0f, 0.0f);
            if (temporalStateValid) {
                logLuminance = clamp(
                    logLuminance,
                    previous.g - MeterWinsorRangeEv,
                    previous.g + MeterWinsorRangeEv
                );
            }
            exposureLogSum += logLuminance * weight;
            exposureWeight += weight;

            float3 combined = scene;
            if (AdaptData2.y > 0.5f) {
                float3 bloom = tex2Dlod(BloomTexture, float4(sampleUv, 0.0f, 0.0f)).rgb;
                bloom = ApplySaturation(bloom, AdaptData3.y);
                bloom = ApplyWarmth(bloom, AdaptData3.z)
                    * exp2(clamp(AdaptData2.w, -0.5f, 0.5f));
                float bloomLift = 1.0f + AdaptData3.w * 0.25f;
                combined = ComposeBloom(
                    scene,
                    bloom * max(AdaptData2.z, 0.0f) * bloomLift,
                    AdaptData3.x
                );
            }

            if (AdaptData1.y > 0.5f) {
                // Automatic tone observes the upper display tail, including
                // native near-white values. Requiring values above 1.0 made a
                // post-native tone mapper inert because Fallout had already
                // clipped most scene radiance. Spatial weighting stabilizes
                // edge flashes, but exposure's outlier policy is intentionally
                // absent so real highlight sources remain visible here.
                float peak = max(combined.r, max(combined.g, combined.b));
                float softHighlight = Smooth01((peak - 0.72f) / 0.26f);
                float clipRisk = Smooth01((peak - 0.94f) / 0.16f);
                float toneWeight = SpatialWeight(sampleUv);
                highlightSum += softHighlight * toneWeight;
                highlightWeight += toneWeight;
                highlightMaximum = max(
                    highlightMaximum,
                    clipRisk * saturate(toneWeight * 1.5f)
                );
            }
        }
    }

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

        float exposureDelta = meteredMean - adaptedLog;
        float deadband = Smooth01(
            (abs(exposureDelta) - ExposureDeadbandEv) / ExposureDeadbandFadeEv
        );
        float targetExposure = AdaptData1.x > 0.5f
            ? clamp(exposureDelta * deadband, -AdaptData0.y, AdaptData0.y)
            : 0.0f;
        exposureEv = AdaptData1.x > 0.5f
            ? AdaptValue(
                exposureEv,
                targetExposure,
                frameSeconds,
                speedScale,
                ExposureResponseHalfLifeSeconds
            )
            : 0.0f;

        float meanHighlight = highlightWeight > 0.0001f
            ? highlightSum / highlightWeight
            : 0.0f;
        float targetTone = AdaptData1.y > 0.5f
            ? saturate(meanHighlight * 0.55f + highlightMaximum * 0.65f)
            : 0.0f;
        float toneHalfLife = targetTone > toneActivity
            ? ToneRiseHalfLifeSeconds
            : ToneFallHalfLifeSeconds;
        toneActivity = AdaptData1.y > 0.5f
            ? AdaptValue(toneActivity, targetTone, frameSeconds, speedScale, toneHalfLife)
            : 0.0f;
    } else {
        exposureEv = AdaptData1.x > 0.5f ? exposureEv : 0.0f;
        toneActivity = AdaptData1.y > 0.5f ? toneActivity : 0.0f;
    }

    // The response is indexed by display luminance rather than channel peak.
    // Fallout's native HDR blend usually delivers values in 0..1, so a knee
    // confined to the last few percent of that interval was mathematically
    // active but visually inert. This luminance-only extended Reinhard ratio
    // has photographic midtone-to-highlight authority while one shared scale
    // preserves RGB ratios. Gamma conversion and the nonlinear curve execute
    // only for these 128 response pixels, never for the full-resolution pass.
    //
    // Automatic activity modulates an always-present configured curve by only
    // +/-30 percent. Camera motion therefore changes the look gradually but
    // never makes a nonzero tone setting disappear in an ordinary scene.
    // Creative exposure remains in analytic grading before the LUT; this
    // independent scale owns only transient camera adaptation.
    float exposureScale = exp2(exposureEv);
    float curveLuma = input.uv.x * ResponseCurveMaxLuma;
    float exposedLuma = curveLuma * exposureScale;
    float linearLuma = pow(max(exposedLuma, 0.0f), DisplayGamma);
    float reinhardRatio =
        (1.0f + linearLuma / ToneWhitePointSquared) / (1.0f + linearLuma);
    float activityScale = lerp(
        ToneMinimumActivityScale,
        ToneMaximumActivityScale,
        saturate(toneActivity)
    );
    float effectiveStrength = AdaptData1.y > 0.5f
        ? AdaptData1.z * activityScale
        : 0.0f;
    float toneScale = pow(
        max(reinhardRatio, 0.00001f),
        effectiveStrength / DisplayGamma
    );
    float responseScale = exposureScale * toneScale;

    // G/B/A are replicated temporal state. R varies across the response
    // texels and is the only lane sampled by full-resolution composition.
    return float4(responseScale, adaptedLog, exposureEv, toneActivity);
}
