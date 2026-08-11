// One-pixel display-luminance meter and temporal adaptation for OMV.
//
// Fallout's native image-space pipeline has already mapped the source into a
// clamped display-referred range. The constants below are therefore calibrated
// display values, not physical scene luminance or EV100. A fixed grid avoids
// temporal sample noise, while center weighting prevents an edge highlight
// from steering the entire image abruptly.

sampler2D SceneColor : register(s0);
sampler2D PreviousHistory : register(s1);

// x = frame seconds, y = symmetric exposure range EV,
// z = adaptation-speed scalar, w = previous history valid.
float4 AdaptData0 : register(c0);
// x = auto exposure enabled, y = automatic tone enabled,
// z = reserved tone strength, w = reserved.
float4 AdaptData1 : register(c1);

static const float3 LumaFactors = float3(0.2126f, 0.7152f, 0.0722f);
static const float DisplayKey = 0.36f;
static const float MinimumMeterLuma = 1.0f / 1024.0f;
static const float BlackStart = 1.0f / 255.0f;
static const float BlackEnd = 4.0f / 255.0f;
static const float ExposureTransitionEv = 0.50f;
static const float BrightSceneSpeedEv = 0.90f;
static const float DarkSceneSpeedEv = 0.45f;
static const float ToneHalfLifeSeconds = 0.85f;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float AdaptExposure(float currentEv, float targetEv, float frameSeconds, float speedScale) {
    float delta = targetEv - currentEv;
    float distance = abs(delta);
    if (distance <= 0.00001f) {
        return targetEv;
    }

    // Closing exposure in a bright scene is intentionally faster than opening
    // it in darkness. Far from the target the change is a bounded EV/second
    // ramp; near the target the exponential rate is chosen so its derivative
    // matches that ramp at ExposureTransitionEv and cannot jitter or overshoot.
    float speed = (delta < 0.0f ? BrightSceneSpeedEv : DarkSceneSpeedEv) * speedScale;
    if (distance > ExposureTransitionEv) {
        return currentEv + sign(delta) * min(distance, speed * frameSeconds);
    }
    float alpha = 1.0f - exp2(
        -speed * frameSeconds / (ExposureTransitionEv * 0.69314718056f)
    );
    return currentEv + delta * saturate(alpha);
}

float AdaptTone(float current, float target, float frameSeconds, float speedScale) {
    float alpha = 1.0f - exp2(-frameSeconds * speedScale / ToneHalfLifeSeconds);
    return lerp(current, target, saturate(alpha));
}

float4 Main(PixelInput input) : COLOR0 {
    float weightedLog = 0.0f;
    float weightedLogSquared = 0.0f;
    float weightedHighlights = 0.0f;
    float totalWeight = 0.0f;

    // This loop executes exactly 64 samples for one output pixel. Keeping the
    // loop in bytecode avoids a ps_3_0 instruction explosion; its fixed bounds
    // and coordinates make the cost and spatial response deterministic.
    [loop]
    for (int y = 0; y < 8; ++y) {
        [loop]
        for (int x = 0; x < 8; ++x) {
            float2 sampleUv = (float2(x, y) + float2(0.5f, 0.5f)) * 0.125f;
            float3 color = tex2Dlod(SceneColor, float4(sampleUv, 0.0f, 0.0f)).rgb;
            float luminance = saturate(dot(max(color, 0.0f.xxx), LumaFactors));
            float blackWeight = Smooth01((luminance - BlackStart) / (BlackEnd - BlackStart));
            float2 centered = sampleUv * 2.0f - 1.0f;
            float centerWeight = lerp(1.0f, 0.35f, saturate(dot(centered, centered) * 0.5f));
            float weight = blackWeight * centerWeight;
            float logLuminance = clamp(log2(max(luminance, MinimumMeterLuma)), -10.0f, 0.0f);
            float highlight = Smooth01((luminance - 0.70f) / 0.25f);

            weightedLog += logLuminance * weight;
            weightedLogSquared += logLuminance * logLuminance * weight;
            weightedHighlights += highlight * weight;
            totalWeight += weight;
        }
    }

    float4 previous = tex2Dlod(PreviousHistory, float4(0.5f, 0.5f, 0.0f, 0.0f));
    bool validMeter = totalWeight > 0.0001f;
    float inverseWeight = validMeter ? rcp(totalWeight) : 0.0f;
    float meanLog = weightedLog * inverseWeight;
    float variance = max(weightedLogSquared * inverseWeight - meanLog * meanLog, 0.0f);
    float highlightOccupancy = weightedHighlights * inverseWeight;

    float exposureRange = clamp(AdaptData0.y, 0.0f, 1.5f);
    float targetExposure = AdaptData1.x > 0.5f && validMeter
        ? clamp(log2(DisplayKey) - meanLog, -exposureRange, exposureRange)
        : 0.0f;
    float contrastSignal = saturate((sqrt(variance) - 1.0f) * 0.25f);
    float highlightSignal = saturate(highlightOccupancy * 2.5f + contrastSignal * 0.35f);
    float targetShoulder = AdaptData1.y > 0.5f ? lerp(0.82f, 0.66f, highlightSignal) : 0.76f;
    float targetCrosstalk = AdaptData1.y > 0.5f ? lerp(0.03f, 0.10f, highlightSignal) : 0.05f;

    // A fully black/loading image contains no useful exposure measurement.
    // Holding valid history avoids opening exposure against a black frame; a
    // first black frame starts from neutral until real image content arrives.
    if (!validMeter && AdaptData0.w > 0.5f) {
        targetExposure = previous.r;
        targetShoulder = previous.g;
        targetCrosstalk = previous.b;
    }

    float frameSeconds = clamp(AdaptData0.x, 1.0f / 240.0f, 1.0f / 20.0f);
    float speedScale = clamp(AdaptData0.z, 0.25f, 2.0f);
    if (AdaptData0.w < 0.5f) {
        // Enabling the feature or resuming after an interrupted Present epoch
        // must never snap to a newly measured value. Seed neutral and let the
        // same bounded response used in steady state perform the transition.
        return float4(0.0f, 0.76f, 0.05f, 1.0f);
    }

    return float4(
        AdaptExposure(previous.r, targetExposure, frameSeconds, speedScale),
        AdaptTone(previous.g, targetShoulder, frameSeconds, speedScale),
        AdaptTone(previous.b, targetCrosstalk, frameSeconds, speedScale),
        1.0f
    );
}
