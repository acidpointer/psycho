sampler2D ShaftMask : register(s0);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 EnvironmentData : register(c6);
float4 OptionData3 : register(c7);
float4 SunData : register(c8);
float4 NativeSunData : register(c10);
// Keep sample spacing within the reconstruction footprint, with a hard GPU
// bound for high resolutions. Blur uses the same count to cover capped gaps.
// Depth is known only inside the viewport. Preserve the sun's projected
// direction while clipping the ray endpoint, rather than clamping the sun
// itself or treating unknown offscreen taps as opaque geometry.
float2 CoveredEndpoint(float2 uv) {
    float2 delta = SunData.xy - uv;
    float2 boundary = float2(delta.x >= 0.0f ? 1.0f : 0.0f, delta.y >= 0.0f ? 1.0f : 0.0f);
    float2 extent = abs(boundary - uv) / max(abs(delta), 0.000001f);
    return uv + delta * min(1.0f, min(extent.x, extent.y));
}

int RadialSampleCount(float2 uv) {
    return (int)clamp(ceil(length((CoveredEndpoint(uv) - uv) * ScreenData.xy) * 0.5f), 32.0f, 256.0f);
}

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float InterleavedNoise(float2 uv) {
	float2 pixel = floor(uv * ScreenData.xy);
	return frac(52.9829189f * frac(dot(pixel, float2(0.06711056f, 0.00583715f))));
}

float4 Main(PixelInput input) : COLOR0 {
    if (SunData.z <= 0.5f || OptionData0.x <= 0.0f || OptionData0.y <= 0.0f) {
        return 0.0f;
    }

    // Directional illumination is independent of the rendered solar sprite.
    // The mask samples participating paths; it does not enlarge the sun disk.
    float noise = InterleavedNoise(input.uv);
    float2 endpoint = CoveredEndpoint(input.uv);
    float brightness = max(dot(max(NativeSunData.rgb, 0.0f), float3(0.2126f, 0.7152f, 0.0722f)),
        max(NativeSunData.r, max(NativeSunData.g, NativeSunData.b)) * 0.72f);
    float response = lerp(0.02f, 0.75f, saturate(OptionData1.z));
    float sourceStrength = saturate(brightness / max(brightness + response, 0.001f));
    sourceStrength = sourceStrength * sourceStrength * (3.0f - 2.0f * sourceStrength);

    float decay = clamp(OptionData0.z, 0.55f, 1.0f);
    int sampleCount = RadialSampleCount(input.uv);
    float weightStep = 1.0f / sampleCount;
    float distanceDecay = pow(decay, (48.0f / sampleCount) * max(OptionData0.w, 0.10f));
    float2 delta = (endpoint - input.uv) / sampleCount;
    // The serialized sampling control sets within-segment jitter amplitude.
    float2 sampleUv = input.uv + delta * (noise * saturate(OptionData3.x / 48.0f) - 1.0f);

    float illumination = 1.0f;
    float light = 0.0f;
    float weight = 1.0f;
    float weightSum = 0.0f;

    [loop]
    for (int i = 0; i < sampleCount; ++i) {
        sampleUv += delta;
        float2 insideMin = step(0.0f, sampleUv);
        float2 insideMax = step(sampleUv, 1.0f);
        float inside = insideMin.x * insideMin.y * insideMax.x * insideMax.y;
        float2 mask = tex2Dlod(ShaftMask, float4(sampleUv, 0.0f, 0.0f)).rg;
        float pathOpen = mask.g * inside;
        // Occluded taps contribute no light, but cannot extinguish subsequent
        // open taps. Camera-depth occlusion is not light-path transmittance.
        illumination *= distanceDecay;
        // Soften fractional edge coverage without leaking through opaque taps.
        float softenedOpen = lerp(pathOpen, sqrt(pathOpen), saturate(OptionData3.w));
        // Fade the screen-space kernel toward its point endpoint. Giving
        // the final taps increasing weight spread a source-center weapon
        // across the entire sky when strengthening the projected wedge.
        // This is a normalized artistic blur, not light-path extinction.
        float sampleWeight = illumination * weight * weight;
        light += softenedOpen * sampleWeight;
        // Decay weights the integral, not obstruction. Normalize by the same
        // decayed weights so an open path remains neutral at every setting.
        weightSum += sampleWeight;
        weight -= weightStep;
    }

    // The integral already measures missing path coverage. Exponentiating it
    // amplified a tiny source-center blocker into almost full-screen shadow.
    // Preserve fractional openings and blocker coverage without that gain.
    float blockage = saturate(1.0f - light / max(weightSum, 0.000001f));
    return float4(saturate(sourceStrength * blockage * max(OptionData0.w, 0.0f)), 0.0f, 0.0f, 1.0f);
}
