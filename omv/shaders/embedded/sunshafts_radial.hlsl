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
int RadialSampleCount(float2 uv) {
    return (int)clamp(ceil(length((SunData.xy - uv) * ScreenData.xy) * 0.5f), 32.0f, 256.0f);
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
    float2 endpoint = SunData.xy;
    float brightness = max(dot(max(NativeSunData.rgb, 0.0f), float3(0.2126f, 0.7152f, 0.0722f)),
        max(NativeSunData.r, max(NativeSunData.g, NativeSunData.b)) * 0.72f);
    float response = lerp(0.02f, 0.75f, saturate(OptionData1.z));
    float sourceStrength = saturate(brightness / max(brightness + response, 0.001f));
    sourceStrength = sourceStrength * sourceStrength * (3.0f - 2.0f * sourceStrength);

    float decay = clamp(OptionData0.z, 0.55f, 1.0f);
    int sampleCount = RadialSampleCount(input.uv);
    float weightStep = pow(1.021193f, 32.0f / sampleCount);
    float distanceDecay = pow(decay, (48.0f / sampleCount) * max(OptionData0.w, 0.10f));
    float2 delta = (endpoint - input.uv) / sampleCount;
    // The serialized sampling control sets within-segment jitter amplitude.
    float2 sampleUv = input.uv + delta * (noise * saturate(OptionData3.x / 48.0f) - 1.0f);

    float illumination = 1.0f;
    float light = 0.0f;
    float weight = 0.024f;
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
        light += softenedOpen * illumination * weight;
        // Decay weights the integral, not obstruction. Normalize by the same
        // decayed weights so an open path remains neutral at every setting.
        weightSum += illumination * weight;
        weight *= weightStep;
    }

    // Match the established thin-occluder contrast curve. Mean openness alone
    // dilutes thin blockers across the path and leaves almost no ray contrast.
    float blockage = saturate(1.0f - light / max(weightSum, 0.000001f));
    float visibility = exp(-12.0f * blockage * max(OptionData0.w, 0.10f));
    // Carry missing illumination, rather than positive light or a high-pass
    // edge accent. The compose pass applies these broad radial shadow bands.
    return float4(saturate(sourceStrength * (1.0f - visibility)), 0.0f, 0.0f, 1.0f);
}
