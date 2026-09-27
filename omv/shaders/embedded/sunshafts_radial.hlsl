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

static const int SampleCount = 32;
// The marched distance, total extinction, and weight ramp must stay matched
// to the audited 48-step reference equation (48/32 = 1.5). Fewer, longer
// steps apply the per-step decay factor to the 1.5 power (f^1.5, written as
// f * sqrt(f)), and the weight ramp grows by 1.014^1.5, so the 32-step march
// integrates the same underlying shaft with coarser sampling rather than a
// shorter or brighter one. The deterministic reference test in sunshafts.rs
// bounds the discretization difference against the 48-step model.
static const float WeightStep = 1.021193f;
// The march has no per-step length factor, so the reduced march renormalizes
// its sum by the step-count ratio; without it, a constant mask would darken
// by exactly 48/32.
static const float StepScale = 1.5f;

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

    float density = max(OptionData0.w, 0.10f);
    float decay = clamp(OptionData0.z, 0.55f, 1.04f);
    float occlusionSoftness = saturate(OptionData3.w);
    float blockedDecay = lerp(0.10f, 0.34f, occlusionSoftness);
    float2 delta = (SunData.xy - input.uv) * density / SampleCount;
    float2 sampleUv = input.uv + delta * InterleavedNoise(input.uv);

    float illumination = 1.0f;
    float light = 0.0f;
    float weight = 0.024f;

    [loop]
    for (int i = 0; i < SampleCount; ++i) {
        sampleUv += delta;
        float2 insideMin = step(0.0f, sampleUv);
        float2 insideMax = step(sampleUv, 1.0f);
        float inside = insideMin.x * insideMin.y * insideMax.x * insideMax.y;
        float2 mask = tex2Dlod(ShaftMask, float4(sampleUv, 0.0f, 0.0f)).rg;
        float source = mask.r * inside;
        float pathOpen = mask.g * inside;
        float decayFactor = lerp(blockedDecay, decay, pathOpen);
        illumination *= decayFactor * sqrt(decayFactor);
        float softenedOpen = saturate(pathOpen + occlusionSoftness * 0.10f);
        light += source * softenedOpen * illumination * weight;
        weight *= WeightStep;
    }

    return float4(saturate(light * 2.70f * StepScale), 0.0f, 0.0f, 1.0f);
}
