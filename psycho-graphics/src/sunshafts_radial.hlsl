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

static const int SampleCount = 48;

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float InterleavedNoise(float2 uv) {
    float2 pixel = floor(uv * ScreenData.xy);
    return frac(52.9829189f * frac(dot(pixel + FrameData.xx, float2(0.06711056f, 0.00583715f))));
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
        float2 mask = tex2Dlod(ShaftMask, float4(sampleUv, 0.0f, 0.0f)).rg;
        float source = mask.r;
        float pathOpen = mask.g;
        illumination *= lerp(blockedDecay, decay, pathOpen);
        float softenedOpen = saturate(pathOpen + occlusionSoftness * 0.10f);
        light += source * softenedOpen * illumination * weight;
        weight *= 1.014f;
    }

    return float4(saturate(light * 2.70f), 0.0f, 0.0f, 1.0f);
}
