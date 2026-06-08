sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 EnvironmentData : register(c6);
float4 OptionData3 : register(c7);
float4 SunData : register(c8);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 LuminanceFactors = float3(0.2126f, 0.7152f, 0.0722f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

bool UseReversedDepth() {
    return OptionData2.z > 0.5f;
}

bool IsInsideScreen(float2 uv) {
    return uv.x >= 0.0f && uv.y >= 0.0f && uv.x <= 1.0f && uv.y <= 1.0f;
}

float HardwareDepth(float2 uv) {
    return tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
}

float FirstPersonHardwareDepth(float2 uv) {
    return tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
}

float3 SceneSample(float2 uv) {
    return tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f)).rgb;
}

float ScreenDistance(float2 a, float2 b) {
    float aspect = max(CameraData.z, 0.1f);
    return length((a - b) * float2(aspect, 1.0f));
}

float LinearDepth(float depth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    if (UseReversedDepth()) {
        return (nearZ * farZ) / max(depth * (farZ - nearZ) + nearZ, 0.001f);
    }

    return (nearZ * farZ) / max(farZ - depth * (farZ - nearZ), 0.001f);
}

float SkyMask(float2 uv) {
    if (!IsInsideScreen(uv) || FrameData.w < 0.5f) {
        return 0.0f;
    }

    float rawDepth = HardwareDepth(uv);
    float linearDepth = LinearDepth(rawDepth);
    float farZ = max(CameraData.y, 2.0f);

    if (UseReversedDepth()) {
        float endpointSky = 1.0f - Smooth01(rawDepth / 0.000080f);
        float farSky = Smooth01((linearDepth - farZ * 0.985f) / max(farZ * 0.015f, 1.0f));
        return saturate(max(endpointSky, farSky));
    }

    float endpointSky = Smooth01((rawDepth - 0.999920f) / 0.000080f);
    float farSky = Smooth01((linearDepth - farZ * 0.985f) / max(farZ * 0.015f, 1.0f));
    return saturate(max(endpointSky, farSky));
}

float FirstPersonMask(float2 uv) {
    if (!IsInsideScreen(uv) || FrameData.w < 0.5f) {
        return 0.0f;
    }

    float depth = FirstPersonHardwareDepth(uv);
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon) ? 1.0f : 0.0f;
}

float FirstPersonBlock(float2 uv) {
    float2 texel = ScreenData.zw;
    float mask = FirstPersonMask(uv);
    mask = max(mask, FirstPersonMask(uv + float2( texel.x * 1.5f, 0.0f)));
    mask = max(mask, FirstPersonMask(uv + float2(-texel.x * 1.5f, 0.0f)));
    mask = max(mask, FirstPersonMask(uv + float2(0.0f,  texel.y * 1.5f)));
    mask = max(mask, FirstPersonMask(uv + float2(0.0f, -texel.y * 1.5f)));
    return mask * saturate(OptionData2.x);
}

float RawBrightness(float3 color) {
    float luminance = dot(color, LuminanceFactors);
    float peak = max(color.r, max(color.g, color.b));
    return max(luminance, peak * 0.72f);
}

float ShaftSourceMask(float3 color) {
    float threshold = saturate(OptionData1.z) * 0.58f;
    float brightness = RawBrightness(color);
    float broad = Smooth01((brightness - threshold) / max(1.0f - threshold, 0.001f));
    return saturate(broad);
}

float SunVisibilityAround(float2 sunUv) {
    if (!IsInsideScreen(sunUv)) {
        return 0.0f;
    }

    float radiusPixels = max(OptionData3.x, 10.0f);
    float2 stepUv = ScreenData.zw * radiusPixels;
    float center = SkyMask(sunUv);
    float s0 = SkyMask(sunUv + float2( stepUv.x, 0.0f));
    float s1 = SkyMask(sunUv + float2(-stepUv.x, 0.0f));
    float s2 = SkyMask(sunUv + float2(0.0f,  stepUv.y));
    float s3 = SkyMask(sunUv + float2(0.0f, -stepUv.y));
    float s4 = SkyMask(sunUv + float2( stepUv.x,  stepUv.y));
    float s5 = SkyMask(sunUv + float2(-stepUv.x,  stepUv.y));
    float s6 = SkyMask(sunUv + float2( stepUv.x, -stepUv.y));
    float s7 = SkyMask(sunUv + float2(-stepUv.x, -stepUv.y));
    float average = center * 0.12f + (s0 + s1 + s2 + s3) * 0.12f + (s4 + s5 + s6 + s7) * 0.10f;
    float peak = max(max(max(s0, s1), max(s2, s3)), max(max(s4, s5), max(s6, s7)));
    return saturate(max(Smooth01(average * 1.18f), peak * 0.38f));
}

float SunSource(float2 uv) {
    float visibility = SunVisibilityAround(SunData.xy);
    if (visibility <= 0.0f) {
        return 0.0f;
    }

    float distanceToSun = ScreenDistance(uv, SunData.xy);
    float coreRadius = max(OptionData3.y, 0.012f);
    float haloRadius = max(coreRadius * 4.0f, 0.080f);
    float fieldRadius = max(coreRadius * 9.0f, 0.260f);
    float core = 1.0f - Smooth01(distanceToSun / coreRadius);
    float halo = 1.0f - Smooth01(distanceToSun / haloRadius);
    float field = 1.0f - Smooth01(distanceToSun / fieldRadius);
    float sceneSource = ShaftSourceMask(SceneSample(uv));
    return visibility * saturate(core * 0.88f + halo * 0.42f + field * 0.24f + sceneSource * 0.035f);
}

float4 Main(PixelInput input) : COLOR0 {
    float sky = SkyMask(input.uv);
    float firstPerson = FirstPersonBlock(input.uv);
    float pathOpen = sky * (1.0f - firstPerson);
    float source = SunSource(input.uv);

    return float4(source, pathOpen, firstPerson, 1.0f);
}
