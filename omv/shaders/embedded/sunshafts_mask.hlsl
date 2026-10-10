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
float4 NativeSunData : register(c10);
float4 DepthData : register(c11);

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
	return DepthData.x >= 0.0f ? DepthData.x > 0.5f : OptionData2.z > 0.5f;
}

float HardwareDepth(float2 uv) {
    return tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
}

float FirstPersonHardwareDepth(float2 uv) {
    return tex2Dlod(FirstPersonDepth, float4(uv, 0.0f, 0.0f)).r;
}

float NativeSunStrength() {
    float3 color = max(NativeSunData.rgb, 0.0f);
    float luminance = dot(color, LuminanceFactors);
    float peak = max(color.r, max(color.g, color.b));
    float brightness = max(luminance, peak * 0.72f);
    float response = lerp(0.02f, 0.75f, saturate(OptionData1.z));
    return Smooth01(brightness / max(brightness + response, 0.001f));
}

// Vector arithmetic reduces four coverage texels together without four
// copies of depth reconstruction or uniform first-person admission branches.
float4 SkyCoverage(float4 rawDepth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    float4 linearDepth;
    float4 endpoint;
    if (UseReversedDepth()) {
        linearDepth = (nearZ * farZ) / max(rawDepth * (farZ - nearZ) + nearZ, 0.001f);
        float4 t = saturate(rawDepth / 0.000080f);
        endpoint = 1.0f - t * t * (3.0f - 2.0f * t);
    } else {
        linearDepth = (nearZ * farZ) / max(farZ - rawDepth * (farZ - nearZ), 0.001f);
        float4 t = saturate((rawDepth - 0.999920f) / 0.000080f);
        endpoint = t * t * (3.0f - 2.0f * t);
    }
    float4 t = saturate((linearDepth - farZ * 0.985f) / max(farZ * 0.015f, 1.0f));
    return saturate(max(endpoint, t * t * (3.0f - 2.0f * t))) * step(0.5f, FrameData.w);
}

float4 Main(PixelInput input) : COLOR0 {
    // Point-sampled 2x2 source texels preserve fractional opening coverage.
    float2 offset = ScreenData.zw * 0.5f;
    float2 a = input.uv + float2(-offset.x, -offset.y);
    float2 b = input.uv + float2( offset.x, -offset.y);
    float2 c = input.uv + float2(-offset.x,  offset.y);
    float2 d = input.uv + float2( offset.x,  offset.y);
    float4 first = 0.0f;
    float requested = saturate(OptionData2.x);
    if (requested > 0.0f && DepthData.z > 0.5f) {
        first = 1.0f;
        if (DepthData.w > 0.5f) {
            float4 depth = float4(FirstPersonHardwareDepth(a), FirstPersonHardwareDepth(b), FirstPersonHardwareDepth(c), FirstPersonHardwareDepth(d));
            first = float4(depth > DepthEndpointEpsilon) * float4(depth < 1.0f - DepthEndpointEpsilon) * requested;
        }
    }
    float4 sky = SkyCoverage(float4(HardwareDepth(a), HardwareDepth(b), HardwareDepth(c), HardwareDepth(d)));
    float pathOpen = dot(sky * (1.0f - first), 0.25f);
    float source = pathOpen * NativeSunStrength() * saturate(SunData.w);
    return float4(source, pathOpen, dot(first, 0.25f), 1.0f);
}
