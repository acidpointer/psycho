sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);
sampler2D ShaftLight : register(s4);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);
float4 EnvironmentData : register(c6);
float4 OptionData3 : register(c7);
float4 SunData : register(c8);
float4 EffectData : register(c9);

static const float DepthEndpointEpsilon = 0.000001f;
static const float3 WarmTint = float3(1.0f, 0.80f, 0.46f);
static const float3 DayTint = float3(1.0f, 0.94f, 0.80f);

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

bool DebugMask() {
    return OptionData2.w > 0.5f;
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

float FogAlpha(float linearDepth) {
    if (EnvironmentData.w < 0.5f) {
        return 0.0f;
    }

    float fogStart = EnvironmentData.x;
    float fogEnd = EnvironmentData.y;
    if (fogEnd <= fogStart || fogEnd <= 0.0f) {
        return 0.0f;
    }

    float fogPower = max(EnvironmentData.z, 0.001f);
    float fogT = saturate((linearDepth - fogStart) / max(fogEnd - fogStart, 0.001f));
    return max(pow(fogT, fogPower), Smooth01(fogT));
}

float ReceiverMask(float2 uv) {
    if (FirstPersonBlock(uv) > 0.0f) {
        return 0.0f;
    }

    float sky = SkyMask(uv);
    if (sky > 0.0f) {
        return sky;
    }

    float linearDepth = LinearDepth(HardwareDepth(uv));
    return saturate(FogAlpha(linearDepth) * 0.16f);
}

float SunVisibilityAround(float2 sunUv) {
    if (!IsInsideScreen(sunUv)) {
        return 0.0f;
    }

    float radiusPixels = max(OptionData3.x, 12.0f);
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
    float average = center * 0.08f + (s0 + s1 + s2 + s3) * 0.13f + (s4 + s5 + s6 + s7) * 0.10f;
    float peak = max(max(max(s0, s1), max(s2, s3)), max(max(s4, s5), max(s6, s7)));
    return saturate(max(Smooth01(average * 1.16f), peak * 0.34f));
}

float DistanceShape(float screenDistance) {
    float range = max(OptionData2.y, 0.08f);
    float nearFade = Smooth01(screenDistance / max(OptionData3.y * 0.65f, 0.008f));
    float farFade = 1.0f - Smooth01(screenDistance / range);
    return nearFade * farFade;
}

float ExposureCurve(float amount) {
    amount = max(amount, 0.0f);
    return amount / (1.0f + amount * 1.25f);
}

float SunCoreRepair(float2 uv, float visibility) {
    if (FirstPersonBlock(uv) > 0.0f) {
        return 0.0f;
    }

    float radius = max(OptionData3.y * 0.60f, 0.010f);
    float core = 1.0f - Smooth01(ScreenDistance(uv, SunData.xy) / radius);
    return core * core * visibility;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 color = tex2D(SceneColor, input.uv);
    if (SunData.z <= 0.5f || OptionData0.x <= 0.0f || OptionData0.y <= 0.0f || OptionData1.x <= 0.0f) {
        return color;
    }

    float visibility = SunVisibilityAround(SunData.xy);
    float receiver = ReceiverMask(input.uv);
    float shaft = tex2Dlod(ShaftLight, float4(input.uv, 0.0f, 0.0f)).r;
    float screenDistance = ScreenDistance(input.uv, SunData.xy);
    float distanceShape = DistanceShape(screenDistance);

    if (DebugMask()) {
        return float4(visibility, receiver, shaft, 1.0f);
    }

    float force = clamp(OptionData1.x, 0.0f, 4.0f);
    float rawAmount = shaft * visibility * receiver * distanceShape;
    rawAmount *= max(OptionData0.x, 0.0f) * max(OptionData0.y, 0.0f) * force * 2.35f;
    float shaftAmount = min(ExposureCurve(rawAmount), 0.46f);
    float repairMask = SunCoreRepair(input.uv, visibility);
    float repairAmount = min(repairMask * force * 0.24f, 0.18f);

    float warmth = saturate(OptionData1.w);
    float3 tint = lerp(DayTint, WarmTint, warmth);
    float3 composed = color.rgb + tint * shaftAmount * (1.0f - color.rgb * 0.55f);
    composed += tint * repairAmount * (1.0f - color.rgb * 0.30f);
    composed = lerp(composed, max(composed, tint * 0.88f), saturate(repairMask * visibility * 0.36f));

    return float4(saturate(composed), color.a);
}
