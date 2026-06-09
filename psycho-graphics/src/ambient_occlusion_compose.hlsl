sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);
sampler2D AOTexture : register(s4);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 FastOption0 : register(c3);
float4 FastOption1 : register(c4);
float4 FastOption2 : register(c5);
float4 EnvironmentData : register(c6);
float4 ContactOption0 : register(c7);
float4 ContactOption1 : register(c8);
float4 ContactOption2 : register(c9);
float4 EffectData : register(c10);

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
    return FastOption1.y > 0.5f || ContactOption1.y > 0.5f;
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

bool IsValidDepth(float depth) {
    if (UseReversedDepth()) {
        return depth >= 0.0f && depth <= 1.0f;
    }

    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float LinearDepth(float depth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    if (UseReversedDepth()) {
        return (nearZ * farZ) / max(depth * (farZ - nearZ) + nearZ, 0.001f);
    }

    return (nearZ * farZ) / max(farZ - depth * (farZ - nearZ), 0.001f);
}

bool IsSkyDepth(float rawDepth, float linearDepth) {
    float farZ = max(CameraData.y, 2.0f);
    if (UseReversedDepth()) {
        return rawDepth <= DepthEndpointEpsilon || linearDepth >= farZ * 0.995f;
    }

    return rawDepth >= (1.0f - DepthEndpointEpsilon) || linearDepth >= farZ * 0.995f;
}

float DepthKey(float linearDepth) {
    float farZ = max(CameraData.y, 2.0f);
    return saturate(log2(linearDepth + 1.0f) / max(log2(farZ + 1.0f), 0.001f));
}

float DepthDebugView(float linearDepth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    float logNear = log2(nearZ + 1.0f);
    float logFar = log2(farZ + 1.0f);
    float view = saturate((log2(linearDepth + 1.0f) - logNear) / max(logFar - logNear, 0.001f));
    return 1.0f - view;
}

bool FirstPersonMaskEnabled() {
    return FrameData.z > 0.5f && (FastOption2.y > 0.5f || ContactOption2.x > 0.5f);
}

bool IsFirstPersonPixel(float2 uv) {
    if (!IsInsideScreen(uv) || !FirstPersonMaskEnabled()) {
        return false;
    }

    float depth = FirstPersonHardwareDepth(uv);
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float FogFadeAmount() {
    return saturate(max(FastOption2.z, ContactOption2.y));
}

float FogAoVisibility(float linearDepth) {
    float amount = FogFadeAmount();
    if (amount <= 0.0f || EnvironmentData.w < 0.5f) {
        return 1.0f;
    }

    float fogStart = EnvironmentData.x;
    float fogEnd = EnvironmentData.y;
    if (fogEnd <= fogStart || fogEnd <= 0.0f) {
        return 1.0f;
    }

    float fogPower = max(EnvironmentData.z, 0.001f);
    float fogT = saturate((linearDepth - fogStart) / max(fogEnd - fogStart, 0.001f));
    float fogAlpha = max(pow(fogT, fogPower), Smooth01(fogT));
    float visibility = 1.0f - Smooth01(saturate((fogAlpha - 0.05f) / 0.80f));
    return lerp(1.0f, visibility, amount);
}

float MinAmbient() {
    float fastStrength = max(FastOption0.x, 0.0f);
    float contactStrength = max(ContactOption0.x, 0.0f);
    float fastMin = FastOption1.z > 0.0f ? FastOption1.z : 0.18f;
    float contactMin = ContactOption1.z > 0.0f ? ContactOption1.z : 0.67f;

    if (fastStrength > 0.0f && contactStrength > 0.0f) {
        return clamp(min(fastMin, contactMin), 0.05f, 0.95f);
    }
    if (contactStrength > 0.0f) {
        return clamp(contactMin, 0.05f, 0.95f);
    }
    return clamp(fastMin, 0.05f, 0.95f);
}

float2 ClampAoUv(float2 uv) {
    float2 halfTexel = EffectData.xy * 0.5f;
    return clamp(uv, halfTexel, 1.0f - halfTexel);
}

float2 AccumulateAo(float2 uv, float centerKey, float spatialWeight) {
    float4 sample = tex2Dlod(AOTexture, float4(ClampAoUv(uv), 0.0f, 0.0f));
    float depthWeight = saturate(1.0f - abs(sample.g - centerKey) * 52.0f);
    depthWeight *= depthWeight;
    float weight = spatialWeight * depthWeight;
    return float2(saturate(sample.r) * weight, weight);
}

float ResolveAo(float2 uv, float centerKey) {
    float2 aoTexel = max(EffectData.xy, ScreenData.zw);
    float2 aoPixel = uv / aoTexel - 0.5f;
    float2 basePixel = floor(aoPixel);
    float2 blend = saturate(aoPixel - basePixel);

    float2 uv00 = (basePixel + float2(0.5f, 0.5f)) * aoTexel;
    float2 uv10 = (basePixel + float2(1.5f, 0.5f)) * aoTexel;
    float2 uv01 = (basePixel + float2(0.5f, 1.5f)) * aoTexel;
    float2 uv11 = (basePixel + float2(1.5f, 1.5f)) * aoTexel;

    float2 sum = 0.0f;
    sum += AccumulateAo(uv00, centerKey, (1.0f - blend.x) * (1.0f - blend.y));
    sum += AccumulateAo(uv10, centerKey, blend.x * (1.0f - blend.y));
    sum += AccumulateAo(uv01, centerKey, (1.0f - blend.x) * blend.y);
    sum += AccumulateAo(uv11, centerKey, blend.x * blend.y);

    return sum.y > 0.0001f ? saturate(sum.x / sum.y) : 0.0f;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 color = tex2D(SceneColor, input.uv);

    if (FrameData.w < 0.5f) {
        if (FastOption1.x > 0.5f) {
            return float4(1.0f, 0.0f, 1.0f, 1.0f);
        }
        return color;
    }

    if (IsFirstPersonPixel(input.uv)) {
        return color;
    }

    float rawDepth = HardwareDepth(input.uv);
    if (!IsValidDepth(rawDepth)) {
        if (FastOption1.x > 0.5f) {
            return float4(0.0f, 0.0f, 1.0f, 1.0f);
        }
        return color;
    }

    float centerDepth = LinearDepth(rawDepth);
    if (IsSkyDepth(rawDepth, centerDepth)) {
        if (FastOption1.x > 0.5f) {
            return float4(0.0f, 0.0f, 0.0f, 1.0f);
        }
        return color;
    }

    if (FastOption1.x > 0.5f) {
        float depthView = DepthDebugView(centerDepth);
        return float4(depthView, depthView, depthView, 1.0f);
    }

    float centerKey = DepthKey(centerDepth);
    float aoAmount = ResolveAo(input.uv, centerKey);

    float lumaProtect = FastOption1.w > 0.0f ? FastOption1.w : 0.45f;
    float luminance = dot(color.rgb, LuminanceFactors);
    float luminanceFade = saturate(1.0f - luminance * lumaProtect);
    float amount = aoAmount * luminanceFade * FogAoVisibility(centerDepth);
    float ao = max(1.0f - amount, MinAmbient());
    color.rgb *= ao;
    return color;
}
