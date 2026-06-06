sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 OptionData0 : register(c3);
float4 OptionData1 : register(c4);
float4 OptionData2 : register(c5);

static const float DepthEndpointEpsilon = 0.000001f;
static const float MinRadiusPixels = 1.0f;
static const float MinRange = 0.35f;
static const float MinBias = 0.015f;
static const float DepthBiasScale = 0.000035f;
static const float DefaultMinAmbient = 0.18f;
static const float DefaultLuminanceProtection = 0.45f;
static const float3 LuminanceFactors = float3(0.2126f, 0.7152f, 0.0722f);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float HardwareDepth(float2 uv) {
    return tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
}

bool UseReversedDepth() {
    return OptionData1.y > 0.5f;
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

float DepthDebugView(float linearDepth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    float logNear = log2(nearZ + 1.0f);
    float logFar = log2(farZ + 1.0f);
    float view = saturate((log2(linearDepth + 1.0f) - logNear) / max(logFar - logNear, 0.001f));
    return 1.0f - view;
}

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float MinAmbient() {
    if (OptionData1.z > 0.0f) {
        return clamp(OptionData1.z, 0.05f, 0.95f);
    }

    return DefaultMinAmbient;
}

float LuminanceProtection() {
    if (OptionData1.w > 0.0f) {
        return saturate(OptionData1.w);
    }

    return DefaultLuminanceProtection;
}

float Stability() {
    if (OptionData2.x > 0.0f) {
        return saturate(OptionData2.x);
    }

    return 0.65f;
}

float SoftRangeWeight(float delta, float range) {
    float softBand = lerp(0.18f, 0.65f, Stability());
    float start = range * (1.0f - softBand);
    return 1.0f - Smooth01((delta - start) / max(range - start, 0.001f));
}

float RadiusPixels(float linearDepth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    float logNear = log2(nearZ + 1.0f);
    float logFar = log2(farZ + 1.0f);
    float depthFade = saturate((log2(linearDepth + 1.0f) - logNear) / max(logFar - logNear, 0.001f));
    float baseRadius = lerp(OptionData0.z, MinRadiusPixels, depthFade);
    float radiusScale = max(OptionData0.y, 1.0f) / 128.0f;
    return clamp(baseRadius * radiusScale, MinRadiusPixels, OptionData0.z);
}

float NeighborDepthDelta(float centerDepth, float2 uv, float2 offset) {
    float rawDepth = HardwareDepth(uv + offset);
    if (!IsValidDepth(rawDepth)) {
        return 0.0f;
    }

    float linearDepth = LinearDepth(rawDepth);
    if (IsSkyDepth(rawDepth, linearDepth)) {
        return 0.0f;
    }

    return abs(centerDepth - linearDepth);
}

float EdgeFade(float centerDepth, float2 uv, float range) {
    float2 texel = ScreenData.zw;
    float delta = 0.0f;
    delta = max(delta, NeighborDepthDelta(centerDepth, uv, float2( texel.x, 0.0f)));
    delta = max(delta, NeighborDepthDelta(centerDepth, uv, float2(-texel.x, 0.0f)));
    delta = max(delta, NeighborDepthDelta(centerDepth, uv, float2(0.0f,  texel.y)));
    delta = max(delta, NeighborDepthDelta(centerDepth, uv, float2(0.0f, -texel.y)));

    float edgeWeight = SoftRangeWeight(delta, range * 1.5f);
    return lerp(0.45f, 1.0f, edgeWeight);
}

float SampleOcclusion(float centerDepth, float2 uv, float2 direction, float radiusPixels, float range, float bias) {
    float2 offset = direction * radiusPixels * ScreenData.zw;
    float rawSampleDepth = HardwareDepth(uv + offset);
    if (!IsValidDepth(rawSampleDepth)) {
        return 0.0f;
    }

    float sampleDepth = LinearDepth(rawSampleDepth);
    if (IsSkyDepth(rawSampleDepth, sampleDepth)) {
        return 0.0f;
    }

    float delta = centerDepth - sampleDepth;
    float absDelta = abs(delta);
    float depthWeight = SoftRangeWeight(absDelta, range);
    float occlusion = Smooth01((delta - bias) / max(range * 0.65f - bias, 0.001f));
    return occlusion * depthWeight * depthWeight;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 color = tex2D(SceneColor, input.uv);

    if (FrameData.w < 0.5f) {
        if (OptionData1.x > 0.5f) {
            return float4(1.0f, 0.0f, 1.0f, 1.0f);
        }
        return color;
    }

    float rawDepth = HardwareDepth(input.uv);
    if (!IsValidDepth(rawDepth)) {
        if (OptionData1.x > 0.5f) {
            return float4(0.0f, 0.0f, 1.0f, 1.0f);
        }
        return color;
    }

    float centerDepth = LinearDepth(rawDepth);
    if (IsSkyDepth(rawDepth, centerDepth)) {
        if (OptionData1.x > 0.5f) {
            return float4(0.0f, 0.0f, 0.0f, 1.0f);
        }
        return color;
    }

    if (OptionData1.x > 0.5f) {
        float depthView = DepthDebugView(centerDepth);
        return float4(depthView, depthView, depthView, 1.0f);
    }

    float passIndex = FrameData.y;
    float totalPasses = max(FrameData.z, 1.0f);
    float radiusPixels = RadiusPixels(centerDepth) * (1.0f + passIndex * 0.55f);
    float range = max(centerDepth * OptionData0.w, MinRange);
    float bias = max(centerDepth * DepthBiasScale, MinBias);
    float edgeFade = EdgeFade(centerDepth, input.uv, range);

    float occlusion = 0.0f;
    occlusion += SampleOcclusion(centerDepth, input.uv, float2( 1.0000f,  0.0000f), radiusPixels, range, bias);
    occlusion += SampleOcclusion(centerDepth, input.uv, float2(-1.0000f,  0.0000f), radiusPixels, range, bias);
    occlusion += SampleOcclusion(centerDepth, input.uv, float2( 0.0000f,  1.0000f), radiusPixels, range, bias);
    occlusion += SampleOcclusion(centerDepth, input.uv, float2( 0.0000f, -1.0000f), radiusPixels, range, bias);
    occlusion += SampleOcclusion(centerDepth, input.uv, float2( 0.7071f,  0.7071f), radiusPixels * 1.35f, range, bias);
    occlusion += SampleOcclusion(centerDepth, input.uv, float2(-0.7071f,  0.7071f), radiusPixels * 1.35f, range, bias);
    occlusion += SampleOcclusion(centerDepth, input.uv, float2( 0.7071f, -0.7071f), radiusPixels * 1.35f, range, bias);
    occlusion += SampleOcclusion(centerDepth, input.uv, float2(-0.7071f, -0.7071f), radiusPixels * 1.35f, range, bias);

    float passStrength = OptionData0.x / totalPasses;
    float luminance = dot(color.rgb, LuminanceFactors);
    float luminanceFade = saturate(1.0f - luminance * LuminanceProtection());
    float amount = saturate(occlusion * 0.22f) * passStrength * edgeFade * luminanceFade;
    float ao = max(1.0f - amount, MinAmbient());
    color.rgb *= ao;
    return color;
}
