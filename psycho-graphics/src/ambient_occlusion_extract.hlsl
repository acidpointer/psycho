sampler2D SceneDepth : register(s1);
sampler2D FirstPersonDepth : register(s2);

float4 ScreenData : register(c0);
float4 FrameData : register(c1);
float4 CameraData : register(c2);
float4 FastOption0 : register(c3);
float4 FastOption1 : register(c4);
float4 FastOption2 : register(c5);
float4 ContactOption0 : register(c7);
float4 ContactOption1 : register(c8);
float4 ContactOption2 : register(c9);

static const float DepthEndpointEpsilon = 0.000001f;
static const float MinFastRadiusPixels = 1.0f;
static const float MinFastRange = 0.35f;
static const float MinFastBias = 0.015f;
static const float FastDepthBiasScale = 0.000035f;
static const float MinContactRange = 0.08f;
static const float MinContactBias = 0.01f;

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

bool FirstPersonMaskEnabled() {
    return FastOption2.y > 0.5f || ContactOption2.x > 0.5f;
}

bool IsFirstPersonPixel(float2 uv) {
    if (!FirstPersonMaskEnabled()) {
        return false;
    }

    float depth = FirstPersonHardwareDepth(uv);
    return depth > DepthEndpointEpsilon && depth < (1.0f - DepthEndpointEpsilon);
}

float DepthKey(float linearDepth) {
    float farZ = max(CameraData.y, 2.0f);
    return saturate(log2(linearDepth + 1.0f) / max(log2(farZ + 1.0f), 0.001f));
}

float Stability() {
    float fastStability = FastOption2.x > 0.0f ? FastOption2.x : 0.65f;
    float contactStability = ContactOption1.w > 0.0f ? ContactOption1.w : 0.63f;
    return saturate(max(fastStability, contactStability));
}

float SoftRangeWeight(float delta, float range) {
    float softBand = lerp(0.22f, 0.72f, Stability());
    float start = range * (1.0f - softBand);
    return 1.0f - Smooth01((delta - start) / max(range - start, 0.001f));
}

float FastRadiusPixels(float linearDepth) {
    float nearZ = max(CameraData.x, 0.01f);
    float farZ = max(CameraData.y, nearZ + 1.0f);
    float logNear = log2(nearZ + 1.0f);
    float logFar = log2(farZ + 1.0f);
    float depthFade = saturate((log2(linearDepth + 1.0f) - logNear) / max(logFar - logNear, 0.001f));
    float maxRadius = max(FastOption0.z, MinFastRadiusPixels);
    float baseRadius = lerp(maxRadius, MinFastRadiusPixels, depthFade);
    float radiusScale = max(FastOption0.y, 1.0f) / 128.0f;
    return clamp(baseRadius * radiusScale, MinFastRadiusPixels, maxRadius);
}

float2 SampleOcclusionPair(float centerDepth, float2 uv, float2 direction, float fastRadius, float fastRange, float fastBias, float contactRadius, float contactRange, float contactBias) {
    float sampleRadius = max(fastRadius, contactRadius);
    float2 sampleUv = uv + direction * sampleRadius * ScreenData.zw;
    float rawSampleDepth = HardwareDepth(sampleUv);
    if (!IsValidDepth(rawSampleDepth)) {
        return float2(0.0f, 0.0f);
    }

    float sampleDepth = LinearDepth(rawSampleDepth);
    if (IsSkyDepth(rawSampleDepth, sampleDepth) || IsFirstPersonPixel(sampleUv)) {
        return float2(0.0f, 0.0f);
    }

    float delta = centerDepth - sampleDepth;
    float absDelta = abs(delta);
    float fastWeight = SoftRangeWeight(absDelta, fastRange);
    float fast = Smooth01((delta - fastBias) / max(fastRange * 0.65f - fastBias, 0.001f)) * fastWeight * fastWeight;

    if (delta <= 0.0f) {
        return float2(fast, 0.0f);
    }

    float contactWeight = SoftRangeWeight(delta, contactRange);
    float contact = Smooth01((delta - contactBias) / max(contactRange * 0.6f - contactBias, 0.001f)) * contactWeight;
    return float2(fast, contact);
}

float4 Main(PixelInput input) : COLOR0 {
    if (FrameData.w < 0.5f) {
        return float4(0.0f, 1.0f, 0.0f, 1.0f);
    }

    if (IsFirstPersonPixel(input.uv)) {
        return float4(0.0f, 1.0f, 0.0f, 1.0f);
    }

    float rawDepth = HardwareDepth(input.uv);
    if (!IsValidDepth(rawDepth)) {
        return float4(0.0f, 1.0f, 0.0f, 1.0f);
    }

    float centerDepth = LinearDepth(rawDepth);
    if (IsSkyDepth(rawDepth, centerDepth)) {
        return float4(0.0f, 1.0f, 0.0f, 1.0f);
    }

    float fastStrength = max(FastOption0.x, 0.0f);
    float contactStrength = max(ContactOption0.x, 0.0f);
    if (fastStrength <= 0.0f && contactStrength <= 0.0f) {
        return float4(0.0f, DepthKey(centerDepth), 0.0f, 1.0f);
    }

    float fastRadius = FastRadiusPixels(centerDepth);
    float fastRange = max(centerDepth * FastOption0.w, MinFastRange);
    float fastBias = max(centerDepth * FastDepthBiasScale, MinFastBias);

    float contactRadius = max(ContactOption0.y, 0.5f);
    float contactRange = max(centerDepth * ContactOption0.z, MinContactRange);
    float contactBias = max(centerDepth * ContactOption0.w, MinContactBias);

    float2 occlusion = 0.0f;
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2( 1.0000f,  0.0000f), fastRadius, fastRange, fastBias, contactRadius, contactRange, contactBias);
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2(-1.0000f,  0.0000f), fastRadius, fastRange, fastBias, contactRadius, contactRange, contactBias);
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2( 0.0000f,  1.0000f), fastRadius, fastRange, fastBias, contactRadius, contactRange, contactBias);
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2( 0.0000f, -1.0000f), fastRadius, fastRange, fastBias, contactRadius, contactRange, contactBias);
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2( 0.7071f,  0.7071f), fastRadius * 1.35f, fastRange, fastBias, contactRadius * 1.35f, contactRange, contactBias);
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2(-0.7071f,  0.7071f), fastRadius * 1.35f, fastRange, fastBias, contactRadius * 1.35f, contactRange, contactBias);
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2( 0.7071f, -0.7071f), fastRadius * 1.35f, fastRange, fastBias, contactRadius * 1.35f, contactRange, contactBias);
    occlusion += SampleOcclusionPair(centerDepth, input.uv, float2(-0.7071f, -0.7071f), fastRadius * 1.35f, fastRange, fastBias, contactRadius * 1.35f, contactRange, contactBias);

    float amount = saturate(occlusion.x * 0.22f) * fastStrength;
    amount += saturate(occlusion.y * 0.125f) * contactStrength;
    return float4(saturate(amount), DepthKey(centerDepth), 0.0f, 1.0f);
}
