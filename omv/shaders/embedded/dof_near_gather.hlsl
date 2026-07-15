sampler2D PrefilterTexture : register(s0);
sampler2D DilatedNearCoc : register(s1);
sampler2D FullCoc : register(s2);

float4 ScreenData : register(c0);
float4 RadiusData : register(c6);
float4 TargetData : register(c8);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float2 Rotate(float2 value, float2 rotation) {
    return float2(
        value.x * rotation.x - value.y * rotation.y,
        value.x * rotation.y + value.y * rotation.x
    );
}

float2 PixelRotation(float2 pixel) {
    float2 value = frac(float2(
        dot(pixel, float2(0.06711056f, 0.00583715f)),
        dot(pixel, float2(0.75487766f, 0.56984030f))
    )) * 2.0f - 1.0f;
    return value * rsqrt(max(dot(value, value), 0.0001f));
}

void AccumulateNear(
    float2 uv,
    float2 diskOffset,
    float centerRadius,
    inout float3 colorSum,
    inout float nearWeightSum,
    inout float spatialWeightSum
) {
    float2 sampleUv = saturate(uv + diskOffset * centerRadius * ScreenData.zw);
    float nearCoc = saturate(-tex2Dlod(FullCoc, float4(sampleUv, 0.0f, 0.0f)).r);
    float ringDistance = length(diskOffset) * centerRadius;
    float sampleRadius = RadiusData.x * nearCoc;
    float coverage = saturate((sampleRadius - ringDistance + 2.0f) * 0.25f);
    float spatial = saturate(1.15f - dot(diskOffset, diskOffset) * 0.35f);
    float weight = coverage * nearCoc * spatial;
    colorSum += tex2Dlod(PrefilterTexture, float4(sampleUv, 0.0f, 0.0f)).rgb * weight;
    nearWeightSum += weight;
    spatialWeightSum += spatial;
}

float4 Main(PixelInput input) : COLOR0 {
    float dilatedCoc = tex2Dlod(DilatedNearCoc, float4(input.uv, 0.0f, 0.0f)).r;
    if (dilatedCoc <= 0.001f || RadiusData.x <= 0.001f) {
        return 0.0f;
    }

    float2 pixel = floor(input.uv * TargetData.xy);
    float2 rotation = PixelRotation(pixel);
    float centerRadius = RadiusData.x * dilatedCoc;
    float centerNear = saturate(-tex2Dlod(FullCoc, float4(input.uv, 0.0f, 0.0f)).r);
    float centerWeight = centerNear * 1.5f;
    float3 centerColor = tex2Dlod(PrefilterTexture, float4(input.uv, 0.0f, 0.0f)).rgb;
    float3 colorSum = centerColor * centerWeight;
    float nearWeightSum = centerWeight;
    float spatialWeightSum = 1.5f;
#define NEAR_TAP(x, y) AccumulateNear(input.uv, Rotate(float2(x, y), rotation), centerRadius, colorSum, nearWeightSum, spatialWeightSum)
    NEAR_TAP( 0.0000f,  0.3000f);
    NEAR_TAP( 0.2598f,  0.1500f);
    NEAR_TAP( 0.2598f, -0.1500f);
    NEAR_TAP( 0.0000f, -0.3000f);
    NEAR_TAP(-0.2598f, -0.1500f);
    NEAR_TAP(-0.2598f,  0.1500f);
    NEAR_TAP( 0.0000f,  0.6800f);
    NEAR_TAP( 0.5889f,  0.3400f);
    NEAR_TAP( 0.5889f, -0.3400f);
    NEAR_TAP( 0.0000f, -0.6800f);
    NEAR_TAP(-0.5889f, -0.3400f);
    NEAR_TAP(-0.5889f,  0.3400f);
#if DOF_TAP_COUNT >= 16
    NEAR_TAP( 0.5000f,  0.0000f);
    NEAR_TAP( 0.0000f,  0.5000f);
    NEAR_TAP(-0.5000f,  0.0000f);
    NEAR_TAP( 0.0000f, -0.5000f);
#endif
#if DOF_TAP_COUNT >= 24
    NEAR_TAP( 0.9239f,  0.3827f);
    NEAR_TAP( 0.3827f,  0.9239f);
    NEAR_TAP(-0.3827f,  0.9239f);
    NEAR_TAP(-0.9239f,  0.3827f);
    NEAR_TAP(-0.9239f, -0.3827f);
    NEAR_TAP(-0.3827f, -0.9239f);
    NEAR_TAP( 0.3827f, -0.9239f);
    NEAR_TAP( 0.9239f, -0.3827f);
#endif
    if (nearWeightSum <= 0.0001f) {
        return 0.0f;
    }
    float coverage = saturate(nearWeightSum / max(spatialWeightSum, 0.0001f) * 2.8f);
    float3 color = colorSum / nearWeightSum;
    return float4(color * coverage, coverage);
}
