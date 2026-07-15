sampler2D PrefilterTexture : register(s0);
sampler2D FullCoc : register(s1);

float4 ScreenData : register(c0);
float4 RadiusData : register(c6);
float4 DistantData : register(c7);
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

void AccumulateFar(
    float2 uv,
    float2 diskOffset,
    float centerCoc,
    float centerRadius,
    inout float3 colorSum,
    inout float weightSum
) {
    float2 sampleUv = saturate(uv + diskOffset * centerRadius * ScreenData.zw);
    float sampleCoc = saturate(tex2Dlod(FullCoc, float4(sampleUv, 0.0f, 0.0f)).r);
    float ringDistance = length(diskOffset) * centerRadius;
    float sampleRadius = RadiusData.y * sampleCoc;
    float coverage = saturate((sampleRadius - ringDistance + 2.0f) * 0.25f);
    float plane = saturate(1.0f - abs(sampleCoc - centerCoc) * 2.5f);
    plane *= plane;
    float radiusSquared = dot(diskOffset, diskOffset);
    float roundSpatial = saturate(1.15f - radiusSquared * 0.35f);
    float softSpatial = exp2(-radiusSquared * 1.8f);
    float spatial = lerp(
        roundSpatial,
        softSpatial,
        (DistantData.z > 0.5f) ? saturate(RadiusData.z) : 0.0f
    );
    float weight = coverage * plane * spatial;
    colorSum += tex2Dlod(PrefilterTexture, float4(sampleUv, 0.0f, 0.0f)).rgb * weight;
    weightSum += weight;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 center = tex2Dlod(PrefilterTexture, float4(input.uv, 0.0f, 0.0f));
    float centerCoc = saturate(tex2Dlod(FullCoc, float4(input.uv, 0.0f, 0.0f)).r);
    if (centerCoc <= 0.001f || RadiusData.y <= 0.001f) {
        return float4(center.rgb, centerCoc);
    }

    float2 pixel = floor(input.uv * TargetData.xy);
    float2 rotation = (DistantData.z > 0.5f) ? float2(1.0f, 0.0f) : PixelRotation(pixel);
    float centerRadius = RadiusData.y * centerCoc;
    float3 colorSum = center.rgb * 1.5f;
    float weightSum = 1.5f;
#define FAR_TAP(x, y) AccumulateFar(input.uv, Rotate(float2(x, y), rotation), centerCoc, centerRadius, colorSum, weightSum)
    FAR_TAP( 0.0000f,  0.3000f);
    FAR_TAP( 0.2598f,  0.1500f);
    FAR_TAP( 0.2598f, -0.1500f);
    FAR_TAP( 0.0000f, -0.3000f);
    FAR_TAP(-0.2598f, -0.1500f);
    FAR_TAP(-0.2598f,  0.1500f);
    FAR_TAP( 0.0000f,  0.6800f);
    FAR_TAP( 0.5889f,  0.3400f);
    FAR_TAP( 0.5889f, -0.3400f);
    FAR_TAP( 0.0000f, -0.6800f);
    FAR_TAP(-0.5889f, -0.3400f);
    FAR_TAP(-0.5889f,  0.3400f);
#if DOF_TAP_COUNT >= 16
    FAR_TAP( 0.5000f,  0.0000f);
    FAR_TAP( 0.0000f,  0.5000f);
    FAR_TAP(-0.5000f,  0.0000f);
    FAR_TAP( 0.0000f, -0.5000f);
#endif
#if DOF_TAP_COUNT >= 24
    FAR_TAP( 0.9239f,  0.3827f);
    FAR_TAP( 0.3827f,  0.9239f);
    FAR_TAP(-0.3827f,  0.9239f);
    FAR_TAP(-0.9239f,  0.3827f);
    FAR_TAP(-0.9239f, -0.3827f);
    FAR_TAP(-0.3827f, -0.9239f);
    FAR_TAP( 0.3827f, -0.9239f);
    FAR_TAP( 0.9239f, -0.3827f);
#endif
#if DOF_TAP_COUNT >= 36
    FAR_TAP( 0.8114f,  0.2174f);
    FAR_TAP( 0.5940f,  0.5940f);
    FAR_TAP( 0.2174f,  0.8114f);
    FAR_TAP(-0.2174f,  0.8114f);
    FAR_TAP(-0.5940f,  0.5940f);
    FAR_TAP(-0.8114f,  0.2174f);
    FAR_TAP(-0.8114f, -0.2174f);
    FAR_TAP(-0.5940f, -0.5940f);
    FAR_TAP(-0.2174f, -0.8114f);
    FAR_TAP( 0.2174f, -0.8114f);
    FAR_TAP( 0.5940f, -0.5940f);
    FAR_TAP( 0.8114f, -0.2174f);
#endif
    return float4(colorSum / max(weightSum, 0.0001f), centerCoc);
}
