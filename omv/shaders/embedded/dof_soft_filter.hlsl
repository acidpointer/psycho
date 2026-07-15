sampler2D SourceTexture : register(s0);

float4 FilterData : register(c9);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

void Accumulate(
    float2 uv,
    float baseWeight,
    float centerCoc,
    bool nearLayer,
    inout float4 valueSum,
    inout float weightSum
) {
    float4 value = tex2Dlod(SourceTexture, float4(saturate(uv), 0.0f, 0.0f));
    float compatibility = nearLayer
        ? 1.0f
        : max(saturate(1.0f - abs(value.a - centerCoc) * 3.0f), 0.04f);
    compatibility *= compatibility;
    float weight = baseWeight * compatibility;
    valueSum += value * weight;
    weightSum += weight;
}

float4 Main(PixelInput input) : COLOR0 {
    bool nearLayer = FilterData.z > 0.5f;
    float2 offset = FilterData.xy;
    float4 center = tex2Dlod(SourceTexture, float4(input.uv, 0.0f, 0.0f));
    if (center.a <= 0.001f) {
        return center;
    }
    float4 valueSum = center * 4.0f;
    float weightSum = 4.0f;
    Accumulate(input.uv + float2( offset.x, 0.0f), 1.0f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(-offset.x, 0.0f), 1.0f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(0.0f,  offset.y), 1.0f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(0.0f, -offset.y), 1.0f, center.a, nearLayer, valueSum, weightSum);
#if DOF_SOFT_TAP_COUNT >= 9
    Accumulate(input.uv + float2( offset.x,  offset.y), 0.75f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(-offset.x,  offset.y), 0.75f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2( offset.x, -offset.y), 0.75f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(-offset.x, -offset.y), 0.75f, center.a, nearLayer, valueSum, weightSum);
#endif
#if DOF_SOFT_TAP_COUNT >= 13
    Accumulate(input.uv + float2( offset.x * 2.0f, 0.0f), 0.35f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(-offset.x * 2.0f, 0.0f), 0.35f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(0.0f,  offset.y * 2.0f), 0.35f, center.a, nearLayer, valueSum, weightSum);
    Accumulate(input.uv + float2(0.0f, -offset.y * 2.0f), 0.35f, center.a, nearLayer, valueSum, weightSum);
#endif
    float4 result = valueSum / max(weightSum, 0.0001f);
    if (!nearLayer) {
        result.a = center.a;
    }
    return result;
}
