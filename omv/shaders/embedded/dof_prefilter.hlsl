sampler2D SceneColor : register(s0);
sampler2D FullCoc : register(s1);

float4 ScreenData : register(c0);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float3 ToLinear(float3 color) {
    return color * (color * (color * 0.305306011f + 0.682171111f) + 0.012522878f);
}

float CocWeight(float centerCoc, float sampleCoc) {
    float difference = abs(sampleCoc - centerCoc);
    float samePlane = saturate(1.0f - difference * 3.5f);
    samePlane *= samePlane;
    bool oppositeNearPlane = (centerCoc < -0.001f) != (sampleCoc < -0.001f);
    return oppositeNearPlane ? samePlane * 0.04f : max(samePlane, 0.08f);
}

void Accumulate(
    float2 uv,
    float centerCoc,
    float baseWeight,
    inout float3 colorSum,
    inout float weightSum
) {
    uv = saturate(uv);
    float sampleCoc = tex2Dlod(FullCoc, float4(uv, 0.0f, 0.0f)).r;
    float weight = baseWeight * CocWeight(centerCoc, sampleCoc);
    colorSum += ToLinear(tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f)).rgb) * weight;
    weightSum += weight;
}

float4 Main(PixelInput input) : COLOR0 {
    float centerCoc = tex2Dlod(FullCoc, float4(input.uv, 0.0f, 0.0f)).r;
    float2 offset = ScreenData.zw * 0.5f;
    float3 colorSum = 0.0f;
    float weightSum = 0.0f;
    Accumulate(input.uv, centerCoc, 2.0f, colorSum, weightSum);
    Accumulate(input.uv + float2(-offset.x, -offset.y), centerCoc, 1.0f, colorSum, weightSum);
    Accumulate(input.uv + float2( offset.x, -offset.y), centerCoc, 1.0f, colorSum, weightSum);
    Accumulate(input.uv + float2(-offset.x,  offset.y), centerCoc, 1.0f, colorSum, weightSum);
    Accumulate(input.uv + float2( offset.x,  offset.y), centerCoc, 1.0f, colorSum, weightSum);
    return float4(colorSum / max(weightSum, 0.0001f), centerCoc);
}
