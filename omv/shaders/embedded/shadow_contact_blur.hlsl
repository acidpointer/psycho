// One-pass depth-aware cross filter for exterior contact visibility.
float4 ScreenData : register(c0);
sampler2D ContactMap : register(s0);

struct PixelInput { float2 uv : TEXCOORD0; };

float2 WeightedTap(float2 uv, float centerDepth, float weight) {
    float2 sampleValue = tex2Dlod(ContactMap, float4(uv, 0.0f, 0.0f)).rg;
    float sampleDepth = sampleValue.g;
    // Match the temporal and final-composite ownership tolerance. A broad
    // twenty-unit filter admitted unrelated wall/foreground evidence as a
    // moving dark line even though the center depth itself stayed valid.
    float accepted = abs(sampleDepth - centerDepth) <= max(2.0f, centerDepth * 0.0025f);
    return float2(sampleValue.r * weight * accepted, weight * accepted);
}

float4 Main(PixelInput input) : COLOR0 {
    float2 center = tex2Dlod(ContactMap, float4(input.uv, 0.0f, 0.0f)).rg;
    if (center.g <= 0.0f) return float4(1.0f, 0.0f, 0.0f, 1.0f);
    float2 sum = float2(center.r * 0.40f, 0.40f);
    sum += WeightedTap(input.uv + float2(ScreenData.z, 0.0f), center.g, 0.15f);
    sum += WeightedTap(input.uv - float2(ScreenData.z, 0.0f), center.g, 0.15f);
    sum += WeightedTap(input.uv + float2(0.0f, ScreenData.w), center.g, 0.15f);
    sum += WeightedTap(input.uv - float2(0.0f, ScreenData.w), center.g, 0.15f);
    return float4(sum.x / max(sum.y, 0.0001f), center.g, 0.0f, 1.0f);
}
