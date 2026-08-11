// Depth-aware separable filter for the exterior contact-shadow visibility.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 BlurControl : register(c6); // x reversed depth, yz filter direction
sampler2D ContactMap : register(s0);
sampler2D SceneDepth : register(s1);

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (BlurControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float2 WeightedTap(float2 uv, float centerDepth, float weight) {
    float sampleDepth = LinearDepth(tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r);
    float accepted = abs(sampleDepth - centerDepth) <= max(20.0f, centerDepth * 0.02f);
    return float2(tex2Dlod(ContactMap, float4(uv, 0.0f, 0.0f)).r * weight * accepted,
        weight * accepted);
}

float4 Main(PixelInput input) : COLOR0 {
    float centerDepth = LinearDepth(tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r);
    float2 stepUv = BlurControl.yz * ScreenData.zw;
    float2 sum = 0.0f;
    [loop]
    for (int tap = -2; tap <= 2; ++tap) {
        int distance = abs(tap);
        float weight = distance == 0 ? 0.40f : (distance == 1 ? 0.24f : 0.06f);
        sum += WeightedTap(input.uv + stepUv * tap, centerDepth, weight);
    }
    return float4(sum.x / max(sum.y, 0.0001f), 0.0f, 0.0f, 1.0f);
}
