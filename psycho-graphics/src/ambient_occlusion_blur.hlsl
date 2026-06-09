sampler2D AOInput : register(s0);

float4 EffectData : register(c10);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float2 WeightedSample(float2 uv, float centerDepth, float weight, float sharpness) {
    float4 sample = tex2D(AOInput, uv);
    float depthWeight = saturate(1.0f - abs(sample.g - centerDepth) * sharpness);
    depthWeight *= depthWeight;
    return float2(sample.r * weight * depthWeight, weight * depthWeight);
}

float4 Main(PixelInput input) : COLOR0 {
    float4 center = tex2D(AOInput, input.uv);
    float2 direction = EffectData.xy;
    float sharpness = 42.0f;

    float2 sum = float2(center.r * 0.227027f, 0.227027f);
    sum += WeightedSample(input.uv + direction * 1.0f, center.g, 0.194594f, sharpness);
    sum += WeightedSample(input.uv - direction * 1.0f, center.g, 0.194594f, sharpness);
    sum += WeightedSample(input.uv + direction * 2.0f, center.g, 0.121621f, sharpness);
    sum += WeightedSample(input.uv - direction * 2.0f, center.g, 0.121621f, sharpness);
    sum += WeightedSample(input.uv + direction * 3.0f, center.g, 0.054054f, sharpness);
    sum += WeightedSample(input.uv - direction * 3.0f, center.g, 0.054054f, sharpness);
    sum += WeightedSample(input.uv + direction * 4.0f, center.g, 0.016216f, sharpness);
    sum += WeightedSample(input.uv - direction * 4.0f, center.g, 0.016216f, sharpness);

    float amount = sum.x / max(sum.y, 0.0001f);
    return float4(amount, center.g, 0.0f, 1.0f);
}
