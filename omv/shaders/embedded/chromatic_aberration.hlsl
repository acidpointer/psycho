sampler2D SceneColor : register(s0);

float4 ScreenData : register(c0);
float4 ChromaticData : register(c3);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float Smooth01(float value) {
    value = saturate(value);
    return value * value * (3.0f - 2.0f * value);
}

float4 SampleScene(float2 uv) {
    return tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f));
}

float4 Main(PixelInput input) : COLOR0 {
    float4 center = SampleScene(input.uv);
    float2 pixelVector = (input.uv - 0.5f) * ScreenData.xy;
    float radiusSquared = dot(pixelVector, pixelVector);
    float inverseRadius = rsqrt(max(radiusSquared, 0.000001f));
    float normalizedRadius = length((input.uv - 0.5f) * 2.0f);
    float radialWeight = Smooth01(normalizedRadius);
    float2 radialDirection = pixelVector * inverseRadius;
    float2 offset = radialDirection * ScreenData.zw * ChromaticData.x * radialWeight;
    float red = SampleScene(input.uv + offset).r;
    float blue = SampleScene(input.uv - offset).b;
    return float4(red, center.g, blue, center.a);
}
