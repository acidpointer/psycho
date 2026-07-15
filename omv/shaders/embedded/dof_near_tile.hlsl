sampler2D SourceTexture : register(s0);

float4 SourceData : register(c9);
float4 ReduceData : register(c10);

struct PixelInput {
    float2 uv : TEXCOORD0;
};

float ReadValue(float2 uv) {
    float value = tex2Dlod(SourceTexture, float4(saturate(uv), 0.0f, 0.0f)).r;
    return ReduceData.x > 0.5f ? saturate(-value) : saturate(value);
}

void Accumulate(float2 uv, inout float maximum) {
    maximum = max(maximum, ReadValue(uv));
}

float4 Main(PixelInput input) : COLOR0 {
    float2 outputPixel = floor(input.uv * SourceData.zw);
    float2 baseUv;
    float2 stepUv;
    if (ReduceData.x > 0.5f) {
        baseUv = float2((outputPixel.x * 8.0f + 0.5f) * SourceData.x, input.uv.y);
        stepUv = float2(SourceData.x, 0.0f);
    } else {
        baseUv = float2(input.uv.x, (outputPixel.y * 8.0f + 0.5f) * SourceData.y);
        stepUv = float2(0.0f, SourceData.y);
    }

    float maximum = 0.0f;
    Accumulate(baseUv, maximum);
    Accumulate(baseUv + stepUv, maximum);
    Accumulate(baseUv + stepUv * 2.0f, maximum);
    Accumulate(baseUv + stepUv * 3.0f, maximum);
    Accumulate(baseUv + stepUv * 4.0f, maximum);
    Accumulate(baseUv + stepUv * 5.0f, maximum);
    Accumulate(baseUv + stepUv * 6.0f, maximum);
    Accumulate(baseUv + stepUv * 7.0f, maximum);
    return float4(maximum, 0.0f, 0.0f, 1.0f);
}
