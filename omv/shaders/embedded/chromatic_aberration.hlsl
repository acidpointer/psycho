// Peripheral optical displacement followed by display noise. s8 retains the
// pre-grade input only for the original deband flatness gate; source alpha
// remains the center alpha, and no temporary alpha channel is repurposed.
sampler2D DebandSource : register(s8);
float4 ChromaticData : register(c3);
struct PixelInput { float2 uv : TEXCOORD0; };

float DebandFlatWeight(float2 uv) {
    if (GradeData4.x < 0.5f || GradeData5.z < 0.5f || GradeData2.z <= 0.00001f) {
        return 0.0f;
    }
    float2 offset = ScreenData.zw * 6.0f;
    float3 center = tex2Dlod(DebandSource, float4(uv, 0, 0)).rgb;
    float3 left = tex2Dlod(DebandSource, float4(uv - float2(offset.x, 0), 0, 0)).rgb;
    float3 right = tex2Dlod(DebandSource, float4(uv + float2(offset.x, 0), 0, 0)).rgb;
    float3 up = tex2Dlod(DebandSource, float4(uv - float2(0, offset.y), 0, 0)).rgb;
    float3 down = tex2Dlod(DebandSource, float4(uv + float2(0, offset.y), 0, 0)).rgb;
    float3 average = (center + left + right + up + down) * 0.2f;
    float3 delta = max(max(abs(left - right), abs(up - down)), abs(center - average));
    return 1.0f - Smooth01(max(delta.r, max(delta.g, delta.b)) * 42.5f);
}

float4 Main(PixelInput input) : COLOR0 {
    float4 center = SampleScene(input.uv);
    float2 pixelVector = (input.uv - 0.5f) * ScreenData.xy;
    float radiusSquared = dot(pixelVector, pixelVector);
    float inverseRadius = rsqrt(max(radiusSquared, 0.000001f));
    float normalizedRadius = length((input.uv - 0.5f) * 2.0f);
    // The central 55 percent of normalized radius stays optically clear.
    float radialWeight = Smooth01((normalizedRadius - 0.55f) / 0.45f);
    float2 radialDirection = pixelVector * inverseRadius;
    float2 offset = radialDirection * ScreenData.zw * ChromaticData.x * radialWeight;
    float red = SampleScene(input.uv + offset).r;
    float blue = SampleScene(input.uv - offset).b;
    float3 color = float3(red, center.g, blue);
    color = ApplyOutputNoise(color, input.uv, DebandFlatWeight(input.uv));
    return float4(color, center.a);
}
