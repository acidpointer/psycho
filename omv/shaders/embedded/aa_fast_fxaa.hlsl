// Fast FXAA uses the same mip-zero equation as the first-person companion.
// Keep the released full-frame alpha output; finishing owns scene alpha.
float4 Options : register(c3);
float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    return float4(ResolveFxaa(uv, SampleScene(uv).rgb, Options), 1.0);
}
