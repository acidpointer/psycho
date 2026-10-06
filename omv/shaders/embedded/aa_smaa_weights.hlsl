// Full SMAA 1x: official area/search lookups, diagonals and corner patterns.
// Search bounds are 16 orthogonal steps and 8 diagonal steps.
sampler2D Edges : register(s0);
sampler2D Area : register(s1);
sampler2D Search : register(s2);
float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float2 pixel;
    float4 offsets[3];
    SMAABlendingWeightCalculationVS(uv, pixel, offsets);
    return SMAABlendingWeightCalculationPS(uv, pixel, offsets, Edges, Area, Search, 0.0);
}
