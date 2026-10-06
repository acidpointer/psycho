// Official SMAA neighborhood blending with OMV's unchanged center alpha.
sampler2D SceneColor : register(s0);
sampler2D Weights : register(s1);
sampler2D Edges : register(s2);
float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float alpha = tex2Dlod(SceneColor, float4(uv, 0.0, 0.0)).a;
    if (Options1.y > 1.5) {
        return float4(tex2Dlod(Weights, float4(uv, 0.0, 0.0)).rgb, alpha);
    }
    if (Options1.y > 0.5) {
        return float4(tex2Dlod(Edges, float4(uv, 0.0, 0.0)).rg, 0.0, alpha);
    }
    float4 offsets;
    SMAANeighborhoodBlendingVS(uv, offsets);
    float4 color = SMAANeighborhoodBlendingPS(uv, offsets, SceneColor, Weights);
    color.a = alpha;
    return color;
}
