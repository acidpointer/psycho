// OMV entry point for the MIT-licensed official SMAA HLSL3 implementation.
// Declarations and SMAA.hlsl are concatenated by the preparation worker.
sampler2D SceneColor : register(s0);
float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float4 offsets[3];
    SMAAEdgeDetectionVS(uv, offsets);
    float2 edges;
    if (Options0.x < 0.5) edges = SMAALumaEdgeDetectionPS(uv, offsets, SceneColor);
    else edges = SMAAColorEdgeDetectionPS(uv, offsets, SceneColor);
    return float4(edges, 0.0, 0.0);
}
