// Shared numeric display-color input for finishing and spatial AA. The caller
// owns a clamp/linear, mip-zero, non-sRGB sampler and output-pixel dimensions.
sampler2D SceneColor : register(s0);
float4 ScreenData : register(c0);

float4 SampleScene(float2 uv) {
#if OMV_SCENE_IMPLICIT_LOD
    // Standalone FXAA retains its released implicit-LOD bytecode. Its bound
    // sampler has no mip filter; finishing uses explicit LOD inside branches.
    return tex2D(SceneColor, uv);
#else
    return tex2Dlod(SceneColor, float4(uv, 0.0f, 0.0f));
#endif
}
