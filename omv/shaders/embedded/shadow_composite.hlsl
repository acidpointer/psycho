// OMV final world-shadow compositor. Runs before other scene-pre effects.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
row_major float4x4 CascadeMatrix0 : register(c6);
row_major float4x4 CascadeMatrix1 : register(c10);
row_major float4x4 CascadeMatrix2 : register(c14);
row_major float4x4 CascadeMatrix3 : register(c18);
float4 CascadeSplits : register(c22);
float4 ShadowControl : register(c23); // x reversed, y exterior, z darkness, w bleed reduction
float4 CascadeBlendWidth : register(c24);
float4 CascadeTexel : register(c25); // x half texel, y one minus half texel

sampler2D SceneColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D ShadowAtlas : register(s2);
sampler2D PointShadowBuffer : register(s3);

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (ShadowControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float3 RelativeWorldPosition(float2 uv, float depth) {
    float3 view = float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
    float4 homogeneous = float4(view, 1.0f);
    return float3(dot(ViewToWorld0, homogeneous), dot(ViewToWorld1, homogeneous), dot(ViewToWorld2, homogeneous));
}

float ReduceLightBleeding(float probability) {
    return saturate((probability - ShadowControl.w) / max(1.0f - ShadowControl.w, 0.001f));
}

float Chebyshev(float2 moments, float receiver, float minimumVariance) {
    if (receiver <= moments.x) return 1.0f;
    float variance = max(moments.y - moments.x * moments.x, minimumVariance);
    float difference = receiver - moments.x;
    return ReduceLightBleeding(variance / (variance + difference * difference));
}

float Evsm4(float4 moments, float depth) {
    float normalized = depth * 2.0f - 1.0f;
    float2 warped = float2(exp(5.54f * normalized), -exp(-5.0f * normalized));
    float2 scale = 0.00002f * float2(5.54f, 5.0f) * warped;
    return min(
        Chebyshev(moments.xz, warped.x, scale.x * scale.x),
        Chebyshev(moments.yw, warped.y, scale.y * scale.y));
}

float2 AtlasUv(float2 localUv, int cascadeIndex) {
    float2 quadrant = cascadeIndex == 0 ? float2(0.0f, 0.0f)
        : (cascadeIndex == 1 ? float2(0.5f, 0.0f)
        : (cascadeIndex == 2 ? float2(0.0f, 0.5f) : float2(0.5f, 0.5f)));
    // Filtering must not cross atlas quadrant boundaries. The inset is
    // expressed in local 2048-map UVs and therefore remains independent of
    // the enclosing 4096 atlas layout.
    localUv = clamp(localUv, CascadeTexel.xx, CascadeTexel.yy);
    return localUv * 0.5f + quadrant;
}

float CascadeVisibility(
    row_major float4x4 transform,
    int cascadeIndex,
    float3 worldPosition)
{
    float4 projected = mul(float4(worldPosition, 1.0f), transform);
    float3 ndc = projected.xyz / max(projected.w, 0.000001f);
    float2 localUv = float2(ndc.x * 0.5f + 0.5f, 0.5f - ndc.y * 0.5f);
    if (min(localUv.x, localUv.y) < 0.0f || max(localUv.x, localUv.y) > 1.0f) return 1.0f;
    float2 uv = AtlasUv(localUv, cascadeIndex);
    return Evsm4(tex2Dlod(ShadowAtlas, float4(uv, 0.0f, 0.0f)), saturate(ndc.z));
}

float DirectionalVisibility(float3 worldPosition, float viewDepth) {
    float values[4];
    values[0] = CascadeVisibility(CascadeMatrix0, 0, worldPosition);
    values[1] = CascadeVisibility(CascadeMatrix1, 1, worldPosition);
    values[2] = CascadeVisibility(CascadeMatrix2, 2, worldPosition);
    values[3] = CascadeVisibility(CascadeMatrix3, 3, worldPosition);
    int cascade = viewDepth <= CascadeSplits.x ? 0
        : (viewDepth <= CascadeSplits.y ? 1 : (viewDepth <= CascadeSplits.z ? 2 : 3));
    if (cascade >= 3) return values[3];
    float boundary = CascadeSplits[cascade];
    float width = max(CascadeBlendWidth[cascade], 0.001f);
    float blend = smoothstep(boundary - width, boundary, viewDepth);
    return lerp(values[cascade], values[cascade + 1], blend);
}

float4 Main(PixelInput input) : COLOR0 {
    float4 scene = tex2Dlod(SceneColor, float4(input.uv, 0.0f, 0.0f));
    float rawDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
    float viewDepth = LinearDepth(rawDepth);
    float3 worldPosition = RelativeWorldPosition(input.uv, viewDepth);
    float2 pointShadow = tex2Dlod(PointShadowBuffer, float4(input.uv, 0.0f, 0.0f)).rg;
    // Exteriors combine two visibility values. Interiors instead consume the
    // bounded local-light energy accumulated from their cube maps, matching
    // NVR's ambient-floor semantics rather than darkening by a ratio of only
    // the selected lights.
    float raw = saturate(pointShadow.x);
    if (ShadowControl.y > 0.5f) {
        raw = min(DirectionalVisibility(worldPosition, viewDepth), raw);
    }
    float visibility = 1.0f - saturate(ShadowControl.z) * (1.0f - raw);
    scene.rgb *= visibility;
    return scene;
}
