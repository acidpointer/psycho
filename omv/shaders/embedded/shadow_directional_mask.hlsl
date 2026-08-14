// Directional visibility. Production concatenates this source into the
// source-owned compositor; the standalone entry remains a compile-time oracle.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
row_major float4x4 CascadeMatrices[4] : register(c6);
float4 CascadeSplits : register(c22);
float4 ShadowControl : register(c23); // x reversed depth
float4 CascadeBlendWidth : register(c24);
float4 CascadeTexel : register(c25);
float4 DepthControl : register(c26);
float4 SunDirection : register(c27);
float4 ActorControl : register(c28);
float4 ActorCrops[3] : register(c29);
float4 ActorTexel : register(c32);

#if OMV_FUSED_DIRECTIONAL
sampler2D SceneDepth : register(s1);
sampler2D ShadowAtlas : register(s2);
sampler2D ActorNearMiddleMoments : register(s3);
sampler2D ActorFarMoments : register(s4);
#else
sampler2D SceneDepth : register(s0);
sampler2D ShadowAtlas : register(s1);
sampler2D ActorNearMiddleMoments : register(s2);
sampler2D ActorFarMoments : register(s3);
#endif

static const float ShadowDepthKeyRange = 250000.0f;

#ifndef OMV_SHADOW_PIXEL_INPUT
#define OMV_SHADOW_PIXEL_INPUT 1
struct PixelInput { float2 uv : TEXCOORD0; };
#endif

float LinearDepth(float rawDepth) {
    if (ShadowControl.x > 0.5f)
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

bool HasGeometryDepth(float rawDepth) {
    return rawDepth > DepthControl.x && rawDepth < 1.0f - DepthControl.x;
}

float2 SnapDepthUv(float2 uv) {
    // Half-resolution raster centers lie on full-resolution texel boundaries.
    // Pin every receiver to the point-sampled depth texel which owns it so
    // camera motion cannot alternate between two reconstructed positions.
    float2 texel = clamp(floor(uv * ScreenData.xy), 0.0f, ScreenData.xy - 1.0f);
    return (texel + 0.5f) * ScreenData.zw;
}

float3 ViewPosition(float2 uv, float depth) {
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

float3 RelativeWorldPosition(float2 uv, float depth) {
    float4 view = float4(ViewPosition(uv, depth), 1.0f);
    return float3(dot(ViewToWorld0, view), dot(ViewToWorld1, view), dot(ViewToWorld2, view));
}

float3 ReconstructWorldNormal(float2 uv, float centerDepth) {
    float2 pixel = ScreenData.zw;
    float2 minimumUv = pixel * 0.5f;
    float2 maximumUv = 1.0f - minimumUv;
    // `uv` is already an exact full-resolution texel center. One integer
    // texel step stays exact, so only edge clamping is needed here.
    float2 leftUv = clamp(uv - float2(pixel.x, 0.0f), minimumUv, maximumUv);
    float2 rightUv = clamp(uv + float2(pixel.x, 0.0f), minimumUv, maximumUv);
    float2 upUv = clamp(uv - float2(0.0f, pixel.y), minimumUv, maximumUv);
    float2 downUv = clamp(uv + float2(0.0f, pixel.y), minimumUv, maximumUv);
    float rawLeft = tex2Dlod(SceneDepth, float4(leftUv, 0.0f, 0.0f)).r;
    float rawRight = tex2Dlod(SceneDepth, float4(rightUv, 0.0f, 0.0f)).r;
    float rawUp = tex2Dlod(SceneDepth, float4(upUv, 0.0f, 0.0f)).r;
    float rawDown = tex2Dlod(SceneDepth, float4(downUv, 0.0f, 0.0f)).r;
    float leftDepth = HasGeometryDepth(rawLeft) ? LinearDepth(rawLeft) : centerDepth;
    float rightDepth = HasGeometryDepth(rawRight) ? LinearDepth(rawRight) : centerDepth;
    float upDepth = HasGeometryDepth(rawUp) ? LinearDepth(rawUp) : centerDepth;
    float downDepth = HasGeometryDepth(rawDown) ? LinearDepth(rawDown) : centerDepth;
    float3 center = ViewPosition(uv, centerDepth);
    float3 left = ViewPosition(leftUv, leftDepth);
    float3 right = ViewPosition(rightUv, rightDepth);
    float3 up = ViewPosition(upUv, upDepth);
    float3 down = ViewPosition(downUv, downDepth);
    float3 dx = abs(leftDepth - centerDepth) < abs(rightDepth - centerDepth)
        ? center - left : right - center;
    float3 dy = abs(upDepth - centerDepth) < abs(downDepth - centerDepth)
        ? center - up : down - center;
    float3 viewNormal = cross(dx, dy);
    viewNormal *= rsqrt(max(dot(viewNormal, viewNormal), 0.0000001f));
    float4 normal = float4(viewNormal, 0.0f);
    return float3(dot(ViewToWorld0, normal), dot(ViewToWorld1, normal), dot(ViewToWorld2, normal));
}

float ReduceLightBleeding(float probability, float amount) {
    return saturate((probability - amount) / max(1.0f - amount, 0.001f));
}

float Chebyshev(float2 moments, float receiver, float minimumVariance, float bleedReduction) {
    if (receiver <= moments.x) return 1.0f;
    float variance = max(moments.y - moments.x * moments.x, minimumVariance);
    float difference = receiver - moments.x;
    return ReduceLightBleeding(variance / (variance + difference * difference), bleedReduction);
}

float Evsm4(float4 moments, float depth, float bleedReduction) {
    float normalized = depth * 2.0f - 1.0f;
    float2 warped = float2(exp(5.54f * normalized), -exp(-5.0f * normalized));
    float2 scale = 0.01f * float2(5.54f, 5.0f) * warped;
    return min(
        Chebyshev(moments.xz, warped.x, scale.x * scale.x, bleedReduction),
        Chebyshev(moments.yw, warped.y, scale.y * scale.y, bleedReduction));
}

float2 AtlasUv(float2 localUv, int cascadeIndex) {
    float2 quadrant = cascadeIndex == 0 ? float2(0.0f, 0.0f)
        : (cascadeIndex == 1 ? float2(0.5f, 0.0f)
        : (cascadeIndex == 2 ? float2(0.0f, 0.5f) : float2(0.5f, 0.5f)));
    localUv = clamp(localUv, CascadeTexel.xx, CascadeTexel.yy);
    return localUv * 0.5f + quadrant;
}

float2 SampleActorDepthCoverage(float2 uv, int cascadeIndex) {
    if (cascadeIndex < 2) {
        float2 packedUv = float2(uv.x * 0.5f + 0.5f * cascadeIndex, uv.y);
        return tex2Dlod(ActorNearMiddleMoments, float4(packedUv, 0.0f, 0.0f)).rg;
    }
    return tex2Dlod(ActorFarMoments, float4(uv, 0.0f, 0.0f)).rg;
}

float ActorVisibility(float2 depthCoverage, float receiverDepth) {
    float coverage = saturate(depthCoverage.y);
    if (coverage <= 0.0001f) return 1.0f;
    float actorDepth = depthCoverage.x / max(coverage, 0.0001f);
    return receiverDepth <= actorDepth + 0.0005f ? 1.0f : 1.0f - coverage;
}

float CascadeVisibility(row_major float4x4 transform, int cascadeIndex, float3 worldPosition) {
    float4 projected = mul(float4(worldPosition, 1.0f), transform);
    if (projected.w <= 0.0f) return 1.0f;
    float3 ndc = projected.xyz / max(projected.w, 0.000001f);
    float2 localUv = float2(ndc.x * 0.5f + 0.5f, 0.5f - ndc.y * 0.5f);
    if (min(localUv.x, localUv.y) < 0.0f || max(localUv.x, localUv.y) > 1.0f ||
        ndc.z < 0.0f || ndc.z > 1.0f) return 1.0f;

    float bleed = cascadeIndex == 0 ? 0.1f
        : (cascadeIndex == 1 ? 0.2f : (cascadeIndex == 2 ? 0.6f : 0.8f));
    float4 staticCenter = tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv, cascadeIndex), 0.0f, 0.0f));
    float actorVisibility = 1.0f;
    if (cascadeIndex < 3 && ActorControl[cascadeIndex] > 0.5f) {
        float4 crop = ActorCrops[cascadeIndex];
        float2 actorUv = localUv * crop.xy + crop.zw;
        if (min(actorUv.x, actorUv.y) >= 0.0f && max(actorUv.x, actorUv.y) <= 1.0f) {
            actorVisibility = ActorVisibility(
                SampleActorDepthCoverage(clamp(actorUv, ActorTexel.xx, ActorTexel.yy), cascadeIndex),
                saturate(ndc.z));
        }
    }
    float visibility = min(Evsm4(staticCenter, saturate(ndc.z), bleed), actorVisibility);
    if (visibility > 0.02f && visibility < 0.98f) {
        float2 radius = CascadeTexel.zz;
        float4 filtered = staticCenter
            + tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv + float2(-radius.x, -radius.y), cascadeIndex), 0.0f, 0.0f))
            + tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv + float2( radius.x,  radius.y), cascadeIndex), 0.0f, 0.0f));
        visibility = min(Evsm4(filtered / 3.0f, saturate(ndc.z), bleed), actorVisibility);
    }
    return visibility;
}

float DirectionalVisibility(float3 worldPosition, float viewDepth) {
    int cascade = viewDepth < CascadeSplits.x ? 0
        : (viewDepth < CascadeSplits.y ? 1
        : (viewDepth < CascadeSplits.z ? 2
        : (viewDepth < CascadeSplits.w ? 3 : -1)));
    if (cascade < 0) return 1.0f;
    float current = CascadeVisibility(CascadeMatrices[cascade], cascade, worldPosition);
    float blend = smoothstep(
        CascadeSplits[cascade] - CascadeBlendWidth[cascade],
        CascadeSplits[cascade],
        viewDepth);
    if (cascade >= 3) return lerp(current, 1.0f, blend);
    if (blend <= 0.0f) return current;
    return lerp(
        current,
        CascadeVisibility(CascadeMatrices[cascade + 1], cascade + 1, worldPosition),
        blend);
}

float DirectionalVisibilityAtReceiver(float2 depthUv, float viewDepth) {
    float3 worldPosition = RelativeWorldPosition(depthUv, viewDepth);
    float visibility = DirectionalVisibility(worldPosition, viewDepth);
    if (visibility < 0.98f) {
        float3 normal = ReconstructWorldNormal(depthUv, viewDepth);
        float normalOffset = saturate(1.0f - dot(normal, SunDirection.xyz));
        visibility = DirectionalVisibility(worldPosition + normal * normalOffset, viewDepth);
    }
    return visibility;
}

#if !OMV_FUSED_DIRECTIONAL
float4 Main(PixelInput input) : COLOR0 {
    float2 depthUv = SnapDepthUv(input.uv);
    float rawDepth = tex2Dlod(SceneDepth, float4(depthUv, 0.0f, 0.0f)).r;
    float viewDepth = HasGeometryDepth(rawDepth) ? LinearDepth(rawDepth) : 0.0f;
    return float4(
        viewDepth > 0.0f && viewDepth < DepthLinearizeData.w * 0.985f
            ? DirectionalVisibilityAtReceiver(depthUv, viewDepth) : 1.0f,
        viewDepth > 0.0f ? viewDepth / ShadowDepthKeyRange : 0.0f,
        0.0f,
        1.0f);
}
#endif
