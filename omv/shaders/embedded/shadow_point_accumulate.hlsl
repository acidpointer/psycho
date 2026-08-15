// One-pass OMV point-shadow accumulation over scene depth and twelve complete point cubes.
#ifndef OMV_POINT_CAPACITY
#define OMV_POINT_CAPACITY 12
#endif

float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
float4 PointControl : register(c6); // x reversed depth, y light count, z radial bias
float4 LightPositionRadius[12] : register(c7);
float4 LightColorIntensity[12] : register(c19);
float4 LightMetadata[12] : register(c31); // x native receiver radius, y shadow weight

sampler2D SceneDepth : register(s0);
samplerCUBE ShadowCube0 : register(s1);
#if OMV_POINT_CAPACITY >= 2
samplerCUBE ShadowCube1 : register(s2);
#endif
#if OMV_POINT_CAPACITY >= 3
samplerCUBE ShadowCube2 : register(s3);
#endif
#if OMV_POINT_CAPACITY >= 4
samplerCUBE ShadowCube3 : register(s4);
#endif
#if OMV_POINT_CAPACITY >= 5
samplerCUBE ShadowCube4 : register(s5);
#endif
#if OMV_POINT_CAPACITY >= 6
samplerCUBE ShadowCube5 : register(s6);
#endif
#if OMV_POINT_CAPACITY >= 7
samplerCUBE ShadowCube6 : register(s7);
#endif
#if OMV_POINT_CAPACITY >= 8
samplerCUBE ShadowCube7 : register(s8);
#endif
#if OMV_POINT_CAPACITY >= 9
samplerCUBE ShadowCube8 : register(s9);
#endif
#if OMV_POINT_CAPACITY >= 10
samplerCUBE ShadowCube9 : register(s10);
#endif
#if OMV_POINT_CAPACITY >= 11
samplerCUBE ShadowCube10 : register(s11);
#endif
#if OMV_POINT_CAPACITY >= 12
samplerCUBE ShadowCube11 : register(s12);
#endif

static const float ShadowDepthKeyRange = 250000.0f;

struct PixelInput { float2 uv : TEXCOORD0; };

float3 ViewPosition(float2 uv, float depth) {
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

float LinearDepth(float rawDepth) {
    if (PointControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float2 SnapDepthUv(float2 uv) {
    float2 texel = clamp(floor(uv * ScreenData.xy), 0.0f, ScreenData.xy - 1.0f);
    return (texel + 0.5f) * ScreenData.zw;
}

float3 SampleViewPosition(float2 uv) {
    // Main snaps centerUv once. Adding or subtracting one full-resolution
    // texel therefore remains on an exact depth-texel center; snapping every
    // neighbor again only repeats floor/clamp arithmetic in the hottest
    // receiver path.
    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
    return ViewPosition(uv, LinearDepth(rawDepth));
}

float3 RelativeWorldPosition(float2 uv, float depth) {
    float4 view = float4(ViewPosition(uv, depth), 1.0f);
    return float3(dot(ViewToWorld0, view), dot(ViewToWorld1, view), dot(ViewToWorld2, view));
}

float3 WorldNormal(float3 viewNormal) {
    float4 normalVector = float4(viewNormal, 0.0f);
    float3 normal = float3(
        dot(ViewToWorld0, normalVector), dot(ViewToWorld1, normalVector), dot(ViewToWorld2, normalVector));
    return normal * rsqrt(max(dot(normal, normal), 0.0000001f));
}

float SourceGuard(float normalizedDistance) {
    // The emitting mesh is not direct irradiance owned by this pass. The
    // fade also rejects unreliable radial depths immediately around a source.
    return smoothstep(0.02f, 0.08f, normalizedDistance);
}

struct LightEnergy {
    float3 total;
    float3 deficit;
};

struct PointOutput {
    float4 deficit : COLOR0;
    float4 total : COLOR1;
};

LightEnergy EvaluateLight(
    samplerCUBE shadowCube,
    float3 worldPosition,
    float3 normal,
    float4 lightPositionRadius,
    float4 lightColorIntensity,
    float4 lightMetadata)
{
    float3 toLight = lightPositionRadius.xyz - worldPosition;
    float distance = length(toLight);
    float normalizedReceiverDistance = distance / lightMetadata.x;
    // CPU selection admits only finite positive receiver/cube radii, and the
    // static light-count branches never evaluate an uninitialized slot.
    if (normalizedReceiverDistance >= 1.0f) {
        LightEnergy empty;
        empty.total = 0.0f;
        empty.deficit = 0.0f;
        return empty;
    }

    float radial = saturate(1.0f - normalizedReceiverDistance * normalizedReceiverDistance);
    radial = radial * radial
        / max(1.0f + 5.0f * normalizedReceiverDistance * normalizedReceiverDistance, 0.001f);
    float lambert = dot(toLight / max(distance, 0.001f), normal);
    // Depth-derived normals are least reliable close to a point source. Keep
    // the established isotropic near-source transition; immutable visibility
    // below, rather than a receiver-facing heuristic, owns wall containment.
    float diffuse = saturate(lerp(
        1.0f, lambert, smoothstep(0.0f, 0.2f, normalizedReceiverDistance)));
    // CPU admission already publishes finite nonnegative native colors.
    float3 contribution = radial * diffuse * lightColorIntensity.rgb;
    float3 cubeDirection = toLight * float3(-1.0f, -1.0f, 1.0f);
    float normalizedCubeDistance = distance / lightPositionRadius.w;
    float casterDepth = texCUBElod(shadowCube, float4(cubeDirection, 0.0f)).r;
    float shadowVisibility = casterDepth
            + PointControl.z * normalizedCubeDistance >= normalizedCubeDistance
        ? 1.0f : 0.0f;
    shadowVisibility = lerp(
        1.0f, shadowVisibility, casterDepth > 0.0f && casterDepth < 1.0f);
    float outerEnvelope = 1.0f - smoothstep(0.8f, 1.0f, normalizedReceiverDistance);
    // These presentation weights belong only to subtractable occluded energy.
    // Applying them to `total` as well makes deficit/total cancel every fade.
    float shadowWeight = SourceGuard(normalizedReceiverDistance) * outerEnvelope
        * lightMetadata.y;
    float3 deficit = contribution * (1.0f - shadowVisibility) * shadowWeight;
    LightEnergy result;
    result.total = contribution;
    result.deficit = deficit;
    return result;
}

PointOutput Main(PixelInput input) {
    float2 centerUv = SnapDepthUv(input.uv);
    float rawDepth = tex2Dlod(SceneDepth, float4(centerUv, 0.0f, 0.0f)).r;
    if (rawDepth <= 1.0f / 65536.0f || rawDepth >= 1.0f - 1.0f / 65536.0f) {
        PointOutput empty;
        empty.deficit = 0.0f;
        empty.total = 0.0f;
        return empty;
    }

    // Reconstruct the identical edge-aware receiver normal that the deleted
    // geometry prepass wrote, but consume it immediately. This removes one
    // full-resolution FP16 write/read pair without approximating geometry.
    float depth = LinearDepth(rawDepth);
    float3 center = ViewPosition(centerUv, depth);
    float3 left = SampleViewPosition(centerUv - float2(ScreenData.z, 0.0f));
    float3 right = SampleViewPosition(centerUv + float2(ScreenData.z, 0.0f));
    float3 up = SampleViewPosition(centerUv - float2(0.0f, ScreenData.w));
    float3 down = SampleViewPosition(centerUv + float2(0.0f, ScreenData.w));
    float3 dx = dot(left - center, left - center) < dot(right - center, right - center)
        ? center - left : right - center;
    float3 dy = dot(up - center, up - center) < dot(down - center, down - center)
        ? center - up : down - center;
    float3 viewNormal = cross(dx, dy);
    viewNormal *= rsqrt(max(dot(viewNormal, viewNormal), 0.0000001f));

    float3 worldPosition = RelativeWorldPosition(centerUv, depth);
    float3 normal = WorldNormal(viewNormal);
    float3 total = 0.0f;
    float3 deficit = 0.0f;
    if (PointControl.y > 0.0f) { LightEnergy light = EvaluateLight(ShadowCube0, worldPosition, normal, LightPositionRadius[0], LightColorIntensity[0], LightMetadata[0]); total += light.total; deficit += light.deficit; }
#if OMV_POINT_CAPACITY >= 2
    if (PointControl.y > 1.0f) { LightEnergy light = EvaluateLight(ShadowCube1, worldPosition, normal, LightPositionRadius[1], LightColorIntensity[1], LightMetadata[1]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 3
    if (PointControl.y > 2.0f) { LightEnergy light = EvaluateLight(ShadowCube2, worldPosition, normal, LightPositionRadius[2], LightColorIntensity[2], LightMetadata[2]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 4
    if (PointControl.y > 3.0f) { LightEnergy light = EvaluateLight(ShadowCube3, worldPosition, normal, LightPositionRadius[3], LightColorIntensity[3], LightMetadata[3]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 5
    if (PointControl.y > 4.0f) { LightEnergy light = EvaluateLight(ShadowCube4, worldPosition, normal, LightPositionRadius[4], LightColorIntensity[4], LightMetadata[4]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 6
    if (PointControl.y > 5.0f) { LightEnergy light = EvaluateLight(ShadowCube5, worldPosition, normal, LightPositionRadius[5], LightColorIntensity[5], LightMetadata[5]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 7
    if (PointControl.y > 6.0f) { LightEnergy light = EvaluateLight(ShadowCube6, worldPosition, normal, LightPositionRadius[6], LightColorIntensity[6], LightMetadata[6]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 8
    if (PointControl.y > 7.0f) { LightEnergy light = EvaluateLight(ShadowCube7, worldPosition, normal, LightPositionRadius[7], LightColorIntensity[7], LightMetadata[7]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 9
    if (PointControl.y > 8.0f) { LightEnergy light = EvaluateLight(ShadowCube8, worldPosition, normal, LightPositionRadius[8], LightColorIntensity[8], LightMetadata[8]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 10
    if (PointControl.y > 9.0f) { LightEnergy light = EvaluateLight(ShadowCube9, worldPosition, normal, LightPositionRadius[9], LightColorIntensity[9], LightMetadata[9]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 11
    if (PointControl.y > 10.0f) { LightEnergy light = EvaluateLight(ShadowCube10, worldPosition, normal, LightPositionRadius[10], LightColorIntensity[10], LightMetadata[10]); total += light.total; deficit += light.deficit; }
#endif
#if OMV_POINT_CAPACITY >= 12
    if (PointControl.y > 11.0f) { LightEnergy light = EvaluateLight(ShadowCube11, worldPosition, normal, LightPositionRadius[11], LightColorIntensity[11], LightMetadata[11]); total += light.total; deficit += light.deficit; }
#endif
    PointOutput output;
    // Keeping both RGB quantities exact is essential when differently colored
    // lights overlap. A scalar occlusion ratio would darken channels owned by
    // an unoccluded light in the same batch.
    // RGB is additively blended when independently scissored batches overlap.
    // Accumulate the depth-key sum and batch count in the two alpha channels;
    // the compositor divides them before receiver rejection. Storing the raw
    // key in both alphas would make a two-batch overlap appear twice as deep
    // and produce a camera-dependent unshadowed seam.
    float depthKey = depth / ShadowDepthKeyRange;
    output.deficit = float4(deficit, depthKey);
    output.total = float4(total, 1.0f);
    return output;
}
