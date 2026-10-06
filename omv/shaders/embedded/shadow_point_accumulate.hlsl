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
float4 PointControl : register(c6); // x reversed depth, y light count, z radial bias, w cube resolution
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

float3 ShadowReceiverWorldNormal(float2 uv, float depth);

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

float3 RelativeWorldPosition(float2 uv, float depth) {
    float4 view = float4(ViewPosition(uv, depth), 1.0f);
    return float3(dot(ViewToWorld0, view), dot(ViewToWorld1, view), dot(ViewToWorld2, view));
}

// Select a face explicitly and sample inside its texel, avoiding ambiguous
// hardware face selection on equal major axes. The basis follows the six
// production right-handed cube views after the receiver's (-x,-y,+z) mapping.
float3 PointCubeSampleDirection(float3 direction, out float3 rasterRay) {
    float3 axis = abs(direction);
    float major = max(axis.x, max(axis.y, axis.z));
    float xFace = axis.x >= axis.y && axis.x >= axis.z ? 1.0f : 0.0f;
    float yFace = xFace == 0.0f && axis.y >= axis.z ? 1.0f : 0.0f;
    float zFace = 1.0f - xFace - yFace;
    float3 faceMask = float3(xFace, yFace, zFace);
    float3 side = direction >= 0.0f ? 1.0f : -1.0f;
    float3 orientation = float3(lerp(1.0f, side.z, zFace), -1.0f, lerp(side.y, -side.x, xFace));
    float3 projected = direction / major;
    float3 texel = clamp(floor((projected * orientation * 0.5f + 0.5f) * PointControl.w), 0.0f, PointControl.w - 1.0f);
    // D3D9 generation uses integer pixel centers; texture addressing uses
    // half-integer centers. Restore the major axis after quantizing the two
    // face coordinates so sampling cannot select a different face at a tie.
    float3 raster = texel * (2.0f / PointControl.w) - 1.0f;
    rasterRay = lerp(raster * orientation, projected, faceMask) * float3(-1.0f, -1.0f, 1.0f);
    return lerp((raster + 1.0f / PointControl.w) * orientation, projected, faceMask);
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
    LightEnergy empty;
    empty.total = 0.0f;
    empty.deficit = 0.0f;
    float3 toLight = lightPositionRadius.xyz - worldPosition;
    float distance = length(toLight);
    float normalizedReceiverDistance = distance / lightMetadata.x;
    // A singular source ray has no direction or visibility. Native lighting
    // remains unchanged there; no radius-wide fixture exclusion is involved.
    if (!(distance > 0.0f && normalizedReceiverDistance < 1.0f)) return empty;
    float normalDotLight = dot(toLight, normal);
    // Only front-facing direct light owns a subtractable shadow. Positive
    // isotropic energy on backfaces canceled in deficit/total and darkened
    // unrelated native radiance inside a radius-shaped near-source region.
    if (!(normalDotLight > 0.0f)) return empty;

    float radial = saturate(1.0f - normalizedReceiverDistance * normalizedReceiverDistance);
    radial = radial * radial
        / max(1.0f + 5.0f * normalizedReceiverDistance * normalizedReceiverDistance, 0.001f);
    float diffuse = saturate(normalDotLight / distance);
    float3 contribution = radial * diffuse * lightColorIntensity.rgb;
    if (!any(contribution > 0.0f)) return empty;
    float3 rasterRay;
    float3 cubeDirection = PointCubeSampleDirection(toLight * float3(-1.0f, -1.0f, 1.0f), rasterRay);
    float normalizedCubeDistance = distance / lightPositionRadius.w;
    float planeDenominator = dot(normal, rasterRay);
    float planeNumerator = normalDotLight * length(rasterRay);
    // Intersect the receiver's local plane with the ray which generated the
    // sampled radial depth. Only a positive intersection inside the native
    // cube volume replaces the original comparison; parallel, opposite, or
    // out-of-volume intersections keep its bounded distance-scaled bias.
    float planeScale = planeDenominator * lightPositionRadius.w;
    if (planeDenominator > 0.0f && planeScale < 3.402823466e+38f && planeNumerator < planeScale)
        normalizedCubeDistance = planeNumerator / planeScale;
    float casterDepth = texCUBElod(shadowCube, float4(cubeDirection, 0.0f)).r;
    float shadowVisibility = casterDepth
            + PointControl.z * normalizedCubeDistance >= normalizedCubeDistance
        ? 1.0f : 0.0f;
    shadowVisibility = lerp(
        1.0f, shadowVisibility, casterDepth > 0.0f && casterDepth < 1.0f);
    float outerEnvelope = 1.0f - smoothstep(0.8f, 1.0f, normalizedReceiverDistance);
    // These presentation weights belong only to subtractable occluded energy.
    // Applying them to `total` as well makes deficit/total cancel every fade.
    // The radial depth bias already keeps a generating surface from
    // self-shadowing, and final composition independently preserves HDR
    // emission. A radius-wide source guard also suppresses nearby opaque
    // fixtures, so it made lamp-cage shadows pulse as the flame moved.
    float shadowWeight = outerEnvelope * lightMetadata.y;
    float3 deficit = contribution * (1.0f - shadowVisibility) * shadowWeight;
    LightEnergy result;
    result.total = contribution;
    result.deficit = deficit;
    return result;
}

PointOutput Main(PixelInput input) {
    float2 centerUv = SnapDepthUv(input.uv);
    float rawDepth = tex2Dlod(SceneDepth, float4(centerUv, 0.0f, 0.0f)).r;
    if (!(rawDepth > 1.0f / 65536.0f && rawDepth < 1.0f - 1.0f / 65536.0f)) {
        PointOutput empty;
        empty.deficit = 0.0f;
        empty.total = 0.0f;
        return empty;
    }

    float depth = LinearDepth(rawDepth);
    if (!(depth > 0.0f && depth < DepthLinearizeData.w)) {
        PointOutput empty;
        empty.deficit = 0.0f;
        empty.total = 0.0f;
        return empty;
    }
    float3 worldPosition = RelativeWorldPosition(centerUv, depth);
    float3 normal = ShadowReceiverWorldNormal(centerUv, depth);
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
