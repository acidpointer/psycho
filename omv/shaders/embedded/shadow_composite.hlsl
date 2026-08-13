// Source-owned OMV world-shadow composition. Fog, alpha, and first person draw later.
#ifndef OMV_POINT_LIGHTS
#define OMV_POINT_LIGHTS 1
#endif

float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
row_major float4x4 CascadeMatrices[4] : register(c6);
float4 CascadeSplits : register(c22);
float4 ShadowControl : register(c23); // x reversed, y directional enabled, z darkness
float4 CascadeBlendWidth : register(c24);
float4 CascadeTexel : register(c25); // x half texel, y one minus half texel, z radius
float4 DepthControl : register(c26); // x endpoint epsilon
float4 CascadeSpheres[4] : register(c27);
float4 ContactControl : register(c31); // x contact texture enabled
float4 PointControl : register(c32); // x point buffer enabled, y darkness
float4 SunDirection : register(c33);
float4 ActorControl : register(c34); // xyz actor-only near/middle/far maps enabled
float4 ContactTexel : register(c35); // xy half-resolution contact texel

static const float ContactDepthKeyRange = 250000.0f;

sampler2D SourceColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D ShadowAtlas : register(s2);
sampler2D PointShadowBuffer : register(s3);
sampler2D ContactVisibility : register(s4);
sampler2D ActorNearMiddleMoments : register(s5);
sampler2D PointLightTotal : register(s6);
sampler2D ActorFarMoments : register(s7);

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (ShadowControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float3 ViewPosition(float2 uv, float depth) {
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

float3 RelativeWorldPosition(float2 uv, float depth) {
    float3 view = ViewPosition(uv, depth);
    float4 homogeneous = float4(view, 1.0f);
    return float3(dot(ViewToWorld0, homogeneous), dot(ViewToWorld1, homogeneous), dot(ViewToWorld2, homogeneous));
}

bool HasGeometryDepth(float rawDepth) {
    return rawDepth > DepthControl.x && rawDepth < 1.0f - DepthControl.x;
}

float3 ReconstructWorldNormal(float2 uv, float centerDepth) {
    // Select the depth-nearest derivative on each axis. This avoids crossing a
    // silhouette while remaining deterministic across the fullscreen quad's
    // triangle diagonal; ddx/ddy are undefined after receiver rejection.
    float2 pixel = ScreenData.zw;
    float rawLeft = tex2Dlod(SceneDepth, float4(uv - float2(pixel.x, 0.0f), 0.0f, 0.0f)).r;
    float rawRight = tex2Dlod(SceneDepth, float4(uv + float2(pixel.x, 0.0f), 0.0f, 0.0f)).r;
    float rawUp = tex2Dlod(SceneDepth, float4(uv - float2(0.0f, pixel.y), 0.0f, 0.0f)).r;
    float rawDown = tex2Dlod(SceneDepth, float4(uv + float2(0.0f, pixel.y), 0.0f, 0.0f)).r;
    float leftDepth = HasGeometryDepth(rawLeft) ? LinearDepth(rawLeft) : centerDepth;
    float rightDepth = HasGeometryDepth(rawRight) ? LinearDepth(rawRight) : centerDepth;
    float upDepth = HasGeometryDepth(rawUp) ? LinearDepth(rawUp) : centerDepth;
    float downDepth = HasGeometryDepth(rawDown) ? LinearDepth(rawDown) : centerDepth;
    float3 center = ViewPosition(uv, centerDepth);
    float3 left = ViewPosition(uv - float2(pixel.x, 0.0f), leftDepth);
    float3 right = ViewPosition(uv + float2(pixel.x, 0.0f), rightDepth);
    float3 up = ViewPosition(uv - float2(0.0f, pixel.y), upDepth);
    float3 down = ViewPosition(uv + float2(0.0f, pixel.y), downDepth);
    float3 dx = abs(leftDepth - centerDepth) < abs(rightDepth - centerDepth)
        ? center - left : right - center;
    float3 dy = abs(upDepth - centerDepth) < abs(downDepth - centerDepth)
        ? center - up : down - center;
    float3 viewNormal = cross(dx, dy);
    viewNormal *= rsqrt(max(dot(viewNormal, viewNormal), 0.0000001f));
    float4 normalVector = float4(viewNormal, 0.0f);
    return float3(dot(ViewToWorld0, normalVector), dot(ViewToWorld1, normalVector), dot(ViewToWorld2, normalVector));
}

float CascadeBleedReduction(int cascadeIndex) {
    return cascadeIndex == 0 ? 0.1f
        : (cascadeIndex == 1 ? 0.2f : (cascadeIndex == 2 ? 0.6f : 0.8f));
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
    // This is NVR's 0.01 receiver-bias-derived FP16 variance floor.
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

float4 NearestMoments(float4 left, float4 right) {
    // The first EVSM component is exp(positiveExponent * depth), hence the
    // smaller mean belongs to the nearer complete depth distribution. Never
    // take a component-wise minimum: the negative squared moment has the
    // opposite ordering and would no longer describe any distribution.
    return right.x < left.x ? right : left;
}

float4 SampleActorMoments(float2 uv, int cascadeIndex) {
    if (cascadeIndex < 2) {
        float2 packedUv = float2(uv.x * 0.5f + 0.5f * cascadeIndex, uv.y);
        return tex2Dlod(ActorNearMiddleMoments, float4(packedUv, 0.0f, 0.0f));
    }
    return tex2Dlod(ActorFarMoments, float4(uv, 0.0f, 0.0f));
}

float CascadeVisibility(row_major float4x4 transform, int cascadeIndex, float3 worldPosition) {
    float4 projected = mul(float4(worldPosition, 1.0f), transform);
    if (projected.w <= 0.0f) return 1.0f;
    float3 ndc = projected.xyz / max(projected.w, 0.000001f);
    float2 localUv = float2(ndc.x * 0.5f + 0.5f, 0.5f - ndc.y * 0.5f);
    if (min(localUv.x, localUv.y) < 0.0f || max(localUv.x, localUv.y) > 1.0f ||
        ndc.z < 0.0f || ndc.z > 1.0f) return 1.0f;

    float bleed = CascadeBleedReduction(cascadeIndex);
    float4 staticCenter = tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv, cascadeIndex), 0.0f, 0.0f));
    float4 center = staticCenter;
    float4 actor = staticCenter;
    float hasActor = cascadeIndex < 3 && ActorControl[cascadeIndex] > 0.5f;
    if (hasActor) {
        actor = SampleActorMoments(clamp(localUv, CascadeTexel.xx, CascadeTexel.yy), cascadeIndex);
        // Actor maps use a hardware-zero clear so their presentation-rate
        // update does not run a full 2048-square four-sample far-clear shader.
        // Positive EVSM's first moment is strictly positive for every valid
        // depth, making zero an unambiguous empty-texel sentinel.
        hasActor = actor.x > 0.0f;
        if (hasActor) center = NearestMoments(center, actor);
    }
    float visibility = Evsm4(center, saturate(ndc.z), bleed);
    // Hardware bilinear is sufficient in flat regions. Only an actual EVSM
    // transition pays two opposite diagonal reads. Each read is itself a
    // bilinear four-texel footprint, so this reconstructs a symmetric edge
    // filter without charging every 3440x1440 receiver five atlas lookups.
    if (visibility > 0.02f && visibility < 0.98f) {
        float2 radius = CascadeTexel.zz;
        // Filter only the static distribution as before. Actor moments are
        // already bilinear and stay a complete distribution; re-select them
        // after filtering rather than averaging unrelated static/actor
        // moments and creating light leaks.
        float4 filtered = staticCenter
            + tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv + float2(-radius.x, -radius.y), cascadeIndex), 0.0f, 0.0f))
            + tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv + float2( radius.x,  radius.y), cascadeIndex), 0.0f, 0.0f));
        filtered /= 3.0f;
        visibility = Evsm4(hasActor ? NearestMoments(filtered, actor) : filtered,
            saturate(ndc.z), bleed);
    }
    return visibility;
}

float DirectionalVisibility(float3 worldPosition) {
    float3 delta0 = worldPosition - CascadeSpheres[0].xyz;
    float3 delta1 = worldPosition - CascadeSpheres[1].xyz;
    float3 delta2 = worldPosition - CascadeSpheres[2].xyz;
    float3 delta3 = worldPosition - CascadeSpheres[3].xyz;
    float4 distanceSquared = float4(
        dot(delta0, delta0), dot(delta1, delta1),
        dot(delta2, delta2), dot(delta3, delta3));
    float4 radiusSquared = float4(
        CascadeSpheres[0].w * CascadeSpheres[0].w,
        CascadeSpheres[1].w * CascadeSpheres[1].w,
        CascadeSpheres[2].w * CascadeSpheres[2].w,
        CascadeSpheres[3].w * CascadeSpheres[3].w);
    int cascade = distanceSquared.x < radiusSquared.x ? 0
        : (distanceSquared.y < radiusSquared.y ? 1
        : (distanceSquared.z < radiusSquared.z ? 2
        : (distanceSquared.w < radiusSquared.w ? 3 : -1)));
    if (cascade < 0) return 1.0f;

    float radius = CascadeSpheres[cascade].w;
    float distance = sqrt(distanceSquared[cascade]);
    float current = CascadeVisibility(
        CascadeMatrices[cascade], cascade, worldPosition);
    float blend = smoothstep(radius * 0.9f, radius, distance);
    if (cascade >= 3) return lerp(current, 1.0f, blend);
    if (blend <= 0.0f) return current;
    float next = CascadeVisibility(
        CascadeMatrices[cascade + 1], cascade + 1, worldPosition);
    return lerp(current, next, blend);
}

float2 ContactTap(float2 uv, float receiverDepth, float tolerance) {
    float2 contact = tex2Dlod(ContactVisibility, float4(uv, 0.0f, 0.0f)).rg;
    float contactDepth = contact.g * ContactDepthKeyRange;
    float accepted = contact.g > 0.0f && abs(contactDepth - receiverDepth) <= tolerance;
    return float2(contact.r * accepted, accepted);
}

float ContactVisibilityForReceiver(float2 uv, float receiverDepth) {
    // Most full-resolution pixels and their nearest half-resolution contact
    // texel belong to the same receiver and pay one lookup. At a 2x2-block
    // depth edge, point upsampling would attach the odd pixel's key to the even
    // pixel and create a moving line. Only that mismatch pays a four-tap
    // bilateral lookup, rejecting each foreign receiver before interpolation.
    float2 nearest = tex2Dlod(ContactVisibility, float4(uv, 0.0f, 0.0f)).rg;
    float nearestDepth = nearest.g * ContactDepthKeyRange;
    float tolerance = max(2.0f, receiverDepth * 0.0025f);
    if (nearest.g > 0.0f && abs(nearestDepth - receiverDepth) <= tolerance)
        return nearest.r;

    float2 contactTexel = ContactTexel.xy;
    float accepted = nearest.g > 0.0f && abs(nearestDepth - receiverDepth) <= tolerance;
    float2 resolved = float2(nearest.r * accepted, accepted);
    // The nearest point sample is already one member of the full-resolution
    // pixel's surrounding 2x2 half-resolution footprint. Select the other
    // three from the receiver's side of that texel center. This is both a more
    // accurate bilateral upsample and one fewer texture read than resampling a
    // four-arm cross after the rejected nearest lookup.
    float2 nearestCenter = (floor(uv / contactTexel) + 0.5f) * contactTexel;
    float2 direction = float2(
        uv.x >= nearestCenter.x ? contactTexel.x : -contactTexel.x,
        uv.y >= nearestCenter.y ? contactTexel.y : -contactTexel.y);
    resolved += ContactTap(uv + float2(direction.x, 0.0f), receiverDepth, tolerance);
    resolved += ContactTap(uv + float2(0.0f, direction.y), receiverDepth, tolerance);
    resolved += ContactTap(uv + direction, receiverDepth, tolerance);
    return resolved.y > 0.0001f ? resolved.x / resolved.y : 1.0f;
}

float4 Main(PixelInput input) : COLOR0 {
    float4 source = tex2Dlod(SourceColor, float4(input.uv, 0.0f, 0.0f));
    float rawDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
    if (rawDepth <= DepthControl.x || rawDepth >= 1.0f - DepthControl.x) return source;

    float viewDepth = LinearDepth(rawDepth);
    // FNV sky meshes may write finite depth at the camera far plane. The same
    // endpoint-plus-far classifier is shared by OMV DOF/sun visibility; it is
    // independent of cascade distance and therefore cannot change with shadow
    // sliders or camera angle.
    if (viewDepth <= 0.0f || viewDepth >= DepthLinearizeData.w * 0.985f) return source;
    float3 worldPosition = RelativeWorldPosition(input.uv, viewDepth);

    float directional = 1.0f;
    if (ShadowControl.y > 0.5f) {
        if (viewDepth < CascadeSplits.w) {
            directional = DirectionalVisibility(worldPosition);
            // Receiver bias matters at an actual shadow transition. Keeping
            // neighbor depth reconstruction inside this branch avoids four
            // full-resolution reads for uniformly lit or shadowed pixels.
            if (directional > 0.02f && directional < 0.98f) {
                float3 normal = ReconstructWorldNormal(input.uv, viewDepth);
                float normalOffset = saturate(1.0f - dot(normal, SunDirection.xyz));
                directional = DirectionalVisibility(worldPosition + normal * normalOffset);
            }
        }
        // NVR contact rays own an independent, much longer view-depth range.
        // Gating them by CascadeSplits.w made the default effect disappear as
        // soon as a receiver left the roughly 6000-unit mapped region.
        if (ContactControl.x > 0.5f) {
            directional = min(
                directional,
                ContactVisibilityForReceiver(input.uv, viewDepth));
        }
        directional = 1.0f - saturate(ShadowControl.z) * (1.0f - directional);
    }

#if OMV_POINT_LIGHTS
    float3 pointDeficit = max(
        tex2Dlod(PointShadowBuffer, float4(input.uv, 0.0f, 0.0f)).rgb, 0.0f);
    float3 pointTotal = max(
        tex2Dlod(PointLightTotal, float4(input.uv, 0.0f, 0.0f)).rgb, 0.0f);
    float3 linearSource = pow(max(source.rgb, 0.0f), 2.2f);
    // Values above one identify an HDR emitter/highlight. NVR re-adds its HDR
    // excess; preserving the complete source is stricter and prevents lamp
    // meshes from becoming black while their surrounding direct light still
    // receives cube-proven occlusion.
    float emitter = smoothstep(1.0f, 1.15f, max(linearSource.r, max(linearSource.g, linearSource.b)));
    float3 ownedLocal = min(pointTotal, linearSource);
    pointDeficit = min(pointDeficit, ownedLocal) * saturate(PointControl.y);
    // Directional light owns no local-source energy. Restore that term after
    // applying the sun factor, then subtract only cube-proven local occlusion.
    float3 shadowed = max(
        linearSource * directional + ownedLocal * (1.0f - directional) - pointDeficit,
        0.0f);
    // The analytic replacement-light estimate may exceed the energy actually
    // present in the native material. Exterior local shadows may remove that
    // light down to the sun-only surface, never cut through it into unrelated
    // ambient energy. Interiors have no directional lower bound.
    if (ShadowControl.y > 0.5f)
        shadowed = max(shadowed, linearSource * directional);
    float3 finalLinear = lerp(shadowed, linearSource, emitter);
    return float4(pow(max(finalLinear, 0.0f), 1.0f / 2.2f), source.a);
#else
    // With no selected local light, the source-owned equation reduces exactly
    // to one scalar attenuation. Specializing this overwhelmingly common
    // exterior path removes two full-resolution point-buffer reads and six
    // component-wise pow operations without changing directional, contact,
    // actor, HDR-emitter, or gamma behavior.
    float maximumSource = max(source.r, max(source.g, source.b));
    float emitter = smoothstep(1.0f, 1.15f, pow(max(maximumSource, 0.0f), 2.2f));
    float attenuation = lerp(directional, 1.0f, emitter);
    return float4(
        source.rgb * pow(attenuation, 1.0f / 2.2f),
        source.a);
#endif
}
