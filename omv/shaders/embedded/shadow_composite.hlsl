// Source-owned OMV world-shadow composition. Fog, alpha, and first person draw later.
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
float4 ActorControl : register(c34); // x actor-only near map enabled

sampler2D SourceColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D ShadowAtlas : register(s2);
sampler2D PointShadowBuffer : register(s3);
sampler2D ContactVisibility : register(s4);
sampler2D ActorMoments : register(s5);
sampler2D PointLightTotal : register(s6);

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

float CascadeVisibility(row_major float4x4 transform, int cascadeIndex, float3 worldPosition) {
    float4 projected = mul(float4(worldPosition, 1.0f), transform);
    float3 ndc = projected.xyz / max(projected.w, 0.000001f);
    float2 localUv = float2(ndc.x * 0.5f + 0.5f, 0.5f - ndc.y * 0.5f);
    if (min(localUv.x, localUv.y) < 0.0f || max(localUv.x, localUv.y) > 1.0f) return 1.0f;

    float bleed = CascadeBleedReduction(cascadeIndex);
    float4 center = tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv, cascadeIndex), 0.0f, 0.0f));
    float visibility = Evsm4(center, saturate(ndc.z), bleed);
    // Hardware bilinear is sufficient in flat regions. Only an actual EVSM
    // transition pays two opposite diagonal reads. Each read is itself a
    // bilinear four-texel footprint, so this reconstructs a symmetric edge
    // filter without charging every 3440x1440 receiver five atlas lookups.
    if (visibility > 0.02f && visibility < 0.98f) {
        float2 radius = CascadeTexel.zz;
        float4 filtered = center
            + tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv + float2(-radius.x, -radius.y), cascadeIndex), 0.0f, 0.0f))
            + tex2Dlod(ShadowAtlas, float4(AtlasUv(localUv + float2( radius.x,  radius.y), cascadeIndex), 0.0f, 0.0f));
        visibility = Evsm4(filtered / 3.0f, saturate(ndc.z), bleed);
    }
    return visibility;
}

float ActorVisibility(float3 worldPosition) {
    if (ActorControl.x <= 0.5f) return 1.0f;
    float4 projected = mul(float4(worldPosition, 1.0f), CascadeMatrices[0]);
    float3 ndc = projected.xyz / max(projected.w, 0.000001f);
    float2 uv = float2(ndc.x * 0.5f + 0.5f, 0.5f - ndc.y * 0.5f);
    if (min(uv.x, uv.y) < 0.0f || max(uv.x, uv.y) > 1.0f) return 1.0f;
    uv = clamp(uv, CascadeTexel.xx, CascadeTexel.yy);
    // The actor producer already uses NVR's four coverage samples and this
    // lookup is bilinear. A second transition kernel would add map reads to
    // every near-cascade specialization for little silhouette improvement.
    float4 moments = tex2Dlod(ActorMoments, float4(uv, 0.0f, 0.0f));
    return Evsm4(moments, saturate(ndc.z), CascadeBleedReduction(0));
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
    float current = CascadeVisibility(CascadeMatrices[cascade], cascade, worldPosition);
    if (cascade == 0) current = min(current, ActorVisibility(worldPosition));
    float blend = smoothstep(radius * 0.9f, radius, distance);
    if (cascade >= 3) return lerp(current, 1.0f, blend);
    if (blend <= 0.0f) return current;
    float next = CascadeVisibility(CascadeMatrices[cascade + 1], cascade + 1, worldPosition);
    return lerp(current, next, blend);
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
            float2 contact = tex2Dlod(
                ContactVisibility, float4(input.uv, 0.0f, 0.0f)).rg;
            float contactMatchesReceiver = contact.g > 0.0f &&
                abs(contact.g - viewDepth) <= max(2.0f, viewDepth * 0.0025f);
            directional = min(directional, contactMatchesReceiver ? contact.r : 1.0f);
        }
        directional = 1.0f - saturate(ShadowControl.z) * (1.0f - directional);
    }

    float3 pointDeficit = 0.0f;
    float3 pointTotal = 0.0f;
    if (PointControl.x > 0.5f) {
        pointDeficit = max(
            tex2Dlod(PointShadowBuffer, float4(input.uv, 0.0f, 0.0f)).rgb, 0.0f);
        pointTotal = max(
            tex2Dlod(PointLightTotal, float4(input.uv, 0.0f, 0.0f)).rgb, 0.0f);
    }

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
    float3 finalLinear = lerp(shadowed, linearSource, emitter);
    return float4(pow(max(finalLinear, 0.0f), 1.0f / 2.2f), source.a);
}
