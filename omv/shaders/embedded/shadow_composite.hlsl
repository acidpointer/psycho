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

sampler2D SourceColor : register(s0);
sampler2D SceneDepth : register(s1);
sampler2D ShadowAtlas : register(s2);
sampler2D PointShadowBuffer : register(s3);
sampler2D ContactVisibility : register(s4);

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

float3 ReconstructWorldNormal(float3 viewPosition) {
    // Quad derivatives recover the same planar normal without four more
    // full-resolution depth fetches. They are used only for this one-world-
    // unit receiver bias, never to place contact-ray evidence; silhouette
    // ownership still comes from the map and depth receiver classifier.
    float3 viewNormal = cross(ddx(viewPosition), ddy(viewPosition));
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
            // Modern NVR separates a receiver from its own moments by one
            // world unit at grazing incidence. Reconstructing from current
            // depth avoids a separately timed normals-buffer dependency.
            float3 normal = ReconstructWorldNormal(ViewPosition(input.uv, viewDepth));
            // The producer publishes a normalized stabilized sun vector.
            float normalOffset = saturate(1.0f - dot(normal, SunDirection.xyz));
            directional = DirectionalVisibility(worldPosition + normal * normalOffset);
        }
        // NVR contact rays own an independent, much longer view-depth range.
        // Gating them by CascadeSplits.w made the default effect disappear as
        // soon as a receiver left the roughly 6000-unit mapped region.
        if (ContactControl.x > 0.5f) {
            directional = min(directional,
                tex2Dlod(ContactVisibility, float4(input.uv, 0.0f, 0.0f)).r);
        }
        directional = 1.0f - saturate(ShadowControl.z) * (1.0f - directional);
    }

    float3 pointDeficit = 0.0f;
    if (PointControl.x > 0.5f) {
        pointDeficit = max(tex2Dlod(PointShadowBuffer, float4(input.uv, 0.0f, 0.0f)).rgb, 0.0f)
            * saturate(PointControl.y);
    }

    float3 linearSource = pow(max(source.rgb, 0.0f), 2.2f);
    // Values above one identify an HDR emitter/highlight. NVR re-adds its HDR
    // excess; preserving the complete source is stricter and prevents lamp
    // meshes from becoming black while their surrounding direct light still
    // receives cube-proven occlusion.
    float emitter = smoothstep(1.0f, 1.15f, max(linearSource.r, max(linearSource.g, linearSource.b)));
    float3 shadowed = max(linearSource * directional - pointDeficit, 0.0f);
    float3 finalLinear = lerp(shadowed, linearSource, emitter);
    return float4(pow(max(finalLinear, 0.0f), 1.0f / 2.2f), source.a);
}
