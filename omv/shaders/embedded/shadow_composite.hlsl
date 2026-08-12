// OMV world-shadow compositor. Runs before atmosphere, alpha, and later effects.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
row_major float4x4 CascadeMatrices[4] : register(c6);
float4 CascadeSplits : register(c22);
float4 ShadowControl : register(c23); // x reversed, y exterior, z darkness, w bleed reduction
float4 CascadeBlendWidth : register(c24);
float4 CascadeTexel : register(c25); // x half texel, y one minus half texel
float4 DepthControl : register(c26); // x endpoint epsilon
float4 CascadeSpheres[4] : register(c27); // xyz camera-relative center, w coverage radius
float4 ContactControl : register(c31); // x enabled, y max depth, z stable EVSM contrast

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
    return ReduceLightBleeding(
        variance / (variance + difference * difference), bleedReduction);
}

static const float EvsmReceiverBias = 0.01f;

float Evsm4(float4 moments, float depth, float bleedReduction) {
    float normalized = depth * 2.0f - 1.0f;
    float2 warped = float2(exp(5.54f * normalized), -exp(-5.0f * normalized));
    // NVR derives the minimum EVSM variance from a 0.01 receiver bias. The
    // former 0.00002 value was 500 times smaller and exposed quantization as
    // self-shadow speckle that blinked on broad walls.
    float2 scale = EvsmReceiverBias * float2(5.54f, 5.0f) * warped;
    return min(
        Chebyshev(moments.xz, warped.x, scale.x * scale.x, bleedReduction),
        Chebyshev(moments.yw, warped.y, scale.y * scale.y, bleedReduction));
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
    float3 worldPosition,
    float2 texelOffset)
{
    float4 projected = mul(float4(worldPosition, 1.0f), transform);
    float3 ndc = projected.xyz / max(projected.w, 0.000001f);
    float2 localUv = float2(ndc.x * 0.5f + 0.5f, 0.5f - ndc.y * 0.5f);
    if (min(localUv.x, localUv.y) < 0.0f || max(localUv.x, localUv.y) > 1.0f) return 1.0f;
    float2 uv = AtlasUv(localUv + texelOffset, cascadeIndex);
    return Evsm4(
        tex2Dlod(ShadowAtlas, float4(uv, 0.0f, 0.0f)),
        saturate(ndc.z),
        CascadeBleedReduction(cascadeIndex));
}

float ContactFilteredVisibility(
    row_major float4x4 transform,
    int cascadeIndex,
    float3 worldPosition,
    float viewDepth)
{
    float visibility = CascadeVisibility(transform, cascadeIndex, worldPosition, 0.0f);
    if (ContactControl.x <= 0.5f || viewDepth >= ContactControl.y) return visibility;

    // Refine the stable EVSM probability itself instead of searching camera
    // depth or offsetting the light-map receiver. Squaring uncertain values
    // tightens soft contact transitions while preserving fully lit/shadowed
    // endpoints, adds no texture work, and cannot invent camera-following
    // occluders or move a silhouette across an atlas boundary.
    float strength = saturate(ContactControl.z * 0.15f);
    return lerp(visibility, visibility * visibility, strength);
}

float DirectionalVisibility(float3 worldPosition, float viewDepth) {
    // Cached maps retain the receiver sphere that was used to generate them.
    // Selecting by current-camera view depth can choose a quadrant whose
    // retained projection no longer contains the receiver, producing moving
    // holes and abrupt distant disappearance. NVR selects the first owning
    // sphere and blends only through its outer ten percent.
    float4 distances = float4(
        length(worldPosition - CascadeSpheres[0].xyz),
        length(worldPosition - CascadeSpheres[1].xyz),
        length(worldPosition - CascadeSpheres[2].xyz),
        length(worldPosition - CascadeSpheres[3].xyz));
    int cascade = distances.x < CascadeSpheres[0].w ? 0
        : (distances.y < CascadeSpheres[1].w ? 1
        : (distances.z < CascadeSpheres[2].w ? 2
        : (distances.w < CascadeSpheres[3].w ? 3 : -1)));
    if (cascade < 0) return 1.0f;

    float radius = CascadeSpheres[cascade].w;
    float distanceToCenter = distances[cascade];
    float current = ContactFilteredVisibility(
        CascadeMatrices[cascade], cascade, worldPosition, viewDepth);
    float blend = smoothstep(radius * 0.9f, radius, distanceToCenter);
    if (cascade >= 3) return lerp(current, 1.0f, blend);
    if (blend <= 0.0f) return current;

    float next = ContactFilteredVisibility(
        CascadeMatrices[cascade + 1], cascade + 1, worldPosition, viewDepth);
    return lerp(current, next, blend);
}

float4 Main(PixelInput input) : COLOR0 {
    float rawDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
    if (rawDepth <= DepthControl.x || rawDepth >= 1.0f - DepthControl.x) {
        return float4(1.0f, 1.0f, 1.0f, 1.0f);
    }
    float viewDepth = LinearDepth(rawDepth);
    float3 worldPosition = RelativeWorldPosition(input.uv, viewDepth);
    if (ShadowControl.y > 0.5f) {
        float raw = DirectionalVisibility(worldPosition, viewDepth);
        float visibility = 1.0f - saturate(ShadowControl.z) * (1.0f - raw);
        return float4(visibility.xxx, 1.0f);
    }
    float4 pointShadow = tex2Dlod(PointShadowBuffer, float4(input.uv, 0.0f, 0.0f));
    // Interior composition uses reverse-subtract blending. Returning the
    // occluded RGB contribution removes only direct energy from selected
    // native point lights; ambient, emissive, and the light source itself are
    // no longer multiplied by a global darkness factor.
    return float4(saturate(pointShadow.rgb * ShadowControl.z), 1.0f);
}
