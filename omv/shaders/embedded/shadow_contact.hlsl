// NVR-derived exterior screen-space contact shadows without derivative or noise textures.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ContactControl : register(c6); // x reversed, y max depth, z ray distance, w thickness
float4 ViewLightDirection : register(c7);
float4 ContactSampleOffsets : register(c8);
float4 ContactDepthPrecision : register(c9); // x inverse provider depth levels
sampler2D SceneDepth : register(s0);

static const float DepthEndpointEpsilon = 1.0f / 65536.0f;
static const float ContactDepthKeyRange = 250000.0f;

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (ContactControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float RawDepth(float linearDepth) {
    if (ContactControl.x > 0.5f) {
        return (DepthLinearizeData.x / linearDepth - DepthLinearizeData.z) /
            DepthLinearizeData.y;
    }
    return (DepthLinearizeData.w - DepthLinearizeData.x / linearDepth) /
        DepthLinearizeData.y;
}

float3 ViewPosition(float2 uv, float rawDepth) {
    float depth = LinearDepth(rawDepth);
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

bool HasGeometryDepth(float rawDepth) {
    // Ordinary and reversed targets clear to opposite endpoints. Both are
    // background, not far-plane geometry that may occlude a contact ray.
    return rawDepth > DepthEndpointEpsilon && rawDepth < (1.0f - DepthEndpointEpsilon);
}

float2 SnapDepthUv(float2 uv) {
    // Reconstruct the exact full-resolution texel selected by point sampling
    // so clamped edge coordinates cannot shift the view position during
    // sub-pixel camera motion.
    float2 texel = clamp(floor(uv * ScreenData.xy), 0.0f, ScreenData.xy - 1.0f);
    return (texel + 0.5f) * ScreenData.zw;
}

float2 ProjectViewPosition(float3 position) {
    float inverseDepth = rcp(max(position.z, 0.001f));
    float projectedX = position.x * inverseDepth;
    float projectedY = position.y * inverseDepth;
    return float2(
        (projectedX - CameraFrustum.x) / (CameraFrustum.y - CameraFrustum.x),
        (CameraFrustum.w - projectedY) / (CameraFrustum.w - CameraFrustum.z));
}

float2 ReceiverRawDepthGradient(
    float2 centerUv,
    float centerRawDepth,
    float centerDepth,
    float2 projectedRayUv,
    out float valid,
    out float planeRawEpsilon) {
    float2 pixel = ScreenData.zw;
    // Sample away from the projected light ray. A touching caster is expected
    // on the ray-facing side; the opposite two receiver samples build its
    // supporting plane without crossing that silhouette. This preserves the
    // four ray taps while halving the normal-estimation depth work.
    float horizontalSign = projectedRayUv.x >= centerUv.x ? -1.0f : 1.0f;
    float verticalSign = projectedRayUv.y >= centerUv.y ? -1.0f : 1.0f;
    float2 horizontalUv = SnapDepthUv(
        centerUv + float2(horizontalSign * pixel.x, 0.0f));
    float2 verticalUv = SnapDepthUv(
        centerUv + float2(0.0f, verticalSign * pixel.y));
    float rawHorizontal = tex2Dlod(SceneDepth, float4(horizontalUv, 0.0f, 0.0f)).r;
    float rawVertical = tex2Dlod(SceneDepth, float4(verticalUv, 0.0f, 0.0f)).r;
    float horizontalValid = HasGeometryDepth(rawHorizontal) ? 1.0f : 0.0f;
    float verticalValid = HasGeometryDepth(rawVertical) ? 1.0f : 0.0f;
    float receiverTolerance = max(2.0f, centerDepth * 0.0025f);
    float receiverRawTolerance = max(
        abs(RawDepth(centerDepth + receiverTolerance) - centerRawDepth),
        2.0f / 16777216.0f);
    planeRawEpsilon = max(
        abs(RawDepth(centerDepth + max(0.5f, centerDepth * 0.00001f)) - centerRawDepth),
        1.0f / 16777216.0f);
    float horizontalOffset = horizontalUv.x - centerUv.x;
    float verticalOffset = verticalUv.y - centerUv.y;
    valid = horizontalValid * verticalValid *
        (abs(horizontalOffset) >= pixel.x * 0.5f) *
        (abs(verticalOffset) >= pixel.y * 0.5f) *
        (abs(rawHorizontal - centerRawDepth) <= receiverRawTolerance) *
        (abs(rawVertical - centerRawDepth) <= receiverRawTolerance);
    // Post-projection device depth is affine over a rasterized plane. Building
    // this gradient in raw depth is both exact for the receiver primitive and
    // cheaper than repeatedly reconstructing view-space neighbor positions.
    return float2(
        (rawHorizontal - centerRawDepth) /
            ((horizontalOffset < 0.0f ? -1.0f : 1.0f) * max(abs(horizontalOffset), pixel.x)),
        (rawVertical - centerRawDepth) /
            ((verticalOffset < 0.0f ? -1.0f : 1.0f) * max(abs(verticalOffset), pixel.y)));
}

float ContactSample(
    float2 receiverUv,
    float receiverRawDepth,
    float2 receiverRawGradient,
    float planeRawEpsilon,
    float3 marched,
    float thickness) {
    float2 uv = ProjectViewPosition(marched);
    if (min(uv.x, uv.y) <= 0.0f || max(uv.x, uv.y) >= 1.0f) return 0.0f;
    uv = SnapDepthUv(uv);
    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
    if (!HasGeometryDepth(rawDepth)) return 0.0f;
    float sceneDepth = LinearDepth(rawDepth);
    float predictedReceiverRawDepth = receiverRawDepth +
        dot(receiverRawGradient, uv - receiverUv);
    float delta = marched.z - sceneDepth;
    // Each endpoint used to infer the affine raw-depth gradient is quantized.
    // Its uncertainty accumulates with extrapolation distance; a fixed one-LSB
    // test turns shallow, distant walls into detached camera-dependent blocks.
    float2 sampleOffsetPixels = abs(uv - receiverUv) * ScreenData.xy;
    float quantizationEpsilon = ContactDepthPrecision.x *
        (2.0f + sampleOffsetPixels.x + sampleOffsetPixels.y);
    float separatePlane = abs(rawDepth - predictedReceiverRawDepth) >
        max(planeRawEpsilon, quantizationEpsilon);
    return delta > 0.01f && delta < thickness && separatePlane ? 1.0f : 0.0f;
}

float4 Main(PixelInput input) : COLOR0 {
    float2 centerUv = SnapDepthUv(input.uv);
    float rawCenterDepth = tex2Dlod(SceneDepth, float4(centerUv, 0.0f, 0.0f)).r;
    if (!HasGeometryDepth(rawCenterDepth)) return float4(1.0f, 0.0f, 0.0f, 1.0f);
    float3 center = ViewPosition(centerUv, rawCenterDepth);
    if (center.z <= 0.0f || center.z >= ContactControl.y) return float4(1.0f, 0.0f, 0.0f, 1.0f);
    // Four deterministic tests retain NVR's five-step screen-space contract
    // (its paired source loop emits cumulative positions 1, 3, 6, and 10).
    // Fixed positions are deliberate:
    // screen-anchored noise moves across world surfaces with camera motion and
    // made contact shadows visibly blink on walls.
    // NVR scales ray length by the camera depth range, not by the user-facing
    // contact cutoff. Coupling the two made a distance-slider edit move every
    // existing contact shadow and amplified camera-dependent false shapes.
    float normalizedDepth = saturate(length(center) / DepthLinearizeData.w);
    float rayScale = pow(max(normalizedDepth, 0.0001f), 0.6f);
    float3 stepVector = normalize(ViewLightDirection.xyz) *
        (ContactControl.z / 5.0f) * rayScale;
    float planeValid = 0.0f;
    float planeRawEpsilon = 0.0f;
    float2 receiverGradient = ReceiverRawDepthGradient(
        centerUv,
        rawCenterDepth,
        center.z,
        ProjectViewPosition(center + stepVector),
        planeValid,
        planeRawEpsilon);
    if (planeValid < 0.5f) return float4(1.0f, center.z / ContactDepthKeyRange, 0.0f, 1.0f);
    float occlusion = 0.0f;
    float weight = 0.0f;
    // Keep one bounded shader loop instead of four compiler-inlined projection
    // bodies. The native upload owns the exact cumulative positions so the
    // contract can be validated without HLSL source-text assertions.
    [loop]
    for (int sampleIndex = 0; sampleIndex < 4; ++sampleIndex) {
        float sampleOffset = sampleIndex == 0 ? ContactSampleOffsets.x
            : (sampleIndex == 1 ? ContactSampleOffsets.y
            : (sampleIndex == 2 ? ContactSampleOffsets.z : ContactSampleOffsets.w));
        float sampleWeight = rcp(sampleOffset);
        occlusion += ContactSample(
            centerUv,
            rawCenterDepth,
            receiverGradient,
            planeRawEpsilon,
            center + stepVector * sampleOffset,
            ContactControl.w) * sampleWeight;
        weight += sampleWeight;
    }
    float visibility = 1.0f - pow(saturate(occlusion / weight), 0.3f);
    visibility = lerp(visibility, 1.0f, smoothstep(ContactControl.y * 0.8f, ContactControl.y, center.z));
    // G16 cannot represent NVR's 180,000-unit default as raw linear depth.
    // A fixed normalized key preserves all schema-one distances and remains
    // stable when the camera far plane or FOV changes between render stages.
    return float4(visibility * visibility, center.z / ContactDepthKeyRange, 0.0f, 1.0f);
}
