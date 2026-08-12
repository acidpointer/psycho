// NVR-derived exterior screen-space contact shadows without derivative or noise textures.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ContactControl : register(c6); // x reversed, y max depth, z ray distance, w thickness
float4 ViewLightDirection : register(c7);
float4 ContactSampleOffsets : register(c8);
sampler2D SceneDepth : register(s0);

static const float DepthEndpointEpsilon = 1.0f / 65536.0f;

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (ContactControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
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

float2 ProjectViewPosition(float3 position) {
    float inverseDepth = rcp(max(position.z, 0.001f));
    float projectedX = position.x * inverseDepth;
    float projectedY = position.y * inverseDepth;
    return float2(
        (projectedX - CameraFrustum.x) / (CameraFrustum.y - CameraFrustum.x),
        (CameraFrustum.w - projectedY) / (CameraFrustum.w - CameraFrustum.z));
}

float ContactSample(float3 marched, float thickness) {
    float2 uv = ProjectViewPosition(marched);
    if (min(uv.x, uv.y) <= 0.0f || max(uv.x, uv.y) >= 1.0f) return 0.0f;
    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
    if (!HasGeometryDepth(rawDepth)) return 0.0f;
    float sceneDepth = LinearDepth(rawDepth);
    float delta = marched.z - sceneDepth;
    return delta > 0.01f && delta < thickness ? 1.0f : 0.0f;
}

float4 Main(PixelInput input) : COLOR0 {
    float rawCenterDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
    if (!HasGeometryDepth(rawCenterDepth)) return float4(1.0f, 0.0f, 0.0f, 1.0f);
    float3 center = ViewPosition(input.uv, rawCenterDepth);
    if (center.z <= 0.0f || center.z >= ContactControl.y) return float4(1.0f, center.z, 0.0f, 1.0f);

    // Four deterministic tests retain NVR's five-step screen-space contract
    // (its paired source loop emits cumulative positions 1, 3, 6, and 10).
    // Fixed positions are deliberate:
    // screen-anchored noise moves across world surfaces with camera motion and
    // made contact shadows visibly blink on walls.
    // NVR scales ray length by the camera depth range, not by the user-facing
    // contact cutoff. Coupling the two made a distance-slider edit move every
    // existing contact shadow and amplified camera-dependent false shapes.
    float normalizedDepth = saturate(center.z / DepthLinearizeData.w);
    float rayScale = pow(max(normalizedDepth, 0.0001f), 0.6f);
    float3 stepVector = normalize(ViewLightDirection.xyz) *
        (ContactControl.z / 5.0f) * rayScale;
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
        occlusion += ContactSample(center + stepVector * sampleOffset, ContactControl.w) * sampleWeight;
        weight += sampleWeight;
    }
    float visibility = 1.0f - pow(saturate(occlusion / weight), 0.3f);
    visibility = lerp(visibility, 1.0f, smoothstep(ContactControl.y * 0.8f, ContactControl.y, center.z));
    // Linear receiver depth travels with visibility through filtering and
    // history. It is the disocclusion key which prevents camera motion from
    // dragging a contact shape onto a different wall or ground plane.
    return float4(visibility * visibility, center.z, 0.0f, 1.0f);
}
