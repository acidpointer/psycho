// Shared depth-derived receiver normal for point lighting and sun competition.
// Inputs belong to the exact full-resolution depth publication. Missing depth
// or a degenerate supporting triangle returns zero rather than invented light.
#ifndef OMV_SHADOW_RECEIVER_NORMAL
#define OMV_SHADOW_RECEIVER_NORMAL 1

float3 ShadowReceiverViewPosition(float2 uv, float depth) {
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

float3 ShadowReceiverNeighbor(float2 texel, float3 center) {
    float2 sampledUv = (clamp(texel, 0.0f, ScreenData.xy - 1.0f) + 0.5f) * ScreenData.zw;
    float rawDepth = tex2Dlod(SceneDepth, float4(sampledUv, 0.0f, 0.0f)).r;
    bool valid = rawDepth > 1.0f / 65536.0f && rawDepth < 1.0f - 1.0f / 65536.0f;
    float depth = LinearDepth(rawDepth);
    valid = valid && depth > 0.0f && depth < DepthLinearizeData.w;
    return valid ? ShadowReceiverViewPosition(sampledUv, depth) : center;
}

float3 ShadowReceiverWorldNormal(float2 uv, float depth) {
    float2 texel = floor(uv * ScreenData.xy);
    float3 center = ShadowReceiverViewPosition((texel + 0.5f) * ScreenData.zw, depth);
    float3 left = center - ShadowReceiverNeighbor(texel - float2(1.0f, 0.0f), center);
    float3 right = ShadowReceiverNeighbor(texel + float2(1.0f, 0.0f), center) - center;
    float3 up = center - ShadowReceiverNeighbor(texel - float2(0.0f, 1.0f), center);
    float3 down = ShadowReceiverNeighbor(texel + float2(0.0f, 1.0f), center) - center;
    // Clamping at an image border samples the center again. That is not a
    // supporting edge; select the inward neighbor instead.
    float leftLength = dot(left, left);
    float rightLength = dot(right, right);
    float upLength = dot(up, up);
    float downLength = dot(down, down);
    float3 dx = leftLength > 0.0f && (rightLength == 0.0f || leftLength < rightLength) ? left : right;
    float3 dy = upLength > 0.0f && (downLength == 0.0f || upLength < downLength) ? up : down;
    float3 viewNormal = cross(dx, dy);
    float4 normalVector = float4(viewNormal, 0.0f);
    float3 worldNormal = float3(dot(ViewToWorld0, normalVector), dot(ViewToWorld1, normalVector), dot(ViewToWorld2, normalVector));
    float squareLength = dot(worldNormal, worldNormal);
    bool valid = squareLength > 0.0f && squareLength < 3.402823466e+38f;
    return valid ? worldNormal * rsqrt(valid ? squareLength : 1.0f) : 0.0f;
}

#endif
