// Coverage-bounded receiver geometry shared by all point-light batches.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 PointControl : register(c6); // x reversed depth
sampler2D SceneDepth : register(s0);

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (PointControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float3 ViewPosition(float2 uv) {
    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r;
    float depth = LinearDepth(rawDepth);
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

float4 Main(PixelInput input) : COLOR0 {
    float rawDepth = tex2Dlod(SceneDepth, float4(input.uv, 0.0f, 0.0f)).r;
    if (rawDepth <= 1.0f / 65536.0f || rawDepth >= 1.0f - 1.0f / 65536.0f) return 0.0f;

    float depth = LinearDepth(rawDepth);
    float3 center = float3(
        lerp(CameraFrustum.x, CameraFrustum.y, input.uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, input.uv.y) * depth,
        depth);
    float3 left = ViewPosition(input.uv - float2(ScreenData.z, 0.0f));
    float3 right = ViewPosition(input.uv + float2(ScreenData.z, 0.0f));
    float3 up = ViewPosition(input.uv - float2(0.0f, ScreenData.w));
    float3 down = ViewPosition(input.uv + float2(0.0f, ScreenData.w));
    float3 dx = dot(left - center, left - center) < dot(right - center, right - center)
        ? center - left : right - center;
    float3 dy = dot(up - center, up - center) < dot(down - center, down - center)
        ? center - up : down - center;
    float3 normal = cross(dx, dy);
    normal *= rsqrt(max(dot(normal, normal), 0.0000001f));
    return float4(normal, depth);
}
