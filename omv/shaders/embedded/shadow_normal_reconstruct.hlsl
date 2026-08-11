// OMV depth-derived world normals shared by the point-shadow passes.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
float4 NormalControl : register(c6); // x reversed depth
sampler2D SceneDepth : register(s0);

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (NormalControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float3 RelativeWorldPosition(float2 uv) {
    float depth = LinearDepth(tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r);
    float3 view = float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
    float4 homogeneous = float4(view, 1.0f);
    return float3(dot(ViewToWorld0, homogeneous), dot(ViewToWorld1, homogeneous), dot(ViewToWorld2, homogeneous));
}

float3 ReconstructNormal(float2 uv, float3 center) {
    float3 left = RelativeWorldPosition(uv - float2(ScreenData.z, 0.0f));
    float3 right = RelativeWorldPosition(uv + float2(ScreenData.z, 0.0f));
    float3 up = RelativeWorldPosition(uv - float2(0.0f, ScreenData.w));
    float3 down = RelativeWorldPosition(uv + float2(0.0f, ScreenData.w));
    // Camera rotation makes world Z unrelated to depth discontinuities. Pick
    // the shorter full 3D edge on each axis so silhouettes do not fold their
    // foreground and background surfaces into one false normal.
    float3 dx = dot(left - center, left - center) < dot(right - center, right - center)
        ? center - left : right - center;
    float3 dy = dot(up - center, up - center) < dot(down - center, down - center)
        ? center - up : down - center;
    float3 normal = cross(dx, dy);
    return normal * rsqrt(max(dot(normal, normal), 0.0000001f));
}

float4 Main(PixelInput input) : COLOR0 {
    float3 center = RelativeWorldPosition(input.uv);
    float3 normal = ReconstructNormal(input.uv, center);
    return float4(normal * 0.5f + 0.5f, 1.0f);
}
