// OMV point-shadow accumulation. Each pass consumes six of twelve cube maps.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
float4 PointControl : register(c6); // x reversed depth, y count, z bias
float4 LightPositionRadius[6] : register(c7);
float4 LightColorIntensity[6] : register(c13);

sampler2D SceneDepth : register(s0);
samplerCUBE ShadowCube0 : register(s1);
samplerCUBE ShadowCube1 : register(s2);
samplerCUBE ShadowCube2 : register(s3);
samplerCUBE ShadowCube3 : register(s4);
samplerCUBE ShadowCube4 : register(s5);
samplerCUBE ShadowCube5 : register(s6);
sampler2D NormalBuffer : register(s7);

struct PixelInput { float2 uv : TEXCOORD0; };

float LinearDepth(float rawDepth) {
    if (PointControl.x > 0.5f) {
        return DepthLinearizeData.x / max(rawDepth * DepthLinearizeData.y + DepthLinearizeData.z, 0.001f);
    }
    return DepthLinearizeData.x / max(DepthLinearizeData.w - rawDepth * DepthLinearizeData.y, 0.001f);
}

float3 ViewPosition(float2 uv) {
    float depth = LinearDepth(tex2Dlod(SceneDepth, float4(uv, 0.0f, 0.0f)).r);
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

float3 RelativeWorldPosition(float2 uv) {
    float3 view = ViewPosition(uv);
    float4 homogeneous = float4(view, 1.0f);
    return float3(dot(ViewToWorld0, homogeneous), dot(ViewToWorld1, homogeneous), dot(ViewToWorld2, homogeneous));
}

float3 SamplePointShadow(
    samplerCUBE cubeMap,
    float3 worldPosition,
    float3 normal,
    float4 lightPositionRadius,
    float4 lightColorIntensity)
{
    float3 toLight = lightPositionRadius.xyz - worldPosition;
    float radius = max(lightPositionRadius.w, 0.001f);
    float distance = length(toLight);
    float normalizedDistance = distance / radius;
    float radial = saturate(1.0f - normalizedDistance * normalizedDistance);
    radial = radial * radial / max(1.0f + 5.0f * normalizedDistance * normalizedDistance, 0.001f);
    // Match NVR's near-light bleed guard: directly beside a light, an
    // unreliable reconstructed normal must not turn the source into a black
    // disk. The ordinary Lambert term takes over smoothly by 20% radius.
    float lambert = dot(toLight / max(distance, 0.001f), normal);
    float diffuse = saturate(lerp(1.0f, lambert, smoothstep(0.0f, 0.2f, normalizedDistance)));
    float3 contribution = radial * diffuse * max(lightColorIntensity.rgb, 0.0f)
        * max(lightColorIntensity.w, 0.0f);
    float storedDepth = texCUBElod(
        cubeMap, float4(toLight * float3(-1.0f, -1.0f, 1.0f), 0.0f)).r;
    float visibility = storedDepth + PointControl.z * normalizedDistance >= normalizedDistance
        ? 1.0f : 0.0f;
    visibility = lerp(1.0f, visibility, storedDepth > 0.0f && storedDepth < 1.0f);
    return contribution * (1.0f - visibility);
}

float4 Main(PixelInput input) : COLOR0 {
    float3 worldPosition = RelativeWorldPosition(input.uv);
    float3 normal = normalize(
        tex2Dlod(NormalBuffer, float4(input.uv, 0.0f, 0.0f)).xyz * 2.0f - 1.0f);
    float3 sum = 0.0f;
    if (PointControl.y > 0.0f) sum += SamplePointShadow(ShadowCube0, worldPosition, normal, LightPositionRadius[0], LightColorIntensity[0]);
    if (PointControl.y > 1.0f) sum += SamplePointShadow(ShadowCube1, worldPosition, normal, LightPositionRadius[1], LightColorIntensity[1]);
    if (PointControl.y > 2.0f) sum += SamplePointShadow(ShadowCube2, worldPosition, normal, LightPositionRadius[2], LightColorIntensity[2]);
    if (PointControl.y > 3.0f) sum += SamplePointShadow(ShadowCube3, worldPosition, normal, LightPositionRadius[3], LightColorIntensity[3]);
    if (PointControl.y > 4.0f) sum += SamplePointShadow(ShadowCube4, worldPosition, normal, LightPositionRadius[4], LightColorIntensity[4]);
    if (PointControl.y > 5.0f) sum += SamplePointShadow(ShadowCube5, worldPosition, normal, LightPositionRadius[5], LightColorIntensity[5]);
    return float4(sum, 1.0f);
}
