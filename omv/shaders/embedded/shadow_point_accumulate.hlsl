// Six-light OMV point-shadow accumulation over precomputed receiver geometry.
float4 ScreenData : register(c0);
float4 DepthLinearizeData : register(c1);
float4 CameraFrustum : register(c2);
float4 ViewToWorld0 : register(c3);
float4 ViewToWorld1 : register(c4);
float4 ViewToWorld2 : register(c5);
float4 PointControl : register(c6); // x unused, y light count, z radial bias
float4 LightPositionRadius[6] : register(c7);
float4 LightColorIntensity[6] : register(c13);

sampler2D ReceiverGeometry : register(s0);
samplerCUBE ShadowCube0 : register(s1);
samplerCUBE ShadowCube1 : register(s2);
samplerCUBE ShadowCube2 : register(s3);
samplerCUBE ShadowCube3 : register(s4);
samplerCUBE ShadowCube4 : register(s5);
samplerCUBE ShadowCube5 : register(s6);

struct PixelInput { float2 uv : TEXCOORD0; };

float3 ViewPosition(float2 uv, float depth) {
    return float3(
        lerp(CameraFrustum.x, CameraFrustum.y, uv.x) * depth,
        lerp(CameraFrustum.w, CameraFrustum.z, uv.y) * depth,
        depth);
}

float3 RelativeWorldPosition(float2 uv, float depth) {
    float4 view = float4(ViewPosition(uv, depth), 1.0f);
    return float3(dot(ViewToWorld0, view), dot(ViewToWorld1, view), dot(ViewToWorld2, view));
}

float3 WorldNormal(float3 viewNormal) {
    float4 normalVector = float4(viewNormal, 0.0f);
    float3 normal = float3(
        dot(ViewToWorld0, normalVector), dot(ViewToWorld1, normalVector), dot(ViewToWorld2, normalVector));
    return normal * rsqrt(max(dot(normal, normal), 0.0000001f));
}

float SourceGuard(float normalizedDistance) {
    // The emitting mesh is not direct irradiance owned by this pass. The
    // fade also rejects unreliable radial depths immediately around a source.
    return smoothstep(0.02f, 0.08f, normalizedDistance);
}

struct LightEnergy {
    float3 total;
    float3 deficit;
};

struct PointOutput {
    float4 deficit : COLOR0;
    float4 total : COLOR1;
};

LightEnergy EvaluateLight(
    samplerCUBE shadowCube,
    float3 worldPosition,
    float3 normal,
    float4 lightPositionRadius,
    float4 lightColorIntensity)
{
    float radius = max(lightPositionRadius.w, 0.001f);
    float3 toLight = lightPositionRadius.xyz - worldPosition;
    float distance = length(toLight);
    float normalizedDistance = distance / radius;
    if (normalizedDistance >= 1.0f || lightPositionRadius.w <= 0.0f) {
        LightEnergy empty;
        empty.total = 0.0f;
        empty.deficit = 0.0f;
        return empty;
    }

    float radial = saturate(1.0f - normalizedDistance * normalizedDistance);
    radial = radial * radial / max(1.0f + 5.0f * normalizedDistance * normalizedDistance, 0.001f);
    float lambert = dot(toLight / max(distance, 0.001f), normal);
    float diffuse = saturate(lerp(1.0f, lambert, smoothstep(0.0f, 0.2f, normalizedDistance)));
    float3 contribution = radial * diffuse * max(lightColorIntensity.rgb, 0.0f)
        * max(lightColorIntensity.w, 0.0f);
    float storedDepth = texCUBElod(
        shadowCube, float4(toLight * float3(-1.0f, -1.0f, 1.0f), 0.0f)).r;
    float visibility = storedDepth + PointControl.z * normalizedDistance >= normalizedDistance
        ? 1.0f : 0.0f;
    visibility = lerp(1.0f, visibility, storedDepth > 0.0f && storedDepth < 1.0f);
    contribution *= SourceGuard(normalizedDistance);
    float3 deficit = contribution * (1.0f - visibility);
    LightEnergy result;
    result.total = contribution;
    result.deficit = deficit;
    return result;
}

PointOutput Main(PixelInput input) {
    float4 receiver = tex2Dlod(ReceiverGeometry, float4(input.uv, 0.0f, 0.0f));
    if (receiver.w <= 0.0f) {
        PointOutput empty;
        empty.deficit = 0.0f;
        empty.total = 0.0f;
        return empty;
    }

    float3 worldPosition = RelativeWorldPosition(input.uv, receiver.w);
    float3 normal = WorldNormal(receiver.xyz);
    float3 total = 0.0f;
    float3 deficit = 0.0f;
    if (PointControl.y > 0.0f) { LightEnergy light = EvaluateLight(ShadowCube0, worldPosition, normal, LightPositionRadius[0], LightColorIntensity[0]); total += light.total; deficit += light.deficit; }
    if (PointControl.y > 1.0f) { LightEnergy light = EvaluateLight(ShadowCube1, worldPosition, normal, LightPositionRadius[1], LightColorIntensity[1]); total += light.total; deficit += light.deficit; }
    if (PointControl.y > 2.0f) { LightEnergy light = EvaluateLight(ShadowCube2, worldPosition, normal, LightPositionRadius[2], LightColorIntensity[2]); total += light.total; deficit += light.deficit; }
    if (PointControl.y > 3.0f) { LightEnergy light = EvaluateLight(ShadowCube3, worldPosition, normal, LightPositionRadius[3], LightColorIntensity[3]); total += light.total; deficit += light.deficit; }
    if (PointControl.y > 4.0f) { LightEnergy light = EvaluateLight(ShadowCube4, worldPosition, normal, LightPositionRadius[4], LightColorIntensity[4]); total += light.total; deficit += light.deficit; }
    if (PointControl.y > 5.0f) { LightEnergy light = EvaluateLight(ShadowCube5, worldPosition, normal, LightPositionRadius[5], LightColorIntensity[5]); total += light.total; deficit += light.deficit; }
    PointOutput output;
    // Keeping both RGB quantities exact is essential when differently colored
    // lights overlap. A scalar occlusion ratio would darken channels owned by
    // an unoccluded light in the same batch.
    output.deficit = float4(deficit, 0.0f);
    output.total = float4(total, 0.0f);
    return output;
}
