// PBR calculations.
#if defined(__INTELLISENSE__)
    #include "Helpers.hlsl"
#endif

struct PBRLightingComponents {
    float3 diffuse;
    float3 specular;
};

float3 SafeNormalize(float3 value, float3 fallback) {
    float lengthSquared = dot(value, value);
    return lengthSquared > 1e-8 ? value * rsqrt(lengthSquared) : fallback;
}

// Geometric specular AA
// http://www.jp.square-enix.com/tech/library/pdf/ImprovedGeometricSpecularAA.pdf
// https://www.jcgt.org/published/0010/02/02/paper.pdf
float SpecularAA(float3 normal, float roughness, float sigma, float kappa) {
    float SIGMA2 = 0.15915494;
    float KAPPA = 0.18;
    float3 dndu = ddx(normal);
    float3 dndv = ddy(normal);
    float variance = SIGMA2 * (dot(dndu, dndu) + dot(dndv, dndv));
    float kernel_roughness = min(KAPPA, variance);
    return sqrt(saturate(roughness * roughness + kernel_roughness));
}

// Fresnel
// Schlick approximation
float3 Fresnel(float3 f0, float3 f90, float cosine) {
    float oneMinusCosine = 1.0 - cosine;
    float squared = oneMinusCosine * oneMinusCosine;
    return f0 + (f90 - f0) * (squared * squared * oneMinusCosine);
}

// Diffuse
// Lambert
float3 LambertianDiffuse(float3 albedo, float3 fresnel) {
    return (1 - fresnel) * albedo / PI;
}

float3 StableObjectDiffuse(float3 albedo, float LdotH) {
    // Global metalness has no material mask, so it must not remove the diffuse baseline.
    const float3 dielectricFresnel = Fresnel(float(0.04).rrr, (1.0).xxx, LdotH);
    return LambertianDiffuse(albedo, dielectricFresnel);
}

float3 DisneyDiffuse(float3 albedo, float roughness, float NdotV, float NdotL, float LdotH) {
    const float linearRoughness = roughness * roughness;

    const float energyBias = lerp (0, 0.5 , linearRoughness);
    const float energyFactor = lerp (1.0, 1.0 / 1.51, linearRoughness);
    const float fd90 = energyBias + 2.0 * LdotH * LdotH * linearRoughness;
    const float3 f0 = float(1.0).xxx;
    const float lightScatter = Fresnel(f0, fd90, NdotL).r;
    const float viewScatter = Fresnel(f0, fd90, NdotV).r;

    return (albedo / PI) * lightScatter * viewScatter * energyFactor;
}

// Specular
// D (normal distribution function)
float GGX(float NdotH, float roughness) {
    float roughnessSquared = roughness * roughness;
    float a2 = roughnessSquared * roughnessSquared;
    float d = max((NdotH * a2 - NdotH) * NdotH + 1, 1e-5);
    return a2 / (PI * d * d);
}

// G1
float ShlickBeckmann(float NdotX, float roughness) {
    float roughnessPlusOne = roughness + 1.0;
    float k = roughnessPlusOne * roughnessPlusOne * 0.125;
    return NdotX/max(NdotX * (1 - k) + k, 0.00000001);
}

// Smith
float GeometryShadowing(float roughness, float NdotV, float NdotL) {
    return ShlickBeckmann(NdotV, roughness) * ShlickBeckmann(NdotL, roughness);
}

// F
float3 FresnelShlick(float3 reflectance, float3 halfway, float3 eyeDir) {
    return reflectance + (1 - reflectance) * pow(1 - shades(halfway, eyeDir), 5.0);
}

// BRDF
float3 BRDF(float roughness, float3 fresnel, float NdotV, float NdotL, float NdotH){
    float3 num = GGX(NdotH, roughness) * GeometryShadowing(roughness, NdotV, NdotL) * fresnel;
    float denom = 4.0 * NdotV * NdotL;
    return num/denom;
}

float3 PBRDiffuse(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    normal = normalize(normal);
    eyeDir = normalize(eyeDir);
    lightDir = normalize(lightDir);

    const float3 halfway = SafeNormalize(eyeDir + lightDir, normal);
    const float NdotL = shades(normal, lightDir);
    const float LdotH = shades(lightDir, halfway);

    const float3 diffuse = StableObjectDiffuse(albedo, LdotH);

    return diffuse * NdotL * lightColor * PI;
}

float3 PBRSpecular(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    normal = normalize(normal);
    eyeDir = normalize(eyeDir);
    lightDir = normalize(lightDir);

    const float3 halfway = SafeNormalize(eyeDir + lightDir, normal);
    const float NdotL = max(shades(normal, lightDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    const float3 spec = BRDF(roughness, fresnel, NdotV, NdotL, NdotH);

    return spec * NdotL * lightColor * PI;
}

PBRLightingComponents EvaluatePBR(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    PBRLightingComponents lighting;
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    normal = normalize(normal);
    eyeDir = normalize(eyeDir);
    lightDir = normalize(lightDir);

    const float3 halfway = SafeNormalize(eyeDir + lightDir, normal);
    const float NdotL = max(shades(normal, lightDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    lighting.diffuse = StableObjectDiffuse(albedo, LdotH);

    lighting.specular = BRDF(roughness, fresnel, NdotV, NdotL, NdotH);

    lighting.diffuse *= NdotL * lightColor * PI;
    lighting.specular *= NdotL * lightColor * PI;
    return lighting;
}

float3 PBR(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    PBRLightingComponents lighting = EvaluatePBR(metallicness, roughness, albedo, normal, eyeDir, lightDir, lightColor);
    return lighting.diffuse + lighting.specular;
}

#define SUN_RADIUS 0.00918043

float3 PBRSunSpecular(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    normal = normalize(normal);
    eyeDir = normalize(eyeDir);
    lightDir = normalize(lightDir);

    const float3 reflectDir = reflect(lightDir, normal);

    const float radius = sin(SUN_RADIUS);
    const float dist = cos(SUN_RADIUS);

    const float LdotR = dot(lightDir, reflectDir);
    const float3 closestPoint = reflectDir - LdotR * lightDir;
    const float3 closestDirection = SafeNormalize(closestPoint, reflectDir);
    const float3 sunDir = LdotR < dist ? SafeNormalize(dist * lightDir + closestDirection * radius, reflectDir) : reflectDir;

    const float3 halfway = SafeNormalize(eyeDir + sunDir, normal);
    const float NdotS = max(shades(normal, sunDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float NdotL = shades(normal, lightDir);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    const float3 spec = BRDF(roughness, fresnel, NdotV, NdotS, NdotH);

    return spec * NdotS * lightColor * PI;
}

PBRLightingComponents EvaluatePBRSun(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    PBRLightingComponents lighting;
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    normal = normalize(normal);
    eyeDir = normalize(eyeDir);
    lightDir = normalize(lightDir);

    const float3 reflectDir = reflect(lightDir, normal);

    const float radius = sin(SUN_RADIUS);
    const float dist = cos(SUN_RADIUS);

    const float LdotR = dot(lightDir, reflectDir);
    const float3 closestPoint = reflectDir - LdotR * lightDir;
    const float3 closestDirection = SafeNormalize(closestPoint, reflectDir);
    const float3 sunDir = LdotR < dist ? SafeNormalize(dist * lightDir + closestDirection * radius, reflectDir) : reflectDir;

    const float3 halfway = SafeNormalize(eyeDir + sunDir, normal);
    const float NdotS = max(shades(normal, sunDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float NdotL = shades(normal, lightDir);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    lighting.diffuse = StableObjectDiffuse(albedo, LdotH);

    lighting.specular = BRDF(roughness, fresnel, NdotV, NdotS, NdotH);

    lighting.diffuse *= NdotL * lightColor * PI;
    lighting.specular *= NdotS * lightColor * PI;
    return lighting;
}

float3 PBRSun(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    PBRLightingComponents lighting = EvaluatePBRSun(metallicness, roughness, albedo, normal, eyeDir, lightDir, lightColor);
    return lighting.diffuse + lighting.specular;
}
