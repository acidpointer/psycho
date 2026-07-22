// PBR calculations.
#if defined(__INTELLISENSE__)
    #include "Helpers.hlsl"
#endif

float3 SafeNormalize(float3 value, float3 fallback) {
    float lengthSquared = dot(value, value);
    return lengthSquared > 1e-8 ? value * rsqrt(lengthSquared) : fallback;
}

float3 StableNormalize(float3 value) {
    float lengthSquared = dot(value, value);
    return value * rsqrt(max(lengthSquared, 1e-8));
}

float3 StableHalfway(float3 eyeDir, float3 lightDir) {
    float3 halfway = eyeDir + lightDir;
    float lengthSquared = dot(halfway, halfway);
    return halfway * rsqrt(max(lengthSquared, 1e-8));
}

struct PbrObjectSurface {
    float3 diffuseColor;
    float materialResponse;
    float distributionScale;
    float specularStrength;
    float specularFade;
};

PbrObjectSurface PreparePbrObjectSurface(float3 albedo, float materialResponse, float specularStrength, float specularFade) {
    PbrObjectSurface surface;
    surface.diffuseColor = albedo / PI;
    surface.materialResponse = materialResponse;
    surface.distributionScale = (materialResponse + 2.0) * 0.125;
    surface.specularStrength = saturate(specularStrength);
    surface.specularFade = saturate(specularFade);
    return surface;
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

float3 PBRDiffuse(PbrObjectSurface surface, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = float(0.04).rrr;

    lightDir = StableNormalize(lightDir);

    const float3 halfway = StableHalfway(eyeDir, lightDir);
    const float NdotL = shades(normal, lightDir);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    const float3 diffuse = (1 - fresnel) * surface.diffuseColor;

    return diffuse * NdotL * lightColor * PI;
}

float3 PBRSpecular(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    lightDir = StableNormalize(lightDir);

    const float3 halfway = StableHalfway(eyeDir, lightDir);
    const float NdotL = max(shades(normal, lightDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    const float3 spec = BRDF(roughness, fresnel, NdotV, NdotL, NdotH);

    return spec * NdotL * lightColor * PI;
}

float3 PBRBoundedSpecular(PbrObjectSurface surface, float attenuation, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = float(0.04).rrr;

    lightDir = StableNormalize(lightDir);

    const float3 halfway = StableHalfway(eyeDir, lightDir);
    const float NdotL = shades(normal, lightDir);
    const float NdotH = shades(normal, halfway);
    const float LdotH = shades(lightDir, halfway);
    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);
    const float distribution = pow(NdotH, surface.materialResponse) * surface.distributionScale;
    const float3 radiance = NdotL * lightColor * attenuation;
    const float3 specular = fresnel * distribution * radiance;
    return saturate(specular * surface.specularStrength) * surface.specularFade;
}

float3 PBRBounded(PbrObjectSurface surface, float attenuation, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = float(0.04).rrr;

    lightDir = StableNormalize(lightDir);

    const float3 halfway = StableHalfway(eyeDir, lightDir);
    const float NdotL = shades(normal, lightDir);
    const float NdotH = shades(normal, halfway);
    const float LdotH = shades(lightDir, halfway);
    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);
    const float distribution = pow(NdotH, surface.materialResponse) * surface.distributionScale;
    const float3 radiance = NdotL * lightColor * attenuation;
    const float3 diffuse = (1 - fresnel) * surface.diffuseColor * radiance * PI;
    const float3 specular = fresnel * distribution * radiance;
    return diffuse + saturate(specular * surface.specularStrength) * surface.specularFade;
}

float3 PBR(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    normal = SafeNormalize(normal, float3(0, 0, 1));
    eyeDir = SafeNormalize(eyeDir, normal);
    lightDir = StableNormalize(lightDir);

    const float3 halfway = StableHalfway(eyeDir, lightDir);
    const float NdotL = max(shades(normal, lightDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    const float3 diffuse = (1 - metallicness) * LambertianDiffuse(albedo, fresnel);

    const float3 spec = BRDF(roughness, fresnel, NdotV, NdotL, NdotH);

    return (diffuse + spec) * NdotL * lightColor * PI;
}

#define SUN_RADIUS 0.00918043

float3 PBRSunSpecular(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    lightDir = StableNormalize(lightDir);

    const float3 reflectDir = reflect(lightDir, normal);

    const float radius = sin(SUN_RADIUS);
    const float dist = cos(SUN_RADIUS);

    const float LdotR = dot(lightDir, reflectDir);
    const float3 closestPoint = reflectDir - LdotR * lightDir;
    const float3 closestDirection = SafeNormalize(closestPoint, reflectDir);
    const float3 sunDir = LdotR < dist ? SafeNormalize(dist * lightDir + closestDirection * radius, reflectDir) : reflectDir;

    const float3 halfway = StableHalfway(eyeDir, sunDir);
    const float NdotS = max(shades(normal, sunDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float NdotL = shades(normal, lightDir);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    const float3 spec = BRDF(roughness, fresnel, NdotV, NdotS, NdotH);

    return spec * NdotS * lightColor * PI;
}

float3 PBRSun(float metallicness, float roughness, float3 albedo, float3 normal, float3 eyeDir, float3 lightDir, float3 lightColor) {
    const float3 reflectance = lerp(float(0.04).rrr, albedo, metallicness);

    lightDir = StableNormalize(lightDir);

    const float3 reflectDir = reflect(lightDir, normal);

    const float radius = sin(SUN_RADIUS);
    const float dist = cos(SUN_RADIUS);

    const float LdotR = dot(lightDir, reflectDir);
    const float3 closestPoint = reflectDir - LdotR * lightDir;
    const float3 closestDirection = SafeNormalize(closestPoint, reflectDir);
    const float3 sunDir = LdotR < dist ? SafeNormalize(dist * lightDir + closestDirection * radius, reflectDir) : reflectDir;

    const float3 halfway = StableHalfway(eyeDir, sunDir);
    const float NdotS = max(shades(normal, sunDir), 0.00001);
    const float NdotV = max(shades(normal, eyeDir), 0.00001);
    const float NdotH = shades(normal, halfway);
    const float NdotL = shades(normal, lightDir);
    const float LdotH = shades(lightDir, halfway);

    const float3 fresnel = Fresnel(reflectance, (1.0).xxx, LdotH);

    const float3 diffuse = (1 - metallicness) * LambertianDiffuse(albedo, fresnel);

    const float3 spec = BRDF(roughness, fresnel, NdotV, NdotS, NdotH);

    return (diffuse * NdotL + spec * NdotS) * lightColor * PI;
}
