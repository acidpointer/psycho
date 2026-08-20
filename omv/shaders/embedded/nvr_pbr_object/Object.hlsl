#if defined(__INTELLISENSE__)
    #include "Pointlights.hlsl"
    #include "PBR.hlsl"
#else
    #include "includes/Pointlights.hlsl"
    #include "includes/PBR.hlsl"
#endif

float4 TESR_PBRData : register(c32);
float4 TESR_PBRExtraData : register(c33);

float getRoughness(float gloss) {
    return clamp((1 - saturate(gloss)) * TESR_PBRData.y, 0.043, 1.0);
}

float getSpecularGlossPower(float glossPower) {
    const float roughnessScale = max(TESR_PBRData.y, 0.043);
    return max(glossPower / (roughnessScale * roughnessScale), 1.0);
}

float getRoughness(float glossmap, float meshgloss){
    // return pow(glossmap, log(meshgloss));    
    // no gloss = 1
    // full gloss = 0

    return saturate(1 - log(meshgloss) / 4 * glossmap);
    // return 1 - saturate(log(meshgloss)/4 + glossmap);
    // return pow(1 - glossmap, meshgloss);
}

// Vanilla
float3 getVanillaLighting(float3 lightDir, float radius, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float gloss, float glossPower) {
    float att = vanillaAtt(lightDir, radius);

    lightDir = normalize(lightDir);
    viewDir = normalize(viewDir);
    float3 halfwayDir = normalize(lightDir + viewDir);
    
    float NdotL = shades(normal.xyz, lightDir.xyz);
    
    #if defined(ONLY_SPECULAR)
        float specStrength = gloss * pow(abs(shades(normal.xyz, halfwayDir.xyz)), glossPower);
        float3 lighting = saturate(((0.2 >= NdotL ? (specStrength * saturate(NdotL + 0.5)) : specStrength) * lightColor.rgb) * att);
    #elif defined(SPECULAR)
        float specStrength = gloss * pow(abs(shades(normal.xyz, halfwayDir.xyz)), glossPower);
        float3 lighting = albedo.rgb * NdotL * lightColor.rgb * att;
        lighting += saturate(((0.2 >= NdotL ? (specStrength * saturate(NdotL + 0.5)) : specStrength) * lightColor.rgb) * att);
    #else
        float3 lighting = albedo.rgb * NdotL * lightColor.rgb * att;
    #endif
    
    return lighting;
}

float3 getVanillaLightingAtt(float3 lightDir, float att, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float gloss, float glossPower) {
    lightDir = normalize(lightDir);
    viewDir = normalize(viewDir);
    float3 halfwayDir = normalize(lightDir + viewDir);
    
    float NdotL = shades(normal.xyz, lightDir.xyz);
    
    #if defined(ONLY_SPECULAR)
        float specStrength = gloss * pow(abs(shades(normal.xyz, halfwayDir.xyz)), glossPower);
        float3 lighting = saturate(((0.2 >= NdotL ? (specStrength * saturate(NdotL + 0.5)) : specStrength) * lightColor.rgb) * att);
    #elif defined(SPECULAR)
        float specStrength = gloss * pow(abs(shades(normal.xyz, halfwayDir.xyz)), glossPower);
        float3 lighting = albedo.rgb * NdotL * lightColor.rgb * att;
        lighting += saturate(((0.2 >= NdotL ? (specStrength * saturate(NdotL + 0.5)) : specStrength) * lightColor.rgb) * att);
    #else
        float3 lighting = albedo.rgb * NdotL * lightColor.rgb * att;
    #endif
    
    return lighting;
}

// PBR
float3 getPointLightLighting(float3 lightDir, float radius, float3 lightColor, float3 viewDir, float3 normal, PbrObjectSurface surface) {
    lightColor = lightColor * TESR_PBRData.z;

    float att = vanillaAtt(lightDir, radius);

    #if defined(ONLY_SPECULAR)
        return PBRBoundedSpecular(surface, att, normal, viewDir, lightDir, lightColor);
    #elif defined(SPECULAR)
        return PBRBounded(surface, att, normal, viewDir, lightDir, lightColor);
    #else
        return att * PBRDiffuse(surface, normal, viewDir, lightDir, lightColor);
    #endif
}

float3 getPointLightLightingAtt(float3 lightDir, float att, float3 lightColor, float3 viewDir, float3 normal, PbrObjectSurface surface) {
    lightColor = lightColor * TESR_PBRData.z;

    #if defined(ONLY_SPECULAR)
        return PBRBoundedSpecular(surface, att, normal, viewDir, lightDir, lightColor);
    #elif defined(SPECULAR)
        return PBRBounded(surface, att, normal, viewDir, lightDir, lightColor);
    #else
        return att * PBRDiffuse(surface, normal, viewDir, lightDir, lightColor);
    #endif
}

#if defined(SPECULAR)
float3 getBoundedLightingWithNativeCeiling(
    float3 lightDir,
    float3 nativeHalfway,
    float att,
    float3 lightColor,
    float3 viewDir,
    float3 normal,
    float3 albedo,
    float gloss,
    float glossPower,
    PbrObjectSurface surface,
    out float3 nativeLighting
) {
    // The replacement needs a per-pixel view vector for its PBR response, but
    // the native high-light vertex rows publish an independently normalized
    // halfway vector in TEXCOORD5..7. Preserve that interpolated value for the
    // native ceiling: rebuilding it per pixel makes the ceiling depend on
    // camera distance and triangle perspective differently from native.
    lightDir = StableNormalize(lightDir);
    const float3 pbrHalfway = StableHalfway(viewDir, lightDir);
    nativeHalfway = StableNormalize(nativeHalfway);
    const float NdotL = shades(normal, lightDir);
    const float pbrNdotH = shades(normal, pbrHalfway);
    const float nativeNdotH = shades(normal, nativeHalfway);
    const float LdotH = shades(lightDir, pbrHalfway);

    const float3 pbrLightColor = lightColor * TESR_PBRData.z;
    const float3 fresnel = Fresnel(float(0.04).rrr, (1.0).xxx, LdotH);
    const float distribution = pow(pbrNdotH, surface.materialResponse) * surface.distributionScale;
    const float3 radiance = NdotL * pbrLightColor * att;
    const float3 diffuse = (1 - fresnel) * surface.diffuseColor * radiance * PI;
    const float3 specular = fresnel * distribution * radiance;

    const float nativeSpecular = gloss * pow(abs(nativeNdotH), glossPower);
    nativeLighting = albedo * NdotL * lightColor * att;
    nativeLighting += (0.2 >= NdotL
        ? nativeSpecular * saturate(NdotL + 0.5)
        : nativeSpecular)
        * lightColor * att * surface.specularFade;

    return diffuse + saturate(specular * surface.specularStrength) * surface.specularFade;
}
#endif

float3 getSunLighting(float3 lightDir, float3 lightColor, float3 viewDir, float3 normal, PbrObjectSurface surface) {
    lightColor = lightColor * TESR_PBRData.z;

    #if defined(ONLY_SPECULAR)
        return PBRBoundedSpecular(surface, 1.0, normal, viewDir, lightDir, lightColor);
    #elif defined(SPECULAR)
        return PBRBounded(surface, 1.0, normal, viewDir, lightDir, lightColor);
    #else
        return PBRDiffuse(surface, normal, viewDir, lightDir, lightColor);
    #endif
}

float3 getAmbientLighting(float3 ambient, float3 albedo) {
    return ambient * TESR_PBRData.w * albedo;
}
