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

float getObjectSpecularTransition(float nativeTransition) {
    return smoothstep(0.0, 0.1, saturate(nativeTransition));
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
float3 getPointLightLighting(float3 lightDir, float radius, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float roughness) {
    lightColor = lightColor * TESR_PBRData.z;
    albedo = lerp(luma(albedo), albedo, TESR_PBRExtraData.x);
    
    float att = vanillaAtt(lightDir, radius);
    
    #if defined(ONLY_SPECULAR)
        return att * PBRSpecular(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #elif defined(SPECULAR)
        return att * PBR(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #else
        return att * PBRDiffuse(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #endif
}

float3 getPointLightLightingAtt(float3 lightDir, float att, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float roughness) {
    lightColor = lightColor * TESR_PBRData.z;
    albedo = lerp(luma(albedo), albedo, TESR_PBRExtraData.x);
    
    #if defined(ONLY_SPECULAR)
        return att * PBRSpecular(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #elif defined(SPECULAR)
        return att * PBR(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #else
    return att * PBRDiffuse(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #endif
}

PBRLightingComponents getPointLightLightingComponents(float3 lightDir, float radius, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float roughness) {
    lightColor *= TESR_PBRData.z;
    albedo = lerp(luma(albedo), albedo, TESR_PBRExtraData.x);

    float att = vanillaAtt(lightDir, radius);
    PBRLightingComponents lighting = EvaluatePBR(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    lighting.diffuse *= att;
    lighting.specular *= att;
    return lighting;
}

PBRLightingComponents getPointLightLightingAttComponents(float3 lightDir, float att, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float roughness) {
    lightColor *= TESR_PBRData.z;
    albedo = lerp(luma(albedo), albedo, TESR_PBRExtraData.x);

    PBRLightingComponents lighting = EvaluatePBR(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    lighting.diffuse *= att;
    lighting.specular *= att;
    return lighting;
}

float3 getSunLighting(float3 lightDir, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float roughness) {
    lightColor = lightColor * TESR_PBRData.z;
    albedo = lerp(luma(albedo), albedo, TESR_PBRExtraData.x);
    
    #if defined(ONLY_SPECULAR)
        return PBRSunSpecular(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #elif defined(SPECULAR)
        return PBRSun(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #else
        return PBRDiffuse(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
    #endif
}

PBRLightingComponents getSunLightingComponents(float3 lightDir, float3 lightColor, float3 viewDir, float3 normal, float3 albedo, float roughness) {
    lightColor *= TESR_PBRData.z;
    albedo = lerp(luma(albedo), albedo, TESR_PBRExtraData.x);
    return EvaluatePBRSun(saturate(TESR_PBRData.x), roughness, albedo, normal, viewDir, lightDir, lightColor);
}

float3 getAmbientLighting(float3 ambient, float3 albedo) {
    return ambient * TESR_PBRData.w * albedo;
}
