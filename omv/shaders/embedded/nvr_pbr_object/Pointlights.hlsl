// Pointlight helper functions.

#if defined(__INTELLISENSE__)
    #include "Helpers.hlsl"
#endif

// Vanilla attenuation, lightVector not normalized.
float vanillaAtt(float3 lightVector, float radius) {
    return saturate(1 - dot(lightVector, lightVector) / max(radius * radius, 1e-8));
}

// https://lisyarus.github.io/blog/posts/point-light-attenuation.html
float lisyarusAtt(float3 lightVector, float radius, float falloff=5.0) {
    const float3 normalized = lightVector / radius;
    const float s2 = shades(normalized, normalized);

    return sqr(1 - s2) / (1 + falloff * s2);
}

// Modified Frostbite attenuation (UE4), lightVector not normalized.
float frostbiteAtt(float3 lightVector, float radius) {
    const float squaredDistance = dot(lightVector, lightVector);
    const float invSqrRadius = 1.f / (radius * radius);
    const float factor = squaredDistance * invSqrRadius;
    const float smoothFactor = saturate(1.f - factor * factor);
    const float smoothDistanceAtt = smoothFactor * smoothFactor;
    
    return smoothDistanceAtt / (squaredDistance + 1);
}
