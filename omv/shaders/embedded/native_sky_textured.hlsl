float2 Params : register(c4);
float4 SkyUpper : register(c21);
float4 SkyLower : register(c22);
float4 HorizonColor : register(c23);
float4 SunLightColor : register(c24);
float4 SunDirection : register(c25);
float4 SkyData : register(c26);
float4 CloudData : register(c27);
float4 SunData : register(c28);
float4 SunsetColor : register(c29);
float4 ObjectData : register(c31);

sampler2D SkyTexture : register(s0);
sampler2D SkyTextureBlend : register(s1);

struct PixelInput {
    float2 uv : TEXCOORD0;
    float2 screen : VPOS;
    float2 blendUv : TEXCOORD1;
    float3 location : TEXCOORD2;
    float4 color : COLOR0;
    float4 kind : COLOR1;
};

float3 Linearize3(float3 color) {
    float3 low = color / 12.92;
    float3 high = pow((color + 0.055) / 1.055, 2.4);
    return (color <= 0.04045) ? low : high;
}

float4 Linearize4(float4 color) {
    return float4(Linearize3(color.rgb), color.a);
}

float3 Delinearize3(float3 color) {
    float3 low = color * 12.92;
    float3 high = pow(abs(color), 1.0 / 2.4) * 1.055 - 0.055;
    return (color <= 0.0031308) ? low : high;
}

float Pow4(float value) {
    float value2 = value * value;
    return value2 * value2;
}

float Pow8(float value) {
    float value2 = value * value;
    float value4 = value2 * value2;
    return value4 * value4;
}

float Pow20(float value) {
    float value2 = value * value;
    float value4 = value2 * value2;
    float value16 = value4 * value4;
    value16 *= value16;
    return value16 * value4;
}

float3 EvaluateSky(float verticality, float atmosphere, float sunHeight, float sunInfluence, float3 sunColor) {
    float3 color = lerp(SkyLower.rgb, SkyUpper.rgb, verticality);
    color = lerp(color, HorizonColor.rgb, saturate(atmosphere * (0.5 + 0.5 * sunInfluence)));
    color += sunColor * sunInfluence * (1.0 - sunHeight) * atmosphere * SkyData.z * smoothstep(0.0, 0.5, SunData.x);
    return color;
}

float4 SampleWeatherTextures(float2 uv, float2 blendUv) {
    float4 first = Linearize4(tex2D(SkyTexture, uv));
    float4 second = Linearize4(tex2D(SkyTextureBlend, blendUv));
    float4 blended = lerp(first, second, Params.x);
    float firstWeight = dot(abs(first.rgb), 1.0);
    float secondWeight = dot(abs(second.rgb), 1.0);
    float4 selected = (firstWeight <= 0.00001) ? second : ((secondWeight <= 0.00001) ? first : blended);
    selected.a = blended.a;
    return selected;
}

#if OMV_CELESTIAL
float4 Main(PixelInput input) : COLOR0 {
    float4 textureColor = Linearize4(tex2D(SkyTexture, input.uv));
    float4 vertexColor = Linearize4(input.color);
    float sunHeight = SunData.w;
    float3 sunColor = SunLightColor.rgb;
    float isSun = 1.0 - step(0.5, abs(ObjectData.x));
    float isMoon = 1.0 - step(0.5, abs(ObjectData.x - 6.0));
    float daylightGate = smoothstep(0.498, 0.502, SunData.x);

    float3 nonSunColor = textureColor.rgb * vertexColor.rgb * Params.y * lerp(SunData.y, 1.0, isMoon);
    float nonSunAlpha = textureColor.a * vertexColor.a;
    float sunsetWeight = smoothstep(0.3, 0.0, sunHeight);
    float3 sunResult = textureColor.rgb + sunColor * (sunsetWeight + SunData.y);
    float sunAlpha = textureColor.a * daylightGate;
    float4 result = float4(lerp(nonSunColor, sunResult, isSun), lerp(nonSunAlpha, sunAlpha, isSun));
    return float4(Delinearize3(result.rgb), result.a);
}
#else
#if OMV_CLOUD_NORMALS
float3 DecodeCloudNormal(float2 encoded, float3 eyeDirection) {
    float2 partial = encoded * 2.0 - 1.0;
    float z = sqrt(1.0 - saturate(dot(partial, partial)));
    float3 tangentNormal = normalize(float3(partial, z));
    float3 tangent = float3(eyeDirection.y, -eyeDirection.x, 0.0);
    tangent *= rsqrt(max(dot(tangent, tangent), 0.000001));
    float3 bitangent = cross(tangent, eyeDirection);
    return normalize(tangentNormal.x * tangent + tangentNormal.y * bitangent + tangentNormal.z * eyeDirection);
}
#endif

float4 Main(PixelInput input) : COLOR0 {
    const float3 up = float3(0.0, 0.0, 1.0);
    float4 cloud = SampleWeatherTextures(input.uv, input.blendUv);
    float4 vertexColor = Linearize4(input.color);
    float3 eyeDirection = normalize(input.location);
    float verticalBase = dot(eyeDirection, up) * 0.5 + 0.5;
    float verticality = verticalBase * verticalBase * verticalBase;
    float atmosphere = Pow8(1.0 - verticality) * SkyData.x;
    float sunFacing = saturate(dot(eyeDirection, SunDirection.xyz) * 0.5 + 0.5);
    float sunInfluence = pow(sunFacing, SunDirection.w);
    float sunHeight = SunData.w;
    float3 sunColor = SunLightColor.rgb;
    float3 skyColor = EvaluateSky(verticality, atmosphere, sunHeight, sunInfluence, sunColor);
    float alpha = cloud.a * CloudData.z;
    float3 scattering = Pow20(sunInfluence) * smoothstep(0.5, 1.0, 1.0 - alpha) * sunColor;

#if OMV_CLOUD_NORMALS
    float3 normal = DecodeCloudNormal(cloud.xy, -eyeDirection);
    float grey = lerp(saturate(CloudData.w), 1.0, cloud.z);
    float3 ambient = skyColor * grey * lerp(0.5, 0.7, sunFacing);
    float3 diffuse = saturate(dot(normal, SunDirection.xyz)) * sunColor * (1.0 - dot(ambient, float3(0.2126, 0.7152, 0.0722))) * lerp(0.8, 1.0, sunFacing);
    float fresnelWeight = Pow4(1.0 - max(dot(-eyeDirection, normal), 0.0));
    float3 fresnel = fresnelWeight * saturate(sunFacing * 2.0 - 1.0) * max(dot(normal, up), 0.0) * (sunColor + skyColor) * 0.2;
    float3 bounce = max(dot(normal, -up), 0.0) * ObjectData.yzw * 0.1 * sunHeight;
    cloud = float4(ambient + diffuse + fresnel + scattering + bounce, alpha);
#else
    float grey = lerp(dot(cloud.rgb, float3(0.2126, 0.7152, 0.0722)), 1.0, saturate(CloudData.w));
    grey = (grey - 0.5) * 1.5 + 0.5;
    float3 baseSky = SkyUpper.rgb;
    float3 darkSky = baseSky * 0.5;
    darkSky = darkSky * darkSky;
    darkSky = darkSky * darkSky * (baseSky * 0.5);
    float3 cloudTint = lerp(darkSky, lerp(baseSky, sunColor * 5.0, 0.7 * sunFacing + 0.3), (1.0 - sunInfluence) * grey);
    cloudTint = lerp(1.0, cloudTint * CloudData.w * 1.333, (1.0 - sunHeight) * smoothstep(0.0, 0.5, SunData.x));
    cloud.rgb = cloud.rgb * cloudTint + scattering * 4.0 * (1.0 - sunHeight) * smoothstep(0.0, 0.5, SunData.x);
#endif

    cloud.rgb *= vertexColor.rgb * Params.y * SunsetColor.w * CloudData.w;
    cloud.a = pow(saturate(cloud.a * vertexColor.a), rcp(max(CloudData.z, 0.05)));
    return float4(Delinearize3(cloud.rgb), cloud.a);
}
#endif
