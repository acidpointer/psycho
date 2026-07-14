float4 AmbientColor : register(c1);
float4 PSLightColor : register(c3);
float4 LandLODSpec : register(c38);
float4 TESR_TerrainData : register(c89);
float4 TESR_TerrainExtraData : register(c90);

sampler2D BaseMap : register(s0);
sampler2D NormalMap : register(s1);
sampler2D LODLandNoise : register(s2);

struct PixelInput
{
    float2 uv : TEXCOORD0;
    float3 light_dir : TEXCOORD3_centroid;
    float blend : TEXCOORD4_centroid;
    float4 fog_color : TEXCOORD5_centroid;
    float3 local_position : TEXCOORD6_centroid;
    float3 eye_position : TEXCOORD7_centroid;
};

struct PixelOutput
{
    float4 color_0 : COLOR0;
};

static const float PI = 3.14159265f;
static const float SUN_RADIUS = 0.00918043f;

float3 SafeNormalize(float3 value, float3 fallback)
{
    float len_sq = dot(value, value);
    return (len_sq > 0.000001f) ? value * rsqrt(len_sq) : fallback;
}

float Shades(float3 a, float3 b)
{
    return saturate(dot(a, b));
}

float3 Luma(float3 value)
{
    float lum = dot(value, float3(0.299f, 0.587f, 0.114f));
    return float3(lum, lum, lum);
}

float3 ExpandNormal(float3 value)
{
    return SafeNormalize(value * 2.0f - 1.0f, float3(0.0f, 0.0f, 1.0f));
}

bool TerrainPbrEnabled()
{
    return TESR_TerrainExtraData.x > 0.5f;
}

float PbrRoughnessScale()
{
    return (TESR_TerrainData.y > 0.0f) ? TESR_TerrainData.y : 1.0f;
}

float PbrMetallicness()
{
    return saturate(TESR_TerrainData.x);
}

float PbrLightMultiplier()
{
    return (TESR_TerrainData.z > 0.0f) ? TESR_TerrainData.z : 1.0f;
}

float PbrAmbientMultiplier()
{
    return (TESR_TerrainData.w > 0.0f) ? TESR_TerrainData.w : 1.0f;
}

float PbrAlbedoSaturation()
{
    return (TESR_TerrainExtraData.y > 0.0f) ? TESR_TerrainExtraData.y : 1.0f;
}

float RoughnessFromGloss(float gloss)
{
    return clamp((1.0f - saturate(gloss)) * PbrRoughnessScale(), 0.043f, 1.0f);
}

float3 Fresnel(float3 f0, float3 f90, float cosine)
{
    float f = 1.0f - saturate(cosine);
    float f2 = f * f;
    return f0 + (f90 - f0) * (f2 * f2 * f);
}

float3 LambertianDiffuse(float3 albedo, float3 fresnel)
{
    return (1.0f - fresnel) * albedo / PI;
}

float GGX(float ndoth, float roughness)
{
    float a2 = roughness * roughness * roughness * roughness;
    float d = max((ndoth * a2 - ndoth) * ndoth + 1.0f, 0.00001f);
    return a2 / max(PI * d * d, 0.00001f);
}

float SchlickBeckmann(float ndotx, float roughness)
{
    float k = (roughness + 1.0f) * (roughness + 1.0f) * 0.125f;
    return ndotx / max(ndotx * (1.0f - k) + k, 0.00000001f);
}

float GeometryShadowing(float roughness, float ndotv, float ndotl)
{
    return SchlickBeckmann(ndotv, roughness) * SchlickBeckmann(ndotl, roughness);
}

float3 Brdf(float roughness, float3 fresnel, float ndotv, float ndotl, float ndoth)
{
    float3 numerator = GGX(ndoth, roughness) * GeometryShadowing(roughness, ndotv, ndotl) * fresnel;
    return numerator / max(4.0f * ndotv * ndotl, 0.00001f);
}

float3 PbrSun(float roughness, float3 albedo, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
{
    float metallic = PbrMetallicness();
    float3 reflectance = lerp(float3(0.04f, 0.04f, 0.04f), albedo, metallic);

    normal = SafeNormalize(normal, float3(0.0f, 0.0f, 1.0f));
    view_dir = SafeNormalize(view_dir, light_dir);
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));

    float3 reflect_dir = reflect(light_dir, normal);
    float radius = sin(SUN_RADIUS);
    float dist = cos(SUN_RADIUS);
    float ldotr = dot(light_dir, reflect_dir);
    float3 closest_point = reflect_dir - ldotr * light_dir;
    float3 sun_dir = (ldotr < dist)
        ? SafeNormalize(dist * light_dir + SafeNormalize(closest_point, reflect_dir) * radius, reflect_dir)
        : reflect_dir;

    float3 halfway = SafeNormalize(view_dir + sun_dir, normal);
    float ndots = max(Shades(normal, sun_dir), 0.00001f);
    float ndotv = max(Shades(normal, view_dir), 0.00001f);
    float ndoth = Shades(normal, halfway);
    float ndotl = Shades(normal, light_dir);
    float ldoth = Shades(light_dir, halfway);
    float3 fresnel = Fresnel(reflectance, float3(1.0f, 1.0f, 1.0f), ldoth);
    float3 diffuse = LambertianDiffuse(albedo, fresnel) * (1.0f - metallic);
    float3 specular = Brdf(roughness, fresnel, ndotv, ndots, ndoth);

    return (diffuse * ndotl + specular * ndots) * light_color * PI;
}

float3 VanillaDirect(float3 light_dir, float3 light_color, float3 view_dir, float3 normal, float3 albedo, float gloss, float gloss_power)
{
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));
    view_dir = SafeNormalize(view_dir, float3(0.0f, 0.0f, 1.0f));

    float3 halfway = SafeNormalize(light_dir + view_dir, normal);
    float ndotl = Shades(normal, light_dir);
    float spec_strength = gloss * pow(abs(Shades(normal, halfway)), gloss_power);
    float3 lighting = albedo * ndotl * light_color;
    lighting += saturate((0.2f >= ndotl ? spec_strength * saturate(ndotl + 0.5f) : spec_strength) * light_color);
    return lighting;
}

float3 SunLighting(float3 light_dir, float3 sun_color, float3 view_dir, float3 normal, float3 ambient_color, float3 albedo, float gloss, float gloss_power, float roughness)
{
    float3 ambient = ambient_color * PbrAmbientMultiplier() * albedo;

    if (TerrainPbrEnabled())
    {
        return max(float3(0.0f, 0.0f, 0.0f), PbrSun(roughness, albedo, normal, view_dir, light_dir, sun_color * PbrLightMultiplier()) + ambient);
    }

    return VanillaDirect(light_dir, sun_color, view_dir, normal, albedo, gloss, gloss_power) + ambient;
}

PixelOutput Main(PixelInput input)
{
    PixelOutput output;

    float3 view_dir = SafeNormalize(input.eye_position - input.local_position, input.light_dir);
    float4 normal_sample = tex2D(NormalMap, input.uv);
    float3 normal = ExpandNormal(normal_sample.rgb);
    float gloss = normal_sample.a * ((LandLODSpec.x > 0.0f) ? 1.0f : 0.0f);
    float roughness = RoughnessFromGloss(gloss);

    float3 albedo = tex2D(BaseMap, input.uv).rgb;
    albedo = lerp(Luma(albedo), albedo, PbrAlbedoSaturation());

    float noise_tile = (TESR_TerrainExtraData.w > 0.0f) ? TESR_TerrainExtraData.w : 1.75f;
    float noise = tex2D(LODLandNoise, input.uv * noise_tile).r;

    float3 lighting = SunLighting(
        input.light_dir,
        PSLightColor.rgb,
        view_dir,
        normal,
        AmbientColor.rgb,
        albedo,
        gloss,
        LandLODSpec.x,
        roughness
    );

    float noise_scale = saturate(TESR_TerrainExtraData.z);
    lighting = lerp(lighting, lighting * ((noise * 0.8f) + 0.55f), noise_scale);

    output.color_0.rgb = lerp(max(lighting, float3(0.0f, 0.0f, 0.0f)), input.fog_color.rgb, saturate(input.fog_color.a));
    output.color_0.a = saturate(input.blend);
    return output;
}
