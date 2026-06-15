float4 AmbientColor : register(c1);
float4 PSLightColor[10] : register(c3);
float4 LODTexParams : register(c31);
float4 LandLODSpec : register(c38);
float4 TESR_TerrainData : register(c89);
float4 TESR_TerrainExtraData : register(c90);

sampler2D BaseMap : register(s0);
sampler2D NormalMap : register(s1);
sampler2D LODParentTex : register(s4);
sampler2D LODParentNormals : register(s6);
sampler2D LODLandNoise : register(s7);

struct PixelInput
{
    float2 uv : TEXCOORD0;
    float4 fog_color : COLOR1;
    float3 light_dir : TEXCOORD1;
    float3 local_position : TEXCOORD2;
    float3 eye_position : TEXCOORD3;
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
    return saturate(max(0.043f, 1.0f - saturate(gloss)) * PbrRoughnessScale());
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

float3 PbrSun(float roughness, float3 albedo, float3 normal, float3 eye_dir, float3 light_dir, float3 light_color)
{
    float metallic = PbrMetallicness();
    float3 reflectance = lerp(float3(0.04f, 0.04f, 0.04f), albedo, metallic);

    normal = SafeNormalize(normal, float3(0.0f, 0.0f, 1.0f));
    eye_dir = SafeNormalize(eye_dir, light_dir);
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));

    float3 reflect_dir = reflect(light_dir, normal);
    float radius = sin(SUN_RADIUS);
    float dist = cos(SUN_RADIUS);
    float ldotr = dot(light_dir, reflect_dir);
    float3 closest_point = reflect_dir - ldotr * light_dir;
    float3 sun_dir = (ldotr < dist)
        ? SafeNormalize(dist * light_dir + SafeNormalize(closest_point, reflect_dir) * radius, reflect_dir)
        : reflect_dir;

    float3 halfway = SafeNormalize(eye_dir + sun_dir, normal);
    float ndots = max(Shades(normal, sun_dir), 0.00001f);
    float ndotv = max(Shades(normal, eye_dir), 0.00001f);
    float ndoth = Shades(normal, halfway);
    float ndotl = Shades(normal, light_dir);
    float ldoth = Shades(light_dir, halfway);
    float3 fresnel = Fresnel(reflectance, float3(1.0f, 1.0f, 1.0f), ldoth);
    float3 diffuse = LambertianDiffuse(albedo, fresnel) * (1.0f - metallic);
    float3 specular = Brdf(roughness, fresnel, ndotv, ndots, ndoth);

    return (diffuse * ndotl + specular * ndots) * light_color * PI;
}

float3 AmbientLighting(float3 ambient, float3 albedo)
{
    return ambient * PbrAmbientMultiplier() * albedo;
}

float4 Main(PixelInput input) : COLOR0
{
    float lod_blend = saturate(LODTexParams.w);

    float4 normal_sample = tex2D(NormalMap, input.uv);
    float4 parent_normal_sample = tex2D(LODParentNormals, (input.uv * 0.5f) + LODTexParams.xy);
    normal_sample = lerp(parent_normal_sample, normal_sample, lod_blend);

    float2 base_uv = (input.uv * 0.9921875f) + (1.0f / 256.0f);
    float3 parent_albedo = tex2D(LODParentTex, (0.5f * base_uv) + lerp(LODTexParams.xy, 0.25f, 1.0f / 128.0f)).rgb;
    float3 base_albedo = tex2D(BaseMap, base_uv).rgb;
    float3 albedo = lerp(parent_albedo, base_albedo, lod_blend);

    float noise_tile = (TESR_TerrainExtraData.w > 0.0f) ? TESR_TerrainExtraData.w : 1.75f;
    float noise = tex2D(LODLandNoise, input.uv * noise_tile).r;
    albedo = lerp(Luma(albedo), albedo, PbrAlbedoSaturation());

    float3 normal = ExpandNormal(normal_sample.rgb);
    float gloss = normal_sample.a * ((LandLODSpec.x > 0.0f) ? 1.0f : 0.0f);
    float roughness = RoughnessFromGloss(gloss);
    float3 light_dir = SafeNormalize(input.light_dir.xyz, float3(0.0f, 0.0f, 1.0f));
    float3 view_dir = SafeNormalize(input.eye_position - input.local_position, light_dir);

    float3 lighting = PbrSun(
        roughness,
        albedo,
        normal,
        view_dir,
        light_dir,
        PSLightColor[0].rgb * PbrLightMultiplier()
    );
    lighting += AmbientLighting(AmbientColor.rgb, albedo);

    float noise_scale = saturate(TESR_TerrainExtraData.z);
    lighting = lerp(lighting, lighting * ((noise * 0.8f) + 0.55f), noise_scale);

    float3 final_color = lerp(max(lighting, float3(0.0f, 0.0f, 0.0f)), input.fog_color.rgb, saturate(input.fog_color.a));
    return float4(final_color, 1.0f);
}
