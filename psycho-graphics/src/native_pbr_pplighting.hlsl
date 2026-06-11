float4 AmbientColor : register(c1);
float4 PSLightColor[10] : register(c3);
float4 Toggles : register(c27);
float4 PbrMaterialFlags : register(c31);
float4 TESR_PBRData : register(c32);
float4 TESR_PBRExtraData : register(c33);

sampler2D BaseMap : register(s0);
sampler2D NormalMap : register(s1);

struct PixelInput
{
    float3 vertex_color : COLOR0;
    float4 fog_color : COLOR1;
    float2 uv : TEXCOORD0;
    float4 light_dir : TEXCOORD1;
    float3 view_dir : TEXCOORD6;
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

float3 DecodeNormal(float4 normal_sample)
{
    return SafeNormalize(normal_sample.xyz * 2.0f - 1.0f, float3(0.0f, 0.0f, 1.0f));
}

float PbrRoughnessScale()
{
    return (TESR_PBRData.y > 0.0f) ? TESR_PBRData.y : 1.0f;
}

float PbrLightMultiplier()
{
    return (TESR_PBRData.z > 0.0f) ? TESR_PBRData.z : 1.0f;
}

float PbrAmbientMultiplier()
{
    return (TESR_PBRData.w > 0.0f) ? TESR_PBRData.w : 1.0f;
}

float PbrAlbedoSaturation()
{
    return (TESR_PBRExtraData.x > 0.0f) ? TESR_PBRExtraData.x : 1.0f;
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

float3 PbrSun(float metallicness, float roughness, float3 albedo, float3 normal, float3 eye_dir, float3 light_dir, float3 light_color)
{
    float3 reflectance = lerp(float3(0.04f, 0.04f, 0.04f), albedo, metallicness);

    normal = SafeNormalize(normal, float3(0.0f, 0.0f, 1.0f));
    eye_dir = SafeNormalize(eye_dir, float3(0.0f, 0.0f, 1.0f));
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
    float3 diffuse = (1.0f - metallicness) * LambertianDiffuse(albedo, fresnel);
    float3 specular = Brdf(roughness, fresnel, ndotv, ndots, ndoth);

    return (diffuse * ndotl + specular * ndots) * light_color * PI;
}

float3 AmbientLighting(float3 ambient, float3 albedo)
{
    return ambient * PbrAmbientMultiplier() * albedo;
}

float4 Main(PixelInput input) : COLOR0
{
    float4 base_color = tex2D(BaseMap, input.uv.xy);

    if (AmbientColor.a < 1.0f) {
        clip(base_color.a - Toggles.w);
    }

    float4 normal_sample = tex2D(NormalMap, input.uv.xy);
    float3 normal = DecodeNormal(normal_sample);
    float roughness = RoughnessFromGloss(normal_sample.a);

    float3 albedo = base_color.rgb;
    albedo = (Toggles.x <= 0.0f) ? albedo : albedo * saturate(input.vertex_color.rgb);
    albedo = lerp(Luma(albedo), albedo, PbrAlbedoSaturation());

    float3 light_color = PSLightColor[0].rgb * PbrLightMultiplier();
    float3 lighting = PbrSun(0.0f, roughness, albedo, normal, input.view_dir.xyz, input.light_dir.xyz, light_color);
    lighting += AmbientLighting(AmbientColor.rgb, albedo);

    float3 final_color = (Toggles.y <= 0.0f)
        ? lighting
        : lerp(lighting, input.fog_color.rgb, saturate(input.fog_color.a));

    return float4(final_color, base_color.a * AmbientColor.a);
}
