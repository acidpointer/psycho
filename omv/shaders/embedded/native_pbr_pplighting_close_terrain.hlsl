#ifndef PBR_TERRAIN_TEX_COUNT
#define PBR_TERRAIN_TEX_COUNT 1
#endif

#ifndef PBR_TERRAIN_POINT_LIGHTS
#define PBR_TERRAIN_POINT_LIGHTS 0
#endif

float4 AmbientColor : register(c1);
float4 SunColor : register(c3);
float4 SunDir : register(c18);
float4 LandSpec[2] : register(c32);
float4 LandHeight[2] : register(c34);
float4 FogParam : register(c36);
float4 FogColor : register(c37);
float4 TESR_TerrainData : register(c89);
float4 TESR_TerrainExtraData : register(c90);
float OMV_SupplementalPointLightCount : register(c91);
float4 OMV_SupplementalPointLightData[48] : register(c92);

sampler2D BaseMap[7] : register(s0);
sampler2D NormalMap[7] : register(s7);

#if PBR_TERRAIN_POINT_LIGHTS > 0
float4 PointLightColor[PBR_TERRAIN_POINT_LIGHTS] : register(c39);
float4 PointLightPosition[PBR_TERRAIN_POINT_LIGHTS] : register(c63);
float PointLightCount : register(c88);
#endif

struct PixelInput
{
    float2 uv : TEXCOORD0;
    float3 vertex_color : TEXCOORD1_centroid;
    float3 local_position : TEXCOORD2_centroid;
    float3 tangent : TEXCOORD3_centroid;
    float3 binormal : TEXCOORD4_centroid;
    float3 normal : TEXCOORD5_centroid;
    float4 blend_0 : COLOR0;
    float4 blend_1 : COLOR1;
    float4 projection_position : TEXCOORD6_centroid;
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

float3 StableHalfway(float3 view_dir, float3 light_dir)
{
    float3 halfway = view_dir + light_dir;
    float length_squared = dot(halfway, halfway);
    return halfway * rsqrt(max(length_squared, 1.0e-8f));
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
    return TESR_TerrainData.z;
}

float PbrAmbientMultiplier()
{
    return TESR_TerrainData.w;
}

float PbrAlbedoSaturation()
{
    return TESR_TerrainExtraData.y;
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

struct PbrSurface
{
    float3 reflectance;
    float3 diffuse_color;
    float ndotv;
    float alpha2;
    float geometry_k;
    float view_shadowing;
};

PbrSurface PreparePbrSurface(float roughness, float3 albedo, float3 normal, float3 view_dir)
{
    PbrSurface surface;
    float metallic = PbrMetallicness();
    surface.reflectance = lerp(float3(0.04f, 0.04f, 0.04f), albedo, metallic);
    surface.diffuse_color = albedo * (1.0f - metallic) / PI;
    surface.ndotv = max(Shades(normal, view_dir), 0.00001f);
    float alpha = roughness * roughness;
    surface.alpha2 = alpha * alpha;
    surface.geometry_k = (roughness + 1.0f) * (roughness + 1.0f) * 0.125f;
    surface.view_shadowing = surface.ndotv / max(
        surface.ndotv * (1.0f - surface.geometry_k) + surface.geometry_k,
        0.00000001f
    );
    return surface;
}

float3 PreparedBrdf(PbrSurface surface, float3 fresnel, float ndotl, float ndoth)
{
    float distribution_denominator = (ndoth * surface.alpha2 - ndoth) * ndoth + 1.0f;
    float distribution = surface.alpha2 / max(
        PI * distribution_denominator * distribution_denominator,
        0.00001f
    );
    float light_shadowing = ndotl / max(
        ndotl * (1.0f - surface.geometry_k) + surface.geometry_k,
        0.00000001f
    );
    float3 numerator = distribution * surface.view_shadowing * light_shadowing * fresnel;
    return numerator / max(4.0f * surface.ndotv * ndotl, 0.00001f);
}

float3 PbrDirect(PbrSurface surface, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
{

    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));

    float3 halfway = StableHalfway(view_dir, light_dir);
    float ndotl = max(Shades(normal, light_dir), 0.00001f);
    float ndoth = Shades(normal, halfway);
    float ldoth = Shades(light_dir, halfway);
    float3 fresnel = Fresnel(surface.reflectance, float3(1.0f, 1.0f, 1.0f), ldoth);
    float3 diffuse = (1.0f - fresnel) * surface.diffuse_color;
    float3 specular = PreparedBrdf(surface, fresnel, ndotl, ndoth);

    return (diffuse + specular) * ndotl * light_color * PI;
}

float3 PbrSun(PbrSurface surface, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
{
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));

    float3 reflect_dir = reflect(light_dir, normal);
    float radius = sin(SUN_RADIUS);
    float dist = cos(SUN_RADIUS);
    float ldotr = dot(light_dir, reflect_dir);
    float3 closest_point = reflect_dir - ldotr * light_dir;
    float3 sun_dir = (ldotr < dist)
        ? SafeNormalize(dist * light_dir + SafeNormalize(closest_point, reflect_dir) * radius, reflect_dir)
        : reflect_dir;

    float3 halfway = StableHalfway(view_dir, sun_dir);
    float ndots = max(Shades(normal, sun_dir), 0.00001f);
    float ndoth = Shades(normal, halfway);
    float ndotl = Shades(normal, light_dir);
    float ldoth = Shades(light_dir, halfway);
    float3 fresnel = Fresnel(surface.reflectance, float3(1.0f, 1.0f, 1.0f), ldoth);
    float3 diffuse = (1.0f - fresnel) * surface.diffuse_color;
    float3 specular = PreparedBrdf(surface, fresnel, ndots, ndoth);

    return (diffuse * ndotl + specular * ndots) * light_color * PI;
}

float VanillaAtt(float3 light_vector, float radius)
{
    float safe_radius = max(radius, 0.001f);
    float3 att = light_vector / safe_radius;
    return saturate(1.0f - Shades(att, att));
}

float3 BlendDiffuseMaps(float3 vertex_color, float2 uv, float blends[7])
{
    float3 color = float3(0.0f, 0.0f, 0.0f);
    [unroll] for (int i = 0; i < PBR_TERRAIN_TEX_COUNT; i++)
    {
        color += tex2D(BaseMap[i], uv).rgb * blends[i];
    }

    return color * vertex_color;
}

float3 BlendNormalMaps(float2 uv, float blends[7], float spec[7], out float gloss)
{
    gloss = 0.0f;

    float3 blended_normal = float3(0.0f, 0.0f, 0.0f);
    [unroll] for (int i = 0; i < PBR_TERRAIN_TEX_COUNT; i++)
    {
        float blend = blends[i];
        float4 normal_sample = tex2D(NormalMap[i], uv);
        blended_normal += (normal_sample.rgb - 0.5f) * blend;
        gloss += normal_sample.a * blend * ((spec[i] > 0.0f) ? 1.0f : 0.0f);
    }

    gloss = saturate(gloss);
    return SafeNormalize(blended_normal, float3(0.0f, 0.0f, 1.0f));
}

float3 SunLighting(PbrSurface surface, float3 light_dir, float3 sun_color, float3 view_dir, float3 normal, float3 ambient_color, float3 albedo, float parallax_multiplier)
{
    float3 light_color = sun_color * PbrLightMultiplier() * parallax_multiplier;
    float3 ambient = ambient_color * PbrAmbientMultiplier() * albedo;
    return max(float3(0.0f, 0.0f, 0.0f), PbrSun(surface, normal, view_dir, light_dir, light_color) + ambient);
}

float3 PointLighting(PbrSurface surface, float3 light_dir, float attenuation, float3 light_color, float3 view_dir, float3 normal)
{
    return max(float3(0.0f, 0.0f, 0.0f), PbrDirect(surface, normal, view_dir, light_dir, light_color * PbrLightMultiplier()) * attenuation);
}

PixelOutput Main(PixelInput input)
{
    PixelOutput output;

    float3 tangent = SafeNormalize(input.tangent, float3(1.0f, 0.0f, 0.0f));
    float3 binormal = SafeNormalize(input.binormal, float3(0.0f, 1.0f, 0.0f));
    float3 normal_ws = SafeNormalize(input.normal, float3(0.0f, 0.0f, 1.0f));
    float3x3 tbn = float3x3(tangent, binormal, normal_ws);
    float3 view_dir = SafeNormalize(mul(tbn, input.eye_position - input.local_position), float3(0.0f, 0.0f, 1.0f));

    float blends[7] = {
        input.blend_0.x,
        input.blend_0.y,
        input.blend_0.z,
        input.blend_0.w,
        input.blend_1.x,
        input.blend_1.y,
        input.blend_1.z
    };
    float spec[7] = {
        LandSpec[0].x,
        LandSpec[0].y,
        LandSpec[0].z,
        LandSpec[0].w,
        LandSpec[1].x,
        LandSpec[1].y,
        LandSpec[1].z
    };
    float2 terrain_uv = input.uv.xy;

    float gloss = 0.0f;
    float3 albedo = BlendDiffuseMaps(input.vertex_color, terrain_uv, blends);
    albedo = lerp(Luma(albedo), albedo, PbrAlbedoSaturation());
    float3 normal = BlendNormalMaps(terrain_uv, blends, spec, gloss);
    float roughness = RoughnessFromGloss(gloss);
    PbrSurface pbr_surface = PreparePbrSurface(roughness, albedo, normal, view_dir);

    float3 light_ts = mul(tbn, SunDir.xyz);
    float3 lighting = SunLighting(pbr_surface, light_ts, SunColor.rgb, view_dir, normal, AmbientColor.rgb, albedo, 1.0f);

    int native_point_count = 0;
#if PBR_TERRAIN_POINT_LIGHTS > 0
    native_point_count = min((int)PointLightCount, PBR_TERRAIN_POINT_LIGHTS);
#endif
    int supplemental_point_count = min((int)OMV_SupplementalPointLightCount, 24 - native_point_count);
    int total_point_count = native_point_count + supplemental_point_count;
    [loop] for (int point_index = 0; point_index < total_point_count; point_index++)
    {
        float4 light_position;
        float4 light_color;
#if PBR_TERRAIN_POINT_LIGHTS > 0
        [branch] if (point_index < native_point_count)
        {
            light_position = PointLightPosition[point_index];
            light_color = PointLightColor[point_index];
        }
        else
#endif
        {
            int supplemental_index = point_index - native_point_count;
            light_position = OMV_SupplementalPointLightData[supplemental_index * 2];
            light_color = OMV_SupplementalPointLightData[supplemental_index * 2 + 1];
        }

        float3 light_vector = light_position.xyz - input.local_position;
        float attenuation = VanillaAtt(light_vector, light_position.w);
        [branch] if (attenuation > 0.001f)
        {
            lighting += PointLighting(
                pbr_surface,
                mul(tbn, light_vector),
                attenuation,
                light_color.rgb,
                view_dir,
                normal
            );
        }
    }

    float3 fog_position = input.projection_position.xyz;
    fog_position.z = input.projection_position.w - input.projection_position.z;
    float fog_strength = 1.0f - saturate((FogParam.x - length(fog_position)) / FogParam.y);
    float fog_alpha = pow(fog_strength, FogParam.z);

    output.color_0.rgb = lerp(max(lighting, float3(0.0f, 0.0f, 0.0f)), FogColor.rgb, fog_alpha);
    output.color_0.a = 1.0f;
    return output;
}
