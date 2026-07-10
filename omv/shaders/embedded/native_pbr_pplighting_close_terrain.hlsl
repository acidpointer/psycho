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
float4 TESR_TerrainParallaxData : register(c91);
float4 TESR_TerrainParallaxExtraData : register(c92);

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
    float a = roughness * roughness;
    float a2 = a * a;
    float d = (ndoth * a2 - ndoth) * ndoth + 1.0f;
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

float3 PbrDirect(float roughness, float3 albedo, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
{
    float metallic = PbrMetallicness();
    float3 reflectance = lerp(float3(0.04f, 0.04f, 0.04f), albedo, metallic);

    normal = SafeNormalize(normal, float3(0.0f, 0.0f, 1.0f));
    view_dir = SafeNormalize(view_dir, float3(0.0f, 0.0f, 1.0f));
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));

    float3 halfway = SafeNormalize(view_dir + light_dir, normal);
    float ndotl = max(Shades(normal, light_dir), 0.00001f);
    float ndotv = max(Shades(normal, view_dir), 0.00001f);
    float ndoth = Shades(normal, halfway);
    float ldoth = Shades(light_dir, halfway);
    float3 fresnel = Fresnel(reflectance, float3(1.0f, 1.0f, 1.0f), ldoth);
    float3 diffuse = LambertianDiffuse(albedo, fresnel) * (1.0f - metallic);
    float3 specular = Brdf(roughness, fresnel, ndotv, ndotl, ndoth);

    return (diffuse + specular) * ndotl * light_color * PI;
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

float3 VanillaDirect(float3 light_dir, float attenuation, float3 light_color, float3 view_dir, float3 normal, float3 albedo, float gloss, float gloss_power)
{
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));
    view_dir = SafeNormalize(view_dir, float3(0.0f, 0.0f, 1.0f));

    float3 halfway = SafeNormalize(light_dir + view_dir, normal);
    float ndotl = Shades(normal, light_dir);
    float spec_strength = gloss * pow(abs(Shades(normal, halfway)), gloss_power);
    float3 lighting = albedo * ndotl * light_color * attenuation;
    lighting += saturate(((0.2f >= ndotl ? (spec_strength * saturate(ndotl + 0.5f)) : spec_strength) * light_color) * attenuation);
    return lighting;
}

float VanillaAtt(float3 light_vector, float radius)
{
    float safe_radius = max(radius, 0.001f);
    float3 att = light_vector / safe_radius;
    return saturate(1.0f - Shades(att, att));
}

void CopyTerrainWeights(float blends[7], out float weights[7])
{
    [unroll] for (int i = 0; i < 7; i++)
    {
        weights[i] = blends[i];
    }
}

float TerrainHeight(float2 uv, float2 dx, float2 dy, float blend_factor, float blends[7], float height_status[7], out float weights[7])
{
    float blend_power = max(blend_factor * 4.0f, 0.0001f);
    float total = 0.0f;

    [unroll] for (int clear_index = 0; clear_index < 7; clear_index++)
    {
        weights[clear_index] = 0.0f;
    }

    [unroll] for (int i = 0; i < PBR_TERRAIN_TEX_COUNT; i++)
    {
        weights[i] = pow(abs(blends[i]), 1.0f + blend_factor);
        if (weights[i] > 0.0f)
        {
            float height = (height_status[i] > 0.0f) ? tex2Dgrad(BaseMap[i], uv, dx, dy).a : 0.5f;
            weights[i] *= 0.001f + pow(abs(height), blend_power);
        }
        total += weights[i];
    }

    float inv_total = (total > 0.000001f) ? rcp(total) : 0.0f;
    [unroll] for (int weight_index = 0; weight_index < PBR_TERRAIN_TEX_COUNT; weight_index++)
    {
        weights[weight_index] *= inv_total;
    }

    return pow(max(total, 0.000001f), rcp(blend_power));
}

float2 TerrainParallaxCoords(float distance, float2 uv, float2 dx, float2 dy, float3 view_dir_ts, float blends[7], float height_status[7], out float weights[7])
{
    if (TESR_TerrainParallaxData.x <= 0.0f)
    {
        CopyTerrainWeights(blends, weights);
        return uv;
    }

    float max_steps = (TESR_TerrainParallaxData.w > 0.0f) ? 16.0f : 8.0f;
    float max_distance = max(TESR_TerrainParallaxExtraData.x, 1.0f);
    float height = TESR_TerrainParallaxExtraData.y;
    float distance_blend = saturate(distance / max_distance);
    float quality = saturate(1.0f - distance_blend);
    float blend_factor = (TESR_TerrainParallaxData.z > 0.0f) ? quality : 0.25f;

    view_dir_ts = SafeNormalize(view_dir_ts, float3(0.0f, 0.0f, 1.0f));
    view_dir_ts.z = (view_dir_ts.z * 0.7f) + 0.3f;
    view_dir_ts.xy /= max(abs(view_dir_ts.z), 0.0001f);

    float max_height = height;
    float min_height = max_height * 0.5f;
    if (distance_blend >= 1.0f)
    {
        CopyTerrainWeights(blends, weights);
        return uv;
    }

    int num_steps = int((max_steps * (1.0f - distance_blend)) + 0.5f);
    num_steps = ((num_steps + 3) / 4) * 4;
    num_steps = clamp(num_steps, 4, (int)max_steps);

    float step_size = rcp((float)num_steps);
    float2 offset_per_step = view_dir_ts.xy * max_height * step_size;
    float2 previous_offset = view_dir_ts.xy * min_height + uv;
    float previous_bound = 1.0f;
    float previous_height = 1.0f;
    float2 point_a = 0.0f;
    float2 point_b = 0.0f;
    int original_steps = num_steps;
    bool done = false;
    bool contact_refinement = false;

    [loop][fastopt] while (num_steps > 0 && !done)
    {
        float4 current_offset[2];
        current_offset[0] = previous_offset.xyxy - float4(1.0f, 1.0f, 2.0f, 2.0f) * offset_per_step.xyxy;
        current_offset[1] = previous_offset.xyxy - float4(3.0f, 3.0f, 4.0f, 4.0f) * offset_per_step.xyxy;
        float4 current_bound = float4(previous_bound, previous_bound, previous_bound, previous_bound)
            - float4(1.0f, 2.0f, 3.0f, 4.0f) * step_size;
        float4 current_height;

        current_height.x = TerrainHeight(current_offset[0].xy, dx, dy, blend_factor, blends, height_status, weights);
        current_height.y = TerrainHeight(current_offset[0].zw, dx, dy, blend_factor, blends, height_status, weights);
        current_height.z = TerrainHeight(current_offset[1].xy, dx, dy, blend_factor, blends, height_status, weights);
        current_height.w = TerrainHeight(current_offset[1].zw, dx, dy, blend_factor, blends, height_status, weights);

        bool4 test_result = current_height >= current_bound;
        [branch] if (any(test_result))
        {
            float2 last_offset = 0.0f;
            [flatten] if (test_result.w)
            {
                last_offset = current_offset[1].xy;
                point_a = float2(current_bound.w, current_height.w);
                point_b = float2(current_bound.z, current_height.z);
            }
            [flatten] if (test_result.z)
            {
                last_offset = current_offset[0].zw;
                point_a = float2(current_bound.z, current_height.z);
                point_b = float2(current_bound.y, current_height.y);
            }
            [flatten] if (test_result.y)
            {
                last_offset = current_offset[0].xy;
                point_a = float2(current_bound.y, current_height.y);
                point_b = float2(current_bound.x, current_height.x);
            }
            [flatten] if (test_result.x)
            {
                last_offset = previous_offset;
                point_a = float2(current_bound.x, current_height.x);
                point_b = float2(previous_bound, previous_height);
            }

            if (contact_refinement)
            {
                done = true;
            }
            else
            {
                contact_refinement = true;
                previous_offset = last_offset;
                previous_bound = point_b.x;
                num_steps = original_steps;
                step_size /= (float)num_steps;
                offset_per_step /= (float)num_steps;
            }
        }
        else
        {
            previous_offset = current_offset[1].zw;
            previous_bound = current_bound.w;
            previous_height = current_height.w;
            num_steps -= 4;
        }
    }

    float delta_b = point_b.x - point_b.y;
    float delta_a = point_a.x - point_a.y;
    float denominator = delta_b - delta_a;
    float parallax_amount = (abs(denominator) > 0.000001f)
        ? (point_a.x * delta_b - point_b.x * delta_a) / denominator
        : 0.0f;
    distance_blend *= distance_blend;

    float offset = (1.0f - parallax_amount) * -max_height + min_height;
    return lerp(view_dir_ts.xy * offset + uv, uv, distance_blend);
}

float TerrainParallaxShadow(float distance, float2 uv, float2 dx, float2 dy, float3 light_ts, float blends[7], float height_status[7])
{
    if (TESR_TerrainParallaxData.y <= 0.0f)
    {
        return 1.0f;
    }

    float max_distance = max(TESR_TerrainParallaxExtraData.x, 1.0f);
    float shadows_intensity = TESR_TerrainParallaxExtraData.z;
    float quality = 1.0f - distance / max_distance;
    if (quality <= 0.0f)
    {
        return 1.0f;
    }

    float weights[7] = { 0, 0, 0, 0, 0, 0, 0 };
    float base_height = TerrainHeight(uv, dx, dy, quality, blends, height_status, weights);
    float2 ray_dir = light_ts.xy * 0.1f;
    float4 multipliers = rcp(float4(1.0f, 2.0f, 3.0f, 4.0f));
    float4 base_heights = float4(base_height, base_height, base_height, base_height);
    float4 shadow_heights = base_heights;

    shadow_heights.x = TerrainHeight(uv + ray_dir * multipliers.x, dx, dy, quality, blends, height_status, weights);
    if (quality > 0.25f)
    {
        shadow_heights.y = TerrainHeight(uv + ray_dir * multipliers.y, dx, dy, quality, blends, height_status, weights);
    }
    if (quality > 0.5f)
    {
        shadow_heights.z = TerrainHeight(uv + ray_dir * multipliers.z, dx, dy, quality, blends, height_status, weights);
    }
    if (quality > 0.75f)
    {
        shadow_heights.w = TerrainHeight(uv + ray_dir * multipliers.w, dx, dy, quality, blends, height_status, weights);
    }

    return 1.0f - saturate(dot(max(float4(0.0f, 0.0f, 0.0f, 0.0f), shadow_heights - base_heights), float4(1.0f, 1.0f, 1.0f, 1.0f)) * shadows_intensity) * quality;
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

float3 BlendNormalMaps(float2 uv, float blends[7], float spec[7], out float gloss, out float spec_exponent)
{
    gloss = 0.0f;
    spec_exponent = 0.0f;

    float3 blended_normal = float3(0.0f, 0.0f, 0.0f);
    [unroll] for (int i = 0; i < PBR_TERRAIN_TEX_COUNT; i++)
    {
        float blend = blends[i];
        float4 normal_sample = tex2D(NormalMap[i], uv);
        blended_normal += normal_sample.rgb * blend;
        gloss += normal_sample.a * blend * ((spec[i] > 0.0f) ? 1.0f : 0.0f);
        spec_exponent += spec[i] * blend;
    }

    gloss = saturate(gloss);
    return ExpandNormal(blended_normal);
}

float3 SunLighting(float3 light_dir, float3 sun_color, float3 view_dir, float3 normal, float3 ambient_color, float3 albedo, float gloss, float gloss_power, float roughness, float parallax_multiplier)
{
    float3 light_color = sun_color * PbrLightMultiplier() * parallax_multiplier;
    float3 ambient = ambient_color * PbrAmbientMultiplier() * albedo;

    if (TerrainPbrEnabled())
    {
        return max(float3(0.0f, 0.0f, 0.0f), PbrSun(roughness, albedo, normal, view_dir, light_dir, light_color) + ambient);
    }

    return VanillaDirect(light_dir, 1.0f, sun_color, view_dir, normal, albedo, gloss, gloss_power) + ambient;
}

float3 PointLighting(float3 light_dir, float attenuation, float3 light_color, float3 view_dir, float3 normal, float3 albedo, float gloss, float gloss_power, float roughness)
{
    if (TerrainPbrEnabled())
    {
        return max(float3(0.0f, 0.0f, 0.0f), PbrDirect(roughness, albedo, normal, view_dir, light_dir, light_color * PbrLightMultiplier()) * attenuation);
    }

    return VanillaDirect(light_dir, attenuation, light_color, view_dir, normal, albedo, gloss, gloss_power);
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
    float height_status[7] = {
        LandHeight[0].x,
        LandHeight[0].y,
        LandHeight[0].z,
        LandHeight[0].w,
        LandHeight[1].x,
        LandHeight[1].y,
        LandHeight[1].z
    };
    float weights[7] = { 0, 0, 0, 0, 0, 0, 0 };
    float distance_to_eye = length(input.eye_position - input.local_position);
    float2 terrain_dx = ddx(input.uv.xy);
    float2 terrain_dy = ddy(input.uv.xy);
    float2 terrain_uv = TerrainParallaxCoords(
        distance_to_eye,
        input.uv.xy,
        terrain_dx,
        terrain_dy,
        view_dir,
        blends,
        height_status,
        weights
    );

    float gloss = 0.0f;
    float spec_exponent = 0.0f;
    float3 albedo = BlendDiffuseMaps(input.vertex_color, terrain_uv, weights);
    albedo = lerp(Luma(albedo), albedo, PbrAlbedoSaturation());
    float3 normal = BlendNormalMaps(terrain_uv, weights, spec, gloss, spec_exponent);
    float roughness = RoughnessFromGloss(gloss);

    float3 light_ts = mul(tbn, SunDir.xyz);
    float parallax_shadow = TerrainParallaxShadow(distance_to_eye, terrain_uv, terrain_dx, terrain_dy, light_ts, blends, height_status);
    float3 lighting = SunLighting(light_ts, SunColor.rgb, view_dir, normal, AmbientColor.rgb, albedo, gloss, spec_exponent, roughness, parallax_shadow);

#if PBR_TERRAIN_POINT_LIGHTS > 0
    int point_count = min((int)PointLightCount, PBR_TERRAIN_POINT_LIGHTS);
    [loop] for (int point_index = 0; point_index < point_count; point_index++)
    {
        float3 light_vector = PointLightPosition[point_index].xyz - input.local_position;
        float attenuation = VanillaAtt(light_vector, PointLightPosition[point_index].w);
        [branch] if (attenuation > 0.001f)
        {
            lighting += PointLighting(
                mul(tbn, light_vector),
                attenuation,
                PointLightColor[point_index].rgb,
                view_dir,
                normal,
                albedo,
                gloss,
                spec_exponent,
                roughness
            );
        }
    }
#endif

    float3 fog_position = input.projection_position.xyz;
    fog_position.z = input.projection_position.w - input.projection_position.z;
    float fog_strength = 1.0f - saturate((FogParam.x - length(fog_position)) / FogParam.y);
    float fog_alpha = pow(fog_strength, FogParam.z);

    output.color_0.rgb = lerp(max(lighting, float3(0.0f, 0.0f, 0.0f)), FogColor.rgb, fog_alpha);
    output.color_0.a = 1.0f;
    return output;
}
