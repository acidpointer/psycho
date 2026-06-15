#ifndef PBR_OBJECT_LOW
#define PBR_OBJECT_LOW 0
#endif

#ifndef PBR_OBJECT_HIGH
#define PBR_OBJECT_HIGH 0
#endif

#ifndef PBR_OBJECT_LIGHTS
#define PBR_OBJECT_LIGHTS 1
#endif

#ifndef PBR_OBJECT_OPT
#define PBR_OBJECT_OPT 0
#endif

#ifndef PBR_OBJECT_SHADOW
#define PBR_OBJECT_SHADOW 0
#endif

#ifndef PBR_OBJECT_SPECULAR
#define PBR_OBJECT_SPECULAR 0
#endif

float4 AmbientColor : register(c1);
float4 PSLightColor[10] : register(c3);
float4 TESR_PBRData : register(c32);
float4 TESR_PBRExtraData : register(c33);

sampler2D BaseMap : register(s0);
sampler2D NormalMap : register(s1);

#if PBR_OBJECT_HIGH
float4 PSLightPosition[8] : register(c19);
#if PBR_OBJECT_OPT
#define PbrObjectLightsUsed PSLightColor[0].a
#define PbrObjectLightOffset 1
#else
float4 EmittanceColor : register(c2);
float4 Toggles : register(c27);
#define PbrObjectLightsUsed EmittanceColor.a
#define PbrObjectLightOffset 0
#endif
#else
#if !PBR_OBJECT_OPT
float4 Toggles : register(c27);
#endif
#if PBR_OBJECT_SHADOW
sampler2D ShadowMap : register(s6);
sampler2D ShadowMaskMap : register(s7);
#endif
#endif

#if PBR_OBJECT_LOW
struct PixelInput
{
    float3 vertex_color : COLOR0;
    float4 fog_color : COLOR1;
    float2 uv : TEXCOORD0;
    float4 light_dir : TEXCOORD1;
#if PBR_OBJECT_LIGHTS > 1
    float4 light2_dir : TEXCOORD2;
#endif
#if PBR_OBJECT_LIGHTS > 2
    float4 light3_dir : TEXCOORD3;
#endif
    float3 view_dir : TEXCOORD6;
#if PBR_OBJECT_SHADOW
    float4 shadow_uvs : TEXCOORD7;
#endif
};
#endif

#if PBR_OBJECT_HIGH
struct PixelInput
{
    float4 vertex_color : COLOR0;
    float4 fog_color : COLOR1;
    float4 screen_position : POSITION;
    float2 uv : TEXCOORD0;
    float4 local_position : TEXCOORD1;
    float4 light_dir : TEXCOORD2;
    float4 light2 : TEXCOORD3;
    float4 light3 : TEXCOORD4;
#if PBR_OBJECT_LIGHTS > 3
    float4 light4 : TEXCOORD5;
#endif
#if PBR_OBJECT_LIGHTS > 4
    float4 light5 : TEXCOORD6;
    float4 light6 : TEXCOORD7;
#endif
};
#endif

static const float PI = 3.14159265f;

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

float PbrMetallicness()
{
    return saturate(TESR_PBRData.x);
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

float3 PbrDiffuseOnly(float3 albedo, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
{
    float3 reflectance = float3(0.04f, 0.04f, 0.04f);

    normal = SafeNormalize(normal, float3(0.0f, 0.0f, 1.0f));
    view_dir = SafeNormalize(view_dir, float3(0.0f, 0.0f, 1.0f));
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));

    float3 halfway = SafeNormalize(view_dir + light_dir, normal);
    float ndotl = Shades(normal, light_dir);
    float ldoth = Shades(light_dir, halfway);
    float3 fresnel = Fresnel(reflectance, float3(1.0f, 1.0f, 1.0f), ldoth);
    return LambertianDiffuse(albedo, fresnel) * ndotl * light_color * PI;
}

float3 PbrFull(float roughness, float3 albedo, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
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

float3 PbrDirect(float roughness, float3 albedo, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
{
#if PBR_OBJECT_SPECULAR
    return PbrFull(roughness, albedo, normal, view_dir, light_dir, light_color);
#else
    return PbrDiffuseOnly(albedo, normal, view_dir, light_dir, light_color);
#endif
}

float VanillaAtt(float3 light_vector, float radius)
{
    float safe_radius = max(radius, 0.001f);
    float3 att = light_vector / safe_radius;
    return saturate(1.0f - Shades(att, att));
}

float3 AmbientLighting(float3 ambient, float3 albedo)
{
    return ambient * PbrAmbientMultiplier() * albedo;
}

float3 PointLight(float3 light_vector, float radius, float3 light_color, float3 view_dir, float3 normal, float3 albedo, float roughness)
{
    float att = VanillaAtt(light_vector, radius);
    return att * PbrDirect(roughness, albedo, normal, view_dir, light_vector, light_color * PbrLightMultiplier());
}

float3 PointLightAtt(float3 light_vector, float att, float3 light_color, float3 view_dir, float3 normal, float3 albedo, float roughness)
{
    return att * PbrDirect(roughness, albedo, normal, view_dir, light_vector, light_color * PbrLightMultiplier());
}

float3 ObjectAlbedo(float4 base_color, float3 vertex_color)
{
#if PBR_OBJECT_OPT
    float3 albedo = base_color.rgb * saturate(vertex_color.rgb);
#else
    float3 albedo = (Toggles.x <= 0.0f)
        ? base_color.rgb
        : base_color.rgb * saturate(vertex_color.rgb);
#endif
    return lerp(Luma(albedo), albedo, PbrAlbedoSaturation());
}

float3 ShadowMultiplier(PixelInput input)
{
#if PBR_OBJECT_SHADOW
    float3 shadow = tex2D(ShadowMap, input.shadow_uvs.xy).rgb;
    float shadow_mask = tex2D(ShadowMaskMap, input.shadow_uvs.zw).x;
    return lerp(float3(1.0f, 1.0f, 1.0f), shadow, shadow_mask);
#else
    return float3(1.0f, 1.0f, 1.0f);
#endif
}

float4 Main(PixelInput input) : COLOR0
{
    float4 base_color = tex2D(BaseMap, input.uv.xy);

#if !PBR_OBJECT_OPT
    if (AmbientColor.a < 1.0f) {
        clip(base_color.a - Toggles.w);
    }
#endif

    float3 albedo = ObjectAlbedo(base_color, input.vertex_color.rgb);
    float4 normal_sample = tex2D(NormalMap, input.uv.xy);
    float3 normal = DecodeNormal(normal_sample);
    float roughness = RoughnessFromGloss(normal_sample.a);

#if PBR_OBJECT_LOW
    float3 view_dir = input.view_dir.xyz;
    float3 lighting = PbrDirect(
        roughness,
        albedo,
        normal,
        view_dir,
        input.light_dir.xyz,
        PSLightColor[0].rgb * ShadowMultiplier(input) * PbrLightMultiplier()
    );

#if PBR_OBJECT_LIGHTS > 1
    lighting += PointLight(input.light2_dir.xyz, input.light2_dir.w, PSLightColor[1].rgb, view_dir, normal, albedo, roughness);
#endif

#if PBR_OBJECT_LIGHTS > 2
    lighting += PointLight(input.light3_dir.xyz, input.light3_dir.w, PSLightColor[2].rgb, view_dir, normal, albedo, roughness);
#endif
#endif

#if PBR_OBJECT_HIGH
    float3 view_dir = float3(input.light_dir.w, input.light2.w, input.light3.w);

#if PBR_OBJECT_OPT
    float att = VanillaAtt(PSLightPosition[0].xyz - input.local_position.xyz, PSLightPosition[0].w);
    float3 lighting = PointLightAtt(input.light_dir.xyz, att, PSLightColor[0].rgb, view_dir, normal, albedo, roughness);
#else
    float att = 0.0f;
    float3 lighting = PbrDirect(
        roughness,
        albedo,
        normal,
        view_dir,
        input.light_dir.xyz,
        PSLightColor[0].rgb * PbrLightMultiplier()
    );
#endif

    float lights_used = PbrObjectLightsUsed;

    if (lights_used > 1.0f) {
        att = VanillaAtt(PSLightPosition[PbrObjectLightOffset + 0].xyz - input.local_position.xyz, PSLightPosition[PbrObjectLightOffset + 0].w);
        lighting += PointLightAtt(input.light2.xyz, att, PSLightColor[1].rgb, view_dir, normal, albedo, roughness);
    }

    if (lights_used >= 2.0f) {
        att = VanillaAtt(PSLightPosition[PbrObjectLightOffset + 1].xyz - input.local_position.xyz, PSLightPosition[PbrObjectLightOffset + 1].w);
        lighting += PointLightAtt(input.light3.xyz, att, PSLightColor[2].rgb, view_dir, normal, albedo, roughness);
    }

#if PBR_OBJECT_LIGHTS > 3
    if (lights_used >= 3.0f) {
        att = VanillaAtt(PSLightPosition[PbrObjectLightOffset + 2].xyz - input.local_position.xyz, PSLightPosition[PbrObjectLightOffset + 2].w);
        lighting += PointLightAtt(input.light4.xyz, att, PSLightColor[3].rgb, view_dir, normal, albedo, roughness);
    }
#endif

#if PBR_OBJECT_LIGHTS > 4
    if (lights_used >= 4.0f) {
        att = VanillaAtt(PSLightPosition[3].xyz - input.local_position.xyz, PSLightPosition[3].w);
        lighting += PointLightAtt(input.light5.xyz, att, PSLightColor[4].rgb, view_dir, normal, albedo, roughness);
    }

    if (lights_used >= 5.0f) {
        att = VanillaAtt(PSLightPosition[4].xyz - input.local_position.xyz, PSLightPosition[4].w);
        lighting += PointLightAtt(input.light6.xyz, att, PSLightColor[5].rgb, view_dir, normal, albedo, roughness);
    }
#endif
#endif

    lighting += AmbientLighting(AmbientColor.rgb, albedo);

#if PBR_OBJECT_OPT
    float3 final_color = lerp(lighting, input.fog_color.rgb, saturate(input.fog_color.a));
#else
    float3 final_color = (Toggles.y <= 0.0f)
        ? lighting
        : lerp(lighting, input.fog_color.rgb, saturate(input.fog_color.a));
#endif

    return float4(final_color, base_color.a * AmbientColor.a);
}
