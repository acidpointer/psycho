float4 AmbientColor : register(c1);
float4 LightControl : register(c2);
float4 PSLightColor[10] : register(c3);
float4 PSLightPosition[8] : register(c19);
float4 Toggles : register(c27);
float4 TESR_PBRData : register(c32);
float4 TESR_PBRExtraData : register(c33);

sampler2D BaseMap : register(s0);
sampler2D NormalMap : register(s1);

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
    float4 light4 : TEXCOORD5;
};

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

float3 PbrDiffuse(float3 albedo, float3 normal, float3 view_dir, float3 light_dir, float3 light_color)
{
    float3 reflectance = float3(0.04f, 0.04f, 0.04f);

    normal = SafeNormalize(normal, float3(0.0f, 0.0f, 1.0f));
    view_dir = SafeNormalize(view_dir, float3(0.0f, 0.0f, 1.0f));
    light_dir = SafeNormalize(light_dir, float3(0.0f, 0.0f, 1.0f));

    float3 halfway = SafeNormalize(view_dir + light_dir, normal);
    float ndotl = Shades(normal, light_dir);
    float ldoth = Shades(light_dir, halfway);
    float3 fresnel = Fresnel(reflectance, float3(1.0f, 1.0f, 1.0f), ldoth);
    float3 diffuse = LambertianDiffuse(albedo, fresnel);

    return diffuse * ndotl * light_color * PI;
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

float3 PointLight(float3 light_vector, float attenuation, float3 light_color, float3 view_dir, float3 normal, float3 albedo)
{
    return attenuation * PbrDiffuse(albedo, normal, view_dir, light_vector, light_color * PbrLightMultiplier());
}

float4 Main(PixelInput input) : COLOR0
{
    float4 base_color = tex2D(BaseMap, input.uv.xy);

    if (AmbientColor.a < 1.0f) {
        clip(base_color.a - Toggles.w);
    }

    float3 albedo = (Toggles.x <= 0.0f)
        ? base_color.rgb
        : base_color.rgb * saturate(input.vertex_color.rgb);
    albedo = lerp(Luma(albedo), albedo, PbrAlbedoSaturation());

    float3 normal = DecodeNormal(tex2D(NormalMap, input.uv.xy));
    float3 view_dir = float3(input.light_dir.w, input.light2.w, input.light3.w);

    float3 lighting = PbrDiffuse(
        albedo,
        normal,
        view_dir,
        input.light_dir.xyz,
        PSLightColor[0].rgb * PbrLightMultiplier()
    );

    float lights_used = LightControl.a;
    float att = VanillaAtt(PSLightPosition[0].xyz - input.local_position.xyz, PSLightPosition[0].w);
    lighting += (lights_used > 1.0f ? 1.0f : 0.0f) * PointLight(input.light2.xyz, att, PSLightColor[1].rgb, view_dir, normal, albedo);

    att = VanillaAtt(PSLightPosition[1].xyz - input.local_position.xyz, PSLightPosition[1].w);
    lighting += (lights_used >= 2.0f ? 1.0f : 0.0f) * PointLight(input.light3.xyz, att, PSLightColor[2].rgb, view_dir, normal, albedo);

    att = VanillaAtt(PSLightPosition[2].xyz - input.local_position.xyz, PSLightPosition[2].w);
    lighting += (lights_used >= 3.0f ? 1.0f : 0.0f) * PointLight(input.light4.xyz, att, PSLightColor[3].rgb, view_dir, normal, albedo);

    lighting += AmbientLighting(AmbientColor.rgb, albedo);

    float3 final_color = (Toggles.y <= 0.0f)
        ? lighting
        : lerp(lighting, input.fog_color.rgb, saturate(input.fog_color.a));

    return float4(final_color, base_color.a * AmbientColor.a);
}
