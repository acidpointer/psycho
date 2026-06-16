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

#ifndef PBR_OBJECT_ONLY_LIGHT
#define PBR_OBJECT_ONLY_LIGHT 0
#endif

#ifndef PBR_OBJECT_DIFFUSE
#define PBR_OBJECT_DIFFUSE 0
#endif

#ifndef PBR_OBJECT_POINT
#define PBR_OBJECT_POINT 0
#endif

struct VertexInput
{
    float4 position : POSITION;
    float3 tangent : TANGENT;
    float3 binormal : BINORMAL;
    float3 normal : NORMAL;
    float4 uv : TEXCOORD0;
#if !PBR_OBJECT_ONLY_LIGHT
    float4 vertex_color : COLOR0;
#endif
};

row_major float4x4 ModelViewProj : register(c0);
float4 LightData[10] : register(c25);
float4 EyePosition : register(c16);

#if !PBR_OBJECT_ONLY_LIGHT
float3 FogColor : register(c15);
float4 FogParam : register(c14);
#endif

#if PBR_OBJECT_SHADOW
row_major float4x4 ShadowProj : register(c18);
float4 ShadowProjData : register(c22);
float4 ShadowProjTransform : register(c23);
#endif

#if PBR_OBJECT_HIGH && !PBR_OBJECT_OPT
float4 fvars0 : register(c17);
#endif

float3x3 TangentBasis(VertexInput input)
{
    return float3x3(input.tangent.xyz, input.binormal.xyz, input.normal.xyz);
}

#if !PBR_OBJECT_ONLY_LIGHT
float4 FogColorOut(float4 screen_position)
{
    float3 fog_position = screen_position.xyz;
    fog_position.z = screen_position.w - fog_position.z;
    float fog_strength = 1.0f - saturate((FogParam.x - length(fog_position)) / FogParam.y);
    fog_strength = log2(fog_strength);
    return float4(FogColor.rgb, exp2(fog_strength * FogParam.z));
}
#endif

#if PBR_OBJECT_LOW

struct VertexOutput
{
#if !PBR_OBJECT_ONLY_LIGHT
    float4 vertex_color : COLOR0;
    float4 fog_color : COLOR1;
#endif
    float4 position : POSITION;
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

VertexOutput Main(VertexInput input)
{
    VertexOutput output;
    float4 position = input.position;
    float3x3 tbn = TangentBasis(input);

    output.position = mul(ModelViewProj, position);
    output.uv = input.uv.xy;

#if PBR_OBJECT_DIFFUSE || PBR_OBJECT_POINT
    float3 light = LightData[0].xyz - position.xyz;
#else
    float3 light = LightData[0].xyz;
#endif
    output.light_dir.xyz = mul(tbn, light);
    output.light_dir.w = LightData[0].w;
    output.view_dir.xyz = mul(tbn, EyePosition.xyz - position.xyz);

#if PBR_OBJECT_LIGHTS > 1
    light = LightData[1].xyz - position.xyz;
    output.light2_dir.xyz = mul(tbn, light);
    output.light2_dir.w = LightData[1].w;
#endif

#if PBR_OBJECT_LIGHTS > 2
    light = LightData[2].xyz - position.xyz;
    output.light3_dir.xyz = mul(tbn, light);
    output.light3_dir.w = LightData[2].w;
#endif

#if !PBR_OBJECT_ONLY_LIGHT
    output.vertex_color = clamp(input.vertex_color, 0.0f, 1.0f);
    output.fog_color = FogColorOut(output.position);
#endif

#if PBR_OBJECT_SHADOW
    float shadow_param = dot(ShadowProj[3], position);
    float2 shadow_uv;
    shadow_uv.x = dot(ShadowProj[0], position);
    shadow_uv.y = dot(ShadowProj[1], position);
    output.shadow_uvs.xy =
        ((shadow_param * ShadowProjTransform.xy) + shadow_uv) /
        (shadow_param * ShadowProjTransform.w);
    output.shadow_uvs.zw =
        ((shadow_uv.xy - ShadowProjData.xy) / ShadowProjData.w) * float2(1.0f, -1.0f) +
        float2(0.0f, 1.0f);
#endif

    return output;
}

#endif

#if PBR_OBJECT_HIGH

struct VertexOutput
{
    float4 vertex_color : COLOR0;
    float4 fog_color : COLOR1;
    float4 position : POSITION;
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

float PbrHighLightCount()
{
#if PBR_OBJECT_OPT && PBR_OBJECT_SPECULAR
    return min((float)PBR_OBJECT_LIGHTS, EyePosition.w);
#elif PBR_OBJECT_OPT
    return min((float)PBR_OBJECT_LIGHTS, LightData[0].w);
#else
    return min((float)PBR_OBJECT_LIGHTS, fvars0.z);
#endif
}

float LightUsed(float light_index, float light_count)
{
    float lights_frac = frac(light_count);
    float lights_threshold =
        (light_count < 0.0f ? (-lights_frac < lights_frac ? 1.0f : 0.0f) : 0.0f) +
        (light_count - lights_frac);
    return (light_index < lights_threshold) ? 1.0f : 0.0f;
}

VertexOutput Main(VertexInput input)
{
    VertexOutput output;
    float4 position = input.position;
    float3x3 tbn = TangentBasis(input);
    float3 view_dir = mul(tbn, EyePosition.xyz - position.xyz);
    float lights = PbrHighLightCount();
    float used = 0.0f;

    output.position = mul(ModelViewProj, position);
    output.uv = input.uv.xy;
    output.local_position.xyz = position.xyz;
    output.local_position.w = LightData[0].w;

#if PBR_OBJECT_OPT
    used = LightUsed(0.0f, lights);
    output.light_dir.xyz = used * mul(tbn, LightData[1].xyz - position.xyz);
#else
    output.light_dir.xyz = mul(tbn, LightData[0].xyz);
#endif
    output.light_dir.w = view_dir.x;

#if PBR_OBJECT_OPT
    used = LightUsed(1.0f, lights);
    output.light2.xyz = used * mul(tbn, LightData[2].xyz - position.xyz);
#else
    used = LightUsed(1.0f, lights);
    output.light2.xyz = used * mul(tbn, LightData[1].xyz - position.xyz);
#endif
    output.light2.w = view_dir.y;

#if PBR_OBJECT_OPT
    used = LightUsed(2.0f, lights);
    output.light3.xyz = used * mul(tbn, LightData[3].xyz - position.xyz);
#else
    used = LightUsed(2.0f, lights);
    output.light3.xyz = used * mul(tbn, LightData[2].xyz - position.xyz);
#endif
    output.light3.w = view_dir.z;

#if PBR_OBJECT_LIGHTS > 3
#if PBR_OBJECT_OPT
    used = LightUsed(3.0f, lights);
    output.light4.xyz = used * mul(tbn, LightData[4].xyz - position.xyz);
    output.light4.w = used * LightData[4].w;
#else
    used = LightUsed(3.0f, lights);
    output.light4.xyz = used * mul(tbn, LightData[3].xyz - position.xyz);
    output.light4.w = used * LightData[3].w;
#endif
#endif

#if PBR_OBJECT_LIGHTS > 4
    used = LightUsed(4.0f, lights);
    output.light5.xyz = used * mul(tbn, LightData[4].xyz - position.xyz);
    output.light5.w = used * LightData[4].w;

    used = LightUsed(5.0f, lights);
    output.light6.xyz = used * mul(tbn, LightData[5].xyz - position.xyz);
    output.light6.w = used * LightData[5].w;
#endif

    output.vertex_color = clamp(input.vertex_color, 0.0f, 1.0f);
    output.fog_color = FogColorOut(output.position);

    return output;
}

#endif
