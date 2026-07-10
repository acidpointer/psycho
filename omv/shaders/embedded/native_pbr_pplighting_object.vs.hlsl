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

#ifndef PBR_OBJECT_SKIN
#define PBR_OBJECT_SKIN 0
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
#if PBR_OBJECT_SKIN
    float3 blend_weight : BLENDWEIGHT;
    float4 blend_indices : BLENDINDICES;
#endif
};

#if PBR_OBJECT_SKIN
row_major float4x4 SkinModelViewProj : register(c1);
float4 Bones[54] : register(c44);
#else
row_major float4x4 ModelViewProj : register(c0);
#endif
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

#if PBR_OBJECT_SKIN
float SkinWeight(float3 value)
{
    return value.x + value.y + value.z;
}

float3 SkinPosition(float4 offset, float4 blend, float4 position)
{
    float3 result = 0.0f;
    float3 helper = 0.0f;

    helper.x = dot(Bones[offset.x], position);
    helper.y = dot(Bones[offset.x + 1], position);
    helper.z = dot(Bones[offset.x + 2], position);
    result += helper * blend.x;

    helper.x = dot(Bones[offset.y], position);
    helper.y = dot(Bones[offset.y + 1], position);
    helper.z = dot(Bones[offset.y + 2], position);
    result += helper * blend.y;

    helper.x = dot(Bones[offset.z], position);
    helper.y = dot(Bones[offset.z + 1], position);
    helper.z = dot(Bones[offset.z + 2], position);
    result += helper * blend.z;

    helper.x = dot(Bones[offset.w], position);
    helper.y = dot(Bones[offset.w + 1], position);
    helper.z = dot(Bones[offset.w + 2], position);
    result += helper * blend.w;

    return result;
}

float3 SkinVector(float4 offset, float4 blend, float3 value)
{
    float3 result = 0.0f;
    float3 helper = 0.0f;

    helper.x = dot(Bones[offset.x].xyz, value);
    helper.y = dot(Bones[offset.x + 1].xyz, value);
    helper.z = dot(Bones[offset.x + 2].xyz, value);
    result += helper * blend.x;

    helper.x = dot(Bones[offset.y].xyz, value);
    helper.y = dot(Bones[offset.y + 1].xyz, value);
    helper.z = dot(Bones[offset.y + 2].xyz, value);
    result += helper * blend.y;

    helper.x = dot(Bones[offset.z].xyz, value);
    helper.y = dot(Bones[offset.z + 1].xyz, value);
    helper.z = dot(Bones[offset.z + 2].xyz, value);
    result += helper * blend.z;

    helper.x = dot(Bones[offset.w].xyz, value);
    helper.y = dot(Bones[offset.w + 1].xyz, value);
    helper.z = dot(Bones[offset.w + 2].xyz, value);
    result += helper * blend.w;

    return result;
}

float3x3 SkinTangentBasis(float4 offset, float4 blend, VertexInput input)
{
    return float3x3(
        normalize(SkinVector(offset, blend, input.tangent)),
        normalize(SkinVector(offset, blend, input.binormal)),
        normalize(SkinVector(offset, blend, input.normal))
    );
}
#endif

void ResolveObjectVertex(VertexInput input, out float4 position, out float3x3 tbn, out float4 clip_position)
{
    position = input.position;
#if PBR_OBJECT_SKIN
    float4 offset = input.blend_indices.zyxw * 765.01001f;
    float4 blend = input.blend_weight.xyzz;
    blend.w = 1.0f - SkinWeight(input.blend_weight);
    tbn = SkinTangentBasis(offset, blend, input);
    position.w = 1.0f;
    position.xyz = SkinPosition(offset, blend, position);
    clip_position = mul(SkinModelViewProj, position);
#else
    tbn = TangentBasis(input);
    clip_position = mul(ModelViewProj, position);
#endif
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
    float4 position;
    float3x3 tbn;
    float4 clip_position;
    ResolveObjectVertex(input, position, tbn, clip_position);

    output.position = clip_position;
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
    float4 position;
    float3x3 tbn;
    float4 clip_position;
    ResolveObjectVertex(input, position, tbn, clip_position);
    float3 view_dir = mul(tbn, EyePosition.xyz - position.xyz);
    float lights = PbrHighLightCount();
    float used = 0.0f;

    output.position = clip_position;
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
