struct VertexInput
{
    float4 position : POSITION;
    float4 uv : TEXCOORD0;
};

struct VertexOutput
{
    float4 position : POSITION;
    float2 uv : TEXCOORD0;
    float3 light_dir : TEXCOORD3;
    float blend : TEXCOORD4;
    float4 fog_color : TEXCOORD5;
    float3 local_position : TEXCOORD6;
    float3 eye_position : TEXCOORD7;
};

row_major float4x4 ModelViewProj : register(c0);

float4 FogParam : register(c14);
float3 FogColor : register(c15);
float4 EyePosition : register(c16);
float4 LandBlendParams : register(c19);
float4 LightData : register(c25);

static const float UV_SCALE = 1.0f / 64.0f;
static const float UV_SCALE_QUANT = 127.0f / 128.0f;
static const float UV_OFFSET = 1.0f / 256.0f;
static const float BLEND_BASE_DISTANCE = 9625.59961f;
static const float BLEND_SCALE = 0.000375600968f;

VertexOutput Main(VertexInput input)
{
    VertexOutput output;

    float4 clip_position = mul(ModelViewProj, input.position);
    output.position = clip_position;

    float2 uv = (input.uv.xy * UV_SCALE) + LandBlendParams.xy;
    uv.x = 1.0f - uv.x;
    output.uv = (uv * UV_SCALE_QUANT) + UV_OFFSET;
    output.light_dir = LightData.xyz;

    float2 blend_vector = LandBlendParams.zw - input.position.xy;
    output.blend = 1.0f - saturate((BLEND_BASE_DISTANCE - length(blend_vector)) * BLEND_SCALE);

    float3 fog_position = clip_position.xyz;
    fog_position.z = clip_position.w - fog_position.z;
    float fog_strength = 1.0f - saturate((FogParam.x - length(fog_position)) / FogParam.y);
    output.fog_color.rgb = FogColor.rgb;
    output.fog_color.a = pow(fog_strength, FogParam.z);

    output.local_position = input.position.xyz;
    output.eye_position = EyePosition.xyz;

    return output;
}
