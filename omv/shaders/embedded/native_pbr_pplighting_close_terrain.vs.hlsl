struct VertexInput
{
    float4 position : POSITION;
    float3 tangent : TANGENT;
    float3 binormal : BINORMAL;
    float3 normal : NORMAL;
    float4 uv : TEXCOORD0;
    float4 vertex_color : COLOR0;
    float4 blend_0 : TEXCOORD1;
    float4 blend_1 : TEXCOORD2;
};

struct VertexOutput
{
    float4 blend_0 : COLOR0;
    float4 blend_1 : COLOR1;
    float4 position : POSITION;
    float2 uv : TEXCOORD0;
    float3 vertex_color : TEXCOORD1;
    float3 local_position : TEXCOORD2;
    float3 tangent : TEXCOORD3;
    float3 binormal : TEXCOORD4;
    float3 normal : TEXCOORD5;
    float4 projection_position : TEXCOORD6;
    float3 eye_position : TEXCOORD7;
};

row_major float4x4 ModelViewProj : register(c0);
float4 EyePosition : register(c16);

VertexOutput Main(VertexInput input)
{
    VertexOutput output;

    float4 clip_position = mul(ModelViewProj, input.position);

    output.blend_0 = input.blend_0;
    output.blend_1 = input.blend_1;
    output.position = clip_position;
    output.uv = input.uv.xy;
    output.vertex_color = saturate(input.vertex_color.rgb);
    output.local_position = input.position.xyz;
    output.tangent = input.tangent;
    output.binormal = input.binormal;
    output.normal = input.normal;
    output.projection_position = clip_position;
    output.eye_position = EyePosition.xyz;

    return output;
}
