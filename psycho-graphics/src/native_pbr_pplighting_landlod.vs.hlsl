struct VertexInput
{
    float4 position : POSITION;
    float4 uv : TEXCOORD0;
    float geomorph_height : TEXCOORD1;
};

struct VertexOutput
{
    float4 fog_color : COLOR1;
    float4 position : POSITION;
    float2 uv : TEXCOORD0;
    float3 light_dir : TEXCOORD1;
    float3 local_position : TEXCOORD2;
    float3 eye_position : TEXCOORD3;
};

row_major float4x4 ModelViewProj : register(c0);
row_major float4x4 ObjToCubeSpace : register(c8);

float4 HighDetailRange : register(c12);
float4 FogParam : register(c14);
float3 FogColor : register(c15);
float4 EyePosition : register(c16);
float4 LODLandParams : register(c19);
float4 LightData : register(c25);

float RangeMask(float4 cube_row, float4 position, float center, float half_extent)
{
    return (abs(dot(cube_row, position) - center) < half_extent) ? 1.0f : 0.0f;
}

VertexOutput Main(VertexInput input)
{
    VertexOutput output;

    float4 geomorph_position = input.position;
    geomorph_position.z = lerp(input.geomorph_height, input.position.z, LODLandParams.x);

    float x_mask = RangeMask(ObjToCubeSpace[0], geomorph_position, HighDetailRange.x, HighDetailRange.z);
    float y_mask = RangeMask(ObjToCubeSpace[1], geomorph_position, HighDetailRange.y, HighDetailRange.w);

    float4 local_position = input.position;
    local_position.z = geomorph_position.z - ((x_mask * y_mask) * LODLandParams.y);

    float4 clip_position = mul(ModelViewProj, local_position);
    float3 fog_position = clip_position.xyz;
    fog_position.z = clip_position.w - fog_position.z;

    float fog_strength = 1.0f - saturate((FogParam.x - length(fog_position)) / FogParam.y);

    output.position = clip_position;
    output.fog_color.rgb = FogColor.rgb;
    output.fog_color.a = pow(fog_strength, FogParam.z);
    output.uv = input.uv.xy;
    output.light_dir = LightData.xyz;
    output.local_position = local_position.xyz;
    output.eye_position = EyePosition.xyz;

    return output;
}
