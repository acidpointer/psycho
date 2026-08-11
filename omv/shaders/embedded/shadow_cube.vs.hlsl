// Adapted from New Vegas Reloaded's ShadowCubeMap.vso.hlsl (GPL-3.0-or-later).
row_major float4x4 ShadowWorld : register(c0);
row_major float4x4 ShadowViewProjection : register(c4);
float4 GeometryData : register(c8);
float4 BoneRows[54] : register(c9);
float4 LightPositionRadius : register(c63);

struct VertexInput {
    float4 position : POSITION;
    float4 uv0 : TEXCOORD0;
    float4 blendWeight : BLENDWEIGHT;
    float4 blendIndices : BLENDINDICES;
};

struct VertexOutput {
    float4 position : POSITION;
    float3 lightVector : TEXCOORD0;
    float2 uv : TEXCOORD1;
};

float3 SkinPosition(VertexInput input) {
    float4 indices = input.blendIndices.zyxw * 765.01001f;
    float4 position = float4(input.position.xyz, 1.0f);
    float3 result = 0.0f;
    float4 weights = float4(input.blendWeight.xyz, 1.0f - dot(input.blendWeight.xyz, 1.0f));
    for (int influence = 0; influence < 4; ++influence) {
        int base = indices[influence];
        result += float3(
            dot(BoneRows[base + 0], position),
            dot(BoneRows[base + 1], position),
            dot(BoneRows[base + 2], position)) * weights[influence];
    }
    return result;
}

VertexOutput Main(VertexInput input) {
    VertexOutput output;
    float4 world = GeometryData.x == 1.0f
        ? float4(SkinPosition(input), 1.0f)
        : mul(input.position, ShadowWorld);
    output.position = mul(world, ShadowViewProjection);
    output.lightVector = LightPositionRadius.xyz - world.xyz;
    output.uv = input.uv0.xy;
    return output;
}
