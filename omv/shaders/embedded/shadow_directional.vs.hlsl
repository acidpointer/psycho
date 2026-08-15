// Adapted from New Vegas Reloaded's ShadowMap.vso.hlsl (GPL-3.0-or-later).
row_major float4x4 ShadowWorld : register(c0);
row_major float4x4 ShadowViewProjection : register(c4);
float4 GeometryData : register(c8);
float4 BoneRows[54] : register(c9);
float4 SpeedTreeRows[77] : register(c63);
float4 TerrainRows[6] : register(c140);

#ifndef OMV_BLEND_INDEX_ENCODING
#define OMV_BLEND_INDEX_ENCODING 0
#endif

static const float GEOMETRY_SKINNED = 1.0f;
static const float GEOMETRY_SPEEDTREE = 2.0f;
static const float GEOMETRY_TERRAIN_LOD = 3.0f;
static const float TwoPi = 6.28318548f;

struct VertexInput {
    float4 position : POSITION;
    float4 uv0 : TEXCOORD0;
    float4 terrain : TEXCOORD1;
    float4 blendWeight : BLENDWEIGHT;
    float4 blendIndices : BLENDINDICES;
};

struct VertexOutput {
    float4 position : POSITION;
    float4 shadowPosition : TEXCOORD0;
    float2 uv : TEXCOORD1;
};

float3 SkinPosition(VertexInput input) {
#if OMV_BLEND_INDEX_ENCODING == 0
    // D3DCOLOR exposes packed bytes in BGRA order and normalizes them.
    float4 indices = input.blendIndices.zyxw * 765.01001f;
#elif OMV_BLEND_INDEX_ENCODING == 1
    // UBYTE4N preserves declaration order and normalizes each byte.
    float4 indices = input.blendIndices.xyzw * 765.01001f;
#else
    // Raw UBYTE4 values need only conversion from bone number to row offset.
    float4 indices = input.blendIndices.xyzw * 3.0f;
#endif
    float4 position = float4(input.position.xyz, 1.0f);
    float3 skinned0 = float3(
        dot(BoneRows[indices.x + 0], position),
        dot(BoneRows[indices.x + 1], position),
        dot(BoneRows[indices.x + 2], position));
    float3 skinned1 = float3(
        dot(BoneRows[indices.y + 0], position),
        dot(BoneRows[indices.y + 1], position),
        dot(BoneRows[indices.y + 2], position));
    float3 skinned2 = float3(
        dot(BoneRows[indices.z + 0], position),
        dot(BoneRows[indices.z + 1], position),
        dot(BoneRows[indices.z + 2], position));
    float3 skinned3 = float3(
        dot(BoneRows[indices.w + 0], position),
        dot(BoneRows[indices.w + 1], position),
        dot(BoneRows[indices.w + 2], position));
    float finalWeight = 1.0f - dot(input.blendWeight.xyz, 1.0f);
    return skinned0 * input.blendWeight.x
        + skinned1 * input.blendWeight.y
        + skinned2 * input.blendWeight.z
        + skinned3 * finalWeight;
}

void AnimationRotation(float4 parameters, float index, out float angleSin, out float angleCos) {
    float first = frac((index / 48.0f + parameters.y) * 0.499999583f + 0.5f);
    float second = frac(sin(first * TwoPi - 3.14159274f) * parameters.x
        * parameters.z * 0.159154937f + 0.5f);
    sincos(second * TwoPi - 3.14159274f, angleSin, angleCos);
}

float4 SpeedTreePosition(VertexInput input) {
    float4 billboardRight = SpeedTreeRows[0];
    float4 billboardUp = SpeedTreeRows[1];
    float4 rock = SpeedTreeRows[2];
    float4 rustle = SpeedTreeRows[3];
    float rustleSin;
    float rustleCos;
    AnimationRotation(rustle, input.blendIndices.z, rustleSin, rustleCos);
    float rockSin;
    float rockCos;
    AnimationRotation(rock, input.blendIndices.z, rockSin, rockCos);
    float2 matrixIndices = input.blendIndices.zy - frac(input.blendIndices.zy);
    float4 leaf = SpeedTreeRows[20 + matrixIndices.x] * input.blendIndices.w;
    float leafY = dot(float3(0.0f, rockCos, -rockSin), leaf.xyz);
    float leafZ = dot(float3(0.0f, rockSin, rockCos), leaf.xyz);
    float3 right = float3(
        dot(float3(rustleCos, -rustleSin, 0.0f), billboardRight.xyz),
        dot(float3(rustleSin, rustleCos, 0.0f), billboardRight.xyz),
        billboardRight.z);
    float3 up = float3(
        dot(float3(rustleCos, -rustleSin, 0.0f), billboardUp.xyz),
        dot(float3(rustleSin, rustleCos, 0.0f), billboardUp.xyz),
        billboardUp.z);
    float4 offsetPosition = float4(input.position.xyz + right * leafY + up * leafZ, input.position.w);
    int windIndex = 4 + (int)matrixIndices.y;
    float4 windPosition = float4(
        dot(SpeedTreeRows[windIndex + 0], offsetPosition),
        dot(SpeedTreeRows[windIndex + 1], offsetPosition),
        dot(SpeedTreeRows[windIndex + 2], offsetPosition),
        dot(SpeedTreeRows[windIndex + 3], offsetPosition));
    return lerp(offsetPosition, windPosition, input.blendIndices.x);
}

VertexOutput Main(VertexInput input) {
    VertexOutput output;
    float4 local = input.position;
    if (GeometryData.x == GEOMETRY_SKINNED) {
        local = float4(SkinPosition(input), 1.0f);
    } else if (GeometryData.x == GEOMETRY_SPEEDTREE) {
        local = SpeedTreePosition(input);
    } else if (GeometryData.x == GEOMETRY_TERRAIN_LOD) {
        float4 terrainPosition = local;
        terrainPosition.z = lerp(input.terrain.x, local.z, TerrainRows[5].x);
        float insideY = abs(dot(TerrainRows[1], terrainPosition) - TerrainRows[4].y) < TerrainRows[4].w;
        float insideX = abs(dot(TerrainRows[0], terrainPosition) - TerrainRows[4].x) < TerrainRows[4].z;
        // The visible terrain LOD consumes the geomorphed height. Applying the
        // loaded-cell drop to the original vertex instead projects a different
        // silhouette which deforms and flickers as the camera crosses the LOD
        // transition. This ordering is the exact NVR TerrainLODPass contract.
        local.z = terrainPosition.z - insideX * insideY * TerrainRows[5].y;
    }
    float4 world = GeometryData.x == GEOMETRY_SKINNED ? local : mul(local, ShadowWorld);
    float4 projected = mul(world, ShadowViewProjection);
    // Near-plane pancaking retains casters whose bounds cross the light near plane.
    projected.z = max(projected.z, 0.0f);
    output.position = projected;
    output.shadowPosition = projected;
    output.uv = input.uv0.xy;
    return output;
}
