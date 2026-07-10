// Transform a position based on bones.
float3 BonesTransformPosition(float4 bones[54], float4 offset, float4 blend, float4 pos) {
    float3 result, helper;
    
    helper.x = dot(bones[offset.x].xyzw, pos.xyzw);
    helper.y = dot(bones[offset.x + 1].xyzw, pos.xyzw);
    helper.z = dot(bones[offset.x + 2].xyzw, pos.xyzw);
    result.xyz = helper.xyz * blend.x;
    
    helper.x = dot(bones[offset.y].xyzw, pos.xyzw);
    helper.y = dot(bones[offset.y + 1].xyzw, pos.xyzw);
    helper.z = dot(bones[offset.y + 2].xyzw, pos.xyzw);
    result.xyz += helper.xyz * blend.y;
    
    helper.x = dot(bones[offset.z].xyzw, pos.xyzw);
    helper.y = dot(bones[offset.z + 1].xyzw, pos.xyzw);
    helper.z = dot(bones[offset.z + 2].xyzw, pos.xyzw);
    result.xyz += helper.xyz * blend.z;
    
    helper.x = dot(bones[offset.w].xyzw, pos.xyzw);
    helper.y = dot(bones[offset.w + 1].xyzw, pos.xyzw);
    helper.z = dot(bones[offset.w + 2].xyzw, pos.xyzw);
    result.xyz += helper.xyz * blend.w;
    
    return result;
}

// Transform a vector based on bones.
float3 BonesTransformVector(float4 bones[54], float4 offset, float4 blend, float3 vec) {
    float3 result, helper;
    
    helper.x = dot(bones[offset.x].xyz, vec.xyz);
    helper.y = dot(bones[offset.x + 1].xyz, vec.xyz);
    helper.z = dot(bones[offset.x + 2].xyz, vec.xyz);
    result.xyz = helper.xyz * blend.x;
    
    helper.x = dot(bones[offset.y].xyz, vec.xyz);
    helper.y = dot(bones[offset.y + 1].xyz, vec.xyz);
    helper.z = dot(bones[offset.y + 2].xyz, vec.xyz);
    result.xyz += helper.xyz * blend.y;
    
    helper.x = dot(bones[offset.z].xyz, vec.xyz);
    helper.y = dot(bones[offset.z + 1].xyz, vec.xyz);
    helper.z = dot(bones[offset.z + 2].xyz, vec.xyz);
    result.xyz += helper.xyz * blend.z;
    
    helper.x = dot(bones[offset.w].xyz, vec.xyz);
    helper.y = dot(bones[offset.w + 1].xyz, vec.xyz);
    helper.z = dot(bones[offset.w + 2].xyz, vec.xyz);
    result.xyz += helper.xyz * blend.w;
    
    return result;
}

// Transform TBN with bones.
float3x3 BonesTransformTBN(float4 bones[54], float4 offset, float4 blend, float3 tangent, float3 binormal, float3 normal) {
    return float3x3(
        normalize(BonesTransformVector(bones, offset, blend, tangent)),
        normalize(BonesTransformVector(bones, offset, blend, binormal)),
        normalize(BonesTransformVector(bones, offset, blend, normal))
    );
}