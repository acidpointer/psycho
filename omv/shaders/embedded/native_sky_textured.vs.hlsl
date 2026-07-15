row_major float4x4 ModelViewProjection : register(c0);
float4 BlendColor[3] : register(c4);
#if OMV_CLOUD_VERTEX
float TexCoordYOff : register(c12);
#endif

struct VertexInput {
    float4 position : POSITION;
    float4 uv : TEXCOORD0;
#if OMV_CLOUD_VERTEX
    float3 tangent : TANGENT;
    float3 binormal : BINORMAL;
    float3 normal : NORMAL;
#endif
    float4 color : COLOR0;
};

struct VertexOutput {
    float4 position : POSITION;
    float2 uv : TEXCOORD0;
    float2 blendUv : TEXCOORD1;
    float3 location : TEXCOORD2;
    float4 color : COLOR0;
    float4 kind : COLOR1;
};

VertexOutput Main(VertexInput input) {
    VertexOutput output;
    output.color.rgb = input.color.r * BlendColor[0].rgb + input.color.g * BlendColor[1].rgb + input.color.b * BlendColor[2].rgb;
    output.color.a = BlendColor[0].a * input.color.a;

#if OMV_CLOUD_VERTEX
    output.location = input.position.xyz;
    input.position.z -= 5.0;
    output.position = mul(ModelViewProjection, input.position).xyww;
#if OMV_REVERSED_DEPTH
    output.position.z *= 0.000100017;
#else
    output.position.z *= 0.999899983;
#endif
    output.uv = float2(input.uv.x, input.uv.y + TexCoordYOff);
    output.blendUv = output.uv;
    output.kind = float4(0.0, 1.0, 0.0, 1.0);
#elif OMV_MOON_MASK_VERTEX
    output.position = mul(ModelViewProjection, input.position).xyww;
#if OMV_REVERSED_DEPTH
    output.position.z *= 0.000050008;
#else
    output.position.z *= 0.999949992;
#endif
    output.uv = input.uv.xy;
    output.blendUv = input.uv.xy;
    output.location = input.position.xyz;
    output.kind = float4(0.0, 0.0, 1.0, 1.0);
#else
    output.position = mul(ModelViewProjection, input.position).xyww;
#if OMV_REVERSED_DEPTH
    output.position.z *= 0.000100017;
#else
    output.position.z *= 0.999899983;
#endif
    output.uv = input.uv.xy;
    output.blendUv = input.uv.xy;
    output.location = output.position.xyz;
    output.kind = float4(1.0, 0.0, 0.0, 1.0);
#endif
    return output;
}
