// OMV temporal AA depth rejection key. World alpha remains engine-owned.

sampler2D SceneDepth : register(s0);

float4 CameraData : register(c0);

bool ReversedDepth() {
    return CameraData.z > 0.5;
}

bool ValidDepth(float depth) {
    return ReversedDepth() ? depth > 0.000001 && depth <= 1.0 : depth > 0.000001 && depth < 0.999999;
}

float LinearDepth(float depth) {
    float nearZ = max(CameraData.x, 0.01);
    float farZ = max(CameraData.y, nearZ + 1.0);
    if (ReversedDepth()) {
        return nearZ * farZ / max(depth * (farZ - nearZ) + nearZ, 0.001);
    }
    return nearZ * farZ / max(farZ - depth * (farZ - nearZ), 0.001);
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float rawDepth = tex2Dlod(SceneDepth, float4(uv, 0.0, 0.0)).r;
    float farZ = max(CameraData.y, max(CameraData.x, 0.01) + 1.0);
    float linearDepth = ValidDepth(rawDepth) ? LinearDepth(rawDepth) : farZ;
    float key = saturate(log2(linearDepth + 1.0) / max(log2(farZ + 1.0), 0.001));
    return float4(key, 0.0, 0.0, 1.0);
}
