// SMAA 1x blend-weight pass adapted from the MIT-licensed SMAA reference implementation.
// OMV uses a fixed four-pixel search and private color targets instead of stencil.

sampler2D Edges : register(s0);
float4 ScreenData : register(c0);
float4 Options1 : register(c4);

float2 SampleEdges(float2 uv) {
    return tex2Dlod(Edges, float4(uv, 0.0, 0.0)).rg;
}

float4 Main(float2 uv : TEXCOORD0) : COLOR0 {
    float2 t = ScreenData.zw;
    float2 edge = SampleEdges(uv);
    float4 weights = 0.0;

    [branch] if (edge.r > 0.0) {
        float2 span = 0.0;
        float2 open = 1.0;
        float2 pair = float2(SampleEdges(uv + float2(0.0, -t.y)).r,
                             SampleEdges(uv + float2(0.0, t.y)).r);
        open *= step(0.5, pair);
        span += open;
        pair = float2(SampleEdges(uv + float2(0.0, -2.0 * t.y)).r,
                      SampleEdges(uv + float2(0.0, 2.0 * t.y)).r);
        open *= step(0.5, pair);
        span += open;
        pair = float2(SampleEdges(uv + float2(0.0, -3.0 * t.y)).r,
                      SampleEdges(uv + float2(0.0, 3.0 * t.y)).r);
        open *= step(0.5, pair);
        span += open;
        pair = float2(SampleEdges(uv + float2(0.0, -4.0 * t.y)).r,
                      SampleEdges(uv + float2(0.0, 4.0 * t.y)).r);
        open *= step(0.5, pair);
        span += open;
        weights.rg = (span.yx + 0.5) / (span.x + span.y + 2.0);
    }
    [branch] if (edge.g > 0.0) {
        float2 span = 0.0;
        float2 open = 1.0;
        float2 pair = float2(SampleEdges(uv + float2(-t.x, 0.0)).g,
                             SampleEdges(uv + float2(t.x, 0.0)).g);
        open *= step(0.5, pair);
        span += open;
        pair = float2(SampleEdges(uv + float2(-2.0 * t.x, 0.0)).g,
                      SampleEdges(uv + float2(2.0 * t.x, 0.0)).g);
        open *= step(0.5, pair);
        span += open;
        pair = float2(SampleEdges(uv + float2(-3.0 * t.x, 0.0)).g,
                      SampleEdges(uv + float2(3.0 * t.x, 0.0)).g);
        open *= step(0.5, pair);
        span += open;
        pair = float2(SampleEdges(uv + float2(-4.0 * t.x, 0.0)).g,
                      SampleEdges(uv + float2(4.0 * t.x, 0.0)).g);
        open *= step(0.5, pair);
        span += open;
        weights.ba = (span.yx + 0.5) / (span.x + span.y + 2.0);
    }
    float corner = 1.0 - saturate(Options1.x / 100.0) * 0.5;
    return weights * corner;
}
