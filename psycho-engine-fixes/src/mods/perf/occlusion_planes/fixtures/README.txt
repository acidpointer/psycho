Actual archived occlusion regression inputs

woodshack_blackvoid.bin contains the complete BlackVoid block from
WoodShack01.NIF: 28 vertices and 49 decoded strip triangles, including the
zero-area [23,23,23] connector. Format: little-endian u32 vertex count, f32 xyz
per vertex, u32 triangle count, u16 abc per triangle. The original extraction
verified every vertex/index byte against the source block. This asset was the
local profile winner, not a reconstructed crash-time VFS capture.
Provenance: .reports/20261021-generator-surface-audit/asset-input.json.

pre_surface_correction.cache is the actual version-9 plane cache archived with
the October 21 invisible-terrain incident. Its own signature is used to test
rejection by generation revision, independent of plugin-signature mismatch.
Provenance: .reports/20261021-invisible-terrain-crash/inputs.json.

Neither fixture proves native object lifetime or crash recovery.
