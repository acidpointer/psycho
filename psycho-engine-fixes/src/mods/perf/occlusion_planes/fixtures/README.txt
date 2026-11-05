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

rockwasteland07.bin and nvdlc02_cliff_mural.bin contain complete uncompressed
geometry blocks parsed by the strict NIF audit reader. Their input format is
the same as woodshack_blackvoid.bin. These are physical installed asset blocks,
not runtime placements, material-admission captures or proven profile winners.

rockwasteland07: DC Geology/meshes/landscape/rocks/rockwasteland07.nif,
NiTriStripsData block 9 at offset 8774, 305 vertices and 959 decoded triangles.
Source NIF SHA-256:
1253aeb03b80c955d0f689915eb77d6b42ad26fbfa0788e2e33d8976d548cb0e

nvdlc02_cliff_mural: MAC-10/meshes/nvdlc02/landscape/cliffs/
nvdlc02zcliff06bsmural.nif, NiTriStripsData block 26 at offset 384814,
495 vertices and 1091 decoded triangles. Source NIF SHA-256:
52d0f59f1f30f22517e54015204de3e09e2bfdcf8dfd932d14840218cdfc6ad4

Both complete blocks produce no legacy rectangles at identity placement.
Their offline viewpoints are defined from their actual AABBs; they do not
reconstruct a cell. Stencil-side parameters test geometry policy, not the
unavailable runtime material state.

orientation_cases.bin stores u32 count followed by count records of twelve
binary32 coordinates and one signed orientation byte. Its 101 cases use the
first 32 rockwasteland07 triangles with source-vertex and AABB-derived camera
points, plus explicit finite extreme/subnormal coordinate substitutions.
Expected signs were independently computed with Python Fraction from the
stored IEEE coordinates, using det(a-d,b-d,c-d). This exercises both the small
certified binary64 filter and full fixed-width integer fallback; it is not an engine
visibility or rendering oracle. Extraction and raw provenance are retained in
.reports/20261105-occlusion-plan/.
