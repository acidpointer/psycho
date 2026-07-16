# Fallout New Vegas Shader Disassembly

This directory contains instruction-level D3D9 assembly extracted from every
installed `Data/Shaders/shaderpackage*.sdp` file. Each package has its own
directory because shader names repeat across quality packages and their
bytecode is not always identical.

Archive summary:

- 16 shader packages
- 15,791 shader records
- 8,160 pixel shaders
- 7,631 vertex shaders
- shader models 1.1, 2.0, 2.1, and 3.0
- 156 duplicate-named records retained with occurrence and package-offset
  suffixes

Each package contains `_manifest.tsv` with the source record name, stage,
shader model, bytecode size, original package offset, and generated output
file. The manifest record count exactly matches the number of `.dis` files.

## Regeneration

Build the extractor as a 32-bit Windows executable:

```sh
i686-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 \
  analysis/disassemble_sdp_shader.c \
  -o /tmp/disassemble_sdp_shader.exe \
  -ld3dx9
```

Run that executable under Wine once per package. It accepts two arguments:

```text
disassemble_sdp_shader.exe shaderpackage.sdp output-directory
```

The extractor validates the fixed 256-byte SDP record name, bytecode length,
and D3D vertex/pixel version token before asking `D3DXDisassembleShader` to
produce assembly. It does not modify the source packages.

## PBR object starting points

The active high-quality package is represented by `shaderpackage019`. Useful
combined-specular object pairs include:

- `SLS2012.vso` / `SLS2017.pso`
- `SLS2016.vso` / `SLS2023.pso`
- `SLS2025.vso` / `SLS2034.pso`
- `SLS2026.vso` / `SLS2035.pso`

Do not assume another package is identical. The manifests and disassemblies
are retained for every installed package so cross-package contracts can be
checked directly.
