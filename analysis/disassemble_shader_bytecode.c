#include <d3dx9shader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint32_t read_u32(const unsigned char *bytes)
{
	return (uint32_t)bytes[0]
		| ((uint32_t)bytes[1] << 8)
		| ((uint32_t)bytes[2] << 16)
		| ((uint32_t)bytes[3] << 24);
}

static unsigned char *read_file(const char *path, size_t *size)
{
	FILE *file = fopen(path, "rb");
	if (file == NULL)
		return NULL;

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return NULL;
	}
	long length = ftell(file);
	if (length < 8 || fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return NULL;
	}

	unsigned char *bytes = malloc((size_t)length);
	if (bytes == NULL || fread(bytes, 1, (size_t)length, file) != (size_t)length) {
		free(bytes);
		fclose(file);
		return NULL;
	}

	fclose(file);
	*size = (size_t)length;
	return bytes;
}

static int is_shader_version(uint32_t version)
{
	uint32_t stage = version & 0xffff0000u;
	return stage == 0xffff0000u || stage == 0xfffe0000u;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s shader.cso\n", argv[0]);
		return 2;
	}

	size_t bytecode_size = 0;
	unsigned char *bytecode = read_file(argv[1], &bytecode_size);
	if (bytecode == NULL) {
		fprintf(stderr, "cannot read %s\n", argv[1]);
		return 1;
	}
	if (bytecode_size % sizeof(uint32_t) != 0 || !is_shader_version(read_u32(bytecode))) {
		fprintf(stderr, "%s is not valid D3D9 shader bytecode\n", argv[1]);
		free(bytecode);
		return 1;
	}

	ID3DXBuffer *assembly = NULL;
	HRESULT result = D3DXDisassembleShader((const DWORD *)bytecode, FALSE, NULL, &assembly);
	if (FAILED(result) || assembly == NULL) {
		fprintf(stderr, "D3DXDisassembleShader failed: 0x%08lx\n", result);
		free(bytecode);
		return 1;
	}

	fwrite(
		assembly->lpVtbl->GetBufferPointer(assembly),
		1,
		assembly->lpVtbl->GetBufferSize(assembly),
		stdout);
	assembly->lpVtbl->Release(assembly);
	free(bytecode);
	return 0;
}
