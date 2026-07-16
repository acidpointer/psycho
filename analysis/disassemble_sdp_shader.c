#include <d3dx9shader.h>
#include <direct.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECORD_NAME_SIZE 256

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
	if (file == NULL) {
		fprintf(stderr, "cannot open %s\n", path);
		return NULL;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return NULL;
	}
	long length = ftell(file);
	if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
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

static int has_shader_extension(const char *name)
{
	size_t length = strlen(name);
	if (length < 5)
		return 0;

	const char *extension = name + length - 4;
	return _stricmp(extension, ".pso") == 0 || _stricmp(extension, ".vso") == 0;
}

static int is_safe_record_name(const unsigned char *record, size_t available)
{
	size_t length = 0;
	while (length < RECORD_NAME_SIZE && length < available && record[length] != 0) {
		unsigned char value = record[length];
		if (value < 0x21 || value > 0x7e || value == '/' || value == '\\' || value == ':')
			return 0;
		++length;
	}

	if (length == 0 || length >= RECORD_NAME_SIZE || length >= available)
		return 0;
	return has_shader_extension((const char *)record);
}

static int is_shader_version(uint32_t version)
{
	uint32_t stage = version & 0xffff0000u;
	return stage == 0xffff0000u || stage == 0xfffe0000u;
}

static int create_directory(const char *path)
{
	if (_mkdir(path) == 0 || errno == EEXIST)
		return 0;
	fprintf(stderr, "cannot create output directory %s\n", path);
	return 1;
}

static int write_disassembly(
	const char *output_directory,
	const char *source_name,
	const char *output_name,
	const unsigned char *bytecode,
	uint32_t bytecode_size)
{
	ID3DXBuffer *assembly = NULL;
	HRESULT result = D3DXDisassembleShader((const DWORD *)bytecode, FALSE, NULL, &assembly);
	if (FAILED(result) || assembly == NULL) {
		fprintf(stderr, "D3DXDisassembleShader failed for %s: 0x%08lx\n", source_name, result);
		return 1;
	}

	char path[MAX_PATH * 4];
	int path_length = snprintf(path, sizeof(path), "%s\\%s", output_directory, output_name);
	if (path_length < 0 || (size_t)path_length >= sizeof(path)) {
		fprintf(stderr, "output path is too long for %s\n", source_name);
		assembly->lpVtbl->Release(assembly);
		return 1;
	}

	FILE *output = fopen(path, "wb");
	if (output == NULL) {
		fprintf(stderr, "cannot create %s\n", path);
		assembly->lpVtbl->Release(assembly);
		return 1;
	}

	fprintf(output, "; Source record: %s\n", source_name);
	fprintf(output, "; Bytecode size: %lu bytes\n\n", (unsigned long)bytecode_size);
	fwrite(
		assembly->lpVtbl->GetBufferPointer(assembly),
		1,
		assembly->lpVtbl->GetBufferSize(assembly),
		output);
	fclose(output);
	assembly->lpVtbl->Release(assembly);
	return 0;
}

static int find_seen_name(char **names, unsigned int count, const char *name)
{
	for (unsigned int index = 0; index < count; ++index) {
		if (strcmp(names[index], name) == 0)
			return (int)index;
	}
	return -1;
}

static int disassemble_package(
	const unsigned char *package,
	size_t package_size,
	const char *output_directory)
{
	if (create_directory(output_directory) != 0)
		return 1;

	char manifest_path[MAX_PATH * 4];
	int manifest_path_length = snprintf(
		manifest_path,
		sizeof(manifest_path),
		"%s\\_manifest.tsv",
		output_directory);
	if (manifest_path_length < 0 || (size_t)manifest_path_length >= sizeof(manifest_path))
		return 1;

	FILE *manifest = fopen(manifest_path, "wb");
	if (manifest == NULL) {
		fprintf(stderr, "cannot create %s\n", manifest_path);
		return 1;
	}
	fprintf(
		manifest,
		"name\tstage\tmodel\tbytecode_bytes\tpackage_offset\toutput_file\n");

	unsigned int shader_count = 0;
	unsigned int error_count = 0;
	char *seen_names[2048] = {0};
	unsigned int seen_counts[2048] = {0};
	unsigned int seen_name_count = 0;
	for (size_t offset = 0; offset + RECORD_NAME_SIZE + 8 <= package_size; ++offset) {
		const unsigned char *record = package + offset;
		if (!is_safe_record_name(record, package_size - offset))
			continue;

		const unsigned char *length_field = record + RECORD_NAME_SIZE;
		uint32_t bytecode_size = read_u32(length_field);
		if (bytecode_size < 8 || bytecode_size % 4 != 0)
			continue;
		if (offset + RECORD_NAME_SIZE + 4 + bytecode_size > package_size)
			continue;

		const unsigned char *bytecode = length_field + 4;
		uint32_t version = read_u32(bytecode);
		if (!is_shader_version(version))
			continue;

		const char *name = (const char *)record;
		const char *stage = (version & 0xffff0000u) == 0xffff0000u ? "pixel" : "vertex";
		unsigned int major = (version >> 8) & 0xffu;
		unsigned int minor = version & 0xffu;
		int seen_index = find_seen_name(seen_names, seen_name_count, name);
		if (seen_index < 0) {
			if (seen_name_count >= sizeof(seen_names) / sizeof(seen_names[0])) {
				fprintf(stderr, "too many shader names in package\n");
				++error_count;
				break;
			}
			seen_names[seen_name_count] = _strdup(name);
			if (seen_names[seen_name_count] == NULL) {
				++error_count;
				break;
			}
			seen_index = (int)seen_name_count;
			++seen_name_count;
		}

		unsigned int occurrence = seen_counts[seen_index]++;
		char output_name[RECORD_NAME_SIZE + 80];
		if (occurrence == 0) {
			snprintf(output_name, sizeof(output_name), "%s.dis", name);
		} else {
			snprintf(
				output_name,
				sizeof(output_name),
				"%s.duplicate_%u.offset_%08lx.dis",
				name,
				occurrence + 1,
				(unsigned long)offset);
		}
		fprintf(
			manifest,
			"%s\t%s\t%u_%u\t%lu\t%lu\t%s\n",
			name,
			stage,
			major,
			minor,
			(unsigned long)bytecode_size,
			(unsigned long)offset,
			output_name);

		error_count += write_disassembly(
			output_directory,
			name,
			output_name,
			bytecode,
			bytecode_size);
		++shader_count;
		offset += RECORD_NAME_SIZE + 3 + bytecode_size;
	}

	for (unsigned int index = 0; index < seen_name_count; ++index)
		free(seen_names[index]);
	fclose(manifest);
	printf("shaders=%u errors=%u output=%s\n", shader_count, error_count, output_directory);
	return error_count == 0 && shader_count != 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s shaderpackage.sdp output-directory\n", argv[0]);
		return 2;
	}

	size_t package_size = 0;
	unsigned char *package = read_file(argv[1], &package_size);
	if (package == NULL) {
		fprintf(stderr, "cannot read shader package\n");
		return 1;
	}

	int status = disassemble_package(package, package_size, argv[2]);
	free(package);
	return status;
}
