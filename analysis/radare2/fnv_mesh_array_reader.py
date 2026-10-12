"""Read installed BSA/NIF data for the Fairfax submission audit; never write assets.

Only BSA 103/104 and Bethesda NIF 20.2.0.7/user 11/BS 34 are admitted.
Unsupported versions and incomplete blocks fail explicitly. Field layouts follow
niftools/nifskope lib/fsengine/bsa.{h,cpp} and niftools/nifxml nif.xml,
retrieved 2026-10-12. This is an asset reader, not an engine behavioral test.

Format authorities:
https://raw.githubusercontent.com/niftools/nifxml/master/nif.xml
https://raw.githubusercontent.com/niftools/nifskope/develop/lib/fsengine/bsa.cpp

The target set is the retained nine-cell top-STAT model list. The configured
Default modlist supplies physical search sources; it does not establish the
reported run's profile or winning overrides. Each physical variant is emitted
separately. Unsupported indexes remain explicit in the output.
"""

import collections
import json
import mmap
import os
import pathlib
import struct
import zlib


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, size):
        assert size >= 0 and self.pos + size <= len(self.data)
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def integer(self, fmt):
        return struct.unpack('<' + fmt, self.take(struct.calcsize('<' + fmt)))[0]

    def string(self, fmt='I'):
        return self.take(self.integer(fmt)).decode('latin1').rstrip('\0')


class Archive:
    def __init__(self, path):
        self.path = path
        self.file = path.open('rb')
        self.data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        r = Reader(self.data)
        assert r.take(4) == b'BSA\0'
        self.version = r.integer('I')
        assert self.version in (103, 104), (str(path), self.version)
        offset, self.flags, folders, files, folder_names, file_names, _ = struct.unpack('<7I', r.take(28))
        assert self.flags & 3 == 3
        r.pos = offset
        folder_records = [struct.unpack('<QII', r.take(16)) for _ in range(folders)]
        names_start = offset + folder_names + folders * 17 + files * 16
        names = Reader(self.data[names_start:names_start + file_names])
        assert len(names.data) == file_names
        self.entries = {}
        count = 0
        for _, num_files, _ in folder_records:
            folder = r.string('B').replace('\\', '/').lower()
            for _ in range(num_files):
                _, size, address = struct.unpack('<QII', r.take(16))
                end = names.data.find(b'\0', names.pos)
                assert end >= names.pos
                name = names.take(end - names.pos + 1)[:-1].decode('latin1').lower()
                key = folder + '/' + name
                assert key not in self.entries
                assert address + (size & 0x3fffffff) <= len(self.data)
                self.entries[key] = (size, address)
                count += 1
        assert count == files and r.pos == names_start, (
            str(path), count, files, names.pos, file_names, r.pos, names_start)
        # The installed voice archive pads its declared filename table with zeros.
        # Every declared file name has already been consumed; nonzero tails fail.
        assert not any(names.data[names.pos:]), (str(path), 'filename table tail')
        self.filename_padding = file_names - names.pos

    def read(self, key):
        flags, address = self.entries[key]
        r = Reader(self.data[address:address + (flags & 0x3fffffff)])
        if self.version == 104 and self.flags & 0x100:
            r.take(r.integer('B'))
        data = r.take(len(r.data) - r.pos)
        if bool(flags & 0xc0000000) != bool(self.flags & 4):
            expected = struct.unpack_from('<I', data)[0]
            compressed = zlib.decompressobj()
            data = compressed.decompress(data[4:]) + compressed.flush()
            assert compressed.eof and not compressed.unused_data and len(data) == expected
        return data


def geometry_data(data, kind):
    r = Reader(data)
    group = r.integer('i')
    vertices = r.integer('H')
    keep, compress, has_vertices = r.take(3)
    assert has_vertices in (0, 1)
    if has_vertices:
        r.take(vertices * 12)
    flags = r.integer('H')
    normals = r.integer('B')
    assert normals in (0, 1)
    if normals:
        r.take(vertices * 12 * (3 if flags & 4096 else 1))
    r.take(16)  # NiBound: center and radius.
    colors = r.integer('B')
    assert colors in (0, 1)
    if colors:
        r.take(vertices * 16)
    r.take((flags & 1) * vertices * 8)
    consistency = r.integer('H')
    additional = r.integer('i')
    triangles = r.integer('H')
    result = dict(type=kind, vertices=vertices, triangles=triangles,
                  consistency=hex(consistency), additional=additional,
                  group=group, keep=keep, compress=compress)
    if kind == 'NiTriStripsData':
        arrays = r.integer('H')
        lengths = [r.integer('H') for _ in range(arrays)]
        present = r.integer('B')
        assert present in (0, 1)
        points = [[r.integer('H') for _ in range(n)] for n in lengths] if present else []
        assert all(p < vertices for strip in points for p in strip)
        result.update(arrays=arrays, lengths=lengths, has_points=present,
                      points=sum(lengths), invalid_short_arrays=sum(n < 3 for n in lengths))
    else:
        num_points = r.integer('I')
        present = r.integer('B')
        assert present in (0, 1) and num_points == triangles * 3
        if present:
            points = [r.integer('H') for _ in range(num_points)]
            assert all(p < vertices for p in points)
        matches = r.integer('H')
        for _ in range(matches):
            r.take(r.integer('H') * 2)
        result.update(arrays=1, has_points=present, points=num_points, match_groups=matches)
    assert r.pos == len(data), (kind, r.pos, len(data))
    return result


def object_net(r):
    name = r.integer('i')
    extra = [r.integer('i') for _ in range(r.integer('I'))]
    controller = r.integer('i')
    return dict(name_index=name, extra=extra, controller=controller)


def property_data(data, kind):
    r = Reader(data)
    result = dict(type=kind, **object_net(r))
    if kind == 'NiAlphaProperty':
        flags = r.integer('H')
        result.update(flags=hex(flags), blend=bool(flags & 1),
                      test=bool(flags & 0x200), threshold=r.integer('B'))
    else:
        result['shade_flags'] = r.integer('H')
        result['shader_type'] = r.integer('I')
        result['flags'] = hex(r.integer('I'))
        result['flags2'] = hex(r.integer('I'))
        result['environment_scale'] = r.integer('f')
        result['clamp'] = r.integer('I')
        result['textures'] = r.integer('i')
        result['refraction'] = r.integer('f')
        result['refraction_period'] = r.integer('i')
        result['parallax_passes'] = r.integer('f')
        result['parallax_scale'] = r.integer('f')
    assert r.pos == len(data), (kind, r.pos, len(data))
    return result


def geometry_object(data, kind):
    r = Reader(data)
    result = dict(type=kind, **object_net(r))
    result['flags'] = hex(r.integer('I'))
    r.take(12 + 36 + 4)  # Translation, rotation, uniform scale.
    result['properties'] = [r.integer('i') for _ in range(r.integer('I'))]
    result['collision'] = r.integer('i')
    result['data'] = r.integer('i')
    result['skin'] = r.integer('i')
    materials = r.integer('I')
    r.take(materials * 8)
    result['active_material'] = r.integer('i')
    result['material_update'] = r.integer('B')
    assert r.pos == len(data), (kind, r.pos, len(data))
    return result


def nif(data):
    r = Reader(data)
    end = data.index(b'\n') + 1
    header = r.take(end).decode('ascii').strip()
    version = r.integer('I')
    endian = r.integer('B')
    user = r.integer('I')
    count = r.integer('I')
    bs = r.integer('I')
    assert version == 0x14020007 and endian == 1 and user == 11 and bs == 34, (header, user, bs)
    for _ in range(3):
        r.string('B')
    types = [r.string() for _ in range(r.integer('H'))]
    indices = [r.integer('H') for _ in range(count)]
    assert all(i < len(types) for i in indices)
    sizes = [r.integer('I') for _ in range(count)]
    strings = r.integer('I')
    maximum = r.integer('I')
    for _ in range(strings):
        text = r.string()
        assert len(text) <= maximum
    for _ in range(r.integer('I')):
        r.integer('I')
    blocks = []
    properties = []
    geometries = []
    for block_id, (i, size) in enumerate(zip(indices, sizes)):
        block = r.take(size)
        if types[i] in ('NiTriStripsData', 'NiTriShapeData'):
            blocks.append(dict(block=block_id, **geometry_data(block, types[i])))
        elif types[i] in ('NiAlphaProperty', 'BSShaderPPLightingProperty'):
            properties.append(dict(block=block_id, **property_data(block, types[i])))
        elif types[i] in ('NiTriStrips', 'NiTriShape'):
            geometries.append(dict(block=block_id, **geometry_object(block, types[i])))
    roots = [r.integer('i') for _ in range(r.integer('I'))]
    assert all(0 <= i < count for i in roots) and r.pos == len(data)
    return dict(version=header, user=user, bs=bs,
                types=dict(collections.Counter(types[i] for i in indices)),
                geometry=blocks, objects=geometries, properties=properties)


def main():
    root = pathlib.Path('/data/storage0/Games/FalloutNV_TTW')
    enabled = [line[1:] for line in
               (root / 'profiles/Default/modlist.txt').read_text().splitlines()
               if line.startswith('+')]
    sources = [root / 'mods' / name for name in enabled]
    sources += [root / 'overwrite', root / 'FalloutNV/Data']
    raw = pathlib.Path('analysis/radare2/output/fnv_fairfax_record_population_20261012.txt').read_text()
    models = set()
    for line in raw.splitlines():
        if line.startswith('{'):
            row = json.loads(line)
            for item in row.get('top_static_models', []):
                models.add('meshes/' + item['model'].replace('\\', '/').lower())
    found = set()
    archive_paths = set()
    for source in sources:
        if not source.is_dir():
            continue
        for directory, _, names in os.walk(source):
            parent = pathlib.Path(directory)
            for name in names:
                path = parent / name
                if name.lower().endswith('.bsa'):
                    archive_paths.add(path)
                model = path.relative_to(source).as_posix().lower()
                if model in models:
                    found.add(model)
                    print(json.dumps(dict(model=model, loose=str(path),
                                          **nif(path.read_bytes())), sort_keys=True))
    for path in sorted(archive_paths):
        try:
            archive = Archive(path)
        except AssertionError as error:
            print(json.dumps(dict(archive_index=str(path), unsupported=repr(error)), sort_keys=True))
            continue
        selected = sorted(models.intersection(archive.entries))
        print(json.dumps(dict(archive_index=str(path), version=archive.version,
                              filename_padding=archive.filename_padding,
                              entries=len(archive.entries), matched=len(selected)), sort_keys=True))
        for model in selected:
            found.add(model)
            print(json.dumps(dict(model=model, archive=str(path),
                                  **nif(archive.read(model))), sort_keys=True))
        archive.data.close()
        archive.file.close()
    print(json.dumps(dict(summary=True, enabled_mods=len(enabled), models=len(models),
                          archives=len(archive_paths), missing=sorted(models - found)), sort_keys=True))


if __name__ == '__main__':
    main()
