"""Extract AI record evidence without retaining input filenames or metadata.

Read-only research utility, not an engine behavioral test. Inputs are explicit;
outputs contain public engine identifiers, exact record payloads, field deltas,
and executable initializer evidence. No plugin header text or paths are emitted.
Record layout authority: TES5Edit/TES5Edit Core/wbDefinitionsFNV.pas, CSTY/GMST.
Runtime field names: vendored xNVSE GameForms.h, TESCombatStyle.
Unsupported layouts fail rather than producing partial evidence.
"""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import struct
import zlib


def require(condition, message):
    if not condition:
        raise ValueError(message)


def subrecords(data):
    pos = 0
    extended = None
    result = {}
    while pos < len(data):
        require(pos + 6 <= len(data), "Truncated subrecord header")
        tag = data[pos:pos + 4].decode("ascii")
        size = struct.unpack_from("<H", data, pos + 4)[0]
        pos += 6
        if tag == "XXXX":
            require(size == 4 and extended is None, "Invalid extended size")
            extended = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            continue
        size = size if extended is None else extended
        extended = None
        require(pos + size <= len(data), "Truncated subrecord payload")
        result.setdefault(tag, []).append(data[pos:pos + size])
        pos += size
    require(extended is None, "Unconsumed extended size")
    return result


def one(subs, tag):
    values = subs.get(tag, [])
    require(len(values) == 1, "Missing or repeated " + tag)
    return values[0]


def read_records(path):
    data = path.read_bytes()
    counts = collections.Counter()
    groups = collections.Counter()
    retained = []

    def walk(start, end):
        while start < end:
            require(start + 24 <= end, "Truncated record header")
            tag = data[start:start + 4].decode("ascii")
            size, flags, form = struct.unpack_from("<III", data, start + 4)
            if tag == "GRUP":
                require(size >= 24 and start + size <= end, "Invalid group")
                group_type = struct.unpack_from("<I", data, start + 12)[0]
                label = data[start + 8:start + 12].decode("ascii") if group_type == 0 else "type:" + str(group_type)
                groups[label] += 1
                walk(start + 24, start + size)
                start += size
                continue
            require(start + 24 + size <= end, "Record crosses group boundary")
            counts[tag] += 1
            if tag in ("GMST", "CSTY", "TES4", "NPC_", "CREA"):
                payload = data[start + 24:start + 24 + size]
                if flags & 0x40000:
                    expected = struct.unpack_from("<I", payload)[0]
                    payload = zlib.decompress(payload[4:])
                    require(len(payload) == expected, "Decompressed size mismatch")
                retained.append((tag, form, start, flags, subrecords(payload)))
            start += 24 + size
        require(start == end, "Incorrect group end")

    walk(0, len(data))
    return data, counts, groups, retained


def style_schema():
    standard = [(0, "B", "dodgeChance"), (1, "B", "LRChance")]
    standard += [(4 + 4 * i, "f", name) for i, name in enumerate([
        "dodgeLRTimerMin", "dodgeLRTimerMax", "dodgeFWTimerMin",
        "dodgeFWTimerMax", "dodgeBKTimerMin", "dodgeBKTimerMax",
        "idleTimerMin", "idleTimerMax"])]
    standard += [(36, "B", "blockChance"), (37, "B", "attackChance")]
    standard += [(40 + 4 * i, "f", name) for i, name in enumerate([
        "staggerBonusToAttack", "KOBonusToAttack", "H2HBonusToAttack"])]
    standard += [(52, "B", "powerAttackChance"),
                 (56, "f", "staggerBonusToPower"), (60, "f", "KOBonusToPower")]
    standard += [(64 + i, "B", "powerAttack" + name)
                 for i, name in enumerate(["N", "F", "B", "L", "R"])]
    standard += [(72, "f", "holdTimerMin"), (76, "f", "holdTimerMax"),
                 (80, "H", "csFlags"), (84, "B", "acrobaticDodgeChance"),
                 (85, "B", "rushAttackChance"), (88, "f", "rushAttackDistMult")]
    advanced = [(4 * i, "f", name) for i, name in enumerate([
        "dodgeFatigueModMult", "dodgeFatigueModBase", "encumSpeedModBase",
        "encumSpeedModMult", "dodgeUnderAttackMult", "dodgeNotUnderAttackMult",
        "dodgeBackUnderAttackMult", "dodgeBackNotUnderAttackMult",
        "dodgeFWAttackingMult", "dodgeFWNotAttackingMult", "blockSkillModMult",
        "blockSkillModBase", "blockUnderAttackMult", "blockNotUnderAttackMult",
        "attackSkillModMult", "attackSkillModBase", "attackUnderAttackMult",
        "attackNotUnderAttackMult", "attackDuringBlockMult",
        "powerAttackFatigueModBase", "powerAttackFatigueModMult"])]
    simple = [(4 * i, "I" if i in (9, 10) else "f", name)
              for i, name in enumerate([
                  "coverSearchRadius", "takeCoverChance", "waitTimeMin",
                  "waitTimeMax", "waitToFireTimerMin", "waitToFireTimerMax",
                  "fireTimerMin", "fireTimerMax", "rangedWeapRangeMultMin",
                  "unused24", "weaponRestrictions", "rangedWeapRangeMultMax",
                  "maxTargetingFOV", "combatRadius", "semiAutoFiringDelayMultMin",
                  "semiAutoFiringDelayMultMax"])]
    return {"CSTD": (92, 0x58, standard), "CSAD": (84, 0xB4, advanced),
            "CSSD": (64, 0x18, simple)}


class Executable:
    def __init__(self, path):
        self.data = path.read_bytes()
        require(hashlib.sha256(self.data).hexdigest() ==
                "42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c",
                "Unsupported executable identity")
        pe = struct.unpack_from("<I", self.data, 60)[0]
        optional = struct.unpack_from("<H", self.data, pe + 20)[0]
        base = struct.unpack_from("<I", self.data, pe + 52)[0]
        self.sections = []
        for i in range(struct.unpack_from("<H", self.data, pe + 6)[0]):
            start = pe + 24 + optional + 40 * i
            _, rva, size, offset = struct.unpack_from("<IIII", self.data, start + 8)
            self.sections.append((offset, size, base + rva))

    def va(self, offset):
        return next(v + offset - p for p, n, v in self.sections if p <= offset < p + n)

    def read(self, address, size):
        offset = next(p + address - v for p, n, v in self.sections
                      if v <= address and address + size <= v + n)
        return self.data[offset:offset + size]

    def initializer(self, name):
        needle = name.encode("ascii") + b"\0"
        strings = []
        start = 0
        while (start := self.data.find(needle, start)) >= 0:
            strings.append(start)
            start += len(needle)
        if not strings:
            require(needle.lower() not in self.data.lower(),
                    "Setting name differs only in case; inspect before decoding")
            return {"status": "name absent from supported executable"}
        candidates = []
        for string in strings:
            push = b"\x68" + struct.pack("<I", self.va(string))
            start = 0
            while (start := self.data.find(push, start)) >= 0:
                ref = start
                start += len(push)
                # Admit only exact, directly observed setting initializer shapes.
                if self.data[ref + 5:ref + 6] != b"\xb9" or self.data[ref + 10:ref + 11] != b"\xe8":
                    continue
                const = None
                if name[0] == "f" and self.data[ref - 13:ref - 7] == b"\x55\x8b\xec\x51\xd9\x05" and self.data[ref - 3:ref] == b"\xd9\x1c\x24":
                    const = struct.unpack_from("<I", self.data, ref - 7)[0]
                    raw = self.read(const, 4)
                    first = ref - 13
                elif name[0] == "f" and self.data[ref - 9:ref] == b"\x55\x8b\xec\x51\xd9\xe8\xd9\x1c\x24":
                    raw = struct.pack("<f", 1)
                    first = ref - 9
                elif name[0] == "i" and self.data[ref - 5:ref - 1] == b"\x55\x8b\xec\x6a":
                    raw = struct.pack("<i", struct.unpack_from("<b", self.data, ref - 1)[0])
                    first = ref - 5
                else:
                    continue
                obj = struct.unpack_from("<I", self.data, ref + 6)[0]
                target = self.va(ref + 15) + struct.unpack_from("<i", self.data, ref + 11)[0]
                require(target == (0x40E0B0 if name[0] == "f" else 0x40C150),
                        "Unexpected setting constructor")
                candidates.append({"status": "decoded", "initializer": hex(self.va(first)),
                                   "name_address": hex(self.va(string)), "setting_object": hex(obj),
                                   "value_address": hex(obj + 4), "constructor": hex(target),
                                   "constant_address": hex(const) if const is not None else None,
                                   "bytes": self.data[first:ref + 15].hex(), "data_hex": raw.hex(),
                                   "value": struct.unpack("<i" if name[0] == "i" else "<f", raw)[0]})
        require(len(candidates) == 1, "Ambiguous or unsupported initializer for " + name)
        return candidates[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sample", "master", "exe", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    _, counts, groups, records = read_records(args.sample)
    require(set(counts) == {"TES4", "GMST", "CSTY"}, "Unexpected sample record types")
    master_data, master_counts, _, master = read_records(args.master)
    exe = Executable(args.exe)
    master_gm = {one(s, "EDID").rstrip(b"\0").decode("ascii"): (f, o, s)
                 for t, f, o, _, s in master if t == "GMST"}
    master_cs = {f: (o, s) for t, f, o, _, s in master if t == "CSTY"}
    settings = []
    styles = []
    direct_actors = collections.Counter()
    for tag, _, _, _, subs in master:
        if tag in ("NPC_", "CREA") and "ZNAM" in subs:
            direct_actors[struct.unpack("<I", one(subs, "ZNAM"))[0]] += 1
    for tag, form, offset, flags, subs in records:
        if tag == "TES4":
            continue
        require(tag in ("GMST", "CSTY"), "Unexpected sample record type")
        name = one(subs, "EDID").rstrip(b"\0").decode("ascii")
        if tag == "GMST":
            require(set(subs) == {"EDID", "DATA"}, "Unknown setting subrecord")
            raw = one(subs, "DATA")
            require(len(raw) == 4 and name[0] in "fi", "Unsupported setting type")
            init = exe.initializer(name)
            baseline = master_gm.get(name)
            old = one(baseline[2], "DATA") if baseline else bytes.fromhex(init["data_hex"]) if init["status"] == "decoded" else None
            fmt = "<i" if name[0] == "i" else "<f"
            settings.append({"name": name, "record_offset": hex(offset), "flags": hex(flags),
                             "data_hex": raw.hex(), "value": struct.unpack(fmt, raw)[0],
                             "baseline_kind": "base master" if baseline else "executable initializer" if old is not None else "unknown",
                             "baseline_offset": hex(baseline[1]) if baseline else None,
                             "baseline_data_hex": old.hex() if old is not None else None,
                             "baseline_value": struct.unpack(fmt, old)[0] if old is not None else None,
                             "changed": raw != old if old is not None else None, "engine": init})
        else:
            require(form in master_cs, "Style absent from baseline")
            require(set(subs) == {"EDID", "CSTD", "CSAD", "CSSD"}, "Unknown style subrecord")
            old_offset, old_subs = master_cs[form]
            require(one(old_subs, "EDID") == one(subs, "EDID"), "Style identity differs")
            blocks = {}
            for block, (size, runtime, fields) in style_schema().items():
                new, old = one(subs, block), one(old_subs, block)
                require(len(new) == len(old) == size, "Unsupported style block size")
                decoded = []
                covered = set()
                for pos, fmt, field in fields:
                    width = struct.calcsize("<" + fmt)
                    covered.update(range(pos, pos + width))
                    decoded.append({"field": field, "offset": pos, "runtime_offset": hex(runtime + pos),
                                    "type": fmt, "baseline": struct.unpack_from("<" + fmt, old, pos)[0],
                                    "value": struct.unpack_from("<" + fmt, new, pos)[0],
                                    "changed": old[pos:pos + width] != new[pos:pos + width]})
                require(all(new[i] == old[i] for i in range(size) if i not in covered),
                        "Undecoded bytes changed")
                blocks[block] = {"data_hex": new.hex(), "baseline_data_hex": old.hex(), "fields": decoded}
            styles.append({"name": name, "form_id": f"{form:08X}", "record_offset": hex(offset),
                           "baseline_offset": hex(old_offset), "flags": hex(flags),
                           "base_direct_actor_records": direct_actors[form], "blocks": blocks})
    result = {"scope": "Static data and supported-executable evidence; no gameplay acceptance",
              "identity_policy": "Input paths, plugin identity and header text intentionally omitted",
              "format_authority": {
                  "url": "https://github.com/TES5Edit/TES5Edit/blob/dev-4.1.6/Core/wbDefinitionsFNV.pas",
                  "retrieved": "2026-10-20",
                  "source_sha256": "89b1420415b858e004429e89a828348a1df71f5c8b199d4ea66e02f0ca41b012"},
              "record_counts": dict(counts), "groups": dict(groups),
              "base_master_sha256": hashlib.sha256(master_data).hexdigest(),
              "base_master_record_counts": {k: master_counts[k] for k in ("GMST", "CSTY", "NPC_", "CREA")},
              "settings": settings, "styles": styles,
              "untouched_base_styles": [{"form_id": f"{f:08X}", "name": one(s, "EDID").rstrip(b"\0").decode("ascii")}
                                        for f, (_, s) in master_cs.items() if f not in {int(c["form_id"], 16) for c in styles}]}
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="ascii")
    print(json.dumps({"records": dict(counts), "settings": len(settings), "styles": len(styles),
                      "settings_changed": sum(s["changed"] is True for s in settings),
                      "settings_unchanged": sum(s["changed"] is False for s in settings),
                      "settings_unknown": sum(s["changed"] is None for s in settings)}))


if __name__ == "__main__":
    main()
