# @category Analysis
# @description Verify Stage 8 byte layout for NOP patching (v3 - corrected ranges)

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []


def write(msg):
    output.append(msg)
    print(msg)


def get_bytes(addr, length):
    result = ""
    for i in range(length):
        b = getByte(toAddr(addr + i)) & 0xFF
        result += "%02x " % b
    return result.strip()


def dump_site(start, size, label, desc):
    end = start + size
    write("=" * 70)
    write("SITE %s: 0x%08x-0x%08x (%d bytes) %s" % (label, start, end, size, desc))
    write("=" * 70)
    insts = []
    inst_iter = currentProgram.getListing().getInstructions(toAddr(start), True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        a = inst.getAddress().getOffset()
        if a >= end:
            break
        if a < start:
            continue
        bhex = get_bytes(a, inst.getLength())
        tgt = ""
        for ref in inst.getReferencesFrom():
            if ref.getReferenceType().isCall():
                tgt = " -> 0x%08x" % ref.getToAddress().getOffset()
        write("  0x%08x: %s  [%s]%s" % (a, inst.getMnemonicString(), bhex, tgt))
        insts.append(inst.getLength())
    total = 0
    for l in insts:
        total += l
    if total == size:
        write("  OK: %d bytes, instruction-aligned" % total)
        return True
    write("  FAIL: cover %d bytes, expected %d" % (total, size))
    return False


def dump_full(start, end):
    write("")
    write("=" * 70)
    write("FULL CASE 8 DUMP (0x%08x..0x%08x)" % (start, end))
    write("=" * 70)
    patch_addrs = [
        0x00866C79,
        0x00866C7B,
        0x00866C81,
        0x00866C8F,
        0x00866C91,
        0x00866C93,
        0x00866C99,
        0x00866C9E,
        0x00866CA0,
        0x00866CA6,
    ]
    inst_iter = currentProgram.getListing().getInstructions(toAddr(start), True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        a = inst.getAddress().getOffset()
        if a >= end:
            break
        bhex = get_bytes(a, inst.getLength())
        mark = ">> " if a in patch_addrs else "   "
        write("  %s0x%08x: %-40s %s" % (mark, a, bhex, inst.getMnemonicString()))
    write("")
    write("  >> = instruction inside a NOP patch site")


# =====================================================================
# Main body: only function calls, no loops
# =====================================================================

write("STAGE 8 PATCH SITE VERIFICATION v3")
write("===================================")
write("")
write("Corrected ranges (PUSH+MOV+CALL = 2+6+5 = 13 bytes per site):")
write("  Site A: 0x00866c79-0x00866c86 (13 bytes) PUSH+MOV+get_owner(idx=1)")
write("  Site B: 0x00866c8f-0x00866c91 (2 bytes)  JNZ skip")
write("  Site C: 0x00866c91-0x00866c9e (13 bytes) PUSH+MOV+release_sem(idx=1)")
write("  Site D: 0x00866c9e-0x00866cab (13 bytes) PUSH+MOV+signal_idle(idx=1)")
write("")

ok_a = dump_site(0x00866C79, 13, "A", "PUSH 1 + MOV ECX + get_owner(idx=1)")
ok_b = dump_site(0x00866C8F, 2, "B", "JNZ 0x00866cab")
ok_c = dump_site(0x00866C91, 13, "C", "PUSH 1 + MOV ECX + release_sem(idx=1)")
ok_d = dump_site(0x00866C9E, 13, "D", "PUSH 1 + MOV ECX + signal_idle(idx=1)")

dump_full(0x00866C40, 0x00866CD0)

write("")
write("=" * 70)
write("RESULT")
write("=" * 70)
if ok_a and ok_b and ok_c and ok_d:
    write("ALL 4 SITES VERIFIED - safe to patch")
    write("")
    write("Implementation:")
    write("  patch_bytes(0x00866C79, &[0x90; 13])  // Site A")
    write("  patch_bytes(0x00866C8F, &[0x90; 2])   // Site B")
    write("  patch_bytes(0x00866C91, &[0x90; 13])  // Site C")
    write("  patch_bytes(0x00866C9E, &[0x90; 13])  // Site D")
else:
    write("VERIFICATION FAILED - check individual sites above")

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/stage8_patch_verification_v3.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
