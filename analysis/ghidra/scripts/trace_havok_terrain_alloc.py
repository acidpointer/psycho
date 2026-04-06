# @category Analysis
# @description Trace allocation/free paths for terrain collision data that
# Havok raycasts access. Crash at 0x00CAFED5 with ECX=0x5C8564E0 during
# hkp3AxisSweep raycast. Need to find what allocates terrain data through
# CRT malloc and how it gets freed during cell unload.
#
# Key hypothesis: terrain collision data (heightfield arrays, MOPP codes)
# is allocated through CRT malloc → our IAT hook routes large allocs to
# VirtualAlloc → freed via VirtualFree(MEM_DECOMMIT) with zero grace period
# → Havok raycast hits unmapped pages → crash.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
    output.append(msg)
    print(msg)

def decompile_at(addr_int, label, max_len=8000):
    addr = toAddr(addr_int)
    func = fm.getFunctionAt(addr)
    if func is None:
        func = fm.getFunctionContaining(addr)
    write("")
    write("=" * 70)
    write("%s @ 0x%08x" % (label, addr_int))
    write("=" * 70)
    if func is None:
        write("  [function not found]")
        return
    faddr = func.getEntryPoint().getOffset()
    write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
    if faddr != addr_int:
        write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
    result = decomp.decompileFunction(func, 120, monitor)
    if result and result.decompileCompleted():
        code = result.getDecompiledFunction().getC()
        write(code[:max_len])
    else:
        write("  [decompilation failed]")

def find_refs_to(addr_int, label):
    write("")
    write("-" * 70)
    write("References TO 0x%08x (%s)" % (addr_int, label))
    write("-" * 70)
    refs = ref_mgr.getReferencesTo(toAddr(addr_int))
    count = 0
    while refs.hasNext():
        ref = refs.next()
        from_func = fm.getFunctionContaining(ref.getFromAddress())
        fname = from_func.getName() if from_func else "???"
        write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
        count += 1
        if count > 40:
            write("  ... (truncated)")
            break
    write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
    func = fm.getFunctionAt(toAddr(addr_int))
    if func is None:
        func = fm.getFunctionContaining(toAddr(addr_int))
    if func is None:
        write("  [function not found at 0x%08x]" % addr_int)
        return
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    write("")
    write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
    count = 0
    while inst_iter.hasNext():
        inst = inst_iter.next()
        refs = inst.getReferencesFrom()
        for ref in refs:
            if ref.getReferenceType().isCall():
                tgt = ref.getToAddress().getOffset()
                tgt_func = fm.getFunctionAt(toAddr(tgt))
                name = tgt_func.getName() if tgt_func else "???"
                write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
                count += 1
    write("  Total: %d calls" % count)

def find_callers_in_range(target_addr, range_start, range_end, label):
    write("")
    write("-" * 70)
    write("%s callers from 0x%08x-0x%08x" % (label, range_start, range_end))
    write("-" * 70)
    refs = ref_mgr.getReferencesTo(toAddr(target_addr))
    count = 0
    while refs.hasNext():
        ref = refs.next()
        src = ref.getFromAddress().getOffset()
        if range_start <= src <= range_end and ref.getReferenceType().isCall():
            func = fm.getFunctionContaining(ref.getFromAddress())
            name = func.getName() if func else "???"
            write("  0x%08x in %s" % (src, name))
            count += 1
    write("  Total: %d callers" % count)

# ===================================================================
# SECTION 1: Exact crash instruction at 0x00CAFED5
# ===================================================================

write("SECTION 1: Exact crash instruction at 0x00CAFED5")
write("=" * 70)

crash_addr = toAddr(0x00CAFED5)
inst = currentProgram.getListing().getInstructionContaining(crash_addr)
if inst:
    write("  Address: 0x%08x" % inst.getAddress().getOffset())
    write("  Mnemonic: %s" % inst.getMnemonicString())
    write("  Operands: %s" % inst.getDefaultOperandRepresentation(0))
    write("  Full: %s" % inst.toString())
    write("")
    write("  Surrounding instructions:")
    iter_before = currentProgram.getListing().getInstructions(inst.getAddress(), False)
    before_list = []
    for i in range(20):
        if iter_before.hasNext():
            before_list.append(iter_before.next())
    before_list.reverse()
    for b in before_list:
        prefix = ">> " if b.getAddress().getOffset() == 0x00CAFED5 else "   "
        write("%s  0x%08x: %s" % (prefix, b.getAddress().getOffset(), b.toString()))
    iter_after = currentProgram.getListing().getInstructions(inst.getAddress(), True)
    for i in range(20):
        if iter_after.hasNext():
            a = iter_after.next()
            prefix = ">> " if a.getAddress().getOffset() == 0x00CAFED5 else "   "
            write("%s  0x%08x: %s" % (prefix, a.getAddress().getOffset(), a.toString()))
else:
    write("  [no instruction found at 0x00CAFED5]")

# ===================================================================
# SECTION 2: Full crash function decompilation
# ===================================================================

write("")
write("SECTION 2: Full crash function (0x00D16300)")
write("=" * 70)

decompile_at(0x00D16300, "hkp3AxisSweep_broadphase_raycast", max_len=15000)

# ===================================================================
# SECTION 3: Havok Allocate Dispatcher
# Does it call CRT malloc? Or GameHeap only?
# ===================================================================

write("")
write("SECTION 3: Havok Allocate Dispatcher - allocation path")
write("=" * 70)

decompile_at(0x00C3E1B0, "Havok_Allocate_Dispatcher")
find_and_print_calls_from(0x00C3E1B0, "Havok_Allocate_Dispatcher")

# Does it call GameHeap::Allocate?
find_refs_to(0x00AA3E40, "GameHeap_Allocate")

# Does it call CRT malloc?
find_refs_to(0x00B65D00, "msvcrt_malloc")

# ===================================================================
# SECTION 4: hkpMoppCode allocation and free paths
# ===================================================================

write("")
write("SECTION 4: hkpMoppCode allocation and free paths")
write("=" * 70)

decompile_at(0x00C42180, "Havok_Reconstruct_moppCode")
find_and_print_calls_from(0x00C42180, "Havok_Reconstruct_moppCode")
find_refs_to(0x00C42180, "Havok_Reconstruct_moppCode")

decompile_at(0x00C41FE0, "Havok_FreeEntry")
find_and_print_calls_from(0x00C41FE0, "Havok_FreeEntry")
find_refs_to(0x00C41FE0, "Havok_FreeEntry")

# Who calls FreeEntry during cell unload?
find_callers_in_range(0x00C41FE0, 0x00450000, 0x00460000, "cell_unload")
find_callers_in_range(0x00C41FE0, 0x00860000, 0x00880000, "heap_compact")

# ===================================================================
# SECTION 5: Cell unload - what frees terrain data?
# ===================================================================

write("")
write("SECTION 5: Cell unload - terrain data free paths")
write("=" * 70)

decompile_at(0x00453A80, "FindCellToUnload")
find_and_print_calls_from(0x00453A80, "FindCellToUnload")

decompile_at(0x00452490, "ProcessPendingCleanup")
find_and_print_calls_from(0x00452490, "ProcessPendingCleanup")

decompile_at(0x00878250, "DeferredCleanupSmall")
find_and_print_calls_from(0x00878250, "DeferredCleanupSmall")

# What calls GameHeap free during cell unload?
find_callers_in_range(0x00AA4060, 0x00450000, 0x00460000, "cell_unload_GHEAP_free")
find_callers_in_range(0x00AA4060, 0x00878000, 0x00879000, "deferred_cleanup_GHEAP_free")

# What calls CRT free during cell unload?
find_callers_in_range(0x00B65D30, 0x00450000, 0x00460000, "cell_unload_CRT_free")
find_callers_in_range(0x00B65D30, 0x00878000, 0x00879000, "deferred_cleanup_CRT_free")

# ===================================================================
# SECTION 6: Heightfield shape creation - how terrain data is allocated
# ===================================================================

write("")
write("SECTION 6: Heightfield shape - data allocation path")
write("=" * 70)

find_refs_to(0x00C696D0, "TtPickObject_BroadphaseQuery")

# hkWorld::addEntity / removeEntity
decompile_at(0x00C41250, "hkWorld_addEntity")
find_and_print_calls_from(0x00C41250, "hkWorld_addEntity")

decompile_at(0x00C41340, "hkWorld_removeEntity")
find_and_print_calls_from(0x00C41340, "hkWorld_removeEntity")

# Does PDD call removeEntity?
find_callers_in_range(0x00C41340, 0x00868000, 0x0086A000, "PDD_removeEntity")

# ===================================================================
# SECTION 7: Pre-destruction protocol effect on broadphase
# ===================================================================

write("")
write("SECTION 7: Pre-destruction protocol and broadphase")
write("=" * 70)

decompile_at(0x00878160, "PreDestruction_Setup")
find_and_print_calls_from(0x00878160, "PreDestruction_Setup")

decompile_at(0x00878200, "PostDestruction_Restore")
find_and_print_calls_from(0x00878200, "PostDestruction_Restore")

# Does PreDestruction call removeEntity?
find_callers_in_range(0x00C41340, 0x00878000, 0x00879000, "pre_destruction_removeEntity")

# ===================================================================
# SECTION 8: IAT free path analysis - the critical path
# ===================================================================

write("")
write("SECTION 8: IAT free path - when does VirtualAlloc free trigger?")
write("=" * 70)

write("IAT free path:")
write("  1. mi_is_in_heap_region(ptr) -> true -> mi_free (purge_delay protects)")
write("  2. mi_is_in_heap_region(ptr) -> false")
write("     a. is_virtual_alloc_ptr(ptr) -> true -> VirtualFree(MEM_DECOMMIT) [CRASH]")
write("     b. is_virtual_alloc_ptr(ptr) -> false -> original_free")
write("")
write("Crash pointer 0x5C8564E0:")
write("  - 0x5C8564E0 - 0x20000000 (arena base) = 0x3C8564E0 (968MB)")
write("  - OUTSIDE 512MB primary arena")
write("  - Could be: mimalloc overflow, VirtualAlloc large alloc, other")
write("")
write("KEY QUESTION: Was terrain data allocated through IAT VirtualAlloc")
write("and freed via VirtualFree(MEM_DECOMMIT) while Havok still references it?")

# What functions allocate through VirtualAlloc in the terrain path?
find_refs_to(0x00401000, "VirtualAlloc_wrapper_00401000")

# ===================================================================
# Output
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/virtualalloc_iat_root_cause.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
