# @category Analysis
# @description Trace terrain collision allocation paths: find functions that
# allocate large buffers (>= 1MB) via CRT malloc that Havok references.
# This traces the chain from terrain loading -> malloc -> Havok shape -> crash.

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType

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

# ===================================================================
# Helper: find_callers_in_range defined at top level (safe pattern)
# ===================================================================

def find_callers_in_range_func(target_addr, range_start, range_end, label):
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
# SECTION 1: Havok allocate dispatcher - does it call CRT malloc?
# hkAllocate_Dispatcher at 0x00c3e1b0
# ===================================================================

write("SECTION 1: hkAllocate_Dispatcher - allocation path analysis")
write("=" * 70)

decompile_at(0x00C3E1B0, "Havok_Allocate_Dispatcher")
find_and_print_calls_from(0x00C3E1B0, "Havok_Allocate_Dispatcher")

# Find what alloc dispatcher allocates through - does it call GameHeap?
find_refs_to(0x00AA3E40, "GameHeap_Allocate_00AA3E40")

# Does it call CRT malloc directly?
find_refs_to(0x00B65D00, "msvcrt_malloc_if_exists")
find_refs_to(0x00B65D10, "msvcrt_free_if_exists")

# ===================================================================
# SECTION 2: Terrain collision data allocation
# hkpMoppCode / hkHeightFieldShape data buffers
# The crash involves hkpMoppCode (stack slot 66). How is it allocated?
# ===================================================================

write("")
write("SECTION 2: hkpMoppCode allocation and lifecycle")
write("=" * 70)

# hkpMoppCode RTTI
find_refs_to(0x0102E368, "hkpMoppCode_RTTI")

# hkMoppCode constructor
find_refs_to(0x00C41FE0, "Havok_FreeEntry_00C41FE0")

# Havok_Reconstruct which allocates the MOPP code storage
decompile_at(0x00C42180, "Havok_Reconstruct_FUN_00C42180")
find_and_print_calls_from(0x00C42180, "Havok_Reconstruct_FUN_00C42180")

# What allocates through Havok_Reconstruct?
find_refs_to(0x00C42180, "Havok_Reconstruct")

# What allocates through Havok_FreeEntry?
find_refs_to(0x00C41FE0, "Havok_FreeEntry")

# ===================================================================
# SECTION 3: 3-Axis Sweep broadphase - how entries are managed
# The crash happens inside hkp3AxisSweep narrow phase raycast.
# hkp3AxisSweep RTTI at 0x010CD5CC
# ===================================================================

write("")
write("SECTION 3: hkp3AxisSweep broadphase entry management")
write("=" * 70)

find_refs_to(0x010CD5CC, "hkp3AxisSweep_RTTI")

# hkp3AxisSweep add/remove entity
find_callers_in_range = None  # we define it below

# ===================================================================
# SECTION 4: Cell unload - what frees terrain data?
# Stage 5: FindCellToUnload (0x00453A80)
# ProcessPendingCleanup (0x00452490)
# ===================================================================

write("")
write("SECTION 4: Cell unload - terrain data free paths")
write("=" * 70)

decompile_at(0x00453A80, "FindCellToUnload")
find_and_print_calls_from(0x00453A80, "FindCellToUnload")

# What does FindCellToUnload call that frees Havok data?
find_refs_to(0x00AA4060, "GameHeap_Free_00AA4060")

# Process pending cleanup
decompile_at(0x00452490, "ProcessPendingCleanup")
find_and_print_calls_from(0x00452490, "ProcessPendingCleanup")

# ===================================================================
# SECTION 5: hkWorld entity add/remove - how shapes enter/leave broadphase
# addEntity at +0x5c of world vtable
# removeEntity at +0x60 of world vtable
# ===================================================================

write("")
write("SECTION 5: Havok entity add/remove from broadphase")
write("=" * 70)

# FUN_00c41250 - hkWorld::addEntity
decompile_at(0x00C41250, "hkWorld_addEntity")
find_and_print_calls_from(0x00C41250, "hkWorld_addEntity")

# FUN_00c41340 - hkWorld::removeEntity
decompile_at(0x00C41340, "hkWorld_removeEntity")
find_and_print_calls_from(0x00C41340, "hkWorld_removeEntity")

# Who calls removeEntity during cell unload?
find_callers_in_range_func(0x00C41340, 0x00400000, 0x00900000, "Cell_unload_code")

# ===================================================================
# SECTION 6: The crash area - 0x00CAFED5 is inside FUN_00D16300
# This is the hkp3AxisSweep broadphase raycast function
# We need to understand what data structure it accesses that gets freed
# ===================================================================

write("")
write("SECTION 6: Crash function decompilation - 0x00D16300 area")
write("=" * 70)

decompile_at(0x00D16300, "hkp3AxisSweep_broadphase_raycast", max_len=10000)
find_and_print_calls_from(0x00D16300, "hkp3AxisSweep_broadphase_raycast")

# The crash is at 0x00CAFED5 which is INSIDE this function.
# What structure does it access at the crash point?

# ===================================================================
# SECTION 7: Terrain loading - what allocates collision data?
# Look at terrain loader functions
# ===================================================================

write("")
write("SECTION 7: Terrain loading - collision data allocation")
write("=" * 70)

# bhkWorldM - the game's Havok world wrapper
# How terrain collision is loaded into Havok
find_refs_to(0x010C3BC4, "bhkWorldM_RTTI")

# Terrain collision file loading (bhkNiTToShape, etc.)
find_refs_to(0x00C696D0, "Havok_BroadphaseQuery_TtPickObject")

# ===================================================================
# SECTION 8: CRT malloc callers in terrain/collision code
# Find functions that call msvcrt malloc in the terrain system
# ===================================================================

write("")
write("SECTION 8: CRT malloc in terrain systems")
write("=" * 70)

# Find all calls to malloc in the game
# msvcrt.dll imports - the game uses msvcrt.dll
# Look for calls to the IAT entry for malloc

# First find the malloc IAT thunk
write("Searching for malloc IAT thunk references...")
find_refs_to(0x00B65D00, "malloc_IAT_thunk")

# And free IAT thunk
find_refs_to(0x00B65D30, "free_IAT_thunk")

# ===================================================================
# SECTION 9: The specific crash instruction analysis
# 0x00CAFED5 - what exactly does this instruction do?
# ===================================================================

write("")
write("SECTION 9: Crash instruction at 0x00CAFED5")
write("=" * 70)

# Get the instruction at the crash address
crash_addr = toAddr(0x00CAFED5)
inst = currentProgram.getListing().getInstructionContaining(crash_addr)
if inst:
    write("  Address: 0x%08x" % inst.getAddress().getOffset())
    write("  Mnemonic: %s" % inst.getMnemonicString())
    write("  Operands: %s" % inst.getDefaultOperandRepresentation(0))
    write("  Full: %s" % inst.toString())
    # Check if this is a memory read
    refs = inst.getReferencesFrom()
    for ref in refs:
        write("  References: %s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
else:
    write("  [no instruction found at crash address]")

# Decontaining function around crash
decompile_at(0x00CAFED5, "Crash_Instruction_Context")

# ===================================================================
# SECTION 10: Heightfield / terrain shape lifecycle
# bhkMoppBvTreeShape, hkHeightFieldShape
# ===================================================================

write("")
write("SECTION 10: Heightfield/terrain shape lifecycle")
write("=" * 70)

# bhkMoppBvTreeShape RTTI
find_refs_to(0x0102E368, "bhkMoppBvTreeShape_or_hkpMoppCode_RTTI")

# hkHeightFieldShape related functions
# Look for heightfield creation
find_refs_to(0x00C91F70, "hkWorld_CastRay_NoFilter")
find_refs_to(0x00C92040, "hkWorld_CastRay_WithFilter")

# ===================================================================
# SECTION 11: PDD and Havok entity removal
# When PDD processes deferred destruction of terrain shapes,
# does it remove them from the broadphase FIRST?
# ===================================================================

write("")
write("SECTION 11: PDD and Havok entity removal ordering")
write("=" * 70)

decompile_at(0x00868D70, "PDD_ProcessDeferredDestruction")
find_and_print_calls_from(0x00868D70, "PDD_ProcessDeferredDestruction")

# Deferred cleanup small - the standard PDD sequence
find_refs_to(0x00878250, "DeferredCleanupSmall")

# What does PDD do for Havok entities?
# Look for hkWorld::removeEntity calls in the PDD chain
find_callers_in_range_func(0x00C41340, 0x00860000, 0x00880000, "PDD_heap_compact_range")

# ===================================================================
# Output
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/terrain_collision_alloc_trace.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()


