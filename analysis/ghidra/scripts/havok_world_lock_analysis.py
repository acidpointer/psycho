# @category Analysis
# @description Deep analysis of Havok world lock mechanism and broadphase
# access serialization. We need to understand:
# 1. What is hkWorld_Lock (FUN_00c3e310)? CriticalSection? Atomic?
# 2. Who holds the lock when modifying broadphase?
# 3. Do AI workers ever acquire the lock?
# 4. Can we acquire it ourselves to serialize broadphase access?
# 5. What is the lock object structure at world+0x7c/+0x80?
# 6. FUN_00c3e750 (lock acquire) and FUN_00c3e7d0 (lock release) internals

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
		if count > 50:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

write("=" * 70)
write("HAVOK WORLD LOCK + BROADPHASE SERIALIZATION ANALYSIS")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: hkWorld_Lock internals -- what kind of lock is it?")
write("# FUN_00c3e310 calls FUN_00c3e750 then invokes callback at +0x7c")
write("#" * 70)

decompile_at(0x00c3e310, "hkWorld_Lock")
decompile_at(0x00c3e750, "hkWorld_Lock_Acquire (called by Lock)")
find_and_print_calls_from(0x00c3e750, "hkWorld_Lock_Acquire")

decompile_at(0x00c3e340, "hkWorld_Unlock")
decompile_at(0x00c3e7d0, "hkWorld_Unlock_Release (called by Unlock)")
find_and_print_calls_from(0x00c3e7d0, "hkWorld_Unlock_Release")

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: What are the lock/unlock callbacks at world+0x7c/+0x80?")
write("# These are function pointers called after lock acquire/release.")
write("# In debug builds this would be hkCheckDeterminismUtil.")
write("# In release builds these might be NULL or no-ops.")
write("#" * 70)

# The world object structure around the lock:
# +0x58: broadphase pointer
# +0x7c: lock callback (called by hkWorld_Lock after acquire)
# +0x80: unlock callback (called by hkWorld_Unlock after release)
# +0x94: pending operation count (addEntity checks this)

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_00c674d0 -- caller of addEntity")
write("# One of the 4 callers. What context does it run in?")
write("#" * 70)

decompile_at(0x00c674d0, "AddEntity_Caller1_FUN_00c674d0")
find_refs_to(0x00c674d0, "AddEntity_Caller1")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00cf7c10 -- caller of addEntity")
write("#" * 70)

decompile_at(0x00cf7c10, "AddEntity_Caller2_FUN_00cf7c10", 10000)
find_refs_to(0x00cf7c10, "AddEntity_Caller2")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00ce1680 -- caller of addEntity")
write("#" * 70)

decompile_at(0x00ce1680, "AddEntity_Caller3_FUN_00ce1680")
find_refs_to(0x00ce1680, "AddEntity_Caller3")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_00c97f80 -- caller of addEntity")
write("#" * 70)

decompile_at(0x00c97f80, "AddEntity_Caller4_FUN_00c97f80")
find_refs_to(0x00c97f80, "AddEntity_Caller4")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Who calls FUN_00c41fe0 (removeEntry)?")
write("# This calls broadphase->removeObjectBatch (vtable+0x28)")
write("#" * 70)

find_refs_to(0x00c41fe0, "hkWorld_RemoveEntry")

# Trace deeper: who calls FUN_00c42960 which calls removeEntry?
decompile_at(0x00c42960, "RemoveEntry_Caller_FUN_00c42960")
find_refs_to(0x00c42960, "RemoveEntry_Caller")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00c42b40 -- called during bhkCollisionObject dtor")
write("# What does it do to broadphase?")
write("#" * 70)

decompile_at(0x00c42b40, "CollObj_Cleanup_FUN_00c42b40")
find_refs_to(0x00c42b40, "CollObj_Cleanup")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: Who acquires hkWorld_Lock during the frame?")
write("# Trace callers of FUN_00c3e310 to see which phase they run in")
write("#" * 70)

# Already have refs from previous analysis. Let's decompile the callers
# to understand WHEN they lock:
decompile_at(0x00448420, "hkWorldLock_Caller_FUN_00448420")
decompile_at(0x00850ba0, "hkWorldLock_Caller_FUN_00850ba0")
decompile_at(0x00856ca0, "hkWorldLock_Caller_FUN_00856ca0", 10000)
decompile_at(0x00861130, "hkWorldLock_Caller_FUN_00861130", 10000)
decompile_at(0x00847df0, "hkWorldLock_Caller_FUN_00847df0", 10000)
decompile_at(0x005d15d0, "hkWorldLock_Caller_FUN_005d15d0")
decompile_at(0x00869f30, "hkWorldLock_Caller_FUN_00869f30")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: Bethesda's bhkWorldM wrapper -- does it add")
write("# any synchronization on top of Havok's lock?")
write("#" * 70)

# bhkWorldM constructor or init -- look for lock setup
decompile_at(0x00c9a040, "bhkWorldM_Init1")
decompile_at(0x00c99ff0, "bhkWorldM_Init2")

# ===================================================================
write("")
write("#" * 70)
write("# PART 11: Process manager lock (DAT_011f11a0) relationship")
write("# to Havok world lock. Are they nested? Same? Different?")
write("#" * 70)

decompile_at(0x0040fbf0, "ProcessMgr_Lock_Acquire")
decompile_at(0x0040fba0, "ProcessMgr_Lock_Release")

# ===================================================================
write("")
write("#" * 70)
write("# PART 12: FUN_00c3dfa0 -- the ONLY caller of hkWorld_Step")
write("# When does the Havok simulation step run?")
write("#" * 70)

decompile_at(0x00c3dfa0, "hkWorld_Step_Caller")
find_refs_to(0x00c3dfa0, "hkWorld_Step_Caller")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/havok_world_lock_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
