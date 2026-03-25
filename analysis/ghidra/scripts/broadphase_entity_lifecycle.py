# @category Analysis
# @description Trace entity add/remove from Havok broadphase.
# The crash is in hkpWorld::addEntity (FUN_00c94bd0) on AI thread.
# We need to understand:
# 1. Who calls addEntity? From which threads?
# 2. Who calls removeEntity? From which threads?
# 3. What broadphase vtable+0x18 (addObjectBatch) does
# 4. Does PDD removal leave broadphase in inconsistent state?
# 5. What is FUN_00d07420 (called during addEntity for simulation islands)?

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
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

write("=" * 70)
write("BROADPHASE ENTITY LIFECYCLE ANALYSIS")
write("Who adds/removes entities? On which thread? When?")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: hkpWorld::addEntity (FUN_00c94bd0) -- who calls it?")
write("#" * 70)

find_refs_to(0x00c94bd0, "hkpWorld_addEntity")

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Entity removal -- FUN_00c420d0 (RemoveFromWorld)")
write("# Called during PDD destruction chain")
write("#" * 70)

decompile_at(0x00c420d0, "Havok_RemoveFromWorld", 10000)
find_refs_to(0x00c420d0, "Havok_RemoveFromWorld")
find_and_print_calls_from(0x00c420d0, "Havok_RemoveFromWorld")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: hkWorld_RemoveEntry (FUN_00c41fe0)")
write("# Called during entity removal")
write("#" * 70)

decompile_at(0x00c41fe0, "hkWorld_RemoveEntry")
find_refs_to(0x00c41fe0, "hkWorld_RemoveEntry")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00d07420 -- simulation island management")
write("# Called during addEntity for island assignment")
write("#" * 70)

decompile_at(0x00d07420, "SimIsland_AddEntity", 10000)
find_refs_to(0x00d07420, "SimIsland_AddEntity")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00d07830 -- simulation island creation")
write("# Creates new hkpSimulationIsland (RTTI 0x010CCF28)")
write("#" * 70)

decompile_at(0x00d07830, "SimIsland_Create")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: bhkCollisionObject destructor (FUN_00c40b70)")
write("# This is called during PDD queue 0x20 processing")
write("# Does it properly remove from broadphase before freeing?")
write("#" * 70)

decompile_at(0x00c40b70, "bhkCollisionObject_dtor", 10000)
find_and_print_calls_from(0x00c40b70, "bhkCollisionObject_dtor")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_00c90510 -- called during addEntity per-entity")
write("# What does it initialize?")
write("#" * 70)

decompile_at(0x00c90510, "AddEntity_PerEntityInit")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00c9c040 -- called during addEntity after")
write("# broadphase update. What does it do?")
write("#" * 70)

decompile_at(0x00c9c040, "AddEntity_PostBroadphase")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_00c91160 -- called when this+0x94 != 0")
write("# This is the DEFERRED path in addEntity.")
write("# When pending operations exist, addEntity defers instead of")
write("# adding directly. What does it do?")
write("#" * 70)

decompile_at(0x00c91160, "AddEntity_Deferred")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: FUN_00c91120 and FUN_00c91140")
write("# Called when pending count reaches 0 after addEntity batch.")
write("# These process deferred operations.")
write("#" * 70)

decompile_at(0x00c91120, "ProcessDeferredOps1")
decompile_at(0x00c91140, "ProcessDeferredOps2")

# ===================================================================
write("")
write("#" * 70)
write("# PART 11: FUN_00d00500 and FUN_00cffa00")
write("# Called AFTER broadphase batch add for each entity.")
write("# These finalize the entity in the simulation.")
write("#" * 70)

decompile_at(0x00d00500, "PostAdd_FUN_00d00500")
decompile_at(0x00cffa00, "PostAdd_FUN_00cffa00", 10000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 12: Havok world this+0x58 (broadphase pointer)")
write("# What is the broadphase vtable? What is vtable+0x18?")
write("# The crash is in broadphase->addObjectBatch (vtable+0x18)")
write("#" * 70)

# hkp3AxisSweep vtable -- this is the broadphase implementation
# From RTTI: 0x010CD5CC (hkp3AxisSweep)
# vtable should be nearby
find_refs_to(0x010CD5CC, "hkp3AxisSweep RTTI")

# Also check the broadphase remove function
# vtable+0x1C would be removeObjectBatch
# vtable+0x20 might be updateAabbs

# ===================================================================
write("")
write("#" * 70)
write("# PART 13: FUN_00cf1480 -- called per entity in addEntity")
write("# Zeroes broadphase handle data")
write("#" * 70)

decompile_at(0x00cf1480, "ZeroBroadphaseHandle")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/broadphase_entity_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
