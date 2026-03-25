# @category Analysis
# @description Find ALL functions that modify the Havok world state.
# The world is accessed through DAT_01202d98 (IOManager/bhkWorld singleton)
# and through DAT_011dea3c (TES singleton -> bhkWorldM).
# We need to find every function that:
# 1. Calls addEntity, removeEntity, addConstraint, removeConstraint
# 2. Calls broadphase vtable methods (add/remove/update)
# 3. Modifies simulation island lists
# 4. Calls Havok step/integrate
# 5. Modifies entity motion state
# Then check if each path is properly locked.

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
		if count > 60:
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

write("=" * 70)
write("ALL HAVOK WORLD MODIFIERS AUDIT")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Havok world singleton access")
write("# DAT_01202d98 is the IOManager/world pointer")
write("# Who reads it? (potential world accessors)")
write("#" * 70)

# The bhkWorldM is typically accessed through TES singleton +offset
# Let's find who accesses the Havok world through different paths

# FUN_008c8bb0 sets a flag on an object. What object?
# The AI setup functions might give us the world pointer
decompile_at(0x008c8bd0, "AISetup_FUN_008c8bd0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Havok entity state changes (activation/deactivation)")
write("# These modify simulation island membership")
write("#" * 70)

# FUN_00c9c1d0 -- called after addEntity broadphase check
decompile_at(0x00c9c1d0, "EntityActivation_FUN_00c9c1d0")
find_refs_to(0x00c9c1d0, "EntityActivation")

# FUN_00c9bfa0 -- called from addEntity post-broadphase
decompile_at(0x00c9bfa0, "EntityDeactivation_FUN_00c9bfa0")
find_refs_to(0x00c9bfa0, "EntityDeactivation")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Simulation island merge/split")
write("# When entities interact, islands merge. When they separate, split.")
write("# These operations modify the world's island list.")
write("#" * 70)

# FUN_00cb4640 -- calls SimIsland_AddEntity multiple times
decompile_at(0x00cb4640, "IslandMerge_FUN_00cb4640")
find_refs_to(0x00cb4640, "IslandMerge")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Havok phantom (trigger volume) operations")
write("# Phantoms also use the broadphase. Add/remove phantom?")
write("#" * 70)

# FUN_00ce1680 is one of the 4 addEntity callers
decompile_at(0x00ce1680, "PhantomAdd_FUN_00ce1680")
find_refs_to(0x00ce1680, "PhantomAdd")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Bethesda's physics attach/detach")
write("# These are the game-level functions that add/remove")
write("# collision objects from the Havok world")
write("#" * 70)

# FUN_00c6b540 -- one of the addEntity caller chains
decompile_at(0x00c6b540, "PhysicsAttach_FUN_00c6b540")
find_refs_to(0x00c6b540, "PhysicsAttach")

# FUN_00c6b3c0 -- another addEntity caller chain
decompile_at(0x00c6b3c0, "PhysicsAttach2_FUN_00c6b3c0")
find_refs_to(0x00c6b3c0, "PhysicsAttach2")

# FUN_00c68a40 -- another path
decompile_at(0x00c68a40, "PhysicsSetup_FUN_00c68a40")
find_refs_to(0x00c68a40, "PhysicsSetup")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Havok motion state updates")
write("# Does updating an entity's position modify broadphase?")
write("# The broadphase stores AABBs. Position changes = AABB update.")
write("#" * 70)

# FUN_00c9c040 -- PostAdd_PostBroadphase, modifies entity motion
decompile_at(0x00d01a80, "BroadphaseUpdateAABB_FUN_00d01a80")
find_refs_to(0x00d01a80, "BroadphaseUpdateAABB")

# FUN_00d01ae0 -- also broadphase related
decompile_at(0x00d01ae0, "BroadphaseModify_FUN_00d01ae0")
find_refs_to(0x00d01ae0, "BroadphaseModify")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Havok collision detection -- narrowphase")
write("# The narrowphase reads broadphase data. Concurrent modification = crash")
write("#" * 70)

# FUN_00cf7080 -- called during addEntity after broadphase add
decompile_at(0x00cf7080, "NarrowphaseSetup_FUN_00cf7080")

# FUN_00d00370 -- called at end of addEntity processing
decompile_at(0x00d00370, "PostEntityAdd_FUN_00d00370")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00c3e860 -- called during hkWorld step")
write("# Processes pending operations count")
write("#" * 70)

decompile_at(0x00c3e860, "StepPendingOps_FUN_00c3e860")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: Havok world update AABB -- FUN_00d16300")
write("# This is the 3-axis sweep broadphase query/update")
write("# Previously seen in crash analysis. Who calls it?")
write("#" * 70)

find_refs_to(0x00d16300, "BroadphaseSweep_FUN_00d16300")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: FUN_00c42b40 -- called by bhkCollisionObject dtor")
write("# Removes something from a hash table. What hash table?")
write("#" * 70)

decompile_at(0x00c42b40, "CollObjCleanup_FUN_00c42b40")
find_refs_to(0x00c42b40, "CollObjCleanup")

# ===================================================================
write("")
write("#" * 70)
write("# PART 11: FUN_00c90490 -- called at start of deferred ops")
write("# processing in FUN_00cf7c10. Lock acquisition?")
write("#" * 70)

decompile_at(0x00c90490, "DeferredOpsStart_FUN_00c90490")

# ===================================================================
write("")
write("#" * 70)
write("# PART 12: FUN_00c905b0 -- called after entity processing")
write("# Decrements entity refcount?")
write("#" * 70)

decompile_at(0x00c905b0, "EntityDecRef_FUN_00c905b0")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/all_havok_world_modifiers.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
