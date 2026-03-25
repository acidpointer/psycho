# @category Analysis
# @description Audit ALL Havok world access paths that do NOT hold
# the hkWorld lock. The lock is at world+0x48 via FUN_00c3e750.
# We need to find every function that modifies broadphase, simulation
# islands, entity lists, or constraint systems WITHOUT locking.
#
# Strategy:
# 1. Find all callers of hkWorld_Lock (FUN_00c3e310) -- these are SAFE
# 2. Find all callers of addEntity (FUN_00c94bd0) -- check if locked
# 3. Find all callers of removeEntry (FUN_00c41fe0) -- check if locked
# 4. Find all callers of bhkCollisionObject dtor -- check if locked
# 5. Find functions that write to broadphase (world+0x58) vtable calls
# 6. Find functions that modify simulation islands
# 7. Trace FUN_00c97f80, FUN_00cf7c10, FUN_00ce1680 callers deep
# 8. Check if any of these run on AI threads or BSTaskManagerThread

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

def check_if_calls(func_addr, target_addr):
	func = fm.getFunctionAt(toAddr(func_addr))
	if func is None:
		func = fm.getFunctionContaining(toAddr(func_addr))
	if func is None:
		return False
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				if ref.getToAddress().getOffset() == target_addr:
					return True
	return False

write("=" * 70)
write("HAVOK UNSYNCHRONIZED ACCESS AUDIT")
write("Find ALL paths that touch Havok world without hkWorld_Lock")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: addEntity callers -- do they hold hkWorld_Lock?")
write("# FUN_00c94bd0 has 4 callers. Check each.")
write("#" * 70)

# addEntity callers: 0x00c674d0, 0x00cf7c10, 0x00ce1680, 0x00c97f80
# hkWorld_Lock is FUN_00c3e310

add_entity_callers = [0x00c674d0, 0x00cf7c10, 0x00ce1680, 0x00c97f80]
lock_func = 0x00c3e310

write("")
write("Checking if addEntity callers acquire hkWorld_Lock:")
for caller in add_entity_callers:
	has_lock = check_if_calls(caller, lock_func)
	func = fm.getFunctionAt(toAddr(caller))
	name = func.getName() if func else "???"
	write("  0x%08x (%s): calls hkWorld_Lock = %s" % (caller, name, has_lock))

# Trace callers of each addEntity caller to find thread context
write("")
write("Callers of each addEntity caller (to find thread context):")

for caller in add_entity_callers:
	find_refs_to(caller, "addEntity_caller_0x%08x" % caller)

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: removeEntity/removeEntry callers -- locked?")
write("# FUN_00c41fe0 (removeEntry) and FUN_00c42960 (removeEntity)")
write("#" * 70)

remove_funcs = [0x00c41fe0, 0x00c42960, 0x00c41f40]
write("")
write("Checking if remove callers acquire hkWorld_Lock:")
for rf in remove_funcs:
	has_lock = check_if_calls(rf, lock_func)
	func = fm.getFunctionAt(toAddr(rf))
	name = func.getName() if func else "???"
	write("  0x%08x (%s): calls hkWorld_Lock = %s" % (rf, name, has_lock))

# FUN_00c41f40 calls FUN_00c42960 which calls FUN_00c41fe0
decompile_at(0x00c41f40, "RemoveEntity_Wrapper_FUN_00c41f40")
find_refs_to(0x00c41f40, "RemoveEntity_Wrapper")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: bhkCollisionObject dtor callers -- who triggers?")
write("# FUN_00c40b70 is the dtor. Who calls it and from which thread?")
write("#" * 70)

find_refs_to(0x00c40b70, "bhkCollisionObject_dtor")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Havok constraint management -- add/remove constraints")
write("# Constraints also modify world state. Are they locked?")
write("#" * 70)

# FUN_00cb5570 -- called during deferred ops processing in addEntity caller
decompile_at(0x00cb5570, "ConstraintAdd_FUN_00cb5570")
find_refs_to(0x00cb5570, "ConstraintAdd")

# FUN_00cb5750 -- called during deferred ops
decompile_at(0x00cb5750, "ConstraintRemove_FUN_00cb5750")
find_refs_to(0x00cb5750, "ConstraintRemove")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00c914d0 -- called during deferred ops (case 1)")
write("# Entity removal through deferred path")
write("#" * 70)

decompile_at(0x00c914d0, "DeferredRemoveEntity_FUN_00c914d0")
find_refs_to(0x00c914d0, "DeferredRemoveEntity")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_00c91620 -- called during deferred ops (case 2)")
write("# Entity state change through deferred path")
write("#" * 70)

decompile_at(0x00c91620, "DeferredEntityStateChange_FUN_00c91620")
find_refs_to(0x00c91620, "DeferredEntityStateChange")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_00ca8420 -- called during deferred ops (case 4)")
write("# Physics property change?")
write("#" * 70)

decompile_at(0x00ca8420, "DeferredPropertyChange_FUN_00ca8420")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Havok raycast functions -- used by AI for pathfinding")
write("# Do raycasts acquire hkWorld_Lock? They should at least read-lock.")
write("#" * 70)

# From the crash stack, the raycast goes through:
# FUN_00cbf860 (TtRayCstCached) -> broadphase query
decompile_at(0x00cbf860, "HavokRayCast_Cached")

# FUN_00c698c0 -- broadphase query caller
decompile_at(0x00c698c0, "BroadphaseQuery_FUN_00c698c0")
find_refs_to(0x00c698c0, "BroadphaseQuery")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_00c6b540, FUN_00c68a40, FUN_00c6b0a0")
write("# These call FUN_00c674d0 (addEntity caller1).")
write("# What are they? Character physics setup? Ragdoll creation?")
write("#" * 70)

decompile_at(0x00c6b540, "AddEntityPath_FUN_00c6b540")
find_refs_to(0x00c6b540, "AddEntityPath1_callers")

decompile_at(0x00c68a40, "AddEntityPath_FUN_00c68a40")
find_refs_to(0x00c68a40, "AddEntityPath2_callers")

decompile_at(0x00c6b0a0, "AddEntityPath_FUN_00c6b0a0")
find_refs_to(0x00c6b0a0, "AddEntityPath3_callers")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: FUN_00c97f80 callers -- this calls addEntity directly")
write("# In what context? During AI? During loading?")
write("#" * 70)

find_refs_to(0x00c97f80, "AddEntity_Caller4_FUN_00c97f80")

# Decompile the callers to see context
decompile_at(0x00c97f80, "AddEntity_Caller4_Full", 10000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 11: FUN_00446f70 and FUN_00446ff0")
write("# Called by hkWorld_Lock acquire/release to signal physics threads.")
write("# What are these? SetEvent? Semaphore?")
write("#" * 70)

decompile_at(0x00446f70, "LockSignal_FUN_00446f70")
decompile_at(0x00446ff0, "UnlockSignal_FUN_00446ff0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 12: FUN_008c8fd0 -- called by main thread during AI")
write("# in FUN_0096bcd0. Process manager related?")
write("#" * 70)

decompile_at(0x008c8fd0, "MainDuringAI_FUN_008c8fd0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 13: FUN_00c7fa90 -- called by FUN_008e51b0 (AI worker)")
write("# Physics update during AI execution. Touches Havok?")
write("#" * 70)

decompile_at(0x00c7fa90, "AIWorker_HavokUpdate_FUN_00c7fa90")
find_refs_to(0x00c7fa90, "HavokUpdate_callers")

# ===================================================================
write("")
write("#" * 70)
write("# PART 14: FUN_00975080 -- called at end of AI worker cell mgmt")
write("# FUN_00453550 calls this. What does it do?")
write("#" * 70)

decompile_at(0x00975080, "AIWorker_EndCellMgmt_FUN_00975080")
find_and_print_calls_from(0x00975080, "AIWorker_EndCellMgmt")

# ===================================================================
write("")
write("#" * 70)
write("# PART 15: FUN_009bec10 and FUN_009ae580")
write("# Called from FUN_0096db30 (AI worker physics)")
write("# For actors that are not loaded or are in special state")
write("#" * 70)

decompile_at(0x009bec10, "AIWorker_SpecialActor_FUN_009bec10")
find_and_print_calls_from(0x009bec10, "AIWorker_SpecialActor1")

decompile_at(0x009ae580, "AIWorker_SpecialActor_FUN_009ae580")
find_and_print_calls_from(0x009ae580, "AIWorker_SpecialActor2")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/havok_unsync_access_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
