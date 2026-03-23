# @category Analysis
# @description DEEP research: QueuedCharacter ragdoll bone data lifecycle.
# Goal: understand EXACTLY when ragdoll bone transforms are freed,
# when QueuedCharacter processes them, and why UAF happens at 0x00A6DF48.
# Need: pointer chain QueuedCharacter -> Character -> bhkRagdollController -> bone array -> rotation matrix

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	listing = currentProgram.getListing()
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def find_xrefs_to(addr_int, label, limit=25):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)

def read_vtable(vtable_addr, label, count=16):
	write("")
	write("%s vtable at 0x%08x:" % (label, vtable_addr))
	for i in range(count):
		entry_addr = vtable_addr + i * 4
		val = getInt(toAddr(entry_addr)) & 0xFFFFFFFF
		func = fm.getFunctionContaining(toAddr(val))
		fname = func.getName() if func else "???"
		write("  [%2d] +0x%02x -> 0x%08x %s" % (i, i*4, val, fname))


write("=" * 70)
write("QueuedCharacter + Ragdoll Bone Data Lifecycle")
write("Crash: 0x00A6DF48 reads freed rotation matrix via ragdoll bone array")
write("=" * 70)

# =====================================================================
# PART 1: QueuedCharacter vtable (0x01016CEC from crash log)
# Identify Process, Complete, destructor methods
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: QueuedCharacter vtable — identify Process method")
write("#" * 70)

read_vtable(0x01016CEC, "QueuedCharacter", 16)

# Find who writes this vtable (= constructor)
find_xrefs_to(0x01016CEC, "QueuedCharacter_vtable")

# =====================================================================
# PART 2: QueuedCharacter constructor and creation context
# Who creates QueuedCharacter tasks and when?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: QueuedCharacter constructor — creation context")
write("#" * 70)

# From vtable xrefs, find the constructor function
# Also search for QueuedReference base class (0x01016D20 from stack trace has LockFreeMap<TESObjectREFR*, QueuedReference>)
find_xrefs_to(0x01016D20, "QueuedReference_RTTI_or_vtable")

# =====================================================================
# PART 3: The crash path: FUN_00930c70 (Actor processing)
# This reads ragdoll bone data. How does it get the pointer?
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_00930c70 — Actor processing reads ragdoll data")
write("#" * 70)

decompile_at(0x00930c70, "ActorProcess_CrashPath")
find_calls_from(0x00930c70, "ActorProcess_CrashPath")

# =====================================================================
# PART 4: FUN_00c79680 (skeleton update, immediate caller of crash)
# Reads *(param_1 + 0xa4) for bone array, then bone+0x34 for transform
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00c79680 — skeleton update, reads bone array")
write("#" * 70)

decompile_at(0x00c79680, "SkeletonUpdate_ReadsBoneArray")

# =====================================================================
# PART 5: bhkRagdollController vtable (0x010C4DDC from crash)
# Find destructor — when does ragdoll get destroyed?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: bhkRagdollController — vtable and destructor")
write("#" * 70)

read_vtable(0x010C4DDC, "bhkRagdollController", 8)

# Destructor is typically vtable[0]
ragdoll_dtor = getInt(toAddr(0x010C4DDC)) & 0xFFFFFFFF
if ragdoll_dtor != 0:
	decompile_at(ragdoll_dtor, "bhkRagdollController_Dtor")
	find_xrefs_to(ragdoll_dtor, "bhkRagdollController_Dtor_callers")

# =====================================================================
# PART 6: Queue dispatch — 0x0045211D area (from crash stack)
# How does the game dispatch QueuedCharacter processing?
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: Queue dispatch — 0x00452100 area")
write("#" * 70)

decompile_at(0x00452100, "QueueDispatch_Area")
find_calls_from(0x00452100, "QueueDispatch_Area")

# =====================================================================
# PART 7: FUN_0056f8d0 area — reference processing bridge
# Between dispatch and actor processing
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: Reference processing bridge — 0x0056f8d4 area")
write("#" * 70)

decompile_at(0x0056f8d0, "RefProcessing_Bridge")
find_calls_from(0x0056f8d0, "RefProcessing_Bridge")

# =====================================================================
# PART 8: IOManager main-thread processing (FUN_00c3dbf0)
# Phase 3 of frame loop. What conditions must hold for processing?
# Can we add validation before dispatch?
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: IOManager main-thread processing — Phase 3")
write("#" * 70)

decompile_at(0x00c3dbf0, "IOManager_MainThread")
find_calls_from(0x00c3dbf0, "IOManager_MainThread")

# =====================================================================
# PART 9: FUN_00c3e420 — IOManager dequeue completed task
# This is the function that dequeues tasks for main-thread processing
# What task state transitions happen here?
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: IOManager dequeue completed tasks for main thread")
write("#" * 70)

decompile_at(0x00c3e420, "IOManager_DequeueCompleted")
find_calls_from(0x00c3e420, "IOManager_DequeueCompleted")

# =====================================================================
# PART 10: NiNode PDD queue 0x08 — what destroys ragdoll?
# FUN_00418d20 is the destructor for queue 0x08 items
# Does it free bhkRagdollController bone data?
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: NiNode PDD destructor — frees ragdoll via tree?")
write("#" * 70)

decompile_at(0x00418d20, "NiNode_PDD_Dtor_Queue08")
find_calls_from(0x00418d20, "NiNode_PDD_Dtor_Queue08")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/queuedcharacter_ragdoll_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
