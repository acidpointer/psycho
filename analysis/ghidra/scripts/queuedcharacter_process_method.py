# @category Analysis
# @description Analyze QueuedCharacter Process method (vtable[5] = 0x0043fdf0)
# and the full chain to ragdoll crash. Need to find validation points.

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


write("=" * 70)
write("QueuedCharacter Process Method + Ragdoll Validation Points")
write("=" * 70)

# =====================================================================
# PART 1: QueuedCharacter Process method = vtable[5] = FUN_0043fdf0
# This is called from IOManager main-thread processing via vtable+0x14
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: QueuedCharacter Process method (vtable[5])")
write("#" * 70)

decompile_at(0x0043fdf0, "QueuedCharacter_Process_vtable5")
find_calls_from(0x0043fdf0, "QueuedCharacter_Process_vtable5")

# =====================================================================
# PART 2: QueuedCharacter constructor (FUN_00441440, writes vtable)
# How is the Character reference stored? What offset?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: QueuedCharacter constructor (FUN_00441440)")
write("#" * 70)

decompile_at(0x00441440, "QueuedCharacter_Ctor")
find_calls_from(0x00441440, "QueuedCharacter_Ctor")
find_xrefs_to(0x00441440, "QueuedCharacter_Ctor_callers")

# =====================================================================
# PART 3: FUN_0043fcd0 - gets NiNode (3D model) from Character
# This is the function that returns the NiNode pointer used by
# ragdoll update. If NiNode is freed, this returns stale pointer.
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_0043fcd0 - get NiNode from Character")
write("#" * 70)

decompile_at(0x0043fcd0, "GetNiNode_FromCharacter")

# =====================================================================
# PART 4: FUN_00c6c210 - ragdoll controller update
# Called from FUN_00930c70 line 160. Does it validate anything?
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00c6c210 - ragdoll controller update entry")
write("#" * 70)

decompile_at(0x00c6c210, "RagdollController_Update")
find_calls_from(0x00c6c210, "RagdollController_Update")

# =====================================================================
# PART 5: FUN_00c7d900 - ragdoll cleanup (called by destructor)
# What does it free? Does it NULL the bone array pointer?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00c7d900 - ragdoll cleanup before free")
write("#" * 70)

decompile_at(0x00c7d900, "RagdollCleanup_BeforeFree")
find_calls_from(0x00c7d900, "RagdollCleanup_BeforeFree")

# =====================================================================
# PART 6: FUN_0056f700 - called from queue dispatch (0x00452118)
# This calls FUN_00930c70. What checks does it do BEFORE calling?
# Can we hook HERE to validate the Character/NiNode state?
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: Who calls FUN_00930c70? Find all callers")
write("#" * 70)

find_xrefs_to(0x00930c70, "ActorProcess_CrashPath_callers")

# =====================================================================
# PART 7: FUN_00c7d810 - who calls the immediate crash function?
# Can we hook at this level?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: Who calls FUN_00c7d810 (ragdoll update)?")
write("#" * 70)

find_xrefs_to(0x00c7d810, "RagdollUpdate_callers")

# =====================================================================
# PART 8: FUN_009306d0 - called early in FUN_00930c70
# At line 196: local_74 = FUN_009306d0(local_28)
# If this returns non-null, the ragdoll update path is taken.
# If null, a NEW ragdoll is created. What does this function check?
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_009306d0 - ragdoll existence check")
write("#" * 70)

decompile_at(0x009306d0, "CheckExistingRagdoll")
find_calls_from(0x009306d0, "CheckExistingRagdoll")

# =====================================================================
# PART 9: FUN_0048fb50 - NiNode PDD destructor inner
# Called by FUN_00418d20. Does it detach ragdoll? Free bone data?
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_0048fb50 - NiNode PDD destructor inner")
write("#" * 70)

decompile_at(0x0048fb50, "NiNode_PDD_Inner")
find_calls_from(0x0048fb50, "NiNode_PDD_Inner")

# =====================================================================
# PART 10: IOManager vtable callback at +0x14
# The main thread calls vtable+0x14 on each completed task.
# Is this always FUN_0043fdf0 for QueuedCharacter?
# Can we hook the IOManager dispatch point instead?
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: IOManager completed task dispatch")
write("# vtable+0x14 is the Process callback")
write("#" * 70)

# The dispatch is: (**(code **)(*local_14 + 0x14))()
# local_14 is the task pointer. *local_14 is vtable. vtable+0x14 is Process.
# For QueuedCharacter: vtable[5] = +0x14 = FUN_0043fdf0

# FUN_00c3e490 - the actual dequeue function
decompile_at(0x00c3e490, "IOManager_ActualDequeue")
find_calls_from(0x00c3e490, "IOManager_ActualDequeue")


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/queuedcharacter_process_method.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
