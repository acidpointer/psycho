# @category Analysis
# @description Find ALL code paths that access the Havok broadphase
# during AI execution. The broadphase is at world+0x58.
# We need to find:
# 1. Which vtable calls from actor processing reach broadphase add/remove
# 2. Whether the main thread's parallel work touches broadphase
# 3. Which actor vtable offsets (0x25c, 0x2b8, 0x348, etc) lead to Havok
# 4. FUN_00c3e1b0 (hkWorld step) -- does it run during AI?
# 5. What bhkWorld functions access broadphase without locking?

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
		if count > 50:
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
write("BROADPHASE ACCESS DURING AI EXECUTION")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Actor vtable+0x25c -- called by main thread FUN_0096bcd0")
write("# during AI parallel work. What does it do?")
write("# Also vtable+0x350 (called conditionally)")
write("#" * 70)

# We can't directly decompile vtable calls, but we can find the
# concrete implementations. For Character (most common actor type),
# the vtable is at the Character class RTTI.
# Character vtable entries can be found from the class.

# FUN_00966f20 -- called from AIWorker_Process1, processes actors
decompile_at(0x00966f20, "ProcessActor_FUN_00966f20")
find_and_print_calls_from(0x00966f20, "ProcessActor_FUN_00966f20")

# FUN_00967350 -- called from AIWorker_Process1
decompile_at(0x00967350, "ProcessActor_FUN_00967350")
find_and_print_calls_from(0x00967350, "ProcessActor_FUN_00967350")

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_008c8bb0 and FUN_008c8bd0")
write("# Called at start of AI processing. Setup functions?")
write("#" * 70)

decompile_at(0x008c8bb0, "AISetup_FUN_008c8bb0")
decompile_at(0x008c8bd0, "AISetup_FUN_008c8bd0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_008c3c40 -- called by main thread FUN_009784c0")
write("# during AI. Actor processing with 2 char params.")
write("#" * 70)

decompile_at(0x008c3c40, "MainDuringAI_ProcessActor_FUN_008c3c40", 10000)
find_and_print_calls_from(0x008c3c40, "MainDuringAI_ProcessActor_FUN_008c3c40")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Havok entity add from Bethesda game code")
write("# FUN_00c674d0 calls addEntity. Who calls FUN_00c674d0?")
write("# Trace the full call chain to find if it reaches AI code")
write("#" * 70)

decompile_at(0x00c674d0, "BethesdaAddEntity_FUN_00c674d0")
find_refs_to(0x00c674d0, "BethesdaAddEntity")

# Trace one level deeper for each caller
decompile_at(0x00c67b20, "AddEntity_via_FUN_00c67b20")
find_refs_to(0x00c67b20, "AddEntity_via_callers")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00c97f80 calls addEntity -- trace callers")
write("#" * 70)

decompile_at(0x00c97f80, "AddEntity_via_FUN_00c97f80")
find_refs_to(0x00c97f80, "AddEntity_via_FUN_00c97f80_callers")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_00888970 -- called by AIWorker_Process2")
write("# What does it do? Physics related?")
write("#" * 70)

decompile_at(0x00888970, "AIWorker2_FUN_00888970")
find_and_print_calls_from(0x00888970, "AIWorker2_FUN_00888970")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_0087af50 -- called by FUN_004772f0 (AI worker)")
write("# Animation/physics update during AI")
write("#" * 70)

decompile_at(0x0087af50, "AIWorker_AnimPhys_FUN_0087af50", 10000)
find_and_print_calls_from(0x0087af50, "AIWorker_AnimPhys_FUN_0087af50")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_008e51b0 -- called by FUN_0096db30 (AI worker)")
write("# Actor process update during physics step")
write("#" * 70)

decompile_at(0x008e51b0, "AIWorker_PhysProcess_FUN_008e51b0", 10000)
find_and_print_calls_from(0x008e51b0, "AIWorker_PhysProcess_FUN_008e51b0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: bhkWorld step -- FUN_00c3dfa0")
write("# This calls hkWorld_Step (FUN_00c3e1b0)")
write("# Who calls FUN_00c3dfa0 and when?")
write("#" * 70)

decompile_at(0x00c3dfa0, "bhkWorld_Step")
find_refs_to(0x00c3dfa0, "bhkWorld_Step")

# Trace callers of the step function
decompile_at(0x00448420, "StepCaller_FUN_00448420")
find_refs_to(0x00448420, "StepCaller_callers")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: FUN_00c468c0 and FUN_00c74550")
write("# Called by FUN_00453550 (AI worker cell management)")
write("# These set Havok world gravity/parameters")
write("#" * 70)

decompile_at(0x00c468c0, "HavokSetGravity_FUN_00c468c0")
decompile_at(0x00c74550, "HavokSetParam_FUN_00c74550")

# ===================================================================
write("")
write("#" * 70)
write("# PART 11: FUN_0096e3c0 -- called from AIWorker_Process1")
write("# When distance check fails. Physics related?")
write("#" * 70)

decompile_at(0x0096e3c0, "AIWorker_DistCheck_FUN_0096e3c0")
find_and_print_calls_from(0x0096e3c0, "AIWorker_DistCheck_FUN_0096e3c0")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/broadphase_access_during_ai.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
