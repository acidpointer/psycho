# @category Analysis
# @description Trace combat detection and hit processing paths.
# Symptoms: enemies don't react, bullets do nothing, VATS works.
# Need to understand:
# 1. What function handles actor perception/detection (can actor see player)?
# 2. What function processes weapon hit/damage?
# 3. What does FUN_008880C3 do (from the crash stack)?
# 4. What does FUN_005672B4 do (from the crash stack)?
# 5. What does FUN_00493686 do (from the crash stack)?
# 6. What does FUN_005F2F98 do (from the crash stack)?
# 7. FUN_008380AA and FUN_0083876A (deeper in crash stack)
# 8. FUN_0062127A (crash site) - what does it access?

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
write("COMBAT DETECTION + HIT PROCESSING ANALYSIS")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Crash stack functions from AI Thread 1 combat crash")
write("#" * 70)

decompile_at(0x0062127A, "CrashSite_0062127A")
decompile_at(0x0083876A, "CrashCaller1_0083876A")
decompile_at(0x008380AA, "CrashCaller2_008380AA", 10000)
decompile_at(0x005F2F98, "CrashCaller3_005F2F98", 10000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_00493686 and FUN_005672B4 -- animation/combat?")
write("#" * 70)

decompile_at(0x00493686, "AnimCombat_00493686")
decompile_at(0x005672B4, "AnimCombat_005672B4")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_008880C3 -- called from AI worker during combat")
write("# This is inside FUN_0096cda0's actor processing")
write("#" * 70)

decompile_at(0x008880C3, "AIWorkerCombat_008880C3")
find_and_print_calls_from(0x008880C3, "AIWorkerCombat")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_0096CD92 -- inside FUN_0096cca0 (actor iteration)")
write("# What vtable call is at this address?")
write("#" * 70)

decompile_at(0x0096CD92, "ActorIteration_0096CD92")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: AI combat perception -- how does AI detect player?")
write("# FUN_008a0d10 is called from AIWorker_Process1")
write("# FUN_008b06d0 is also called from there")
write("#" * 70)

decompile_at(0x008a0d10, "AIPerception_008a0d10", 10000)
decompile_at(0x008b06d0, "AICombatDecision_008b06d0", 10000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Weapon hit detection")
write("# What processes projectile hits?")
write("#" * 70)

# FUN_005ae270 and FUN_005a9d60 are called at the END of AI execution
# These might be hit processing
decompile_at(0x005ae270, "AIEndPhase_005ae270")
decompile_at(0x005a9d60, "AIEndPhase_005a9d60")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_00888970 -- called from AIWorker_Process2")
write("# Actor state update during AI?")
write("#" * 70)

decompile_at(0x00888970, "ActorStateUpdate_00888970", 10000)
find_and_print_calls_from(0x00888970, "ActorStateUpdate")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Process manager actor iteration")
write("# FUN_00978550 is called at Phase 5 with process manager lock")
write("# What does it do to actors?")
write("#" * 70)

decompile_at(0x00978550, "ProcessMgr_00978550", 10000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_0096e3c0 -- distance check from AIWorker_Process1")
write("# Called when actor is far from player. Affects detection?")
write("#" * 70)

decompile_at(0x0096e3c0, "AIDistanceCheck_0096e3c0")
find_and_print_calls_from(0x0096e3c0, "AIDistanceCheck")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: HeapCompact stage 4 - PDD with TryAcquire")
write("# Does stage 4 PDD modify actor state that AI reads?")
write("# FUN_00868d70 is PDD. What actors does it destroy?")
write("#" * 70)

decompile_at(0x00868d70, "PDD_FUN_00868d70", 10000)
find_and_print_calls_from(0x00868d70, "PDD")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/combat_detection_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
