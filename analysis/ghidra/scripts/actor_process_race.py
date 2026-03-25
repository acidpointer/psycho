# @category Analysis
# @description Trace the actor process (HighProcess) lifecycle and
# concurrent access from main thread and AI workers.
# The crash was at FUN_009306d0(actor) + 0x410 -> FUN_00621270.
# We need to understand:
# 1. What is FUN_009306d0? What does it return (HighProcess pointer)?
# 2. Who modifies/frees HighProcess? From which thread?
# 3. What is the actor process downgrade path (High->Medium->Low)?
# 4. Does process downgrade happen during AI execution?
# 5. What is the process manager lock (DAT_011f11a0) role in this?
# 6. FUN_00978550 (Phase 5 with process mgr lock) -- does it downgrade?

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
write("ACTOR PROCESS RACE CONDITION ANALYSIS")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_009306d0 -- returns actor's process (HighProcess?)")
write("# Called before accessing +0x410 which crashed")
write("#" * 70)

decompile_at(0x009306d0, "GetActorProcess_009306d0")
find_refs_to(0x009306d0, "GetActorProcess")

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_008d8520 -- also gets process, called by AI worker")
write("# and main thread parallel work. Same or different?")
write("#" * 70)

decompile_at(0x008d8520, "GetProcess2_008d8520")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Actor process set/change -- who sets the process?")
write("# Look for writes to actor+0x1D0 or wherever process ptr is")
write("#" * 70)

# FUN_00931850 -- checks if actor has process? Called from many places
decompile_at(0x00931850, "HasProcess_00931850")

# FUN_008d6f30 -- another process accessor, called from AI worker
decompile_at(0x008d6f30, "GetProcess3_008d6f30")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Process downgrade -- High to Medium to Low")
write("# When does the game change actor process level?")
write("#" * 70)

# FUN_008c8fd0 -- called by main thread during AI (FUN_0096bcd0)
# This was identified as process-manager related
decompile_at(0x008c8fd0, "ProcessChange_008c8fd0")
find_refs_to(0x008c8fd0, "ProcessChange")

# FUN_008c3c40 -- called by main thread FUN_009784c0 during AI
decompile_at(0x008c3c40, "ProcessUpdate_008c3c40", 10000)
find_and_print_calls_from(0x008c3c40, "ProcessUpdate")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Process manager lock (DAT_011f11a0)")
write("# Phase 5 acquires, Phase 6 releases. What happens between?")
write("# FUN_00978550 runs with lock held.")
write("#" * 70)

decompile_at(0x00978550, "ProcessMgr_WithLock_00978550", 10000)
find_and_print_calls_from(0x00978550, "ProcessMgr_WithLock")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Actor process creation/destruction")
write("# HighProcess RTTI at 0x01087864 (from crash data)")
write("#" * 70)

find_refs_to(0x01087864, "HighProcess_RTTI")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_0096e870 -- called by main thread FUN_0096bcd0")
write("# during AI when actor is flagged for downgrade")
write("#" * 70)

decompile_at(0x0096e870, "ActorDowngrade_0096e870")
find_and_print_calls_from(0x0096e870, "ActorDowngrade")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00977130 -- called at end of FUN_0096bcd0")
write("# After all actor processing. Commit changes?")
write("#" * 70)

decompile_at(0x00977130, "PostProcess_00977130")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_00975080 -- called at end of AI worker cell mgmt")
write("# FUN_00453550 calls this. Process manager related?")
write("#" * 70)

decompile_at(0x00975080, "AIEndCellMgmt_00975080")
find_and_print_calls_from(0x00975080, "AIEndCellMgmt")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: FUN_0096c7c0 -- called by main thread AFTER waiting")
write("# for AI worker steps 1 and 3. Calls vtable+0x2F8 on actors.")
write("# Does this modify actor state that AI worker reads?")
write("#" * 70)

decompile_at(0x0096c7c0, "MainPostWait_0096c7c0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 11: What is at actor offset for process pointer?")
write("# Need to find which offset in Actor stores the process ptr")
write("#" * 70)

# Character vtable -- from RTTI 0x01086A6C
find_refs_to(0x01086a6c, "Character_RTTI")

# The crash showed HighProcess at stack offset. Actor->GetProcess
# likely reads actor+some_offset to get HighProcess pointer.
# FUN_009306d0 will tell us.

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/actor_process_race.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
