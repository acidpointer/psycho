# @category Analysis
# @description Verify AI thread join safety.
# Our pressure relief calls FUN_008c7990 (AI join) before cell unloading.
# The game also calls it at 0x0086ee4e AFTER our hook.
# Could our extra join corrupt semaphore state or cause deadlock?
#
# Also: the crash is during Havok world step at FUN_00c3dbf0.
# Could previous frame's AI join + cell unload corrupt Havok state?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_xrefs_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	if func is None:
		return
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	body = func.getBody()
	count = 0
	seen = set()
	for rng in body:
		addr_iter = rng.getMinAddress()
		while addr_iter is not None and addr_iter.compareTo(rng.getMaxAddress()) <= 0:
			refs = getReferencesFrom(addr_iter)
			for ref in refs:
				if ref.getReferenceType().isCall():
					to_addr = ref.getToAddress()
					key = str(to_addr)
					if key not in seen:
						seen.add(key)
						target_func = fm.getFunctionAt(to_addr)
						tname = target_func.getName() if target_func else "???"
						write("  CALL 0x%s -> %s @ site 0x%s" % (to_addr, tname, ref.getFromAddress()))
						count += 1
			addr_iter = addr_iter.next()
	write("  Total: %d" % count)

write("=" * 70)
write("AI JOIN SAFETY + HAVOK WORLD STEP CRASH")
write("=" * 70)
write("")
write("Crash: FUN_00c3dbf0 (Havok step) -> JIP DoQueuedRefHook ->")
write("  ragdoll setup -> FUN_00a6df48 (CRASH, eax=garbage)")
write("  bhkWorldM corrupt, NPC Bittercup, QueuedCharacter on stack")
write("")
write("Question 1: Does our FUN_008c7990 call consume a semaphore")
write("  that the game's own join needs?")
write("Question 2: Does FUN_00c3dbf0 process queued references?")
write("Question 3: Could previous frame cell unload corrupt Havok?")

# SECTION 1: FUN_008c7990 (AI join) - semaphore mechanics
write("")
write("#" * 70)
write("# SECTION 1: FUN_008c7990 semaphore mechanics")
write("# What does it wait on? What does the AI thread signal?")
write("# Is the wait/signal pair consumed or reusable?")
write("#" * 70)

decompile_at(0x008C7990, "AIThreadJoin")
decompile_at(0x008C7490, "AIThreadJoin_PerThread")
decompile_at(0x004424E0, "WaitPrimitive_004424e0")
decompile_at(0x00442550, "SignalPrimitive_00442550")

# SECTION 2: What happens after our join in the frame?
write("")
write("#" * 70)
write("# SECTION 2: Game's own AI join at 0x0086ee4e")
write("# Disassembly around the join to understand the conditional")
write("#" * 70)

listing = currentProgram.getListing()
write("")
write("--- Disassembly 0x0086ee40 to 0x0086ee70 ---")
addr = toAddr(0x0086ee40)
end_addr = toAddr(0x0086ee70)
while addr.compareTo(end_addr) < 0:
	inst = listing.getInstructionAt(addr)
	if inst is not None:
		mnemonic = inst.getMnemonicString()
		ops = ""
		for i in range(inst.getNumOperands()):
			if i > 0:
				ops = ops + ", "
			ops = ops + inst.getDefaultOperandRepresentation(i)
		write("  0x%s  %s %s" % (addr, mnemonic, ops))
		addr = addr.add(inst.getLength())
	else:
		addr = addr.add(1)

# SECTION 3: FUN_00c3dbf0 - what IS this function?
write("")
write("#" * 70)
write("# SECTION 3: FUN_00c3dbf0 - called with DAT_01202d98 (Havok world)")
write("# Is it truly Havok step or does it do reference processing?")
write("#" * 70)

decompile_at(0x00C3DBF0, "HavokStep_or_Other_00c3dbf0", 12000)
find_xrefs_from(0x00C3DBF0, "HavokStep_or_Other_00c3dbf0")

# SECTION 4: The crash function and callers
write("")
write("#" * 70)
write("# SECTION 4: Crash site FUN_00a6df48 + ragdoll chain")
write("#" * 70)

decompile_at(0x00A6DF48, "CrashSite_00a6df48")
decompile_at(0x00C796F7, "Havok_Ragdoll_00c796f7")
decompile_at(0x00C7D866, "Havok_Ragdoll2_00c7d866")

# SECTION 5: FUN_0045211d - queued reference processing
write("")
write("#" * 70)
write("# SECTION 5: FUN_0045211d - what JIP hooks")
write("#" * 70)

decompile_at(0x0045211D, "QueuedRef_Process_0045211d")

# SECTION 6: Is FUN_008c80e0 (AI dispatch prep) state-dependent?
write("")
write("#" * 70)
write("# SECTION 6: AI dispatch condition - when are threads NOT dispatched?")
write("# If threads aren't dispatched, our join would be a no-op?")
write("#" * 70)

decompile_at(0x008C80E0, "AI_DispatchPrep_008c80e0")
decompile_at(0x008C78C0, "AI_Start_008c78c0")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/ai_join_safety.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
