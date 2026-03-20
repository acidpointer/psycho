# @category Analysis
# @description Find the AI thread join point in the main loop.
# Goal: Find where AI threads are guaranteed idle so we can
# either move our hook there or add a wait before cell unloading.
#
# Known: AI dispatch uses barrier stages 0-11 via FUN_008c79e0/008c7a70
# Known: Our hook is at FUN_008705d0 (called @ 0x0086edf0 in FUN_0086e650)
# Need: Where in FUN_0086e650 does AI dispatch happen? Where is AI join?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=15000):
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

def find_xrefs_to(addr_int, label, limit=20):
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
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

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
						write("  CALL 0x%s -> %s @ call_site 0x%s" % (to_addr, tname, ref.getFromAddress()))
						count += 1
			addr_iter = addr_iter.next()
	write("  Total unique calls: %d" % count)

write("=" * 70)
write("AI THREAD JOIN POINT ANALYSIS")
write("=" * 70)
write("")
write("Need to find WHERE in the per-frame function AI threads are idle.")
write("Our hook is at 0x008705d0, called @ 0x0086edf0 in FUN_0086e650.")
write("AI dispatch FUN_008c7e30 must be called somewhere in this frame.")
write("AI wait FUN_008c7a70 must also be called to join AI threads.")

# SECTION 1: FUN_0086e650 — the per-frame function (FULL call graph with sites)
write("")
write("#" * 70)
write("# SECTION 1: FUN_0086e650 full call graph WITH call site addresses")
write("# This lets us determine ORDER of calls within the function")
write("#" * 70)

decompile_at(0x0086E650, "PerFrame_FUN_0086e650", 30000)
find_xrefs_from(0x0086E650, "PerFrame_FUN_0086e650")

# SECTION 2: AI dispatch — where is it called from in FUN_0086e650?
write("")
write("#" * 70)
write("# SECTION 2: Who calls AI dispatch (FUN_008c7e30)?")
write("# Need to find the call site within FUN_0086e650 or its children")
write("#" * 70)

find_xrefs_to(0x008C7E30, "AI_Dispatch_008c7e30")

# Also check AI wait
find_xrefs_to(0x008C7A70, "AI_WaitBarrier_008c7a70")

# SECTION 3: AI dispatch internals — which barrier stage means "all done"?
write("")
write("#" * 70)
write("# SECTION 3: AI dispatch (FUN_008c7e30) — full barrier sequence")
write("# Which barrier stage means AI threads are idle?")
write("#" * 70)

decompile_at(0x008C7E30, "AI_Dispatch_008c7e30", 15000)
find_xrefs_from(0x008C7E30, "AI_Dispatch_008c7e30")

# SECTION 4: FUN_0086f6a0 — also calls FUN_00552570, what else?
write("")
write("#" * 70)
write("# SECTION 4: FUN_0086f6a0 — parent of FUN_00552570 second caller")
write("# Is this part of the frame sequence?")
write("#" * 70)

decompile_at(0x0086F6A0, "FUN_0086f6a0")
find_xrefs_to(0x0086F6A0, "FUN_0086f6a0")
find_xrefs_from(0x0086F6A0, "FUN_0086f6a0")

# SECTION 5: The functions around our hook in FUN_0086e650
# We know our hook is at 0x0086edf0. What's at 0x0086eac9 (HeapCompact)?
# What's between them? Is AI dispatch between?
write("")
write("#" * 70)
write("# SECTION 5: Functions called between HeapCompact and our hook")
write("# HeapCompact @ 0x0086eac9, our hook @ 0x0086edf0")
write("# What happens in between? Does AI dispatch run here?")
write("#" * 70)

# Read raw disassembly between these two points to see call sequence
listing = currentProgram.getListing()
write("")
write("--- Disassembly from 0x0086eac0 to 0x0086ee20 ---")
addr = toAddr(0x0086eac0)
end_addr = toAddr(0x0086ee20)
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

# SECTION 6: AI thread entry — what barrier does it wait on?
write("")
write("#" * 70)
write("# SECTION 6: AI thread work loop — barrier wait pattern")
write("#" * 70)

decompile_at(0x008C7764, "AI_ThreadWorkLoop_008c7764")
decompile_at(0x008C7720, "AI_ThreadInner_008c7720")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_ai_join_point.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
