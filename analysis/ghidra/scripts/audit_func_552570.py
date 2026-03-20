# @category Analysis
# @description Research FUN_00552570 — called from our hook position
# when multi-threaded. Could be AI thread sync barrier.
# If it waits for AI threads to complete, our hook IS safe for
# cell unloading after this call.

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
						write("  CALL 0x%s -> %s" % (to_addr, tname))
						count += 1
			addr_iter = addr_iter.next()
	write("  Total unique calls: %d" % count)

write("=" * 70)
write("FUN_00552570 — AI SYNC OR NOT?")
write("=" * 70)
write("")
write("Called from our hook target FUN_008705d0 when multi-threaded.")
write("If this waits for AI threads, our cell unloading is safe.")

# Section 1: FUN_00552570 full decompile
write("")
write("#" * 70)
write("# SECTION 1: FUN_00552570 full decompile + call graph")
write("#" * 70)

decompile_at(0x00552570, "FUN_00552570")
find_xrefs_to(0x00552570, "FUN_00552570")
find_xrefs_from(0x00552570, "FUN_00552570")

# Section 2: Our hook target — full decompile to see call order
write("")
write("#" * 70)
write("# SECTION 2: FUN_008705d0 (our hook) — what calls FUN_00552570?")
write("#" * 70)

decompile_at(0x008705D0, "OurHookTarget_008705d0")
find_xrefs_from(0x008705D0, "OurHookTarget_008705d0")

# Section 3: Subcalls of FUN_00552570
write("")
write("#" * 70)
write("# SECTION 3: Deep dive into FUN_00552570 subcalls")
write("#" * 70)

# Section 4: FUN_0086f640, FUN_0086f890, FUN_0086f670
# These are the other functions called from our hook target
write("")
write("#" * 70)
write("# SECTION 4: Other functions in our hook target")
write("#" * 70)

decompile_at(0x0086F640, "FUN_0086f640_PreHook")
decompile_at(0x0086F890, "FUN_0086f890_MidHook")
decompile_at(0x0086F670, "FUN_0086f670_PostHook")

# Section 5: AI barrier functions for comparison
write("")
write("#" * 70)
write("# SECTION 5: Known AI barrier functions for pattern matching")
write("#" * 70)

decompile_at(0x008C79E0, "AI_SetBarrier")
decompile_at(0x008C7A70, "AI_WaitBarrier")
decompile_at(0x00442550, "AI_ThreadSync_00442550")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_func_552570.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
