# @category Analysis
# @description Find vanilla callsites where FUN_008324e0 is called as a stop/start pair, and examine the code between them.
#
# Questions this answers:
#  Q1. Does vanilla always pair mode=0 (stop) with mode=1 (start), or are
#      there lone calls?
#  Q2. What does the game do BETWEEN a stop(0) and start(1) pair? (This
#      tells us what operations are considered unsafe while PPL is active.)
#  Q3. Is there a pattern like "stop(0); free_havok_data; start(1)"? If
#      yes, that confirms our plan to wrap Stage 4 the same way.
#
# Why this matters:
#  Our plan is to wrap run_oom_stage(4) with stop_havok_drain() + nothing
#  (assume PPL resumes naturally). If vanilla never does that -- if vanilla
#  always pairs with a matching start_havok() call -- we may need to add
#  start_havok() after our Stage 4 call too.

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

def collect_callers(addr_int):
	# Returns list of (from_addr_int, containing_func_addr_int)
	out = []
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		src = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fentry = from_func.getEntryPoint().getOffset() if from_func else 0
		out.append((src, fentry))
	return out

def print_callers(addr_int, label):
	write("")
	write("-" * 70)
	write("Callers of %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	callers = collect_callers(addr_int)
	if not callers:
		write("  [no callers found]")
		return
	for item in callers:
		src = item[0]
		fentry = item[1]
		func = fm.getFunctionAt(toAddr(fentry)) if fentry else None
		fname = func.getName() if func else "???"
		write("  0x%08x in %s @ 0x%08x" % (src, fname, fentry))
	write("  Total callers: %d" % len(callers))

def find_caller_funcs_with_both_modes(addr_int, label):
	# A function that calls FUN_008324e0 TWICE (once per mode) is a
	# stop/start pair -- that's the protocol pattern we want to learn.
	write("")
	write("-" * 70)
	write("Callers of %s that invoke it multiple times (stop/start pairs)" % label)
	write("-" * 70)
	callers = collect_callers(addr_int)
	counts = {}
	for item in callers:
		fentry = item[1]
		if fentry == 0:
			continue
		counts[fentry] = counts.get(fentry, 0) + 1
	multi = []
	for fentry in counts:
		if counts[fentry] >= 2:
			multi.append((fentry, counts[fentry]))
	if not multi:
		write("  [no function calls %s more than once]" % label)
		return []
	for item in multi:
		fentry = item[0]
		cnt = item[1]
		func = fm.getFunctionAt(toAddr(fentry))
		fname = func.getName() if func else "???"
		write("  %s @ 0x%08x -- %d calls" % (fname, fentry, cnt))
	write("  Total: %d functions call it multiple times" % len(multi))
	return multi

def decompile_pair_callers(multi, target_addr, label):
	# For each function that calls target more than once, decompile it so
	# we can see the stop/start protocol and what happens between them.
	write("")
	write("######################################################################")
	write("# Decompiled stop/start pair containers for %s" % label)
	write("######################################################################")
	for item in multi:
		fentry = item[0]
		cnt = item[1]
		decompile_at(fentry, "Pair container (%d calls)" % cnt, max_len=10000)

# --- Main body ---

write("######################################################################")
write("# Vanilla stop_havok_drain + start_havok protocol")
write("######################################################################")
write("")
write("Find vanilla code that calls FUN_008324e0 (HavokStopStart) and")
write("examine whether mode=0 and mode=1 are paired. Read the code between")
write("a pair to learn what vanilla considers 'unsafe while PPL is active'.")

print_callers(0x008324E0, "HavokStopStart")

pair_list = find_caller_funcs_with_both_modes(0x008324E0, "HavokStopStart")
decompile_pair_callers(pair_list, 0x008324E0, "HavokStopStart")

# Also look at the outer-loop / main-loop area to see if there's a
# stop/start around cell destruction (FUN_0086B3E8 region per prior Ghidra
# output).
decompile_at(0x0086B3E8, "Main loop tail (context for cell-destruction protocol)", max_len=4000)

# --- Output ---

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/vanilla_stop_start_protocol.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
