# @category Analysis
# @description Deep analysis of HeapCompact (0x00866a90) and cleanup call chain

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_at(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	output.append("")
	output.append("=" * 70)
	output.append("%s @ 0x%08x" % (label, addr_int))
	output.append("=" * 70)
	if func is None:
		output.append("  [function not found]")
		return
	output.append("  Size: %d bytes" % func.getBody().getNumAddresses())
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > 6000:
			output.append(code[:6000])
		else:
			output.append(code)
	output.append("")

def find_calls_from(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return []
	called = []
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				called.append(ref.getToAddress().getOffset())
	return called

def list_calls(addr_int, label):
	calls = find_calls_from(addr_int)
	unique = sorted(set(calls))
	output.append("--- %s calls %d unique functions ---" % (label, len(unique)))
	for t in unique:
		f = fm.getFunctionAt(toAddr(t))
		n = "???"
		if f is not None:
			n = f.getName()
		output.append("  -> 0x%08x %s" % (t, n))
	return unique

# =====================================================================
output.append("DEEP ANALYSIS OF HEAP COMPACT / CLEANUP CHAIN")
output.append("=" * 70)

# --- Depth 0: HeapCompact ---
decompile_at(0x00866a90, "HeapCompact (depth=0)")
depth0_calls = list_calls(0x00866a90, "HeapCompact")

# --- Depth 1: everything HeapCompact calls ---
output.append("")
output.append("=" * 70)
output.append("DEPTH 1: Functions called by HeapCompact")
output.append("=" * 70)

depth1_visited = set()
depth1_all_calls = []
for t in depth0_calls:
	if t < 0x00401000 or t > 0x00F00000:
		pass
	elif t not in depth1_visited:
		depth1_visited.add(t)
		decompile_at(t, "depth=1")
		sub_calls = list_calls(t, "0x%08x" % t)
		for s in sub_calls:
			depth1_all_calls.append(s)

# --- Depth 2: everything depth-1 calls ---
output.append("")
output.append("=" * 70)
output.append("DEPTH 2: Functions called by depth-1")
output.append("=" * 70)

depth2_visited = set()
for t in depth1_all_calls:
	if t < 0x00401000 or t > 0x00F00000:
		pass
	elif t in depth1_visited:
		pass
	elif t in depth2_visited:
		pass
	elif t == 0x00866a90:
		pass
	else:
		depth2_visited.add(t)
		decompile_at(t, "depth=2")
		list_calls(t, "0x%08x" % t)

# =====================================================================
# Additional maintenance functions
# =====================================================================
output.append("")
output.append("=" * 70)
output.append("ADDITIONAL: Maintenance functions left alive in patches")
output.append("=" * 70)

decompile_at(0x00AA6F90, "PurgeUnusedArenas")
decompile_at(0x00AA7290, "DecrementArenaRef")
decompile_at(0x00AA7300, "ReleaseArenaByPtr")
decompile_at(0x00AA68A0, "SBM_ResetStats")

# =====================================================================
# Callers of HeapCompact
# =====================================================================
output.append("")
output.append("=" * 70)
output.append("CALLERS OF HeapCompact (0x00866a90)")
output.append("=" * 70)

refs = ref_mgr.getReferencesTo(toAddr(0x00866a90))
for ref in refs:
	from_addr = ref.getFromAddress()
	from_func = fm.getFunctionContaining(from_addr)
	fname = "unknown"
	faddr = 0
	if from_func is not None:
		fname = from_func.getName()
		faddr = from_func.getEntryPoint().getOffset()
	output.append("  0x%08x in %s (0x%08x)" % (from_addr.getOffset(), fname, faddr))

# =====================================================================
# TLS notes
# =====================================================================
output.append("")
output.append("=" * 70)
output.append("THREAD-LOCAL STATE in heap functions")
output.append("=" * 70)
output.append("")
output.append("GameHeap::Allocate reads TLS[_tls_index + 0x2b4]")
output.append("to select a per-thread allocator pool.")
output.append("If HeapCompact touches this TLS state, calling from")
output.append("a non-game thread would crash on null/garbage TLS data.")

# Write
text = "\n".join(output)
outpath = "/tmp/deep_heap_compact.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
