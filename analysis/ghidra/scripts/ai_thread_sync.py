# @category Analysis
# @description Analyze AI thread sync model and ProcessDeferredDestruction callers

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
	output.append("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > 6000:
			output.append(code[:6000])
		else:
			output.append(code)
	output.append("")

def get_xrefs_to(addr_int):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	result = []
	for ref in refs:
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		if from_func is not None:
			result.append(from_func.getEntryPoint().getOffset())
	return result

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
# PART 1: All callers of ProcessDeferredDestruction
# =====================================================================
output.append("=" * 70)
output.append("PART 1: CALLERS OF ProcessDeferredDestruction (0x00868D70)")
output.append("=" * 70)

deferred_callers = get_xrefs_to(0x00868D70)
output.append("Total xrefs: %d" % len(deferred_callers))
unique_deferred_callers = sorted(set(deferred_callers))
for ca in unique_deferred_callers:
	f = fm.getFunctionAt(toAddr(ca))
	n = "???"
	if f is not None:
		n = f.getName()
	output.append("  0x%08x %s" % (ca, n))

output.append("")
for ca in unique_deferred_callers:
	decompile_at(ca, "Caller of ProcessDeferredDestruction")

# =====================================================================
# PART 2: AI thread functions from crash callstack
# =====================================================================
output.append("")
output.append("=" * 70)
output.append("PART 2: AI THREAD FUNCTIONS (from crash callstack)")
output.append("=" * 70)

ai_addrs = [
	0x008C7764,
	0x008C71A8,
	0x008C7F89,
	0x0096C539,
	0x00888AE8,
	0x008E44DE,
	0x0088C49D,
]

for addr in ai_addrs:
	decompile_at(addr, "AI thread function")
	list_calls(addr, "0x%08x" % addr)

# =====================================================================
# PART 3: Does AI thread call GameHeap::Allocate?
# Check if any of the AI crash callstack functions call 0x00AA3E40
# =====================================================================
output.append("")
output.append("=" * 70)
output.append("PART 3: DO AI THREADS CALL GameHeap::Allocate?")
output.append("=" * 70)
output.append("")

gheap_alloc = 0x00AA3E40
gheap_alloc_callers = get_xrefs_to(gheap_alloc)
gheap_alloc_callers_set = set(gheap_alloc_callers)

# Check havok physics functions from crash stack
havok_addrs = [
	0x00CAFED5,
	0x00D2610B,
	0x00D16B3E,
	0x00CBF918,
	0x00C92006,
	0x00C698D7,
	0x00553F0E,
	0x004584A2,
	0x00458435,
]

output.append("Checking if Havok/AI functions call GameHeap::Allocate:")
for addr in havok_addrs:
	func = fm.getFunctionContaining(toAddr(addr))
	if func is None:
		output.append("  0x%08x [no function]" % addr)
	else:
		faddr = func.getEntryPoint().getOffset()
		calls = find_calls_from(faddr)
		has_alloc = False
		for c in calls:
			if c == gheap_alloc:
				has_alloc = True
		if has_alloc:
			output.append("  0x%08x %s -> CALLS GameHeap::Allocate" % (faddr, func.getName()))
		else:
			output.append("  0x%08x %s -> no direct call" % (faddr, func.getName()))

# Also check depth-2: do functions called by havok funcs call allocate?
output.append("")
output.append("Depth-2 check (functions called by Havok code that call allocate):")
for addr in havok_addrs:
	func = fm.getFunctionContaining(toAddr(addr))
	if func is None:
		pass
	else:
		faddr = func.getEntryPoint().getOffset()
		calls = find_calls_from(faddr)
		for c in calls:
			if c < 0x00401000 or c > 0x00F00000:
				pass
			else:
				sub_calls = find_calls_from(c)
				for sc in sub_calls:
					if sc == gheap_alloc:
						sf = fm.getFunctionAt(toAddr(c))
						sn = "???"
						if sf is not None:
							sn = sf.getName()
						output.append("  0x%08x -> 0x%08x %s -> GameHeap::Allocate" % (faddr, c, sn))

# =====================================================================
# PART 4: Where does the game naturally call ProcessDeferredDestruction
# outside of HeapCompact? (main loop locations)
# =====================================================================
output.append("")
output.append("=" * 70)
output.append("PART 4: MAIN LOOP CONTEXT FOR ProcessDeferredDestruction")
output.append("=" * 70)
output.append("")

# Decompile the main loop function that contains the maintenance section
decompile_at(0x0086E650, "MainLoop (FUN_0086e650)")
list_calls(0x0086E650, "MainLoop")

# Write output
text = "\n".join(output)
outpath = "/tmp/ai_thread_sync.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
