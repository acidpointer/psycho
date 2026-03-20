# @category Analysis
# @description AUDIT: HeapCompact stages 0-5 detailed analysis.
# We trigger stages 0-2. What EXACTLY does each stage do?
# What are stages 3-5 that we excluded? Are stages 0-2 truly safe?
# FUN_00878080 is the HeapCompact entry point.

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
		write("  [function not found at 0x%08x]" % addr_int)
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
write("AUDIT: HEAPCOMPACT STAGES 0-5 DETAILED")
write("=" * 70)
write("")
write("HeapCompact entry: FUN_00878080")
write("Trigger: heap_singleton+0x134 (0x011F636C)")
write("We set trigger=2 (stages 0-2). What does each stage do?")

# Section 1: HeapCompact main function
write("")
write("#" * 70)
write("# SECTION 1: FUN_00878080 — HeapCompact entry (full decompile)")
write("#" * 70)

decompile_at(0x00878080, "HeapCompact_Main", 15000)
find_xrefs_from(0x00878080, "HeapCompact_Main")

# Section 2: Each stage's function
write("")
write("#" * 70)
write("# SECTION 2: Individual stage functions")
write("# HeapCompact calls different functions based on stage counter")
write("#" * 70)

# ProcessPendingCleanup — Stage 0
decompile_at(0x00452490, "ProcessPendingCleanup (Stage 0?)")

# ProcessDeferredDestruction — used by DeferredCleanupSmall
decompile_at(0x00868D70, "ProcessDeferredDestruction", 12000)

# Section 3: Where is HeapCompact called from?
write("")
write("#" * 70)
write("# SECTION 3: HeapCompact callers — when does the game run it?")
write("#" * 70)

addr = toAddr(0x00878080)
refs = getReferencesTo(addr)
write("")
write("Callers of HeapCompact (0x00878080):")
for ref in refs:
	from_addr = ref.getFromAddress()
	func = fm.getFunctionContaining(from_addr)
	fname = func.getName() if func else "???"
	write("  %s @ 0x%s in %s" % (ref.getReferenceType(), from_addr, fname))

# Section 4: The main loop structure around HeapCompact
write("")
write("#" * 70)
write("# SECTION 4: Main loop around HeapCompact (FUN_0086a850)")
write("# What runs before/after HeapCompact? AI dispatch? Render?")
write("#" * 70)

decompile_at(0x0086A850, "MainLoop (huge - first 15000 chars)", 15000)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_heapcompact_stages.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
