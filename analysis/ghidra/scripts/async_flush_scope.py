# @category Analysis
# @description Deep dive into what AsyncQueueFlush actually drains

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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
write("ASYNC FLUSH SCOPE ANALYSIS")
write("=" * 70)

# SECTION 1: DeferredCleanupSmall call graph
write("")
write("#" * 70)
write("# SECTION 1: DeferredCleanupSmall 0x00878250 call graph")
write("#" * 70)

decompile_at(0x00878250, "DeferredCleanupSmall", 10000)
find_xrefs_from(0x00878250, "DeferredCleanupSmall")

# SECTION 2: AsyncQueueFlush internals
write("")
write("#" * 70)
write("# SECTION 2: AsyncQueueFlush 0x00C459D0 subcalls")
write("#" * 70)

decompile_at(0x00C459D0, "AsyncQueueFlush")
find_xrefs_from(0x00C459D0, "AsyncQueueFlush")
decompile_at(0x00C46080, "AsyncFlush_Inner1", 10000)
find_xrefs_from(0x00C46080, "AsyncFlush_Inner1")
decompile_at(0x00C45A80, "AsyncFlush_Inner2", 10000)

# SECTION 3: CellLoader vs IOManager queue
write("")
write("#" * 70)
write("# SECTION 3: CellLoader entry points")
write("#" * 70)

decompile_at(0x00527C00, "CellLoader_Entry1")
decompile_at(0x00528600, "CellLoader_Main", 10000)

# SECTION 4: CellTransitionHandler
write("")
write("#" * 70)
write("# SECTION 4: CellTransitionHandler 0x008774A0")
write("#" * 70)

decompile_at(0x008774A0, "CellTransitionHandler", 12000)

# SECTION 5: PreDestructionSetup subcalls
write("")
write("#" * 70)
write("# SECTION 5: PreDestructionSetup 0x00878160 subcalls")
write("#" * 70)

decompile_at(0x00878160, "PreDestructionSetup", 6000)
find_xrefs_from(0x00878160, "PreDestructionSetup")

decompile_at(0x00878200, "PostDestructionRestore", 6000)
find_xrefs_from(0x00878200, "PostDestructionRestore")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/async_flush_scope.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
