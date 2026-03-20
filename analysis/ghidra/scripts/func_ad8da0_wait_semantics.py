# @category Analysis
# @description Research FUN_00ad8da0 - the actual IO wait/drain function
# Called as FUN_00ad8da0(TES+0x77c, 1000) by FUN_00877700
# Need: return value semantics, timeout behavior, what it waits on

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
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)

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
write("FUN_00ad8da0 WAIT SEMANTICS")
write("=" * 70)
write("")
write("Called as: FUN_00ad8da0(TES+0x77c, 1000)")
write("Need: what it waits on, return value, can we use timeout=0?")

# SECTION 1: FUN_00ad8da0 itself
write("")
write("#" * 70)
write("# SECTION 1: FUN_00ad8da0 full decompile")
write("#" * 70)

decompile_at(0x00AD8DA0, "FUN_00ad8da0_IOWait", 15000)
find_xrefs_to(0x00AD8DA0, "FUN_00ad8da0")
find_xrefs_from(0x00AD8DA0, "FUN_00ad8da0")

# SECTION 2: TES+0x77c - what is this field?
write("")
write("#" * 70)
write("# SECTION 2: What is at TES+0x77c? (DAT_011dea3c + 0x77c)")
write("# This is the object passed to the wait function")
write("#" * 70)

# TES singleton is at DAT_011dea3c
# TES+0x77c would be at the address stored at 011dea3c, plus 0x77c
# Look for writes to this offset
write("TES singleton ptr: DAT_011dea3c")
write("Wait target: *(DAT_011dea3c) + 0x77c")

# SECTION 3: Any subcalls from FUN_00ad8da0
write("")
write("#" * 70)
write("# SECTION 3: Decompile subcalls to understand wait mechanism")
write("#" * 70)

# These will be filled after we see what FUN_00ad8da0 calls

# SECTION 4: Is there a non-blocking check?
write("")
write("#" * 70)
write("# SECTION 4: Other callers of FUN_00ad8da0 - timeout patterns")
write("#" * 70)

# Check what timeouts other callers use

# SECTION 5: FUN_00877700 alternatives
write("")
write("#" * 70)
write("# SECTION 5: FUN_008776e0 (end of CellTransition)")
write("# Does it re-enable task processing?")
write("#" * 70)

decompile_at(0x008776E0, "FUN_008776e0_ReenableIO")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/func_ad8da0_wait_semantics.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
