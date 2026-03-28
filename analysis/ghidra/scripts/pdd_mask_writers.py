# @category Analysis
# @description Decompile FUN_008681c0 and FUN_00868210 -- the two functions
#   that WRITE DAT_011de804 (PDD skip mask). Need to verify whether
#   FUN_00868210 restores saved value (safe) or AND-clears bits (unsafe).

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
	fsize = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, fsize))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > max_len:
			write(code[:max_len])
			write("  ... [truncated at %d chars]" % max_len)
		else:
			write(code)
	else:
		write("  [decompilation failed]")

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


write("PDD Mask Writers -- FUN_008681c0 and FUN_00868210")
write("=" * 70)
write("")
write("CRITICAL QUESTION: Does FUN_00868210 restore saved value (safe)")
write("or AND-clear specific bits (unsafe for our Gen skip approach)?")

# ===================================================================
# PART 1: FUN_008681c0 -- mask SET function (queue add entry)
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_008681c0 -- mask writer (queue add enter)")
write("#" * 70)

decompile_at(0x008681c0, "FUN_008681c0 (mask set / queue add enter)")
find_and_print_calls_from(0x008681c0, "FUN_008681c0")

# ===================================================================
# PART 2: FUN_00868210 -- mask CLEAR function (queue add exit)
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_00868210 -- mask writer (queue add exit)")
write("#" * 70)

decompile_at(0x00868210, "FUN_00868210 (mask clear / queue add exit)")
find_and_print_calls_from(0x00868210, "FUN_00868210")

# ===================================================================
# PART 3: Who calls FUN_008681c0 and FUN_00868210?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: All callers of mask writers")
write("#" * 70)

find_refs_to(0x008681c0, "FUN_008681c0 (mask set)")
find_refs_to(0x00868210, "FUN_00868210 (mask clear)")

# ===================================================================
# PART 4: FUN_00866a90 -- HeapCompact stage executor
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: HeapCompact stage executor (calls PDD stage 4)")
write("#" * 70)
write("# Does it write the mask before calling PDD?")

decompile_at(0x00866a90, "FUN_00866a90 (HeapCompact stage executor)", 16000)
find_and_print_calls_from(0x00866a90, "HeapCompact stage executor")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/pdd_mask_writers.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
