# @category Analysis
# @description Root cause analysis for BSTreeNode RefCount:0 crash (C0000417)
#
# Crash callstack:
#   0x00EC7C62 (CRT invalid param handler)
#   0x00B03E48
#   0x0066691F / 0x00666868 / 0x006667DF  (BSTreeManager area)
#   0x00CFCC2C
#   0x0066B68F
#   0x00CFCC2C  (repeated)
#   0x00C45C4B / 0x00C45A9E / 0x00C459AB  (async flush area)
#   0x00870552  (near our mid-frame hook FUN_008705d0)
#   0x0086EDED  (main loop)
#
# Questions to answer:
#   1. What function is at 0x00870552? What does it do?
#   2. Why does it call async flush (0x00C459xx)?
#   3. What do the BSTreeManager functions at 0x00666xxx do?
#   4. How does BSTreeNode RefCount reach 0 in this path?
#   5. What is the full chain from main loop to the crash?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
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
		return None
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
	return func

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


write("BSTreeNode C0000417 Crash Root Cause Analysis")
write("=" * 70)
write("")
write("CRASH: C0000417 at 0x00EC7C62")
write("BSTreeNode 'WastelandUndergrowth01.spt' RefCount:0")
write("Multiple NiRefObject with RefCount:0 on stack")
write("")

# ===================================================================
# PART 1: The crash callstack functions - identify each one
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Crash Callstack - Identify Each Function")
write("#" * 70)

decompile_at(0x00870552, "CALLSTACK: Near mid-frame hook (crash entry from main loop)")
find_and_print_calls_from(0x00870552, "Near mid-frame hook")

decompile_at(0x00C459AB, "CALLSTACK: Async flush area (lowest)")
decompile_at(0x00C45A9E, "CALLSTACK: Async flush area (mid)")
decompile_at(0x00C45C4B, "CALLSTACK: Async flush area (top)")

decompile_at(0x0066B68F, "CALLSTACK: BSTreeManager area (0x0066B68F)")
decompile_at(0x006667DF, "CALLSTACK: BSTreeManager area (0x006667DF)")
decompile_at(0x00666868, "CALLSTACK: BSTreeManager area (0x00666868)")
decompile_at(0x0066691F, "CALLSTACK: BSTreeManager area (0x0066691F)")

decompile_at(0x00B03E48, "CALLSTACK: Before CRT handler (0x00B03E48)")

# ===================================================================
# PART 2: What does FUN_008705d0 (our hook area) actually call?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_008705d0 and Surrounding Functions")
write("#" * 70)

decompile_at(0x008705d0, "FUN_008705d0 (our mid-frame hook target)")
find_and_print_calls_from(0x008705d0, "FUN_008705d0")

# ===================================================================
# PART 3: The async flush function and what it touches
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Async Flush Chain")
write("#" * 70)

decompile_at(0x00C459D0, "FUN_00C459D0 (async flush)")
find_and_print_calls_from(0x00C459D0, "Async flush")
find_refs_to(0x00C459D0, "Async flush callers")

# ===================================================================
# PART 4: BSTreeNode destructor and when it removes from BSTreeManager
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: BSTreeNode Destruction")
write("#" * 70)

# BSTreeNode vtable = 0x010668E4 - find destructor
decompile_at(0x0066B5F0, "BSTreeNode destructor (near 0x0066B68F in callstack)")
find_and_print_calls_from(0x0066B5F0, "BSTreeNode destructor")

decompile_at(0x00665BE0, "TreeMgr_RemoveByKey")
find_refs_to(0x00665BE0, "TreeMgr_RemoveByKey callers")

# ===================================================================
# PART 5: How does the game's per-frame PDD drain handle BSTreeNode?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Per-Frame PDD NiNode Queue Processing")
write("#" * 70)

decompile_at(0x00868850, "Per-frame PDD drain (FUN_00868850)")
find_and_print_calls_from(0x00868850, "Per-frame PDD drain")

decompile_at(0x00868D70, "Full PDD (all queues)")
find_and_print_calls_from(0x00868D70, "Full PDD")

# ===================================================================
# PART 6: The main loop between our hook and the crash
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Main Loop Context")
write("#" * 70)

decompile_at(0x0086EDED, "Main loop at crash callstack entry")
decompile_at(0x0086B3E8, "Main loop outer")

# ===================================================================
# PART 7: HeapCompact stages 0-3 - do they touch BSTreeNode?
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: HeapCompact Stages 0-3 (what we signal)")
write("#" * 70)

decompile_at(0x00878110, "HeapCompact dispatcher (reads trigger)")
find_and_print_calls_from(0x00878110, "HeapCompact dispatcher")

decompile_at(0x00878080, "HeapCompact frame check (calls dispatcher)")
find_and_print_calls_from(0x00878080, "HeapCompact frame check")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bstreenode_crash_root_cause.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
