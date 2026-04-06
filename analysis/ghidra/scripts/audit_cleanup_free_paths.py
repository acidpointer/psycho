# @category Analysis
# @description Trace what game cleanup stages actually free and through which paths.
# Goal: find memory that gets allocated but never freed through our hooks.

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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
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
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		rtype = ref.getReferenceType()
		if rtype.isCall():
			write("  CALL @ 0x%08x in %s (0x%08x)" % (ref.getFromAddress().getOffset(), fname, faddr))
			count += 1
	write("  Total: %d call refs" % count)


# --- Main body ---

write("AUDIT: Cleanup stage free paths - what actually frees memory?")
write("=" * 70)
write("")
write("We hook FUN_00aa3e40 (alloc) and FUN_00aa4060 (free) via inline hooks.")
write("ALL calls to these functions go through our hooks.")
write("But what if cleanup stages free memory through OTHER paths?")
write("")

# SECTION 1: What does operator delete actually call?
write("# SECTION 1: operator delete / game free entry points")
write("# FUN_00401030 is the game's operator delete.")
write("# Does it call our hooked FUN_00aa4060, or something else?")
decompile_at(0x00401030, "OperatorDelete_00401030")
find_and_print_calls_from(0x00401030, "OperatorDelete")

# What about NiRefObject::DecRef -> delete?
write("")
write("# NiRefObject destructor chain")
decompile_at(0x00418D20, "NiRefObject_DecRef_or_Delete")
find_and_print_calls_from(0x00418D20, "NiRefObject_DecRef")

# SECTION 2: Cell unload - what gets freed?
write("")
write("# SECTION 2: Cell unload function and what it frees")
write("# FUN_004539A0 is FindCellToUnload (called from Stage 5).")
write("# What memory does it actually free?")
decompile_at(0x004539A0, "FindCellToUnload")
find_and_print_calls_from(0x004539A0, "FindCellToUnload")

# SECTION 3: PDD (Process Deferred Destruction)
write("")
write("# SECTION 3: PDD - what it processes and how it frees")
decompile_at(0x00868850, "PerFrame_QueueDrain_PDD")
decompile_at(0x00868D70, "PDD_Purge")
find_and_print_calls_from(0x00868D70, "PDD_Purge")

# SECTION 4: DeferredCleanupSmall
write("")
write("# SECTION 4: DeferredCleanupSmall - the async flush + PDD combo")
write("# Called from destruction_protocol after cell unload.")
# Need to find the address - check globals
decompile_at(0x00877770, "DeferredCleanupSmall")
find_and_print_calls_from(0x00877770, "DeferredCleanupSmall")

# SECTION 5: Fast travel / cell transition handlers
write("")
write("# SECTION 5: Cell transition - what calls GlobalCleanup (now patched)?")
write("# FUN_0093cdf0 and FUN_0093d500 call FUN_00aa7030 directly.")
write("# We ret-patched FUN_00aa7030. What ELSE do these functions do?")
decompile_at(0x0093CDF0, "FastTravel_Handler")
find_and_print_calls_from(0x0093CDF0, "FastTravel_Handler")
decompile_at(0x0093D500, "CellTransition_Handler")
find_and_print_calls_from(0x0093D500, "CellTransition_Handler")

# SECTION 6: What calls FUN_00401000 (FormHeap_Allocate)?
write("")
write("# SECTION 6: FormHeap_Allocate callers - verify ALL go through our hook")
find_refs_to(0x00401000, "FormHeap_Allocate_00401000")

# SECTION 7: What calls FUN_00401030 (FormHeap_Free)?
write("")
write("# SECTION 7: FormHeap_Free callers - verify ALL go through our hook")
find_refs_to(0x00401030, "FormHeap_Free_00401030")

# SECTION 8: Are there OTHER heap alloc/free functions?
write("")
write("# SECTION 8: Other alloc/free entry points we might miss")
write("# Check operator new at 0x00401000 and alternatives")
decompile_at(0x00401000, "FormHeap_Allocate")
decompile_at(0x00401030, "FormHeap_Free")

# Check if there is an aligned alloc that bypasses
decompile_at(0x00AA5EC0, "SBM_AlignedAlloc_VirtualAlloc")

# SECTION 9: Havok memory system - does it use our heap or its own?
write("")
write("# SECTION 9: Havok memory system")
write("# Havok may have its own allocator that bypasses the game heap.")
decompile_at(0x00C459D0, "HavokGC_AsyncFlush")
find_and_print_calls_from(0x00C459D0, "HavokGC")


# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_cleanup_free_paths.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
