# @category Analysis
# @description Verify ALL allocation paths — does FUN_00aa13e0 bypass our hooks?
#   What is DAT_011f6080? Is FUN_00aa4060 our hooked free or separate?
#
# Critical: FUN_00aa13e0 has 61 callers and uses DAT_011f6080, not DAT_011f6238
#   (our hooked heap singleton). If this is a separate allocator, objects
#   allocated through it would be freed through our hooks → mismatch → crash.
#
# Also: the vanilla alloc (FUN_00aa3e40) has an INFINITE retry loop with
#   OOM stages. It NEVER returns NULL. Our mimalloc CAN return NULL.
#   The game assumes alloc never fails → NULL return = crash.

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


write("Allocation Path Verification")
write("=" * 70)

# ===================================================================
# PART 1: FUN_00aa13e0 — the alternative alloc with 61 callers
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00aa13e0 — Alternative Alloc")
write("#" * 70)
write("# Uses DAT_011f6080, calls vtable[1] with 7 params")
write("# DAT_011f6080 is set by FUN_00aa2020 (SBM init)")
write("# Is this the SAME heap or a different one?")

# DAT_011f6080 — what is this object?
find_refs_to(0x011f6080, "DAT_011f6080 (alternative heap object)")

# FUN_00aa2020 sets it: DAT_011f6080 = FUN_00aa3e40(&DAT_011f6238, 4)
# So DAT_011f6080 is allocated FROM our hooked heap (DAT_011f6238)!
# It's a 4-byte allocation. Then *DAT_011f6080 = FUN_009fd0f0(...)
# DAT_011f6080 points to an object whose vtable has alloc at offset 4.

# What is FUN_009fd0f0?
decompile_at(0x009fd0f0, "Object factory for DAT_011f6080")
find_and_print_calls_from(0x009fd0f0, "Object factory")

# ===================================================================
# PART 2: FUN_00aa4060 — the SBM free function
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_00aa4060 — SBM Free")
write("#" * 70)
write("# Called by FUN_00401030 (game delete operator)")
write("# Is this our hooked free? Or separate?")

decompile_at(0x00aa4060, "SBM free (FUN_00aa4060)")
find_and_print_calls_from(0x00aa4060, "SBM free")

# ===================================================================
# PART 3: FUN_00401020 — heap singleton getter
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_00401020 — Heap Singleton Getter")
write("#" * 70)

decompile_at(0x00401020, "Heap singleton getter")

# ===================================================================
# PART 4: What are our actual hook targets?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Hook Target Functions")
write("#" * 70)
write("# Our hooks are on MemoryHeap vtable methods")
write("# DAT_011f6238 = MemoryHeap singleton")
write("# vtable[0] = dtor, vtable[1] = alloc, vtable[2] = free, etc.")
write("# What functions are at those vtable slots?")

# Read the vtable pointer from the heap singleton
# The vtable is at *DAT_011f6238 (the first 4 bytes)
# We can't read memory, but we can check what functions
# reference DAT_011f6238

find_refs_to(0x011f6238, "MemoryHeap singleton (DAT_011f6238)")

# The alloc/free functions that are the vtable entries:
# FUN_00aa3e40 is alloc (confirmed — new operator calls it)
# FUN_00aa4060 is free (confirmed — delete operator calls it)
# Are these the SAME functions we hook?

# ===================================================================
# PART 5: FUN_00aa4290 — fallback alloc (called when pools exhausted)
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00aa4290 — Fallback Alloc")
write("#" * 70)
write("# Called by FUN_00aa3e40 when pool alloc fails AND when")
write("# OOM stages exhausted (local_d != 0)")

decompile_at(0x00aa4290, "Fallback alloc (FUN_00aa4290)")
find_and_print_calls_from(0x00aa4290, "Fallback alloc")

# ===================================================================
# PART 6: DAT_011f6118 — what is this object?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: DAT_011f6118 — Secondary Heap?")
write("#" * 70)

find_refs_to(0x011f6118, "DAT_011f6118 (secondary heap?)")
decompile_at(0x009fd0f0, "Factory that creates DAT_011f6080 payload")

# ===================================================================
# PART 7: FUN_00aa6aa0 — pool alloc from specific pool
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_00aa6aa0 — Pool-specific alloc")
write("#" * 70)

decompile_at(0x00aa6aa0, "Pool alloc (FUN_00aa6aa0)")

# ===================================================================
# PART 8: FUN_00aa4960 — pool lookup by size
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00aa4960 — Pool Lookup")
write("#" * 70)

decompile_at(0x00aa4960, "Pool lookup by size")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bulletproof_alloc_paths.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
