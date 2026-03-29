# @category Analysis
# @description Research how SBM (vanilla allocator) handles freed memory vs mimalloc,
#   and what game code DEPENDS on zombie memory behavior
#
# SBM keeps freed memory readable (pool allocator, block reuse).
# mimalloc mi_free makes memory immediately available for reuse.
# Our quarantine delays mi_free by 2 epochs.
#
# But the NPC crash shows a linked list node freed in the SAME function
# that later reads it. Even 0-epoch quarantine should protect this
# (entry is in current epoch, not reclaimed). UNLESS something else
# is wrong.
#
# Questions:
#   1. SBM alloc/free internals — how does pool recycling work?
#   2. When does SBM actually REUSE a freed block?
#   3. What happens to mimalloc freed memory — is it zeroed? returned to OS?
#   4. How many game code patterns depend on reading freed memory?
#   5. Is our quarantine push() correctly catching ALL gheap_free calls?
#   6. Could there be a free path that bypasses our hook?

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
		if count > 60:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("Quarantine vs SBM — Zombie Memory Research")
write("=" * 70)

# ===================================================================
# PART 1: SBM pool allocator internals
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: SBM Pool Allocator")
write("#" * 70)
write("# Pool init: FUN_00aa3cc0 creates pools with sizes 8-508 bytes")
write("# Larger allocs go to a general heap")

decompile_at(0x00aa3cc0, "SBM pool create (FUN_00aa3cc0)")

# SBM alloc — the 3 functions that call OOM executor
decompile_at(0x00aa3e40, "SBM alloc (pool path)", 16000)

# SBM free
decompile_at(0x00aa2020, "SBM init/setup")
find_refs_to(0x00aa2020, "SBM init callers")

# ===================================================================
# PART 2: FUN_00401030 — the game's delete operator
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Game Delete Operator (FUN_00401030)")
write("#" * 70)
write("# Called everywhere for deallocation. Does it call our hooked free?")

decompile_at(0x00401030, "Game delete operator")
find_and_print_calls_from(0x00401030, "Game delete operator")

# FUN_00401000 — the game's new operator (alloc)
decompile_at(0x00401000, "Game new operator")
find_and_print_calls_from(0x00401000, "Game new operator")

# ===================================================================
# PART 3: Our hook targets — verify coverage
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Hook Target Verification")
write("#" * 70)
write("# Our hooks are inline hooks on the MemoryHeap vtable functions.")
write("# Verify: do FUN_00401000 and FUN_00401030 go through our hooks?")

# FUN_00401000 (new) calls what?
# FUN_00401030 (delete) calls what?
# These should call through the MemoryHeap vtable which we hooked.

# Also check: are there OTHER alloc/free paths that bypass our hooks?
# CRT malloc/free, VirtualAlloc, HeapAlloc, etc.

# FUN_00aa13e0 — another allocator? (called from BSTreeManager code)
decompile_at(0x00aa13e0, "Alternative alloc? (FUN_00aa13e0)")
find_refs_to(0x00aa13e0, "Alternative alloc callers")

# ===================================================================
# PART 4: FUN_004019a0 — InterlockedDecrement (refcount release)
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Reference Counting")
write("#" * 70)
write("# NiRefObject uses InterlockedDecrement for refcount.")
write("# When refcount hits 0, the destructor is called.")
write("# FUN_004019a0 might be the Release/DecRef function.")

decompile_at(0x004019a0, "Refcount decrement (FUN_004019a0)")
decompile_at(0x00401970, "Refcount related (FUN_00401970)")

# ===================================================================
# PART 5: What uses FUN_00401030 in the crash chain?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Delete in Crash Chain")
write("#" * 70)
write("# FUN_008f63e0 calls FUN_00401030 on list entries DURING iteration")
write("# Then calls FUN_00470470 to clear the list AFTER iteration")
write("# FUN_00470470 reads next pointers from entries freed by FUN_00401030")
write("# With SBM: freed memory readable. With mimalloc: in quarantine.")
write("# This should be safe (current epoch). Why does it crash?")

# Maybe FUN_00401030 doesn't go through our hook?
# Or maybe the linked list spans multiple frames?


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bulletproof_quarantine_vs_sbm.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
