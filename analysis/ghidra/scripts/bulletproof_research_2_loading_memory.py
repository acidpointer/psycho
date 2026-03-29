# @category Analysis
# @description Research loading memory flow — what fills quarantine, what causes OOM,
#   how the vanilla game manages memory during coc/fast travel
#
# During coc goodsprings:
#   commit goes from 1400MB to 1900MB (+500MB)
#   quarantine grows from 0 to 400MB
#   22MB terrain allocation fails → OOM
#
# Questions:
#   1. What does the vanilla game's alloc do when it fails? (before our hook)
#   2. Does the vanilla game have its own quarantine/zombie mechanism?
#   3. What functions allocate the 22MB terrain? Can we trace the caller?
#   4. What does the game free during coc that goes to our quarantine?
#   5. How does the vanilla game's MemoryHeap handle pressure?
#   6. What is the vanilla flow: alloc fails → what happens?
#   7. Does the vanilla game ever signal HeapCompact itself during loading?

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


write("Loading Memory Flow Research")
write("=" * 70)

# ===================================================================
# PART 1: Vanilla MemoryHeap alloc — what happens on failure?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Vanilla MemoryHeap::Allocate")
write("#" * 70)
write("# Our hooks replace alloc/free. What did the VANILLA alloc do?")
write("# The hooked functions are at the vtable entries.")
write("# MemoryHeap vtable at heap_singleton (0x011F6238)")

# The vanilla alloc is what we hooked. Let's see the original.
# Our hook targets are in statics.rs. The original function addresses
# are the hook targets. Let's find them.

# Heap singleton at 0x011F6238. Vtable at *(0x011F6238).
# alloc = vtable[1], free = vtable[2], realloc = vtable[3], msize = vtable[4]
# But we hook inline, not vtable. The hook targets are the actual functions.

# From our hook setup, the alloc hook target is the function that the game
# calls for heap allocation. Let's look at who calls the OOM executor.
find_refs_to(0x00866a90, "OOM stage executor callers")

# The OOM executor is called from the vanilla alloc when it fails.
# Let's find the vanilla alloc function that calls it.

# ===================================================================
# PART 2: The 22MB terrain allocation — who calls it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Large Allocation Paths (terrain LOD)")
write("#" * 70)
write("# 22369768 bytes = 21.3MB. This is TESObjectLAND terrain data.")
write("# Who allocates this size? What function?")

# TESObjectLAND is the terrain. Its loading function allocates terrain data.
# From crash dumps: Class: TESObjectLAND at 0x0102DCD4
decompile_at(0x00586170, "TESObjectLAND related (from FindCellToUnload chain)")

# ===================================================================
# PART 3: Vanilla HeapCompact trigger — who writes it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: HeapCompact Trigger Writers")
write("#" * 70)

find_refs_to(0x011F636C, "HEAP_COMPACT_TRIGGER (who writes besides us?)")

# ===================================================================
# PART 4: MemoryHeap internal structure
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: MemoryHeap Internals")
write("#" * 70)

# The heap at 0x011F6238 has fields:
# +0x14: critical section (used by HeapCompact)
# +0x110: primary heap pointer (used by OOM)
# +0x134: HeapCompact trigger
# What other fields affect alloc behavior?

# Let's look at the vanilla alloc function body
# The vtable for MemoryHeap should have alloc at a known offset
# Let's find it through the OOM executor's caller

decompile_at(0x00866800, "Near OOM executor (possible alloc function)")
decompile_at(0x00866700, "Before OOM (possible alloc entry)")

# ===================================================================
# PART 5: What writes LOADING_FLAG during coc?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Loading Flag (0x011DEA2B) Writers")
write("#" * 70)

find_refs_to(0x011DEA2B, "LOADING_FLAG writers")

# ===================================================================
# PART 6: DeferredCleanupSmall callers — complete list
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: DeferredCleanupSmall (FUN_00878250) — ALL callers")
write("#" * 70)

find_refs_to(0x00878250, "DeferredCleanupSmall callers")

# ===================================================================
# PART 7: Vanilla per-frame cleanup — FUN_008782b0
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Vanilla Per-Frame Cleanup (FUN_008782b0)")
write("#" * 70)
write("# Called from main loop. Does it call DeferredCleanupSmall?")

decompile_at(0x008782b0, "Vanilla per-frame cleanup")
find_and_print_calls_from(0x008782b0, "Vanilla per-frame cleanup")

# ===================================================================
# PART 8: What allocates during loading that uses 500MB?
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: BSTask/IOManager during loading")
write("#" * 70)
write("# During coc, BSTaskManagerThread loads textures, models, terrain.")
write("# These allocations go through our gheap_alloc.")
write("# What BSTask types allocate the most?")

# QueuedReference (from earlier crash) — loading references
decompile_at(0x00545030, "QueuedReference process (near crash addr)")
find_and_print_calls_from(0x00545030, "QueuedReference process")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bulletproof_loading_memory.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
