# @category Analysis
# @description Understand the COMPLETE engine free contract:
#              1. What does SBM's freelist write to freed blocks? (which bytes)
#              2. What does mi_free write? (which bytes)
#              3. What do stale readers actually READ from freed blocks?
#              4. Can we make mi_free's writes COMPATIBLE with stale readers?

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
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
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

# ===================================================================
# PART 1: SBM POOL ALLOCATOR INTERNALS
# What EXACTLY does SBM write when freeing a block?
# ===================================================================

write("ENGINE FREE CONTRACT ANALYSIS")
write("=" * 70)
write("")
write("QUESTION: When SBM frees a block, which bytes are modified?")
write("QUESTION: When a stale reader reads a freed block, what does it see?")
write("QUESTION: Can we replicate SBM's post-free memory state with mimalloc?")
write("")

# SBM pool freelist operations
decompile_at(0x00AA6C70, "SBM pool freelist INSERT (on free)")
decompile_at(0x00AA6B60, "SBM pool freelist REMOVE (on alloc)")

# SBM pool alloc/free entry points
decompile_at(0x00AA3E40, "GameHeap::Allocate (SBM entry)")
decompile_at(0x00AA4060, "GameHeap::Free (SBM entry)")

# SBM arena management
decompile_at(0x00AA5C80, "SBM deallocate all arenas")
decompile_at(0x00AA7030, "GlobalCleanup (iterates 256 pool slots)")

# SBM pool structure - how pools and arenas relate
decompile_at(0x00AA4290, "SBM fallback malloc (when pools exhausted)")

# ===================================================================
# PART 2: WHAT STALE READERS ACTUALLY READ
# The QueuedTexture crash reads through vtable. What offset?
# NPC linked list reads next pointer. What offset?
# ===================================================================

write("")
write("PART 2: STALE READER PATTERNS")
write("=" * 70)
write("")
write("Pattern A: Virtual call through freed object")
write("  obj->vtable[N]()  where obj is freed")
write("  Reads: offset 0 (vtable ptr) + vtable[N] (function ptr)")
write("")
write("Pattern B: Linked list next pointer")
write("  next = *(freed_node + 4)")
write("  Reads: offset 4")
write("")
write("Pattern C: Refcount decrement")
write("  InterlockedDecrement(obj + 4)  // NiRefObject refcount")
write("  Reads/writes: offset 4")
write("")

# NPC linked list iteration (reads freed nodes)
decompile_at(0x00470470, "NPC linked list clear (reads freed nodes)")
decompile_at(0x004702F0, "NPC list node free")

# NiRefObject DecRef - reads offset +4 (refcount) then calls delete
decompile_at(0x0044DD60, "IOTask DecRef (reads refcount at +8)")
find_and_print_calls_from(0x0044DD60, "IOTask DecRef")

# ===================================================================
# PART 3: MIMALLOC FREE INTERNALS
# What does mi_free write to the block?
# From mimalloc source: mi_block_set_next writes at offset 0
# ===================================================================

write("")
write("PART 3: MIMALLOC vs SBM BLOCK STATE AFTER FREE")
write("=" * 70)
write("")
write("mimalloc mi_free writes:")
write("  offset 0: next-free pointer (4 bytes on 32-bit)")
write("  All other bytes: UNTOUCHED")
write("")
write("SBM FUN_00aa6c70 writes:")
write("  (need to decompile to determine)")
write("")
write("IF SBM also writes at offset 0 only, then mi_free is COMPATIBLE")
write("with SBM's behavior for stale reads at offset 4+.")
write("")
write("The CRASH comes from virtual calls: vtable ptr is at offset 0.")
write("After mi_free, offset 0 = freelist next pointer (a heap address).")
write("Reading this as vtable -> accessing freelist address as vtable ->")
write("function pointer at vtable[N] is garbage -> EIP=0 crash.")
write("")
write("With SBM: offset 0 = freelist next pointer (a POOL address).")
write("Reading this as vtable -> accessing pool address as vtable ->")
write("function pointer at vtable[N] is ALSO garbage.")
write("BUT: SBM pool addresses are in game VA space (not zero/invalid).")
write("The 'vtable' entries happen to be other pool blocks, which")
write("contain non-zero data -> call goes to random game code, not 0x0.")
write("This is STILL undefined behavior but doesn't crash with NULL.")
write("")

# ===================================================================
# PART 4: THE REAL QUESTION
# If mi_free overwrites offset 0 with freelist pointer, and the
# crash is from reading offset 0 as vtable... what if we DON'T
# overwrite offset 0? What if we store the freelist pointer elsewhere?
#
# OR: what if we NULL-check the vtable entry before calling?
# That's a HOOK on the virtual dispatch.
# ===================================================================

write("")
write("PART 4: POTENTIAL ENGINE-LEVEL FIXES")
write("=" * 70)
write("")
write("Fix A: Hook the virtual dispatch in BST task processing.")
write("  Before calling vtable[N], validate the vtable pointer.")
write("  If vtable is in freelist range (not RDATA), skip the call.")
write("  Requires: hook at the CALL instruction in BST loop.")
write("")
write("Fix B: Hook NiSourceTexture destructor to cancel queued tasks.")
write("  When NiSourceTexture is destroyed, find and cancel all")
write("  QueuedTexture tasks that reference it.")
write("  Requires: ability to walk the BST task queue.")
write("")
write("Fix C: Replace mi_free's freelist write with a safe sentinel.")
write("  Instead of writing freelist next ptr at offset 0, write a")
write("  known 'dead vtable' pointer that has safe no-op methods.")
write("  Requires: custom mimalloc modification OR post-free write.")
write("")
write("Fix D: After mi_free, write a 'dead vtable' at offset 0.")
write("  mi_free(ptr); *(uint32_t*)ptr = DEAD_VTABLE_ADDRESS;")
write("  The dead vtable has all entries pointing to a no-op function.")
write("  Stale reads get the dead vtable -> call no-op -> no crash.")
write("  Requires: allocate a static vtable with NOP entries.")
write("")

# ===================================================================
# PART 5: FIND ALL VIRTUAL CALL SITES IN BST LOOP
# These are the EXACT hooks we'd need for Fix A.
# ===================================================================

write("")
write("PART 5: BST VIRTUAL CALL SITES")
write("=" * 70)

# Decompile BST loop to find all indirect calls
decompile_at(0x00C410B0, "BST main loop (find all vtable calls)")

# The task processing dispatcher
decompile_at(0x0044CD00, "IOTask_Create / dispatch")
decompile_at(0x0044B660, "IOTask submit path 1")
decompile_at(0x006C65B0, "IOTask submit path 2")
decompile_at(0x00C3F7A0, "IOTask submit path 3")

# ===================================================================
# OUTPUT
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/engine_free_contract.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
