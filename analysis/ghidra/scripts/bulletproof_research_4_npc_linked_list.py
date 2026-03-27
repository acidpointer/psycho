# @category Analysis
# @description Research the NPC linked list crash — what is at process+0x268,
#   who adds/removes entries, and how our quarantine could free a node
#
# Crash: FUN_00470470 iterates linked list at this+0x268, reads node+4 (next),
# node memory was freed by quarantine → garbage → crash
#
# The "this" is the process manager (at 0x11e0e80 area)
# Called from FUN_008f63e0 which processes NPC combat/AI state changes
#
# Questions:
#   1. What is the linked list at +0x268? What objects are in it?
#   2. Who ADDS to this list? When?
#   3. Who REMOVES from this list? When?
#   4. How could a node be freed by gheap_free (→ quarantine) while
#      still in the list?
#   5. Is FUN_0066e590 (called during iteration) BSTreeNode-related?
#   6. FUN_004702f0 — what does the list node destructor do?
#   7. Is this crash related to our HeapCompact signaling or quarantine?

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


write("NPC Linked List Crash Research")
write("=" * 70)

# ===================================================================
# PART 1: FUN_00470470 — the crash function (linked list clear)
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00470470 (linked list clear)")
write("#" * 70)

decompile_at(0x00470470, "Linked list clear (crash site)")
decompile_at(0x004702f0, "List node destructor (FUN_004702f0)")
find_and_print_calls_from(0x004702f0, "List node destructor")

# Who calls FUN_00470470?
find_refs_to(0x00470470, "Linked list clear callers")

# ===================================================================
# PART 2: FUN_008f63e0 — the NPC process update that calls list clear
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: NPC Process Update (FUN_008f63e0)")
write("#" * 70)
write("# Iterates this+0x268 and this+0x26c linked lists")
write("# Creates FUN_0066e590 objects, calls vtable[0x504]")

# FUN_0066e590 — what is this? BSTreeNode-related?
decompile_at(0x0066e590, "Object created during NPC update")
find_refs_to(0x0066e590, "FUN_0066e590 callers")

# FUN_008d6fc0 — called during NPC update iteration
decompile_at(0x008d6fc0, "NPC update helper (FUN_008d6fc0)")

# FUN_005ae3d0 — adds to some collection
decompile_at(0x005ae3d0, "Collection add (FUN_005ae3d0)")

# ===================================================================
# PART 3: Who ADDS to process manager +0x268/+0x26c?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Process Manager +0x268/+0x26c Writers")
write("#" * 70)
write("# These offsets are in the ProcessManager or GridCellArray.")
write("# The 'this' in FUN_008f63e0 is passed from FUN_0096c710")
write("# which reads it from param_1 + 0x268")

# FUN_0096c710 passes 'this' from a ProcessManager-like object
# Let's check who writes to offset 0x268 in process managers
# The process manager at 0x11e0e80 has 0x268 = linked list head

# FUN_008f6630 — called after the first list iteration
decompile_at(0x008f6630, "Post-list-iteration (FUN_008f6630)")
find_and_print_calls_from(0x008f6630, "Post-list-iteration")

# ===================================================================
# PART 4: FUN_006815c0 — reads data from linked list node
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_006815c0 (list node data reader)")
write("#" * 70)

decompile_at(0x006815c0, "List node data (FUN_006815c0)")

# ===================================================================
# PART 5: FUN_00726070 used as list iterator (next sibling)
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00726070 as List Iterator")
write("#" * 70)
write("# In FUN_008f63e0: for (; local_18 != 0; local_18 = FUN_00726070(local_18))")
write("# FUN_00726070 reads param_1+4 = next pointer")
write("# If the node was freed by quarantine, param_1+4 is garbage")

# Already decompiled FUN_00726070 — returns *(param_1 + 4)
# The question: what NiAVObject-derived objects are in these lists?
# And how do they get freed while still in the list?

# FUN_00401030 — the delete operator called on list entries
decompile_at(0x00401030, "Delete operator (FUN_00401030)")

# ===================================================================
# PART 6: Is this a known vanilla bug or our quarantine?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Who FREES list nodes via gheap_free?")
write("#" * 70)
write("# If a list node at +0x268 goes through gheap_free → quarantine")
write("# → epoch reclaim → mi_free, but the list still has the pointer...")
write("# The game expects the freed memory to stay readable (SBM zombie)")

# FUN_00470470 is also called from FUN_008f63e0 at the END of iteration
# After the for loop: FUN_00470470(*(this + 0x268))
# This clears the list AFTER processing. If a node was freed during
# processing (by FUN_00401030 inside the loop), but the list still
# has it... the clear function reads freed memory.

# Actually, looking at FUN_008f63e0 more carefully:
# Line 201-222: iterates list, calls FUN_00401030 on each entry
# Line 224: calls FUN_00470470 to clear the list head
# Between these, the entries were deleted but the LIST STRUCTURE
# still has next pointers through them. FUN_00470470 reads those
# next pointers from memory that was just freed by FUN_00401030.

# With SBM: freed memory readable → next pointers intact
# With mimalloc + quarantine: freed memory in quarantine → readable
# UNLESS quarantine already reclaimed it (2+ epochs old)

# But the free (FUN_00401030) and the list clear (FUN_00470470)
# happen in the SAME function call! Same frame! The freed entry
# would be in the CURRENT epoch → not reclaimed yet.

# UNLESS our quarantine is broken somehow, OR the entry was freed
# in a PREVIOUS frame and the list wasn't cleared.

write("# Key question: can the list at +0x268 persist across frames")
write("# with stale entries? Or is it always processed+cleared in")
write("# the same frame?")

# Who writes to the list between frames?
# FUN_008f63e0 reads the list. Who populates it?
# From FUN_0096c710: it iterates actors and calls FUN_008f63e0
# on each actor's process manager

# The list might be populated during AI processing (Phase 8-10)
# and cleared during post-AI (Phase 11+). If an entry is freed
# during AI but the list clear hasn't run yet...

# Check FUN_0096c240 and FUN_0096c860/0096c970 — what do they do?
decompile_at(0x0096c240, "Process manager update 1 (FUN_0096c240)")
find_and_print_calls_from(0x0096c240, "Process manager update 1")

decompile_at(0x0096c860, "Process manager update 2 (FUN_0096c860)")
find_and_print_calls_from(0x0096c860, "Process manager update 2")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bulletproof_npc_linked_list.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
