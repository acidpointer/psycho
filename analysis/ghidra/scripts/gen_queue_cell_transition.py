# @category Analysis
# @description Research Gen queue lifecycle during CellTransition (coc/fast travel)
#
# The Gen queue (0x11de874) accumulates 1000-4000 entries during stress flying.
# When coc fires, CellTransition drains them ALL during loading → massive
# destruction → quarantine fills 400MB+ → OOM.
#
# Questions:
#   1. What fills the Gen queue? What are Generic PDD entries?
#   2. Where does CellTransition drain the Gen queue?
#   3. Does CellTransition call full PDD? Where exactly?
#   4. What is the reentrancy guard DAT_011de958 and who checks it?
#   5. Can we drain Gen queue incrementally (not all at once)?
#   6. What does each Gen queue entry's vtable[4] (destructor) do?
#   7. Is there a way to process Gen queue without the stall?

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


write("Gen Queue and CellTransition Analysis")
write("=" * 70)

# ===================================================================
# PART 1: Who WRITES to the Gen queue? What goes in it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Gen Queue Writers (0x11de874)")
write("#" * 70)

find_refs_to(0x011de874, "Generic PDD queue (DAT_011de874)")

# ===================================================================
# PART 2: CellTransition handler — where does it drain PDD?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: CellTransition Handler (FUN_008774a0)")
write("#" * 70)

decompile_at(0x008774a0, "CellTransitionHandler", 20000)
find_and_print_calls_from(0x008774a0, "CellTransitionHandler")

# ===================================================================
# PART 3: What queues Gen entries during normal gameplay?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Gen Queue Entry Point — FUN_00869560 and FUN_008694c0")
write("#" * 70)
write("# From per-frame PDD, Gen entries move between queues via")
write("# FUN_008694c0 and FUN_00869560. Who calls them?")

decompile_at(0x008694c0, "PDD queue transfer 1 (FUN_008694c0)")
find_refs_to(0x008694c0, "PDD queue transfer 1")

decompile_at(0x00869560, "PDD queue transfer 2 (FUN_00869560)")
find_refs_to(0x00869560, "PDD queue transfer 2")

# ===================================================================
# PART 4: PDD reentrancy guard — who checks DAT_011de958?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: PDD Reentrancy Guard (DAT_011de958)")
write("#" * 70)

find_refs_to(0x011de958, "PDD reentrancy guard")

# ===================================================================
# PART 5: Gen queue processing in per-frame drain — the vtable call
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Gen Queue Per-Frame Processing")
write("#" * 70)
write("# Per-frame drain processes Generic with vtable[4] call:")
write("#   (**(code **)(*(int *)*piVar7 + 0x10))(1);")
write("# What objects are in the Gen queue? What does vtable[4] do?")

# The Generic queue handler in per-frame PDD calls vtable[0x10] = vtable[4]
# These are TESForm-derived objects. What specific forms?

# FUN_00564d80 is called to check if the generic entry needs processing
decompile_at(0x00564d80, "Gen entry check (FUN_00564d80)")

# ===================================================================
# PART 6: What function adds to Generic queue?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Generic Queue Add Function")
write("#" * 70)

# The Generic queue is at 0x11de874. Entries are added via some function.
# Let's find who writes to the queue data structure.
# Queue structure: +0x00 = data ptr, +0x08 = capacity, +0x0A = count
# The add function likely writes to the data array and increments count.

# FUN_006bf8f0 is called in per-frame drain for Gen queue
decompile_at(0x006bf8f0, "Gen queue remove entry (FUN_006bf8f0)")

# FUN_00877a30 reads from queues
decompile_at(0x00877a30, "Queue read entry (FUN_00877a30)")

# ===================================================================
# PART 7: FUN_0093c200 — CellTransition sub-function
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: CellTransition Sub-Functions")
write("#" * 70)

decompile_at(0x0093c200, "CellTransition sub (calls SpeedTree update)")
find_and_print_calls_from(0x0093c200, "CellTransition sub")

# FUN_00454774 from crash callstack — cell loading
decompile_at(0x00454774, "Cell loading function")
find_and_print_calls_from(0x00454774, "Cell loading")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/gen_queue_cell_transition.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
