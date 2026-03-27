# @category Analysis
# @description Trace IO task types that reference BSTreeNode, and SpeedTree
#   update functions that iterate BSTreeManager map
#
# From crash analysis:
#   FUN_0086ff70 → FUN_00c458f0 (IO task processor) → vtable call → BSTreeNode → crash
#   FUN_006652e0 (SpeedTree update) calls FUN_006658b0, FUN_00664720, FUN_00665520
#
# Questions:
#   1. What does FUN_006658b0 do? Does it iterate BSTreeManager map?
#   2. What do FUN_00664720 and FUN_00665520 do with BSTreeManager?
#   3. What IO task types exist that reference BSTreeNode?
#   4. What does FUN_00c45b20 (the task processor inner loop) do with completed tasks?
#   5. What is FUN_00869180 (skip mask checker in full PDD)?
#   6. How does the TLS=0 mechanism work in stage 5?
#   7. What does FUN_00877430 do (called from FUN_0086ff70 in loading path)?

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


write("BSTreeNode IO Task and SpeedTree Deep Analysis")
write("=" * 70)

# ===================================================================
# PART 1: SpeedTree update internals — what reads BSTreeManager map?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: SpeedTree Update Internals")
write("#" * 70)

decompile_at(0x006658b0, "FUN_006658b0 (called from SpeedTree update on BSTreeMgr)")
find_and_print_calls_from(0x006658b0, "FUN_006658b0")

decompile_at(0x00664720, "FUN_00664720 (called from SpeedTree update)")
find_and_print_calls_from(0x00664720, "FUN_00664720")

decompile_at(0x00665520, "FUN_00665520 (called from SpeedTree update)")
find_and_print_calls_from(0x00665520, "FUN_00665520")

# ===================================================================
# PART 2: BSTreeManager::FUN_00664840 — the getter used everywhere
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: BSTreeManager getter")
write("#" * 70)

decompile_at(0x00664840, "BSTreeManager getter (FUN_00664840)")

# ===================================================================
# PART 3: IO task completion chain — what task types exist?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: IO Task Completion")
write("#" * 70)

# FUN_00c45b20 is the inner task processor from crash callstack
decompile_at(0x00c45b20, "IO task processor inner (FUN_00c45b20)")
find_and_print_calls_from(0x00c45b20, "IO task processor inner")

# What queues completed tasks? FUN_00c45e50 dequeues them
decompile_at(0x00c45e50, "IO task dequeue (FUN_00c45e50)")

# FUN_00c46080 — called from async flush
decompile_at(0x00c46080, "IO flush helper (FUN_00c46080)")
find_and_print_calls_from(0x00c46080, "IO flush helper")

# ===================================================================
# PART 4: FUN_00869180 — PDD skip mask check (used by full PDD)
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: PDD Skip Mask (FUN_00869180)")
write("#" * 70)
write("# Full PDD calls FUN_00869180(mask) before each queue.")
write("# If returns non-zero, queue is SKIPPED.")
write("# Mask values: 0x10=NiNode, 0x08=?, 0x04=Texture, 0x02=Anim,")
write("#   0x01=Generic, 0x20=last queue")

decompile_at(0x00869180, "PDD skip mask check")

# ===================================================================
# PART 5: FUN_00877430 — called from FUN_0086ff70 loading path
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00877430 (loading transition handler?)")
write("#" * 70)

decompile_at(0x00877430, "Loading transition (in FUN_0086ff70)")
find_and_print_calls_from(0x00877430, "Loading transition")

# ===================================================================
# PART 6: NiNode destructor chain — does it remove from BSTreeManager?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: NiNode Destructor → BSTreeNode Destructor chain")
write("#" * 70)

# FUN_00418d20 is called by per-frame PDD for NiNode queue
# What does it call? Does it reach BSTreeNode destructor?
decompile_at(0x00418d20, "NiNode_Release (PDD NiNode handler)")
decompile_at(0x0048fb50, "NiNode chain (called by NiNode_Release)")
find_and_print_calls_from(0x0048fb50, "NiNode chain")

# FUN_0043b4a0 — called by BSTreeNode destructor (from lifecycle output)
decompile_at(0x0043b4a0, "BSTreeNode cleanup (called by ~BSTreeNode)")
find_and_print_calls_from(0x0043b4a0, "BSTreeNode cleanup")

# ===================================================================
# PART 7: HeapCompact stage 5 TLS=0 mechanism
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: HeapCompact Stage 5 TLS=0")
write("#" * 70)
write("# From memory: Stage 5 uses TLS=0 for immediate BSTreeNode")
write("# destruction + BSTreeManager map removal")

# The HeapCompact frame check calls the dispatcher
decompile_at(0x00878080, "HeapCompact frame check")
find_and_print_calls_from(0x00878080, "HeapCompact frame check")

# FUN_00878360 — called from per-frame PDD, checks HeapCompact state
decompile_at(0x00878360, "HeapCompact state check (FUN_00878360)")

# ===================================================================
# PART 8: FUN_00418e00 — Texture queue handler (called by both PDD types)
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Queue handlers called by PDD")
write("#" * 70)

decompile_at(0x00418e00, "Texture queue handler (FUN_00418e00)")
decompile_at(0x00868ce0, "Anim queue handler (FUN_00868ce0)")

# ===================================================================
# PART 9: FUN_00664cd0 callers — who triggers BSTreeManager cleanup?
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: BSTreeManager cleanup (FUN_00664cd0) full caller chain")
write("#" * 70)

find_refs_to(0x00664cd0, "BSTreeManager cleanup")

# Also check FUN_00664940 (BSTreeManager destroy) callers
find_refs_to(0x00664940, "BSTreeManager destroy")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bstree_io_task_and_speedtree.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
