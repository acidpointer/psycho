# @category Analysis
# @description Decompiles the 4 callers of HeapCompact (FUN_00866a90) to understand how each one invokes OOM recovery and what the outer loop looks like.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []


def write(msg):
	output.append(msg)
	print(msg)


def decompile_at(addr_int, label, max_len=10000):
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
	write(
		"  Function: %s @ 0x%08x, Size: %d bytes"
		% (func.getName(), faddr, func.getBody().getNumAddresses())
	)
	if faddr != addr_int:
		write(
			"  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)"
			% (addr_int, func.getName(), faddr)
		)
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
				write(
					"  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name)
				)
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
		write(
			"  %s @ 0x%08x (in %s)"
			% (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname)
		)
		count += 1
		if count > 60:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


# ======================================================================
write("HEAPCOMPACT CALLERS - HOW EACH ONE TRIGGERS OOM RECOVERY")
write("Goal: Understand the outer loop pattern for each caller")
write("=" * 70)

# Caller 1: FUN_00aa3e40 — the OOM recovery loop
write("")
write("#" * 70)
write("# CALLER 1: FUN_00aa3e40 — OOM recovery loop (GameHeap alloc)")
write("#" * 70)
decompile_at(0x00AA3E40, "GameHeap_OOM_Recovery", 15000)
find_and_print_calls_from(0x00AA3E40, "GameHeap_OOM_Recovery")
find_refs_to(0x00AA3E40, "GameHeap_OOM_Recovery")

# Caller 2: FUN_00878080
write("")
write("#" * 70)
write("# CALLER 2: FUN_00878080 — periodic cleanup caller")
write("#" * 70)
decompile_at(0x00878080, "PeriodicCleanup_Caller", 8000)
find_and_print_calls_from(0x00878080, "PeriodicCleanup_Caller")

# Caller 3: FUN_00aa5e30
write("")
write("#" * 70)
write("# CALLER 3: FUN_00aa5e30 — SBM heap resize/expansion")
write("#" * 70)
decompile_at(0x00AA5E30, "SBM_HeapResize", 8000)
find_and_print_calls_from(0x00AA5E30, "SBM_HeapResize")

# Caller 4: FUN_00aa5ec0
write("")
write("#" * 70)
write("# CALLER 4: FUN_00aa5ec0 — second SBM caller")
write("#" * 70)
decompile_at(0x00AA5EC0, "SBM_SecondCaller", 8000)
find_and_print_calls_from(0x00AA5EC0, "SBM_SecondCaller")

# Now trace the OOM loop's caller
write("")
write("#" * 70)
write("# BONUS: What calls FUN_00aa3e40?")
write("#" * 70)
find_refs_to(0x00AA3E40, "GameHeap_OOM_Recovery")

# And the GameHeap::Allocate entry
write("")
write("#" * 70)
write("# BONUS: GameHeap::Allocate (FUN_00aa3df0)")
write("# The actual entry point that calls OOM recovery")
write("#" * 70)
decompile_at(0x00AA3DF0, "GameHeap_Allocate", 5000)
find_and_print_calls_from(0x00AA3DF0, "GameHeap_Allocate")
find_refs_to(0x00AA3DF0, "GameHeap_Allocate")

# What is FUN_00866d10 called from HeapCompact case 1?
write("")
write("#" * 70)
write("# BONUS: FUN_00866d10 — FileHeap compact (called by stage 1)")
write("#" * 70)
decompile_at(0x00866D10, "FileHeap_Compact", 5000)

# What is FUN_00aa5c80?
write("")
write("#" * 70)
write("# BONUS: FUN_00aa5c80 — called by stage 1 after compact")
write("#" * 70)
decompile_at(0x00AA5C80, "After_Compact", 5000)

# What is the process manager lock function?
write("")
write("#" * 70)
write("# BONUS: FUN_0078d200 — TryEnter ProcessManager lock")
write("# Used by stage 4 (PDD) and stage 5 (cell unload)")
write("#" * 70)
decompile_at(0x0078D200, "TryEnter_ProcessManager", 3000)
find_refs_to(0x0078D200, "TryEnter_ProcessManager")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/vanilla_oom_callers.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
