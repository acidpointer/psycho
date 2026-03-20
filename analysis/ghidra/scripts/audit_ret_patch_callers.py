# @category Analysis
# @description AUDIT: All 7 RET-patched + 3 NOP-patched functions.
# Find ALL callers of each. If ANY caller is on a hot path (not just
# shutdown/init), our patch breaks runtime behavior.
# Already found: PostDestructionRestore calls FUN_00AA7030!

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=6000):
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_all_callers(addr_int, label):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- ALL callers of %s (0x%08x) ---" % (label, addr_int))
	callers = []
	count = 0
	for ref in refs:
		if ref.getReferenceType().isCall() or str(ref.getReferenceType()) == "UNCONDITIONAL_CALL":
			from_addr = ref.getFromAddress()
			func = fm.getFunctionContaining(from_addr)
			fname = func.getName() if func else "???"
			faddr = str(func.getEntryPoint()) if func else "???"
			write("  CALL @ 0x%s (in %s @ %s)" % (from_addr, fname, faddr))
			callers.append((func.getEntryPoint().getOffset() if func else 0, fname))
			count += 1
	write("  Total callers: %d" % count)
	return callers

write("=" * 70)
write("AUDIT: RET-PATCHED AND NOP-PATCHED FUNCTION CALLERS")
write("=" * 70)
write("")
write("If any caller is on a runtime path (not init/shutdown), our patch")
write("breaks game behavior and likely causes crashes or memory leaks.")

# === 7 RET-patched functions ===
patches = [
	(0x00AA6840, "SBM_StatsReset"),
	(0x00866770, "SBM_ConfigInit"),
	(0x00866E00, "SBM_RelatedInit"),
	(0x00866D10, "SBM_GetSingleton"),
	(0x00AA7030, "SBM_GlobalCleanup"),
	(0x00AA5C80, "SBM_DeallocAllArenas"),
	(0x00AA58D0, "SBM_SheapCleanup"),
]

for addr, name in patches:
	write("")
	write("#" * 70)
	write("# RET-PATCH: %s @ 0x%08x" % (name, addr))
	write("#" * 70)
	callers = find_all_callers(addr, name)
	decompile_at(addr, name)
	# Decompile each caller to understand context
	for caller_addr, caller_name in callers[:5]:
		if caller_addr != 0:
			decompile_at(caller_addr, "CALLER: %s" % caller_name)

# === 3 NOP-patched calls ===
write("")
write("#" * 70)
write("# NOP-PATCHED CALLS")
write("#" * 70)

nop_patches = [
	(0x0086C56F, "HeapConstruction_DoubleCheck"),
	(0x00C42EB1, "CRT_HeapInit_1"),
	(0x00EC1701, "CRT_HeapInit_2"),
]

for addr, name in nop_patches:
	write("")
	write("--- NOP-PATCH: %s @ 0x%08x ---" % (name, addr))
	# Show the containing function to understand context
	func = fm.getFunctionContaining(toAddr(addr))
	if func:
		write("  In function: %s @ %s" % (func.getName(), func.getEntryPoint()))
		decompile_at(func.getEntryPoint().getOffset(), "Container of %s" % name)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_ret_patch_callers.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
