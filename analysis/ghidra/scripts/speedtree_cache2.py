# Ghidra Jython script: SpeedTree cache analysis part 2
# Decompile key functions found in part 1

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

funcMgr = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory()
refMgr = currentProgram.getReferenceManager()

outfile = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/speedtree_cache2.txt"
out = open(outfile, "w")

def write(msg):
	out.write(msg + "\n")
	print(msg)

def decompile_at(addr_int, label):
	addr = af.getDefaultAddressSpace().getAddress(addr_int)
	func = funcMgr.getFunctionAt(addr)
	if func is None:
		func = funcMgr.getFunctionContaining(addr)
	write("")
	write("=" * 60)
	write("%s @ 0x%08X" % (label, addr_int))
	write("=" * 60)
	if func is None:
		write("[no function found]")
		return
	size = func.getBody().getNumAddresses()
	write("Function: %s, Size: %d bytes" % (func.getName(), size))
	write("")
	results = decomp.decompileFunction(func, 30, monitor)
	if results is None:
		write("[decompilation failed]")
		return
	df = results.getDecompiledFunction()
	if df is None:
		write("[decompilation failed]")
		return
	write(df.getC())

def find_refs_to(addr_int, label):
	write("")
	write("=" * 60)
	write("References TO 0x%08X (%s)" % (addr_int, label))
	write("=" * 60)
	addr = af.getDefaultAddressSpace().getAddress(addr_int)
	refs = refMgr.getReferencesTo(addr)
	funcs = set()
	for ref in refs:
		fromAddr = ref.getFromAddress()
		func = funcMgr.getFunctionContaining(fromAddr)
		if func is not None:
			funcs.add(func)
	write("Found %d functions:" % len(funcs))
	for func in sorted(funcs, key=lambda f: f.getEntryPoint().getOffset()):
		entry = func.getEntryPoint()
		write("  0x%08X  %s  (%d bytes)" % (entry.getOffset(), func.getName(), func.getBody().getNumAddresses()))
	return funcs

write("SpeedTree Cache Analysis - Part 2")
write("=" * 60)

# 1. FUN_00869180 - queue skip gate function
decompile_at(0x00869180, "Queue gate function (checks if queue should be skipped)")

# 2. FUN_00703980 - called in pre-destruction setup (FUN_00878160)
#    Could be SpeedTree cache invalidation
decompile_at(0x00703980, "Pre-destruction call (from FUN_00878160)")

# 3. FUN_00664990 - BSTreeManager cleanup (called by destructor with param=1)
decompile_at(0x00664990, "BSTreeManager cleanup (FUN_00664990)")

# 4. FUN_00867f50 / FUN_00867f70 - lock functions for PDD
decompile_at(0x00867f50, "PDD lock function A (param_1==0)")
decompile_at(0x00867f70, "PDD lock function B (param_1==1)")

# 5. FUN_00418d20 - the NiObject destructor called by queue 0x08
decompile_at(0x00418d20, "NiObject destructor (queue 0x08 and 0x10)")

# 6. FUN_00418e00 - called by queue 0x04
decompile_at(0x00418e00, "Queue 0x04 destructor")

# 7. FUN_00868ce0 - called by queue 0x02 (physics?)
decompile_at(0x00868ce0, "Queue 0x02 handler (physics?)")

# 8. FUN_00651e30 / FUN_00651f40 - called after PDD in FUN_00878250
decompile_at(0x00651e30, "Post-PDD call 1 (from FUN_00878250)")
decompile_at(0x00651f40, "Post-PDD call 2 (from FUN_00878250)")

# 9. FUN_008781e0 - sets something to 0x7fffffff before PDD
decompile_at(0x008781e0, "Pre-PDD flag set (0x7fffffff)")

# 10. Find what references the gate variable that FUN_00869180 reads
#     We need to understand what controls queue skipping
find_refs_to(0x00869180, "Queue gate function")

# 11. FUN_00665be0 - removes tree entry from manager (called from FUN_0043dac0)
decompile_at(0x00665be0, "Remove tree from manager")

# 12. FUN_00664f50 - find tree in manager (called from FUN_0043da00)
decompile_at(0x00664f50, "Find tree in manager")

# 13. FUN_00665b80 - remove tree entry (called from FUN_0043da00)
decompile_at(0x00665b80, "Remove tree entry from manager")

# 14. Decompile FUN_0078d1f0 - gate check for queue 0x10
decompile_at(0x0078d1f0, "Queue 0x10 gate check")

# 15. Decompile FUN_00868250 - gate check for queues 0x08, 0x04, 0x01
decompile_at(0x00868250, "Queue 0x08/0x04/0x01 gate check (lock acquire?)")

write("")
write("=" * 60)
write("DONE")
write("=" * 60)

out.close()
print("Output written to: " + outfile)
