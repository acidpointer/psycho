# Ghidra Jython script: Find SpeedTree cache management functions
# Goal: Find the function that flushes/invalidates BSTreeManager's caches
# so we can call it before ProcessDeferredDestruction

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()
funcMgr = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()
af = currentProgram.getAddressFactory()

BSTREE_MGR_PTR = 0x11D5C48
BSTREE_MODEL_VTBL = 0x1066768
BSTREE_NODE_VTBL = 0x10668E4

outfile = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/speedtree_cache.txt"
out = open(outfile, "w")

def write(msg):
	out.write(msg + "\n")
	print(msg)

def decompile_func(func):
	if func is None:
		return ""
	results = decomp.decompileFunction(func, 30, monitor)
	if results is None:
		return ""
	decompiledFunc = results.getDecompiledFunction()
	if decompiledFunc is None:
		return ""
	return decompiledFunc.getC()

write("=" * 70)
write("SpeedTree Cache Analysis")
write("=" * 70)
write("")

# 1. Find all functions referencing BSTreeManager singleton (0x11D5C48)
write("=" * 70)
write("PART 1: Functions referencing BSTreeManager singleton (0x11D5C48)")
write("=" * 70)

addr = af.getDefaultAddressSpace().getAddress(BSTREE_MGR_PTR)
refs = refMgr.getReferencesTo(addr)
mgr_funcs = set()

for ref in refs:
	fromAddr = ref.getFromAddress()
	func = funcMgr.getFunctionContaining(fromAddr)
	if func is not None:
		mgr_funcs.add(func)

write("Found %d functions referencing BSTreeManager singleton:" % len(mgr_funcs))
write("")

for func in sorted(mgr_funcs, key=lambda f: f.getEntryPoint().getOffset()):
	entry = func.getEntryPoint()
	size = func.getBody().getNumAddresses()
	write("  0x%08X  %s  (%d bytes)" % (entry.getOffset(), func.getName(), size))

write("")

# 2. Decompile each function referencing BSTreeManager
write("=" * 70)
write("PART 2: Decompilation of BSTreeManager-referencing functions")
write("=" * 70)

for func in sorted(mgr_funcs, key=lambda f: f.getEntryPoint().getOffset()):
	entry = func.getEntryPoint()
	size = func.getBody().getNumAddresses()
	write("")
	write("-" * 60)
	write("Function: %s @ 0x%08X (%d bytes)" % (func.getName(), entry.getOffset(), size))
	write("-" * 60)
	code = decompile_func(func)
	if code:
		write(code)
	else:
		write("  [decompilation failed]")

write("")

# 3. Find functions referencing BSTreeModel vtable
write("=" * 70)
write("PART 3: Functions referencing BSTreeModel vtable (0x%08X)" % BSTREE_MODEL_VTBL)
write("=" * 70)

addr2 = af.getDefaultAddressSpace().getAddress(BSTREE_MODEL_VTBL)
refs2 = refMgr.getReferencesTo(addr2)
model_funcs = set()

for ref in refs2:
	fromAddr = ref.getFromAddress()
	func = funcMgr.getFunctionContaining(fromAddr)
	if func is not None:
		model_funcs.add(func)

write("Found %d functions referencing BSTreeModel vtable:" % len(model_funcs))
for func in sorted(model_funcs, key=lambda f: f.getEntryPoint().getOffset()):
	entry = func.getEntryPoint()
	size = func.getBody().getNumAddresses()
	write("  0x%08X  %s  (%d bytes)" % (entry.getOffset(), func.getName(), size))

write("")

# 4. Find functions referencing BSTreeNode vtable
write("=" * 70)
write("PART 4: Functions referencing BSTreeNode vtable (0x%08X)" % BSTREE_NODE_VTBL)
write("=" * 70)

addr3 = af.getDefaultAddressSpace().getAddress(BSTREE_NODE_VTBL)
refs3 = refMgr.getReferencesTo(addr3)
node_funcs = set()

for ref in refs3:
	fromAddr = ref.getFromAddress()
	func = funcMgr.getFunctionContaining(fromAddr)
	if func is not None:
		node_funcs.add(func)

write("Found %d functions referencing BSTreeNode vtable:" % len(node_funcs))
for func in sorted(node_funcs, key=lambda f: f.getEntryPoint().getOffset()):
	entry = func.getEntryPoint()
	size = func.getBody().getNumAddresses()
	write("  0x%08X  %s  (%d bytes)" % (entry.getOffset(), func.getName(), size))

write("")

# 5. Analyze ProcessDeferredDestruction queues
write("=" * 70)
write("PART 5: ProcessDeferredDestruction (0x00868D70) full decompilation")
write("=" * 70)

pdd_addr = af.getDefaultAddressSpace().getAddress(0x00868D70)
pdd_func = funcMgr.getFunctionAt(pdd_addr)
if pdd_func is not None:
	code = decompile_func(pdd_func)
	if code:
		write(code)
	else:
		write("[decompilation failed]")
else:
	write("[function not found at 0x00868D70]")

write("")

# 6. Look for DAT_011de808 (deferred destruction flags) references
write("=" * 70)
write("PART 6: References to deferred destruction flag DAT_011de808")
write("=" * 70)

flag_addr = af.getDefaultAddressSpace().getAddress(0x011de808)
flag_refs = refMgr.getReferencesTo(flag_addr)
flag_funcs = set()

for ref in flag_refs:
	fromAddr = ref.getFromAddress()
	func = funcMgr.getFunctionContaining(fromAddr)
	if func is not None:
		flag_funcs.add(func)

write("Found %d functions referencing 0x011de808:" % len(flag_funcs))
for func in sorted(flag_funcs, key=lambda f: f.getEntryPoint().getOffset()):
	entry = func.getEntryPoint()
	write("  0x%08X  %s" % (entry.getOffset(), func.getName()))

write("")

# 7. Look at what gets called right before ProcessDeferredDestruction
#    in the game's normal flow (FUN_00878250 which calls it)
write("=" * 70)
write("PART 7: FUN_00878250 (caller of ProcessDeferredDestruction)")
write("=" * 70)

caller_addr = af.getDefaultAddressSpace().getAddress(0x00878250)
caller_func = funcMgr.getFunctionAt(caller_addr)
if caller_func is not None:
	code = decompile_func(caller_func)
	if code:
		write(code)
	else:
		write("[decompilation failed]")
else:
	write("[function not found]")

write("")

# 8. Also check FUN_00878160 (called right before 00878250 in FUN_008782b0)
write("=" * 70)
write("PART 8: FUN_00878160 (pre-destruction setup)")
write("=" * 70)

setup_addr = af.getDefaultAddressSpace().getAddress(0x00878160)
setup_func = funcMgr.getFunctionAt(setup_addr)
if setup_func is not None:
	code = decompile_func(setup_func)
	if code:
		write(code)
	else:
		write("[decompilation failed]")
else:
	write("[function not found]")

write("")

# 9. Decompile interesting BSTreeManager functions (those that look like cleanup)
write("=" * 70)
write("PART 9: Cross-reference - functions in both BSTreeManager AND model/node sets")
write("=" * 70)

overlap = mgr_funcs.intersection(model_funcs.union(node_funcs))
for func in sorted(overlap, key=lambda f: f.getEntryPoint().getOffset()):
	entry = func.getEntryPoint()
	write("  0x%08X  %s (in both manager and model/node refs)" % (entry.getOffset(), func.getName()))

write("")
write("=" * 70)
write("DONE")
write("=" * 70)

out.close()
print("Output written to: " + outfile)
