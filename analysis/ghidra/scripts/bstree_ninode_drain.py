# @category Analysis
# @description BSTreeManager + NiNode queue drain analysis for safe PDD queue 0x08 processing
#
# Goal: Determine how to safely drain PDD queue 0x08 (NiNode/BSTreeNode)
# from the post-render hook at 0x008705D0.
#
# The core problem: BSTreeManager (DAT_011d5c48) holds cross-frame pointers
# to BSTreeNode objects. Destroying BSTreeNodes via PDD without first removing
# them from the cache causes SpeedTree use-after-free crashes.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label):
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
	write("  Function: %s, Size: %d bytes, Convention: %s" % (
		func.getName(),
		func.getBody().getNumAddresses(),
		func.getCallingConventionName() or "unknown"))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > 12000:
			write(code[:12000])
			write("  ... [truncated at 12000 chars]")
		else:
			write(code)
	else:
		write("  [decompilation failed]")
	write("")

def find_calls_from(addr_int, label):
	"""Find all functions called BY a given function via instruction refs."""
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return []
	called = []
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				called.append(ref.getToAddress().getOffset())
	unique = sorted(set(called))
	write("  Calls %d unique functions:" % len(unique))
	for t in unique:
		f = fm.getFunctionAt(toAddr(t))
		n = f.getName() if f is not None else "???"
		sz = f.getBody().getNumAddresses() if f is not None else 0
		write("    -> 0x%08x  %s  (%d bytes)" % (t, n, sz))
	return unique

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	funcs = set()
	count = 0
	for ref in refs:
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			funcs.add(from_func)
		count += 1
	write("  %d references from %d functions:" % (count, len(funcs)))
	for func in sorted(funcs, key=lambda f: f.getEntryPoint().getOffset()):
		entry = func.getEntryPoint()
		write("    0x%08x  %s  (%d bytes)" % (
			entry.getOffset(),
			func.getName(),
			func.getBody().getNumAddresses()))
	return funcs


write("BSTreeManager + NiNode Queue Drain Analysis")
write("=" * 70)
write("")
write("CONTEXT: We need to safely drain PDD queue 0x08 (NiNode/BSTreeNode)")
write("from our post-render hook at 0x008705D0. Currently skipped because")
write("BSTreeManager holds cross-frame pointers to BSTreeNodes.")

# ===================================================================
# PART 1: Cell unload path - how does DestroyCell handle BSTreeNodes?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Cell Destruction Path")
write("#" * 70)

decompile_at(0x00462290, "DestroyCell (called by FindCellToUnload)")
find_calls_from(0x00462290, "DestroyCell")

decompile_at(0x0043dac0, "TreeMgr_RemoveOnState (remove tree when state > 3)")
find_refs_to(0x0043dac0, "TreeMgr_RemoveOnState")

# ===================================================================
# PART 2: BSTreeManager map structure and iteration
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: BSTreeManager Map Structure")
write("#" * 70)

decompile_at(0x00664870, "BSTreeManager Create (constructor)")
decompile_at(0x00664740, "BSTreeManager internal cleanup (called by FUN_00664990)")
decompile_at(0x00664990, "BSTreeManager Cleanup")
decompile_at(0x00664940, "BSTreeManager Destroy")

decompile_at(0x00665be0, "TreeMgr_RemoveByKey (from treeNodesMap)")
decompile_at(0x00665b80, "TreeMgr_RemoveEntry (from map)")
decompile_at(0x00664f50, "TreeMgr_FindOrCreate (874 bytes, reveals map layout)")

# ===================================================================
# PART 3: Scene graph invalidation path
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Scene Graph Invalidation (pre-destruction setup)")
write("#" * 70)

decompile_at(0x00878160, "Pre-destruction setup (FUN_00878160)")
find_refs_to(0x00878160, "Pre-destruction setup")

decompile_at(0x00703980, "Pre-destruction call (from FUN_00878160)")
find_calls_from(0x00703980, "Pre-destruction call")

decompile_at(0x007160b0, "Scene graph invalidation? (FUN_007160b0)")
find_refs_to(0x007160b0, "FUN_007160b0")
find_calls_from(0x007160b0, "FUN_007160b0")

# ===================================================================
# PART 4: NiNode destructor chain - what happens when queue 0x08 runs
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: NiNode Destructor Chain (Queue 0x08)")
write("#" * 70)

decompile_at(0x00418d20, "NiNode_Release (queue 0x08 destructor)")
find_calls_from(0x00418d20, "NiNode_Release")

# ===================================================================
# PART 5: Cell transition handler PDD path - the SAFE full PDD
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Cell Transition Safe PDD Path")
write("#" * 70)

decompile_at(0x008774a0, "CellTransitionHandler (safe full PDD)")
find_calls_from(0x008774a0, "CellTransitionHandler")

decompile_at(0x0093bea0, "CellTransition_Conditional (calls PDD)")

decompile_at(0x00878250, "DeferredCleanup_Small (calls PDD(1))")
find_refs_to(0x00878250, "DeferredCleanup_Small")

# ===================================================================
# PART 6: HeapCompact Stage 5 - the original safe unload+PDD sequence
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: HeapCompact Stage 5")
write("#" * 70)

decompile_at(0x00866a90, "HeapCompact (stage 5 = cell unload + PDD)")
decompile_at(0x00452490, "ProcessPendingCleanup")

# ===================================================================
# PART 7: BSTreeNode lifecycle - construction, caching, removal
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: BSTreeNode Lifecycle")
write("#" * 70)

decompile_at(0x0066b120, "BSTreeNode constructor (1161 bytes)")
decompile_at(0x0043da00, "TreeMgr_AddTree (adds to BSTreeManager)")
decompile_at(0x0066b6c0, "BSTreeNode init/setup")

# ===================================================================
# PART 8: Generic pre-cleanup called before cell ops
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Generic Pre-Cleanup")
write("#" * 70)

decompile_at(0x00453a70, "Generic cleanup (FUN_00453a70)")

# ===================================================================
# PART 9: Cross-reference - queue writers and BSTreeManager readers
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: NiNode Queue + BSTreeManager Cross-References")
write("#" * 70)

find_refs_to(0x011de808, "DAT_011de808 (NiNode PDD queue)")
find_refs_to(0x011d5c48, "DAT_011d5c48 (BSTreeManager singleton)")

# ===================================================================
# PART 10: Big update function (8357 bytes, another PDD caller)
# ===================================================================
write("")
write("#" * 70)
write("# PART 10: Big Update Function")
write("#" * 70)

decompile_at(0x0045dfe0, "Big update function (8357 bytes, calls PDD)")
find_calls_from(0x0045dfe0, "Big update function")

write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

# Write output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bstree_ninode_drain.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
