# @category Analysis
# @description Trace BSTreeNode lifecycle through quarantine — what reads freed BSTreeNode
#   memory and when, to determine why ring buffer quarantine crashes but double-buffer doesn't
#
# Key question: The old double-buffer (1-epoch drain at Phase 7) WORKS.
# The new ring buffer (2-epoch drain at Phase 7) CRASHES with BSTreeNode RefCount:0.
# More protection should be SAFER, not less safe. Something else must differ.
#
# Hypothesis to test:
#   - Does something ACCESS BSTreeNode memory between Phase 7 drain and Phase 10?
#   - Does the async flush path (0x00C459D0) read BSTreeNode data?
#   - Is there a code path that reads quarantined BSTreeNode AFTER mi_free?
#   - Does HeapCompact stage 3 (HavokGC) somehow invalidate BSTreeNode state?
#
# BSTreeManager singleton: DAT_011d5c48
# BSTreeNode vtable: 0x010668E4
# NiNode PDD queue: 0x011de808

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


write("Quarantine BSTreeNode Lifecycle Analysis")
write("=" * 70)
write("")
write("Goal: Find WHY ring buffer (2-epoch) crashes when double-buffer (1-epoch) doesn't")
write("")

# ===================================================================
# PART 1: BSTreeManager readers — who iterates the tree node map?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: BSTreeManager Readers (who accesses tree node map)")
write("#" * 70)
write("# DAT_011d5c48 = BSTreeManager singleton")
write("# Any function reading this after we mi_free BSTreeNodes is a crash candidate")

find_refs_to(0x011d5c48, "BSTreeManager singleton (DAT_011d5c48)")

# Key BSTreeManager functions that iterate the map
decompile_at(0x006649D0, "BSTreeManager::UpdateTrees (iterates map, accesses nodes)")
find_and_print_calls_from(0x006649D0, "BSTreeManager::UpdateTrees")

decompile_at(0x00664C80, "BSTreeManager map iteration (near UpdateTrees)")
decompile_at(0x00664D80, "BSTreeManager map iteration 2")

# ===================================================================
# PART 2: RENDER path — does render read BSTreeManager map?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Render Path and BSTreeNode Access")
write("#" * 70)

# SpeedTree render functions
decompile_at(0x00665600, "SpeedTree render/update")
decompile_at(0x006668b0, "SpeedTree node processing (near crash addr 0x00666868)")
find_and_print_calls_from(0x006668b0, "SpeedTree node processing")

decompile_at(0x00666700, "SpeedTree function near 0x006667DF")
find_and_print_calls_from(0x00666700, "SpeedTree near crash")

# ===================================================================
# PART 3: What runs between Phase 7 (our drain) and Phase 10 (our hook)?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Main Loop Phases 7-10 (between drain and epoch advance)")
write("#" * 70)
write("# Phase 7 (0x0086eadf): our on_pre_ai — quarantine reclaim happens here")
write("# Phase 8 (0x0086ec87): AI_START")
write("# Phase 9 (0x0086ecba): RENDER — BSTreeManager accessed here?")
write("# Phase 10 (0x0086edf0): our on_mid_frame hook")
write("# Does RENDER iterate BSTreeManager map and access reclaimed nodes?")

decompile_at(0x0086ecba, "RENDER entry (Phase 9)")
find_and_print_calls_from(0x0086ecba, "RENDER entry")

# ===================================================================
# PART 4: DeferredCleanupSmall — does it trigger BSTreeNode access?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: DeferredCleanupSmall Internals")
write("#" * 70)

decompile_at(0x00878250, "DeferredCleanupSmall")
find_and_print_calls_from(0x00878250, "DeferredCleanupSmall")

# The async flush inside DeferredCleanupSmall
decompile_at(0x00C459D0, "Async flush (inside DeferredCleanupSmall)")
find_and_print_calls_from(0x00C459D0, "Async flush")

# ===================================================================
# PART 5: HeapCompact stage 3 (HavokGC) — does it touch BSTreeNode?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: HeapCompact Stage 3 (HavokGC) Internals")
write("#" * 70)

# Need to find what Stage 3 actually calls
decompile_at(0x00878110, "HeapCompact dispatcher")
find_and_print_calls_from(0x00878110, "HeapCompact dispatcher")

# Havok GC
decompile_at(0x00C3B860, "hkMemorySystem GC (if this is stage 3)")
find_and_print_calls_from(0x00C3B860, "hkMemorySystem GC")

# ===================================================================
# PART 6: BSTreeNode free path — when game frees a BSTreeNode, what
#   removes it from BSTreeManager BEFORE our quarantine gets it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: BSTreeNode Free Path")
write("#" * 70)

# When NiNode PDD queue processes a BSTreeNode:
# NiNode_Release → BSTreeNode::~BSTreeNode → TreeMgr_RemoveByKey → gheap_free
decompile_at(0x00418D20, "NiNode_Release (PDD queue 0x08 handler)")
find_and_print_calls_from(0x00418D20, "NiNode_Release")

# BSTreeNode destructor
decompile_at(0x0066B5F0, "BSTreeNode destructor")
find_and_print_calls_from(0x0066B5F0, "BSTreeNode destructor")

# What if BSTreeNode is freed WITHOUT PDD? Direct free paths:
decompile_at(0x0066BAA0, "BSTreeNode::Release (direct release, no PDD?)")
find_refs_to(0x0066BAA0, "BSTreeNode::Release callers")

# ===================================================================
# PART 7: The CFCC2C function (appears twice in crash callstack)
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_00CFCC2C (repeated in callstack)")
write("#" * 70)

decompile_at(0x00CFCC2C, "FUN_00CFCC2C (appears twice in crash stack)")
find_and_print_calls_from(0x00CFCC2C, "FUN_00CFCC2C")
find_refs_to(0x00CFCC2C, "FUN_00CFCC2C callers")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/quarantine_bstree_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
