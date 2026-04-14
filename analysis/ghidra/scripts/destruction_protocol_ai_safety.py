# @category Analysis
# @description Validate destruction_protocol AI safety: trace from pre_destruction_setup through cell unload, identify all points where AI threads could still access freed Havok shapes. Compare with vanilla CellTransitionHandler's StopHavok_DrainAI.

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
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


def find_callers_in_range(target_addr, range_start, range_end, label):
	write("")
	write("-" * 70)
	write("%s callers from 0x%08x-0x%08x" % (label, range_start, range_end))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		src = ref.getFromAddress().getOffset()
		if range_start <= src <= range_end and ref.getReferenceType().isCall():
			func = fm.getFunctionContaining(ref.getFromAddress())
			name = func.getName() if func else "???"
			write("  0x%08x in %s" % (src, name))
			count += 1
	write("  Total: %d callers" % count)


# ======================================================================
# MAIN ANALYSIS
# ======================================================================

write("DESTRUCTION_PROTOCOL AI SAFETY VALIDATION")
write("Goal: Can is_ai_active() reliably gate cell destruction?")
write("      Or do we need StopHavok_DrainAI?")
write("Crash: 0x00C94DA5 on AI Linear Task Thread 2")
write("=" * 70)

# SECTION 1: pre_destruction_setup — what exactly does it lock?
write("")
write("#" * 70)
write("# SECTION 1: pre_destruction_setup (FUN_00c3e310)")
write("# What does it lock? Does it prevent AI Linear Task dispatch?")
write("#" * 70)

decompile_at(0x00C3E310, "pre_destruction_setup (hkWorld_Lock)")
find_and_print_calls_from(0x00C3E310, "pre_destruction_setup")

# SECTION 2: post_destruction_restore — what does it unlock?
write("")
write("#" * 70)
write("# SECTION 2: post_destruction_restore (FUN_00c3e340)")
write("#" * 70)

decompile_at(0x00C3E340, "post_destruction_restore (hkWorld_Unlock)")

# SECTION 3: The actual lock mechanism — spin-wait on what?
write("")
write("#" * 70)
write("# SECTION 3: hkWorld_Lock actual acquire — FUN_00c3e750")
write("# What does it wait for? Does it drain AI workers?")
write("#" * 70)

decompile_at(0x00C3E750, "hkWorld_LockAcquire")

# SECTION 4: FUN_00446f70 — signal workers to stop
write("")
write("#" * 70)
write("# SECTION 4: FUN_00446f70 — called by hkWorld_Lock to signal workers")
write("# Does this stop AI Linear Task Threads too?")
write("#" * 70)

decompile_at(0x00446F70, "hkWorld_SignalWorkers")

# SECTION 5: Who reads the flag that FUN_00446f70 sets?
write("")
write("#" * 70)
write("# SECTION 5: What do workers check? Does AI raycast check it?")
write("#" * 70)

# FUN_00446f70 writes to world+0x44 or similar. Trace what reads it.
find_and_print_calls_from(0x00446F70, "hkWorld_SignalWorkers")

# SECTION 6: StopHavok_DrainAI — the vanilla safe path
write("")
write("#" * 70)
write("# SECTION 6: StopHavok_DrainAI (FUN_008324e0) — vanilla cell transition")
write("# This is what CellTransitionHandler uses. Can destruction_protocol")
write("# call it instead of the custom sleep+IO barrier?")
write("#" * 70)

decompile_at(0x008324E0, "StopHavok_DrainAI")
find_and_print_calls_from(0x008324E0, "StopHavok_DrainAI")

# SECTION 7: FUN_008304a0 — called first by StopHavok_DrainAI
write("")
write("#" * 70)
write("# SECTION 7: FUN_008304a0 — StopHavok step 1")
write("#" * 70)

decompile_at(0x008304A0, "StopHavok_Step1")

# SECTION 8: FUN_008300c0 — the wait with timeout
write("")
write("#" * 70)
write("# SECTION 8: FUN_008300c0 — the actual AI drain wait")
write("# Called with 1000ms timeout. What does it wait on?")
write("#" * 70)

decompile_at(0x008300C0, "AI_DrainWait")

# SECTION 9: Find all callers of StopHavok_DrainAI
write("")
write("#" * 70)
write("# SECTION 9: All callers of StopHavok_DrainAI")
write("#" * 70)

find_refs_to(0x008324E0, "StopHavok_DrainAI")

# SECTION 10: HeapCompact stage 5 — what does it free?
write("")
write("#" * 70)
write("# SECTION 10: HeapCompact stage 5 — does it free Havok shapes?")
write("# The crash: AI thread reads freed hkScaledMoppBvTreeShape")
write("# When does this shape get freed? Stage 5? PDD purge?")
write("#" * 70)

# bhkCollisionObject removes entities from Havok world
decompile_at(0x00C41FE0, "hkWorld_removeEntity")

# PDD queue 0x20 processes bhkCollisionObject destruction
find_refs_to(0x010C3B6C, "bhkCollisionObject_RTTI")

# SECTION 11: Is there a Havok broadphase flag that we can check?
write("")
write("#" * 70)
write("# SECTION 11: Havok broadphase — is there an 'in-flight query' flag?")
write("# If broadphase has a reader count, we could wait for it to drain")
write("#" * 70)

decompile_at(0x00C3E1B0, "HavokStep_or_SyncPair")
find_and_print_calls_from(0x00C3E1B0, "HavokStep_or_SyncPair")

# SECTION 12: FUN_00ad8da0 — PotentialAIWait from cell transition
write("")
write("#" * 70)
write("# SECTION 12: FUN_00ad8da0 — PotentialAIWait with timeout")
write("# Called by CellTransitionHandler. Can destruction_protocol use this?")
write("#" * 70)

decompile_at(0x00AD8DA0, "PotentialAIWait")
find_refs_to(0x00AD8DA0, "PotentialAIWait")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/destruction_protocol_ai_safety.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
