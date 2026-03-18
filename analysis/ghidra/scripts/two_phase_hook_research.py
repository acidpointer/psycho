# @category Analysis
# @description Deep research for two-phase hook: early-frame NiNode drain + post-render cell unload
#
# We need to understand:
#   1. WHY the game's early-frame PDD callers (lines 271, 347) don't drain
#      queue 0x08 fast enough during stress - what conditions gate them?
#   2. EXACT AI thread idle windows - when are AI threads guaranteed idle?
#   3. Safe hook points between lines 271-440 for our early-frame phase
#   4. What FUN_00878160 (pre-destruction setup) actually needs as preconditions
#   5. NiNode queue structure - can we monitor its size?
#
# Output: analysis/ghidra/output/memory/two_phase_hook_research.txt

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
	size = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes, Convention: %s" % (
		func.getName(), size,
		func.getCallingConventionName() or "unknown"))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > 15000:
			write(code[:15000])
			write("  ... [truncated at 15000 chars]")
		else:
			write(code)
	else:
		write("  [decompilation failed]")
	write("")

def find_calls_from(addr_int, label):
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


write("TWO-PHASE HOOK DEEP RESEARCH")
write("=" * 70)

# ===================================================================
# PART 1: FUN_008782b0 (line 271) — the conditional PDD caller
# This is the key function that calls FUN_00878160 + FUN_00878250.
# We need to understand EXACTLY when it fires and when it doesn't.
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_008782b0 — Early-frame conditional PDD (line 271)")
write("# WHY doesn't this fire often enough during stress?")
write("#" * 70)

decompile_at(0x008782b0, "FUN_008782b0 (early-frame conditional PDD, line 271)")
find_calls_from(0x008782b0, "FUN_008782b0")
find_refs_to(0x008782b0, "FUN_008782b0")

# ===================================================================
# PART 2: FUN_004556d0 (line 347) — another conditional PDD caller
# 3611 bytes — much larger. What conditions gate it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_004556d0 — Mid-frame conditional PDD (line 347)")
write("#" * 70)

decompile_at(0x004556d0, "FUN_004556d0 (mid-frame PDD, line 347, 3611 bytes)")
find_calls_from(0x004556d0, "FUN_004556d0")

# ===================================================================
# PART 3: MainLoop (FUN_0086e650) — we need the full frame flow
# Focus on lines 271-486 to find ALL safe hook points
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: MainLoop full decompilation")
write("# Need exact call sequence lines 271-486")
write("#" * 70)

decompile_at(0x0086e650, "MainLoop (2272 bytes, the frame)")

# ===================================================================
# PART 4: FUN_00878080 (line 379) — calls HeapCompact
# This runs between physics setup and AI dispatch.
# Could this be a safe hook point?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00878080 (line 379, HeapCompact caller)")
write("#" * 70)

decompile_at(0x00878080, "FUN_00878080 (line 379, calls HeapCompact)")
find_calls_from(0x00878080, "FUN_00878080")

# ===================================================================
# PART 5: AI dispatch/wait/reset — exact synchronization points
# Need to verify: between AI wait (line 440) and render (line 486),
# are AI threads guaranteed idle?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: AI Thread Synchronization Details")
write("#" * 70)

# AI_StartFrame (line 437) — dispatches AI threads
decompile_at(0x008c80e0, "AI_StartFrame (line 437, dispatches AI)")
find_calls_from(0x008c80e0, "AI_StartFrame")

# AI_ResetEvents (line 439) — resets AI thread events
decompile_at(0x008c78c0, "AI_ResetEvents (line 439)")

# AI_PostRender (line 497) — post-render AI signal
decompile_at(0x008c7990, "AI_PostRender (line 497)")
find_calls_from(0x008c7990, "AI_PostRender")

# AI_MainCoordinator — full orchestration
decompile_at(0x008c7da0, "AI_MainCoordinator (429 bytes)")

# What EXACTLY does AI_ResetEvents do? Does it wait or just reset?
# This determines if AI is guaranteed idle at line 440
decompile_at(0x008c7a70, "AI_Wait (WaitForSingleObject)")

# ===================================================================
# PART 6: NiNode queue (DAT_011de808) structure analysis
# We need to understand the queue data structure to monitor size
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: NiNode Queue Structure (DAT_011de808)")
write("#" * 70)

# FUN_00868330 — one of the queue management functions
decompile_at(0x00868330, "NiNode queue mgmt 1 (339 bytes)")
find_calls_from(0x00868330, "NiNode queue mgmt 1")

# FUN_00868850 — another queue management function (1166 bytes!)
decompile_at(0x00868850, "NiNode queue mgmt 2 (1166 bytes)")

# FUN_00fa1f30 — small function referencing the queue
decompile_at(0x00fa1f30, "Queue ref small (35 bytes)")

# FUN_00fd8da0 — small function referencing the queue
decompile_at(0x00fd8da0, "Queue ref small 2 (15 bytes)")

# ===================================================================
# PART 7: FUN_00878160 preconditions — what must be true before
# calling scene graph invalidation?
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Pre-destruction setup preconditions")
write("#" * 70)

# FUN_00c3e310 — first thing called by FUN_00878160
# Is this a lock? Critical section? What object?
decompile_at(0x00c3e310, "FUN_00c3e310 (first call in pre-destruction setup)")
find_refs_to(0x00c3e310, "FUN_00c3e310")

# DAT_01202d98 — the parameter passed to FUN_00c3e310
# What is this global? Who else uses it?
find_refs_to(0x01202d98, "DAT_01202d98 (param to FUN_00c3e310)")

# FUN_0043c4b0 — called conditionally by FUN_00878160 when param_2 != 0
decompile_at(0x0043c4b0, "FUN_0043c4b0 (conditional prep in pre-destruction)")

# FUN_004a0370 — called with result of FUN_0043c4b0
decompile_at(0x004a0370, "FUN_004a0370 (prep call 2)")

# FUN_008781f0 — called to read a value stored at param_1+8
decompile_at(0x008781f0, "FUN_008781f0 (reads state for pre-destruction)")

# ===================================================================
# PART 8: FUN_007ffe00 and FUN_007a1670 — scene graph setup/cleanup
# What exactly do these do? Can we skip parts that touch physics?
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Scene Graph Invalidation Internals")
write("#" * 70)

decompile_at(0x007ffe00, "FUN_007ffe00 (scene graph setup, 52 bytes)")
find_calls_from(0x007ffe00, "FUN_007ffe00")

decompile_at(0x007a1670, "FUN_007a1670 (scene graph cleanup, 219 bytes)")
find_calls_from(0x007a1670, "FUN_007a1670")

# FUN_00586150 — returns the object whose vtable+0x1c we call
decompile_at(0x00586150, "FUN_00586150 (get scene graph object, 20 bytes)")

# FUN_004b7210 — gets the renderer/scene graph root
decompile_at(0x004b7210, "FUN_004b7210 (get renderer, 10 bytes)")

# FUN_009373f0 — the condition check before invalidation
decompile_at(0x009373f0, "FUN_009373f0 (exterior check?, 16 bytes)")

# ===================================================================
# PART 9: FUN_0086ff70 (line 485, pre-render) — what does this do?
# This runs right before our hook. Could we move our NiNode drain here?
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: Pre-render maintenance (line 485)")
write("#" * 70)

decompile_at(0x0086ff70, "FUN_0086ff70 (pre-render maintenance, 1616 bytes)")
find_calls_from(0x0086ff70, "FUN_0086ff70")

# ===================================================================
# PART 10: FUN_005b6cd0 and FUN_0093d500 — other PDD callers
# Complete picture of all 5 callers
# ===================================================================
write("")
write("#" * 70)
write("# PART 10: Remaining PDD callers")
write("#" * 70)

decompile_at(0x005b6cd0, "FUN_005b6cd0 (PDD caller, 70 bytes)")
find_refs_to(0x005b6cd0, "FUN_005b6cd0")

decompile_at(0x0093d500, "FUN_0093d500 (PDD caller, 352 bytes)")
find_refs_to(0x0093d500, "FUN_0093d500")

decompile_at(0x0093cdf0, "FUN_0093cdf0 (PDD caller, 1779 bytes)")
find_refs_to(0x0093cdf0, "FUN_0093cdf0")

# ===================================================================
# PART 11: FUN_0086f940 (line 273) — cell transition handler in frame
# This conditionally calls FUN_0093bea0 which calls PDD
# ===================================================================
write("")
write("#" * 70)
write("# PART 11: FUN_0086f940 (line 273, cell transition in frame)")
write("#" * 70)

decompile_at(0x0086f940, "FUN_0086f940 (line 273, PreAI_CellHandler, 595 bytes)")
find_calls_from(0x0086f940, "FUN_0086f940")

# ===================================================================
# PART 12: DeferredCleanup_Small post-PDD work
# FUN_00878250 calls PDD then does other stuff. What?
# FUN_00651e30 and FUN_00651f40 — called after PDD
# ===================================================================
write("")
write("#" * 70)
write("# PART 12: Post-PDD cleanup (from DeferredCleanup_Small)")
write("#" * 70)

decompile_at(0x00651e30, "FUN_00651e30 (post-PDD call 1)")
find_calls_from(0x00651e30, "FUN_00651e30")

decompile_at(0x00651f40, "FUN_00651f40 (post-PDD call 2)")
find_calls_from(0x00651f40, "FUN_00651f40")

# FUN_00b5fd60 — called after FUN_00450b80 in DeferredCleanup_Small
decompile_at(0x00b5fd60, "FUN_00b5fd60 (called in DeferredCleanup_Small)")

# FUN_00c459d0 — async queue flush, called with param=0 in DeferredCleanup_Small
decompile_at(0x00c459d0, "FUN_00c459d0 (async queue flush)")

# ===================================================================
# PART 13: What is between lines 440 and 485?
# After AI wait completes and before render — is this a safe window?
# ===================================================================
write("")
write("#" * 70)
write("# PART 13: Functions between AI wait (440) and render (486)")
write("#" * 70)

# These are called in the frame between AI wait and render
# From the main loop decompilation we need to identify them
# FUN_0086f6a0 — post-render cleanup (line 502)
decompile_at(0x0086f6a0, "FUN_0086f6a0 (post-render cleanup, line 502)")
find_calls_from(0x0086f6a0, "FUN_0086f6a0")

# ===================================================================
# PART 14: FUN_00878250 (DeferredCleanup_Small) — who is param_1?
# The param controls whether FUN_00651e30/00651f40 are called.
# What does the caller pass?
# ===================================================================
write("")
write("#" * 70)
write("# PART 14: How callers invoke the pre-destruction + PDD sequence")
write("#" * 70)

# The 5 callers all call FUN_00878160 then FUN_00878250.
# What parameters do they pass? This tells us what state setup is needed.
# We already decompiled them above, but let's look at how they
# sequence the two calls and what params they use.

# FUN_008782b0 is the simplest — decompiled in Part 1
# Let's look at its caller context in the main loop more carefully

# What is DAT_011dfa18? (AI frame dispatch flag)
find_refs_to(0x011dfa18, "DAT_011dfa18 (AI dispatch flag)")

# What is DAT_011dfa19? (AI frame active flag)
find_refs_to(0x011dfa19, "DAT_011dfa19 (AI active flag)")


write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

# Write output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/two_phase_hook_research.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
