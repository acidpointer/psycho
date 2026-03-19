# @category Analysis
# @description Research AI thread pause/resume and HeapCompact's thread sync
#
# The original game solves the NiNode/Havok cleanup problem via:
#   HeapCompact Stage 5: TLS=0 + FindCellToUnload + PDD (main thread only)
#   HeapCompact Stage 8: non-main threads Sleep(1) loop up to 15000x
#
# This creates a safe window where ONLY the main thread runs, making it
# safe to destroy any object. We need to understand if we can create a
# similar safe window without going through the HeapCompact retry loop.
#
# Key questions:
#   1. Can we pause AI threads by NOT dispatching them for one frame?
#   2. What does FUN_008c80e0('\0') do? Does it stop AI dispatch?
#   3. Can we check DAT_011dfa18/19 to know if AI threads are idle?
#   4. Is there a function between AI wait and render we can hook?
#   5. Can we call AI_Wait ourselves to ensure AI is done?
#
# Output: analysis/ghidra/output/memory/ai_pause_mechanism.txt

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


write("AI THREAD PAUSE/RESUME + HEAPCOMPACT SYNC MECHANISM")
write("=" * 70)

# ===================================================================
# PART 1: AI Start/Stop mechanism
# FUN_008c80e0 is called with '\x01' to START and '\0' might STOP.
# If we can stop AI before cleanup and restart after, we have a
# safe window for full PDD.
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: AI Start/Stop Dispatch Control")
write("#" * 70)

# FUN_008c80e0 — the AI start/stop function
# Called as FUN_008c80e0('\x01') to start AI in the main loop
# What happens with FUN_008c80e0('\0')?
decompile_at(0x008c80e0, "AI_StartFrame (dispatch control)")

# FUN_008c80c0 — called by AI_StartFrame when stopping
decompile_at(0x008c80c0, "FUN_008c80c0 (called when AI stops)")
find_calls_from(0x008c80c0, "FUN_008c80c0")

# FUN_008c80d0 — called by AI_MainCoordinator near the end
decompile_at(0x008c80d0, "FUN_008c80d0 (called at end of AI coordinator)")

# Who reads DAT_011dfa18? This is the AI dispatch flag.
# If we set it to 0, do AI threads stop?
find_refs_to(0x011dfa18, "DAT_011dfa18 (AI dispatch flag)")

# Who reads DAT_011dfa19? This is the AI active flag.
find_refs_to(0x011dfa19, "DAT_011dfa19 (AI active flag)")

# ===================================================================
# PART 2: AI thread wait/signal primitives
# Can we wait for AI thread completion ourselves?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: AI Wait/Signal Primitives")
write("#" * 70)

# FUN_008c79e0 — AI_Dispatch (SetEvent)
decompile_at(0x008c79e0, "AI_Dispatch (SetEvent for AI)")

# FUN_008c7a70 — AI_Wait (WaitForSingleObject)
decompile_at(0x008c7a70, "AI_Wait (WaitForSingleObject)")

# FUN_008c7490 — called by AI_PostRender for each thread
decompile_at(0x008c7490, "FUN_008c7490 (AI post-render per-thread)")
find_calls_from(0x008c7490, "FUN_008c7490")

# FUN_008c9fb0 — called by AI_ResetEvents for each thread
decompile_at(0x008c9fb0, "FUN_008c9fb0 (AI dispatch per-thread)")
find_calls_from(0x008c9fb0, "FUN_008c9fb0")

# FUN_008ca070 — the SINGLE-threaded AI path (when thread count < 2)
# Called instead of 008c80e0/008c78c0 pair
decompile_at(0x008ca070, "FUN_008ca070 (single-threaded AI)")
find_calls_from(0x008ca070, "FUN_008ca070")

# FUN_008ca300 — the single-threaded post-render AI path
decompile_at(0x008ca300, "FUN_008ca300 (single-threaded post-render AI)")

# ===================================================================
# PART 3: HeapCompact Stage 8 — how threads sleep
# This is the game's own thread sync for safe cleanup
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: HeapCompact Thread Sync (Stage 8)")
write("#" * 70)

# FUN_00866da0 — called in Stage 8, gets a thread ID(?)
decompile_at(0x00866da0, "FUN_00866da0 (Stage 8 thread check)")

# FUN_00866dc0 — called in Stage 8
decompile_at(0x00866dc0, "FUN_00866dc0 (Stage 8 thread op 1)")

# FUN_00866de0 — called in Stage 8
decompile_at(0x00866de0, "FUN_00866de0 (Stage 8 thread op 2)")

# DAT_01202d98 — used extensively. What is this object?
# It appears in HeapCompact, MainLoop, and pre-destruction setup.
decompile_at(0x00c3dbf0, "FUN_00c3dbf0 (called on DAT_01202d98 in MainLoop)")

# ===================================================================
# PART 4: Functions between AI wait and render (the safe window)
# MainLoop lines ~860-903: after AI dispatch, before render
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Safe Window Functions (after AI wait, before render)")
write("#" * 70)

# FUN_0086fc60 — called at line ~860, after AI dispatch
decompile_at(0x0086fc60, "FUN_0086fc60 (post-AI dispatch)")
find_calls_from(0x0086fc60, "FUN_0086fc60")

# FUN_0086fbe0 — called at line ~812
decompile_at(0x0086fbe0, "FUN_0086fbe0 (mid-frame)")
find_calls_from(0x0086fbe0, "FUN_0086fbe0")

# FUN_0086fd70 — called in multiple places
decompile_at(0x0086fd70, "FUN_0086fd70 (frame maintenance)")
find_calls_from(0x0086fd70, "FUN_0086fd70")

# FUN_00713d80 — used to get the AI event object passed to dispatch/wait
decompile_at(0x00713d80, "FUN_00713d80 (get AI event handle object)")

# ===================================================================
# PART 5: The AI coordinator's dispatch/wait pattern
# Understanding the EXACT sequence of dispatch → work → wait
# tells us when AI is guaranteed idle
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: AI Coordinator Dispatch/Wait Sequence Details")
write("#" * 70)

# FUN_008c7bd0 — AI_Dispatcher2 (alternative dispatcher)
decompile_at(0x008c7bd0, "AI_Dispatcher2 (418 bytes)")
find_calls_from(0x008c7bd0, "AI_Dispatcher2")

# FUN_008c7290 — AI_CoordinatorCaller (calls both coordinators)
decompile_at(0x008c7290, "AI_CoordinatorCaller")
find_calls_from(0x008c7290, "AI_CoordinatorCaller")
find_refs_to(0x008c7290, "AI_CoordinatorCaller")

# ===================================================================
# PART 6: FUN_00868d10 — called right after FUN_00868850
# What does this do? Is it queue finalization?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_00868d10 (post-queue-drain)")
write("#" * 70)

decompile_at(0x00868d10, "FUN_00868d10 (called after per-frame drain)")
find_calls_from(0x00868d10, "FUN_00868d10")

# ===================================================================
# PART 7: FUN_00878360 — the drain multiplier check
# Controls whether FUN_00868850 uses batch size 1x or 2x
# If we can always return true, drain rate doubles
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Drain Multiplier Control")
write("#" * 70)

decompile_at(0x00878360, "FUN_00878360 (drain multiplier check, 20 bytes)")
find_refs_to(0x00878360, "FUN_00878360")

# FUN_00878340 — called after PDD in FUN_008782b0
decompile_at(0x00878340, "FUN_00878340 (post-PDD check)")

# ===================================================================
# PART 8: FUN_00878200 — the post-destruction restore
# Called after FUN_00878160 + FUN_00878250 sequence
# What state does it restore?
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Post-Destruction State Restore")
write("#" * 70)

decompile_at(0x00878200, "FUN_00878200 (post-destruction restore, 80 bytes)")
find_calls_from(0x00878200, "FUN_00878200")

# ===================================================================
# PART 9: ForceUnloadCell vs FindCellToUnload
# HeapCompact Stage 5 falls back to ForceUnloadCell.
# Is it more aggressive? Does it handle BSTreeNodes differently?
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: ForceUnloadCell (HeapCompact fallback)")
write("#" * 70)

decompile_at(0x004539a0, "ForceUnloadCell (196 bytes)")
find_calls_from(0x004539a0, "ForceUnloadCell")

# ===================================================================
# PART 10: What does FUN_00868850 do BEFORE processing queues?
# FUN_00867f50 and FUN_00867f80 — the setup/cleanup
# Are these locks that prevent concurrent access?
# ===================================================================
write("")
write("#" * 70)
write("# PART 10: Per-Frame Drain Setup/Cleanup")
write("#" * 70)

decompile_at(0x00867f50, "FUN_00867f50 (per-frame drain setup)")
find_calls_from(0x00867f50, "FUN_00867f50")

decompile_at(0x00867f80, "FUN_00867f80 (per-frame drain cleanup)")
find_calls_from(0x00867f80, "FUN_00867f80")

# ===================================================================
# PART 11: FUN_0045bc80 — called between AI dispatch and render
# It receives DAT_011dea10 and two '\x01' params
# ===================================================================
write("")
write("#" * 70)
write("# PART 11: Cell Management Between AI and Render")
write("#" * 70)

decompile_at(0x0045bc80, "FUN_0045bc80 (cell management, called pre-render)")
find_calls_from(0x0045bc80, "FUN_0045bc80")

# FUN_0045b070 — called right after FUN_0045bc80
decompile_at(0x0045b070, "FUN_0045b070 (cell management 2)")
find_calls_from(0x0045b070, "FUN_0045b070")

# ===================================================================
# PART 12: Can we read ALL queue sizes at once?
# Understanding total deferred object counts helps us decide strategy
# ===================================================================
write("")
write("#" * 70)
write("# PART 12: All PDD Queue Addresses and Size Reading")
write("#" * 70)

# Each queue has its count at offset +0x0A (u16)
# Let's verify by checking the queue init function
decompile_at(0x00869c60, "Queue init (FUN_00869c60)")

# FUN_008693c0 — enqueue function (adds items to queue 0x08)
decompile_at(0x008693c0, "FUN_008693c0 (enqueue to NiNode queue, 33 bytes)")
find_calls_from(0x008693c0, "FUN_008693c0")

# FUN_00869420/00869510/008694c0 — enqueue for other queues
decompile_at(0x00869420, "FUN_00869420 (enqueue function)")
decompile_at(0x00869510, "FUN_00869510 (enqueue function)")
decompile_at(0x008694c0, "FUN_008694c0 (enqueue function)")

# ===================================================================
# PART 13: The AIThread_MainLoop idle check
# When AI threads are waiting, they call WaitForSingleObject(INFINITE)
# Can we check if they're in this waiting state?
# ===================================================================
write("")
write("#" * 70)
write("# PART 13: AI Thread Idle Detection")
write("#" * 70)

# FUN_008c7720 — AIThread_MainLoop
decompile_at(0x008c7720, "AIThread_MainLoop (111 bytes)")

# FUN_008c7190 — AIThread_TaskDispatch (calls fn ptr at offset 0x4c)
decompile_at(0x008c7190, "AIThread_TaskDispatch (28 bytes)")

# What shutdown flag do AI threads check?
# From the decompilation: while (!shutdown) { WaitForSingleObject... }


write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

# Write output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/ai_pause_mechanism.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
