# @category Analysis
# @description OOM worker recovery research: decompile the game heap retry
# loop, the CRT malloc wrapper, every OOM stage handler, the AI join path,
# and the BSTaskManagerThread loop so we can plan the rework.

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
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		write(
			"  %s @ 0x%08x (in %s @ 0x%08x)"
			% (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr)
		)
		count += 1
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


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
					"  0x%08x -> 0x%08x %s"
					% (inst.getAddress().getOffset(), tgt, name)
				)
				count += 1
	write("  Total: %d calls" % count)


def find_callers_of(addr_int, label, limit=60):
	write("")
	write("-" * 70)
	write("CALLERS OF %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen_entries = {}
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen_entries:
			continue
		seen_entries[entry] = func.getName()
	keys = sorted(seen_entries.keys())
	shown = 0
	for k in keys:
		if shown >= limit:
			break
		write("  0x%08x %s" % (k, seen_entries[k]))
		shown += 1
	write("  Total unique callers: %d" % len(keys))


def find_sleep_and_wait_calls(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return
	write("")
	write("-" * 70)
	write("LOCK/WAIT CALLS inside %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	hits = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if not inst.getFlowType().isCall():
			continue
		refs = inst.getReferencesFrom()
		for ref in refs:
			tgt = ref.getToAddress()
			if tgt is None:
				continue
			tgt_func = fm.getFunctionAt(tgt)
			if tgt_func is None:
				continue
			name = tgt_func.getName()
			if is_lock_or_wait_name(name):
				write(
					"  0x%08x -> %s (0x%08x)"
					% (inst.getAddress().getOffset(), name, tgt.getOffset())
				)
				hits += 1
	write("  Total lock/wait calls: %d" % hits)


def is_lock_or_wait_name(name):
	n = name.lower()
	if "critical" in n:
		return True
	if "srwlock" in n:
		return True
	if "waitfor" in n:
		return True
	if "sleep" in n:
		return True
	if "event" in n:
		return True
	if "semaphore" in n:
		return True
	if "mutex" in n:
		return True
	return False


def find_thread_spawn_sites():
	write("")
	write("-" * 70)
	write("THREAD SPAWN SITES (_beginthreadex / CreateThread)")
	write("-" * 70)
	st = currentProgram.getSymbolTable()
	names = ["_beginthreadex", "beginthreadex", "CreateThread"]
	addrs = []
	for nm in names:
		it = st.getSymbolIterator(nm, True)
		while it.hasNext():
			sym = it.next()
			addrs.append(sym.getAddress().getOffset())
	# De-dup
	seen = {}
	for a in addrs:
		seen[a] = 1
	keys = sorted(seen.keys())
	write("  API entry symbols: %d" % len(keys))
	for k in keys:
		write("    0x%08x" % k)
	# For every API addr, list callers
	for k in keys:
		write("")
		write("  Callers of API at 0x%08x:" % k)
		refs = ref_mgr.getReferencesTo(toAddr(k))
		caller_entries = {}
		while refs.hasNext():
			ref = refs.next()
			if not ref.getReferenceType().isCall():
				continue
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is None:
				continue
			fent = func.getEntryPoint().getOffset()
			caller_entries[fent] = func.getName()
		for ce in sorted(caller_entries.keys()):
			write("    caller 0x%08x %s" % (ce, caller_entries[ce]))


# ======================================================================
# MAIN BODY
# ======================================================================

write("OOM WORKER RECOVERY RESEARCH")
write("Focus: vanilla retry loop, CRT fallback, OOM stages, thread procs")
write("=" * 70)

# ---------------------------------------------------------------------
# K2: vanilla FUN_00aa3e40 retry loop and CRT fallback
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K2: Vanilla game heap retry loop (FUN_00aa3e40)")
write("#" * 70)

decompile_at(0x00aa3e40, "GameHeap_Alloc_RetryLoop")
find_and_print_calls_from(0x00aa3e40, "GameHeap_Alloc_RetryLoop")

write("")
write("#" * 70)
write("# K2: CRT _malloc fallback wrapper (FUN_00aa4290)")
write("# -- what heap does vanilla fall back to on give_up?")
write("#" * 70)

decompile_at(0x00aa4290, "CRT_malloc_wrapper")
find_and_print_calls_from(0x00aa4290, "CRT_malloc_wrapper")

# The next function on the wrapper is the real _malloc symbol. Decompile
# a few likely addresses so we see where CRT heap comes from.
decompile_at(0x00ecd000, "crt_malloc_maybe_A")
decompile_at(0x00ecd060, "crt_malloc_maybe_B")
decompile_at(0x00ecd100, "crt_malloc_maybe_C")

# ---------------------------------------------------------------------
# K2: OOM stage executor (FUN_00866a90) + lock audit of each stage
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K2: OOM stage executor (FUN_00866a90)")
write("#" * 70)

decompile_at(0x00866a90, "OOM_StageExec")
find_sleep_and_wait_calls(0x00866a90, "OOM_StageExec")

write("")
write("#" * 70)
write("# K2: BSTask get_owner / release_sem / signal_idle (stage 8)")
write("#" * 70)

decompile_at(0x00866da0, "BSTask_GetOwner")
decompile_at(0x00866dc0, "BSTask_ReleaseSem")
decompile_at(0x00866de0, "BSTask_SignalIdle")

# ---------------------------------------------------------------------
# K3/K5: lock audit of each stage handler that gheap may call
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K3/K5: lock/wait calls inside stage handlers")
write("#" * 70)

find_sleep_and_wait_calls(0x00868d70, "PDD_FUN_00868d70")
find_sleep_and_wait_calls(0x00c459d0, "HavokGC_FUN_00c459d0")
find_sleep_and_wait_calls(0x00453a80, "FindCellToUnload_FUN_00453a80")
find_sleep_and_wait_calls(0x00452490, "ProcessPendingCleanup_FUN_00452490")
find_sleep_and_wait_calls(0x00aa5c80, "SBM_Dealloc_FUN_00aa5c80")
find_sleep_and_wait_calls(0x00aa7030, "SBM_GlobalCleanup_FUN_00aa7030")
find_sleep_and_wait_calls(0x0078d200, "Stage4_FUN_0078d200")

# ---------------------------------------------------------------------
# K4: main-thread join / wait primitives for workers
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K4: main-thread wait points on worker completion")
write("#" * 70)

decompile_at(0x008c7990, "AI_Join")
find_and_print_calls_from(0x008c7990, "AI_Join")

decompile_at(0x008c7490, "AI_Join_inner")
find_sleep_and_wait_calls(0x008c7490, "AI_Join_inner")

decompile_at(0x008c78c0, "AI_Start")
find_sleep_and_wait_calls(0x008c78c0, "AI_Start")

decompile_at(0x00ad88f0, "PPL_TaskGroup_Drain")
find_sleep_and_wait_calls(0x00ad88f0, "PPL_TaskGroup_Drain")

decompile_at(0x00ad8d10, "PPL_TaskGroup_Wait")
find_sleep_and_wait_calls(0x00ad8d10, "PPL_TaskGroup_Wait")

decompile_at(0x008324e0, "StopHavok_DrainAI")
find_sleep_and_wait_calls(0x008324e0, "StopHavok_DrainAI")

# ---------------------------------------------------------------------
# K5: hkWorld lock + PDD reentrancy -- who calls them?
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K5: hkWorld_Lock callers (reentrancy risk from workers)")
write("#" * 70)

find_callers_of(0x00c3e310, "hkWorld_Lock", limit=100)

write("")
write("#" * 70)
write("# K5: PDD callers")
write("#" * 70)

find_callers_of(0x00868d70, "PDD", limit=100)

# ---------------------------------------------------------------------
# K1: top-level callers of game heap alloc
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K1: unique callers of game heap alloc (FUN_00aa3e40)")
write("#" * 70)

find_callers_of(0x00aa3e40, "GameHeap_Alloc", limit=250)

# ---------------------------------------------------------------------
# K1: all thread creation sites
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K1: thread creation sites (thread procs may reach game heap)")
write("#" * 70)

find_thread_spawn_sites()

# ---------------------------------------------------------------------
# K3: BSTaskManagerThread inner loop (worker alloc path)
# ---------------------------------------------------------------------
write("")
write("#" * 70)
write("# K3: BSTaskManagerThread loop (worker alloc context)")
write("#" * 70)

decompile_at(0x00c41244, "BSTaskManagerThread_Loop_inner")
decompile_at(0x00c41200, "BSTaskManagerThread_Loop_start")

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/oom_worker_threads_and_locks.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
