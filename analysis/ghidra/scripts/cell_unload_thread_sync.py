# @category Analysis
# @description Research: ALL threads that touch cell data during unload — BST, AI, Havok, main

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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), entry, sz))
	if entry != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), entry))
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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 60:
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

# ============================================================================
write("###############################################################")
write("# CELL UNLOAD THREAD SYNCHRONIZATION RESEARCH")
write("# Goal: Map EVERY thread that touches cell/object data during")
write("# unloading. Find missing synchronization points.")
write("###############################################################")

# --- 1. BSTaskManagerThread during cell unload ---
write("\n\n### SECTION 1: BSTaskManagerThread — what it does during cell unload")
write("# BST processes IO tasks. During cell unload, pending tasks for")
write("# the unloading cell may reference freed data.")

# IO Manager main processing loop
decompile_at(0x00C3DBF0, "IOManager_Process (main thread Phase 3)")
find_and_print_calls_from(0x00C3DBF0, "IOManager_Process")

# BSTaskManager thread entry
decompile_at(0x00C3D6C0, "BSTaskManager_ThreadProc")
find_and_print_calls_from(0x00C3D6C0, "BSTaskManager_ThreadProc")

# IO dequeue mechanism (how we block BST during unload)
decompile_at(0x00AD8DA0, "IO_Dequeue_Wait")
find_and_print_calls_from(0x00AD8DA0, "IO_Dequeue_Wait")

# --- 2. AI threads during cell unload ---
write("\n\n### SECTION 2: AI threads — references to cell data")
write("# AI workers access actor data, collision objects, heightfields.")
write("# All tied to cells. What happens when a cell is unloaded?")

# AI thread dispatch
decompile_at(0x008C78C0, "AI_ThreadStart (dispatch)")
find_and_print_calls_from(0x008C78C0, "AI_ThreadStart")

# AI thread join
decompile_at(0x008C7990, "AI_ThreadJoin (wait)")
find_and_print_calls_from(0x008C7990, "AI_ThreadJoin")

# AI process functions that access cell data
decompile_at(0x0096E870, "ActorDowngrade (unloads actor process level)")
find_and_print_calls_from(0x0096E870, "ActorDowngrade")

decompile_at(0x009784C0, "ProcessManager_Update")
find_and_print_calls_from(0x009784C0, "ProcessManager_Update")

# --- 3. Havok threads during cell unload ---
write("\n\n### SECTION 3: Havok — physics world during cell unload")
write("# Havok broadphase holds references to collision objects from cells.")
write("# Cell unload destroys these objects. Race with physics step.")

decompile_at(0x00C3E310, "hkWorld_Lock")
decompile_at(0x00C3E350, "hkWorld_Unlock")

# Havok step function (runs during AI phase?)
decompile_at(0x00C94BD0, "Havok_AddEntity")
decompile_at(0x00C40B70, "Havok_CollisionObject_Dtor")

# --- 4. NVSE plugin threads ---
write("\n\n### SECTION 4: NVSE events during/after cell unload")
write("# NVSE dispatches PLChangeEvent after cell changes.")
write("# Plugins (JIP, kNVSE) cache form pointers from these events.")

# NVSE plugin message dispatch
decompile_at(0x0086FA20, "NVSE_MainLoopHook_Region")
find_and_print_calls_from(0x0086FA20, "NVSE_MainLoopHook_Region")

# The loading state counter that suppresses events
find_refs_to(0x01202D6C, "LOADING_STATE_COUNTER")

# --- 5. Texture loading during cell unload ---
write("\n\n### SECTION 5: Texture system — BST loads textures for new cells")
write("# While we unload old cells, BST loads textures for new ones.")
write("# QueuedTexture references NiSourceTexture from the old cell?")

decompile_at(0x00A61A60, "TextureCache_Find")
find_and_print_calls_from(0x00A61A60, "TextureCache_Find")

decompile_at(0x00A5FCA0, "NiSourceTexture_Dtor")
find_and_print_calls_from(0x00A5FCA0, "NiSourceTexture_Dtor")

# --- 6. The game's own synchronization during cell transition ---
write("\n\n### SECTION 6: Game's built-in sync in CellTransitionHandler")
write("# FUN_008774A0 does its own synchronization. What exactly?")

decompile_at(0x008774A0, "CellTransitionHandler")
find_and_print_calls_from(0x008774A0, "CellTransitionHandler")

# FUN_00877700 — waits for BST pending cell loads
decompile_at(0x00877700, "WaitForPendingCellLoads")
find_and_print_calls_from(0x00877700, "WaitForPendingCellLoads")

# FUN_008324E0 — stops Havok sim, drains AI queues
decompile_at(0x008324E0, "StopHavok_DrainAI")
find_and_print_calls_from(0x008324E0, "StopHavok_DrainAI")

# --- 7. Sound system during cell unload ---
write("\n\n### SECTION 7: Sound system — PlayingSounds iteration")
write("# JIP crash in PlayingSoundsIterator during stress test.")
write("# Does cell unload affect the playing sounds list?")

# BSAudio / sound manager
find_refs_to(0x011F6D98, "BSAudioManager_Singleton")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/cell_unload_thread_sync.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
