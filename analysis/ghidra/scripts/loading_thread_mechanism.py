# @category Analysis
# @description Research: How does synchronous loading work? Does it run on main thread or a loading thread?

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
write("# LOADING THREAD MECHANISM RESEARCH")
write("# Goal: Does loading run on main thread or a separate thread?")
write("# What thread calls gheap_alloc/free during coc/fast travel?")
write("###############################################################")

# --- 1. CellTransitionHandler — the main entry point for coc/fast travel ---
write("\n\n### SECTION 1: CellTransitionHandler (0x008774A0)")
write("# Does it spawn a loading thread? Or run synchronously on caller?")

decompile_at(0x008774A0, "CellTransitionHandler")
find_and_print_calls_from(0x008774A0, "CellTransitionHandler")

# --- 2. The coc console command handler ---
write("\n\n### SECTION 2: Console command dispatch")
write("# Where does 'coc' get processed? What thread runs it?")

# FUN_0093BEA0 — cell transition conditional (called from main loop)
decompile_at(0x0093BEA0, "CellTransition_Conditional")
find_and_print_calls_from(0x0093BEA0, "CellTransition_Conditional")

# --- 3. Fast travel handler ---
write("\n\n### SECTION 3: Fast travel loading path")

# FUN_0093CDF0 — fast travel handler
decompile_at(0x0093CDF0, "FastTravel_Handler")
find_and_print_calls_from(0x0093CDF0, "FastTravel_Handler")

# --- 4. Save/load handler ---
write("\n\n### SECTION 4: Save load path")

# FUN_0084C5A0 — save load entry
decompile_at(0x0084C5A0, "SaveLoad_Handler")
find_and_print_calls_from(0x0084C5A0, "SaveLoad_Handler")

# --- 5. LOADING_FLAG setter ---
write("\n\n### SECTION 5: Who sets LOADING_FLAG (0x011DEA2B)?")
write("# This tells us what thread initiates loading")

find_refs_to(0x011DEA2B, "LOADING_FLAG")

# --- 6. CreateThread / _beginthreadex calls ---
write("\n\n### SECTION 6: Thread creation in loading-related functions")
write("# Does CellTransitionHandler or its callees create threads?")

# Search for CreateThread calls in the loading path
find_refs_to(0x00ECD0CC, "CreateThread (IAT)")
find_refs_to(0x00ECD084, "_beginthreadex (IAT)")

# --- 7. BSTaskManagerThread dispatch during loading ---
write("\n\n### SECTION 7: BSTaskManagerThread task queue during loading")
write("# Who queues tasks for BST? What thread does BST run on?")

# FUN_00C3E420 — dequeue task from completed queue
decompile_at(0x00C3E420, "IOManager_DequeueCompleted")
find_and_print_calls_from(0x00C3E420, "IOManager_DequeueCompleted")

# FUN_00C3D440 — BSTaskManager main loop (thread proc)
decompile_at(0x00C3D440, "BSTaskManager_MainLoop")
find_and_print_calls_from(0x00C3D440, "BSTaskManager_MainLoop")

# --- 8. The actual texture allocation path ---
write("\n\n### SECTION 8: 89MB terrain LOD texture allocation")
write("# What function allocates the large terrain texture?")
write("# D3DXCreateTextureFromFileInMemory or similar")

# FUN_00A61E90 — texture creation (NiDX9SourceTextureData)
decompile_at(0x00A61E90, "TextureCreate")
find_and_print_calls_from(0x00A61E90, "TextureCreate")

# --- 9. GetCurrentThreadId comparison ---
write("\n\n### SECTION 9: Game's own GetCurrentThreadId (0x0040FC90)")
write("# How does the game check main thread?")

decompile_at(0x0040FC90, "Game_GetCurrentThreadId")
find_refs_to(0x0040FC90, "Game_GetCurrentThreadId")

# --- 10. The main thread ID storage in TES ---
write("\n\n### SECTION 10: Where does TES store main thread ID?")

decompile_at(0x0044EDB0, "GetMainThreadId_from_TES")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/loading_thread_mechanism.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
