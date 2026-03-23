# @category Analysis
# @description Research the fast travel race condition causing PopulateArgs crash.
# purge_delay=500 didn't help, so it's NOT page recycling — it's concurrent
# memory access. Something writes to memory while NVSE reads it.
# Need to find: what runs concurrently during fast travel completion,
# what memory is shared, and where synchronization is missing.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	listing = currentProgram.getListing()
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def find_xrefs_to(addr_int, label, limit=25):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)

def disasm_range(start, end, label):
	write("")
	write("=" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start, end))
	write("=" * 70)
	listing = currentProgram.getListing()
	addr = toAddr(start)
	while addr.getOffset() < end:
		inst = listing.getInstructionAt(addr)
		if inst is None:
			addr = addr.add(1)
			continue
		mnemonic = inst.getMnemonicString()
		if "CALL" in mnemonic:
			refs = inst.getReferencesFrom()
			for r in refs:
				target = r.getToAddress().getOffset()
				target_func = fm.getFunctionAt(toAddr(target))
				tname = target_func.getName() if target_func else "0x%08x" % target
				write("  0x%08x: %s  -> %s" % (addr.getOffset(), inst.toString(), tname))
				break
			else:
				write("  0x%08x: %s" % (addr.getOffset(), inst.toString()))
		else:
			write("  0x%08x: %s" % (addr.getOffset(), inst.toString()))
		nxt = inst.getNext()
		if nxt is None:
			break
		addr = nxt.getAddress()


write("=" * 70)
write("FAST TRAVEL RACE CONDITION ANALYSIS")
write("purge_delay=500 didn't help -> NOT page recycling, it's concurrent write")
write("=" * 70)

# =====================================================================
# PART 1: Fast travel execution path in the outer game loop
# What EXACTLY happens from fast travel trigger to first normal frame?
# Disassemble the loading path (0x0086b4f6 branch) in detail
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: Outer loop loading/fast travel path")
write("# From 0x0086b4f6 to CellTransitionHandler and back")
write("#" * 70)

disasm_range(0x0086b4f6, 0x0086b640, "FastTravel_LoadingPath")

# =====================================================================
# PART 2: FUN_0086f940 — called early in the inner loop
# The crash callstack shows this. What does it do?
# Does it trigger model loading that races with NVSE dispatch?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_0086f940 — early frame processing")
write("#" * 70)

decompile_at(0x0086f940, "EarlyFrame_0086f940")
find_calls_from(0x0086f940, "EarlyFrame_0086f940")

# =====================================================================
# PART 3: BSTaskManagerThread during fast travel
# What does BSTaskManagerThread do during/after fast travel?
# FUN_00c3dbf0 (IOManager main-thread processing) runs at Phase 3.
# But BSTaskManagerThread runs on its OWN thread concurrently.
# Does it modify ScriptEventList or form data while main thread reads?
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: BSTaskManagerThread processing loop")
write("# FUN_00c410b0 — the thread loop. What does it access?")
write("#" * 70)

decompile_at(0x00c410b0, "BSTaskThread_Loop")
find_calls_from(0x00c410b0, "BSTaskThread_Loop")

# =====================================================================
# PART 4: FUN_0093cdf0 and FUN_0093d500 — the 5 normal PDD callers
# From the HeapCompact crash, these call DeferredCleanupSmall.
# But they're also in the fast travel path. Do they modify script data?
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_0093cdf0 — normal PDD caller (fast travel path?)")
write("#" * 70)

decompile_at(0x0093cdf0, "NormalPDDCaller_0093cdf0")
find_calls_from(0x0093cdf0, "NormalPDDCaller_0093cdf0")

# =====================================================================
# PART 5: ScriptEventList allocation and destruction
# FUN_005ABF60 creates ScriptEventList.
# Who DESTROYS them? What frees ScriptLocal entries?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: ScriptEventList lifecycle")
write("#" * 70)

decompile_at(0x005ABF60, "ScriptEventList_Create")
find_calls_from(0x005ABF60, "ScriptEventList_Create")

# Who destroys ScriptEventList?
find_xrefs_to(0x005ABF60, "ScriptEventList_Create_callers", 10)

# FUN_005AC020 — ScriptEventList destructor?
decompile_at(0x005AC020, "ScriptEventList_Dtor")
find_calls_from(0x005AC020, "ScriptEventList_Dtor")
find_xrefs_to(0x005AC020, "ScriptEventList_Dtor_callers", 15)

# =====================================================================
# PART 6: The DAT_01202dd8 reentrancy guard in IOManager
# FUN_00c3dbf0 sets DAT_01202dd8 = 1 at entry, 0 at exit.
# Does fast travel / cell transition also read this?
# Could there be a race between IOManager processing and fast travel?
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: IOManager reentrancy guard DAT_01202dd8")
write("#" * 70)

find_xrefs_to(0x01202dd8, "IOManager_ReentrancyGuard", 15)

# =====================================================================
# PART 7: What happens to ScriptEventList during cell unload?
# FUN_00574400 — called from script cleanup
# FUN_00573f40 — called from script cleanup
# Do these free/modify ScriptEventList data?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: Script cleanup during cell unload")
write("#" * 70)

decompile_at(0x00574400, "ScriptCleanup_574400")
find_calls_from(0x00574400, "ScriptCleanup_574400")

decompile_at(0x00573f40, "ScriptCleanup_573f40")
find_calls_from(0x00573f40, "ScriptCleanup_573f40")

# =====================================================================
# PART 8: NVSE MainLoopHook — exactly when does it fire?
# 0x00ECC470 is in the crash stack. What is this function?
# Is it the CRT startup that calls FUN_0086a850?
# The outer loop at 0x0086B3E8 returns here.
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: The exact NVSE hook mechanism")
write("# What instruction does NVSE replace at 0x0086B3E3?")
write("#" * 70)

disasm_range(0x0086B3D0, 0x0086B3F0, "NVSE_HookSite_Exact")

# =====================================================================
# PART 9: Script form data — what fields could be overwritten?
# Script+0x28 = data pointer (compiled bytecode)
# Script+0x2C = data size
# Script+0x40 = VarInfoList
# If these are modified during cell transition while NVSE reads them...
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: Script object layout — what gets modified during transition?")
write("#" * 70)

# FUN_005aa0f0 — Script constructor (writes vtable 0x01037094)
decompile_at(0x005aa0f0, "Script_Ctor")
find_calls_from(0x005aa0f0, "Script_Ctor")

# FUN_005aa170 — Script destructor?
decompile_at(0x005aa170, "Script_Dtor_vtable4")
find_calls_from(0x005aa170, "Script_Dtor_vtable4")

# =====================================================================
# PART 10: Cell detach/attach during fast travel
# When the new cell is attached after fast travel, do scripts get
# reinitialized? Does this modify the FunctionInfo's cached data?
# FUN_00545030 — cell attach function?
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: Cell attach — script reinitialization")
write("#" * 70)

decompile_at(0x00545030, "CellAttach")
find_calls_from(0x00545030, "CellAttach")


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/fast_travel_race_condition.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
