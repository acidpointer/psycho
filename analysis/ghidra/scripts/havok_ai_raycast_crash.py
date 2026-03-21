# @category Analysis
# @description Research Havok AI thread raycasting crash at 0x00C94DA5 — collision shape freed while AI raycasts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
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

def disasm_range(start_int, count=30):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

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

def find_xrefs_to(addr_int, label, limit=20):
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
			break
	write("  Total: %d refs" % count)


write("=" * 70)
write("HAVOK AI THREAD RAYCASTING CRASH — 0x00C94DA5")
write("Thread: AI Linear Task Thread 1")
write("EBP=hkScaledMoppBvTreeShape, EBX=hkpSimulationIsland, ECX=0 (NULL)")
write("EDI=ahkpWorld, 59 loaded cells")
write("Stack: 0x008E50E7, Dogmeat creature, bhkWorldM")
write("=" * 70)

# SECTION 1: Crash point — what function, what's being accessed?
write("")
write("#" * 70)
write("# SECTION 1: Crash point 0x00C94DA5")
write("#" * 70)

decompile_at(0x00C94DA5, "CRASH_POINT")
write("")
write("Disasm around crash:")
disasm_range(0x00C94D80, 25)

# SECTION 2: Caller from stack — 0x008E50E7
write("")
write("#" * 70)
write("# SECTION 2: Stack caller 0x008E50E7 — AI processing?")
write("#" * 70)

decompile_at(0x008E50E7, "AI_PhysicsCaller")
write("")
write("Disasm around 0x008E50E7:")
disasm_range(0x008E50D0, 15)

# SECTION 3: 0x00C90350 from callstack — Havok collision/raycast
write("")
write("#" * 70)
write("# SECTION 3: 0x00C90350 from callstack")
write("#" * 70)

decompile_at(0x00C90350, "HavokCollision")

# SECTION 4: hkWorld_Lock (FUN_00c3e750) — does it check a flag
# that AI raycasting also checks? If so, can we make AI threads
# respect the lock?
write("")
write("#" * 70)
write("# SECTION 4: hkWorld_Lock actual mechanism — FUN_00c3e750")
write("# What flag does it set? Do AI raycasting functions check it?")
write("#" * 70)

decompile_at(0x00C3E750, "hkWorld_LockActual")
write("")
write("Disasm:")
disasm_range(0x00C3E750, 40)

# SECTION 5: hkWorld_Unlock — FUN_00c3e7d0
write("")
write("#" * 70)
write("# SECTION 5: hkWorld_Unlock — FUN_00c3e7d0")
write("#" * 70)

decompile_at(0x00C3E7D0, "hkWorld_UnlockActual")

# SECTION 6: AI raycasting entry — FUN_0096c330
# Does it check any lock before raycasting?
write("")
write("#" * 70)
write("# SECTION 6: AI raycasting — does it check hkWorld lock?")
write("#" * 70)

decompile_at(0x0096C330, "AI_Raycast_Entry", 12000)

# SECTION 7: What does FUN_00446f70 do? (called by hkWorld_Lock per worker)
# This is how hkWorld_Lock signals workers. Can we use the same
# mechanism to signal AI threads?
write("")
write("#" * 70)
write("# SECTION 7: FUN_00446f70 — hkWorld_Lock worker signal")
write("#" * 70)

decompile_at(0x00446F70, "hkWorld_SignalWorker")

# SECTION 8: AI thread dispatch — FUN_008c78c0
# What data does AI thread receive? Does it get a snapshot of
# collision shapes or live pointers?
write("")
write("#" * 70)
write("# SECTION 8: AI thread dispatch — what data is passed?")
write("#" * 70)

decompile_at(0x008C78C0, "AI_ThreadStart")
find_calls_from(0x008C78C0, "AI_ThreadStart")

# SECTION 9: AI thread main work — FUN_008c7720
# The actual work loop on AI thread
write("")
write("#" * 70)
write("# SECTION 9: AI thread work loop")
write("#" * 70)

decompile_at(0x008C7720, "AI_ThreadWorkLoop")

# SECTION 10: hkpSimulationIsland — how is it accessed during raycast?
# The crash involves hkpSimulationIsland on EBX. Is it freed?
write("")
write("#" * 70)
write("# SECTION 10: hkpSimulationIsland RTTI and access patterns")
write("#" * 70)

find_xrefs_to(0x010CCF28, "hkpSimulationIsland_RTTI", 10)

# SECTION 11: bhkCollisionObject destructor — PDD queue 0x20
# When this runs, what Havok objects does it free?
write("")
write("#" * 70)
write("# SECTION 11: bhkCollisionObject lifecycle during cell unload")
write("#" * 70)

# bhkCollisionObject — how does it remove from Havok world?
find_xrefs_to(0x010C3B6C, "bhkCollisionObject_RTTI_maybe", 10)

decompile_at(0x00C41FE0, "hkWorld_RemoveEntry")

# SECTION 12: Is there a way to force Havok broadphase update?
# FUN_00c3e1b0 calls both hkWorld_Lock and Unlock — might be step
write("")
write("#" * 70)
write("# SECTION 12: Potential Havok step/update functions")
write("#" * 70)

decompile_at(0x00C3E1B0, "HavokLockUnlock_Pair")
find_calls_from(0x00C3E1B0, "HavokLockUnlock_Pair")
find_xrefs_to(0x00C3E1B0, "HavokLockUnlock_Pair")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/havok_ai_raycast_crash.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
