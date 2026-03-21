# @category Analysis
# @description Research Havok broadphase entity lifecycle for AI thread crash
#
# Crash: AI Linear Task Thread 2 at 0x00C94DA5
# ECX=0, ESI=0 (NULL entity in broadphase query)
# hkpSimulationIsland, hkScaledMoppBvTreeShape, ahkpWorld on stack
# GrenadeProjectile "Frag Mine" in unloaded cell
#
# Root cause: cell unload at AI_JOIN removes Havok entities.
# Next frame AI threads query broadphase before step processes removals.
#
# Need to understand:
# 1. What exactly is at 0x00C94DA5? What broadphase query crashes?
# 2. Where does Havok step process entity removals?
# 3. Where does the game's per-frame PDD run relative to AI dispatch?
# 4. Can we move our cell unload to the per-frame PDD position?
# 5. What does DeferredCleanupSmall do with Havok entities specifically?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
listing = currentProgram.getListing()

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=6000):
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
	result = decomp.decompileFunction(func, 60, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start_int, count=25):
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_xrefs_to(addr_int, label, limit=10):
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
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

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


write("=" * 70)
write("HAVOK BROADPHASE LIFECYCLE - AI THREAD CRASH")
write("=" * 70)

# SECTION 1: Crash point 0x00C94DA5
write("")
write("# SECTION 1: 0x00C94DA5 - crash point in Havok code")
disasm_range(0x00C94D80, 25)
decompile_at(0x00C94DA5, "Havok_CrashPoint")

# SECTION 2: What function dispatches AI thread work?
# AI_START at 0x0086ec87 calls FUN_008c78c0
write("")
write("# SECTION 2: FUN_008c78c0 - AI thread dispatch (AI_START)")
decompile_at(0x008C78C0, "AI_Dispatch")
find_calls_from(0x008C78C0, "AI_Dispatch")

# SECTION 3: FUN_008c7990 - AI thread join (where our hook is)
write("")
write("# SECTION 3: FUN_008c7990 - AI thread join")
decompile_at(0x008C7990, "AI_Join")

# SECTION 4: Where does per-frame PDD (FUN_004556d0) run in main loop?
# Need exact position relative to AI_START
write("")
write("# SECTION 4: Main loop around per-frame PDD position")
write("# FUN_00868850 is our per-frame hook. Where is it called?")
find_xrefs_to(0x00868850, "PerFrameDrain_callers")

# SECTION 5: What does the Havok step process?
# hkpWorld::stepDeltaTime or similar
write("")
write("# SECTION 5: Havok world step - where entities are removed")
write("# FUN_00c3e310 = hkWorld_Lock (from our code)")
write("# What processes pending removals during AI work?")
decompile_at(0x00C3E310, "hkWorld_Lock")

# SECTION 6: PreDestructionSetup (FUN_00878160) - what Havok ops?
write("")
write("# SECTION 6: FUN_00878160 - PreDestructionSetup")
write("# This does hkWorld_Lock + SceneGraphInvalidate")
decompile_at(0x00878160, "PreDestructionSetup")
find_calls_from(0x00878160, "PreDestructionSetup")

# SECTION 7: DeferredCleanupSmall (FUN_00878250) internals
write("")
write("# SECTION 7: FUN_00878250 - DeferredCleanupSmall")
write("# PDD + AsyncFlush. What happens to Havok entities?")
decompile_at(0x00878250, "DeferredCleanupSmall")
find_calls_from(0x00878250, "DeferredCleanupSmall")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/havok_broadphase_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
