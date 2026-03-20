# @category Analysis
# @description Find Havok broadphase update/step function to force cleanup after entity removal

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
write("HAVOK BROADPHASE STEP/UPDATE RESEARCH")
write("Goal: Find how to force broadphase cleanup after entity removal")
write("=" * 70)

# SECTION 1: hkWorld_RemoveEntry — what exactly does it call on broadphase?
write("")
write("#" * 70)
write("# SECTION 1: hkWorld_RemoveEntry — broadphase removal mechanism")
write("#" * 70)

decompile_at(0x00C41FE0, "hkWorld_RemoveEntry")
find_calls_from(0x00C41FE0, "hkWorld_RemoveEntry")

# SECTION 2: The broadphase vtable — find step/update functions
# world+0x58 is the broadphase object
# We need to find functions on the broadphase that do cleanup/update
write("")
write("#" * 70)
write("# SECTION 2: hkpBroadPhase vtable — what functions exist?")
write("# world+0x58 is broadphase, vtable+0x18 is addObjectBatch")
write("# Look for removeObject, updateAabbs, collide, step")
write("#" * 70)

# The broadphase vtable is at *(*(world+0x58))
# We need the RTTI or vtable address from the crash data
# From the crash, EDI = ahkpWorld. world+0x58 is the broadphase.
# Let's find the broadphase class
find_xrefs_to(0x010C3BC4, "ahkpWorld_RTTI", 10)

# hkp3AxisSweep is the broadphase implementation
# Look for its RTTI
find_xrefs_to(0x010C3C14, "hkp3AxisSweep_RTTI_maybe", 10)

# SECTION 3: FUN_00d00500 — called before crash function with same entity
# Does it check for NULL? What does it do?
write("")
write("#" * 70)
write("# SECTION 3: FUN_00d00500 — called before FUN_00cffa00")
write("# Does it handle NULL entity? What does it do?")
write("#" * 70)

decompile_at(0x00D00500, "CreateCollisionAgent")

# SECTION 4: The game's per-frame PDD caller — does it step Havok AFTER PDD?
write("")
write("#" * 70)
write("# SECTION 4: FUN_004556d0 — game's per-frame PDD caller")
write("# What does it do after DeferredCleanupSmall?")
write("#" * 70)

decompile_at(0x004556D0, "GamePDD_Caller", 15000)
find_calls_from(0x004556D0, "GamePDD_Caller")

# SECTION 5: FUN_008c80e0 — AI dispatch prep
# Does it step the Havok world? Does it update broadphase?
write("")
write("#" * 70)
write("# SECTION 5: AI dispatch prep — FUN_008c80e0")
write("# Does it step Havok before dispatching AI threads?")
write("#" * 70)

decompile_at(0x008C80E0, "AI_DispatchPrep")
find_calls_from(0x008C80E0, "AI_DispatchPrep")

# SECTION 6: Where does hkpWorld::step run in the main loop?
# Search for functions that access world+0x48 (lock) or world+0x44
# Also look at FUN_00c3e750 callers — who locks the Havok world?
write("")
write("#" * 70)
write("# SECTION 6: Who calls hkWorld_Lock? (=who steps physics)")
write("#" * 70)

find_xrefs_to(0x00C3E310, "hkWorld_Lock")
find_xrefs_to(0x00C3E340, "hkWorld_Unlock")

# SECTION 7: PDD queue 0x20 destructor — FUN_00401970
# What exactly is the Havok wrapper destructor?
write("")
write("#" * 70)
write("# SECTION 7: PDD queue 0x20 destructor — Havok wrapper cleanup")
write("#" * 70)

decompile_at(0x00401970, "HavokWrapper_Destructor")

# SECTION 8: bhkWorldM — the Bethesda Havok world wrapper
# From crash stack: bhkWorldM at 0x210A0920
write("")
write("#" * 70)
write("# SECTION 8: bhkWorldM — Bethesda's Havok world wrapper")
write("# Is there a step/update method we can call?")
write("#" * 70)

find_xrefs_to(0x010C69F4, "bhkWorldM_RTTI", 10)

# bhkWorld vtable — look for step function
# bhkWorld is at various RTTI addresses in the game
find_xrefs_to(0x010C6948, "bhkWorld_RTTI_maybe", 10)

# SECTION 9: SceneGraphInvalidate — does it update broadphase?
write("")
write("#" * 70)
write("# SECTION 9: SceneGraphInvalidate FUN_00703980 — Havok effects?")
write("#" * 70)

decompile_at(0x00703980, "SceneGraphInvalidate")
find_calls_from(0x00703980, "SceneGraphInvalidate")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/havok_broadphase_step.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
