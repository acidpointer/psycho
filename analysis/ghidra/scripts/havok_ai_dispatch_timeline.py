# @category Analysis
# @description Map exact frame timeline: per-frame PDD vs AI dispatch vs our hooks
#
# Critical question: can we run cell unloading at the per-frame PDD position
# (BEFORE AI dispatch) instead of at AI_JOIN (AFTER AI dispatch)?
#
# The game's per-frame PDD at FUN_004556d0 calls PreDestruction/DeferredCleanup/
# PostDestruction. AI threads are idle at that point (joined from previous frame).
# If we piggyback on that position, Havok removals happen before AI dispatch,
# and the Havok step during AI work processes them correctly.

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

def disasm_range(start_int, count=30):
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


write("=" * 70)
write("FRAME TIMELINE: PDD vs AI DISPATCH vs HOOKS")
write("=" * 70)

# SECTION 1: Main loop FUN_0086e650 - full disasm of key sections
# Need to find: FUN_004556d0 call, FUN_00868850 call, AI_START, AI_JOIN
write("")
write("# SECTION 1: Main loop start - before AI dispatch")
write("# Look for FUN_004556d0 (per-frame PDD) and FUN_00868850 (our hook)")

# The main loop is at 0x0086e650. Let's find where FUN_004556d0 is called.
# From per-frame PDD calls list, it calls FUN_0043b2b0 at 0x0045578b
# and FUN_00878160 at 0x0045608b. But we need where FUN_004556d0 ITSELF
# is called from the main loop.
find_xrefs_to(0x004556D0, "PerFramePDD_callers")

# SECTION 2: Where FUN_00868850 is called from
write("")
write("# SECTION 2: FUN_00868850 callers (our per-frame drain hook)")
find_xrefs_to(0x00868850, "PerFrameDrain_callers")

# SECTION 3: Disasm the main loop around the per-frame PDD call
# The main loop (FUN_0086e650) is huge. Let's look around key addresses.
write("")
write("# SECTION 3: Main loop disasm near known positions")

# Around where FUN_0086e650 calls various per-frame functions
# DAT_011dea2b check is at 0x0086e771
write("")
write("Main loop around DAT_011dea2b check (0x0086e6e0):")
disasm_range(0x0086E6D0, 25)

# SECTION 4: The area BETWEEN per-frame PDD and AI_START
# This is where we could safely run cell unloading
write("")
write("# SECTION 4: Area between game's PDD and AI_START")
write("# Disasm 0x0086eb00 to 0x0086eca0 to see what happens")
disasm_range(0x0086EB00, 30)

write("")
write("# More context before AI_START:")
disasm_range(0x0086EC40, 25)

# SECTION 5: FUN_0086f6a0 - POST_AI processing (called at 0x0086ee62)
write("")
write("# SECTION 5: FUN_0086f6a0 - POST_AI (after AI join)")
decompile_at(0x0086F6A0, "PostAI")

# SECTION 6: What AI threads actually DO with Havok
# FUN_008c78c0 (AI dispatch) launches threads that call into Havok
write("")
write("# SECTION 6: What work do AI threads perform?")
write("# FUN_008c80e0 - called before AI dispatch at 0x0086ec78")
decompile_at(0x008C80E0, "PreAI_work")

# SECTION 7: FUN_00575e00 from crash stack nearby
# 0x00575E00 was on the crash stack
write("")
write("# SECTION 7: FUN_00575e00 - near crash stack")
decompile_at(0x00575E00, "CrashNearby_575e00")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/havok_ai_dispatch_timeline.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
