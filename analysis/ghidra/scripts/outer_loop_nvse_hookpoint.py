# @category Analysis
# @description Find the exact position of NVSE's MainLoopHook in the outer
# game loop (FUN_0086a850). We need to understand what game function is
# hooked by NVSE at 0x0086B3E8, and what functions run BETWEEN cell
# transition completion and this hook point. We need a game function
# to hook that runs AFTER cell transition but BEFORE the NVSE hook.

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
			write("  0x%08x: [no instruction]" % addr.getOffset())
			addr = addr.add(1)
			continue
		# Check for call instructions and resolve target
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


write("=" * 70)
write("OUTER LOOP NVSE HOOKPOINT ANALYSIS")
write("Find where to set loading counter to suppress NVSE event dispatch")
write("=" * 70)

# =====================================================================
# PART 1: Disassembly around 0x0086B3E8 (NVSE MainLoopHook position)
# What instruction is at this address? What is NVSE hooking?
# What function calls happen before and after this point?
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: Disassembly around NVSE MainLoopHook (0x0086B3E8)")
write("# What game function is called here that NVSE hooks?")
write("#" * 70)

# Disassemble a wide range around the hook point
disasm_range(0x0086B350, 0x0086B450, "Around_NVSE_MainLoopHook")

# =====================================================================
# PART 2: What function is at 0x0086B3E8?
# NVSE hooks a CALL instruction. The target function is what NVSE
# replaces. What is the original function being called?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: Original function at NVSE hook point")
write("#" * 70)

# Check what instruction is at 0x0086B3E8
listing = currentProgram.getListing()
inst = listing.getInstructionAt(toAddr(0x0086B3E8))
if inst:
	write("Instruction at 0x0086B3E8: %s" % inst.toString())
	refs = inst.getReferencesFrom()
	for r in refs:
		write("  Target: 0x%08x" % r.getToAddress().getOffset())
		decompile_at(r.getToAddress().getOffset(), "NVSE_HookedFunction")

# =====================================================================
# PART 3: What runs BETWEEN CellTransitionHandler return and NVSE hook?
# After CellTransitionHandler (FUN_008774a0) returns, the outer loop
# continues. What functions run before reaching 0x0086B3E8?
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: Code path between CellTransition and NVSE hook")
write("# CellTransitionHandler is called from FUN_0086a850")
write("#" * 70)

# Find where CellTransitionHandler (0x008774a0) is called in outer loop
find_xrefs_to(0x008774a0, "CellTransitionHandler_callers", 10)

# Disassemble from CellTransitionHandler call site to NVSE hook
# CellTransitionHandler is called at 0x0086B582 (from xref analysis)
# Let's check the range between cell transition and NVSE hook
disasm_range(0x0086B380, 0x0086B600, "CellTransition_to_NVSE_hook")

# =====================================================================
# PART 4: The inner per-frame loop call
# FUN_0086e650 is the inner loop. Where is it called from FUN_0086a850?
# Is it BEFORE or AFTER the NVSE hook point?
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: Inner loop (FUN_0086e650) call site in outer loop")
write("#" * 70)

find_xrefs_to(0x0086e650, "InnerLoop_callers", 10)

# =====================================================================
# PART 5: FUN_00ecc470 — this appears in crash stack as the function
# that NVSE hooks. What is it?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00ecc470 — the outer loop function NVSE hooks")
write("#" * 70)

decompile_at(0x00ecc470, "NVSE_HookedOuterFunc")

# =====================================================================
# PART 6: What functions in FUN_0086a850 run AFTER the inner loop
# returns but BEFORE the NVSE hook? These are candidate hook points.
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: Functions after inner loop, before NVSE hook")
write("#" * 70)

# The inner loop FUN_0086e650 is called somewhere in FUN_0086a850.
# After it returns, some cleanup runs, then the outer loop iterates.
# NVSE hooks at the loop boundary.
# Disassemble the area around the inner loop call
disasm_range(0x0086B380, 0x0086B400, "PostInnerLoop_area")

# =====================================================================
# PART 7: FUN_0086a830 — frame timer function called at loop start
# This runs at the START of each outer loop iteration, BEFORE inner loop.
# If NVSE fires between outer loop iterations, we could hook a function
# that runs BEFORE NVSE's hook point.
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_0086a830 — frame timer at outer loop start")
write("#" * 70)

decompile_at(0x0086a830, "FrameTimer_LoopStart")
find_xrefs_to(0x0086a830, "FrameTimer_callers", 5)


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/outer_loop_nvse_hookpoint.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
