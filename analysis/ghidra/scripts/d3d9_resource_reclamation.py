# @category Analysis
# @description Research D3D9 resource reclamation and VA fragmentation
#
# D3D9 "Not enough memory" at 2.4-2.7GB RSS. Need to understand:
# 1. What D3D9 resources consume VA (vertex buffers, textures)?
# 2. Can we force D3D9 to release cached resources?
# 3. What does TextureCache_PreReset (FUN_00a62030) actually free?
# 4. What does HeapCompact Stage 2 BSA cleanup do?
# 5. NiDX9Renderer has resource management methods we could call

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
write("D3D9 RESOURCE RECLAMATION RESEARCH")
write("=" * 70)

# SECTION 1: TextureCache_PreReset (FUN_00a62030) - clears ALL cache entries
write("")
write("# SECTION 1: FUN_00a62030 - TextureCache_PreReset")
write("# Clears DAT_011f4468 (hash table) and DAT_011f4464 (array)")
decompile_at(0x00A62030, "TextureCache_PreReset")
find_calls_from(0x00A62030, "TextureCache_PreReset")

# SECTION 2: FUN_00a62090 - TextureCache_Reset (worldspace transition)
write("")
write("# SECTION 2: FUN_00a62090 - TextureCache_Reset")
decompile_at(0x00A62090, "TextureCache_Reset")
find_calls_from(0x00A62090, "TextureCache_Reset")

# SECTION 3: HeapCompact Stage 2 internals
# Stage 2 = BSA/texture cache cleanup
write("")
write("# SECTION 3: What calls does HeapCompact make for Stage 2?")
write("# FUN_00878080 dispatches stages. Need stage 2 specifically.")
decompile_at(0x00878080, "HeapCompact_Dispatch")
find_calls_from(0x00878080, "HeapCompact_Dispatch")

# SECTION 4: FUN_0086a850 - outer update, contains cell transition + reset
# This calls TextureCache_Reset during worldspace changes
write("")
write("# SECTION 4: Where does FUN_0086a850 call texture cache reset?")
write("# Disasm around the texture cache reset call at 0x0086b976")
write("# from previous research")
decompile_at(0x0086B976, "OuterUpdate_TexReset_area")

# SECTION 5: ProcessPendingCleanup (FUN_00452490) - what does it free?
write("")
write("# SECTION 5: FUN_00452490 - ProcessPendingCleanup")
decompile_at(0x00452490, "ProcessPendingCleanup")
find_calls_from(0x00452490, "ProcessPendingCleanup")

# SECTION 6: FUN_004556d0 - the game's per-frame PDD
# This is what the game calls normally. What does it do?
write("")
write("# SECTION 6: FUN_004556d0 - per-frame PDD")
decompile_at(0x004556D0, "PerFramePDD")
find_calls_from(0x004556D0, "PerFramePDD")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/d3d9_resource_reclamation.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
