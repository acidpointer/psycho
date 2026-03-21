# @category Analysis
# @description DEEP research: Complete cell unload flow — what references are invalidated and how

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


write("=" * 70)
write("DEEP RESEARCH: Cell Unload Flow + Object Reference Invalidation")
write("=" * 70)

# =====================================================================
# PART 1: FUN_00552bd0 — called FIRST in DestroyCell
# This is the cell state change. Does it cancel IO tasks for this cell?
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00552bd0 — cell state change (first call in DestroyCell)")
write("#" * 70)

decompile_at(0x00552BD0, "CellState_Change")
find_calls_from(0x00552BD0, "CellState_Change")

# =====================================================================
# PART 2: FUN_004512a0 — called from DestroyCell after state change
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_004512a0 — post state change")
write("#" * 70)

decompile_at(0x004512A0, "DestroyCell_PostState")

# =====================================================================
# PART 3: FUN_00551620/FUN_00551480 — reference iteration loop in DestroyCell
# "while (FUN_00551620()) { FUN_00551480() }" — removing references
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: Reference removal loop in DestroyCell")
write("#" * 70)

decompile_at(0x00551620, "Cell_HasMoreRefs")
decompile_at(0x00551480, "Cell_RemoveRef")
find_calls_from(0x00551480, "Cell_RemoveRef")

# =====================================================================
# PART 4: FUN_0054af40 — actor processing during cell destruction
# This triggers NVSE events. Does it also clean actor → texture refs?
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_0054af40 — actor processing in cell destruction")
write("#" * 70)

decompile_at(0x0054AF40, "ActorProcess_CellDestroy")
find_calls_from(0x0054AF40, "ActorProcess_CellDestroy")

# =====================================================================
# PART 5: FUN_00961f30 — called from DestroyCell with param (cell, 0)
# Cell finalization?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00961f30 — cell finalization")
write("#" * 70)

decompile_at(0x00961F30, "Cell_Finalize")
find_calls_from(0x00961F30, "Cell_Finalize")

# =====================================================================
# PART 6: How does the game manage QueuedTexture → NiSourceTexture refs?
# When a cell is unloaded, do the QueuedTexture tasks for that cell
# get cancelled? Or do they reference NiSourceTexture through a
# different path (texture cache, model data)?
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_0043c150 — QueuedTexture task processing")
write("# What ref does it hold to NiSourceTexture? How?")
write("#" * 70)

# The task processing function that crashes
# It calls FUN_0055b980 (get worldspace) and FUN_0043c4c0 (texture lookup)
# or FUN_00a61b90 (texture load)
# Does it hold a STRONG ref to NiSourceTexture?
decompile_at(0x0055B980, "GetWorldspace")
decompile_at(0x0045CD60, "GetCellTextureInfo")

# FUN_00c3cff0 — called from QueuedTexture processing
decompile_at(0x00C3CFF0, "QueuedTexture_GetIOData")

# =====================================================================
# PART 7: NiSourceTexture creation and registration
# When is it added to the texture cache (DAT_011f4468)?
# When is it REMOVED from the cache?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: NiSourceTexture registration in texture cache")
write("#" * 70)

# FUN_00a61b90 — texture load (no worldspace, direct)
decompile_at(0x00A61B90, "TextureLoad_Direct")

# FUN_00a5fe30 — called from texture processing (creates NiSourceTexture?)
decompile_at(0x00A5FE30, "TextureCreate_OrLookup")

# FUN_00a61040 — called for _e.dd textures
decompile_at(0x00A61040, "TextureCreate_EnvMap")

# =====================================================================
# PART 8: HeapCompact Stage 5 — how does the ORIGINAL game handle this?
# Stage 5 sets TLS=0 (immediate destruction) and calls FindCellToUnload
# What makes this safe in the original game but not in ours?
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: HeapCompact Stage 5 — vanilla handling")
write("#" * 70)

decompile_at(0x00866A90, "HeapCompact_Full", 15000)

# =====================================================================
# PART 9: Who resets/invalidates the texture cache?
# FUN_00a62090 WRITES to DAT_011f4468. When is it called?
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: Texture cache reset — FUN_00a62090")
write("#" * 70)

decompile_at(0x00A62090, "TextureCache_Reset")
find_xrefs_to(0x00A62090, "TextureCache_Reset_callers")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/deep_cell_unload_flow.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
