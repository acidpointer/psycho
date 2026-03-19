# @category Analysis
# @description Research whether SceneGraphInvalidate is safe from post-render.
# The 5 normal PDD callers run at lines 271/347 (pre-AI, pre-render).
# We run at line 486 (post-render). Is SceneGraphInvalidate safe there?
# Key: does FUN_007160b0 (vtable+0x1c cull/update) access freed cell data?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
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
		write("  %s @ %s (in %s)" % (ref.getReferenceType(), ref.getFromAddress(), fname))
		count += 1
		if count > 30:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

write("=" * 70)
write("SCENE GRAPH POST-RENDER SAFETY ANALYSIS")
write("=" * 70)

# Part 1: SceneGraphInvalidate full chain
write("")
write("#" * 70)
write("# PART 1: SceneGraphInvalidate → CullUpdate chain")
write("#" * 70)

decompile_at(0x00703980, "SceneGraphInvalidate (45 bytes)")
decompile_at(0x007160B0, "SceneGraph_CullUpdate (60 bytes)")
decompile_at(0x007FFE00, "CullUpdate_Setup (FUN_007ffe00)")
decompile_at(0x007A1670, "CullUpdate_Cleanup (FUN_007a1670)")
decompile_at(0x00586150, "CullUpdate_Dispatch (FUN_00586150)")

# Part 2: What does vtable+0x1c do for the scene graph root?
write("")
write("#" * 70)
write("# PART 2: BSFadeNode/NiNode vtable+0x1c (cull/update)")
write("# This is called by FUN_00586150 → what does it access?")
write("#" * 70)

# NiNode vtable entry at offset 0x1c
decompile_at(0x004B7210, "GetSceneGraphRoot (FUN_004b7210)")

# Part 3: When in the frame do the 5 normal callers run?
write("")
write("#" * 70)
write("# PART 3: Frame position of the 5 PDD callers")
write("# Map each to main loop line number")
write("#" * 70)

# FUN_004556d0 is called from main loop — find where
find_refs_to(0x004556D0, "Caller1_FUN_004556d0")
find_refs_to(0x008782B0, "Caller2_FUN_008782b0")
find_refs_to(0x0093CDF0, "Caller3_FUN_0093cdf0")
find_refs_to(0x0093D500, "Caller4_FUN_0093d500")
find_refs_to(0x005B6CD0, "Caller5_FUN_005b6cd0")

# Part 4: What state does SceneGraphInvalidate read?
write("")
write("#" * 70)
write("# PART 4: Does SceneGraphInvalidate access cell heightfield data?")
write("# If so, it's unsafe after FindCellToUnload")
write("#" * 70)

# FUN_009373f0 — checks if exterior (used by SceneGraphInvalidate)
decompile_at(0x009373F0, "IsExterior_Check (16 bytes)")

# Part 5: DeferredCleanupSmall internals
write("")
write("#" * 70)
write("# PART 5: DeferredCleanupSmall full chain")
write("# What exactly does it do between PDD and AsyncFlush?")
write("#" * 70)

decompile_at(0x00878250, "DeferredCleanupSmall (86 bytes)")
decompile_at(0x00B5FD60, "DCS_Cleanup1 (FUN_00b5fd60)")
decompile_at(0x00651E30, "DCS_BSACacheCleanup1 (FUN_00651e30)")
decompile_at(0x00651F40, "DCS_BSACacheCleanup2 (FUN_00651f40)")
decompile_at(0x00448620, "DCS_LockRelease (FUN_00448620)")

# Part 6: PostDestructionRestore
write("")
write("#" * 70)
write("# PART 6: PostDestructionRestore (FUN_00878200)")
write("# What exactly does it restore? Does it call hkWorld_Unlock?")
write("#" * 70)

decompile_at(0x00878200, "PostDestructionRestore (80 bytes)")

# Part 7: Is FUN_009373f0 safe post-render?
write("")
write("#" * 70)
write("# PART 7: What does the exterior check read?")
write("# The scene graph root has a byte at offset 0 that indicates type")
write("#" * 70)

decompile_at(0x009373F0, "IsExterior (16 bytes)")
decompile_at(0x004B7210, "GetSceneRoot (returns renderer scene)")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/scene_graph_post_render_safety.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
