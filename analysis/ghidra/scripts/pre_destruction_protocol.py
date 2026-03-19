# @category Analysis
# @description Research the EXACT pre-destruction protocol used by ALL PDD callers.
# Goal: Map the complete lock/invalidate/PDD/unlock sequence that makes
# cleanup safe, and verify every PDD caller follows the same pattern.

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
	funcs = set()
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			funcs.add(from_func)
		count += 1
	write("  %d references from %d functions:" % (count, len(funcs)))
	for func in sorted(funcs, key=lambda f: f.getEntryPoint().getOffset()):
		entry = func.getEntryPoint()
		write("    0x%08x  %s  (%d bytes)" % (
			entry.getOffset(),
			func.getName(),
			func.getBody().getNumAddresses()))
	return funcs

write("=" * 70)
write("PRE-DESTRUCTION PROTOCOL ANALYSIS")
write("=" * 70)
write("")
write("HYPOTHESIS: The game has a specific lock/invalidate/PDD/unlock")
write("protocol that ALL safe PDD callers follow. We call PDD without")
write("this protocol, causing AI thread + SpeedTree crashes.")

# ===================================================================
# PART 1: PreDestruction_Setup (FUN_00878160)
# The function ALL 5 normal PDD callers invoke before PDD
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: PreDestruction_Setup — the full protocol")
write("#" * 70)

decompile_at(0x00878160, "PreDestruction_Setup (113 bytes)")

# ===================================================================
# PART 2: hkWorld_Lock — what exactly does it lock?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: hkWorld_Lock internals")
write("#" * 70)

decompile_at(0x00C3E310, "hkWorld_Lock (43 bytes)")
decompile_at(0x00C3E750, "hkWorld_Lock_Inner (FUN_00c3e750)")
decompile_at(0x00C3E340, "hkWorld_Unlock (49 bytes)")
decompile_at(0x00C3E7D0, "hkWorld_Unlock_Inner (FUN_00c3e7d0)")

write("")
write("DAT_01202d98 = Havok world singleton pointer")
write("hkWorld_Lock takes this as param_1 (ECX)")

# ===================================================================
# PART 3: ALL 5 normal PDD callers — verify they all follow protocol
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: ALL 5 normal PDD callers (full decompilation)")
write("# These are callers of DeferredCleanup_Small (FUN_00878250)")
write("# Expected pattern: PreDestruction_Setup → PDD → cleanup")
write("#" * 70)

# DeferredCleanup_Small itself
decompile_at(0x00878250, "DeferredCleanup_Small (86 bytes)")

# The 5 callers
decompile_at(0x004556D0, "Caller1_FUN_004556d0")
decompile_at(0x008782B0, "Caller2_FUN_008782b0 (CellTransition_SafePoint)")
decompile_at(0x0093CDF0, "Caller3_FUN_0093cdf0")
decompile_at(0x0093D500, "Caller4_FUN_0093d500")
decompile_at(0x005B6CD0, "Caller5_FUN_005b6cd0")

# ===================================================================
# PART 4: Post-destruction cleanup — what happens AFTER PDD?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Post-destruction cleanup/restore")
write("# What do callers do AFTER PDD? Unlock? Restore state?")
write("#" * 70)

# FUN_008781c0 — appears to be the post-destruction restore
decompile_at(0x008781C0, "PostDestruction_Restore? (FUN_008781c0)")

# FUN_008781e0 — SetDistanceThreshold
decompile_at(0x008781E0, "SetDistanceThreshold (16 bytes)")

# FUN_008781f0 — reads distance threshold (save before, restore after)
decompile_at(0x008781F0, "GetDistanceThreshold (FUN_008781f0)")

# ===================================================================
# PART 5: SceneGraphInvalidate — full chain
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: SceneGraphInvalidate — what it does exactly")
write("#" * 70)

decompile_at(0x00703980, "SceneGraphInvalidate (45 bytes)")
decompile_at(0x007160B0, "SceneGraph_CullUpdate (FUN_007160b0)")
decompile_at(0x009373F0, "SceneGraph_IsExterior? (FUN_009373f0)")

# ===================================================================
# PART 6: CellTransitionHandler — does it follow the same protocol?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: CellTransitionHandler — compare protocol")
write("# Does it use hkWorld_Lock? SceneGraphInvalidate?")
write("#" * 70)

decompile_at(0x008774A0, "CellTransitionHandler (561 bytes)", 10000)

# ===================================================================
# PART 7: HeapCompact Stage 5 — does it follow the protocol?
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: HeapCompact Stage 5 — compare protocol")
write("# Stage 5 uses TLS=0 + FindCellToUnload + PDD")
write("# Does it lock hkWorld? Invalidate scene graph?")
write("#" * 70)

decompile_at(0x00866A90, "HeapCompact (602 bytes)", 12000)

# ===================================================================
# PART 8: Who calls hkWorld_Lock? Complete list
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: ALL hkWorld_Lock callers")
write("#" * 70)

find_refs_to(0x00C3E310, "hkWorld_Lock")
find_refs_to(0x00C3E340, "hkWorld_Unlock (FUN_00c3e340)")

# Also check the unlock function that uses offset +0x80
decompile_at(0x00C3E340, "hkWorld_Unlock")

# ===================================================================
# PART 9: FUN_00878080 (MainLoop HeapCompact caller) — full context
# Does the per-frame HeapCompact path use the protocol?
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_00878080 — MainLoop HeapCompact path")
write("# This is what our trigger value activates")
write("#" * 70)

decompile_at(0x00878080, "MainLoop_HeapCompact (FUN_00878080)")

# ===================================================================
# PART 10: FUN_00868850 (per-frame queue drain) — does it lock?
# ===================================================================
write("")
write("#" * 70)
write("# PART 10: Per-frame queue drain (FUN_00868850)")
write("# Our boosted drain hook. Does it use hkWorld_Lock?")
write("#" * 70)

decompile_at(0x00868850, "PerFrame_QueueDrain (1166 bytes)", 12000)

# ===================================================================
# PART 11: DAT_01202d98 — Havok world singleton
# ===================================================================
write("")
write("#" * 70)
write("# PART 11: Havok world singleton (DAT_01202d98)")
write("#" * 70)

find_refs_to(0x01202D98, "DAT_01202d98 (Havok world)")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

# Write output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/pre_destruction_protocol.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
