# @category Analysis
# @description Identify the scene graph object's vtable and the exact function at vtable+0x1c
#
# FUN_007160b0 calls: FUN_00586150(param_1) → vtable+0x1c()
# This vtable call is what accesses heightfield data and crashes.
# We need to know: what class is this? What does vtable+0x1c do?
# Can we call a different vtable method that rebuilds draw lists
# WITHOUT traversing physics data?
#
# Also: understand FUN_00664cd0 called by ProcessPendingCleanup —
# it's called twice and appears to be BSTreeManager-related.
#
# Output: analysis/ghidra/output/memory/scene_graph_vtable.txt

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label):
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
	size = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes, Convention: %s" % (
		func.getName(), size,
		func.getCallingConventionName() or "unknown"))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > 15000:
			write(code[:15000])
			write("  ... [truncated at 15000 chars]")
		else:
			write(code)
	else:
		write("  [decompilation failed]")
	write("")

def find_calls_from(addr_int, label):
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return []
	called = []
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				called.append(ref.getToAddress().getOffset())
	unique = sorted(set(called))
	write("  Calls %d unique functions:" % len(unique))
	for t in unique:
		f = fm.getFunctionAt(toAddr(t))
		n = f.getName() if f is not None else "???"
		sz = f.getBody().getNumAddresses() if f is not None else 0
		write("    -> 0x%08x  %s  (%d bytes)" % (t, n, sz))
	return unique

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	funcs = set()
	count = 0
	for ref in refs:
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

def read_ptr(addr_int):
	"""Read a 4-byte pointer value from memory."""
	try:
		val = mem.getInt(toAddr(addr_int))
		return val & 0xFFFFFFFF
	except:
		return None


write("SCENE GRAPH VTABLE + NINODE QUEUE STRUCTURE RESEARCH")
write("=" * 70)

# ===================================================================
# PART 1: FUN_00586150 — what does it return?
# This is 20 bytes, probably a simple accessor.
# The returned object has vtable+0x1c called on it.
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Scene Graph Object Identity")
write("#" * 70)

decompile_at(0x00586150, "FUN_00586150 (returns scene graph object)")

# FUN_004b7210 — gets the renderer/root
decompile_at(0x004b7210, "FUN_004b7210 (gets renderer)")

# Try to find the vtable of the returned object
# FUN_00586150 is __fastcall, param_1 comes from FUN_004b7210
# Let's see what FUN_004b7210 returns — probably reads a global
# Then FUN_00586150 reads an offset from that

# ===================================================================
# PART 2: Find RTTI for the scene graph object
# If we can identify the class, we can find the vtable and
# determine what vtable+0x1c actually is
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Scene graph class identification")
write("#" * 70)

# NiRenderer/BSRenderedSceneNode/SceneGraph are likely candidates
# Let's search for RTTI strings
# Common Gamebryo/NetImmerse scene graph classes:
# SceneGraph, NiNode, BSRenderedSceneNode

# Try to find SceneGraph-related vtables by looking at known callers
# FUN_007160b0 is the key — it gets obj from FUN_00586150 then calls vtable+0x1c
# Let's trace what FUN_00586150 returns by looking at the global it reads

# ===================================================================
# PART 3: FUN_007a1670 deep dive — the cleanup after cull/update
# 219 bytes — what does it do? Does it touch physics?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Scene graph cleanup (FUN_007a1670)")
write("#" * 70)

decompile_at(0x007a1670, "FUN_007a1670 (scene graph cleanup, 219 bytes)")
find_calls_from(0x007a1670, "FUN_007a1670")

# Decompile each function it calls
calls = find_calls_from(0x007a1670, "FUN_007a1670 (for sub-decompilation)")
for c in calls:
	f = fm.getFunctionAt(toAddr(c))
	if f is not None:
		label = "Sub-call of FUN_007a1670: %s" % f.getName()
		decompile_at(c, label)

# ===================================================================
# PART 4: FUN_00664cd0 — called by ProcessPendingCleanup TWICE
# Also called by BSTreeManager internal cleanup.
# This might be the BSTreeManager draw list update we need.
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00664cd0 (BSTreeManager related, called by cleanup)")
write("#" * 70)

decompile_at(0x00664cd0, "FUN_00664cd0 (called by ProcessPendingCleanup)")
find_refs_to(0x00664cd0, "FUN_00664cd0")
find_calls_from(0x00664cd0, "FUN_00664cd0")

# ===================================================================
# PART 5: PDD queue 0x08 internals — FUN_00868d70 section for 0x08
# We already have the full PDD decompilation. Let's look at how
# queue 0x08 is structured — what's at DAT_011de808?
# Is it a linked list, array, or something else?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: PDD Queue 0x08 Processing Path")
write("#" * 70)

# The PDD function (0x00868d70) checks DAT_011de808 for queue 0x08.
# FUN_00868250 is the try-lock for queues 0x08/0x04/0x01
decompile_at(0x00868250, "PDD queue try-lock (0x08/0x04/0x01)")

# FUN_008691b0 — called by FUN_00868250, does the actual TryEnterCriticalSection
decompile_at(0x008691b0, "PDD TryEnterCriticalSection wrapper")

# FUN_005e03d0 — clears a queue after processing
decompile_at(0x005e03d0, "Queue clear function (called after PDD drain)")

# FUN_004dffa0 — another queue clear function
decompile_at(0x004dffa0, "Queue clear function 2")

# ===================================================================
# PART 6: What reads queue 0x08 size / count?
# If we can read the queue size, we can decide whether to trigger
# early-frame drain based on accumulation.
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Queue size monitoring")
write("#" * 70)

# DAT_011de808 — what type is this? NiTPointerList? BSSimpleList?
# Let's look at how items are added to the queue
# FUN_00868330 (339 bytes) references DAT_011de808
decompile_at(0x00868330, "Queue 0x08 management (339 bytes)")

# FUN_00868850 (1166 bytes) — the big queue processor
# This likely shows the queue iteration pattern
decompile_at(0x00868850, "Queue 0x08 processor (1166 bytes)")

# ===================================================================
# PART 7: The post-PDD sequence in DeferredCleanup_Small
# FUN_00878250 calls:
#   PDD(1) → FUN_00450b80(0) → FUN_00b5fd60 → FUN_00c459d0(0)
#   → optionally FUN_00651e30 + FUN_00651f40
#   → FUN_00448620(DAT_011c3b3c, 1) → ProcessPendingCleanup(manager, 0)
# We need to understand if ALL of these are needed for our hook
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Complete DeferredCleanup_Small sequence")
write("#" * 70)

decompile_at(0x00450b80, "FUN_00450b80 (called after PDD)")
decompile_at(0x00448620, "FUN_00448620 (DAT_011c3b3c flag set)")

# ===================================================================
# PART 8: Can we read the distance threshold back?
# FUN_008781e0 sets DAT_011a95fc. FUN_008781f0 reads it.
# After our early-frame hook, we'd need to restore it.
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Distance threshold read/write")
write("#" * 70)

decompile_at(0x008781e0, "SetDistanceThreshold (writes DAT_011a95fc)")
decompile_at(0x008781f0, "GetDistanceThreshold (reads DAT_011a95fc)")
find_refs_to(0x011a95fc, "DAT_011a95fc (distance threshold)")


write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

# Write output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/scene_graph_vtable.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
