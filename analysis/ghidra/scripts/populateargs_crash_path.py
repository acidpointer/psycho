# @category Analysis
# @description Trace exactly what PopulateArgs reads that crashes.
# The crash is in NVSE's InternalFunctionCaller::PopulateArgs at +0xD4.
# NVSE is at base 0x08890000 (from crash EIP=0x08897FF4, function at
# nvse_1_4+0x67FF4). We can't analyze NVSE's DLL in Ghidra (different binary).
# Instead, trace what GAME DATA the script system accesses:
# 1. CallFunctionScriptAlt calls UserFunctionManager::Call with a Script*
#    and arguments. What does the game store in Script objects?
# 2. Script object layout — what fields could be freed during PDD?
# 3. The argument is lastCell (TESObjectCELL*). What cell sub-objects
#    could be freed that PopulateArgs traverses?
# 4. FUN_004556d0 (per-frame PDD) — what does it free? Does it free
#    cell extra data, script data, or form sub-objects?
# 5. GameHeap::Free callers during per-frame PDD — what types of
#    objects go through our Gheap::free?

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

def read_vtable(vtable_addr, label, count=8):
	write("")
	write("%s vtable at 0x%08x:" % (label, vtable_addr))
	for i in range(count):
		entry_addr = vtable_addr + i * 4
		val = getInt(toAddr(entry_addr)) & 0xFFFFFFFF
		func = fm.getFunctionContaining(toAddr(val))
		fname = func.getName() if func else "???"
		write("  [%2d] +0x%02x -> 0x%08x %s" % (i, i*4, val, fname))


write("=" * 70)
write("PopulateArgs Crash Path — What Game Data Is Stale?")
write("=" * 70)

# =====================================================================
# PART 1: Script object layout
# Class: Script at 0x01037094 from crash log
# What fields does a Script have? Which are allocated via GameHeap?
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: Script object layout and vtable")
write("#" * 70)

read_vtable(0x01037094, "Script", 12)

# Script constructor / key methods
find_xrefs_to(0x01037094, "Script_vtable_refs", 10)

# FUN_005aa8a0 — Script::Execute or similar
decompile_at(0x005aa8a0, "Script_Execute_or_Constructor")

# =====================================================================
# PART 2: TESObjectCELL extra data — what gets freed during PDD?
# The argument passed to CallFunctionScriptAlt is a TESObjectCELL*.
# Cell sub-objects (extra data list, pathfinding, etc.) are freed.
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: TESObjectCELL extra data that PDD frees")
write("#" * 70)

# TESObjectCELL vtable
read_vtable(0x0102E9B4, "TESObjectCELL", 8)

# =====================================================================
# PART 3: What does the game's per-frame PDD (FUN_004556d0) actually
# free via GameHeap? Trace the destruction chain.
# FUN_004556d0 calls FUN_00878250 (DeferredCleanupSmall)
# which calls FUN_00868d70 (PDD) which processes queues.
# What goes into the queues?
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: DeferredCleanupSmall (FUN_00878250) — what it frees")
write("#" * 70)

decompile_at(0x00878250, "DeferredCleanupSmall")
find_calls_from(0x00878250, "DeferredCleanupSmall")

# =====================================================================
# PART 4: FUN_00868330 — who adds items to PDD queues?
# DAT_011de808 (queue 0x08 NiNode), DAT_011de910 (queue 0x04 Texture)
# These xrefs tell us what game operations enqueue objects for deferred
# destruction. The enqueued objects' sub-data becomes stale after PDD.
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: Who enqueues objects for PDD destruction?")
write("#" * 70)

decompile_at(0x00868330, "PDD_EnqueueFunction")
find_calls_from(0x00868330, "PDD_EnqueueFunction")
find_xrefs_to(0x00868330, "PDD_Enqueue_callers", 20)

# =====================================================================
# PART 5: FUN_005585e0 — gets the TESObjectREFR from a form
# Used by CancelStaleTasks. Understanding form→ref chain tells us
# what data is traversed when accessing a form argument.
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: Form to reference resolution")
write("#" * 70)

decompile_at(0x005585e0, "GetRefFromForm")

# =====================================================================
# PART 6: The game's OWN script argument resolution
# FUN_005ae790 or similar — how does the game resolve a form argument
# when calling a script function? This is what NVSE's PopulateArgs
# replicates. If the game validates, NVSE should too.
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: Game's script argument resolution")
write("#" * 70)

# FUN_005ae790 — Script::Run or argument setup
decompile_at(0x005ae790, "Script_ArgSetup")
find_calls_from(0x005ae790, "Script_ArgSetup")

# =====================================================================
# PART 7: Fast travel — what EXACTLY does fast travel free?
# FUN_0078d020 is called after fast travel (from outer loop)
# What does it clean up?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: Fast travel cleanup — FUN_0078d020")
write("#" * 70)

decompile_at(0x0078d020, "FastTravel_Cleanup")
find_calls_from(0x0078d020, "FastTravel_Cleanup")

# =====================================================================
# PART 8: The outer loop code AFTER inner loop and BEFORE loop end
# From disassembly: 0x0086b3e8 onwards. What runs between inner loop
# return and the JMP back to loop start? Any of these could free data.
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: Outer loop post-frame code (0x0086b3e8 area)")
write("# What functions run between inner loop and next iteration?")
write("#" * 70)

# FUN_0078d020 — fast travel complete handler
decompile_at(0x0078d020, "PostFastTravel")

# FUN_0086bdf0 — called at 0x0086b506 in loading path
decompile_at(0x0086bdf0, "LoadingPath_Check")

# FUN_0078cfc0 — called at 0x0086b529
decompile_at(0x0078cfc0, "PreLoading_Setup")

# =====================================================================
# PART 9: CellTransitionHandler (FUN_008774a0) output
# After CellTransitionHandler returns, what state is the game in?
# What has been freed? What is still referenced?
# The key: CellTransitionHandler calls FUN_00868d70('\0') which is
# BLOCKING PDD. This frees objects. Then NVSE fires.
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: What does blocking PDD (FUN_00868d70 with param=0) free?")
write("# vs non-blocking PDD (param=1)?")
write("#" * 70)

# FUN_00868d70 full decompile — the PDD function
decompile_at(0x00868d70, "PDD_Full")

# =====================================================================
# PART 10: TESForm::MarkAsDeleted or equivalent
# When a form is freed, does the game set the DELETED flag (0x20)?
# If so, we could check this flag in our Gheap::free to track
# which forms are being freed.
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: Form deletion flag management")
write("#" * 70)

# Search for writes to form+0x08 (flags field) with value 0x20 (DELETED)
# FUN_00447ce0 — SetDeleted?
decompile_at(0x00447ce0, "Form_SetFlags_area")

# FUN_00440d80 checks flag 0x20 (DELETED). Who SETS it?
find_xrefs_to(0x00440d80, "IsDeleted_callers", 10)

# FUN_00401030 — CommonDelete (from NiNode PDD)
decompile_at(0x00401030, "CommonDelete")


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/populateargs_crash_path.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
