# @category Analysis
# @description Trace HighProcess+0x138 ragdoll NiPointer lifecycle.
# CRITICAL FINDING: Havok bone data is freed through Havok's own allocator,
# NOT GameHeap. Quarantine never protected it. Need to understand:
# 1. Who writes HighProcess+0x138? (ragdoll creation)
# 2. Who clears HighProcess+0x138? (ragdoll destruction)
# 3. FUN_00440ba0 — QueuedCharacter real processing, does it check ragdoll?
# 4. What does HAVOK_DEATH processing do to the ragdoll reference?
# 5. FUN_00559450 — NiPointer accessor, what does it return for freed objects?

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
write("HighProcess+0x138 Ragdoll NiPointer Lifecycle")
write("Havok bone data freed via Havok allocator, NOT GameHeap.")
write("Quarantine never protected it. Need validation fix.")
write("=" * 70)

# =====================================================================
# PART 1: FUN_00440ba0 — QueuedCharacter actual processing
# This is what FUN_00441800 calls. This is where the crash chain starts.
# Need to understand what it does BEFORE calling FUN_00451ef0
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00440ba0 — QueuedCharacter actual processing")
write("#" * 70)

decompile_at(0x00440ba0, "QueuedCharacter_ActualProcess")
find_calls_from(0x00440ba0, "QueuedCharacter_ActualProcess")

# =====================================================================
# PART 2: FUN_004411d0 — QueuedReference base constructor
# Called from QueuedCharacter ctor. What reference does it store?
# What offset is the TESObjectREFR pointer?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_004411d0 — QueuedReference base ctor")
write("#" * 70)

decompile_at(0x004411d0, "QueuedReference_BaseCtor")
find_calls_from(0x004411d0, "QueuedReference_BaseCtor")

# =====================================================================
# PART 3: FUN_00559450 — NiPointer accessor (used everywhere)
# What does it return? Does it check refcount?
# If the pointed object is freed, does it return NULL?
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_00559450 — NiPointer accessor")
write("#" * 70)

decompile_at(0x00559450, "NiPointer_Get")

# =====================================================================
# PART 4: Who WRITES to HighProcess+0x138?
# FUN_00633c90 is NiPointer assign (from FUN_00930c70 line 238)
# Search for all places that set HighProcess+0x138
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00633c90 — NiPointer assign (sets ragdoll ref)")
write("#" * 70)

decompile_at(0x00633c90, "NiPointer_Assign")

# FUN_008d8480 READS HighProcess+0x138. Find who writes to it.
# The write uses NiPointer::operator= which calls FUN_00633c90
# Search for callers of FUN_00633c90 that involve ragdoll
find_xrefs_to(0x00633c90, "NiPointer_Assign_callers", 30)

# =====================================================================
# PART 5: FUN_008ac890 — called early in FUN_00930c70 (line 201)
# This stores the ragdoll into the process. What offset?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_008ac890 — store ragdoll into process?")
write("#" * 70)

decompile_at(0x008ac890, "StoreRagdollToProcess")
find_calls_from(0x008ac890, "StoreRagdollToProcess")

# =====================================================================
# PART 6: HAVOK_DEATH flag processing
# When a character dies with ragdoll, what happens to HighProcess+0x138?
# FUN_008e4e50 and FUN_008e5700 are called in death processing path
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: Death processing — what happens to ragdoll ref?")
write("#" * 70)

decompile_at(0x008e4e50, "DeathProcess_Sub1")
find_calls_from(0x008e4e50, "DeathProcess_Sub1")

decompile_at(0x008e5700, "DeathProcess_Sub2")

# =====================================================================
# PART 7: FUN_00c6d7a0 — called when NiNode changes (line 269)
# Does it detach/clear the ragdoll controller from the old NiNode?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_00c6d7a0 — NiNode change handler")
write("#" * 70)

decompile_at(0x00c6d7a0, "NiNode_ChangeHandler")
find_calls_from(0x00c6d7a0, "NiNode_ChangeHandler")

# =====================================================================
# PART 8: FUN_00810640 — sets the ragdoll's back-pointer to character
# Called at line 240: FUN_00810640(local_74, local_28)
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00810640 — ragdoll back-pointer to character")
write("#" * 70)

decompile_at(0x00810640, "Ragdoll_SetOwnerChar")

# =====================================================================
# PART 9: FUN_00c6a350 — physics attachment (line 289)
# Called with NiNode to attach physics. Does it reference ragdoll?
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_00c6a350 — physics attachment to NiNode")
write("#" * 70)

decompile_at(0x00c6a350, "AttachPhysics")
find_calls_from(0x00c6a350, "AttachPhysics")

# =====================================================================
# PART 10: bhkRagdollController vtable — NiPointer compatible?
# Does bhkRagdollController inherit from NiRefObject?
# If yes, NiPointer at HighProcess+0x138 holds a strong ref.
# When ragdoll is freed via Havok, does it decrement the NiPointer?
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: bhkRagdollController inheritance chain")
write("# vtable 0x010C49C4 (from CreateRagdollController line 501)")
write("#" * 70)

# The vtable set in CreateRagdollController is 0x010C49C4
# Check first 4 entries to identify base class
write("\nbhkRagdollController vtable at 0x010c49c4 (from constructor):")
for i in range(6):
	entry_addr = 0x010c49c4 + i * 4
	val = getInt(toAddr(entry_addr)) & 0xFFFFFFFF
	func = fm.getFunctionContaining(toAddr(val))
	fname = func.getName() if func else "???"
	write("  [%2d] +0x%02x -> 0x%08x %s" % (i, i*4, val, fname))

# The ACTUAL destructor (vtable[0] at the final vtable 0x010C4DDC)
# was FUN_00c7de30 which calls FUN_00c7d900 then GameHeap::Free
# But does it decrement the NiPointer at HighProcess+0x138?
# Check FUN_00c7d900 more carefully for NiPointer operations
# We already have this decompiled. Check for InterlockedDecrement calls.


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/highprocess_ragdoll_ref.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
