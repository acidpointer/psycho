# @category Analysis
# @description Trace ALL free paths during cell transitions.
# Maps: CellTransitionHandler → PDD → destructors → GameHeap::Free vs CRT _free
# Goal: Find if any game frees bypass GameHeap::Free (our quarantine)
# and go through CRT _free() directly.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_at(addr_int, label, max_len=8000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	output.append("")
	output.append("=" * 70)
	output.append("%s @ 0x%08x" % (label, addr_int))
	output.append("=" * 70)
	if func is None:
		output.append("  [function not found]")
		return
	output.append("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		output.append(code[:max_len])
	else:
		output.append("  [decompilation failed]")

output.append("###############################################################")
output.append("# CELL TRANSITION FREE PATHS ANALYSIS")
output.append("# Goal: Find ALL paths where game objects are freed during")
output.append("# cell transitions, and whether they go through GameHeap::Free")
output.append("# (0x00AA4060, our quarantine) or CRT _free (bypasses quarantine)")
output.append("###############################################################")

# === Section 1: Cell Transition Handler ===
output.append("\n\n### SECTION 1: Cell Transition Handler")
decompile_at(0x008774A0, "CellTransitionHandler (561 bytes)")

# === Section 2: PDD - the destructors for each queue ===
output.append("\n\n### SECTION 2: PDD Queue Destructors")
decompile_at(0x00868D70, "ProcessDeferredDestruction (1037 bytes)", 12000)

# Queue 0x08 (NiNode) destructor
decompile_at(0x00418D20, "NiNode_Release (queue 0x08, 44 bytes)")

# Queue 0x04 (Texture) destructor
decompile_at(0x00418E00, "Texture_Release (queue 0x04, 44 bytes)")

# Queue 0x20 (Havok) destructor
decompile_at(0x00401970, "Havok_Release (queue 0x20)")

# Queue 0x01 (Generic) — vtable+0x10 dispatch
# Need to trace where vtable+0x10 leads for common types

# Queue 0x02 (Animation) destructor
decompile_at(0x00868CE0, "Anim_ClearFlag (queue 0x02, 39 bytes)")

# Queue 0x10 (Forms) — queue flush
decompile_at(0x0078D1F0, "PDD_FormLock (queue 0x10, 15 bytes)")

# === Section 3: NiRefObject release/delete chain ===
output.append("\n\n### SECTION 3: NiRefObject Release → Delete chain")
output.append("# When refcount hits 0, does the delete go through GameHeap::Free?")

# NiRefObject::DecRefCount and delete
decompile_at(0x0040F9E0, "NiRefObject_DecRef (common release)")
decompile_at(0x0040FA60, "NiRefObject_Delete (operator delete)")

# GameHeap::Free (our hooked entry point)
decompile_at(0x00AA4060, "GameHeap::Free (hooked)")

# FallbackFree — calls CRT _free directly
decompile_at(0x00AA42C0, "FallbackFree (25 bytes, calls CRT _free)")

# === Section 4: Havok object destruction ===
output.append("\n\n### SECTION 4: Havok object free paths")
output.append("# hkBSHeightFieldShape destruction — does it use GameHeap or CRT?")

# hkBase allocator / deallocator
decompile_at(0x00C3E170, "hkDeallocate (Havok dealloc)")
decompile_at(0x00C3E0D0, "hkAllocate (Havok alloc)")

# bhkCollisionObject destructor
decompile_at(0x00C40DC0, "bhkCollisionObject_dtor")

# === Section 5: DestroyCell chain ===
output.append("\n\n### SECTION 5: DestroyCell → what gets freed")
decompile_at(0x00462290, "DestroyCell (called by FindCellToUnload)")
decompile_at(0x004539A0, "ForceUnloadCell (196 bytes)")

# === Section 6: AI thread heightfield access ===
output.append("\n\n### SECTION 6: AI thread heightfield access pattern")
output.append("# Where exactly does the AI thread read hkBSHeightFieldShape?")
decompile_at(0x0096C330, "AIProcess_Main (991 bytes, raycasting)", 12000)

# === Section 7: HeapCompact Stage 2 ===
output.append("\n\n### SECTION 7: HeapCompact Stage 2 (cell/resource cleanup)")
output.append("# What does Stage 2 actually do? Does it unload cells?")
decompile_at(0x00866A90, "HeapCompact (602 bytes)", 12000)

# The FUN_00652110 called in Stage 2
decompile_at(0x00652110, "Stage2_CellManager (exterior cell manager)")
decompile_at(0x00650A30, "Stage2_ResourceCleanup (BSA/texture caches)")

# === Section 8: IOManager and QueuedTexture ===
output.append("\n\n### SECTION 8: IOManager / QueuedTexture lifecycle")
output.append("# How does IOManager process tasks? Where does it read QueuedTexture?")

# The crash return address was 0x0043BFC1
decompile_at(0x0043BF00, "IO_ProcessTask (around crash addr 0x0043BFC1)")
decompile_at(0x0043BE00, "IO_TaskDispatch (caller)")
decompile_at(0x0044DD00, "IO_QueueProcessor")

# === Write output ===
import os
out_path = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/cell_transition_free_paths.txt"

d = os.path.dirname(out_path)
if not os.path.exists(d):
	os.makedirs(d)

with open(out_path, "w") as f:
	f.write("\n".join(output))

print("Wrote %d lines to %s" % (len(output), out_path))
