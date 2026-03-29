# @category Analysis
# @description Trace COMPLETE BST task processing: every function BST calls,
#              every pointer it dereferences, every virtual call.
#              Goal: find ALL hookable points where BST reads a game pointer
#              that the main thread could free.

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
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

# ===================================================================
# BST THREAD ENTRY AND MAIN LOOP
# The BST thread dequeues tasks and calls virtual methods on them.
# We need to trace every virtual call to find stale pointer reads.
# ===================================================================

write("BST STALE POINTER ANALYSIS")
write("=" * 70)
write("")
write("Goal: Find EVERY function BST calls that dereferences a pointer")
write("obtained from a task object. These are ALL potential UAF sites.")
write("")

# BST entry point
decompile_at(0x00C42DA0, "BST thread entry (lpStartAddress)")

# BST initialization
decompile_at(0x00C80130, "BST init (called from entry)")

# BST main task loop - THE critical function
decompile_at(0x00C410B0, "BST main loop (633 bytes, task processing)")
find_and_print_calls_from(0x00C410B0, "BST main loop")

# ===================================================================
# TASK VIRTUAL DISPATCH
# BST calls vtable methods on dequeued tasks. The vtable offsets
# determine which function processes the task. Find all vtable call
# targets for QueuedTexture, QueuedFile, QueuedHead, BSTask.
# ===================================================================

write("")
write("TASK VIRTUAL DISPATCH")
write("=" * 70)

# QueuedTexture vtable entries (RTTI at 0x01016788)
# Need to find the vtable pointer and read function pointers
write("")
write("QueuedTexture RTTI: 0x01016788")
write("Need to find vtable layout to determine which virtual methods")
write("BST calls and which ones dereference NiSourceTexture.")
write("")

# IOTask release/DecRef - we already hook this (FUN_0044DD60)
decompile_at(0x0044DD60, "IOTask DecRef (our io_task hook target)")

# The function that ACTUALLY processes a QueuedTexture
# From crash calltrace: 0x0043BFC1 return, 0x0043BE3F caller
# These are likely virtual methods called by BST on the QueuedTexture
decompile_at(0x0043BD10, "QueuedTexture::Run (constructor/first method)")

# FUN_0044AD70 from latest crash trace - likely task processing
decompile_at(0x0044AD70, "FUN_0044AD70 (from crash calltrace)")

# ===================================================================
# COMPLETED TASK QUEUE - Main thread side
# After BST completes a task, main thread processes the result.
# FUN_00c3dbf0 is IOManager main-thread processing.
# ===================================================================

write("")
write("MAIN THREAD TASK COMPLETION PROCESSING")
write("=" * 70)

decompile_at(0x00C3DBF0, "IOManager::ProcessCompletedTasks (Phase 3)")
find_and_print_calls_from(0x00C3DBF0, "IOManager::ProcessCompletedTasks")

# ===================================================================
# THE SPECIFIC CRASH: latest crash at 0x00C3CE21
# This was a DIFFERENT crash from the QueuedTexture one.
# Let's see what this function does.
# ===================================================================

write("")
write("LATEST CRASH PATH (0x00C3CE21)")
write("=" * 70)

decompile_at(0x00C3CE21, "Crash at 0x00C3CE21")
decompile_at(0x006F71CB, "Caller 1 (0x006F71CB)")
decompile_at(0x006F65D1, "Caller 2 (0x006F65D1)")

# ===================================================================
# NISOURCETEXTURE REFCOUNT MANAGEMENT
# Who increments/decrements refcount? When does refcount hit 0?
# This determines when the object becomes eligible for destruction.
# ===================================================================

write("")
write("NISOURCETEXTURE REFERENCE MANAGEMENT")
write("=" * 70)

# NiRefObject AddRef/Release
decompile_at(0x006FF2C0, "NiRefObject::IncRefCount (if exists)")
decompile_at(0x006FF2D0, "NiRefObject::DecRefCount (if exists)")

# InterlockedDecrement pattern for refcount
# NiSourceTexture inherits from NiRefObject which has refcount at +0x04
write("")
write("NiRefObject refcount is at offset +0x04.")
write("AddRef = InterlockedIncrement(&this->refcount)")
write("Release = InterlockedDecrement(&this->refcount); if 0, delete this")
write("")

# ===================================================================
# SBM FREE BEHAVIOR - What EXACTLY does SBM do with freed blocks?
# Does it overwrite any bytes? Which offset?
# ===================================================================

write("")
write("SBM FREE INTERNALS")
write("=" * 70)

# FUN_00aa6c70 - SBM pool freelist insert
decompile_at(0x00AA6C70, "SBM freelist insert (what bytes does it overwrite?)")

# FUN_00aa4060 - GameHeap::Free
decompile_at(0x00AA4060, "GameHeap::Free (main free entry)")

# FUN_00aa42c0 - fallback free (malloc-based)
decompile_at(0x00AA42C0, "GameHeap fallback free")

# ===================================================================
# OUTPUT
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bst_stale_ptr_complete.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
