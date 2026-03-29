# @category Analysis
# @description Deep dive into QueuedTexture destructor and +0x30 access.
#              What EXACTLY does the destructor do with the NiSourceTexture?
#              Where can we intercept the stale pointer access?

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

write("QUEUEDTEXTURE DESTRUCTOR DEEP DIVE")
write("=" * 70)
write("")
write("Goal: Find EXACTLY where the NiSourceTexture at +0x30 is accessed")
write("in the QueuedTexture destructor chain. This is the real crash cause.")
write("")

# QueuedTexture destructor (0x0043bf80)
# This is vtable[0] called by DecRef when refcount == 0
decompile_at(0x0043BF80, "QueuedTexture destructor (vtable[0])")
find_and_print_calls_from(0x0043BF80, "QueuedTexture destructor")

# FUN_00c3cea0 -- called from destructor
decompile_at(0x00C3CEA0, "FUN_00c3cea0 (called from QueuedTexture dtor)")
find_and_print_calls_from(0x00C3CEA0, "FUN_00c3cea0")

# FUN_00c3ce60 -- base class constructor/init (called in QueuedTexture ctor)
decompile_at(0x00C3CE60, "FUN_00c3ce60 (base class init)")

# FUN_00633c90 -- initializes +0x30 (NiPointer<NiSourceTexture>)
decompile_at(0x00633C90, "FUN_00633c90 (init NiSourceTexture ptr at +0x30)")
find_and_print_calls_from(0x00633C90, "FUN_00633c90")

# FUN_0066b0d0 -- used in constructor 3 to set +0x30 via ref swap
decompile_at(0x0066B0D0, "FUN_0066b0d0 (NiPointer ref swap at +0x30)")
find_and_print_calls_from(0x0066B0D0, "FUN_0066b0d0")

# FUN_00c3cee0 -- called in constructor, processes the texture path
decompile_at(0x00C3CEE0, "FUN_00c3cee0 (texture path processing)")
find_and_print_calls_from(0x00C3CEE0, "FUN_00c3cee0")

# FUN_00c3cf60 -- called in constructor
decompile_at(0x00C3CF60, "FUN_00c3cf60 (constructor finalize)")
find_and_print_calls_from(0x00C3CF60, "FUN_00c3cf60")

# FUN_00c3cf40 -- called in constructor 2
decompile_at(0x00C3CF40, "FUN_00c3cf40 (constructor 2 path)")

# FUN_00449150 -- called in constructor 3
decompile_at(0x00449150, "FUN_00449150 (constructor 3 task submit)")
find_and_print_calls_from(0x00449150, "FUN_00449150")

# ===================================================================
# PART 2: What happens INSIDE the BST virtual calls?
# Lines 503-504: (**(param_1+0x30)+0x4c)(local_38) and +0x50
# The param_1+0x30 is the BST's OWN dispatch table, not QueuedTexture.
# But what do THOSE functions do with the QueuedTexture (local_38)?
# ===================================================================

write("")
write("PART 2: BST DISPATCH TABLE VIRTUAL METHODS")
write("=" * 70)
write("")
write("BST calls vtable[0x4c](task) and vtable[0x50](task)")
write("These process the QueuedTexture. They may read +0x30.")
write("")

# The BST dispatch object is at param_1+0x30 in the BST main loop.
# We need to find what object this is and its vtable.
# From the BST loop: param_1 is BSTaskManagerThread.
# param_1+0x30 is a pointer to what? Likely a BSResourceManager or similar.

# Let's decompile the functions that FUN_0044ac40 calls
# (which is called from FUN_00c3cb70 which processes completed tasks)
decompile_at(0x0044AC40, "FUN_0044ac40 (task state machine processor)")
find_and_print_calls_from(0x0044AC40, "FUN_0044ac40")

# FUN_0044e050 -- called from state machine for state==1
decompile_at(0x0044E050, "FUN_0044e050 (task completion handler)")
find_and_print_calls_from(0x0044E050, "FUN_0044e050")

# FUN_0092c870 -- also called for state==1
decompile_at(0x0092C870, "FUN_0092c870 (pre-completion)")

# ===================================================================
# PART 3: NiSourceTexture destruction chain
# When PDD destroys NiSourceTexture, what happens to QueuedTexture?
# Does it get notified? Does it null its +0x30?
# ===================================================================

write("")
write("PART 3: NISOURCETEXTURE DESTRUCTION vs QUEUEDTEXTURE LIFECYCLE")
write("=" * 70)

# NiSourceTexture destructor
decompile_at(0x00A5FCA0, "NiSourceTexture destructor")
find_and_print_calls_from(0x00A5FCA0, "NiSourceTexture destructor")

# FUN_004019a0 -- InterlockedDecrement (used in DecRef)
decompile_at(0x004019A0, "FUN_004019a0 (InterlockedDecrement wrapper)")

# ===================================================================
# PART 4: The NiPointer<T> smart pointer at +0x30
# FUN_00633c90 initializes it. What does it do on destruction?
# Does it DecRef the NiSourceTexture when QueuedTexture is destroyed?
# ===================================================================

write("")
write("PART 4: NiPointer SMART POINTER LIFECYCLE")
write("=" * 70)
write("")
write("QueuedTexture+0x30 appears to be an NiPointer<NiSourceTexture>.")
write("NiPointer is a smart pointer that increments refcount on assign")
write("and decrements on release. If this works correctly, PDD should")
write("NOT be able to free NiSourceTexture while QueuedTexture holds it.")
write("")
write("UNLESS: the NiPointer at +0x30 is NOT properly initialized,")
write("or the refcount is managed outside NiPointer (raw pointer copy).")
write("")

# The key: FUN_00633c90((void*)((int)this + 0x30), 0) -- what is this?
# If it's NiPointer::NiPointer(nullptr), it's just init to null.
# Then FUN_00c3cee0 or FUN_0066b0d0 sets the actual texture pointer.
# Does FUN_0066b0d0 increment refcount?

# Let's also look at FUN_00c3cf40 which is used in constructor 2
decompile_at(0x00C3CF40, "FUN_00c3cf40 (sets texture from param)")

# ===================================================================
# OUTPUT
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/queuedtexture_dtor_deep.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
