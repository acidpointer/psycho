# @category Analysis
# @description Why does NiSourceTexture get freed while QueuedTexture
#              holds a refcounted NiPointer to it?
#
#              QueuedTexture+0x30 is NiPointer<NiSourceTexture> that
#              AddRefs on assign (FUN_0040f6e0). PDD should NOT free
#              NiSourceTexture while refcount > 0. Yet the crash happens.
#
#              Possible causes:
#              1. NiPointer at +0x30 is never assigned (stays NULL)
#              2. NiSourceTexture freed through path that ignores refcount
#              3. Refcount corrupted by race condition
#              4. QueuedTexture is destroyed FIRST, DecRefs texture,
#                 then main thread processes the completion and crashes
#                 on the already-destroyed QueuedTexture itself

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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

write("NISOURCETEXTURE REFCOUNT MYSTERY")
write("=" * 70)
write("")
write("Hypothesis 1: QueuedTexture+0x30 NiPointer is never set (stays NULL)")
write("  -> crash is NOT from stale NiSourceTexture at +0x30")
write("  -> crash is from QueuedTexture ITSELF being freed/recycled")
write("")
write("Hypothesis 2: NiSourceTexture freed via path ignoring refcount")
write("  -> need to find all free paths for NiSourceTexture")
write("")
write("Hypothesis 3: The QUEUEDTEXTURE is what gets freed, not NiSourceTexture")
write("  -> QueuedTexture is freed by one DecRef, main thread does second DecRef")
write("  -> double-free on QueuedTexture itself")
write("")

# ===================================================================
# PART 1: Trace the CRASH more carefully
# The crash calltrace shows 0x0044DDA1 TWICE in the stack!
# This means DecRef is called from TWO different places for the
# SAME QueuedTexture. Is this a double-release?
# ===================================================================

write("PART 1: DOUBLE DECREF ANALYSIS")
write("=" * 70)
write("")
write("From crash calltrace:")
write("  0x0044DDA1 (DecRef) -- called from 0x0043BE3F")
write("  0x0044DDA1 (DecRef) -- called from 0x00C3D38F area")
write("")
write("The QueuedTexture is DecRef'd TWICE in the same call chain.")
write("If refcount starts at 1, first DecRef -> 0 -> destructor runs.")
write("Destructor (FUN_0043bf80) calls FUN_00c3cea0 which calls")
write("FUN_00c3c620 which processes more tasks... which call DecRef")
write("on the SAME QueuedTexture AGAIN -> refcount goes to -1 -> ")
write("(*vtable[0])(1) called on already-freed QueuedTexture -> CRASH")
write("")

# FUN_00c3c620 -- called from QueuedTexture base class destructor
# This is the KEY: what does it do? Does it trigger more DecRefs?
decompile_at(0x00C3C620, "FUN_00c3c620 (base class destructor chain)")
find_and_print_calls_from(0x00C3C620, "FUN_00c3c620")

# FUN_00c3c590 -- called from FUN_00c3ce60 (base class init)
decompile_at(0x00C3C590, "FUN_00c3c590 (base class init)")
find_and_print_calls_from(0x00C3C590, "FUN_00c3c590")

# ===================================================================
# PART 2: WHO calls DecRef on QueuedTexture?
# Find all callers of FUN_0044dd60 to understand the lifecycle
# ===================================================================

write("")
write("PART 2: ALL DECREF CALLERS")
write("=" * 70)

find_refs_to(0x0044DD60, "FUN_0044dd60 (DecRef)")

# ===================================================================
# PART 3: FUN_0040f6e0 and FUN_00401970 -- AddRef and Release
# These are the NiRefObject refcount operations.
# FUN_0040f6e0 = InterlockedIncrement (AddRef)
# FUN_00401970 = InterlockedDecrement + destroy if 0 (Release)
# ===================================================================

write("")
write("PART 3: ADDREF / RELEASE INTERNALS")
write("=" * 70)

decompile_at(0x0040F6E0, "FUN_0040f6e0 (AddRef / InterlockedIncrement)")
decompile_at(0x00401970, "FUN_00401970 (Release / InterlockedDecrement + destroy)")
decompile_at(0x0040B460, "FUN_0040b460 (called from FUN_0092c870, pre-completion)")

# ===================================================================
# PART 4: The FULL destruction chain from DecRef
# When DecRef hits 0:
#   (**(code **)*param_1)(1)  -- calls vtable[0] with param=1
# vtable[0] for QueuedTexture is the destructor FUN_0043bf80
# FUN_0043bf80 calls FUN_00c3cea0
# FUN_00c3cea0 calls FUN_00c3c620
# What does FUN_00c3c620 do? Does it re-enter DecRef?
# ===================================================================

write("")
write("PART 4: FULL DESTRUCTION CHAIN")
write("=" * 70)

# FUN_0043be30 -- wrapper that calls destructor + delete
decompile_at(0x0043BE30, "FUN_0043be30 (destructor wrapper + delete)")

# Main thread IO completion processing -- where DecRef originates
decompile_at(0x00C3D9E0, "FUN_00c3d9e0 (from crash calltrace)")
find_and_print_calls_from(0x00C3D9E0, "FUN_00c3d9e0")

decompile_at(0x00C3D94C, "FUN_00c3d94c (from crash calltrace)")

decompile_at(0x00C3C538, "FUN_00c3c538 (from crash calltrace)")
find_and_print_calls_from(0x00C3C538, "FUN_00c3c538")

decompile_at(0x00C3D38F, "FUN_00c3d38f (from crash calltrace)")

decompile_at(0x00C3C67B, "FUN_00c3c67b (from crash calltrace)")

# ===================================================================
# PART 5: FUN_0043feb4 and FUN_00440ebf from calltrace
# These are between the IO completion and DecRef
# ===================================================================

write("")
write("PART 5: TASK COMPLETION -> DECREF CHAIN")
write("=" * 70)

decompile_at(0x0043FEB4, "FUN_0043feb4 (from crash calltrace)")
find_and_print_calls_from(0x0043FEB4, "FUN_0043feb4")

decompile_at(0x00440EBF, "FUN_00440ebf (from crash calltrace)")

decompile_at(0x00441546, "FUN_00441546 (from crash calltrace)")

decompile_at(0x004414CF, "FUN_004414cf (from crash calltrace)")

# ===================================================================
# PART 6: FUN_004019a0 -- the InterlockedDecrement in DecRef
# Is it truly just InterlockedDecrement, or does it do more?
# What if it returns the WRONG value due to race?
# ===================================================================

write("")
write("PART 6: INTERLOCKEDDECREMENT DETAILS")
write("=" * 70)

decompile_at(0x004019A0, "FUN_004019a0 (InterlockedDecrement in DecRef)")
write("")
write("NOTE: FUN_0044dd60 calls FUN_004019a0(param_1 + 2)")
write("param_1 + 2 means offset +8 (2 * sizeof(int) = 8 bytes)")
write("So the refcount is at QueuedTexture+0x08, NOT +0x04!")
write("")
write("This is DIFFERENT from NiRefObject refcount at +0x04.")
write("QueuedTexture has its OWN refcount at +0x08, separate from")
write("any NiRefObject inheritance chain.")
write("")

# ===================================================================
# OUTPUT
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/nisource_refcount_mystery.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
