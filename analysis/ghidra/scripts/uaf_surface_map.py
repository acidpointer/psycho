# @category Analysis
# @description Map ALL cross-thread UAF patterns: BST task processing,
#              QueuedTexture lifecycle, every code path where BST/AI
#              dereferences a pointer obtained from a task/queue that the
#              main thread could free.

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
		if count > 60:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

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
# PART 1: THE EXACT CRASH PATH
# QueuedTexture processing: 0x0043BFC1 (crash return addr),
# 0x0043BE3F (caller), 0x0044DDA1 (io_task area)
# ===================================================================

write("PART 1: QUEUEDTEXTURE CRASH PATH")
write("=" * 70)
write("")
write("The crash is EIP=0x00000000 with return address 0x0043BFC1.")
write("ESI = QueuedTexture object. The function reads NiSourceTexture")
write("from QueuedTexture and calls through its vtable. After mi_free,")
write("the vtable is garbage -> NULL function pointer -> crash.")
write("")

decompile_at(0x0043BFC1, "Crash return address (inside caller)")
decompile_at(0x0043BE3F, "Secondary caller")
decompile_at(0x0044DDA1, "IO task DecRef area")

# QueuedTexture constructors and vtable
decompile_at(0x0043BD10, "QueuedTexture constructor 1 (char path)")
decompile_at(0x0043BE60, "QueuedTexture constructor 2")
decompile_at(0x0043BEF0, "QueuedTexture constructor 3 (ref swap)")
decompile_at(0x0043BF80, "QueuedTexture destructor")

# ===================================================================
# PART 2: BST TASK PROCESSING - the function BST calls to process
# each task. This is where the stale pointer is dereferenced.
# ===================================================================

write("")
write("PART 2: BST TASK PROCESSING LOOP")
write("=" * 70)

# BST main loop
decompile_at(0x00C410B0, "BSTaskManagerThread main loop (task processing)")

# The function that processes completed IO tasks on main thread
decompile_at(0x00C3DBF0, "IOManager main-thread task processing")

# FUN_00c3ce21 - from crash calltrace
decompile_at(0x00C3CE21, "Crash calltrace: inner function")

# FUN_006f71cb, 006f65d1, 006fe1a1, 006fe255 - from latest crash calltrace
decompile_at(0x006F71CB, "Latest crash calltrace 1")
decompile_at(0x006F65D1, "Latest crash calltrace 2")
decompile_at(0x006FE1A1, "Latest crash calltrace 3")
decompile_at(0x006FE255, "Latest crash calltrace 4")
decompile_at(0x0044AD70, "Latest crash calltrace 5")

# ===================================================================
# PART 3: ALL FUNCTIONS THAT READ QueuedTexture+0x30
# (NiSourceTexture pointer). These are ALL potential crash sites.
# ===================================================================

write("")
write("PART 3: QUEUEDTEXTURE VTABLE AND METHODS")
write("=" * 70)

# QueuedTexture RTTI at 0x01016788. Find vtable.
find_refs_to(0x01016788, "QueuedTexture RTTI/vtable")

# QueuedHead (related task type from crash stack)
decompile_at(0x0043C090, "QueuedHead (if function exists here)")

# ===================================================================
# PART 4: NISOURCETEXTURE DESTRUCTOR PATH
# When is NiSourceTexture freed? Who frees it? What cleanup runs?
# ===================================================================

write("")
write("PART 4: NISOURCETEXTURE DESTRUCTION")
write("=" * 70)

# NiSourceTexture destructor (hooked by us)
decompile_at(0x00A5FCA0, "NiSourceTexture destructor")

# Texture cache hash table operations
decompile_at(0x00A61AD0, "Texture cache add/update")
decompile_at(0x00A61A60, "Texture cache find (hooked by us)")
decompile_at(0x00A61B90, "Texture cache find variant")

# ===================================================================
# PART 5: WHAT EXACTLY HAPPENS BETWEEN mi_free AND BLOCK REUSE
# The QueuedTexture reads offset +0x30 from itself. What's at that
# offset? Is it the NiSourceTexture pointer directly?
# ===================================================================

write("")
write("PART 5: QUEUEDTEXTURE OBJECT LAYOUT")
write("=" * 70)
write("")
write("From crash: ESI = QueuedTexture. The function reads through")
write("the NiSourceTexture vtable. Need to find which offset holds")
write("the NiSourceTexture pointer and which virtual method is called.")
write("")

# The actual virtual call that crashes - decompile the function containing 0x0043BFC1
# This should show us the vtable dereference
decompile_at(0x0043BF00, "Function containing crash point (approx)")

# ===================================================================
# PART 6: gameheap_free (FUN_00aa4060) - who calls it and what
# cleanup does the caller do BEFORE freeing?
# ===================================================================

write("")
write("PART 6: FREE CALLERS FOR TEXTURE OBJECTS")
write("=" * 70)

# NiSourceTexture free path - who triggers the free?
find_and_print_calls_from(0x00A5FCA0, "NiSourceTexture dtor")

# operator delete
decompile_at(0x00401030, "operator delete -> GameHeap::Free")

# ===================================================================
# OUTPUT
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/uaf_surface_map.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
