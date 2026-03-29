# @category Analysis
# @description What EXACTLY does SBM write to freed blocks?
#              Decompile FUN_00aa6e00 (freelist link) and trace every
#              byte written. This determines our pool allocator design.

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

write("SBM FREELIST BYTE LAYOUT")
write("=" * 70)
write("")
write("Goal: determine EXACTLY which bytes SBM writes to a freed block.")
write("This tells us what a pool allocator must preserve vs overwrite.")
write("")

# The critical function: FUN_00aa6e00 -- links a freed block into the freelist
# Called from FUN_00aa6c70 (pool free entry point)
decompile_at(0x00AA6E00, "FUN_00aa6e00 (freelist LINK -- writes to freed block)")
find_and_print_calls_from(0x00AA6E00, "FUN_00aa6e00")

# The unlink function: FUN_00aa6e60 -- removes a block from freelist (on alloc)
decompile_at(0x00AA6E60, "FUN_00aa6e60 (freelist UNLINK -- on alloc)")
find_and_print_calls_from(0x00AA6E60, "FUN_00aa6e60")

# The pool free wrapper: FUN_00aa6c70
decompile_at(0x00AA6C70, "FUN_00aa6c70 (pool free entry -- calls aa6e00)")

# The pool alloc: FUN_00aa6aa0 (already decompiled but need full context)
decompile_at(0x00AA6AA0, "FUN_00aa6aa0 (pool alloc -- uses freelist)")

# Page initialization: FUN_00aa6610 -- how are fresh pages divided into blocks?
decompile_at(0x00AA6610, "FUN_00aa6610 (page init -- divides page into blocks)")

# ===================================================================
# PART 2: SBM pool structure layout
# What are the fields of the pool object?
# +0x00: ?
# +0x04: base address
# +0x08: freelist head
# +0x20: spinlock
# +0x24: lock counter
# +0x40: block size
# +0x48: page bitmap
# +0x50: arena size
# +0x58: page count
# ===================================================================

write("")
write("PART 2: SBM POOL OBJECT LAYOUT")
write("=" * 70)
write("")
write("From FUN_00aa6aa0 (alloc) and FUN_00aa6c70 (free):")
write("  pool + 0x04: base address of arena")
write("  pool + 0x08: freelist head pointer")
write("  pool + 0x20: spinlock")
write("  pool + 0x24: lock counter / reentrant depth")
write("  pool + 0x40: block size")
write("  pool + 0x48: per-page allocation count array")
write("  pool + 0x50: total arena size")
write("  pool + 0x58: total allocated page count")
write("")
write("The freelist is a singly-linked list. Each freed block stores")
write("the next pointer somewhere in its body. FUN_00aa6e00 reveals WHERE.")
write("")

# ===================================================================
# PART 3: Pool lookup from pointer
# How does SBM find the pool for a given pointer?
# DAT_011f63b8[(uint)ptr >> 0x18] -- high byte lookup table
# ===================================================================

write("")
write("PART 3: POOL LOOKUP FROM POINTER")
write("=" * 70)
write("")
write("From FUN_00aa4060 (GameHeap::Free):")
write("  pool = DAT_011f63b8[(uint)ptr >> 0x18]")
write("  This is a 256-entry table indexed by the high byte of the pointer.")
write("  Each entry points to the pool that owns that 16MB address range.")
write("")

# FUN_00aa4960 -- alternative pool lookup (for sizes not in fast table)
decompile_at(0x00AA4960, "FUN_00aa4960 (pool lookup by size)")

# FUN_00aa45a0 -- heap lookup (for non-pool pointers)
decompile_at(0x00AA45A0, "FUN_00aa45a0 (heap lookup for non-pool ptr)")

# ===================================================================
# OUTPUT
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/sbm_freelist_byte_layout.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
