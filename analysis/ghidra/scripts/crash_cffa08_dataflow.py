# @category Analysis
# @description Trace data flow into the FUN_00C94BD0 post-broadphase iteration
# loop that crashes at FUN_00CFFA00 with a NULL entity. We need to identify:
#   - what writes [esp+0x5c] (the agent array base)
#   - what writes [esp+0x60] (the loop bound)
#   - whether the bound matches the number of slots actually filled
#   - whether anything between fill and iterate can null a slot

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def disasm_range(start_int, end_int):
	a = toAddr(start_int)
	inst = listing.getInstructionAt(a)
	if inst is None:
		inst = listing.getInstructionAfter(a)
	while inst is not None and inst.getAddress().getOffset() < end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_writes_to_stack_slot(func_entry, slot_disp):
	# Scan a function for instructions writing to [ESP+disp] or [EBP-?]
	# matching slot_disp. Captures the source operand string.
	func = fm.getFunctionAt(toAddr(func_entry))
	if func is None:
		write("  [function %x not found]" % func_entry)
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	matches = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		s = inst.toString()
		# Look for patterns like MOV dword ptr [ESP + 0x5c],...
		if "[ESP" not in s and "[EBP" not in s:
			continue
		mnem = inst.getMnemonicString()
		if mnem not in ("MOV", "LEA", "PUSH"):
			continue
		# Check if the displacement matches
		key = "+ 0x%x" % slot_disp
		alt = "+ 0x%X" % slot_disp
		if key in s.lower() or alt in s.lower() or ("+ %d" % slot_disp) in s:
			write("  0x%08x: %s" % (a.getOffset(), s))
			matches += 1
	write("  ---- %d matches for slot offset 0x%x ----" % (matches, slot_disp))

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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code)

def find_xrefs_to(addr_int, label):
	write("")
	write("--- XRefs TO 0x%08x (%s) ---" % (addr_int, label))
	addr = toAddr(addr_int)
	rm = currentProgram.getReferenceManager()
	refs = rm.getReferencesTo(addr)
	count = 0
	for r in refs:
		t = r.getReferenceType().toString()
		from_addr = r.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(toAddr(from_addr))
		fname = from_func.getName() if from_func else "(no func)"
		write("  %s @ 0x%08x in %s" % (t, from_addr, fname))
		count += 1
	write("  Total: %d refs" % count)

write("=" * 70)
write("FUN_00C94BD0 POST-BROADPHASE ITERATION DATA FLOW")
write("Goal: identify why slot in agent array can be NULL")
write("=" * 70)

# 1. Full disasm of the addEntityBatch function from the broadphase create
#    call through the iteration loop. We saw:
#      0x00c95061: XOR ESI,ESI
#      0x00c95063: TEST EBP,EBP
#      0x00c95067: MOV ECX,[ESP+0x5c]
#      0x00c9506b: MOV EBP,[ECX+ESI*4]   <- crash if entry is NULL
#      0x00c95070: CALL 0x00d00500
#      0x00c95076: CALL 0x00cffa00
#      0x00c9507f: CMP ESI,[ESP+0x60]    <- loop count
#    Want everything from the broadphase invoke (~0x00c94f00 area) to loop end.
write("")
write("#" * 70)
write("# SECTION 1: FUN_00C94BD0 disasm from broadphase invoke through loop")
write("#" * 70)
disasm_range(0x00C94F00, 0x00C95090)

# 2. Scan FUN_00C94BD0 for any write to [esp+0x5c] / [esp+0x60].
#    The scan walks the function body and reports MOV/LEA/PUSH against those
#    stack offsets so we can see exactly what is stored there.
write("")
write("#" * 70)
write("# SECTION 2: stores to [ESP+0x5c] (agent array base candidate)")
write("#" * 70)
find_writes_to_stack_slot(0x00C94BD0, 0x5c)

write("")
write("#" * 70)
write("# SECTION 3: stores to [ESP+0x60] (agent count candidate)")
write("#" * 70)
find_writes_to_stack_slot(0x00C94BD0, 0x60)

# 3. The broadphase invoke is `(**(this+0x58)+0x18)(&local_28,&local_34,aiStack_10)`.
#    That should be hkp3AxisSweep::addObjectBatch. The third arg (arena) is
#    where the agents are written. We need to know whether addObjectBatch can
#    leave NULL slots and whether the count it reports matches the slots filled.
write("")
write("#" * 70)
write("# SECTION 4: hkp3AxisSweep_RTTI references (find vtable + addObjectBatch)")
write("#" * 70)
# Two known RTTI candidates seen in the lifecycle file:
find_xrefs_to(0x010cd5cc, "hkp3AxisSweep RTTI v1")
find_xrefs_to(0x010c3c14, "hkp3AxisSweep RTTI v2")

# 4. FUN_00C85750 returns a thread-local Havok arena (vtable+0x10 = bump alloc).
#    We need to know whether the arena pre-zeros memory.
write("")
write("#" * 70)
write("# SECTION 5: FUN_00C85750 (Havok thread-local arena getter)")
write("#" * 70)
decompile_at(0x00C85750, "havok_arena_get")

# 5. FUN_00C90940 (grow stack) -- called for buffer expansion. Does it zero?
write("")
write("#" * 70)
write("# SECTION 6: FUN_00C90940 (Havok stack grow)")
write("#" * 70)
decompile_at(0x00C90940, "havok_stack_grow")

# 6. FUN_00C908C0 -- called to initialize local_28/local_34 with given size
write("")
write("#" * 70)
write("# SECTION 7: FUN_00C908C0 (Havok stack init)")
write("#" * 70)
decompile_at(0x00C908C0, "havok_stack_init")

# 7. The DAT_011dfa19 is the AI_ACTIVE flag. FUN_008c0460 is on stack 2. Look
#    for who sets DAT_011dfa19=0 (AI join) and where addEntity races with it.
write("")
write("#" * 70)
write("# SECTION 8: AI_ACTIVE_FLAG (DAT_011dfa19) writers")
write("#" * 70)
find_xrefs_to(0x011dfa19, "AI_ACTIVE_FLAG")

# 8. FUN_008c0460 caller from the stack -- "attacking %s no one cared" path
write("")
write("#" * 70)
write("# SECTION 9: Stack caller FUN_008c0460 (AI dialog/attack)")
write("#" * 70)
decompile_at(0x008c0460, "FUN_008c0460")

# 9. Look for any function that explicitly clears/sets to NULL inside addEntityBatch
#    or its children. Specifically scan FUN_00C94BD0 for "MOV [...],0x0".
write("")
write("#" * 70)
write("# SECTION 10: Zero-store instructions in FUN_00C94BD0")
write("#" * 70)
def scan_zero_stores(func_entry):
	func = fm.getFunctionAt(toAddr(func_entry))
	if func is None:
		write("  [func not found]")
		return
	body = func.getBody()
	it = body.getAddresses(True)
	count = 0
	while it.hasNext():
		a = it.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		s = inst.toString()
		mnem = inst.getMnemonicString()
		if mnem == "MOV" and (",0x0" in s or ",0" == s[-2:]):
			if "[" in s:
				write("  0x%08x: %s" % (a.getOffset(), s))
				count += 1
	write("  ---- %d zero-stores ----" % count)

scan_zero_stores(0x00C94BD0)

# 10. Output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_cffa08_dataflow.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
