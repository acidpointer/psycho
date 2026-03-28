# @category Analysis
# @description Research PDD skip mask (DAT_011de804) safety for use in pdd_hook.
#
# Questions:
#   1. Who READS the skip mask? All callers of FUN_00869180.
#   2. Who WRITES DAT_011de804? Any code that stores to this address.
#   3. Does per-frame PDD (FUN_00868850) use FUN_00869180 or read the mask?
#   4. Does full PDD (FUN_00868d70) reset the mask after processing?
#   5. Does cell transition (FUN_0093bea0) write the mask before calling PDD?
#   6. Does loading code write the mask?
#   7. FUN_00869180 itself -- what does it do? Just read a bit, or modify?
#   8. What is the EXACT data layout at DAT_011de804?
#   9. Who else references the PDD data area (0x011de800 - 0x011de960)?
#   10. Does HeapCompact stage 4 write the mask before calling full PDD?

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
	fsize = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, fsize))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > max_len:
			write(code[:max_len])
			write("  ... [truncated at %d chars]" % max_len)
		else:
			write(code)
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
		if count > 50:
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


write("PDD Skip Mask Safety Research")
write("=" * 70)

# ===================================================================
# PART 1: FUN_00869180 -- the skip mask reader
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00869180 -- skip mask reader")
write("#" * 70)
write("# Called with a bit mask (0x10=NiNode, 0x08=Form, 0x04=Texture,")
write("# 0x02=Anim, 0x01=Generic, 0x20=Last). Returns whether that bit")
write("# is set in DAT_011de804. Does it MODIFY the mask?")

decompile_at(0x00869180, "FUN_00869180 (skip mask check)")

# Who calls FUN_00869180?
find_refs_to(0x00869180, "FUN_00869180 callers (skip mask reader)")

# ===================================================================
# PART 2: DAT_011de804 -- all references
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: DAT_011de804 (skip mask) -- all references")
write("#" * 70)
write("# Who reads and writes this address directly?")

find_refs_to(0x011de804, "DAT_011de804 (PDD skip mask)")

# ===================================================================
# PART 3: Does per-frame PDD use the mask?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Per-frame PDD (FUN_00868850) -- does it use skip mask?")
write("#" * 70)
write("# Per-frame PDD uses cascading if-else on queue counts.")
write("# Does it call FUN_00869180 or read DAT_011de804?")

find_and_print_calls_from(0x00868850, "Per-frame PDD (FUN_00868850)")

# ===================================================================
# PART 4: Does full PDD reset the mask?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Full PDD (FUN_00868d70) -- mask usage")
write("#" * 70)
write("# Does it write/reset DAT_011de804 at any point?")
write("# Already decompiled in gen_queue_deadlock.py, re-check calls.")

find_and_print_calls_from(0x00868d70, "Full PDD (FUN_00868d70)")

# ===================================================================
# PART 5: HeapCompact stage 4 -- does it write the mask?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: HeapCompact dispatcher -- mask interaction")
write("#" * 70)
write("# HeapCompact runs stages 0..=trigger. Stage 4 = PDD purge.")
write("# Does it write the skip mask before calling PDD?")

decompile_at(0x00878080, "HeapCompact frame check (Phase 6)", 16000)
find_and_print_calls_from(0x00878080, "HeapCompact frame check")

# ===================================================================
# PART 6: Cell transition -- does it write the mask?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Cell transition mask interaction")
write("#" * 70)
write("# FUN_0093bea0 calls FUN_00868d70. Does it write DAT_011de804?")
write("# Already checked calls in gen_queue_deadlock.py, verify no")
write("# reference to 0x011de804.")

# Check FUN_008774a0 (CellTransitionHandler) too
decompile_at(0x008774a0, "CellTransitionHandler (FUN_008774a0)", 12000)
find_and_print_calls_from(0x008774a0, "CellTransitionHandler")

# ===================================================================
# PART 7: Loading code -- does it write the mask?
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Loading-related mask writes")
write("#" * 70)
write("# Check FUN_00877700 (loading wait function) and FUN_008782b0")
write("# (vanilla per-frame cleanup) for mask references.")

decompile_at(0x00877700, "Loading wait (FUN_00877700)")
find_and_print_calls_from(0x00877700, "Loading wait")

# ===================================================================
# PART 8: FUN_008691a0 -- potential mask writer
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Mask-adjacent functions")
write("#" * 70)
write("# FUN_00869180 reads the mask. Nearby functions may write it.")
write("# Check FUN_008691a0 and neighbors.")

decompile_at(0x008691a0, "FUN_008691a0 (near skip mask reader)")
decompile_at(0x00869160, "FUN_00869160 (near skip mask reader)")

# ===================================================================
# PART 9: FUN_00868d10 -- PDD-related, called right after per-frame
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_00868d10 (called at 0x0086eae4, right after per-frame PDD)")
write("#" * 70)
write("# This is called immediately after FUN_00868850 in the main loop.")
write("# Does it interact with the skip mask?")

decompile_at(0x00868d10, "FUN_00868d10 (post per-frame PDD)")
find_and_print_calls_from(0x00868d10, "FUN_00868d10")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/pdd_skip_mask_safety.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
